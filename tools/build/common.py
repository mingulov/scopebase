# SPDX-License-Identifier: Apache-2.0
"""Bounded SB02 input verification, Cargo admission and evidence primitives.

Availability and execution permission are separate. This module never acquires
sources, learns approvals, builds checksum maps, or invokes a shell.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import tomllib

MAX_JSON = 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_LOG = 4 * 1024 * 1024
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
HOST = 'x86_64-unknown-linux-gnu'
NOTICE_INTRO = 'SB02 checker fixture only; not published. Dependency references are not bundled unless explicitly marked.'
PRODUCT_NOTICE_INTRO = 'ScopeBase package dependency notices. Dependency references are not bundled unless explicitly marked.'
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\Z')


class InputError(ValueError):
    pass


class PolicyError(Exception):
    def __init__(self, code, status='FAIL', detail=None):
        super().__init__(code)
        self.code, self.status, self.detail = code, status, detail


def compact(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def hash_value(value):
    return hashlib.sha256(compact(value)).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise InputError('DUPLICATE_KEY: ' + key)
        result[key] = value
    return result


def read_json(path, limit=MAX_JSON):
    try:
        with Path(path).open('rb') as f:
            raw = f.read(limit + 1)
    except FileNotFoundError:
        raise PolicyError('SOURCE_UNAVAILABLE', 'BLOCKED') from None
    if len(raw) > limit:
        raise InputError('JSON_BOUND')
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InputError('JSON_NUMBER')))
    except (UnicodeError, json.JSONDecodeError) as e:
        raise InputError('JSON_SYNTAX') from e


def exact(obj, keys):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise InputError('SCHEMA_FIELDS: expected ' + ','.join(sorted(keys)))
    return obj


def text(value, label='string'):
    if not isinstance(value, str) or not value or len(value) > 4096 or '\x00' in value:
        raise InputError('SCHEMA_' + label)
    return value


def digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise InputError('SCHEMA_DIGEST')
    return value


def boolean(value):
    if type(value) is not bool:
        raise InputError('SCHEMA_BOOLEAN')


def strings(value, limit=32, nonempty=False):
    if not isinstance(value, list) or len(value) > limit or (nonempty and not value):
        raise InputError('SCHEMA_LIST_BOUND')
    for v in value:
        text(v)
    if len(set(value)) != len(value):
        raise InputError('SCHEMA_DUPLICATE')


def relative(root, value, must_exist=True):
    text(value, 'PATH')
    p = PurePosixPath(value)
    if p.is_absolute() or '..' in p.parts or not p.parts or value != p.as_posix():
        raise InputError('PATH_ESCAPE')
    root = Path(root).resolve()
    path = root / value
    if not path.resolve().is_relative_to(root):
        raise InputError('PATH_ESCAPE')
    if must_exist and not path.exists():
        raise PolicyError('SOURCE_UNAVAILABLE', 'BLOCKED')
    return path


def absolute(value):
    text(value, 'PATH')
    p = Path(value)
    if not p.is_absolute() or '..' in p.parts:
        raise InputError('PATH_ABSOLUTE_REQUIRED')
    return p


def no_symlink_ancestors(path):
    for p in [path, *path.parents]:
        if p.is_symlink():
            raise InputError('OUTPUT_SYMLINK')


def fresh_output(path, sources):
    path = absolute(str(path))
    no_symlink_ancestors(path)
    if any(path.resolve().is_relative_to(Path(p).resolve()) for p in sources):
        raise InputError('OUTPUT_INSIDE_SOURCE')
    if path.exists() and (not path.is_dir() or any(path.iterdir()) or path.stat().st_uid != os.getuid()):
        raise InputError('OUTPUT_EXISTS')
    inspect_config_ancestors(path.parent)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def tree_records(root):
    root = Path(root).resolve()
    records = []
    def visit(directory):
        for p in sorted(directory.iterdir()):
            rel = p.relative_to(root).as_posix()
            mode = p.lstat().st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(p)
                try:
                    resolved = p.resolve(strict=True)
                except (OSError, RuntimeError):
                    raise InputError('BUNDLE_LINK') from None
                if not resolved.is_relative_to(root) or not resolved.is_file():
                    raise InputError('BUNDLE_LINK_ESCAPE')
                records.append(dict(path=rel, kind='symlink', sha256=hashlib.sha256(target.encode()).hexdigest(), link_target=target))
            elif stat.S_ISREG(mode):
                records.append(dict(path=rel, kind='file', sha256=sha(p), link_target=None))
            elif stat.S_ISDIR(mode):
                visit(p)
            else:
                raise InputError('BUNDLE_FILE_TYPE')
    visit(root)
    return sorted(records, key=lambda v: v['path'])


def tree_digest(root):
    return hash_value(tree_records(root))


def fixture_digest(root):
    records = tree_records(root)
    if any(set(PurePosixPath(r['path']).parts) & {'target', '.git', '.cargo'} for r in records):
        raise InputError('GENERATED_SOURCE_INPUT')
    if any(r['kind'] != 'file' for r in records):
        raise InputError('FIXTURE_SYMLINK')
    return hash_value([{'path': r['path'], 'sha256': r['sha256']} for r in records])


def check_hash(path, expected, code='INPUT_CHANGED'):
    digest(expected)
    if not Path(path).is_file():
        raise PolicyError('SOURCE_UNAVAILABLE', 'BLOCKED')
    if sha(path) != expected:
        raise PolicyError(code)


def row(ident, role='probe', required=True, toolchain=None, phase='input'):
    return dict(id=ident, role=role, required=required, toolchain=toolchain, phase=phase,
                status='NOT_RUN', fit='UNKNOWN', reason_code='NOT_RUN', expected=None,
                observed=None, command=None, cwd=None, input_sha256=None, lock_sha256=None,
                resolved_packages=None, resolved_features=None, logs=None, duration_ms=0,
                cleanup='not_started')


def summarize(rows, required_ids, omitted=None):
    ids = [r['id'] for r in rows]
    if len(set(ids)) != len(ids):
        raise InputError('DUPLICATE_ROW')
    if set(required_ids) - set(ids):
        raise InputError('MISSING_ROW')
    if set(ids) - set(required_ids):
        raise InputError('UNEXPECTED_ROW')
    counts = {s: sum(r['status'] == s for r in rows) for s in ('PASS', 'FAIL', 'BLOCKED', 'NOT_RUN')}
    required = [r for r in rows if r['required']]
    failure = any(r['status'] == 'FAIL' for r in required)
    incomplete = any(r['status'] in ('BLOCKED', 'NOT_RUN') or r['cleanup'] == 'unresolved' for r in required)
    status = 'FAIL' if failure else 'BLOCKED' if incomplete else 'PASS'
    return dict(status=status, exit_code={'PASS': 0, 'FAIL': 1, 'BLOCKED': 3}[status], counts=counts,
                required_count=len(required) + len(omitted or []),
                omitted_required_ids=omitted or [], full_matrix_complete=not omitted and not incomplete,
                decisions_required=[r['id'] for r in rows if r['fit'] == 'GAP'])


def atomic_json(path, value):
    raw = compact(value)
    if len(raw) > MAX_REPORT:
        raise InputError('REPORT_BOUND')
    path = absolute(str(path)); no_symlink_ancestors(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        raise InputError('REPORT_EXISTS')
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('xb') as f:
        os.chmod(temporary, 0o600); f.write(raw); f.flush(); os.fsync(f.fileno())
    # Link is no-replace, unlike rename over an existing receipt.
    os.link(temporary, path); temporary.unlink()


def dependency_records(records):
    if not isinstance(records, list):
        raise InputError('SCHEMA_DEPENDENCIES')
    seen = set()
    for r in records:
        exact(r, {'name', 'version', 'source', 'sha256', 'role'})
        for key in ('name', 'version', 'source'):
            text(r[key])
        digest(r['sha256'])
        if r['role'] not in ('host-rust', 'host-proc-macro', 'host-build'):
            raise InputError('SCHEMA_ROLE')
        key = (r['name'], r['version'], r['source'])
        if key in seen:
            raise InputError('SCHEMA_DUPLICATE_DEPENDENCY')
        seen.add(key)


def approvals(records):
    if not isinstance(records, list):
        raise InputError('SCHEMA_APPROVAL')
    seen = set()
    for r in records:
        exact(r, {'name', 'version', 'source', 'sha256', 'build_script', 'reason'})
        for key in ('name', 'version', 'source', 'reason'):
            text(r[key])
        digest(r['sha256'])
        if r['build_script'] is not None:
            relative(Path('/'), r['build_script'], False)
        key = (r['name'], r['version'], r['source'])
        if key in seen:
            raise InputError('SCHEMA_DUPLICATE_APPROVAL')
        seen.add(key)


def validate_matrix(path, kind):
    m = read_json(path)
    common = {'schema_version', 'host', 'cargo_inputs', 'approved_build_inputs', 'toolchains'}
    exact(m, common | ({'cases'} if kind == 'probe' else {'fixture_members', 'members'}))
    if type(m['schema_version']) is not int or m['schema_version'] != 1 or m['host'] != HOST:
        raise InputError('SCHEMA_VERSION_HOST')
    exact(m['cargo_inputs'], {'inventory', 'sha256'})
    absolute(m['cargo_inputs']['inventory']); digest(m['cargo_inputs']['sha256'])
    approvals(m['approved_build_inputs'])
    expected = {'msrv': '1.88.0', 'current': '1.98.1'}
    if not isinstance(m['toolchains'], list) or len(m['toolchains']) != 2:
        raise InputError('SCHEMA_TOOLCHAINS')
    if [t.get('id') if isinstance(t,dict) else None for t in m['toolchains']] != ['msrv','current']:
        raise InputError('SCHEMA_TOOLCHAIN_ORDER')
    for t in m['toolchains']:
        exact(t, {'id', 'version', 'root'})
        if t['id'] not in expected or t['version'] != expected.pop(t['id']):
            raise InputError('SCHEMA_TOOLCHAIN_PIN')
        if t['root'] != '/home/user/.rustup/toolchains/' + t['version'] + '-' + HOST:
            raise InputError('SCHEMA_TOOLCHAIN_ROOT')
    if kind != 'probe' and any(not isinstance(m[k],list) for k in ('fixture_members','members')):
        raise InputError('SCHEMA_MEMBERS')
    entries = m['cases'] if kind == 'probe' else m['fixture_members'] + m['members']
    if not isinstance(entries, list) or not entries:
        raise InputError('SCHEMA_CELL_BOUND')
    ids = set()
    for c in entries:
        keys = ({'id','required','manifest','candidate','default_features','features','tier','assertions','expected_fit','availability','compile_refusals','allowed_dependencies','obligation_refs'} if kind == 'probe' else
                {'id','manifest','role','minimal','default','supported_unions','clients','package_files','allowed_dependencies','license_files','notice_entries','denied_packages'})
        if kind != 'probe' and isinstance(c, dict) and 'minimal_dependencies' in c:
            keys = keys | {'minimal_dependencies'}
        exact(c, keys)
        if not isinstance(c['id'], str) or not IDENT.fullmatch(c['id']) or c['id'] in ids:
            raise InputError('SCHEMA_ID')
        ids.add(c['id']); relative(Path(path).parent, c['manifest'],False)
        dependency_records(c['allowed_dependencies'])
        if kind == 'probe':
            boolean(c['required']); boolean(c['default_features'])
            strings(c['features']); strings(c['assertions'], 128, True); strings(c['obligation_refs'], 128, True)
            if c['tier'] not in ('compile','host_semantic') or c['expected_fit'] not in ('SATISFIED','GAP','OBSERVE') or c['availability'] not in ('ready','pending_acquisition'):
                raise InputError('SCHEMA_PROBE_ENUM')
            exact(c['candidate'], {'name','version','source','sha256'})
            for k in ('name','version','source'):
                text(c['candidate'][k])
            if c['candidate']['sha256'] is not None:
                digest(c['candidate']['sha256'])
            elif c['availability'] != 'pending_acquisition':
                raise InputError('SCHEMA_READY_DIGEST')
            if not isinstance(c['compile_refusals'], list):
                raise InputError('SCHEMA_REFUSALS')
            refusal_ids=set()
            for r in c['compile_refusals']:
                exact(r, {'id','manifest','diagnostic_code','diagnostic_contains','positive_case'})
                for k in r:
                    text(r[k])
                if not IDENT.fullmatch(r['id']) or r['id'] in refusal_ids: raise InputError('SCHEMA_REFUSAL_ID')
                refusal_ids.add(r['id'])
                relative(Path(path).parent, r['manifest'],False)
        else:
            if c['role'] not in ('fixture','product'):
                raise InputError('SCHEMA_ROLE')
            if 'minimal_dependencies' in c:
                dependency_records(c['minimal_dependencies'])
                if any(r not in c['allowed_dependencies'] for r in c['minimal_dependencies']):
                    raise InputError('SCHEMA_MINIMAL_DEPENDENCIES')
            strings(c['minimal']); strings(c['default']); strings(c['package_files'], 1024, True); strings(c['denied_packages'], 128)
            if not isinstance(c['supported_unions'], list):
                raise InputError('SCHEMA_UNIONS')
            union_keys=set()
            for union in c['supported_unions']:
                strings(union, nonempty=True)
                key=tuple(sorted(union))
                if key in union_keys: raise InputError('SCHEMA_DUPLICATE_UNION')
                union_keys.add(key)
            if (not isinstance(c['clients'], list)
                    or len(c['clients']) not in (1, 2)
                    or (c['supported_unions'] and len(c['clients']) != 2)):
                raise InputError('SCHEMA_CLIENTS')
            client_ids = set()
            for client in c['clients']:
                exact(client, {'id','default_features','features','source'})
                text(client['id']); boolean(client['default_features']); strings(client['features'])
                relative(Path(path).parent, client['source'])
                if client['id'] in client_ids or not IDENT.fullmatch(client['id']):
                    raise InputError('SCHEMA_CLIENT_ID')
                client_ids.add(client['id'])
            for union in c['supported_unions']:
                if set().union(*(set(v['features']) for v in c['clients'])) != set(union):
                    raise InputError('SCHEMA_CLIENT_UNION')
            file_records(c['license_files'])
            if not c['license_files'] or not isinstance(c['notice_entries'], list):
                raise InputError('SCHEMA_LICENSES')
            for n in c['notice_entries']:
                exact(n, {'name','version','source','license_expression','selected_option','bundled','files'})
                for k in ('name','version','source','license_expression','selected_option'):
                    text(n[k])
                boolean(n['bundled']); file_records(n['files'])
    if kind == 'probe':
        for c in entries:
            for r in c['compile_refusals']:
                if r['positive_case'] not in ids:
                    raise InputError('SCHEMA_POSITIVE_CASE')
    else:
        if any(c['role'] != 'fixture' for c in m['fixture_members']) or any(c['role'] != 'product' for c in m['members']):
            raise InputError('SCHEMA_MEMBER_ROLE')
    validate_expansion(m,kind)
    return m


def file_records(records):
    if not isinstance(records, list):
        raise InputError('SCHEMA_FILES')
    seen = set()
    for r in records:
        exact(r, {'path','sha256'}); relative(Path('/'), r['path'], False); digest(r['sha256'])
        if r['path'] in seen:
            raise InputError('SCHEMA_DUPLICATE_FILE')
        seen.add(r['path'])


def inspect_config_ancestors(path):
    for parent in [Path(path).resolve(), *Path(path).resolve().parents]:
        for name in ('config', 'config.toml'):
            if (parent / '.cargo' / name).exists():
                raise PolicyError('UNAPPROVED_CARGO_CONFIG')


def inspect_manifest(path, allowed_edges=()):
    path = Path(path)
    data = tomllib.loads(path.read_text())
    allowed = {(Path(a).resolve(), Path(b).resolve()) for a, b in allowed_edges}
    def walk(obj):
        if not isinstance(obj, dict):
            return
        for key, value in obj.items():
            if key == 'git':
                raise PolicyError('SOURCE_OVERRIDE')
            if key == 'path' and isinstance(value, str):
                endpoint = (path.parent / value).resolve()
                # All manifest-declared path edges require a specific authority.
                if (path.resolve(), endpoint) not in allowed:
                    raise PolicyError('EXTERNAL_PATH_DEPENDENCY')
            if key in ('patch', 'replace'):
                # Traverse first to preserve the specific path-refusal reason.
                walk(value)
                if value:
                    raise PolicyError('SOURCE_OVERRIDE')
            elif key not in ('lib','bin','test','bench','example'):
                walk(value)
            elif isinstance(value, list):
                for target in value:
                    if isinstance(target, dict) and 'path' in target:
                        relative(path.parent, target['path'])
            elif isinstance(value, dict) and 'path' in value:
                relative(path.parent, value['path'])
    walk(data)
    package = data.get('package', {})
    if package.get('links'):
        raise PolicyError('NATIVE_LINKS')
    build = package.get('build')
    if build is True or build is None:
        build = 'build.rs' if (path.parent / 'build.rs').is_file() else None
    elif build is False:
        build = None
    elif not isinstance(build, str):
        raise InputError('MANIFEST_BUILD')
    if build:
        relative(path.parent, build)
    return {'data': data, 'build_script': build}


def package_files(actual, allowed):
    if set(actual) != set(allowed) or len(actual) != len(set(actual)):
        raise PolicyError('UNEXPECTED_PACKAGE_FILE', detail={'extra': sorted(set(actual)-set(allowed)), 'missing': sorted(set(allowed)-set(actual))})


def check_licenses(root, licenses, notices, role='fixture'):
    intros = {'fixture': NOTICE_INTRO, 'product': PRODUCT_NOTICE_INTRO}
    if role not in intros:
        raise PolicyError('NOTICE_ROLE_UNKNOWN')
    root = Path(root)
    for r in licenses:
        path = relative(root, r['path'], False)
        if not path.is_file():
            raise PolicyError('LICENSE_TEXT_MISSING')
        check_hash(path, r['sha256'], 'LICENSE_TEXT_MISMATCH')
    path = root / 'THIRD-PARTY-NOTICES.md'
    if not path.is_file():
        raise PolicyError('NOTICE_INCOMPLETE')
    raw = path.read_text()
    match = re.fullmatch(re.escape(intros[role]) + r'\n```json\n(.*?)\n```\n', raw, re.S)
    if not match:
        raise PolicyError('NOTICE_INCOMPLETE')
    try:
        observed = json.loads(match[1], object_pairs_hook=pairs)
    except (ValueError, TypeError):
        raise PolicyError('NOTICE_INCOMPLETE') from None
    expected = sorted(notices, key=lambda n: (n['name'], n['version'], n['source']))
    if observed != expected or notices != expected:
        raise PolicyError('NOTICE_INCOMPLETE')
    for n in notices:
        if n['bundled']:
            for f in n['files']:
                p = relative(root, f['path'], False)
                if not p.is_file():
                    raise PolicyError('LICENSE_TEXT_MISSING')
                check_hash(p, f['sha256'], 'LICENSE_TEXT_MISMATCH')


def rust_refusal(output, code, contains, source_root=None, *, expected_primary=None):
    """Match a compiler diagnostic, optionally at an exact owned source line.

    Without an expected location, retain PP09's legacy source-text check.
    This predicate does not validate command retirement, lock or cleanup facts;
    callers must retain those checks through Execution/accept_refusal.
    """
    root = Path(source_root).resolve() if source_root is not None else None
    expected_file = None
    expected_line = None
    if expected_primary is not None:
        if root is None or not isinstance(expected_primary, tuple) or len(expected_primary) != 2:
            return False
        name, expected_line = expected_primary
        if not isinstance(name, str) or type(expected_line) is not int or expected_line <= 0:
            return False
        path = Path(name)
        if path.is_absolute() or not name or '\x00' in name or '..' in path.parts:
            return False
        expected_file = (root / path).resolve()
        if not expected_file.is_relative_to(root) or not expected_file.is_file():
            return False
        try:
            if expected_line > len(expected_file.read_text().splitlines()):
                return False
        except (OSError, UnicodeError):
            return False
    for line in output.splitlines():
        try:
            obj = json.loads(line)
            msg = obj.get('message', {})
            spans = msg.get('spans', [])
            if (obj.get('reason') != 'compiler-message' or (msg.get('code') or {}).get('code') != code
                    or contains not in msg.get('message', '')):
                continue
            for span in spans:
                if not span.get('is_primary') or not span.get('file_name', '').endswith('.rs'):
                    continue
                if root is None:
                    return True
                file = Path(span['file_name'])
                if not file.is_absolute():
                    file = root / file
                file = file.resolve()
                if not file.is_relative_to(root) or not file.is_file():
                    continue
                number = span.get('line_start', 0)
                if type(number) is not int or number <= 0:
                    continue
                if expected_file is not None:
                    if file == expected_file and number == expected_line:
                        return True
                else:
                    lines = file.read_text().splitlines()
                    if number <= len(lines) and contains in lines[number-1]:
                        return True
        except (ValueError, TypeError, AttributeError, OSError, UnicodeError):
            continue
    return False


def clean_env(output, toolchain, target):
    output, root = Path(output), Path(toolchain['root'])
    for directory in ('home','tmp','cargo-home'):
        (output / directory).mkdir(exist_ok=True, mode=0o700)
    # Reconstruct instead of attempting to enumerate every Cargo override.
    return {'PATH': str(root / 'bin') + ':/usr/bin:/bin', 'HOME': str(output / 'home'),
            'TMPDIR': str(output / 'tmp'), 'CARGO_HOME': str(output / 'cargo-home'),
            'CARGO_TARGET_DIR': str(target), 'CARGO_NET_OFFLINE': 'true',
            'RUSTC': str(root / 'bin/rustc'), 'RUSTDOC': str(root / 'bin/rustdoc'),
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}


def run(argv, cwd, env, logs, timeout=600):
    """Capture bounded logs and retain launch/retirement facts on I/O errors."""
    logs = Path(logs); logs.parent.mkdir(parents=True, exist_ok=True)
    paths = {n: logs.with_suffix('.' + n) for n in ('stdout','stderr')}
    start=time.monotonic(); reason=None; errors=[]; outputs={}; proc=None; select=None
    counts={n:0 for n in paths}; code=None; retired=False; resources_closed=True
    def error(stage, exception):
        nonlocal reason
        errors.append({'stage':stage,'exception':type(exception).__name__,
                       'message':str(exception)[:512],'errno':getattr(exception,'errno',None)})
        if reason is None: reason='INTERRUPTED' if isinstance(exception,KeyboardInterrupt) else 'INTERNAL_ERROR'
    def kill():
        try: os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        except BaseException as exception: error('group-kill',exception)
    try:
        for name,path in paths.items(): outputs[name]=path.open('xb')
        proc=subprocess.Popen([str(v) for v in argv],cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        select=selectors.DefaultSelector()
        for name in paths:
            stream=getattr(proc,name); os.set_blocking(stream.fileno(),False)
            select.register(stream,selectors.EVENT_READ,name)
        deadline=start+timeout
        while select.get_map():
            if time.monotonic()>=deadline:
                reason='TIMEOUT'; break
            for key,_ in select.select(min(.1,max(0,deadline-time.monotonic()))):
                data=os.read(key.fileobj.fileno(),65536)
                if not data:
                    select.unregister(key.fileobj); key.fileobj.close(); continue
                name=key.data; remaining=MAX_LOG-counts[name]; chunk=data[:remaining]
                written=outputs[name].write(chunk)
                if written!=len(chunk): raise OSError('short log write')
                counts[name]+=written
                if len(data)>remaining:
                    reason='LOG_BOUND'; break
            if reason: break
    except BaseException as exception:
        # Before launch there is no child custody to invent. Close any newly
        # opened files below, and propagate the original setup failure.
        if proc is None: raise
        error('collect',exception)
    finally:
        if proc is not None:
            if reason: kill()
            try: code=proc.wait(timeout=2)
            except BaseException as exception:
                error('wait',exception); kill()
                try: code=proc.wait(timeout=2)
                except BaseException as retry: error('wait-after-kill',retry)
            # Reaping the direct child cannot certify surviving descendants.
            try: os.killpg(proc.pid,0)
            except ProcessLookupError: retired=code is not None
            except BaseException as exception:
                error('group-check',exception); kill()
            else: kill()
            if code is None: code=proc.returncode
        if select is not None:
            try: select.close()
            except BaseException as exception:
                error('selector-close',exception); resources_closed=False
        if proc is not None:
            for stream in (proc.stdout,proc.stderr):
                try:
                    if stream and not stream.closed: stream.close()
                except BaseException as exception:
                    error('pipe-close',exception); resources_closed=False
        for stream in outputs.values():
            try: stream.close()
            except BaseException as exception:
                error('log-close',exception); resources_closed=False
    captured={}
    for name,path in paths.items():
        entry={'path':str(path),'sha256':None,'bytes':None}
        try: entry['bytes']=path.stat().st_size
        except BaseException as exception: error('log-stat-'+name,exception)
        try: entry['sha256']=sha(path)
        except BaseException as exception: error('log-hash-'+name,exception)
        captured[name]=entry
    return {'exit_code':code,'reason_code':reason,
            'cleanup':'complete' if retired and resources_closed else 'unresolved',
            'duration_ms':round((time.monotonic()-start)*1000),'command':[str(a) for a in argv],
            'cwd':str(cwd),'process_group':proc.pid,'logs':captured,'errors':errors}


def stdout(result):
    return Path(result['logs']['stdout']['path']).read_text(errors='replace')


def succeeded(result, code='CARGO_FAILED'):
    if result['cleanup'] == 'unresolved':
        raise PolicyError('CLEANUP_UNRESOLVED', 'BLOCKED', result)
    if result['reason_code'] or result['exit_code'] != 0:
        status='BLOCKED' if result['reason_code'] in ('TIMEOUT','INTERRUPTED','LOG_BOUND') else 'FAIL'
        raise PolicyError(result['reason_code'] or code,status,result)


def toolchain_info(t, output, execution=None):
    root = Path(t['root'])
    for tool in ('cargo','rustc','rustdoc'):
        if not (root / 'bin' / tool).is_file():
            raise PolicyError('TOOLCHAIN_UNAVAILABLE', 'BLOCKED')
    env = clean_env(output, t, Path(output) / 'identity-target')
    def inspect(tool,arguments):
        def action(r):
            result=run([root/'bin'/tool,*arguments],output,env,Path(output)/('identity-'+t['id']+'-'+tool))
            if execution: execution.attach(r,result)
            succeeded(result)
            return result
        return execution.step('identity-'+t['id']+'-'+tool,action) if execution else action(None)
    rust=inspect('rustc',['-Vv'])
    cargo=inspect('cargo',['--version'])
    if not stdout(rust).startswith('rustc ' + t['version'] + ' ') or not stdout(cargo).startswith('cargo ' + t['version'] + ' '):
        raise PolicyError('TOOLCHAIN_CHANGED')
    return {**t, 'rustc_vv': stdout(rust).strip(), 'cargo_version': stdout(cargo).strip(),
            'executables': {tool: sha(root/'bin'/tool) for tool in ('cargo','rustc','rustdoc')}}

BTF_REV = '0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0'
BTF_URL = 'https://github.com/retis-org/btf-rs'
BTF_SOURCE = 'git+' + BTF_URL + '?rev=' + BTF_REV + '#' + BTF_REV


def map_btf_manifest(raw, package_root):
    before = tomllib.loads(raw)
    dep = before.get('dependencies', {}).get('btf-rs')
    if not isinstance(dep, dict) or dep.get('git') != BTF_URL or dep.get('rev') != BTF_REV or 'path' in dep or 'package' in dep:
        raise PolicyError('SOURCE_MAPPING')
    expected = json.loads(json.dumps(before))
    mapped = expected['dependencies']['btf-rs']; del mapped['git']; del mapped['rev']; mapped['path'] = str(package_root)
    # Only two exact scalar tokens change; compare the parsed entire document.
    effective, n = re.subn(r'\bgit\s*=\s*[\"\']' + re.escape(BTF_URL) + r'[\"\']',
                           'path = ' + json.dumps(str(package_root)), raw)
    effective, k = re.subn(r'\brev\s*=\s*[\"\']' + BTF_REV + r'[\"\']\s*,?', '', effective)
    # Removing a final inline-table entry can leave a trailing comma, valid TOML.
    if n != 1 or k != 1 or tomllib.loads(effective) != expected:
        raise PolicyError('SOURCE_MAPPING')
    return effective


def verify_bundle_records(records):
    if not isinstance(records, list) or not records:
        raise InputError('SCHEMA_BUNDLE_FILES')
    names = []
    for r in records:
        exact(r, {'path','kind','sha256','link_target'})
        relative(Path('/'), r['path'], False); digest(r['sha256'])
        if r['kind'] == 'file':
            if r['link_target'] is not None: raise InputError('SCHEMA_BUNDLE_LINK')
        elif r['kind'] == 'symlink':
            text(r['link_target'])
            if hashlib.sha256(r['link_target'].encode()).hexdigest() != r['sha256']:
                raise InputError('SCHEMA_BUNDLE_LINK_HASH')
        else:
            raise InputError('SCHEMA_BUNDLE_KIND')
        names.append(r['path'])
    if names != sorted(set(names)):
        raise InputError('SCHEMA_BUNDLE_ORDER')


def vendor_config(raw, root):
    data = tomllib.loads(raw)
    try:
        exact(data, {'source'})
        exact(data['source'], {'crates-io','vendored-sources'})
        exact(data['source']['crates-io'], {'replace-with'})
        exact(data['source']['vendored-sources'], {'directory'})
    except InputError:
        raise PolicyError('CARGO_CONFIG_NEEDS_DECISION','BLOCKED') from None
    if data['source']['crates-io']['replace-with'] != 'vendored-sources' or data['source']['vendored-sources']['directory'] != str(root):
        raise PolicyError('CARGO_CONFIG_NEEDS_DECISION', 'BLOCKED')


def verify_vendor_package(root, record):
    checksum = root / '.cargo-checksum.json'
    check_hash(checksum, record['checksum_file_sha256'])
    data = read_json(checksum)
    exact(data, {'files','package'})
    if data['package'] != record['sha256'] or not isinstance(data['files'], dict):
        raise PolicyError('INPUT_CHANGED')
    for name, expected in data['files'].items():
        check_hash(relative(root, name), expected)
    manifest = tomllib.loads((root / 'Cargo.toml').read_text())
    if (manifest['package']['name'], manifest['package']['version']) != (record['name'], record['version']):
        raise PolicyError('SOURCE_IDENTITY_MISMATCH')


def stage_inputs(reference, output):
    inventory_path = absolute(reference['inventory'])
    check_hash(inventory_path, reference['sha256'])
    inv = read_json(inventory_path)
    exact(inv, {'schema_version','cargo_vendor','registry_packages','source_bundles'})
    if type(inv['schema_version']) is not int or inv['schema_version'] != 1:
        raise InputError('SCHEMA_INVENTORY_VERSION')
    v = inv['cargo_vendor']
    exact(v, {'root','tree_sha256','config','config_sha256','cargo_version','cargo_executable_sha256','acquisition_locks'})
    root = absolute(v['root']); config = absolute(v['config'])
    if not root.is_dir(): raise PolicyError('SOURCE_UNAVAILABLE', 'BLOCKED')
    if v['cargo_version'] != '1.88.0' and not re.fullmatch(r'cargo 1\.88\.0 \([^\n]+\)',v['cargo_version']): raise InputError('SCHEMA_ACQUISITION_CARGO')
    check_hash('/home/user/.rustup/toolchains/1.88.0-'+HOST+'/bin/cargo', v['cargo_executable_sha256'])
    digest(v['tree_sha256'])
    if tree_digest(root) != v['tree_sha256']: raise PolicyError('INPUT_CHANGED')
    check_hash(config, v['config_sha256']); vendor_config(config.read_text(), root)
    if not isinstance(v['acquisition_locks'], list) or not v['acquisition_locks']:
        raise InputError('SCHEMA_ACQUISITION_LOCKS')
    registry_locks = {}
    for lock in v['acquisition_locks']:
        exact(lock, {'manifest','manifest_sha256','lock','lock_sha256'})
        for key in ('manifest','lock'):
            check_hash(absolute(lock[key]), lock[key+'_sha256'])
        lockdata = tomllib.loads(Path(lock['lock']).read_text())
        for package in lockdata.get('package', []):
            if package.get('source') == REGISTRY:
                key = (package['name'], package['version'])
                checksum = package.get('checksum')
                if key in registry_locks and registry_locks[key] != checksum:
                    raise PolicyError('CONFLICTING_SOURCE_IDENTITY')
                registry_locks[key] = checksum
    seen = set(); dirs = set()
    for package in inv['registry_packages']:
        exact(package, {'name','version','source','archive','sha256','vendor_subdir','checksum_file_sha256'})
        for key in ('name','version'): text(package[key])
        if package['source'] != REGISTRY: raise InputError('SCHEMA_REGISTRY_SOURCE')
        key = (package['name'], package['version'])
        if key in seen: raise InputError('SCHEMA_DUPLICATE_PACKAGE')
        seen.add(key)
        if registry_locks.get(key) != package['sha256']: raise PolicyError('LOCK_CHECKSUM_MISMATCH')
        check_hash(absolute(package['archive']), package['sha256'])
        package_root = relative(root, package['vendor_subdir'])
        if '/' in package['vendor_subdir']: raise InputError('SCHEMA_VENDOR_SUBDIR')
        dirs.add(package['vendor_subdir']); verify_vendor_package(package_root, package)
    if seen != set(registry_locks): raise PolicyError('OFFLINE_CLOSURE_INCOMPLETE', 'BLOCKED')
    if set(p.name for p in root.iterdir()) != dirs: raise PolicyError('UNLISTED_VENDOR_PACKAGE')
    destination = Path(output) / 'cargo-inputs'
    destination.mkdir(mode=0o700)
    copied = destination / 'vendor'
    shutil.copytree(root, copied, symlinks=True)
    if tree_digest(copied) != v['tree_sha256']: raise PolicyError('INPUT_CHANGED')
    effective = ('[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
                 '[source.vendored-sources]\ndirectory = ' + json.dumps(str(copied)) + '\n\n[net]\noffline = true\n')
    cargo_home = Path(output) / 'cargo-home'; cargo_home.mkdir(exist_ok=True, mode=0o700)
    (cargo_home / 'config.toml').write_text(effective)
    staged = [{'kind': 'cargo-vendor', 'input_sha256': v['tree_sha256'], 'path': str(copied),
               'original_config_sha256': v['config_sha256'], 'effective_config_sha256': sha(cargo_home/'config.toml'),
               'acquisition_locks': v['acquisition_locks']}]
    packages = []
    for r in inv['registry_packages']:
        packages.append({**r, 'root': copied/r['vendor_subdir']})
        staged.append({'kind':'registry','name':r['name'],'version':r['version'],'source':r['source'],
                       'input_sha256':r['sha256'],'source_sha256':r['sha256'],'path':str(copied/r['vendor_subdir'])})
    for bundle in inv['source_bundles']:
        exact(bundle, {'id','source','archive','archive_sha256','strip_prefix','files','packages','allowed_path_edges'})
        if not IDENT.fullmatch(bundle['id']) or bundle['source'] != BTF_SOURCE:
            raise InputError('SCHEMA_BUNDLE_SOURCE')
        relative(Path('/'), bundle['strip_prefix'], False)
        if '/' in bundle['strip_prefix']: raise InputError('SCHEMA_STRIP_PREFIX')
        verify_bundle_records(bundle['files']); selected_hash = hash_value(bundle['files'])
        check_hash(absolute(bundle['archive']), bundle['archive_sha256'])
        dest = destination/'bundles'/bundle['id']; dest.mkdir(parents=True, mode=0o700)
        wanted = {r['path']:r for r in bundle['files']}; found = set()
        with tarfile.open(bundle['archive'], 'r:*') as tar:
            for member in tar:
                prefix = bundle['strip_prefix'] + '/'
                if not member.name.startswith(prefix): continue
                name = member.name[len(prefix):]
                if name not in wanted: continue
                if name in found: raise InputError('BUNDLE_DUPLICATE_PATH')
                found.add(name); entry = wanted[name]; target = relative(dest, name, False)
                target.parent.mkdir(parents=True, exist_ok=True)
                if entry['kind'] == 'file' and member.isfile():
                    stream = tar.extractfile(member)
                    with target.open('xb') as out: shutil.copyfileobj(stream, out)
                    check_hash(target, entry['sha256'])
                elif entry['kind'] == 'symlink' and member.issym() and member.linkname == entry['link_target']:
                    target.symlink_to(member.linkname)
                else:
                    raise InputError('BUNDLE_FILE_TYPE')
        if found != set(wanted) or tree_records(dest) != bundle['files']:
            raise PolicyError('INPUT_CHANGED')
        names = set()
        for package in bundle['packages']:
            exact(package, {'name','version','manifest','source_sha256'})
            if package['name'] in names or package['source_sha256'] != selected_hash:
                raise InputError('SCHEMA_BUNDLE_PACKAGE')
            names.add(package['name'])
            manifest = relative(dest, package['manifest']); data = tomllib.loads(manifest.read_text())['package']
            def workspace_value(key):
                value = data[key]
                if isinstance(value, dict) and value.get('workspace') is True:
                    value = tomllib.loads((dest/'Cargo.toml').read_text())['workspace']['package'][key]
                return value
            if (workspace_value('name'), workspace_value('version')) != (package['name'], package['version']):
                raise PolicyError('SOURCE_IDENTITY_MISMATCH')
            packages.append({**package, 'source':bundle['source'], 'sha256':selected_hash, 'root':manifest.parent, 'bundle_root':dest, 'bundle':bundle})
        if bundle['allowed_path_edges'] != [{'from':'btf-rs','to':'btf-rs-derive'}] or names != {'btf-rs','btf-rs-derive'}:
            raise InputError('SCHEMA_BUNDLE_EDGES')
        staged.append({'kind':'bundle','source':bundle['source'],'archive_sha256':bundle['archive_sha256'],
                       'input_sha256':selected_hash,'source_sha256':selected_hash,'path':str(dest)})
    return {'inventory':inv, 'packages':packages, 'staged_inputs':staged, 'output':Path(output)}


def staged_edges(staging):
    result = []
    bundles = [p for p in staging['packages'] if 'bundle' in p]
    for package in bundles:
        for edge in package['bundle']['allowed_path_edges']:
            if edge['from'] == package['name']:
                target = next(p for p in bundles if p['name'] == edge['to'])
                result.append((package['root']/'Cargo.toml', target['root']))
    return result


def admit(metadata, allowed, approved, staging, trusted, denied=()):
    """Inspect every resolved manifest, conservatively including inactive targets."""
    actual = []
    records = {(r['name'],r['version'],r['source']):r for r in allowed}
    grants = {(r['name'],r['version'],r['source']):r for r in approved}
    trust = {str(Path(p).resolve()): identity for p,identity in trusted.items()}
    edges = staged_edges(staging)
    # The only external client edges are exact generated subject edges.
    for identity in trust.values():
        edges.extend(identity.get('edges', []))
    for p in metadata['packages']:
        manifest = Path(p['manifest_path']).resolve()
        info = inspect_manifest(manifest, edges)
        if p['name'] in denied or p.get('links'):
            raise PolicyError('POLICY_REJECTED')
        targets = p['targets']
        script_targets = [t for t in targets if 'custom-build' in t['kind']]
        macro = any('proc-macro' in t['kind'] for t in targets)
        if str(manifest) in trust:
            identity = trust[str(manifest)]
            if not script_targets and not macro:
                continue
            source, package_sha = identity['source'], identity['sha256']
        else:
            entry = next((r for r in staging['packages'] if (r['root']/'Cargo.toml').resolve() == manifest), None)
            if entry is None:
                raise PolicyError('SOURCE_UNAVAILABLE', 'BLOCKED')
            if p['source'] not in (None, entry['source']):
                raise PolicyError('SOURCE_IDENTITY_MISMATCH')
            source, package_sha = entry['source'], entry['sha256']
            if 'bundle' in entry:
                if tree_records(entry['bundle_root']) != entry['bundle']['files']:
                    raise PolicyError('INPUT_CHANGED')
            else:
                verify_vendor_package(entry['root'], entry)
            key = (p['name'],p['version'],source)
            permit = records.get(key)
            if permit is None:
                raise PolicyError('DEPENDENCY_NOT_ALLOWED', 'BLOCKED')
            if permit['sha256'] != package_sha:
                raise PolicyError('INPUT_CHANGED')
            kinds = {dep['kind'] for owner in metadata['packages'] for dep in owner['dependencies']
                     if (dep.get('rename') or dep['name']) and dep['name'] == p['name']}
            role = 'host-proc-macro' if macro else 'host-build' if script_targets or ('build' in kinds and None not in kinds and 'dev' not in kinds) else 'host-rust'
            if permit['role'] != role:
                raise PolicyError('DEPENDENCY_ROLE_MISMATCH')
        key = (p['name'],p['version'],source)
        if script_targets or macro:
            grant = grants.get(key)
            script = str(Path(script_targets[0]['src_path']).relative_to(manifest.parent)) if script_targets else None
            if grant is None:
                raise PolicyError('APPROVAL_REQUIRED', 'BLOCKED')
            if grant['sha256'] != package_sha:
                raise PolicyError('APPROVED_INPUT_CHANGED')
            if str(manifest) in trust:
                verify_trusted_mapping(identity,manifest.parent)
            if grant['build_script'] != script:
                raise PolicyError('APPROVED_BUILD_TARGET_CHANGED')
            if macro and script_targets and not ('proc-macro' in grant['reason'] and 'build' in grant['reason']):
                raise PolicyError('APPROVAL_ROLE_INCOMPLETE', 'BLOCKED')
        actual.append({'id':p['id'],'name':p['name'],'version':p['version'],'source':source,
                       'local_source':p['source'],'manifest':str(manifest),'sha256':package_sha,
                       'target_kinds':[t['kind'] for t in targets]})
    return actual

class Execution:
    """Small sequential stage recorder; not an extensible scheduler."""
    def __init__(self, tool, matrix_path, matrix, output, manifest=None, scope='full', omitted=None):
        self.output = Path(output)
        self.matrix = matrix
        self.omitted = omitted or []
        self.report = {'schema_version':1, 'tool':tool, 'cargo_inputs_sha256':matrix['cargo_inputs']['sha256'],
                       'staged_inputs':[], 'scope':scope, 'matrix_sha256':sha(matrix_path),
                       'manifest_sha256':sha(manifest) if manifest else None,
                       'product_base':subprocess.check_output(['git','rev-parse','HEAD'], cwd=Path(__file__).resolve().parents[2],
                                                           env={'PATH':'/usr/bin:/bin','GIT_NO_LAZY_FETCH':'1'}, text=True).strip(),
                       'toolchains':[], 'rows':[], 'summary':None, 'product_qualification':False}
        self.by_id = {}
        self.process_results = {}
        self.staging = None
        self.reserve('tool-error',role='tool',phase='unowned-error',required=False)

    def reserve(self, ident, role='probe', toolchain=None, phase='input', required=True):
        if ident in self.by_id: raise InputError('DUPLICATE_ROW')
        r = row(ident,role,required,toolchain,phase)
        self.by_id[ident] = r; self.report['rows'].append(r)

    def step(self, ident, action, fit='SATISFIED'):
        r = self.by_id[ident]; start = time.monotonic()
        try:
            value = action(r)
            r.update(status='PASS', fit=fit, reason_code='ASSERTIONS_MET', cleanup='complete')
            return value
        except PolicyError as e:
            if getattr(e,'recorded_by',None) is self: raise
            e.recorded_by=self
            result=self.process_results.get(ident)
            if result is not None and not (isinstance(e.detail,dict) and 'cleanup' in e.detail):
                e.detail={**result,'policy_detail':e.detail}
            r.update(status=e.status,reason_code=e.code,fit='UNKNOWN',observed=e.detail)
            if isinstance(e.detail,dict) and 'cleanup' in e.detail:
                self.attach(r,e.detail)
            raise
        except (InputError, tomllib.TOMLDecodeError):
            raise
        except Exception as e:
            result=self.process_results.get(ident)
            detail={'exception':type(e).__name__} if result is None else {
                **result,'reason_code':result.get('reason_code') or 'INTERNAL_ERROR',
                'errors':result.get('errors',[])+[{'stage':'postprocess','exception':type(e).__name__,'message':str(e)[:512]}]}
            code='CLEANUP_UNRESOLVED' if result and result['cleanup']=='unresolved' else 'INTERNAL_ERROR'
            status='BLOCKED' if code=='CLEANUP_UNRESOLVED' else 'FAIL'
            r.update(status=status,reason_code=code,observed=detail)
            if result: self.attach(r,detail)
            failure=PolicyError(code,status,detail)
            failure.recorded_by=self
            raise failure from e
        finally:
            r['duration_ms'] = round((time.monotonic()-start)*1000)

    def attach(self,r,result):
        self.process_results[r['id']]=result
        for key in ('command','cwd','logs','duration_ms','cleanup'):
            r[key] = result[key]
        if result.get('process_group') and result['cleanup'] == 'unresolved':
            r['observed'] = {**result,'owner':str(self.output)}

    def command(self, r, t, manifest, arguments, target, features=(), defaults=True, failure='CARGO_FAILED', extra_env=None, budget=None, lock_path=None):
        env = clean_env(self.output,t,target)
        if extra_env: env.update(extra_env)
        argv = [Path(t['root'])/'bin/cargo', *arguments, '--manifest-path',manifest]
        if not defaults: argv.append('--no-default-features')
        if features: argv.extend(['--features',','.join(features)])
        r['input_sha256'] = tree_digest(Path(manifest).parent)
        lock = Path(lock_path) if lock_path is not None else Path(manifest).parent/'Cargo.lock'
        before_lock = sha(lock) if lock.is_file() else None
        r['lock_sha256_before'] = before_lock
        r['lock_path'] = str(lock)
        timeout=budget.remaining() if budget else 600
        if budget: r['expected']={'cell':budget.ident,'wall_budget_seconds':budget.seconds}
        r['command']=[str(a) for a in argv]; r['cwd']=str(Path(manifest).parent)
        result = None
        try:
            result = run(argv,Path(manifest).parent,env,self.output/'logs'/r['id'],timeout=timeout)
        finally:
            if result is not None: self.attach(r,result)
            r['lock_sha256'] = sha(lock) if lock.is_file() else None
            r['input_sha256_after'] = tree_digest(Path(manifest).parent)
        if budget: budget.complete(result)
        # Incomplete collection/cleanup has priority over any interpretation of
        # partial diagnostics or post-command lock/log processing.
        if result['reason_code'] or result['cleanup']=='unresolved': succeeded(result,failure)
        if '--locked' in arguments and before_lock != r['lock_sha256']:
            raise PolicyError('LOCK_CHANGED')
        diagnostic = Path(result['logs']['stderr']['path']).read_text(errors='replace')
        if result['exit_code'] != 0 and '--locked' in arguments and (
                ('needs to be updated' in diagnostic and '--locked' in diagnostic) or
                any(line.startswith(('error: cannot create the lock file ', 'error: cannot update the lock file '))
                    and line.endswith(' because --locked was passed to prevent this')
                    for line in diagnostic.splitlines())):
            raise PolicyError('LOCK_REQUIRED', detail=result)
        if result['exit_code'] != 0 and ('offline' in Path(result['logs']['stderr']['path']).read_text(errors='replace').lower()) and arguments[0] in ('metadata','generate-lockfile'):
            raise PolicyError('OFFLINE_CLOSURE_INCOMPLETE','BLOCKED',result)
        succeeded(result,failure)
        return result

    def abort(self,error,report_path):
        if getattr(error,'recorded_by',None) is not self:
            r=self.by_id['tool-error']
            r.update(required=True,status=getattr(error,'status','FAIL'),reason_code=getattr(error,'code','INTERNAL_ERROR'),observed={'exception':type(error).__name__})
        return self.finish(report_path)

    def finish(self, report_path):
        guard=self.by_id['tool-error']
        if guard['status']=='NOT_RUN': guard.update(status='PASS',fit='NOT_APPLICABLE',reason_code='NO_UNOWNED_ERROR')
        self.report['summary'] = summarize(self.report['rows'],list(self.by_id),self.omitted)
        kind='probe' if self.report['tool']=='dependency_probe' else 'features'
        declared=validate_expansion(self.matrix,kind)
        selected=declared if kind=='features' else len(self.matrix['toolchains'])*sum(1+len(c['compile_refusals']) for c in self.matrix['cases'] if c['id']+'-source' in self.by_id)
        self.report['summary'].update(declared_compiler_cells=declared,selected_compiler_cells=selected)
        atomic_json(report_path,self.report)
        print(json.dumps({'report':str(Path(report_path).absolute()),'status':self.report['summary']['status'],
                          'counts':self.report['summary']['counts']},separators=(',',':')))
        return self.report['summary']['exit_code']


def metadata_admission(execution, r, t, manifest, target, allowed, trusted, denied=(), features=(), defaults=True, budget=None, lock_path=None):
    result = execution.command(r,t,manifest,['metadata','--offline','--locked','--format-version','1','--filter-platform',HOST],target,features,defaults,budget=budget,lock_path=lock_path)
    try: data = json.loads(stdout(result),object_pairs_hook=pairs)
    except ValueError as e: raise PolicyError('METADATA_INVALID') from e
    resolved = admit(data,allowed,execution.matrix['approved_build_inputs'],execution.staging,trusted,denied)
    r['resolved_packages'] = resolved
    r['resolved_features'] = {n['id']:n['features'] for n in data['resolve']['nodes']}
    return data


def safe_unpack(archive, destination, expected_prefix):
    destination = Path(destination); destination.mkdir(parents=True)
    names = set()
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != expected_prefix:
                raise PolicyError('ARCHIVE_PATH_ESCAPE')
            if member.isdir(): continue
            if not member.isfile() or member.name in names:
                raise PolicyError('ARCHIVE_FILE_TYPE')
            names.add(member.name)
            target = relative(destination,member.name,False); target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as out: shutil.copyfileobj(tar.extractfile(member),out)
    return destination/expected_prefix


def source_copy(source, destination):
    source = Path(source)
    inspect_config_ancestors(source)
    records = tree_records(source)
    if sum((source/r['path']).stat().st_size for r in records) > MAX_JSON:
        raise InputError('FIXTURE_BYTE_BOUND')
    if any(set(PurePosixPath(r['path']).parts) & {'target','.git','.cargo'} for r in records):
        raise InputError('GENERATED_SOURCE_INPUT')
    shutil.copytree(source,destination,symlinks=True)
    if tree_records(destination) != records: raise PolicyError('INPUT_CHANGED')
    return Path(destination)


def validate_report_target(path, sources):
    path=absolute(str(path)); no_symlink_ancestors(path)
    if path.exists(): raise InputError('REPORT_EXISTS')
    if any(path.resolve().is_relative_to(Path(root).resolve()) for root in sources):
        raise InputError('REPORT_INSIDE_SOURCE')
    if path.parent.exists() and path.parent.stat().st_uid != os.getuid():
        raise InputError('REPORT_NOT_OWNED')


def fixture_inventory(root):
    records=tree_records(root)
    if any(r['kind']!='file' for r in records): raise InputError('FIXTURE_SYMLINK')
    return [{'path':r['path'],'sha256':r['sha256']} for r in records]


def original_grant(root, source, approved):
    records=fixture_inventory(root); value=fixture_digest(root)
    info=inspect_manifest(Path(root)/'Cargo.toml'); package=info['data']['package']
    manifest_surface(info['data'])
    macro=info['data'].get('lib',{}).get('proc-macro',False)
    if info['build_script'] or macro:
        grant=next((r for r in approved if (r['name'],r['version'],r['source'])==(package['name'],package['version'],source)),None)
        if grant is None: raise PolicyError('APPROVAL_REQUIRED','BLOCKED')
        if grant['sha256']!=value: raise PolicyError('APPROVED_INPUT_CHANGED')
        if grant['build_script']!=info['build_script']: raise PolicyError('APPROVED_BUILD_TARGET_CHANGED')
    return {'source':source,'sha256':value,'original_root':str(root),'original_files':records}


def verify_original(grant):
    if fixture_inventory(grant['original_root'])!=grant['original_files'] or hash_value(grant['original_files'])!=grant['sha256']:
        raise PolicyError('APPROVED_INPUT_CHANGED')


def copied_mapping(grant, root):
    verify_original(grant)
    original={r['path']:r['sha256'] for r in grant['original_files']}
    actual={r['path']:r['sha256'] for r in fixture_inventory(root)}
    if set(actual)-set(original) != ({'Cargo.lock'} if 'Cargo.lock' not in original else set()):
        raise PolicyError('APPROVED_INPUT_CHANGED')
    if any(actual.get(name)!=digest for name,digest in original.items()):
        raise PolicyError('APPROVED_INPUT_CHANGED')
    return {**grant,'mapped_files':fixture_inventory(root),'original_lock_sha256':original.get('Cargo.lock'),
            'generated_lock_sha256':actual.get('Cargo.lock'),'mapping':'copied-source'}


def verify_trusted_mapping(identity,root):
    if 'mapped_files' not in identity:
        if fixture_digest(root)!=identity['sha256']: raise PolicyError('APPROVED_INPUT_CHANGED')
        return
    verify_original(identity)
    if fixture_inventory(root)!=identity['mapped_files']: raise PolicyError('APPROVED_INPUT_CHANGED')


def archive_mapping(grant,copied,unpacked,archive,allowed):
    verify_trusted_mapping(grant,copied)
    records={r['path']:r['sha256'] for r in fixture_inventory(unpacked)}
    original={r['path']:r['sha256'] for r in grant['original_files']}
    package_files(list(records),allowed)
    if records.get('Cargo.toml.orig')!=original['Cargo.toml']: raise PolicyError('ARCHIVE_MANIFEST_CHANGED')
    if records.get('Cargo.lock')!=grant['generated_lock_sha256']: raise PolicyError('ARCHIVE_LOCK_CHANGED')
    generated={'Cargo.toml','Cargo.toml.orig','Cargo.lock'}
    for name,value in records.items():
        if name not in generated and original.get(name)!=value: raise PolicyError('ARCHIVE_SOURCE_CHANGED')
    # No unspecified generated file, including VCS metadata, acquires authority.
    # The present copied fixture roots deliberately have no VCS metadata.
    return {**grant,'mapped_files':fixture_inventory(unpacked),'mapping':'cargo-archive',
            'archive_sha256':sha(archive),'normalized_manifest_sha256':records['Cargo.toml']}


def manifest_surface(data):
    """Bound the subject/archive mapping to fields Cargo metadata can verify.

    This is an admission list, not a manifest normalizer. Unsupported compilation
    controls require a future explicit mapping contract before they can execute.
    """
    package_fields={'name','version','authors','edition','rust-version','description','documentation',
                    'readme','homepage','repository','license','license-file','keywords','categories',
                    'build','links','exclude','include','publish','metadata','default-run','resolver',
                    'autolib','autobins','autoexamples','autotests','autobenches'}
    dependency_tables={'dependencies','dev-dependencies','build-dependencies'}
    target_tables={'lib','bin','example','test','bench'}
    target_fields={'name','path','edition','crate-type','proc-macro','required-features','test','doctest','doc'}
    dependency_fields={'version','package','optional','default-features','features','registry','registry-index','path'}
    def supported(condition):
        if not condition: raise PolicyError('MANIFEST_SURFACE_UNSUPPORTED','BLOCKED')
    supported(set(data)<=({'package','workspace','features','target','lints','badges'}|dependency_tables|target_tables))
    supported(isinstance(data.get('package'),dict) and set(data['package'])<=package_fields)
    # A standalone empty workspace may disappear in Cargo's archive. Inheritance,
    # workspace resolver/defaults, profiles and unstable fields are not admitted.
    supported(data.get('workspace',{})=={})
    def dependencies(tables):
        supported(isinstance(tables,dict) and set(tables)<=dependency_tables)
        for table in tables.values():
            supported(isinstance(table,dict))
            for dependency in table.values():
                supported(isinstance(dependency,str) or (isinstance(dependency,dict) and set(dependency)<=dependency_fields))
    dependencies({k:data[k] for k in dependency_tables if k in data})
    supported(isinstance(data.get('target',{}),dict))
    for tables in data.get('target',{}).values(): dependencies(tables)
    for name in target_tables:
        targets=[data[name]] if name=='lib' and name in data else data.get(name,[])
        supported(isinstance(targets,list))
        for target in targets: supported(isinstance(target,dict) and set(target)<=target_fields)
    # Metadata resolves target discovery/build paths and effective defaults. It
    # does not expose these packaging/resolver/lint tables, so require equality.
    return {'package':{k:data['package'].get(k) for k in ('include','exclude','resolver')},
            'lints':data.get('lints',{}),'badges':data.get('badges',{})}


def package_semantics(metadata,manifest):
    """Compare whole Cargo metadata plus the explicitly admitted raw surface."""
    manifest=Path(manifest).resolve(); root=manifest.parent
    package=next(v for v in metadata['packages'] if Path(v['manifest_path']).resolve()==manifest)
    # Only opaque package identity and its owned-root manifest path relocate.
    # Keep all other keys, including new Cargo metadata, rather than dropping
    # build-visible values such as CARGO_PKG_AUTHORS/DESCRIPTION/README.
    result={k:v for k,v in package.items() if k not in ('id','manifest_path')}
    def local_path(value):
        if value is None: return None
        # Relative package strings are build-visible (for example README and
        # ./README need not be interchangeable to an approved build script).
        if not Path(value).is_absolute(): return value
        return str(Path(value).resolve().relative_to(root))
    for key in ('readme','license_file'):
        if key in result: result[key]=local_path(result[key])
    result['features']={k:sorted(v) for k,v in package['features'].items()}
    result['dependencies']=sorted(package['dependencies'],key=compact)
    result['targets']=sorted([{**t,'src_path':local_path(t['src_path'])} for t in package['targets']],key=compact)
    result['manifest_surface']=manifest_surface(tomllib.loads(manifest.read_text()))
    return result


def record_transformation(ex,identity,root):
    record={'kind':'fixture-transformation','mapping':identity['mapping'],'path':str(root),
            'original_source_sha256':identity['sha256'],'original_files':identity['original_files'],
            'original_lock_sha256':identity['original_lock_sha256'],'generated_lock_sha256':identity['generated_lock_sha256'],
            'mapped_source_sha256':hash_value(identity['mapped_files'])}
    if 'metadata_semantics_sha256' in identity: record['metadata_semantics_sha256']=identity['metadata_semantics_sha256']
    for name in ('archive_sha256','normalized_manifest_sha256'):
        if name in identity: record[name]=identity[name]
    ex.report['staged_inputs'].append(record)


def probe_case_row_ids(case,toolchains):
    prefix=case['id']; ids=[prefix+'-source',prefix+'-prepare']
    ids += [prefix+'-'+t['id']+'-'+phase for t in toolchains for phase in ('admit','check','test','doc')]
    for refusal in case['compile_refusals']:
        stem=prefix+'-'+refusal['id']; ids += [stem+'-prepare',stem+'-lock']
        ids += [stem+'-'+t['id']+'-'+phase for t in toolchains for phase in ('admit','refusal')]
    return ids


def validate_expansion(matrix,kind):
    toolchains=matrix['toolchains']
    ids=['tool-error','inputs']+['identity-'+t['id']+suffix for t in toolchains for suffix in ('','-rustc','-cargo')]
    if kind=='probe':
        cells=len(toolchains)*sum(1+len(c['compile_refusals']) for c in matrix['cases'])
        for case in matrix['cases']: ids += probe_case_row_ids(case,toolchains)
    else:
        entries=matrix['fixture_members']+matrix['members']
        cells=len(toolchains)*sum(2+len(m['supported_unions']) for m in entries)
        ids += ['root-'+t['id'] for t in toolchains]
        for member in entries:
            prefix=member['id']
            ids += [prefix+'-'+phase for phase in ('source','lock','admit','package-list-msrv','package-list-current','package','archive','archive-metadata')]
            for mode in ['minimal','default']+['union-'+str(i) for i in range(len(member['supported_unions']))]:
                stem=prefix+'-'+mode; ids += [stem+'-prepare',stem+'-lock']
                clients=member['clients'] if mode.startswith('union-') else member['clients'][:1]
                ids += [stem+'-'+t['id']+'-'+phase for t in toolchains for phase in ['admit','check','test','doc']+['run-'+c['id'] for c in clients]]
    if cells>128: raise InputError('SCHEMA_CELL_BOUND')
    if len(ids)!=len(set(ids)) or any(len(ident.encode())>240 for ident in ids):
        raise InputError('SCHEMA_ROW_ID_COLLISION_OR_BOUND')
    return cells


class CellBudget:
    """One monotonic wall deadline across the sequential phases of one cell."""
    def __init__(self,ident,seconds=600,clock=None):
        self.ident=ident; self.seconds=seconds; self.clock=clock or time.monotonic
        self.started=self.clock(); self.deadline=self.started+seconds

    def remaining(self):
        value=self.deadline-self.clock()
        if value<=0:
            raise PolicyError('TIMEOUT','BLOCKED',{'cell':self.ident,'budget_seconds':self.seconds,'elapsed_ms':round((self.clock()-self.started)*1000)})
        return value

    def complete(self,result):
        if self.clock()>=self.deadline and result['reason_code'] is None:
            result['reason_code']='TIMEOUT'


def verify_package_semantics(original,original_manifest,normalized,normalized_manifest):
    expected=package_semantics(original,original_manifest)
    actual=package_semantics(normalized,normalized_manifest)
    if actual!=expected:
        raise PolicyError('ARCHIVE_SEMANTICS_CHANGED',detail={'expected':expected,'observed':actual})
    return hash_value(actual)
