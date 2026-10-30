#!/usr/bin/env python3
"""Prepare native ScopeBase jobs and immutable review inputs; never launch workers."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone


REGISTRY = 'docs/superpowers/plans/2026-10-17-scopebase-traceability.json'
MASTER_PLAN = 'docs/superpowers/plans/2026-10-17-scopebase.md'
POLICY = 'orchestration/policy.json'
RULES = 'orchestration/common-rules.md'
TEMPLATES = [f'orchestration/templates/{name}.md' for name in ('worker', 'reviewer', 'fix', 'report')]
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
ACCEPTED = {'DONE', 'COMPLETE', 'ACCEPTED'}
GOAL_LIMIT = 65536
ROLES = {
    'implementer': ('native', 'gpt-6.1-sol', False, {'high', 'xhigh'}),
    'implementer-escalated': ('native', 'gpt-6.1-sol', False, {'max'}),
    'reviewer': ('native', 'gpt-6.1-sol', True, {'high', 'xhigh'}),
    'critical-reviewer': ('native', 'gpt-6.1-sol', True, {'max'}),
    'architecture': ('native', 'gpt-6.1-sol', True, {'max'}),
    'exceptional-reviewer': ('native', 'gpt-6-astra', True, {'xhigh', 'max'}),
    'mechanical': ('native', 'gpt-6-luna', False, {'medium', 'high'}),
    'muse-reviewer': ('muse', 'muse-spark-1.3', True, {'max'}),
}


class JobError(Exception):
    """A refusal that preserves existing jobs and repository resources."""


def require(condition, message):
    if not condition:
        raise JobError(message)


def git(repo, *args, binary=False):
    # Worktree checkout/status must not invoke an installed filter (for example an
    # LFS network fetch). Disable configured drivers only for this command; no
    # user's configuration or existing worktree is changed.
    configured = subprocess.run(['git', '-C', str(repo), 'config', '--name-only', '--get-regexp',
                                 r'^filter\..*\.[^.]+$'], capture_output=True, text=True)
    require(configured.returncode in (0, 1), 'cannot inspect local Git filter configuration')
    overrides = ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false']
    for driver in sorted({key.rsplit('.', 1)[0] for key in configured.stdout.splitlines()}):
        for field, value in (('clean', ''), ('smudge', ''), ('process', ''), ('required', 'false')):
            overrides.extend(['-c', f'{driver}.{field}={value}'])
    result = subprocess.run(['git', *overrides, '-C', str(repo), *args], capture_output=True, text=not binary,
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1'))
    if result.returncode:
        error = result.stderr.decode(errors='replace') if binary else result.stderr
        raise JobError(f'Git command failed: {error.strip()}')
    return result.stdout


def commit(repo, ref):
    require(ref and not ref.startswith('-'), 'invalid base/head reference')
    return git(repo, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}').strip()


def repository(path):
    source = Path(git(Path(path).resolve(), 'rev-parse', '--show-toplevel').strip()).resolve()
    require(git(source, 'rev-parse', '--is-bare-repository').strip() == 'false', 'bare repository refused')
    common = Path(git(source, 'rev-parse', '--git-common-dir').strip())
    if not common.is_absolute():
        common = source / common
    common = common.resolve()
    require(common.name == '.git', 'Git-common root must be a normal .git directory')
    return source, common.parent, common


def regular_bytes(path, limit=None):
    path = Path(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), f'not a regular file: {path}')
            content = stream.read(limit + 1 if limit is not None else -1)
    except OSError as exc:
        raise JobError(f'file/symlink refusal for {path}: {exc}') from exc
    if limit is not None:
        require(len(content) <= limit, f'file exceeds {limit} byte bound: {path}')
    return content


def decode_text(content, label):
    try:
        text = content.decode('utf-8')
    except UnicodeError as exc:
        raise JobError(f'{label} must be UTF-8 text') from exc
    require('\0' not in text, f'{label} contains NUL')
    return text


def json_file(path):
    try:
        return json.loads(decode_text(regular_bytes(path), str(path)))
    except (ValueError, TypeError) as exc:
        raise JobError(f'malformed JSON in {path}: {exc}') from exc


def digest(content):
    return hashlib.sha256(content).hexdigest()


def private_directory(path, require_private=True):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    require(not path.is_symlink() and path.is_dir(), f'directory/symlink refusal: {path}')
    require(path.stat().st_uid == os.getuid(), f'directory must be owned by this user: {path}')
    require(not require_private or path.stat().st_mode & 0o077 == 0, f'directory must be private: {path}')


def new_file(path, content):
    if isinstance(content, str):
        content = content.encode()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
    except OSError as exc:
        raise JobError(f'exclusive artifact creation failed: {path}: {exc}') from exc


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def replace_manifest(path, value):
    # Only our exclusively reserved manifest is updated, never another attempt's file.
    temporary = path.with_name('job.json.next')
    new_file(temporary, json_bytes(value))
    os.replace(temporary, path)


@contextmanager
def controller(root):
    state = root / '.scopebase'
    private_directory(state)
    lock = state / 'controller.lock'
    try:
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except OSError as exc:
        raise JobError(f'controller lock/symlink refusal: {exc}') from exc
    with os.fdopen(fd, 'r+b') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                'controller lock must be a private regular file')
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield state
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def identifier(value, label):
    require(isinstance(value, str) and ID.fullmatch(value), f'invalid {label} ID')
    return value


def relative_path(value, repo=None):
    require(isinstance(value, str) and value and not value.startswith('/') and '\\' not in value,
            f'invalid relative path: {value!r}')
    parts = value.split('/')
    require(all(p and p not in ('.', '..', '.git', '.scopebase', '.worktrees', '.superpowers') for p in parts)
            and not any(c in value for c in '*?[]{}\0\n\r'), f'invalid literal path: {value!r}')
    if repo is not None:
        current = repo
        for part in parts:
            current = current / part
            require(not current.is_symlink(), f'ownership path crosses a symlink: {value!r}')
    return value


def overlaps(first, second):
    return first == second or first.startswith(second + '/') or second.startswith(first + '/')


def policy(repo):
    data = json_file(repo / POLICY)
    require(isinstance(data, dict) and data.get('schema_version') == 1, 'invalid policy schema')
    require(isinstance(data.get('roles'), dict) and set(data['roles']) == set(ROLES), 'invalid policy roles')
    for name, (backend, model, readonly, allowed) in ROLES.items():
        entry = data['roles'][name]
        require(isinstance(entry, dict), f'invalid policy role {name}')
        efforts = entry.get('allowed_efforts')
        require(entry.get('backend') == backend and entry.get('model') == model and entry.get('read_only') is readonly,
                f'invalid policy routing for role {name}')
        require(isinstance(efforts, list) and efforts and all(isinstance(e, str) for e in efforts)
                and set(efforts) <= allowed and entry.get('reasoning_effort') in efforts,
                f'invalid policy efforts for role {name}')
        if name in {'implementer-escalated', 'critical-reviewer', 'architecture', 'exceptional-reviewer'}:
            require(entry.get('reason_required') is True, f'{name} policy requires a reason')
        if backend == 'muse':
            require(entry.get('contributor_mode') == 'on', 'Muse policy requires Contributor on')
    require(data.get('native_fork_turns') == 'none', 'native policy must use fresh context (fork_turns none)')
    cap = data.get('max_independent_implementation_lanes')
    require(type(cap) is int and 1 <= cap <= 3, 'invalid policy implementation lane cap')
    require(data.get('heavy_build_slots') == 1 and data.get('muse_max_model_steps') == 32,
            'invalid policy resource/Muse bounds')
    return data


def section(text, heading, level):
    match = re.search(r'^' + re.escape(heading) + r'[^\n]*\n', text, re.MULTILINE)
    require(match is not None, f'plan missing exact section: {heading}')
    following = re.search(r'^#{1,' + str(level) + r'} ', text[match.end():], re.MULTILINE)
    end = match.end() + following.start() if following else len(text)
    return text[match.start():end].rstrip() + '\n'



def task_section(text, task_id):
    pattern = r'^(?:## (?:Task )?' + re.escape(task_id) + r':|### ' + re.escape(task_id) + r':)[^\n]*(?:\n|$)'
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    require(len(matches) == 1, f'plan requires exactly one task heading for {task_id}; found {len(matches)}')
    match = matches[0]
    level = len(match.group().split(' ', 1)[0])
    following = re.search(r'^#{1,' + str(level) + r'} ', text[match.end():], re.MULTILINE)
    end = match.end() + following.start() if following else len(text)
    return text[match.start():end].rstrip() + '\n'


def validate_base_paths(repo, base, allowed):
    # Inspect Git's selected tree, not the caller's newer filesystem view.
    entries = git(repo, 'ls-tree', '-r', '-z', base, binary=True).split(b'\0')
    symlinks = {entry.split(b'\t', 1)[1] for entry in entries
                if entry and entry.split(b' ', 1)[0] == b'120000'}
    for path in allowed:
        parts = path.split('/')
        for end in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:end]).encode('utf-8')
            require(prefix not in symlinks, f'ownership path crosses a selected-base symlink: {path!r}')


def inputs(repo, task_id):
    registry = json_file(repo / REGISTRY)
    tasks = registry.get('tasks') if isinstance(registry, dict) else None
    require(isinstance(tasks, list) and tasks, 'invalid product task registry')
    by_id = {}
    for task in tasks:
        require(isinstance(task, dict), 'malformed registry task')
        key = identifier(task.get('id'), 'task')
        require(key not in by_id, f'duplicate task ID in registry: {key}')
        require(isinstance(task.get('depends_on'), list) and isinstance(task.get('status'), str),
                f'malformed prerequisite/status registry for {key}')
        by_id[key] = task
    require(task_id in by_id, f'unknown task ID: {task_id}')
    for entry in by_id.values():
        require(all(isinstance(dep, str) and dep in by_id for dep in entry['depends_on']),
                f'missing prerequisite registry entry for {entry["id"]}')
    task = by_id[task_id]
    plan = relative_path(task.get('plan'), repo)
    require(plan.startswith('docs/superpowers/plans/') and plan.endswith('.md'), 'invalid task plan path')
    # All normative specs are included, so a selected subsystem cannot omit a master contract.
    specs = sorted(git(repo, 'ls-files', '--', 'docs/superpowers/specs/*.md').splitlines())
    require(specs, 'no tracked specification inputs')
    paths = {REGISTRY, POLICY, 'AGENTS.md', RULES, plan, *TEMPLATES, *specs}
    if (repo / MASTER_PLAN).is_file():
        paths.add(MASTER_PLAN)
    contents = {name: regular_bytes(repo / relative_path(name, repo)) for name in sorted(paths)}
    text = decode_text(contents[plan], plan)
    task_text = task_section(text, task_id)
    constraints = section(text, '## Global Constraints', 2)
    if MASTER_PLAN in contents and MASTER_PLAN != plan:
        constraints = section(decode_text(contents[MASTER_PLAN], MASTER_PLAN), '## Global Constraints', 2) + '\n' + constraints
    return task, by_id, contents, task_text, constraints, specs


def bound_to_commit(repo, base, contents):
    for name, content in contents.items():
        try:
            expected = git(repo, 'show', base + ':' + name, binary=True)
        except JobError as exc:
            raise JobError(f'source binding unavailable in base for {name}: {exc}') from exc
        require(expected == content, f'source binding differs from selected base: {name}')



def bounded_nonempty_text(content, label):
    require(len(content) <= GOAL_LIMIT, f'{label} exceeds {GOAL_LIMIT} byte bound')
    text = decode_text(content, label)
    require(text.strip(), f'{label} must be nonempty text')
    return text


def matching_reconciliation(directory, manifest):
    path = directory / 'reconciliation.json'
    if not os.path.lexists(path):
        return False
    record = json_file(path)
    require(isinstance(record, dict) and record.get('schema_version') == 1 and
            record.get('kind') == 'SCOPEBASE_ADMINISTRATIVE_RECONCILIATION' and
            record.get('job_id') == directory.name == manifest.get('job_id') and
            record.get('resources_retired') is True and
            record.get('job_manifest_sha256') == digest(regular_bytes(directory / 'job.json')),
            f'invalid or nonmatching reconciliation: {directory.name}; ownership retained')
    reason = record.get('reason')
    require(isinstance(reason, str), 'invalid reconciliation reason')
    bounded_nonempty_text(reason.encode('utf-8'), 'reconciliation reason')
    require(record.get('reason_sha256') == digest(reason.encode('utf-8')) and
            record.get('evidence_snapshot') == 'reconciliation-evidence.txt', 'invalid reconciliation evidence binding')
    evidence = regular_bytes(directory / 'reconciliation-evidence.txt', GOAL_LIMIT)
    bounded_nonempty_text(evidence, 'reconciliation evidence')
    require(record.get('evidence_sha256') == digest(evidence), 'reconciliation evidence hash differs; ownership retained')
    return True


def reconcile(args):
    job_id = identifier(args.job, 'job')
    require(args.resources_retired, 'explicit --resources-retired assertion required; pending resources retain ownership')
    reason = bounded_nonempty_text(args.reason.encode('utf-8'), 'reconciliation reason')
    evidence_path = Path(args.evidence_file)
    require(evidence_path.is_absolute(), 'reconciliation evidence-file must be an absolute path')
    evidence = regular_bytes(evidence_path, GOAL_LIMIT)
    bounded_nonempty_text(evidence, 'reconciliation evidence')
    _, root, common = repository(args.repo)
    with controller(root) as state:
        jobs = state / 'jobs'
        require(not jobs.is_symlink() and jobs.is_dir(), 'job state missing or symlink refused')
        job = jobs / job_id
        require(not job.is_symlink() and job.is_dir(), 'job missing or symlink refused')
        manifest_bytes = regular_bytes(job / 'job.json')
        manifest = json_file(job / 'job.json')
        require(isinstance(manifest, dict) and manifest.get('schema_version') == 1 and
                manifest.get('kind') == 'SCOPEBASE_ADMINISTRATIVE_JOB' and manifest.get('job_id') == job_id and
                manifest.get('repository_root') == str(root) and manifest.get('git_common_dir') == str(common) and
                manifest.get('execution_state') in ('PREPARING', 'PREPARED', 'PREPARATION_FAILED') and
                isinstance(manifest.get('allowed_paths'), list), 'job manifest binding invalid for reconciliation')
        for path in manifest['allowed_paths']:
            relative_path(path)
        record_path = job / 'reconciliation.json'
        snapshot = job / 'reconciliation-evidence.txt'
        require(not os.path.lexists(record_path) and not os.path.lexists(snapshot),
                'reconciliation or evidence snapshot already exists; evidence never overwritten')
        record = {'schema_version': 1, 'kind': 'SCOPEBASE_ADMINISTRATIVE_RECONCILIATION',
                  'job_id': job_id, 'reconciled_utc': datetime.now(timezone.utc).isoformat(),
                  'resources_retired': True, 'reason': reason, 'reason_sha256': digest(reason.encode('utf-8')),
                  'job_manifest_sha256': digest(manifest_bytes), 'evidence_original_path': str(evidence_path),
                  'evidence_snapshot': snapshot.name, 'evidence_sha256': digest(evidence),
                  'acceptance': 'NOT_ATTESTED; controller assertion releases administrative ownership only'}
        # A failure between these writes preserves a partial attempt and its claim.
        new_file(snapshot, evidence)
        new_file(record_path, json_bytes(record))
        require(matching_reconciliation(job, manifest), 'reconciliation did not validate; ownership retained')
        return {'job': str(job), 'reconciliation': str(record_path), 'evidence_snapshot': str(snapshot),
                'ownership': 'RELEASED_BY_CONTROLLER_ASSERTION'}


# Writing lifecycle is separate from immutable preparation and final reconciliation.
WRITING_LIMIT = 256
SHA256 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
OID = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z', re.ASCII)
SOURCE_KEYS = {'schema_version', 'kind', 'job_id', 'repository_root', 'git_common_dir',
               'worktree', 'worktree_git_dir', 'branch', 'head_commit', 'head_tree', 'status_sha256'}
HEAD_KEYS = {'schema_version', 'kind', 'job_id', 'job_manifest_sha256', 'generation', 'event_sha256'}
EVENT_KEYS = {'schema_version', 'kind', 'job_id', 'job_manifest_sha256', 'generation',
              'previous_event_sha256', 'action', 'writing_permission', 'created_utc', 'reason',
              'reason_sha256', 'evidence_original_path', 'evidence_snapshot', 'evidence_sha256',
              'source_snapshot', 'source_sha256'}


def existing_private_directory(path):
    require(not path.is_symlink() and path.is_dir(), f'writing directory missing or symlink: {path}')
    info = path.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            f'writing directory must be private and user-owned: {path}')


def writing_entries(path, expected):
    # Stop at the first unexpected entry; corrupt directories do not expand the work bound.
    remaining = set(expected)
    for entry in path.iterdir():
        require(entry.name in remaining, f'partial/unexpected writing history entry: {entry}')
        remaining.remove(entry.name)
    require(not remaining, f'writing history missing entries in {path}; custody retained')


def writing_bytes(path, limit):
    content = regular_bytes(path, limit)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            f'writing artifact must be a private user-owned regular file: {path}')
    return content


def canonical_record(path, limit, keys):
    content = writing_bytes(path, limit)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f'duplicate JSON key in writing artifact: {path}')
            result[key] = value
        return result
    try:
        value = json.loads(decode_text(content, str(path)), object_pairs_hook=unique)
    except ValueError as exc:
        raise JobError(f'invalid writing JSON: {path}: {exc}') from exc
    require(isinstance(value, dict) and set(value) == keys and json_bytes(value) == content,
            f'noncanonical or unsupported writing record: {path}')
    require(type(value.get('schema_version')) is int and value['schema_version'] == 1,
            f'unsupported writing schema: {path}')
    return value, content


def writing_artifacts(root, common, directory, manifest):
    require(isinstance(manifest, dict) and type(manifest.get('schema_version')) is int and
            manifest['schema_version'] == 1 and manifest.get('kind') == 'SCOPEBASE_ADMINISTRATIVE_JOB' and
            manifest.get('job_id') == directory.name and ID.fullmatch(directory.name) and
            manifest.get('repository_root') == str(root) and manifest.get('git_common_dir') == str(common) and
            manifest.get('execution_state') == 'PREPARED' and manifest.get('read_only') is False and
            isinstance(manifest.get('allowed_paths'), list) and manifest['allowed_paths'],
            'writing requires a matching writable PREPARED job')
    for path in manifest['allowed_paths']:
        relative_path(path)
    require(not matching_reconciliation(directory, manifest), 'reconciled job cannot regain writing permission')
    artifacts = manifest.get('artifact_sha256')
    require(isinstance(artifacts, dict) and set(artifacts) == {'goal.txt', 'brief.md', 'dispatch.json'},
            'original job artifact bindings missing')
    for name, expected in artifacts.items():
        require(isinstance(expected, str) and SHA256.fullmatch(expected) and
                digest(regular_bytes(directory / name)) == expected, f'original job artifact binding changed: {name}')
    require(manifest.get('goal_snapshot') == str(directory / 'goal.txt') and
            manifest.get('goal_sha256') == artifacts['goal.txt'], 'original goal binding differs')


def writing_source(root, common, directory, manifest, expected_head=None):
    writing_artifacts(root, common, directory, manifest)
    worktree = root / '.worktrees' / directory.name
    branch = 'scopebase/' + directory.name
    require(manifest.get('worktree') == str(worktree) and manifest.get('branch') == branch and
            not worktree.is_symlink() and worktree.is_dir() and not (worktree / '.git').is_symlink(),
            'writing worktree/branch binding missing or replaced')
    actual_source, actual_root, actual_common = repository(worktree)
    git_dir = git(worktree, 'rev-parse', '--absolute-git-dir').strip()
    require(actual_source == worktree and actual_root == root and actual_common == common and
            git_dir == manifest.get('worktree_git_dir') and Path(git_dir).resolve() == Path(git_dir) and
            not Path(git_dir).is_symlink() and Path(git_dir).is_dir() and
            git(worktree, 'symbolic-ref', '--quiet', '--short', 'HEAD').strip() == branch,
            'writing worktree Git identity binding changed')
    registrations = git(root, 'worktree', 'list', '--porcelain', '-z', binary=True).split(b'\0\0')
    registration = [block.split(b'\0') for block in registrations
                    if block.split(b'\0')[0] == b'worktree ' + os.fsencode(worktree)]
    require(len(registration) == 1 and b'branch refs/heads/' + branch.encode() in registration[0],
            'writing worktree is not registered with its exact branch')
    head = commit(worktree, 'HEAD')
    tree = git(worktree, 'rev-parse', '--verify', 'HEAD^{tree}').strip()
    require(OID.fullmatch(head) and OID.fullmatch(tree), 'writing source requires full object IDs')
    if expected_head is not None:
        require(isinstance(expected_head, str) and OID.fullmatch(expected_head) and expected_head == head,
                'requested full HEAD does not match writing source checkpoint')
    index = git(worktree, 'ls-files', '-v', '-z', binary=True).split(b'\0')
    require(all(entry[:1] != b'S' and not entry[:1].islower() for entry in index if entry),
            'writing source has assume-unchanged or skip-worktree index entries')
    entries = git(worktree, 'ls-tree', '-r', '-z', 'HEAD', binary=True).split(b'\0')
    require(not any(entry.startswith(b'160000 ') for entry in entries), 'writing source Gitlink/submodule refused')
    status = git(worktree, 'status', '--porcelain=v1', '--untracked-files=all', binary=True)
    require(not status, 'dirty/untracked writing source; clean full HEAD required')
    return {'schema_version': 1, 'kind': 'SCOPEBASE_WRITING_SOURCE', 'job_id': directory.name,
            'repository_root': str(root), 'git_common_dir': str(common), 'worktree': str(worktree),
            'worktree_git_dir': git_dir, 'branch': branch, 'head_commit': head, 'head_tree': tree,
            'status_sha256': digest(status)}


def writing_state(directory, manifest):
    writing = directory / 'writing'
    if not os.path.lexists(writing):
        return {'generation': 0, 'writing_permission': 'ACTIVE', 'event_sha256': None}
    existing_private_directory(writing)
    writing_entries(writing, {'current.json', 'events'})
    events = writing / 'events'
    existing_private_directory(events)
    head, _ = canonical_record(writing / 'current.json', 4096, HEAD_KEYS)
    manifest_hash = digest(regular_bytes(directory / 'job.json'))
    require(head['kind'] == 'SCOPEBASE_WRITING_HEAD' and head['job_id'] == directory.name and
            head['job_manifest_sha256'] == manifest_hash and
            type(head['generation']) is int and 1 <= head['generation'] <= WRITING_LIMIT and
            isinstance(head['event_sha256'], str) and SHA256.fullmatch(head['event_sha256']),
            'invalid writing head binding; custody retained')
    writing_entries(events, {f'{n:08d}' for n in range(1, head['generation'] + 1)})
    root = directory.parent.parent.parent
    common = root / '.git'
    writing_artifacts(root, common, directory, manifest)
    previous_hash = None
    previous_source = None
    for generation in range(1, head['generation'] + 1):
        event_dir = events / f'{generation:08d}'
        existing_private_directory(event_dir)
        writing_entries(event_dir, {'event.json', 'source.json', 'evidence.txt'})
        suspended = generation % 2 == 1
        extra = {'write_quiescent'} if suspended else {'suspended_event_sha256', 'policy_sha256',
                                                       'implementation_cap', 'other_active_writers'}
        event, event_bytes = canonical_record(event_dir / 'event.json', 131072, EVENT_KEYS | extra)
        source, source_bytes = canonical_record(event_dir / 'source.json', 16384, SOURCE_KEYS)
        evidence = writing_bytes(event_dir / 'evidence.txt', GOAL_LIMIT)
        bounded_nonempty_text(evidence, 'writing evidence')
        require(event['kind'] == 'SCOPEBASE_WRITING_TRANSITION' and event['job_id'] == directory.name and
                event['job_manifest_sha256'] == manifest_hash and type(event['generation']) is int and
                event['generation'] == generation and event['previous_event_sha256'] == previous_hash and
                event['action'] == ('SUSPEND' if suspended else 'RESUME') and
                event['writing_permission'] == ('SUSPENDED' if suspended else 'ACTIVE'),
                'invalid writing transition binding; custody retained')
        require(isinstance(event['created_utc'], str), 'invalid writing creation time')
        try:
            created = datetime.fromisoformat(event['created_utc'])
            require(created.utcoffset() is not None and created.utcoffset().total_seconds() == 0,
                    'writing creation time must be UTC')
        except ValueError as exc:
            raise JobError('invalid writing creation time') from exc
        require(isinstance(event['reason'], str), 'invalid writing reason')
        bounded_nonempty_text(event['reason'].encode('utf-8'), 'writing reason')
        require(event['reason_sha256'] == digest(event['reason'].encode('utf-8')) and
                isinstance(event['evidence_original_path'], str) and Path(event['evidence_original_path']).is_absolute() and
                '\0' not in event['evidence_original_path'] and event['evidence_snapshot'] == 'evidence.txt' and
                event['source_snapshot'] == 'source.json' and event['evidence_sha256'] == digest(evidence) and
                event['source_sha256'] == digest(source_bytes), 'writing snapshot/reason digest binding differs')
        require(source['kind'] == 'SCOPEBASE_WRITING_SOURCE' and source['job_id'] == directory.name and
                all(isinstance(source[key], str) for key in SOURCE_KEYS - {'schema_version'}) and
                source['repository_root'] == str(root) and source['git_common_dir'] == str(common) and
                source['worktree'] == manifest['worktree'] and source['worktree_git_dir'] == manifest['worktree_git_dir'] and
                source['branch'] == manifest['branch'] and OID.fullmatch(source['head_commit']) and
                OID.fullmatch(source['head_tree']) and source['status_sha256'] == digest(b''),
                'invalid writing source snapshot binding')
        if suspended:
            require(event['write_quiescent'] is True, 'writing suspension lacks quiescence assertion')
        else:
            require(event['suspended_event_sha256'] == previous_hash and source_bytes == previous_source and
                    isinstance(event['policy_sha256'], str) and SHA256.fullmatch(event['policy_sha256']) and
                    type(event['implementation_cap']) is int and type(event['other_active_writers']) is int and
                    0 <= event['other_active_writers'] < event['implementation_cap'] <= 3,
                    'invalid resume capacity/source binding')
        previous_hash = digest(event_bytes)
        previous_source = source_bytes
    require(previous_hash == head['event_sha256'], 'writing current head/event hash differs; custody retained')
    if event['writing_permission'] == 'SUSPENDED':
        require(json_bytes(writing_source(root, common, directory, manifest)) == previous_source,
                'suspended writing source checkpoint drift; custody retained')
    return {'generation': head['generation'], 'writing_permission': event['writing_permission'],
            'event_sha256': previous_hash}


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_file(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def writing_transition(args, suspended):
    job_id = identifier(args.job, 'job')
    require(type(args.generation) is int and args.generation >= 0, 'writing generation must be nonnegative integer')
    require(isinstance(args.head, str) and OID.fullmatch(args.head), 'writing requires full lowercase HEAD object ID')
    if suspended:
        require(args.write_quiescent, 'explicit --write-quiescent assertion required')
    reason = bounded_nonempty_text(args.reason.encode('utf-8'), 'writing reason')
    evidence_path = Path(args.evidence_file)
    require(evidence_path.is_absolute(), 'writing evidence-file must be an absolute path')
    evidence = regular_bytes(evidence_path, GOAL_LIMIT)
    bounded_nonempty_text(evidence, 'writing evidence')
    source_repo, root, common = repository(args.repo)
    with controller(root) as state:
        existing_private_directory(state / 'jobs')
        directory = state / 'jobs' / job_id
        existing_private_directory(directory)
        manifest_bytes = regular_bytes(directory / 'job.json')
        manifest = json_file(directory / 'job.json')
        checkpoint = writing_source(root, common, directory, manifest, args.head)
        current = writing_state(directory, manifest)
        require(current['generation'] == args.generation, 'stale writing generation; inspect retained evidence')
        require(current['writing_permission'] == ('ACTIVE' if suspended else 'SUSPENDED'),
                'writing permission already in requested state')
        generation = current['generation'] + 1
        require(generation <= WRITING_LIMIT, 'writing transition bound reached; custody retained')
        event = {'schema_version': 1, 'kind': 'SCOPEBASE_WRITING_TRANSITION', 'job_id': job_id,
                 'job_manifest_sha256': digest(manifest_bytes), 'generation': generation,
                 'previous_event_sha256': current['event_sha256'], 'action': 'SUSPEND' if suspended else 'RESUME',
                 'writing_permission': 'SUSPENDED' if suspended else 'ACTIVE',
                 'created_utc': datetime.now(timezone.utc).isoformat(), 'reason': reason,
                 'reason_sha256': digest(reason.encode('utf-8')), 'evidence_original_path': str(evidence_path),
                 'evidence_snapshot': 'evidence.txt', 'evidence_sha256': digest(evidence),
                 'source_snapshot': 'source.json', 'source_sha256': digest(json_bytes(checkpoint))}
        if suspended:
            event['write_quiescent'] = True
        else:
            policy_bytes = regular_bytes(source_repo / POLICY)
            selected_policy = policy(source_repo)
            require(regular_bytes(source_repo / POLICY) == policy_bytes,
                    'policy changed while validating resume capacity; no transition reserved')
            cap = selected_policy['max_independent_implementation_lanes']
            writers = admission(state, manifest['allowed_paths'], cap, resuming_job=job_id)
            event.update(suspended_event_sha256=current['event_sha256'],
                         policy_sha256=digest(policy_bytes),
                         implementation_cap=cap, other_active_writers=writers)
        source_bytes = json_bytes(checkpoint)
        event_bytes = json_bytes(event)
        head = {'schema_version': 1, 'kind': 'SCOPEBASE_WRITING_HEAD', 'job_id': job_id,
                'job_manifest_sha256': digest(manifest_bytes), 'generation': generation,
                'event_sha256': digest(event_bytes)}
        head_bytes = json_bytes(head)
        require(len(source_bytes) <= 16384 and len(event_bytes) <= 131072 and len(head_bytes) <= 4096,
                'writing JSON exceeds record bound; no transition reserved')
        writing = directory / 'writing'
        if not os.path.lexists(writing):
            writing.mkdir(mode=0o700)
            (writing / 'events').mkdir(mode=0o700)
        events = writing / 'events'
        event_dir = events / f'{generation:08d}'
        event_dir.mkdir(mode=0o700)  # From here every failure is retained, never retried/repaired.
        durable_file(event_dir / 'evidence.txt', evidence)
        durable_file(event_dir / 'source.json', source_bytes)
        durable_file(event_dir / 'event.json', event_bytes)
        sync_directory(event_dir)
        sync_directory(events)
        # Make new directory entries durable before publishing their authoritative head.
        sync_directory(writing)
        sync_directory(directory)
        if not suspended:
            require(regular_bytes(source_repo / POLICY) == policy_bytes, 'resume policy changed before publication')
        require(regular_bytes(directory / 'job.json') == manifest_bytes and
                json_bytes(writing_source(root, common, directory, manifest, args.head)) == json_bytes(checkpoint),
                'writing source/original job changed before head publication')
        durable_file(writing / 'current.json.next', head_bytes)
        os.replace(writing / 'current.json.next', writing / 'current.json')
        sync_directory(writing)
        published = writing_state(directory, manifest)
        require(published['generation'] == generation and published['event_sha256'] == digest(event_bytes),
                'published writing transition failed validation; custody retained')
        return {**published, 'job': str(directory), 'event': str(event_dir / 'event.json'),
                'source_checkpoint': checkpoint, 'source_snapshot': str(event_dir / 'source.json'),
                'source_sha256': event['source_sha256'], 'evidence_snapshot': str(event_dir / 'evidence.txt'),
                'evidence_sha256': event['evidence_sha256'], 'path_ownership': 'RETAINED',
                'resource_retirement': 'NOT_ATTESTED', 'worker_launch': 'NOT_LAUNCHED'}


def suspend_writing(args):
    return writing_transition(args, True)


def resume_writing(args):
    return writing_transition(args, False)


def admission(state, allowed, cap, *, resuming_job=None):
    jobs = state / 'jobs'
    private_directory(jobs)
    writers = 0
    for directory in jobs.iterdir():
        require(not directory.is_symlink() and directory.is_dir(), f'unknown job state preserved: {directory}')
        manifest = json_file(directory / 'job.json')
        require(isinstance(manifest, dict) and isinstance(manifest.get('allowed_paths'), list),
                f'malformed existing ownership manifest: {directory}')
        # Only a complete matching controller closure releases a claim. Process absence never does.
        if matching_reconciliation(directory, manifest):
            continue
        existing = [relative_path(p) for p in manifest['allowed_paths']]
        lifecycle = writing_state(directory, manifest)
        if directory.name == resuming_job:
            require(lifecycle['writing_permission'] == 'SUSPENDED', 'resume subject is not suspended')
            continue
        if existing and lifecycle['writing_permission'] != 'SUSPENDED':
            writers += 1
        if allowed:
            for first in allowed:
                for second in existing:
                    require(not overlaps(first, second), f'writable path overlap: {first} with {directory.name}:{second}')
    require(not allowed or writers < cap, 'implementation lane cap reached; controller reconciliation or suspension required')
    return writers


PACKET_FIELDS = ('purpose_scope', 'decisions', 'starting_bytes', 'origin',
                 'inputs', 'outputs', 'preservation_map', 'license_boundary',
                 'tests', 'effects_bounds', 'resources_parallelism',
                 'acceptance')
PACKET_ORIGINS = {'PORT', 'ADAPT', 'NEW', 'EVALUATE', 'QUALIFY'}
PACKET_LIMIT = 65536


def validate_packet(packet):
    """Enforce the 12-field executor-packet schema (PACKET-GUARD01).

    Schema completeness only: every field present, substantive, and
    origin-restricted. Semantic content stays expert-judged. Returns a
    summary dict; raises JobError naming the offending field.
    """
    require(isinstance(packet, dict), 'packet must be a JSON object')
    for key in packet:
        require(key in PACKET_FIELDS,
                f'packet field {key!r} is not one of the 12 executor-contract fields')
    for field in PACKET_FIELDS:
        require(field in packet, f'packet field {field!r} is missing')
    for field in PACKET_FIELDS:
        if field == 'origin':
            continue
        value = packet[field]
        require(isinstance(value, str) and value.strip(),
                f'packet field {field!r} must be nonempty text')
    origin = packet['origin']
    require(isinstance(origin, dict), "packet field 'origin' must be an object")
    origins = origin.get('origins')
    require(isinstance(origins, list) and origins and
            all(entry in PACKET_ORIGINS for entry in origins),
            "packet field 'origin' origins must be a nonempty list of "
            'PORT/ADAPT/NEW/EVALUATE/QUALIFY')
    require(isinstance(origin.get('statement'), str) and origin['statement'].strip(),
            "packet field 'origin' statement must be nonempty text")
    return {'fields': sorted(PACKET_FIELDS), 'origins': list(origins)}


def prepare(args):
    task_id = identifier(args.task, 'task')
    job_id = identifier(args.job, 'job')
    source, root, common = repository(args.repo)
    with controller(root) as state:
        selected_policy = policy(source)
        require(args.role in selected_policy['roles'], f'unknown role: {args.role}')
        role = selected_policy['roles'][args.role]
        effort = args.effort or role['reasoning_effort']
        require(effort in role['allowed_efforts'], f'effort {effort!r} not allowed for role {args.role}')
        if role.get('reason_required') or (role['backend'] == 'native' and effort == 'max'):
            require(args.reason and args.reason.strip(), 'max escalation requires a reason')
        allowed = sorted(set(relative_path(p, source) for p in (args.write_path or [])))
        require(not (role['read_only'] and allowed), 'read-only roles accept no write paths')
        require(role['read_only'] or allowed, 'writable role requires explicit write paths')
        goal_path = Path(args.goal_file).absolute()
        goal = regular_bytes(goal_path, GOAL_LIMIT)
        require(decode_text(goal, 'goal').strip(), 'goal must be nonempty bounded text')
        packet_bytes = None
        if args.packet:
            packet_path = Path(args.packet).absolute()
            packet_bytes = regular_bytes(packet_path, PACKET_LIMIT)
            try:
                packet_data = json.loads(decode_text(packet_bytes, 'packet'))
            except ValueError as exc:
                raise JobError(f'packet is not valid JSON: {exc}') from exc
            validate_packet(packet_data)
        base = commit(source, args.base)
        task, tasks, contents, task_text, constraints, specs = inputs(source, task_id)
        bound_to_commit(source, base, contents)
        prerequisites = {dep: tasks[dep]['status'] for dep in task['depends_on']}
        if allowed:
            require(all(status in ACCEPTED for status in prerequisites.values()),
                    f'task prerequisites are not accepted: {prerequisites}')
        validate_base_paths(source, base, allowed)
        job = state / 'jobs' / job_id
        worktrees = root / '.worktrees'
        require(not os.path.lexists(job), f'job already exists: {job_id}')
        private_directory(worktrees, require_private=False)
        worktree = worktrees / job_id
        branch = 'scopebase/' + job_id
        require(not os.path.lexists(worktree), f'worktree already exists: {worktree}')
        existing = subprocess.run(['git', '-C', str(source), 'show-ref', '--verify', '--quiet', 'refs/heads/' + branch])
        require(existing.returncode == 1, f'branch already exists or cannot be verified: {branch}')
        admission(state, allowed, selected_policy['max_independent_implementation_lanes'])
        job.mkdir(mode=0o700)  # Exclusive reservation. Failures from here retain all resources.
        manifest = {
            'schema_version': 1, 'kind': 'SCOPEBASE_ADMINISTRATIVE_JOB', 'job_id': job_id, 'task_id': task_id,
            'execution_state': 'PREPARING', 'created_utc': datetime.now(timezone.utc).isoformat(),
            'source_repo': str(source), 'repository_root': str(root), 'git_common_dir': str(common),
            'worktree': str(worktree), 'branch': branch, 'base_commit': base,
            'role': args.role, 'backend': role['backend'], 'model': role['model'], 'reasoning_effort': effort,
            'fresh_context': True, 'fork_turns': 'none' if role['backend'] == 'native' else None,
            'reason': args.reason, 'read_only': role['read_only'], 'allowed_paths': allowed,
            'prerequisites': prerequisites, 'goal_original_path': str(goal_path),
            'goal_snapshot': str(job / 'goal.txt'), 'goal_sha256': digest(goal),
            'bindings': {name: digest(content) for name, content in contents.items()},
            'policy_sha256': digest(contents[POLICY]), 'plan_path': task['plan'],
            'plan_sha256': digest(contents[task['plan']]),
            'spec_sha256': {name: digest(contents[name]) for name in specs},
            'acceptance': 'UNREVIEWED; controller only; no product task status changed',
            'packet_state': 'SUPPLIED_VALID' if packet_bytes is not None else 'UNSUPPLIED',
        }
        if packet_bytes is not None:
            manifest['packet_sha256'] = digest(packet_bytes)
            manifest['packet_snapshot'] = str(job / 'packet.json')
        new_file(job / 'job.json', json_bytes(manifest))
        try:
            for directory in ('tmp', 'cargo-target', 'evidence'):
                (job / directory).mkdir(mode=0o700)
            new_file(job / 'goal.txt', goal)
            if packet_bytes is not None:
                new_file(job / 'packet.json', packet_bytes)
            worktree.mkdir(mode=0o700)
            git(source, 'worktree', 'add', '-b', branch, str(worktree), base)
            for path in allowed:
                relative_path(path, worktree)
            manifest['worktree_git_dir'] = git(worktree, 'rev-parse', '--absolute-git-dir').strip()
            # Reject a hook or concurrent source edit instead of accepting different task bytes.
            for name, expected in manifest['bindings'].items():
                require(digest(regular_bytes(source / name)) == expected and
                        digest(regular_bytes(worktree / name)) == expected, f'input binding changed during preparation: {name}')
            template = 'reviewer' if role['read_only'] else 'worker'
            brief = f'''# ScopeBase job {job_id}: {task_id}

Administrative preparation only. No worker has run; no product task is accepted.

## User goal (immutable snapshot)

{decode_text(goal, 'goal').rstrip()}

## Bound execution

- Worktree: `{worktree}`
- Base commit: `{base}`
- Role/model/effort: `{args.role}` / `{role['model']}` / `{effort}`
- Fresh context: `fork_turns: none`; never reuse an implementation session for its review.
- Allowed write paths: `{json.dumps(allowed)}`; readonly roles have no edit authority.
- Prerequisites: `{json.dumps(prerequisites, sort_keys=True)}`
- TMPDIR: `{job / 'tmp'}`; CARGO_TARGET_DIR: `{job / 'cargo-target'}`
- Evidence: `{job / 'evidence'}`; report: `{job / 'evidence' / 'report.md'}`
- Policy/plan/spec/goal hashes and exact allowed paths: `{job / 'job.json'}`

Read `{worktree / 'AGENTS.md'}`, `{worktree / RULES}`,
`{worktree / ('orchestration/templates/' + template + '.md')}` and `{worktree / TEMPLATES[-1]}`.
Full specifications: {', '.join('`' + str(worktree / spec) + '`' for spec in specs)}.

## Exact plan constraints

{constraints}
## Exact selected task

{task_text}
## Independent acceptance and reporting

Run the task's actual affected checks; preserve red/control evidence and exact commands/results.
Use DONE / DONE_WITH_CONCERNS / BLOCKED / NEEDS_CONTEXT in the report. Record commits,
decisions, assertion changes requiring a ruling, concerns and resource custody. Required absent
cells remain SKIP/BLOCKED/NOT_RUN and incomplete. The controller requires independent review
of the full immutable candidate and current-candidate verification before acceptance. Do not
close product tasks, merge, publish or launch a model as part of this preparation.
'''
            new_file(job / 'brief.md', brief)
            dispatch = {'backend': role['backend'], 'model': role['model'], 'reasoning_effort': effort,
                        'worktree': str(worktree), 'brief': str(job / 'brief.md'), 'read_only': role['read_only'],
                        'launch_state': 'NOT_LAUNCHED', 'allowed_paths': allowed}
            if role['backend'] == 'native':
                dispatch.update({'fork_turns': 'none', 'task_name': re.sub(r'[^a-z0-9_]', '_', job_id.lower()),
                                 'message': f'Read and execute the bound brief {job / "brief.md"} in {worktree}. ' +
                                            'Do not exceed its authority; report with exact evidence.'})
            else:
                dispatch.update({'contributor_mode': 'on', 'effective_provider_tier': 'UNVERIFIED',
                                 'command': [str(worktree / 'bin/muse-run.sh'), str(worktree),
                                             str(job / 'brief.md'), str(job / 'evidence/muse')]})
            new_file(job / 'dispatch.json', json_bytes(dispatch))
            manifest['artifact_sha256'] = {name: digest(regular_bytes(job / name))
                                           for name in ('goal.txt', 'brief.md', 'dispatch.json')}
            manifest['execution_state'] = 'PREPARED'
            replace_manifest(job / 'job.json', manifest)
        except Exception as exc:
            manifest['execution_state'] = 'PREPARATION_FAILED'
            manifest['preparation_error'] = str(exc)
            replace_manifest(job / 'job.json', manifest)
            raise
        return {'job': str(job), 'worktree': str(worktree), 'brief': str(job / 'brief.md'),
                'manifest': str(job / 'job.json'), 'dispatch': str(job / 'dispatch.json')}


def review_package(args):
    job_id = identifier(args.job, 'job')
    source, root, common = repository(args.repo)
    with controller(root) as state:
        job = state / 'jobs' / job_id
        require(not job.is_symlink() and job.is_dir(), 'job missing or symlink refused')
        manifest = json_file(job / 'job.json')
        require(isinstance(manifest, dict) and manifest.get('job_id') == job_id and
                manifest.get('execution_state') == 'PREPARED', 'job is not a matching PREPARED manifest')
        require(manifest.get('git_common_dir') == str(common) and manifest.get('repository_root') == str(root),
                'repository binding differs from job')
        worktree = root / '.worktrees' / job_id
        require(manifest.get('worktree') == str(worktree) and not worktree.is_symlink() and worktree.is_dir(),
                'worktree binding missing or replaced')
        actual_source, actual_root, actual_common = repository(worktree)
        require(actual_source == worktree and actual_root == root and actual_common == common and
                git(worktree, 'rev-parse', '--absolute-git-dir').strip() == manifest.get('worktree_git_dir') and
                git(worktree, 'symbolic-ref', '--quiet', '--short', 'HEAD').strip() == manifest.get('branch'),
                'worktree Git identity binding changed')
        origin = Path(manifest['source_repo'])
        for name, expected in manifest['bindings'].items():
            relative_path(name)
            require(digest(regular_bytes(origin / name)) == expected and
                    digest(regular_bytes(source / name)) == expected and
                    digest(regular_bytes(worktree / name)) == expected, f'input binding changed: {name}')
        for name, expected in manifest['artifact_sha256'].items():
            relative_path(name)
            require(digest(regular_bytes(job / name)) == expected, f'job artifact binding changed: {name}')
        candidate = commit(worktree, args.head)
        require(candidate == commit(worktree, 'HEAD'), 'requested head does not match job worktree HEAD')
        base = manifest['base_commit']
        ancestor = subprocess.run(['git', '-C', str(worktree), 'merge-base', '--is-ancestor', base, candidate])
        require(ancestor.returncode == 0, 'candidate HEAD is not descended from recorded base')
        dirty = git(worktree, 'status', '--porcelain=v1', '--untracked-files=all')
        require(not dirty, 'dirty/untracked source in job worktree; commit or preserve it separately')
        names = git(worktree, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--name-only', '-z', base, candidate, binary=True).split(b'\0')
        allowed = manifest['allowed_paths']
        for name in filter(None, names):
            decoded = name.decode('utf-8', errors='strict')
            require(any(decoded == prefix or decoded.startswith(prefix + '/') for prefix in allowed),
                    f'candidate changed a path outside allowed ownership: {decoded}')
        reviews = job / 'reviews'
        private_directory(reviews)
        package = reviews / candidate
        require(not os.path.lexists(package), 'review package already exists; evidence never overwritten')
        diff = git(worktree, 'diff', '--no-ext-diff', '--no-textconv', '--binary', '--full-index', base, candidate, binary=True)
        commits = git(worktree, 'log', '--format=fuller', '--reverse', base + '..' + candidate)
        stats = git(worktree, 'diff', '--no-ext-diff', '--no-textconv', '--stat', base, candidate)
        package.mkdir(mode=0o700)
        new_file(package / 'diff.patch', diff)
        new_file(package / 'commits.txt', commits)
        new_file(package / 'stat.txt', stats)
        metadata = {'schema_version': 1, 'kind': 'SCOPEBASE_IMMUTABLE_REVIEW_INPUT',
                    'job_id': job_id, 'base_commit': base, 'candidate_commit': candidate,
                    'allowed_paths': allowed, 'diff_sha256': digest(diff),
                    'artifacts_sha256': {'diff.patch': digest(diff), 'commits.txt': digest(commits.encode()),
                                         'stat.txt': digest(stats.encode())},
                    'job_manifest_sha256': digest(regular_bytes(job / 'job.json')),
                    'execution_state': 'NOT_ATTESTED', 'acceptance': 'CONTROLLER_ONLY'}
        new_file(package / 'package.json', json_bytes(metadata))
        return {'package': str(package), 'candidate_commit': candidate}


def doctor(args):
    source, root, common = repository(args.repo)
    selected_policy = policy(source)
    required = {'python': sys.version.split()[0]}
    for command in ('git', 'flock'):
        path = shutil.which(command)
        require(path, f'missing required local tool: {command}')
        result = subprocess.run([path, '--version'], text=True, capture_output=True, timeout=10)
        require(result.returncode == 0, f'required tool version failed: {command}')
        required[command] = result.stdout.strip()
    optional = {}
    for command in ('muse', 'codex'):
        path = shutil.which(command)
        if not path:
            optional[command] = {'available': False, 'status': 'OPTIONAL_MISSING'}
            continue
        try:
            result = subprocess.run([path, '--version'], text=True, capture_output=True, timeout=10)
            optional[command] = {'available': True, 'path': path, 'version_exit': result.returncode,
                                 'version': (result.stdout or result.stderr).strip(), 'model_run': 'NOT_RUN'}
        except (OSError, subprocess.TimeoutExpired) as exc:
            optional[command] = {'available': True, 'status': 'VERSION_UNAVAILABLE', 'error': str(exc)}
    return {'status': 'READY_FOR_PREPARATION', 'source_repo': str(source), 'repository_root': str(root),
            'git_common_dir': str(common), 'head': commit(source, 'HEAD'),
            'worktrees': git(source, 'worktree', 'list', '--porcelain'),
            'source_status': git(source, 'status', '--porcelain=v1', '--untracked-files=all'),
            'policy': 'VALID', 'required_tools': required, 'optional_tools': optional,
            'implementation_lane_cap': selected_policy['max_independent_implementation_lanes'],
            'product_prerequisites': 'NOT_CHECKED; selected-task checks required', 'model_run': 'NOT_RUN'}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise JobError(message)


def main(argv=None):
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('doctor')
    check.add_argument('--repo', default='.')
    prep = commands.add_parser('prepare')
    for option in ('repo', 'task', 'job', 'role', 'goal-file'):
        prep.add_argument('--' + option, required=True)
    prep.add_argument('--base', default='HEAD')
    prep.add_argument('--effort')
    prep.add_argument('--reason')
    prep.add_argument('--packet')
    prep.add_argument('--write-path', nargs='+', action='extend')
    review = commands.add_parser('review-package')
    for option in ('repo', 'job', 'head'):
        review.add_argument('--' + option, required=True)
    closure = commands.add_parser('reconcile')
    for option in ('repo', 'job', 'reason', 'evidence-file'):
        closure.add_argument('--' + option, required=True)
    closure.add_argument('--resources-retired', action='store_true')
    for name in ('suspend-writing', 'resume-writing'):
        transition = commands.add_parser(name)
        for option in ('repo', 'job', 'head', 'reason', 'evidence-file'):
            transition.add_argument('--' + option, required=True)
        transition.add_argument('--generation', required=True, type=int)
        if name == 'suspend-writing':
            transition.add_argument('--write-quiescent', action='store_true')
    try:
        args = parser.parse_args(argv)
        result = {'doctor': doctor, 'prepare': prepare, 'review-package': review_package, 'reconcile': reconcile,
                  'suspend-writing': suspend_writing, 'resume-writing': resume_writing}[args.command](args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (JobError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f'scopebase-job: {exc}', file=sys.stderr)
        return 64


if __name__ == '__main__':
    sys.exit(main())
