#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone offline checks for the exact supplied ScopeBase Linux package.

Requires Python 3.11+, explicit installed tool paths and a prepared offline Cargo
home. Writes fresh evidence/client/target roots and an enclosing one-member
workspace, without changing any subject byte. No repository tools are imported.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob('*')) if p.is_file()}


def main():
    if sys.version_info < (3, 11):
        raise RuntimeError('Python 3.11 or newer is required')
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ['package-root', 'cargo', 'rustc', 'rustdoc', 'cargo-home', 'target-dir', 'output-dir']:
        ap.add_argument('--' + key, required=True, type=Path)
    ap.add_argument('--configuration', required=True, choices=['minimal', 'default', 'union'])
    a = ap.parse_args()
    for key in ['package_root', 'cargo', 'rustc', 'rustdoc', 'cargo_home', 'target_dir', 'output_dir']:
        p = getattr(a, key)
        if not p.is_absolute():
            raise RuntimeError(key + ' must be an absolute path')
        setattr(a, key, p.resolve())
    root, out, target = a.package_root, a.output_dir, a.target_dir
    for p in [a.cargo, a.rustc, a.rustdoc]:
        if not p.is_file() or not os.access(p, os.X_OK):
            raise RuntimeError('explicit executable is unavailable: ' + str(p))
    if not a.cargo_home.is_dir():
        raise RuntimeError('prepared offline Cargo home is unavailable')
    for p in [out, target]:
        if p.exists() or p == root or p in root.parents or root in p.parents:
            raise RuntimeError('output and target must be fresh and outside subject: ' + str(p))
    if out == target or out in target.parents or target in out.parents:
        raise RuntimeError('output and target roots must be disjoint')
    for p in [root, *root.parents, out.parent, *out.parent.parents, target.parent, *target.parent.parents]:
        if (p / '.git').exists() or (p / '.cargo/config').exists() or (p / '.cargo/config.toml').exists():
            raise RuntimeError('repository or implicit Cargo configuration ancestor: ' + str(p))
        if p != root and (p / 'Cargo.toml').exists():
            raise RuntimeError('existing Cargo workspace ancestor: ' + str(p))
    manifest = root / 'Cargo.toml'
    data = tomllib.loads(manifest.read_text())
    if (data['package']['name'], data['package']['version']) != ('scopebase-linux', '0.1.0'):
        raise RuntimeError('wrong subject package')
    if not (root / 'Cargo.lock').is_file():
        raise RuntimeError('prepare the bound source lock before checks; archive lock must be delivered')
    before = inventory(root)
    out.mkdir(parents=True)
    target.mkdir(parents=True)
    (out / 'tmp').mkdir()
    report = {'schema_version': 1, 'configuration': a.configuration, 'subject': str(root), 'subject_before': before, 'commands': [], 'tools': {}, 'status': 'RUNNING', 'claim': 'pure parser package checks only'}
    env = {k: v for k, v in os.environ.items() if k in ['HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'SYSTEMROOT']}
    env.update(PATH=str(a.rustc.parent) + ':/usr/bin:/bin', CARGO_HOME=str(a.cargo_home), CARGO_TARGET_DIR=str(target), CARGO_NET_OFFLINE='true', RUSTC=str(a.rustc), RUSTDOC=str(a.rustdoc), TMPDIR=str(out / 'tmp'))
    report['environment'] = env

    def run(label, argv, cwd=out, acceptable=0):
        argv = [str(x) for x in argv]
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
        (out / (label + '.stdout')).write_text(p.stdout)
        (out / (label + '.stderr')).write_text(p.stderr)
        report['commands'].append({'label': label, 'argv': argv, 'cwd': str(cwd), 'returncode': p.returncode, 'stdout_sha256': digest(out / (label + '.stdout')), 'stderr_sha256': digest(out / (label + '.stderr'))})
        if p.returncode != acceptable:
            raise RuntimeError(label + ' failed; inspect ' + str(out))
        return p

    try:
        for key in ['cargo', 'rustc', 'rustdoc']:
            path = getattr(a, key)
            p = run(key + '-version', [path, '--version'])
            report['tools'][key] = {'path': str(path), 'sha256': digest(path), 'version': p.stdout.strip()}
        # This is a fresh outer boundary; the delivered manifest and lock are unchanged.
        outer = root.parent
        (outer / 'Cargo.toml').write_text('[workspace]\nresolver = "2"\nmembers = [' + json.dumps(root.name) + ']\n')
        shutil.copyfile(root / 'Cargo.lock', outer / 'Cargo.lock')
        flags = {'minimal': ['--no-default-features'], 'default': [], 'union': ['--all-features']}[a.configuration]
        base = [a.cargo, 'test', '--offline', '--locked', '--manifest-path', manifest, *flags, '--test', 'proc_parsers']
        listed = run('parser-inventory', [*base, '--', '--list'], outer)
        names = re.findall(r'^([^\s]+): test$', listed.stdout, re.M)
        if (len(names) < 26
                or 'refuses_mixed_valid_and_malformed' not in names
                or 'a3_exact_prefix_and_whole_snapshot_refusal' not in names
                or 'mount_escapes_are_single_pass_raw_and_decoded' not in names):
            raise RuntimeError('missing required named parser inventory')
        report['parser_cases'] = names
        run('parser-tests', base, outer)
        default = a.configuration == 'default'
        features = ['mapping', 'process', 'supervision', 'walk'] if a.configuration == 'union' else []
        for name in ['maps_inventory', 'mount_audit']:
            client = out / name
            (client / 'src').mkdir(parents=True)
            shutil.copyfile(root / ('tests/support/' + name + '.rs'), client / 'src/main.rs')
            shutil.copytree(root / 'tests/fixtures/procfs', client / 'src/fixtures')
            (client / 'Cargo.toml').write_text('[package]\nname=' + json.dumps('lx05-' + name.replace('_', '-')) + '\nversion="0.0.0"\nedition="2021"\n[workspace]\nresolver="2"\n[dependencies.scopebase-linux]\npath=' + json.dumps(str(root)) + '\nversion="=0.1.0"\ndefault-features=' + str(default).lower() + '\nfeatures=' + json.dumps(features) + '\n')
            run(name + '-lock-preparation', [a.cargo, 'generate-lockfile', '--offline', '--manifest-path', client / 'Cargo.toml'], client)
            frozen_lock = digest(client / 'Cargo.lock')
            meta = json.loads(run(name + '-metadata', [a.cargo, 'metadata', '--offline', '--locked', '--format-version', '1', '--manifest-path', client / 'Cargo.toml'], client).stdout)
            subjects = [p for p in meta['packages'] if p['name'] == 'scopebase-linux']
            if len(subjects) != 1 or Path(subjects[0]['manifest_path']).resolve() != manifest or subjects[0]['version'] != '0.1.0':
                raise RuntimeError('resolved a different subject copy')
            node = next(n for n in meta['resolve']['nodes'] if n['id'] == subjects[0]['id'])
            expected = {'minimal': [], 'default': ['default'], 'union': ['mapping', 'process', 'supervision', 'walk']}[a.configuration]
            if node['features'] != expected:
                raise RuntimeError('wrong subject feature closure: ' + repr(node['features']))
            p = run(name + '-execute', [a.cargo, 'run', '--offline', '--locked', '--message-format=json', '--manifest-path', client / 'Cargo.toml'], client)
            artifacts = [json.loads(line) for line in p.stdout.splitlines() if line.startswith('{')]
            binaries = [Path(row['executable']) for row in artifacts if row.get('reason') == 'compiler-artifact' and row.get('executable')]
            if len(binaries) != 1 or digest(client / 'Cargo.lock') != frozen_lock:
                raise RuntimeError('client executable or lock binding failed')
            report[name] = {'metadata': meta, 'lock_sha256': frozen_lock, 'binary': str(binaries[0]), 'binary_sha256': digest(binaries[0]), 'inputs': inventory(client)}
        # Build exact subject for downstream compile-boundary tests.
        p = run('ui-library', [a.cargo, 'build', '--offline', '--locked', '--manifest-path', manifest, *flags, '--message-format=json'], outer)
        rows = [json.loads(line) for line in p.stdout.splitlines() if line.startswith('{')]
        rlibs = [Path(f) for r in rows if r.get('reason') == 'compiler-artifact' and r.get('target', {}).get('name') == 'scopebase_linux' for f in r['filenames'] if f.endswith('.rlib')]
        if len(rlibs) != 1:
            raise RuntimeError('could not bind actual subject rlib')
        common = [a.rustc, '--edition=2021', '--crate-type=bin', '--emit=metadata', '--error-format=json', '--extern', 'scopebase_linux=' + str(rlibs[0]), '-L', 'dependency=' + str(target / 'debug/deps')]
        run('ui-positive', [*common, root / 'tests/ui/proc_positive.rs', '-o', out / 'positive.rmeta'])
        ui = json.loads((root / 'tests/ui/cases.json').read_text())
        report['ui_cases'] = []
        for c in ui['cases']:
            if not c['id'].startswith('proc_'):
                continue
            p = run('ui-' + c['id'], [*common, root / c['source'], '-o', out / (c['id'] + '.rmeta')], acceptable=1)
            diagnostics = [json.loads(line) for line in p.stderr.splitlines() if line.startswith('{')]
            reached = [d for d in diagnostics if d.get('code') and d['code']['code'] == c['code'] and any(s['is_primary'] and s['line_start'] == c['line'] and Path(s['file_name']).resolve() == root / c['source'] for s in d.get('spans', []))]
            if not reached or not any(c['contains'] in d['message'] for d in reached):
                raise RuntimeError('wrong downstream diagnostic: ' + c['id'])
            report['ui_cases'].append(c)
        report['status'] = 'PASSED'
    except Exception as e:
        report['status'] = 'FAILED'
        report['failure'] = str(e)
        raise
    finally:
        report['subject_after'] = inventory(root)
        report['subject_unchanged'] = before == report['subject_after']
        if not report['subject_unchanged']:
            report['status'] = 'FAILED'
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if report['status'] != 'PASSED':
        raise RuntimeError('subject changed during checks')
    print(json.dumps({'status': report['status'], 'parser_cases': len(names), 'clients': 2, 'ui_cases': len(report['ui_cases']), 'report': str(out / 'result.json')}))


if __name__ == '__main__':
    main()
