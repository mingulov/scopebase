#!/usr/bin/env python3
"""Validate source intake and planning ownership; default checks are structural.

No network, SSH, source mutation, build, runtime probe or qualification occurs.
Optional local checks read immutable Git objects and selected dirty worktree bytes.
Exit 0: valid requested checks; 2: required local source unavailable; 3: invalid.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r'[0-9a-f]{40}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
SOURCE_PATTERNS = {
    'regression_family': r'^\| (H\d{2}) \|',
    'public_contract_gap': r'^## (G\d{2})\.',
    'user_conformance': r'^\| \*\*(UC\d{2})\b',
    'research_todo': r'^\| ([A-Z]\d{2}) \|',
    'overlap_row': r'^\| (\d{1,2}) [^|]*\|',
}
REFERENCE_KINDS = {'H': 'regression_family', 'G': 'public_contract_gap',
                   'UC': 'user_conformance', 'TODO': 'research_todo'}
LICENSES = {'GPL-3.0-or-later', 'GPL-2.0-only', 'GPL-2.0-or-later',
            'Apache-2.0 WITH LLVM-exception', 'MIT OR Apache-2.0', 'NOASSERTION'}
DISPOSITIONS = {'PORT_SOURCE', 'DEPENDENCY_ADAPTER', 'INDEPENDENT_CONTRACT',
                'VECTORS_ONLY', 'PRODUCT_LOCAL', 'REFERENCE_ONLY'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON member: ' + key)
        result[key] = value
    return result


def load_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_members,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def safe_relative(value):
    return (isinstance(value, str) and bool(value) and '\\' not in value
            and not PurePosixPath(value).is_absolute()
            and all(part not in ('', '.', '..') for part in value.split('/'))
            and '\x00' not in value)


def validate(registry, ledger, repo_root):
    errors = []

    def fail(code, context):
        errors.append({'code': code, 'context': str(context)})

    def records(container, key):
        values = container.get(key)
        if not isinstance(values, list) or any(not isinstance(v, dict) for v in values):
            fail('SCHEMA', key + ' must be an array of objects')
            return []
        return values

    def indexed(values, label):
        result = {}
        for value in values:
            ident = value.get('id')
            if not isinstance(ident, str) or not ident or ident in result:
                fail('DUPLICATE_OR_MISSING_ID', label + ': ' + str(ident))
            else:
                result[ident] = value
        return result

    def owners(values, known, code, context):
        if not isinstance(values, list) or not values or any(v not in known for v in values):
            fail(code, context)

    if registry.get('kind') != 'SCOPEBASE_PLANNING_TRACEABILITY' or registry.get('schema_version') != '1.0.0':
        fail('SCHEMA', 'unsupported traceability kind/version')
    if ledger.get('kind') != 'SCOPEBASE_SOURCE_INTAKE' or ledger.get('schema_version') != '1.0.0':
        fail('SCHEMA', 'unsupported intake kind/version')
    if ledger.get('qualification') != 'NOT_RUN':
        fail('QUALIFICATION_CLAIM', 'source intake cannot qualify production capabilities')
    tasks = indexed(records(registry, 'tasks'), 'task')
    requirements = indexed(records(registry, 'requirements'), 'requirement')
    graph = {}
    for ident, task in tasks.items():
        dependencies = task.get('depends_on', [])
        if not isinstance(dependencies, list) or any(d not in tasks for d in dependencies):
            fail('TASK_DEPENDENCY', ident)
            dependencies = []
        graph[ident] = set(dependencies)
        for required in task.get('requirements', []):
            if required not in requirements or ident not in requirements[required].get('tasks', []):
                fail('REQUIREMENT_OWNER', ident + ': ' + required)
    while graph:
        ready = [t for t, deps in graph.items() if not deps.intersection(graph)]
        if not ready:
            fail('TASK_CYCLE', ','.join(sorted(graph)))
            break
        for ident in ready:
            del graph[ident]
    for ident, requirement in requirements.items():
        owners(requirement.get('tasks'), tasks, 'REQUIREMENT_OWNER', ident)
        for task in requirement.get('tasks', []):
            if task in tasks and ident not in tasks[task].get('requirements', []):
                fail('REQUIREMENT_OWNER', ident + ': asymmetric ' + task)

    obligations = {}
    source_paths = set()
    for obligation in records(registry, 'source_obligations'):
        key = (obligation.get('kind'), obligation.get('id'))
        if key in obligations or key[0] not in SOURCE_PATTERNS:
            fail('SOURCE_OBLIGATIONS', key)
        obligations[key] = obligation
        owners(obligation.get('tasks'), tasks, 'OBLIGATION_OWNER', key)
        source = obligation.get('source')
        if not safe_relative(source):
            fail('SOURCE_OBLIGATIONS', 'invalid obligation source: ' + str(source))
        else:
            source_paths.add(repo_root / source)
    bodies = {}
    for path in sorted(source_paths):
        try:
            bodies[path] = path.read_text()
        except OSError as error:
            fail('SOURCE_OBLIGATIONS', error)
    # Each kind's declared source is authoritative, including the JSON H
    # catalog. Comparing its IDs catches a row removed from the registry.
    for kind, pattern in SOURCE_PATTERNS.items():
        expected = set()
        paths = {repo_root / o['source'] for o in obligations.values()
                 if o.get('kind') == kind and safe_relative(o.get('source'))}
        for path in paths:
            if path not in bodies:
                continue
            if path.suffix == '.json':
                if kind != 'regression_family':
                    fail('SOURCE_OBLIGATIONS', 'unsupported JSON source kind: ' + kind)
                    continue
                try:
                    catalog = load_json(path)
                    ids = [case['id'] for case in catalog['cases']]
                    if len(ids) != len(set(ids)):
                        fail('SOURCE_OBLIGATIONS', 'duplicate catalog family')
                    expected.update(ids)
                except (ValueError, KeyError, TypeError) as error:
                    fail('SOURCE_OBLIGATIONS', error)
            else:
                ids = re.findall(pattern, bodies[path], re.M)
                if kind == 'overlap_row':
                    ids = ['OV' + ident for ident in ids]
                if len(ids) != len(set(ids)):
                    fail('SOURCE_OBLIGATIONS', 'duplicate source ID: ' + str(path))
                expected.update(ids)
        actual = {ident for k, ident in obligations if k == kind}
        if not expected or actual != expected:
            fail('SOURCE_OBLIGATIONS', kind + ': source/registry IDs differ')
    coverage = {}
    for row in records(ledger, 'obligation_coverage'):
        key = (row.get('kind'), row.get('id'))
        if key in coverage:
            fail('OBLIGATION_COVERAGE', 'duplicate ' + str(key))
        coverage[key] = row
        owners(row.get('owners'), tasks, 'OBLIGATION_OWNER', key)
        if key in obligations and not set(row.get('owners', [])).issubset(obligations[key].get('tasks', [])):
            fail('OBLIGATION_OWNER', 'unmapped owner ' + str(key))
    if coverage.keys() != obligations.keys():
        fail('OBLIGATION_COVERAGE', 'ledger and registry obligation sets differ')

    def references(value, context):
        if not isinstance(value, dict):
            fail('DANGLING_REFERENCE', context + ': missing reference object')
            return
        for label, kind in REFERENCE_KINDS.items():
            ids = value.get(label)
            known = {ident for k, ident in obligations if k == kind}
            if not isinstance(ids, list) or any(i not in known for i in ids):
                fail('DANGLING_REFERENCE', context + ': ' + label)
        owners(value.get('tasks'), tasks, 'DANGLING_REFERENCE', context + ': tasks')

    donors = indexed(records(ledger, 'donors'), 'donor')
    files = indexed(records(ledger, 'files'), 'file')
    groups = indexed(records(ledger, 'port_groups'), 'port group')
    for ident, donor in donors.items():
        if not SHA.fullmatch(str(donor.get('commit', ''))):
            fail('COMMIT', 'donor ' + ident)
        if not SHA.fullmatch(str(donor.get('tree', ''))):
            fail('TREE', ident)
        for key in ('project', 'host', 'repository_path'):
            if not isinstance(donor.get(key), str) or not donor[key]:
                fail('DONOR_AUTHORITY', ident + ': ' + key)
        entries = donor.get('selected_tree_entries')
        if not isinstance(entries, dict):
            fail('SELECTED_TREE_PATH', ident)
        elif any(not safe_relative(path) or not SHA256.fullmatch(str(sha)) for path, sha in entries.items()):
            fail('SOURCE_EVIDENCE', ident + ': invalid selected tree entry')
    selection = ledger.get('selection', {})
    selected_ids = selection.get('selected_file_ids', [])
    if (not isinstance(selected_ids, list) or set(selected_ids) != files.keys()
            or len(selected_ids) != len(files) or selection.get('selected_file_count') != len(files)):
        fail('SELECTED_INPUTS', 'selected file inventory is incomplete or duplicated')
    if selection.get('unselected_disposition') != 'RESEARCH_ONLY_NOT_ADOPTED':
        fail('SELECTED_INPUTS', 'unselected references need explicit research disposition')
    for donor_id, donor in donors.items():
        recorded_paths = {f.get('path') for f in files.values() if f.get('donor') == donor_id}
        if set(donor.get('selected_tree_entries', {})) != recorded_paths:
            fail('SELECTED_INPUTS', donor_id + ': observed selected tree and file inventory differ')
    for ident, record in files.items():
        donor = donors.get(record.get('donor'), {})
        path = record.get('path')
        if not safe_relative(path) or ident != str(record.get('donor')) + ':' + str(path):
            fail('SOURCE_PATH', ident)
        if not SHA.fullmatch(str(record.get('commit', ''))) or record.get('commit') != donor.get('commit'):
            fail('COMMIT', ident)
        sha = record.get('sha256')
        if not SHA256.fullmatch(str(sha or '')):
            fail('FILE_SHA256', ident)
        if (record.get('owner') not in tasks
                or record.get('owner') not in record.get('references', {}).get('tasks', [])):
            fail('OWNER', ident)
        references(record.get('references'), ident)
        contracts = record.get('intended_contracts')
        if not isinstance(contracts, list) or not contracts or any(g not in groups for g in contracts):
            fail('CONTRACT', ident)
        evidence = record.get('source_evidence', {})
        observed_tree = donor.get('selected_tree_entries', {})
        if path not in observed_tree or evidence.get('exists_at_commit') is not True:
            fail('SELECTED_TREE_PATH', ident)
        if (not SHA256.fullmatch(str(evidence.get('head_blob_sha256', '')))
                or evidence.get('head_blob_sha256') != observed_tree.get(path)
                or evidence.get('observed_sha256') != sha):
            fail('SOURCE_EVIDENCE', ident)
        dirty = record.get('dirty_sha256')
        if (dirty != evidence.get('dirty_sha256')
                or (dirty is not None and (not SHA256.fullmatch(str(dirty)) or dirty != sha or dirty == evidence.get('head_blob_sha256')))
                or (dirty is None and sha != evidence.get('head_blob_sha256'))):
            fail('DIRTY_SHA256', ident)
        license_info = record.get('license', {})
        if not isinstance(license_info, dict):
            license_info = {}
        spdx = license_info.get('spdx')
        if spdx not in LICENSES or not license_info.get('resolution'):
            fail('LICENSE', ident)
        raw_declared = license_info.get('raw_effective_license_observation')
        raw_spdx = license_info.get('raw_spdx_observation')
        normalized = [v for v in (raw_declared or []) if v != '"']
        if (not isinstance(raw_spdx, list)
                or (raw_declared is not None and not isinstance(raw_declared, list))
                or (spdx != 'NOASSERTION' and normalized != [spdx])
                or (spdx == 'NOASSERTION' and normalized)
                or ('"' in (raw_declared or []) and not license_info.get('normalization_note'))
                or (license_info.get('resolution') == 'explicit_spdx' and spdx not in raw_spdx)):
            fail('LICENSE_OBSERVATION', ident)
        license_evidence = license_info.get('evidence')
        if not isinstance(license_evidence, list) or (spdx != 'NOASSERTION' and not license_evidence):
            fail('LICENSE', ident + ': missing license evidence')
        elif any(not isinstance(e, dict) or not safe_relative(e.get('path')) or not SHA256.fullmatch(str(e.get('sha256', ''))) for e in license_evidence):
            fail('LICENSE', ident + ': invalid license evidence')
        adoption = record.get('adoption', {})
        if adoption.get('disposition') not in DISPOSITIONS or adoption.get('copy_status') not in {'NOT_COPIED', 'BLOCKED'}:
            fail('ADOPTION', ident)
        if spdx == 'NOASSERTION':
            if (adoption.get('disposition') != 'REFERENCE_ONLY' or adoption.get('copy_status') != 'BLOCKED'
                    or adoption.get('destination_license') is not None or not adoption.get('blocked_reason')):
                fail('LICENSE_COPY_BLOCKED', ident)
        elif adoption.get('destination_license') not in (None, spdx):
            fail('LICENSE_RELABEL', ident)
        issue_test = record.get('source_issue_test', {})
        if not issue_test.get('issues') or not isinstance(issue_test.get('existing_symbols'), list):
            fail('SOURCE_ISSUE_TEST', ident)
        if any(g not in groups for g in issue_test.get('issues', [])):
            fail('SOURCE_ISSUE_TEST', ident)
    for ident, group in groups.items():
        if group.get('owner') not in tasks:
            fail('OWNER', ident)
        references(group.get('references'), ident)
        source_ids = group.get('source_file_ids')
        if not group.get('contract') or not isinstance(source_ids, list) or not source_ids or any(f not in files for f in source_ids):
            fail('CONTRACT', ident)
        else:
            for file_id in source_ids:
                if ident not in files[file_id].get('intended_contracts', []):
                    fail('CONTRACT', ident + ': asymmetric ' + file_id)
    for file_id, record in files.items():
        for group_id in record.get('intended_contracts', []):
            if group_id in groups and file_id not in groups[group_id].get('source_file_ids', []):
                fail('CONTRACT', file_id + ': asymmetric ' + group_id)
    return errors


def verify_local_sources(ledger, source_roots):
    errors, unavailable = [], []

    def git(root, *args):
        # No replace refs, optional locks or external diff/textconv helpers.
        return subprocess.run(['git', '--no-replace-objects', '--no-optional-locks', '-C', str(root), *args],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)

    for donor in ledger['donors']:
        ident = donor['id']
        root = source_roots.get(ident)
        if root is None and donor['host'] == 'local':
            root = Path(donor['repository_path'])
        if root is None or not root.is_dir():
            unavailable.append({'code': 'SOURCE_UNAVAILABLE', 'context': ident})
            continue
        try:
            probe = git(root, 'cat-file', '-t', donor['commit'])
            if probe.returncode or probe.stdout.strip() != b'commit':
                unavailable.append({'code': 'COMMIT_UNAVAILABLE', 'context': ident})
                continue
            tree = git(root, 'rev-parse', donor['commit'] + '^{tree}')
            if tree.returncode or tree.stdout.decode().strip() != donor['tree']:
                errors.append({'code': 'GIT_SOURCE_TREE', 'context': ident})
                continue
            for record in (f for f in ledger['files'] if f['donor'] == ident):
                blob = git(root, 'cat-file', 'blob', donor['commit'] + ':' + record['path'])
                if blob.returncode:
                    errors.append({'code': 'GIT_SOURCE_PATH', 'context': record['id']})
                    continue
                if digest(blob.stdout) != record['source_evidence']['head_blob_sha256']:
                    errors.append({'code': 'GIT_BLOB_HASH', 'context': record['id']})
                if record['dirty_sha256'] is not None:
                    selected_path = root / record['path']
                    # A selected dirty path cannot escape the repository through symlinks.
                    if not selected_path.resolve().is_relative_to(root.resolve()):
                        errors.append({'code': 'LOCAL_DIRTY_HASH', 'context': record['id']})
                        continue
                    try:
                        actual = digest(selected_path.read_bytes())
                    except OSError:
                        unavailable.append({'code': 'DIRTY_SOURCE_UNAVAILABLE', 'context': record['id']})
                        continue
                    if actual != record['dirty_sha256']:
                        errors.append({'code': 'LOCAL_DIRTY_HASH', 'context': record['id']})
        except (OSError, subprocess.TimeoutExpired) as error:
            unavailable.append({'code': 'SOURCE_UNAVAILABLE', 'context': ident + ': ' + str(error)})
    return errors, unavailable


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('registry', type=Path)
    parser.add_argument('--ledger', type=Path, default=ROOT / 'docs/provenance/donors.json')
    parser.add_argument('--repo-root', type=Path, default=ROOT, help='root of registry source-document paths')
    parser.add_argument('--verify-local-sources', action='store_true')
    parser.add_argument('--source-root', action='append', default=[], metavar='ALIAS=PATH',
                        help='explicit local checkout for an observed donor; never initiates SSH')
    args = parser.parse_args(argv)
    report = {'status': 'INVALID', 'mode': 'STRUCTURAL', 'source_verification': 'NOT_RUN',
              'qualification': 'NOT_EVALUATED', 'errors': [], 'unavailable': []}
    try:
        registry = load_json(args.registry)
        ledger = load_json(args.ledger)
        if not isinstance(registry, dict) or not isinstance(ledger, dict):
            raise ValueError('top-level JSON values must be objects')
        report['errors'] = validate(registry, ledger, args.repo_root)
        roots = {}
        for value in args.source_root:
            alias, separator, path = value.partition('=')
            if not separator or not alias or not path or alias in roots:
                raise ValueError('source root must be unique ALIAS=PATH')
            roots[alias] = Path(path)
        known = {d['id'] for d in ledger.get('donors', [])}
        if roots.keys() - known:
            raise ValueError('unknown source-root aliases: ' + ','.join(sorted(roots.keys() - known)))
        if not report['errors'] and args.verify_local_sources:
            report['mode'] = 'STRUCTURAL_AND_LOCAL_SOURCES'
            report['errors'], report['unavailable'] = verify_local_sources(ledger, roots)
            report['source_verification'] = ('INVALID' if report['errors'] else
                                             'INCOMPLETE' if report['unavailable'] else 'VERIFIED_SELECTED_SOURCES')
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        report['errors'].append({'code': 'JSON_INPUT', 'context': str(error)})
    if report['errors']:
        exit_code = 3
    elif report['unavailable']:
        report['status'], exit_code = 'INCOMPLETE', 2
    else:
        report['status'], exit_code = 'VALID', 0
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
