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
DISPOSITIONS = {'PORT_SOURCE', 'DEPENDENCY_ADAPTER', 'INDEPENDENT_CONTRACT',
                'VECTORS_ONLY', 'PRODUCT_LOCAL', 'REFERENCE_ONLY'}
OWNER_GRANT = {
    'id': 'OWNER-2026-10-18', 'authority': 'USER_DECLARED_AUTHOR', 'status': 'PROVISIONAL',
    'scope': 'USER_CONTRIBUTIONS_IN_SELECTED_FILES',
    'decision_ref': 'docs/superpowers/specs/2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination',
    'allowed_destinations': {'host': 'Apache-2.0', 'bpf-target': 'GPL-2.0-only',
                             'shared-target-source': 'Apache-2.0 OR GPL-2.0-only',
                             'host-build-tool': 'Apache-2.0', 'data-document': 'Apache-2.0'},
}
OFFERED_OPTIONS = {
    'Apache-2.0': {'Apache-2.0'}, 'GPL-2.0-only': {'GPL-2.0-only'},
    'GPL-3.0-or-later': {'GPL-3.0-or-later'},
    'Apache-2.0 WITH LLVM-exception': {'Apache-2.0 WITH LLVM-exception'},
    'GPL-2.0-or-later': {'GPL-2.0-only', 'GPL-2.0-or-later'},
    'MIT OR Apache-2.0': {'MIT', 'Apache-2.0'},
}
DESTINATIONS = set().union(*OFFERED_OPTIONS.values()) | {'Apache-2.0 OR GPL-2.0-only'}
ADOPTION_FIELDS = {'disposition', 'copy_status', 'decision_status', 'source_scope', 'ownership_basis',
                   'artifact_role', 'destination_license', 'authorization_ref', 'third_party_terms', 'blocked_reason'}
FRAGMENT_FIELDS = {'source_scope', 'offered_spdx', 'selected_option', 'license_evidence', 'notice_evidence'}


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


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def positive_integer(value):
    return type(value) is int and value > 0


def document_link(value, root):
    if not isinstance(value, str):
        return False
    path, separator, anchor = value.partition('#')
    if not safe_relative(path) or (separator and not anchor):
        return False
    try:
        body = (root / path).read_text()
    except OSError:
        return False
    if not separator:
        return True
    headings = re.findall(r'^#{1,6}\s+(.+?)\s*#*$', body, re.M)
    anchors = {re.sub(r'[^\w -]', '', heading.lower()).replace(' ', '-') for heading in headings}
    return anchor in anchors or ('id="' + anchor + '"') in body


def valid_scope(value):
    if value == 'FILE':
        return True
    if not isinstance(value, list) or not value:
        return False
    previous = 0
    for pair in value:
        if (not isinstance(pair, list) or len(pair) != 2
                or not all(positive_integer(v) for v in pair)
                or pair[0] > pair[1] or pair[0] <= previous):
            return False
        previous = pair[1]
    return True


def scope_contains(parent, child):
    if parent == 'FILE':
        return True
    if child == 'FILE' or parent is None:
        return False
    return all(any(first <= start and end <= last for first, last in merged_ranges(parent))
               for start, end in child)


def merged_ranges(ranges):
    merged = []
    for first, last in sorted(ranges):
        if merged and first <= merged[-1][1] + 1:
            merged[-1][1] = max(last, merged[-1][1])
        else:
            merged.append([first, last])
    return merged


def validate_adoption(adoption, authorizations, fail, ident):
    """Check the frozen declarations, without adjudicating source ownership."""
    def reject(code, detail):
        fail(code, ident + ': ' + detail)

    def enum(value, values):
        return isinstance(value, str) and value in values

    if not isinstance(adoption, dict) or set(adoption) != ADOPTION_FIELDS:
        reject('ADOPTION', 'exact adoption fields required')
        return
    scope, role = adoption['source_scope'], adoption['artifact_role']
    basis, status = adoption['ownership_basis'], adoption['decision_status']
    destination, authorization = adoption['destination_license'], adoption['authorization_ref']
    terms, reason = adoption['third_party_terms'], adoption['blocked_reason']
    if (not enum(adoption['disposition'], DISPOSITIONS)
            or not enum(adoption['copy_status'], {'NOT_COPIED', 'BLOCKED'})
            or not enum(status, {'READY_FOR_SELECTED_SCOPE', 'NEEDS_DECISION', 'REFERENCE_ONLY'})
            or not enum(basis, {'USER_OWNED', 'THIRD_PARTY', 'MIXED', 'UNRESOLVED'})
            or (scope is not None and not valid_scope(scope))
            or (role is not None and not enum(role, OWNER_GRANT['allowed_destinations']))
            or (destination is not None and not enum(destination, DESTINATIONS))
            or (authorization is not None and not nonempty(authorization))
            or (terms is not None and not isinstance(terms, list))
            or (reason is not None and not nonempty(reason))):
        reject('ADOPTION', 'invalid field type, scope or enum')
        return
    if authorization is not None and (authorization not in authorizations or basis in {'THIRD_PARTY', 'UNRESOLVED'}):
        reject('AUTHORIZATION', 'grant does not resolve within user contributions')
    ready = status == 'READY_FOR_SELECTED_SCOPE'
    if ready:
        if (scope is None or role is None or destination is None or reason is not None
                or adoption['copy_status'] != 'NOT_COPIED' or basis == 'UNRESOLVED'
                or adoption['disposition'] in {'REFERENCE_ONLY', 'PRODUCT_LOCAL'} or terms is None):
            reject('ADOPTION_COMPLETENESS', 'ready scope requires resolved copy declarations')
        if basis in {'USER_OWNED', 'MIXED'} and authorization not in authorizations:
            reject('AUTHORIZATION', 'ready owner portion requires canonical grant')
        if basis in {'USER_OWNED', 'MIXED'} and role is not None:
            if destination != OWNER_GRANT['allowed_destinations'][role]:
                reject('ADOPTION_ROLE', 'owner destination differs from role grant')
        if basis == 'USER_OWNED' and terms != [] and terms is not None:
            reject('ADOPTION_FRAGMENT', 'user-only selection retains upstream records')
        if basis in {'MIXED', 'THIRD_PARTY'} and not terms:
            reject('ADOPTION_FRAGMENT', 'upstream selection requires fragment records')
    elif (not nonempty(reason) or (status == 'NEEDS_DECISION' and adoption['copy_status'] != 'NOT_COPIED')
          or (status == 'REFERENCE_ONLY' and (adoption['copy_status'] != 'BLOCKED'
              or adoption['disposition'] not in {'REFERENCE_ONLY', 'PRODUCT_LOCAL'} or destination is not None))):
        reject('ADOPTION', 'unresolved/reference state requires its reason and copy boundary')

    fragments, retained = [], []
    for fragment in terms or []:
        if not isinstance(fragment, dict) or set(fragment) != FRAGMENT_FIELDS:
            reject('ADOPTION_FRAGMENT', 'exact fragment fields bind source to parent pin/hash')
            continue
        fragment_scope = fragment['source_scope']
        if (not valid_scope(fragment_scope) or scope is None
                or not scope_contains(scope, fragment_scope)):
            reject('ADOPTION_FRAGMENT', 'fragment must be contained in selected source scope')
        else:
            fragments.append(fragment_scope)
        offered, selected = fragment['offered_spdx'], fragment['selected_option']
        if not nonempty(offered) or (selected is not None and not nonempty(selected)):
            reject('ADOPTION_FRAGMENT', 'offered/selected expression type')
        elif selected is not None and selected not in OFFERED_OPTIONS.get(offered, set()):
            reject('ADOPTION_OPTION', 'option not supported by observed upstream expression')
        if ready and selected is None:
            reject('ADOPTION_COMPLETENESS', 'upstream option remains unresolved')
        for key in ('license_evidence', 'notice_evidence'):
            evidence = fragment[key]
            if (not isinstance(evidence, list) or (key == 'license_evidence' and selected is not None and not evidence)
                    or (isinstance(evidence, list) and any(
                        not isinstance(e, dict) or set(e) != {'path', 'sha256'}
                        or not safe_relative(e['path']) or not isinstance(e['sha256'], str)
                        or not SHA256.fullmatch(e['sha256']) for e in evidence))):
                reject('ADOPTION_FRAGMENT', 'invalid ' + key)
        retained.append(selected)
        if ready:
            allowed = ({'Apache-2.0', 'Apache-2.0 WITH LLVM-exception'}
                       if role in {'host', 'host-build-tool', 'data-document'} else
                       {'GPL-2.0-only', 'GPL-2.0-or-later'} if role == 'bpf-target' else set())
            if not enum(selected, allowed):
                reject('ADOPTION_ROLE', 'upstream option requires unresolved role/dependency review')
    if any(s == 'FILE' for s in fragments):
        overlapping = len(fragments) > 1
        full_coverage = len(fragments) == 1 and scope == 'FILE'
    else:
        ranges = sorted(pair for s in fragments for pair in s)
        overlapping = any(right[0] <= left[1] for left, right in zip(ranges, ranges[1:]))
        full_coverage = scope is not None and scope != 'FILE' and merged_ranges(ranges) == merged_ranges(scope)
    if overlapping:
        reject('ADOPTION_FRAGMENT', 'upstream fragments overlap')
    if ready and basis == 'THIRD_PARTY':
        if not full_coverage:
            reject('ADOPTION_FRAGMENT', 'upstream fragments must cover the whole selected scope')
        if any(destination != option for option in retained):
            reject('ADOPTION_ROLE', 'upstream destination must retain every selected option')


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
        if not isinstance(values, list) or not values or any(not isinstance(v, str) or v not in known for v in values):
            fail(code, context)

    if registry.get('kind') != 'SCOPEBASE_PLANNING_TRACEABILITY' or registry.get('schema_version') != '1.0.0':
        fail('SCHEMA', 'unsupported traceability kind/version')
    if ledger.get('kind') != 'SCOPEBASE_SOURCE_INTAKE' or ledger.get('schema_version') != '2.0.0':
        fail('SCHEMA', 'unsupported intake kind/version')
    if ledger.get('qualification') != 'NOT_RUN':
        fail('QUALIFICATION_CLAIM', 'source intake cannot qualify production capabilities')
    grants = ledger.get('authorizations')
    authorizations = {}
    if (not isinstance(grants, list) or grants != [OWNER_GRANT]
            or not document_link(OWNER_GRANT['decision_ref'], repo_root)):
        fail('AUTHORIZATION', 'exact canonical provisional owner grant and decision anchor required')
    else:
        authorizations[OWNER_GRANT['id']] = OWNER_GRANT
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
    canonical_cases = {}
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
                    canonical_cases.update((case['id'], case) for case in catalog['cases'])
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

    def references(value, context, labels=REFERENCE_KINDS, require_tasks=True):
        if not isinstance(value, dict):
            fail('DANGLING_REFERENCE', context + ': missing reference object')
            return
        for label in labels:
            kind = REFERENCE_KINDS[label]
            ids = value.get(label)
            known = {ident for k, ident in obligations if k == kind}
            if not isinstance(ids, list) or any(not isinstance(i, str) or i not in known for i in ids):
                fail('DANGLING_REFERENCE', context + ': ' + label)
        if require_tasks:
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
        if (not isinstance(contracts, list) or not contracts
                or any(not isinstance(g, str) or g not in groups for g in contracts)):
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
        # Unknown source expressions remain observations, not newly supported
        # destination options. The finite admission policy lives above.
        if not nonempty(spdx) or not license_info.get('resolution'):
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
        validate_adoption(record.get('adoption'), authorizations, fail, ident)
        issue_test = record.get('source_issue_test', {})
        if not isinstance(issue_test, dict):
            issue_test = {}
        issues, symbols = issue_test.get('issues'), issue_test.get('existing_symbols')
        if (not isinstance(issues, list) or not issues
                or any(not isinstance(g, str) or g not in groups for g in issues)
                or not isinstance(symbols, list)):
            fail('SOURCE_ISSUE_TEST', ident)
        elif any(not isinstance(s, dict) or not nonempty(s.get('name'))
                 or not positive_integer(s.get('line')) for s in symbols):
            fail('SOURCE_ISSUE_TEST', ident)
    for ident, group in groups.items():
        if group.get('owner') not in tasks:
            fail('OWNER', ident)
        references(group.get('references'), ident)
        source_ids = group.get('source_file_ids')
        if (not nonempty(group.get('contract')) or not isinstance(source_ids, list) or not source_ids
                or any(not isinstance(f, str) or f not in files for f in source_ids)):
            fail('CONTRACT', ident)
        else:
            for file_id in source_ids:
                memberships = files[file_id].get('intended_contracts')
                if not isinstance(memberships, list) or ident not in memberships:
                    fail('CONTRACT', ident + ': asymmetric ' + file_id)
        regressions = group.get('selected_regressions_to_port_or_adapt')
        if not isinstance(regressions, list) or not regressions:
            fail('REGRESSION_REFERENCE', ident + ': missing regression collection')
            regressions = []
        for regression in regressions:
            if not isinstance(regression, dict):
                fail('REGRESSION_REFERENCE', ident + ': malformed regression')
                continue
            alias, path = regression.get('alias'), regression.get('path')
            source_id = str(alias) + ':' + str(path)
            source = files.get(source_id, {})
            issue_test = source.get('source_issue_test')
            issue_test = issue_test if isinstance(issue_test, dict) else {}
            symbols = issue_test.get('existing_symbols')
            if (not isinstance(alias, str) or alias not in donors or not safe_relative(path)
                    or source.get('donor') != alias or source.get('path') != path
                    or not isinstance(source_ids, list) or source_id not in source_ids
                    or not isinstance(source.get('intended_contracts'), list)
                    or ident not in source['intended_contracts']
                    or not isinstance(issue_test.get('issues'), list) or ident not in issue_test['issues']
                    or not nonempty(regression.get('name')) or not positive_integer(regression.get('line'))
                    or regression.get('evidence') != 'SYMBOL_PRESENT_IN_INSPECTED_SOURCE_NOT_RUN'
                    or not isinstance(symbols, list)
                    or not any(isinstance(s, dict) and s.get('name') == regression['name']
                               and s.get('line') == regression['line'] for s in symbols)):
                fail('REGRESSION_REFERENCE', ident + ': ' + source_id)
    for file_id, record in files.items():
        contracts = record.get('intended_contracts')
        for group_id in contracts if isinstance(contracts, list) else []:
            if (isinstance(group_id, str) and group_id in groups
                    and (not isinstance(groups[group_id].get('source_file_ids'), list)
                         or file_id not in groups[group_id]['source_file_ids'])):
                fail('CONTRACT', file_id + ': asymmetric ' + group_id)
    families = ledger.get('case_family_inputs')
    expected_families = {ident for kind, ident in obligations if kind == 'regression_family'}
    if not isinstance(families, dict):
        fail('CASE_FAMILY', 'missing family collection')
        families = {}
    if set(families) != expected_families:
        fail('CASE_FAMILY', 'family inventory differs from canonical obligations')
    for ident, family in families.items():
        if not isinstance(family, dict):
            fail('CASE_FAMILY', ident + ': malformed family')
            continue
        for key in ('short_contract', 'independent_oracle', 'scope_limits'):
            if not nonempty(family.get(key)):
                fail('CASE_FAMILY', ident + ': ' + key)
        control = family.get('known_bad_control')
        if (not isinstance(control, dict) or control.get('status') != 'PLANNED_CONTROL_NOT_RUN'
                or not nonempty(control.get('mutation_or_countermodel'))
                or not nonempty(control.get('required_failure_layer'))):
            fail('CASE_FAMILY', ident + ': known_bad_control')
        references(family.get('related_obligations'), ident, labels=('G', 'UC', 'TODO'), require_tasks=False)
        anchors = family.get('inspected_donor_anchors')
        if not isinstance(anchors, list) or not anchors:
            fail('CASE_FAMILY', ident + ': missing donor anchors')
            anchors = []
        for anchor in anchors:
            if not isinstance(anchor, dict):
                fail('CASE_FAMILY', ident + ': malformed anchor')
                continue
            alias = anchor.get('alias')
            # Preserve explicitly unresolved coordination-workspace research,
            # without pretending that it belongs to a selected product donor.
            unresolved = (alias is None and nonempty(anchor.get('source_context'))
                          and nonempty(anchor.get('source_resolution_status')))
            research_root = repo_root / 'docs/research/2026-10-17-shared-libraries'
            if (not (unresolved or (isinstance(alias, str) and alias in donors))
                    or not nonempty(anchor.get('location')) or not nonempty(anchor.get('coverage'))
                    or not (document_link(anchor.get('pin_document'), research_root)
                            or document_link(anchor.get('pin_document'), repo_root))):
                fail('CASE_FAMILY', ident + ': donor anchor')
        origin = canonical_cases.get(ident, {}).get('origin')
        if origin is not None and family.get('origin') != origin:
            fail('CASE_FAMILY', ident + ': explicit new origin')
    return errors


def verify_local_sources(ledger, source_roots):
    errors, unavailable = [], []

    def git(root, *args):
        # Global controls apply to every invocation, including feature probing.
        # Never obtain missing promisor objects or interpret a selected pathspec.
        return subprocess.run(['git', '--no-lazy-fetch', '--no-replace-objects',
                               '--no-optional-locks', '--literal-pathspecs', '-C', str(root), *args],
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
            supported = git(root, '--version')
            if supported.returncode:
                unavailable.append({'code': 'GIT_INSPECTION_UNAVAILABLE', 'context': ident})
                continue
            probe = git(root, 'cat-file', '-t', donor['commit'])
            if probe.returncode:
                unavailable.append({'code': 'COMMIT_UNAVAILABLE', 'context': ident})
                continue
            if probe.stdout.strip() != b'commit':
                errors.append({'code': 'GIT_SOURCE_COMMIT', 'context': ident})
                continue
            tree = git(root, 'rev-parse', donor['commit'] + '^{tree}')
            if tree.returncode:
                unavailable.append({'code': 'TREE_SOURCE_UNAVAILABLE', 'context': ident})
                continue
            if tree.stdout.decode().strip() != donor['tree']:
                errors.append({'code': 'GIT_SOURCE_TREE', 'context': ident})
                continue
            for record in (f for f in ledger['files'] if f['donor'] == ident):
                entry = git(root, 'ls-tree', '-z', donor['commit'], '--', record['path'])
                if entry.returncode:
                    unavailable.append({'code': 'TREE_SOURCE_UNAVAILABLE', 'context': record['id']})
                    continue
                entries = [item.split(b'\t', 1) for item in entry.stdout.split(b'\0') if item]
                if (len(entries) != 1 or len(entries[0]) != 2
                        or entries[0][1] != record['path'].encode()
                        or entries[0][0].split()[1:2] != [b'blob']):
                    errors.append({'code': 'GIT_SOURCE_PATH', 'context': record['id']})
                    continue
                blob = git(root, 'cat-file', 'blob', entries[0][0].split()[2].decode())
                if blob.returncode:
                    unavailable.append({'code': 'BLOB_SOURCE_UNAVAILABLE', 'context': record['id']})
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
