"""Behavioral intake controls: real JSON documents and a temporary Git donor."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'check_traceability.py'
REPO_ROOT = SCRIPT.parents[2]
SPEC = importlib.util.spec_from_file_location('intake', SCRIPT)
INTAKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INTAKE)


class IntakeFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'donor'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture Author')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.source = b'// SPDX-License-Identifier: GPL-3.0-or-later\n// regression: retains_original_owner\n'
        (self.repo / 'owner.rs').write_bytes(self.source)
        self.git('add', 'owner.rs')
        self.git('commit', '-qm', 'Independent fixture source')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.tree = self.git('rev-parse', 'HEAD^{tree}').strip()
        self.digest = hashlib.sha256(self.source).hexdigest()
        source_text = {'regression_family': '| H01 | contract |\n',
                       'public_contract_gap': '## G01. Gap\n',
                       'user_conformance': '| **UC01** | contract |\n',
                       'research_todo': '| F01 | obligation |\n',
                       'overlap_row': '| 1 overlap | contract |\n'}
        for kind, text in source_text.items():
            (self.root / (kind + '.md')).write_text(text)
        kinds = [('regression_family', 'H01'), ('public_contract_gap', 'G01'),
                 ('user_conformance', 'UC01'), ('research_todo', 'F01'), ('overlap_row', 'OV1')]
        self.registry = {
            'schema_version': '1.0.0', 'kind': 'SCOPEBASE_PLANNING_TRACEABILITY',
            'tasks': [{'id': 'SB01', 'depends_on': [], 'requirements': ['SB-R01'], 'profile_gates': []}],
            'requirements': [{'id': 'SB-R01', 'tasks': ['SB01']}],
            'profiles': [], 'profile_extensions': [], 'profile_ids': [],
            'source_obligations': [{'kind': k, 'id': i, 'source': k + '.md', 'tasks': ['SB01']}
                                   for k, i in kinds],
        }
        refs = {'H': ['H01'], 'G': ['G01'], 'UC': ['UC01'], 'TODO': ['F01'], 'tasks': ['SB01']}
        self.ledger = {
            'schema_version': '2.0.0', 'kind': 'SCOPEBASE_SOURCE_INTAKE',
            'qualification': 'NOT_RUN',
            'selection': {'selected_file_ids': ['D:owner.rs'], 'selected_file_count': 1,
                          'unselected_disposition': 'RESEARCH_ONLY_NOT_ADOPTED'},
            'donors': [{'id': 'D', 'project': 'fixture', 'host': 'local',
                        'repository_path': str(self.repo), 'commit': self.commit, 'tree': self.tree,
                        'selected_tree_entries': {'owner.rs': self.digest}}],
            'files': [{'id': 'D:owner.rs', 'donor': 'D', 'path': 'owner.rs', 'commit': self.commit,
                       'sha256': self.digest, 'dirty_sha256': None, 'owner': 'SB01',
                       'intended_contracts': ['held-owner'], 'references': refs,
                       'license': {'spdx': 'GPL-3.0-or-later', 'resolution': 'explicit_spdx',
                                   'raw_spdx_observation': ['GPL-3.0-or-later'],
                                   'raw_effective_license_observation': ['GPL-3.0-or-later'],
                                   'evidence': [{'path': 'owner.rs', 'sha256': self.digest}]},
                       'adoption': {'disposition': 'PORT_SOURCE', 'copy_status': 'NOT_COPIED',
                                    'decision_status': 'READY_FOR_SELECTED_SCOPE', 'source_scope': 'FILE',
                                    'ownership_basis': 'USER_OWNED', 'artifact_role': 'host',
                                    'destination_license': 'Apache-2.0', 'authorization_ref': 'OWNER-2026-10-18',
                                    'third_party_terms': [], 'blocked_reason': None},
                       'source_evidence': {'exists_at_commit': True, 'head_blob_sha256': self.digest,
                                           'observed_sha256': self.digest, 'dirty_sha256': None},
                       'source_issue_test': {'issues': ['held-owner'],
                                             'existing_symbols': [{'name': 'retains_original_owner', 'line': 2}]}}],
            'port_groups': [{'id': 'held-owner', 'owner': 'SB01', 'references': refs,
                             'source_file_ids': ['D:owner.rs'], 'contract': 'retain original owner',
                             'selected_regressions_to_port_or_adapt': [
                                 {'alias': 'D', 'path': 'owner.rs', 'name': 'retains_original_owner',
                                  'line': 2, 'evidence': 'SYMBOL_PRESENT_IN_INSPECTED_SOURCE_NOT_RUN'}]}],
            'case_family_inputs': {'H01': {
                'short_contract': 'Retain the original owner',
                'inspected_donor_anchors': [{'alias': 'D', 'location': 'owner.rs:2',
                                            'coverage': 'INSPECTED_SOURCE',
                                            'pin_document': 'regression_family.md'}],
                'independent_oracle': 'Distinct original and successor byte sentinels',
                'known_bad_control': {'status': 'PLANNED_CONTROL_NOT_RUN',
                                      'mutation_or_countermodel': 'Reopen successor path',
                                      'required_failure_layer': 'original byte assertion'},
                'related_obligations': {'G': ['G01'], 'UC': ['UC01'], 'TODO': ['F01']},
                'scope_limits': 'Source inspection, no live qualification'}},
            'obligation_coverage': [{'kind': k, 'id': i, 'owners': ['SB01']} for k, i in kinds],
        }
        self.ledger['authorizations'] = [{
            'id': 'OWNER-2026-10-18', 'authority': 'USER_DECLARED_AUTHOR', 'status': 'PROVISIONAL',
            'scope': 'USER_CONTRIBUTIONS_IN_SELECTED_FILES',
            'decision_ref': 'docs/superpowers/specs/2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination',
            'allowed_destinations': {'host': 'Apache-2.0', 'bpf-target': 'GPL-2.0-only',
                                     'shared-target-source': 'Apache-2.0 OR GPL-2.0-only',
                                     'host-build-tool': 'Apache-2.0', 'data-document': 'Apache-2.0'}}]
        decision = self.root / 'docs/superpowers/specs/2026-10-18-scopebase-decisions.md'
        decision.parent.mkdir(parents=True)
        decision.write_text('## D03 — License by code ownership and actual build destination\n')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], check=True,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def run_check(self, *args):
        registry = self.root / 'registry.json'
        ledger = self.root / 'ledger.json'
        registry.write_text(json.dumps(self.registry))
        ledger.write_text(json.dumps(self.ledger))
        return subprocess.run([sys.executable, str(SCRIPT), str(registry), '--ledger', str(ledger),
                               '--repo-root', str(self.root), *args], text=True, capture_output=True)

    def assert_invalid(self, code, *args):
        result = self.run_check(*args)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertTrue(result.stdout, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['status'], 'INVALID')
        self.assertIn(code, {e['code'] for e in payload['errors']}, payload)
        self.assertEqual(payload['qualification'], 'NOT_EVALUATED')


class IntakeValidationTests(IntakeFixture, unittest.TestCase):
    def test_valid_structural_intake_does_not_claim_live_source_verification(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['source_verification'], 'NOT_RUN')
        self.assertEqual(payload['qualification'], 'NOT_EVALUATED')

    def test_valid_pinned_git_source_is_verified_explicitly(self):
        result = self.run_check('--verify-local-sources')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['source_verification'], 'VERIFIED_SELECTED_SOURCES')

    def test_promised_blob_is_incomplete_without_fetch(self):
        # Removing --no-lazy-fetch must expose an actual transport/store effect.
        twin = self.run_check('--verify-local-sources')
        self.assertEqual(twin.returncode, 0, twin.stdout + twin.stderr)
        self.git('config', 'uploadpack.allowFilter', 'true')
        partial = self.root / 'partial'
        subprocess.run(['git', 'clone', '--filter=blob:none', '--no-checkout',
                        self.repo.as_uri(), str(partial)], check=True, capture_output=True)
        blob_id = self.git('rev-parse', 'HEAD:owner.rs').strip()
        probe = subprocess.run(['git', '--no-lazy-fetch', '-C', str(partial),
                                'cat-file', '-e', blob_id], capture_output=True)
        self.assertNotEqual(probe.returncode, 0, 'control requires a truly absent promised blob')
        sentinel = self.root / 'transport-invoked'
        transport = self.root / 'upload-pack'
        transport.write_text('#!/bin/sh\nprintf invoked > "' + str(sentinel) +
                             '"\nexec git-upload-pack "$@"\n')
        transport.chmod(0o700)
        subprocess.run(['git', '-C', str(partial), 'config', 'remote.origin.uploadpack',
                        str(transport)], check=True, capture_output=True)

        def snapshot(directory):
            return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in directory.rglob('*') if p.is_file()}

        objects_before = snapshot(partial / '.git/objects')
        checkout_before = {p: h for p, h in snapshot(partial).items()
                           if not p.startswith('.git/objects/')}
        self.ledger['donors'][0]['repository_path'] = str(partial)
        result = self.run_check('--verify-local-sources')
        with self.subTest(assertion='incomplete'):
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['source_verification'], 'INCOMPLETE')
        with self.subTest(assertion='transport never invoked'):
            self.assertFalse(sentinel.exists())
        with self.subTest(assertion='object store unchanged'):
            self.assertEqual(snapshot(partial / '.git/objects'), objects_before)
        with self.subTest(assertion='checkout unchanged'):
            self.assertEqual({p: h for p, h in snapshot(partial).items()
                              if not p.startswith('.git/objects/')}, checkout_before)

    def test_catalog_json_is_the_authoritative_family_inventory(self):
        (self.root / 'catalog.json').write_text(json.dumps({'cases': [{'id': 'H01'}]}))
        self.registry['source_obligations'][0]['source'] = 'catalog.json'
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_sha_rejected(self):
        del self.ledger['files'][0]['sha256']
        self.assert_invalid('FILE_SHA256')

    def test_missing_license_rejected(self):
        del self.ledger['files'][0]['license']
        self.assert_invalid('LICENSE')

    def test_missing_owner_rejected(self):
        del self.ledger['files'][0]['owner']
        self.assert_invalid('OWNER')

    def test_branch_name_cannot_replace_commit(self):
        self.ledger['files'][0]['commit'] = 'main'
        self.assert_invalid('COMMIT')

    def test_donor_branch_name_cannot_replace_commit(self):
        self.ledger['donors'][0]['commit'] = 'main'
        self.assert_invalid('COMMIT')

    def test_dangling_family_references_rejected(self):
        for kind, value in [('H', 'H99'), ('G', 'G99'), ('UC', 'UC99'), ('TODO', 'F99'), ('tasks', 'SB99')]:
            with self.subTest(kind=kind):
                original = copy.deepcopy(self.ledger)
                self.ledger['files'][0]['references'][kind] = [value]
                self.assert_invalid('DANGLING_REFERENCE')
                self.ledger = original

    def test_missing_registry_obligation_detected_against_source_document(self):
        self.registry['source_obligations'].pop()
        self.assert_invalid('SOURCE_OBLIGATIONS')

    def test_missing_ledger_obligation_is_not_silent(self):
        self.ledger['obligation_coverage'].pop()
        self.assert_invalid('OBLIGATION_COVERAGE')

    def test_unowned_registry_obligation_rejected(self):
        self.registry['source_obligations'][0]['tasks'] = []
        self.assert_invalid('OBLIGATION_OWNER')

    def test_unowned_requirement_rejected(self):
        self.registry['requirements'][0]['tasks'] = []
        self.assert_invalid('REQUIREMENT_OWNER')

    def test_missing_selected_observation_detected(self):
        self.ledger['files'].clear()
        self.assert_invalid('SELECTED_INPUTS')

    def test_path_absent_from_observed_selected_tree_rejected(self):
        self.ledger['donors'][0]['selected_tree_entries'].clear()
        self.assert_invalid('SELECTED_TREE_PATH')

    def test_path_absent_from_actual_pinned_tree_rejected(self):
        self.ledger['donors'][0]['selected_tree_entries']['absent.rs'] = self.digest
        record = self.ledger['files'][0]
        record['path'] = 'absent.rs'
        record['id'] = 'D:absent.rs'
        self.ledger['selection']['selected_file_ids'] = ['D:absent.rs']
        self.ledger['port_groups'][0]['source_file_ids'] = ['D:absent.rs']
        self.ledger['port_groups'][0]['selected_regressions_to_port_or_adapt'][0]['path'] = 'absent.rs'
        del self.ledger['donors'][0]['selected_tree_entries']['owner.rs']
        self.assert_invalid('GIT_SOURCE_PATH', '--verify-local-sources')

    def test_blob_hash_mismatch_rejected(self):
        self.ledger['files'][0]['source_evidence']['head_blob_sha256'] = '1' * 64
        self.assert_invalid('SOURCE_EVIDENCE')

    def test_dirty_hash_mismatch_rejected(self):
        self.ledger['files'][0]['dirty_sha256'] = '1' * 64
        self.assert_invalid('DIRTY_SHA256')

    def make_dirty(self):
        content = self.source + b'// selected WIP regression\n'
        (self.repo / 'owner.rs').write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        record = self.ledger['files'][0]
        record['sha256'] = record['dirty_sha256'] = digest
        record['source_evidence']['observed_sha256'] = digest
        record['source_evidence']['dirty_sha256'] = digest

    def test_dirty_source_valid_twin_checks_pinned_and_worktree_bytes(self):
        self.make_dirty()
        result = self.run_check('--verify-local-sources')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_dirty_source_changed_after_observation_refuses(self):
        self.make_dirty()
        (self.repo / 'owner.rs').write_bytes(b'unselected later WIP')
        self.assert_invalid('LOCAL_DIRTY_HASH', '--verify-local-sources')

    def test_missing_local_source_is_incomplete_instead_of_skip_green(self):
        self.ledger['donors'][0]['repository_path'] = str(self.root / 'missing')
        result = self.run_check('--verify-local-sources')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(result.stdout, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['status'], 'INCOMPLETE')
        self.assertEqual(payload['source_verification'], 'INCOMPLETE')
        self.assertEqual(payload['qualification'], 'NOT_EVALUATED')

    def test_explicit_local_root_overrides_remote_without_ssh(self):
        self.ledger['donors'][0]['host'] = 'um790'
        self.ledger['donors'][0]['repository_path'] = '/work/unavailable'
        result = self.run_check('--verify-local-sources', '--source-root', 'D=' + str(self.repo))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_remote_source_without_explicit_local_root_is_incomplete(self):
        self.ledger['donors'][0]['host'] = 'um790'
        result = self.run_check('--verify-local-sources')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(result.stdout, result.stderr)
        self.assertEqual(json.loads(result.stdout)['source_verification'], 'INCOMPLETE')

    def test_unknown_upstream_observation_cannot_supply_a_grant(self):
        # Supersedes the historical blanket NOASSERTION copy ban: ownership
        # authorization and third-party option admission are separate checks.
        record = self.ledger['files'][0]
        record['license'].update(spdx='NOASSERTION', raw_spdx_observation=[],
                                 raw_effective_license_observation=None, resolution='UNRESOLVED')
        record['adoption'].update(ownership_basis='THIRD_PARTY', authorization_ref=None,
                                 third_party_terms=[{'source_scope': 'FILE', 'offered_spdx': 'NOASSERTION',
                                     'selected_option': 'Apache-2.0', 'license_evidence': [
                                         {'path': 'owner.rs', 'sha256': self.digest}], 'notice_evidence': []}])
        self.assert_invalid('ADOPTION_OPTION')

    def test_unknown_license_reference_only_valid_twin(self):
        record = self.ledger['files'][0]
        record['license']['spdx'] = 'NOASSERTION'
        record['license']['resolution'] = 'UNRESOLVED_BEFORE_COPY'
        record['license']['raw_spdx_observation'] = []
        record['license']['raw_effective_license_observation'] = None
        record['adoption'].update(disposition='REFERENCE_ONLY', copy_status='BLOCKED',
                                  decision_status='REFERENCE_ONLY', ownership_basis='UNRESOLVED',
                                  source_scope=None, artifact_role=None, third_party_terms=None,
                                  authorization_ref=None, destination_license=None,
                                  blocked_reason='Research reference; source slice not selected')
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_declared_license_cannot_disagree_with_observed_spdx(self):
        record = self.ledger['files'][0]
        record['license']['spdx'] = 'Apache-2.0 WITH LLVM-exception'
        record['adoption']['destination_license'] = 'Apache-2.0 WITH LLVM-exception'
        self.assert_invalid('LICENSE_OBSERVATION')

    def test_unresolved_observation_cannot_become_known_by_declaration(self):
        record = self.ledger['files'][0]
        record['license']['raw_spdx_observation'] = []
        record['license']['raw_effective_license_observation'] = None
        self.assert_invalid('LICENSE_OBSERVATION')

    def test_observed_tree_input_cannot_be_silently_unselected(self):
        self.ledger['donors'][0]['selected_tree_entries']['forgotten.rs'] = self.digest
        self.assert_invalid('SELECTED_INPUTS')

    def test_file_owner_must_be_one_of_its_mapped_tasks(self):
        self.registry['tasks'].append({'id': 'SB02', 'requirements': [], 'depends_on': []})
        self.ledger['files'][0]['owner'] = 'SB02'
        self.assert_invalid('OWNER')

    def test_owner_grant_cannot_be_silently_changed_to_mit(self):
        self.ledger['files'][0]['adoption']['destination_license'] = 'MIT'
        self.assert_invalid('ADOPTION_ROLE')

    def test_path_traversal_is_not_a_selected_file(self):
        self.ledger['files'][0]['path'] = '../owner.rs'
        self.assert_invalid('SOURCE_PATH')

    def test_task_dependency_cycle_rejected(self):
        self.registry['tasks'][0]['depends_on'] = ['SB01']
        self.assert_invalid('TASK_CYCLE')

    def test_malformed_nested_metadata_is_structured_invalid_input(self):
        for key in ('adoption', 'source_evidence', 'references'):
            with self.subTest(key=key):
                original = copy.deepcopy(self.ledger)
                self.ledger['files'][0][key] = []
                self.assert_invalid('ADOPTION' if key == 'adoption' else 'JSON_INPUT')
                self.ledger = original

    def test_duplicate_json_member_rejected(self):
        path = self.root / 'duplicate.json'
        path.write_text('{"kind":"SCOPEBASE_SOURCE_INTAKE","kind":"other"}')
        reg = self.root / 'registry.json'
        reg.write_text(json.dumps(self.registry))
        result = subprocess.run([sys.executable, str(SCRIPT), str(reg), '--ledger', str(path)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn('JSON_INPUT', {e['code'] for e in json.loads(result.stdout)['errors']})


class PreservedKnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.registry = INTAKE.load_json(REPO_ROOT / 'docs/superpowers/plans/2026-10-17-scopebase-traceability.json')
        self.ledger = INTAKE.load_json(REPO_ROOT / 'docs/provenance/donors.json')

    def test_case_family_and_regression_references_are_total(self):
        self.assertEqual(INTAKE.validate(self.registry, self.ledger, REPO_ROOT), [])

        def family(ledger):
            return ledger['case_family_inputs']['H04']

        def regression(ledger):
            return ledger['port_groups'][0]['selected_regressions_to_port_or_adapt'][0]

        mutations = [
            ('missing family', 'CASE_FAMILY', lambda j: j['case_family_inputs'].pop('H04')),
            ('new origin erased', 'CASE_FAMILY', lambda j: j['case_family_inputs']['H33'].pop('origin')),
            *[(kind, 'DANGLING_REFERENCE',
               lambda j, k=kind, v=value: family(j)['related_obligations'].__setitem__(k, [v]))
              for kind, value in [('G', 'G99'), ('UC', 'UC99'), ('TODO', 'Z99')]],
            ('missing oracle', 'CASE_FAMILY', lambda j: family(j).pop('independent_oracle')),
            ('empty control', 'CASE_FAMILY', lambda j: family(j).__setitem__('known_bad_control', {})),
            ('unknown anchor donor', 'CASE_FAMILY',
             lambda j: family(j)['inspected_donor_anchors'][0].__setitem__('alias', 'MISSING')),
            ('missing collection', 'REGRESSION_REFERENCE',
             lambda j: j['port_groups'][0].pop('selected_regressions_to_port_or_adapt')),
            ('empty preservation collection', 'REGRESSION_REFERENCE',
             lambda j: j['port_groups'][0].__setitem__('selected_regressions_to_port_or_adapt', [])),
            ('missing donor/file', 'REGRESSION_REFERENCE',
             lambda j: regression(j).update(alias='MISSING', path='absent.rs')),
            ('missing recorded symbol', 'REGRESSION_REFERENCE',
             lambda j: j['files'][0]['source_issue_test'].__setitem__('existing_symbols', [])),
            ('changed line', 'REGRESSION_REFERENCE', lambda j: regression(j).__setitem__('line', 1)),
            ('bool line', 'REGRESSION_REFERENCE', lambda j: regression(j).__setitem__('line', True)),
            ('missing membership', 'REGRESSION_REFERENCE',
             lambda j: j['port_groups'][0]['source_file_ids'].remove(j['files'][0]['id'])),
            ('missing issue membership', 'REGRESSION_REFERENCE',
             lambda j: j['files'][0]['source_issue_test'].__setitem__('issues', [])),
            ('malformed regression', 'REGRESSION_REFERENCE',
             lambda j: j['port_groups'][0]['selected_regressions_to_port_or_adapt'].__setitem__(0, [])),
            ('malformed group membership', 'REGRESSION_REFERENCE',
             lambda j: j['port_groups'][0].__setitem__('source_file_ids', [{}])),
        ]
        for name, expected, mutate in mutations:
            with self.subTest(name=name):
                ledger = copy.deepcopy(self.ledger)
                mutate(ledger)
                errors = INTAKE.validate(self.registry, ledger, REPO_ROOT)
                self.assertIn(expected, {e['code'] for e in errors}, errors)

    def test_documentation_with_no_symbols_remains_valid(self):
        empty = [f for f in self.ledger['files'] if not f['source_issue_test']['existing_symbols']]
        self.assertTrue(empty, 'actual inventory must exercise genuinely zero-symbol inputs')
        self.assertEqual(INTAKE.validate(self.registry, self.ledger, REPO_ROOT), [])


class AdoptionContractTests(IntakeFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.ledger['files'][0]['adoption'] = self.owner()

    def owner(self, role='host'):
        return {'disposition': 'PORT_SOURCE', 'copy_status': 'NOT_COPIED',
                'decision_status': 'READY_FOR_SELECTED_SCOPE', 'source_scope': 'FILE',
                'ownership_basis': 'USER_OWNED', 'artifact_role': role,
                'destination_license': {'host': 'Apache-2.0', 'bpf-target': 'GPL-2.0-only',
                                        'shared-target-source': 'Apache-2.0 OR GPL-2.0-only',
                                        'host-build-tool': 'Apache-2.0', 'data-document': 'Apache-2.0'}[role],
                'authorization_ref': 'OWNER-2026-10-18', 'third_party_terms': [], 'blocked_reason': None}

    def observe(self, spdx):
        # Synthetic grants still describe the actual owned fixture bytes. Each
        # negative twin below preserves this pin/hash and raw observation.
        source = ((('// SPDX-License-Identifier: ' + spdx) if spdx != 'NOASSERTION'
                   else '// Fixture with no SPDX declaration') +
                  '\n// regression: retains_original_owner\n').encode()
        if source != self.source:
            self.source = source
            (self.repo / 'owner.rs').write_bytes(source)
            self.git('add', 'owner.rs')
            self.git('commit', '-qm', 'Select synthetic source observation')
            self.commit = self.git('rev-parse', 'HEAD').strip()
            self.tree = self.git('rev-parse', 'HEAD^{tree}').strip()
            self.digest = hashlib.sha256(source).hexdigest()
        record = self.ledger['files'][0]
        record.update(commit=self.commit, sha256=self.digest)
        record['source_evidence'].update(head_blob_sha256=self.digest, observed_sha256=self.digest)
        donor = self.ledger['donors'][0]
        donor.update(commit=self.commit, tree=self.tree, selected_tree_entries={'owner.rs': self.digest})
        record['license'].update(spdx=spdx, raw_spdx_observation=[] if spdx == 'NOASSERTION' else [spdx],
                                 raw_effective_license_observation=None if spdx == 'NOASSERTION' else [spdx],
                                 resolution='UNRESOLVED' if spdx == 'NOASSERTION' else 'explicit_spdx',
                                 evidence=[{'path': 'owner.rs', 'sha256': self.digest}])

    def fragment(self, offered='Apache-2.0', selected='Apache-2.0', scope='FILE'):
        return {'source_scope': scope, 'offered_spdx': offered, 'selected_option': selected,
                'license_evidence': [{'path': 'owner.rs', 'sha256': self.digest}], 'notice_evidence': []}

    def upstream(self, offered='Apache-2.0', selected='Apache-2.0', role='host'):
        self.observe(offered)
        adoption = self.owner(role)
        adoption.update(ownership_basis='THIRD_PARTY', authorization_ref=None,
                        destination_license=selected, third_party_terms=[self.fragment(offered, selected)])
        self.ledger['files'][0]['adoption'] = adoption
        return adoption

    def assert_valid(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['source_verification'], 'NOT_RUN')

    def test_owner_authorization_pairs_preserve_source_observation(self):
        for spdx in ('GPL-3.0-or-later', 'NOASSERTION'):
            for role in ('host', 'bpf-target', 'shared-target-source', 'host-build-tool', 'data-document'):
                with self.subTest(spdx=spdx, role=role):
                    self.observe(spdx)
                    record = self.ledger['files'][0]
                    record['adoption'] = self.owner(role)
                    observed = copy.deepcopy({k: record[k] for k in ('license', 'sha256', 'commit')})
                    self.assert_valid()
                    for ref in (None, 'UNKNOWN'):
                        record['adoption']['authorization_ref'] = ref
                        self.assert_invalid('AUTHORIZATION')
                    record['adoption'] = self.owner(role)
                    record['adoption']['destination_license'] = 'Apache-2.0' if role != 'host' else 'GPL-2.0-only'
                    if role in ('bpf-target', 'shared-target-source', 'host'):
                        self.assert_invalid('ADOPTION_ROLE')
                    self.assertEqual({k: record[k] for k in observed}, observed)

    def test_owner_grant_is_exact_unique_and_resolves_decision_anchor(self):
        baseline = copy.deepcopy(self.ledger)
        for name, mutate in [
            ('substituted grant', lambda j: j['authorizations'][0]['allowed_destinations'].__setitem__('host', 'MIT')),
            ('duplicate id', lambda j: j['authorizations'].append(copy.deepcopy(j['authorizations'][0]))),
            ('missing grant', lambda j: j.pop('authorizations')),
            ('unknown grant key', lambda j: j['authorizations'][0].__setitem__('extra', True)),
            ('dangling anchor', lambda j: j['authorizations'][0].__setitem__('decision_ref', 'docs/superpowers/specs/2026-10-18-scopebase-decisions.md#absent')),
        ]:
            with self.subTest(name=name):
                self.ledger = copy.deepcopy(baseline)
                mutate(self.ledger)
                self.assert_invalid('AUTHORIZATION')
        self.ledger = baseline
        decision = self.root / self.ledger['authorizations'][0]['decision_ref'].split('#')[0]
        decision.write_text('## A different heading\n')
        self.assert_invalid('AUTHORIZATION')

    def test_upstream_original_terms_cannot_be_relicensed_by_owner_grant(self):
        self.upstream()
        self.assert_valid()
        self.ledger['files'][0]['adoption']['authorization_ref'] = 'OWNER-2026-10-18'
        self.assert_invalid('AUTHORIZATION')
        adoption = self.upstream('GPL-3.0-or-later', 'GPL-3.0-or-later')
        adoption['destination_license'] = 'Apache-2.0'
        self.assert_invalid('ADOPTION_ROLE')

    def test_mixed_fragments_are_retained_bound_and_contained(self):
        adoption = self.owner()
        adoption.update(ownership_basis='MIXED', source_scope=[[1, 10]],
                        third_party_terms=[self.fragment(scope=[[2, 3]])])
        self.ledger['files'][0]['adoption'] = adoption
        self.assert_valid()
        baseline = copy.deepcopy(self.ledger)
        mutations = [
            ('deleted terms', lambda a: a.__setitem__('third_party_terms', [])),
            ('outside selection', lambda a: a['third_party_terms'][0].__setitem__('source_scope', [[2, 11]])),
            ('foreign source binding', lambda a: a['third_party_terms'][0].__setitem__('sha256', '1' * 64)),
            ('owner hides upstream', lambda a: a.__setitem__('ownership_basis', 'USER_OWNED')),
            ('overlap fragments', lambda a: a['third_party_terms'].append(self.fragment(scope=[[3, 4]]))),
            ('missing option evidence', lambda a: a['third_party_terms'][0].__setitem__('license_evidence', [])),
            ('unsafe evidence', lambda a: a['third_party_terms'][0]['license_evidence'][0].__setitem__('path', '../foreign')),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                self.ledger = copy.deepcopy(baseline)
                mutate(self.ledger['files'][0]['adoption'])
                self.assert_invalid('ADOPTION_FRAGMENT')

    def test_unresolved_classification_does_not_admit_copy(self):
        adoption = self.owner()
        adoption.update(decision_status='NEEDS_DECISION', source_scope=None, artifact_role=None,
                        destination_license=None, authorization_ref=None, ownership_basis='UNRESOLVED',
                        third_party_terms=None, blocked_reason='Selected scope and upstream portions not classified')
        self.ledger['files'][0]['adoption'] = adoption
        self.assert_valid()
        adoption.update(decision_status='READY_FOR_SELECTED_SCOPE', source_scope='FILE', artifact_role='host',
                        destination_license='Apache-2.0', ownership_basis='USER_OWNED',
                        authorization_ref='OWNER-2026-10-18', blocked_reason=None)
        self.assert_invalid('ADOPTION_COMPLETENESS')
        adoption['third_party_terms'] = []
        self.assert_valid()

    def test_aya_target_option_stays_unresolved(self):
        adoption = self.upstream('MIT OR Apache-2.0', None, 'bpf-target')
        adoption.update(decision_status='NEEDS_DECISION', blocked_reason='Aya target option awaits D03 dependency decision')
        self.assert_valid()
        for option in ('MIT', 'Apache-2.0'):
            with self.subTest(option=option):
                adoption['third_party_terms'][0]['selected_option'] = option
                adoption.update(destination_license=option, decision_status='READY_FOR_SELECTED_SCOPE', blocked_reason=None)
                self.assert_invalid('ADOPTION_ROLE')

    def test_llvm_exception_is_preserved_and_target_review_required(self):
        adoption = self.upstream('Apache-2.0 WITH LLVM-exception', 'Apache-2.0 WITH LLVM-exception')
        self.assert_valid()
        adoption['third_party_terms'][0]['selected_option'] = 'Apache-2.0'
        self.assert_invalid('ADOPTION_OPTION')
        adoption = self.upstream('Apache-2.0', 'Apache-2.0 WITH LLVM-exception')
        self.assert_invalid('ADOPTION_OPTION')
        for role in ('bpf-target', 'shared-target-source'):
            with self.subTest(role=role):
                self.upstream('Apache-2.0 WITH LLVM-exception', 'Apache-2.0 WITH LLVM-exception', role)
                self.assert_invalid('ADOPTION_ROLE')

    def test_nonnull_fields_are_typed_even_when_unresolved(self):
        baseline = copy.deepcopy(self.ledger)
        fields = {'disposition': '', 'copy_status': 'COPIED', 'decision_status': 'READY',
                  'source_scope': [[True, 2]], 'ownership_basis': 'GUESS', 'artifact_role': 'application',
                  'destination_license': '', 'authorization_ref': 1, 'third_party_terms': {}, 'blocked_reason': 0}
        for key, value in fields.items():
            with self.subTest(key=key, case='missing'):
                self.ledger = copy.deepcopy(baseline)
                del self.ledger['files'][0]['adoption'][key]
                self.assert_invalid('ADOPTION')
            with self.subTest(key=key, case='wrong type or enum'):
                self.ledger = copy.deepcopy(baseline)
                self.ledger['files'][0]['adoption'][key] = value
                self.assert_invalid('ADOPTION')
        self.ledger = copy.deepcopy(baseline)
        self.ledger['files'][0]['adoption']['extra'] = True
        self.assert_invalid('ADOPTION')

    def test_scope_and_upstream_full_coverage_are_required(self):
        baseline = copy.deepcopy(self.ledger)
        for scope in ('', [], [[0, 2]], [[2, 1]], [[1, True]], [[2, 3], [1, 1]], [[1, 3], [3, 4]]):
            with self.subTest(scope=scope):
                self.ledger = copy.deepcopy(baseline)
                self.ledger['files'][0]['adoption']['source_scope'] = scope
                self.assert_invalid('ADOPTION')
        self.ledger = copy.deepcopy(baseline)
        adoption = self.upstream()
        adoption['source_scope'] = [[1, 10]]
        adoption['third_party_terms'] = [self.fragment(scope=[[1, 4]]), self.fragment(scope=[[5, 10]])]
        self.assert_valid()
        adoption['third_party_terms'][1]['source_scope'] = [[6, 10]]
        self.assert_invalid('ADOPTION_FRAGMENT')

    def test_contiguous_selection_ranges_allow_contained_fragment(self):
        adoption = self.upstream()
        adoption.update(source_scope=[[1, 5], [6, 10]],
                        third_party_terms=[self.fragment(scope=[[1, 10]])])
        self.assert_valid()

    def test_fragment_shape_is_total_for_malformed_nested_values(self):
        adoption = self.upstream()
        baseline = copy.deepcopy(self.ledger)
        invalid = {'source_scope': None, 'offered_spdx': [], 'selected_option': [],
                   'license_evidence': [{}], 'notice_evidence': 'missing'}
        for key, value in invalid.items():
            for missing in (True, False):
                with self.subTest(key=key, missing=missing):
                    self.ledger = copy.deepcopy(baseline)
                    fragment = self.ledger['files'][0]['adoption']['third_party_terms'][0]
                    if missing:
                        del fragment[key]
                    else:
                        fragment[key] = value
                    # Direct API must report the semantic record error too.
                    errors = INTAKE.validate(self.registry, self.ledger, self.root)
                    self.assertIn('ADOPTION_FRAGMENT', {e['code'] for e in errors}, errors)

    def test_unlisted_upstream_expression_stays_observed_and_unresolved(self):
        adoption = self.upstream('Unlisted-original-grant', None)
        adoption.update(decision_status='NEEDS_DECISION', blocked_reason='Expert must review the observed grant')
        self.assert_valid()
        adoption['third_party_terms'][0]['selected_option'] = 'Apache-2.0'
        self.assert_invalid('ADOPTION_OPTION')

    def test_retained_gplv2_options_match_bpf_role(self):
        for offered, selected in [('GPL-2.0-only', 'GPL-2.0-only'),
                                  ('GPL-2.0-or-later', 'GPL-2.0-only'),
                                  ('GPL-2.0-or-later', 'GPL-2.0-or-later')]:
            with self.subTest(offered=offered, selected=selected):
                adoption = self.upstream(offered, selected, 'bpf-target')
                self.assert_valid()
                adoption['artifact_role'] = 'host'
                self.assert_invalid('ADOPTION_ROLE')


if __name__ == '__main__':
    unittest.main()
