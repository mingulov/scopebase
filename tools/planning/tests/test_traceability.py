"""Behavioral intake controls: real JSON documents and a temporary Git donor."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'check_traceability.py'


class IntakeValidationTests(unittest.TestCase):
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
            'schema_version': '1.0.0', 'kind': 'SCOPEBASE_SOURCE_INTAKE',
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
                                    'destination_license': 'GPL-3.0-or-later', 'blocked_reason': None},
                       'source_evidence': {'exists_at_commit': True, 'head_blob_sha256': self.digest,
                                           'observed_sha256': self.digest, 'dirty_sha256': None},
                       'source_issue_test': {'issues': ['held-owner'],
                                             'existing_symbols': [{'name': 'retains_original_owner', 'line': 2}]}}],
            'port_groups': [{'id': 'held-owner', 'owner': 'SB01', 'references': refs,
                             'source_file_ids': ['D:owner.rs'], 'contract': 'retain original owner'}],
            'obligation_coverage': [{'kind': k, 'id': i, 'owners': ['SB01']} for k, i in kinds],
        }

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

    def test_unknown_license_cannot_be_mislabeled_for_copy(self):
        record = self.ledger['files'][0]
        record['license']['spdx'] = 'NOASSERTION'
        self.assert_invalid('LICENSE_COPY_BLOCKED')

    def test_unknown_license_reference_only_valid_twin(self):
        record = self.ledger['files'][0]
        record['license']['spdx'] = 'NOASSERTION'
        record['license']['resolution'] = 'UNRESOLVED_BEFORE_COPY'
        record['license']['raw_spdx_observation'] = []
        record['license']['raw_effective_license_observation'] = None
        record['adoption'] = {'disposition': 'REFERENCE_ONLY', 'copy_status': 'BLOCKED',
                              'destination_license': None, 'blocked_reason': 'Grant unresolved'}
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

    def test_silent_gpl_to_mit_relabel_rejected(self):
        self.ledger['files'][0]['adoption']['destination_license'] = 'MIT OR Apache-2.0'
        self.assert_invalid('LICENSE_RELABEL')

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
                self.assert_invalid('JSON_INPUT')
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


if __name__ == '__main__':
    unittest.main()
