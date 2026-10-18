# SPDX-License-Identifier: Apache-2.0
"""A no-union foundation may have one real client; unions still require two."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools' / 'build'))
import common as policy
import test_check_features as feature_fixture


class ClientCardinalityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'matrix.json'
        self.matrix = json.loads((ROOT / 'package-policy.json').read_text())
        self.member = self.matrix['members'][0]
        self.original_clients = copy.deepcopy(self.member['clients'])
        for member in self.matrix['members'] + self.matrix['fixture_members']:
            for client in member['clients']:
                source = self.path.parent / client['source']
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text('fn main() {}\n')

    def validate(self):
        self.path.write_text(json.dumps(self.matrix))
        return policy.validate_matrix(self.path, 'features')

    def test_one_client_without_union_is_admitted(self):
        self.member['supported_unions'] = []
        self.member['clients'] = self.original_clients[:1]
        self.validate()

    def test_existing_two_client_shapes_remain_valid(self):
        self.validate()
        self.member['supported_unions'] = []
        self.validate()

    def test_union_still_requires_two_clients(self):
        self.assertTrue(self.member['supported_unions'])
        self.member['clients'] = self.original_clients[:1]
        with self.assertRaisesRegex(policy.InputError, '^SCHEMA_CLIENTS$'):
            self.validate()
        self.member['clients'] = self.original_clients
        self.validate()

    def test_empty_excessive_and_nonlist_clients_are_refused(self):
        self.member['supported_unions'] = []
        for invalid in ([], self.original_clients + self.original_clients[:1],
                        None, {}, 'xx', True):
            with self.subTest(invalid=invalid):
                self.member['clients'] = invalid
                with self.assertRaisesRegex(policy.InputError, '^SCHEMA_CLIENTS$'):
                    self.validate()

    def test_single_client_keeps_field_validation(self):
        self.member['supported_unions'] = []
        self.member['clients'] = copy.deepcopy(self.original_clients[:1])
        self.member['clients'][0]['skip_admission'] = True
        with self.assertRaisesRegex(policy.InputError, '^SCHEMA_FIELDS:'):
            self.validate()


class OneClientProductControl(feature_fixture.ProductPolicyControls):
    test_product_member_stages_without_changing_approved_manifest = None
    test_missing_and_stale_root_locks_refuse_unchanged_and_restored_twin_passes = None
    test_product_requires_an_executed_doctest = None
    test_product_source_refusals_precede_compilation = None

    def test_real_single_client_archive_runs_in_both_modes_and_compilers(self):
        cell, inputs, source, matrix = self.product()
        member = matrix['members'][0]
        member['supported_unions'] = []
        member['clients'] = member['clients'][:1]
        member['clients'][0]['features'] = []
        (source / 'src/lib.rs').write_text(
            '//! ```\n//! assert_eq!(product_subject::value(), 7);\n//! ```\n'
            'pub fn value() -> u32 { 7 }\n')
        (inputs / 'client.rs').write_text(
            'fn main() { assert_eq!(product_subject::value(), 7); }\n')
        (inputs / 'matrix.json').write_text(json.dumps(matrix))
        report = self.check(cell, inputs, 'single-client-valid')
        self.assertEqual(report['summary']['declared_compiler_cells'], 4)
        self.assertTrue(report['summary']['full_matrix_complete'])
        self.assertFalse(report['product_qualification'])
        runs = [r for r in report['rows'] if r['phase'] == 'run-product-client']
        self.assertEqual(len(runs), 4)
        self.assertEqual({r['toolchain'] for r in runs}, {'msrv', 'current'})
        self.assertTrue(all(r['status'] == 'PASS' for r in runs))
        archives = [r for r in report['rows'] if r['phase'] == 'archive']
        self.assertEqual(len(archives), 1)
        self.assertTrue(Path(archives[0]['observed']['archive']).is_file())


if __name__ == '__main__':
    unittest.main()
