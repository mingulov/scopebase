# SPDX-License-Identifier: Apache-2.0
"""Explicit minimal dependency closures retain exact feature and source policy."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools' / 'build'))
import check_features
import common as policy


class MinimalDependencyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'matrix.json'
        self.matrix = json.loads((ROOT / 'package-policy.json').read_text())
        # Validate only local matrix structure; these records authorize no build.
        self.member = next(m for m in self.matrix['members'] if m['id'] == 'scopebase-capture')
        self.dependencies = copy.deepcopy(self.member['allowed_dependencies'])
        for member in self.matrix['fixture_members'] + self.matrix['members']:
            for client in member['clients']:
                source = self.path.parent / client['source']
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text('fn main() {}\n')

    def validate(self):
        self.path.write_text(json.dumps(self.matrix))
        return policy.validate_matrix(self.path, 'feature')

    def metadata(self):
        subject = {'name': 'literal-registry', 'version': '0.1.0',
                   'source': None, 'id': 'path+literal-registry'}
        client = {'name': 'independent-client', 'version': '0.1.0',
                  'source': None, 'id': 'path+independent-client'}
        packages = [subject, client] + [
            {'name': r['name'], 'version': r['version'], 'source': r['source'],
             'id': r['source'] + '#' + r['name'] + '@' + r['version']}
            for r in self.dependencies]
        return {'packages': packages, 'resolve': {'nodes': [
            {'id': subject['id'], 'features': []}]}}

    def test_existing_matrix_and_legacy_serde_refusal_are_preserved(self):
        self.validate()
        with self.assertRaisesRegex(policy.PolicyError, 'MINIMAL_FEATURE_LEAK'):
            check_features.assert_subject(self.metadata(), 'literal-registry', [], minimal=True)

    def test_explicit_minimal_closure_is_admitted_without_changing_feature_expectation(self):
        self.member['minimal_dependencies'] = copy.deepcopy(self.dependencies)
        try:
            self.validate()
        except policy.InputError as error:
            self.fail('explicit approved mandatory dependency closure was rejected: ' + str(error))
        check_features.assert_subject(self.metadata(), 'literal-registry', [], minimal=True,
                                      minimal_dependencies=self.dependencies)
        wrong_features = self.metadata()
        wrong_features['resolve']['nodes'][0]['features'] = ['json']
        with self.assertRaisesRegex(policy.PolicyError, 'FEATURE_UNION_MISMATCH'):
            check_features.assert_subject(wrong_features, 'literal-registry', [], minimal=True,
                                          minimal_dependencies=self.dependencies)

    def test_missing_extra_and_wrong_version_or_source_are_refused(self):
        check_features.assert_subject(self.metadata(), 'literal-registry', [], minimal=True,
                                      minimal_dependencies=self.dependencies)
        mutants = []
        missing = self.metadata(); missing['packages'].pop(); mutants.append(missing)
        extra = self.metadata(); extra['packages'].append(
            {'name': 'unexpected', 'version': '1.0.0', 'source': 'registry:unexpected', 'id': 'extra'})
        mutants.append(extra)
        wrong_version = self.metadata(); wrong_version['packages'][2]['version'] = '99.0.0'
        mutants.append(wrong_version)
        wrong_source = self.metadata(); wrong_source['packages'][2]['source'] = 'registry:other'
        mutants.append(wrong_source)
        for mutant in mutants:
            with self.subTest(packages=mutant['packages']):
                with self.assertRaisesRegex(policy.PolicyError, 'MINIMAL_DEPENDENCY_MISMATCH'):
                    check_features.assert_subject(mutant, 'literal-registry', [], minimal=True,
                                                  minimal_dependencies=self.dependencies)

    def test_empty_explicit_closure_is_strict_and_union_is_not_minimal(self):
        empty = self.metadata(); empty['packages'] = empty['packages'][:2]
        check_features.assert_subject(empty, 'literal-registry', [], minimal=True,
                                      minimal_dependencies=[])
        with self.assertRaisesRegex(policy.PolicyError, 'MINIMAL_DEPENDENCY_MISMATCH'):
            check_features.assert_subject(self.metadata(), 'literal-registry', [], minimal=True,
                                          minimal_dependencies=[])
        # Another feature union has its ordinary admitted dependency closure.
        check_features.assert_subject(self.metadata(), 'literal-registry', [], minimal=False,
                                      minimal_dependencies=[])

    def test_minimal_grant_cannot_expand_or_change_existing_admission(self):
        self.member['minimal_dependencies'] = copy.deepcopy(self.dependencies)
        self.validate()
        for field, replacement in [('name', 'new-dependency'), ('version', '99.0.0'),
                                   ('source', 'registry:other'), ('sha256', '0' * 64),
                                   ('role', 'host-proc-macro')]:
            mutated = copy.deepcopy(self.dependencies)
            mutated[0][field] = replacement
            with self.subTest(field=field):
                self.member['minimal_dependencies'] = mutated
                with self.assertRaisesRegex(policy.InputError, 'SCHEMA_MINIMAL_DEPENDENCIES'):
                    self.validate()
        self.member['minimal_dependencies'] = self.dependencies + [self.dependencies[0]]
        with self.assertRaisesRegex(policy.InputError, 'SCHEMA_DUPLICATE_DEPENDENCY'):
            self.validate()

    def test_malformed_optional_field_and_unknown_keys_stay_invalid(self):
        for invalid in (None, False, {}, 'serde'):
            self.member['minimal_dependencies'] = invalid
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(policy.InputError, 'SCHEMA_DEPENDENCIES'):
                    self.validate()
        self.member['minimal_dependencies'] = []
        self.member['ignore_minimal_checks'] = True
        with self.assertRaisesRegex(policy.InputError, 'SCHEMA_FIELDS'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
