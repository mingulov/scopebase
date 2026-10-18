"""Exercise SB03 structural refusals against an independent synthetic repository.

Each control first validates its positive twin and asserts a literal diagnostic;
the checker never supplies the expected category/version/profile truth.
"""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

CHECKER = Path(__file__).resolve().parents[1] / 'check_docs.py'
FIXTURE = Path(__file__).parent / 'fixtures/docs/valid'
POLICY = 'docs/contracts/compatibility.md'
REGISTRY = 'profiles/schema-versions.json'
LINUX = 'docs/superpowers/specs/2026-10-17-scopebase-linux-design.md'


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        shutil.copytree(FIXTURE, self.root)
        self.assert_valid()

    def run_checker(self, *args):
        return subprocess.run([sys.executable, str(CHECKER), '--root', str(self.root), *args],
                              capture_output=True, text=True, timeout=10)

    def report(self):
        result = self.run_checker()
        self.assertIn(result.returncode, (0, 3), result.stderr)
        self.assertEqual(result.stderr, '')
        return result, json.loads(result.stdout)

    def assert_valid(self):
        result, report = self.report()
        self.assertEqual(result.returncode, 0, report)
        self.assertEqual(report['status'], 'VALID')
        self.assertEqual(report['qualification'], 'not_evaluated')
        self.assertEqual(report['errors'], [])
        return result.stdout

    def assert_code(self, code):
        result, report = self.report()
        self.assertEqual(result.returncode, 3, report)
        self.assertIn(code, [e['code'] for e in report['errors']], report)
        self.assertEqual(report['qualification'], 'not_evaluated')
        return report

    def registry(self, change):
        path = self.root / REGISTRY
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))

    def block(self, change, relative=POLICY):
        path = self.root / relative
        body = path.read_text()
        before, rest = body.split('```scopebase-doc\n')
        raw, after = rest.split('```', 1)
        value = json.loads(raw)
        change(value)
        path.write_text(before + '```scopebase-doc\n' + json.dumps(value) + '\n```' + after)

    def test_positive_and_deterministic_json(self):
        first = self.assert_valid()
        self.assertEqual(first, self.assert_valid())
        report = json.loads(first)
        self.assertEqual(set(report), {'schema_version', 'status', 'qualification',
                                     'checked_documents', 'errors', 'omitted_errors'})
        self.assertEqual(len(report['checked_documents']), 6)
        self.assertNotIn(self.temp.name, first)

    def test_unknown_registry_major_minor_patch(self):
        for version in ('2.0.0', '1.1.0', '1.0.1'):
            with self.subTest(version=version):
                self.registry(lambda v: v.update(schema_version=version))
                self.assert_code('REGISTRY_VERSION')

    def test_unknown_contract_major(self):
        self.block(lambda v: v['versions'][0].update(version='2'))
        self.assert_code('VERSION_UNSUPPORTED')

    def test_renamed_error_category(self):
        self.block(lambda v: v['errors'][0].update(category='PermissionDenied'))
        self.assert_code('ERROR_CATEGORY')

    def test_category_catalog_drift(self):
        for change in (lambda a: a.pop(), lambda a: a.reverse(),
                       lambda a: a.__setitem__(0, 'NewStage')):
            with self.subTest(change=change):
                shutil.copyfile(FIXTURE / REGISTRY, self.root / REGISTRY)
                change_positive = json.loads((self.root / REGISTRY).read_text())
                change(change_positive['error_domains'][0]['categories'])
                (self.root / REGISTRY).write_text(json.dumps(change_positive))
                self.assert_code('CATEGORY_DRIFT')

    def test_category_source_missing_or_ambiguous(self):
        path = self.root / LINUX
        original = path.read_text()
        for body in (original.replace('Stage variants cover', 'Stages include'), original + original):
            path.write_text(body)
            self.assert_code('CATEGORY_SOURCE')

    def test_unsupported_profile_claim(self):
        for claim in ('qualified', 'supported'):
            self.block(lambda v: v['profiles'][0].update(claim=claim))
            self.assert_code('SUPPORT_CLAIM')

    def test_unknown_profile(self):
        self.block(lambda v: v['profiles'][0].update(id='unknown-v1'))
        self.assert_code('PROFILE_UNKNOWN')

    def test_extension_is_not_base_profile(self):
        self.block(lambda v: v['profiles'][0].update(id='btf-runtime-linkage-v1'))
        self.assert_code('PROFILE_KIND')

    def test_report_is_not_authority_and_live_constructor_twin(self):
        self.block(lambda v: v.update(subject_kind='live_owner', authority_claim='requires_constructor'))
        self.assert_valid()
        self.block(lambda v: v.update(subject_kind='report'))
        self.assert_code('AUTHORITY_CLAIM')

    def test_false_execution(self):
        self.block(lambda v: v.update(mode='illustrative'))
        self.assert_valid()
        self.block(lambda v: v.update(execution='completed'))
        self.assert_code('EXECUTION_CLAIM')

    def test_dangling_references(self):
        for change in (lambda v: v.update(owner_task='ZZ99'),
                       lambda v: v.update(requirements=['SB-R99']),
                       lambda v: v['versions'][0].update(domain='absent'),
                       lambda v: v['errors'][0].update(domain='absent')):
            with self.subTest(change=change):
                shutil.copyfile(FIXTURE / POLICY, self.root / POLICY)
                self.block(change)
                self.assert_code('REFERENCE')

    def test_duplicate_document_id(self):
        self.block(lambda v: v.update(id='architecture'))
        self.assert_code('ID_DUPLICATE')

    def test_duplicate_registry_domain(self):
        self.registry(lambda v: v['domains'].append(copy.deepcopy(v['domains'][0])))
        self.assert_code('ID_DUPLICATE')

    def test_required_document_and_domain(self):
        (self.root / 'docs/architecture.md').unlink()
        self.assert_code('REQUIRED_MISSING')
        shutil.copyfile(FIXTURE / 'docs/architecture.md', self.root / 'docs/architecture.md')
        self.registry(lambda v: v['domains'].pop())
        self.assert_code('REQUIRED_MISSING')

    def test_strict_registry_json_framing(self):
        path = self.root / REGISTRY
        original = path.read_bytes()
        for raw in (b'{"kind":1,"kind":2}', original + b'{}', b'\xff'):
            path.write_bytes(raw)
            self.assert_code('JSON_INPUT')

    def test_null_registry_is_not_empty_success(self):
        (self.root / REGISTRY).write_text('null')
        self.assert_code('SCHEMA_TYPE')

    def test_invalid_registry_catalog_cannot_crash_doc_references(self):
        self.registry(lambda v: v['error_domains'][1].update(categories=5))
        self.assert_code('SCHEMA_TYPE')

    def test_registry_override_diagnostics_do_not_leak_absolute_root(self):
        (self.root / REGISTRY).write_text('invalid JSON')
        result = self.run_checker('--registry', str(self.root / REGISTRY))
        self.assertEqual(result.returncode, 3)
        self.assertNotIn(self.temp.name, result.stdout)

    def test_registry_alias_diagnostic_uses_normalized_relative_path(self):
        (self.root / REGISTRY).write_text('invalid JSON')
        result = self.run_checker('--registry', str(self.root / '..' / 'repo' / REGISTRY))
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)['errors'][0]['path'], 'profiles/schema-versions.json')

    def test_invalid_url_is_local_link_error(self):
        with (self.root / POLICY).open('a') as stream:
            stream.write('\n[broken](https://[bad)\n')
        self.assert_code('LINK')

    def test_strict_doc_types_and_fields(self):
        self.block(lambda v: v.update(schema_version=True))
        self.assert_code('SCHEMA_TYPE')
        shutil.copyfile(FIXTURE / POLICY, self.root / POLICY)
        self.block(lambda v: v.update(support='supported'))
        self.assert_code('SCHEMA_FIELD')

    def test_doc_json_framing_and_duplicate_key(self):
        path = self.root / POLICY
        original = path.read_text()
        for raw in ('{"id":"a","id":"b"}', '{} {}'):
            before, rest = original.split('```scopebase-doc\n')
            _, after = rest.split('```', 1)
            path.write_text(before + '```scopebase-doc\n' + raw + '\n```' + after)
            self.assert_code('JSON_INPUT')

    def test_missing_error_domain_and_unknown_registry_field(self):
        self.registry(lambda v: v['error_domains'].pop())
        self.assert_code('REQUIRED_MISSING')
        shutil.copyfile(FIXTURE / REGISTRY, self.root / REGISTRY)
        self.registry(lambda v: v.update(result='qualified'))
        self.assert_code('SCHEMA_FIELD')

    def test_canonical_domain_version_types(self):
        for version in (True, 1.0, '01', '1.0'):
            self.registry(lambda v: v['domains'][1].update(version=version))
            self.assert_code('SCHEMA_TYPE')

    def test_direct_validate_checks_already_parsed_registry(self):
        from tools.planning.check_docs import validate
        registry = json.loads((self.root / REGISTRY).read_text())
        self.assertEqual(validate(self.root, registry), [])
        errors = validate(self.root, [])
        self.assertIn('SCHEMA_TYPE', [e['code'] for e in errors])

    def test_malformed_nested_values_refuse_without_crashing(self):
        for change in (lambda v: v.update(versions=[[]]),
                       lambda v: v.update(errors=[True]),
                       lambda v: v.update(profiles=[{'id': [], 'claim': 'planned'}]),
                       lambda v: v.update(requirements=[{}])):
            shutil.copyfile(FIXTURE / POLICY, self.root / POLICY)
            self.block(change)
            self.assert_code('SCHEMA_TYPE')

    def concrete_issue(self):
        path = self.root / 'docs/issues/issue-01.md'
        body = (self.root / 'docs/issues/TEMPLATE.md').read_text()
        path.write_text(body.replace('<fill>', 'UNKNOWN — missing evidence; TT01; independent case receipt.'))
        self.block(lambda v: v.update(id='issue-01', mode='contract'), 'docs/issues/issue-01.md')
        self.assert_valid()
        return path

    def test_issue_delivery_headings(self):
        path = self.concrete_issue()
        original = path.read_text()
        for heading in ('Independent oracle', 'Known-bad control and positive twin',
                        'Upstream inclusion and removal test'):
            path.write_text(original.replace('## ' + heading, '## Removed'))
            self.assert_code('ISSUE_SECTION')

    def test_concrete_issue_rejects_empty_and_placeholder(self):
        path = self.concrete_issue()
        original = path.read_text()
        content = 'UNKNOWN — missing evidence; TT01; independent case receipt.'
        for replacement in ('', 'TODO', 'TBD', '<fill>'):
            path.write_text(original.replace(content, replacement, 1))
            self.assert_code('ISSUE_CONTENT')

    def test_each_guide_requires_all_headings(self):
        path = self.root / 'docs/contributing.md'
        path.write_text(path.read_text().replace('### Concurrency and fork', '### Removed', 1))
        self.assert_code('GUIDE_SECTION')

    def test_local_link_anchor(self):
        with (self.root / POLICY).open('a') as stream:
            stream.write('\n[contract](../architecture.md#missing)\n')
        self.assert_code('LINK')

    def test_growing_link_target_reuses_bounded_body_without_reopen(self):
        from tools.planning.check_docs import Checker
        checker = Checker(self.root)
        relative = 'docs/architecture.md'
        target = self.root / relative
        # The positive anchor exists in the real bounded file. Cache it, then
        # deterministically grow that same file beyond the document limit.
        checker.link(relative + '#synthetic-architecture', POLICY)
        self.assertEqual(checker.errors, [])
        with target.open('ab') as stream:
            stream.write(b'\n# Only after growth\n' + b' ' * (2 * 1024 * 1024 + 1))
        self.assertGreater(target.stat().st_size, 2 * 1024 * 1024)
        original_open = Path.open
        opens = []

        def observe_open(path, *args, **kwargs):
            if path == target:
                opens.append((args, kwargs))
            return original_open(path, *args, **kwargs)

        # This spy delegates every operation to the actual file; it supplies no
        # canned bytes/verdict. The IO oracle is zero reopens of cached input.
        with patch.object(Path, 'open', observe_open):
            checker.link(relative + '#synthetic-architecture', POLICY)
            self.assertEqual(checker.errors, [])
            checker.link(relative + '#only-after-growth', POLICY)
        self.assertEqual(opens, [], 'Cached bounded content must not reopen the grown target')
        self.assertEqual([error['code'] for error in checker.errors], ['LINK'])

    def test_angle_link_with_spaces_is_checked(self):
        with (self.root / POLICY).open('a') as stream:
            stream.write('\n[contract](<../missing file.md>)\n')
        self.assert_code('LINK')

    def test_registry_and_category_symlink_escape(self):
        for relative in (REGISTRY, LINUX):
            original = (self.root / relative).read_bytes()
            outside = Path(self.temp.name) / 'outside'
            outside.write_bytes(original)
            (self.root / relative).unlink()
            (self.root / relative).symlink_to(outside)
            self.assert_code('PATH_ESCAPE')
            (self.root / relative).unlink()
            (self.root / relative).write_bytes(original)

    def test_byte_bounds_exact_limit_and_plus_one(self):
        path = self.root / 'docs/architecture.md'
        raw = path.read_bytes()
        path.write_bytes(raw + b' ' * (2 * 1024 * 1024 - len(raw)))
        self.assert_valid()
        with path.open('ab') as stream:
            stream.write(b' ')
        self.assert_code('BOUNDS')

    def test_json_byte_bounds_exact_limit_and_plus_one(self):
        path = self.root / REGISTRY
        raw = path.read_bytes()
        path.write_bytes(raw + b' ' * (1024 * 1024 - len(raw)))
        self.assert_valid()
        with path.open('ab') as stream:
            stream.write(b' ')
        self.assert_code('BOUNDS')

    def test_collection_bounds_and_doc_block_bounds(self):
        self.block(lambda v: v.update(versions=[{'domain': 'native-wire', 'version': '1'}] * 257))
        self.assert_code('BOUNDS')
        shutil.copyfile(FIXTURE / POLICY, self.root / POLICY)
        path = self.root / POLICY
        path.write_text(path.read_text().replace('```scopebase-doc\n', '```scopebase-doc\n' + ' ' * (1024 * 1024)))
        self.assert_code('BOUNDS')

    def test_issue_and_document_count_bounds(self):
        body = (self.root / 'docs/issues/TEMPLATE.md').read_text()
        for number in range(257):
            (self.root / ('docs/issues/issue-%03d.md' % number)).write_text(body)
        report = self.assert_code('BOUNDS')
        # Excess issue populations do not select a filesystem-order-dependent
        # subset; only the full fixed document set is still checked.
        self.assertEqual(len(report['checked_documents']), 6)

    def test_policy_and_link_symlink_escape(self):
        outside = Path(self.temp.name) / 'outside.md'
        path = self.root / 'docs/architecture.md'
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        self.assert_code('PATH_ESCAPE')

    def test_registry_enum_syntax_change_is_not_guessed(self):
        path = self.root / 'docs/superpowers/specs/2026-10-17-scopebase-bpf-toolchain-design.md'
        path.write_text(path.read_text().replace('InvalidInput,', 'InvalidInput(u32),', 1))
        self.assert_code('CATEGORY_SOURCE')

    def test_diagnostic_cap_counts_omissions(self):
        # Valid documents with many independent bad version references exercise
        # collection, rather than a setup/parser error or repeated fixture copy.
        self.block(lambda v: v.update(versions=[{'domain': 'missing-' + str(i), 'version': '1'}
                                               for i in range(150)]))
        report = self.assert_code('REFERENCE')
        self.assertEqual(len(report['errors']), 128)
        self.assertEqual(report['omitted_errors'], 22)
        self.assertNotIn(self.temp.name, json.dumps(report))

    def test_cli_text_and_usage(self):
        result = self.run_checker('--format', 'text')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'VALID; qualification=not_evaluated\n')
        result = self.run_checker('--format', 'unknown')
        self.assertEqual(result.returncode, 64)


class DocumentLinkCompatibilityTests(unittest.TestCase):
    def test_document_link_legacy_and_supplied_body_preserve_anchor_grammar(self):
        from tools.planning.check_traceability import document_link
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            body = '# Mixed case, punctuation!\n\n<span id="explicit-id"></span>\n'
            target = root / 'contract.md'
            target.write_text(body)
            for reference, expected in (
                ('contract.md', True),
                ('contract.md#mixed-case-punctuation', True),
                ('contract.md#explicit-id', True),
                ('contract.md#missing', False),
                ('contract.md#', False),
                ('../contract.md', False),
                (None, False),
            ):
                with self.subTest(reference=reference):
                    self.assertEqual(document_link(reference, root), expected)
                    self.assertEqual(document_link(reference, root, body=body), expected)
            target.unlink()
            self.assertFalse(document_link('contract.md', root))
            # Supplied admitted text checks only its syntax/anchor, without a
            # pathname read or an implied current-filesystem authority claim.
            self.assertTrue(document_link('contract.md#explicit-id', root, body=body))
            self.assertTrue(document_link('contract.md', root, body=''))


if __name__ == '__main__':
    unittest.main()
