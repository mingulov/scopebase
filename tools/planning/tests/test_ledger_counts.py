"""LEDGER-RECONCILE01: TODO header == checkboxes == traceability enforcement.

Each bad control is a single-count edit in exactly one source; it must fail
with its named error code, never a setup crash. Uses real fixture files and
the real script entry point; no mocks.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'check_ledger_counts.py'
REPO_ROOT = SCRIPT.parents[2]

TODO_FIXTURE = """# Fixture TODO

Status: **Two of 3 tasks accepted** (recounted 2026-10-30: header, boxes
and registry agree).

Ledger maps **5 requirements and 3 tasks** to fixtures: 7
source-obligation mappings.

## M0: foundations

- [x] [AA01: first thing](plan.md#aa01) — prerequisites: none.
- [x] [AA02: second thing](plan.md#aa02) — prerequisites: AA01.
- [ ] [AA03: third thing](plan.md#aa03) — prerequisites: AA02.

## Controller maintenance — not task boxes

- [x] EX01: done outside the 86.
"""

REGISTRY_FIXTURE = {
    "tasks": [
        {"id": "AA01", "status": "ACCEPTED"},
        {"id": "AA02", "status": "ACCEPTED"},
        {"id": "AA03", "status": "PLANNED"},
    ],
    "requirements": ["R-01", "R-02", "R-03", "R-04", "R-05"],
    "source_obligations": ["O-01", "O-02", "O-03", "O-04", "O-05",
                           "O-06", "O-07"],
    "counts": {"tasks": 3, "requirements": 5},
}


def load_module():
    spec = importlib.util.spec_from_file_location('ledger_counts', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LedgerCountsFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.todo = self.root / 'TODO.md'
        self.registry = self.root / 'traceability.json'
        self.todo.write_text(TODO_FIXTURE, encoding='utf-8')
        self.registry.write_text(json.dumps(REGISTRY_FIXTURE),
                                 encoding='utf-8')

    def run_checker(self, todo=None, registry=None):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), '--todo', str(todo or self.todo),
             '--registry', str(registry or self.registry)],
            capture_output=True, text=True, timeout=60)
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            self.fail(f'checker printed no JSON report: '
                      f'rc={proc.returncode} stderr={proc.stderr[:300]}')
        return proc.returncode, report

    def codes(self, report):
        return {e['code'] for e in report['errors']}

    def test_agreement_passes(self):
        rc, report = self.run_checker()
        self.assertEqual(rc, 0)
        self.assertEqual(report['status'], 'AGREE')
        self.assertEqual(report['errors'], [])

    def test_header_accepted_single_edit_fails(self):
        self.todo.write_text(TODO_FIXTURE.replace('Two of 3', 'Three of 3'),
                             encoding='utf-8')
        rc, report = self.run_checker()
        self.assertEqual(rc, 1)
        self.assertIn('HEADER_BOX_ACCEPTED', self.codes(report))
        self.assertIn('HEADER_REGISTRY_ACCEPTED', self.codes(report))

    def test_checkbox_flip_fails(self):
        self.todo.write_text(TODO_FIXTURE.replace('- [x] [AA02:', '- [ ] [AA02:'),
                             encoding='utf-8')
        rc, report = self.run_checker()
        self.assertEqual(rc, 1)
        self.assertIn('HEADER_BOX_ACCEPTED', self.codes(report))
        self.assertIn('ACCEPTED_ID_SET', self.codes(report))

    def test_registry_status_flip_fails(self):
        mutated = json.loads(json.dumps(REGISTRY_FIXTURE))
        mutated['tasks'][1]['status'] = 'PLANNED'
        self.registry.write_text(json.dumps(mutated), encoding='utf-8')
        rc, report = self.run_checker()
        self.assertEqual(rc, 1)
        self.assertIn('HEADER_REGISTRY_ACCEPTED', self.codes(report))
        self.assertIn('ACCEPTED_ID_SET', self.codes(report))

    def test_id_swap_with_same_counts_fails(self):
        swapped = TODO_FIXTURE.replace('- [x] [AA02:', '- [ ] [AA02:')
        swapped = swapped.replace('- [ ] [AA03:', '- [x] [AA03:')
        self.todo.write_text(swapped, encoding='utf-8')
        rc, report = self.run_checker()
        self.assertEqual(rc, 1)
        self.assertEqual(self.codes(report), {'ACCEPTED_ID_SET'})

    def test_header_total_single_edit_fails(self):
        self.todo.write_text(
            TODO_FIXTURE.replace('Two of 3 tasks accepted',
                                 'Two of 4 tasks accepted'),
            encoding='utf-8')
        rc, report = self.run_checker()
        self.assertEqual(rc, 1)
        self.assertIn('HEADER_BOX_TOTAL', self.codes(report))

    def test_requirements_single_edit_fails(self):
        mutated = json.loads(json.dumps(REGISTRY_FIXTURE))
        mutated['requirements'].pop()
        self.registry.write_text(json.dumps(mutated), encoding='utf-8')
        rc, report = self.run_checker()
        self.assertEqual(rc, 1)
        self.assertIn('HEADER_REQUIREMENTS', self.codes(report))

    def test_obligations_single_edit_fails(self):
        self.todo.write_text(
            TODO_FIXTURE.replace('7\nsource-obligation', '6\nsource-obligation'),
            encoding='utf-8')
        rc, report = self.run_checker()
        self.assertEqual(rc, 1)
        self.assertIn('HEADER_OBLIGATIONS', self.codes(report))

    def test_number_words(self):
        module = load_module()
        self.assertEqual(module.number_word('Two'), 2)
        self.assertEqual(module.number_word('fifty-one'), 51)
        self.assertEqual(module.number_word('Ninety-nine'), 99)
        with self.assertRaises(ValueError):
            module.number_word('eleventy')

    def test_live_tree_agrees(self):
        rc, report = self.run_checker(
            todo=REPO_ROOT / 'TODO.md',
            registry=REPO_ROOT / 'docs/superpowers/plans/2026-10-17-scopebase-traceability.json')
        self.assertEqual(rc, 0, f'live census disagrees: {report["errors"]}')
        self.assertEqual(report['status'], 'AGREE')


if __name__ == '__main__':
    unittest.main()
