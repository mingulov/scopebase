"""Administrative progress checks against real Git-deliverable planning files.

These fixtures exercise structural acceptance records, never runtime qualification.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
REGISTRY = 'docs/superpowers/plans/2026-10-17-scopebase-traceability.json'
RECORD = 'docs/reviews/sb01-acceptance.md'


class PlanningProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='scopebase progress ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'planning repo'
        self.repo.mkdir()
        tracked = subprocess.run(
            ['git', '-C', str(REPO), 'ls-files', '-z'],
            check=True, stdout=subprocess.PIPE,
        ).stdout.split(b'\0')
        for raw in filter(None, tracked):
            relative = Path(raw.decode())
            source = REPO / relative
            if source.is_file():
                target = self.repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        shutil.copy2(REPO / 'tools/check_planning_docs.py', self.repo / 'tools/check_planning_docs.py')
        # Rebuild the initial administrative baseline even after real task progress.
        self.registry = json.loads((self.repo / REGISTRY).read_text())
        self.registry.update(status='DESIGN_ONLY', implementation_status='NOT_IMPLEMENTED')
        for task in self.registry['tasks']:
            task['status'] = 'PLANNED'
            task.pop('acceptance', None)
        for req in self.registry['requirements']:
            req['status'] = 'PLANNED'
            req.pop('disposition', None)
        self.write(REGISTRY, json.dumps(self.registry, indent=2) + '\n')
        todo = self.repo / 'TODO.md'
        todo.write_text(todo.read_text().replace('- [x] [', '- [ ] ['))
        self.git('init', '-q')
        self.git('add', '-A')
        self.git('-c', 'user.name=Progress Tests', '-c', 'user.email=test@example.invalid',
                 'commit', '-qm', 'actual planning fixture')
        self.subject = self.git('rev-parse', 'HEAD').stdout.strip()
        self.tasks = {task['id']: task for task in self.registry['tasks']}

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args],
                              text=True, capture_output=True, check=True)

    def write(self, relative, text):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def progress(self, task_id='SB01', status='ACCEPTED'):
        self.registry.update(status='DEVELOPMENT', implementation_status='IN_PROGRESS')
        task = self.tasks[task_id]
        task['status'] = status
        if status == 'ACCEPTED':
            task['acceptance'] = {'subject_commit': self.subject, 'evidence_record': RECORD}
            self.write(RECORD, '# Fixture acceptance record\n\nLocal fixture review; no runtime qualification.\n')
            todo = self.repo / 'TODO.md'
            todo.write_text(todo.read_text().replace(f'- [ ] [{task_id}:', f'- [x] [{task_id}:'))
        return task

    def check(self, error=None):
        self.write(REGISTRY, json.dumps(self.registry, indent=2) + '\n')
        result = subprocess.run([sys.executable, str(self.repo / 'tools/check_planning_docs.py')],
                                text=True, capture_output=True)
        self.assertEqual(result.stderr, '', result.stdout + result.stderr)
        report = json.loads(result.stdout)
        if error is None:
            self.assertEqual(result.returncode, 0, report['errors'])
            self.assertEqual(report['errors'], [])
            self.assertEqual(report['counts']['planned_tasks'], 86)
            self.assertEqual(report['counts']['normative_requirements'], 120)
        else:
            self.assertNotEqual(result.returncode, 0, 'invalid progress unexpectedly accepted')
            self.assertTrue(report['errors'], 'invalid progress produced no diagnostic')
            self.assertTrue(all(error in item for item in report['errors']), report['errors'])
        return report

    def test_unchanged_initial_baseline_is_valid(self):
        self.check()

    def test_accepted_sb01_with_deliverable_record_is_valid(self):
        self.progress()
        self.check()

    def test_accepted_sb01_with_tracked_ignored_record_is_valid(self):
        self.progress()
        self.write('.gitignore', (self.repo / '.gitignore').read_text() + '/docs/reviews/\n')
        self.git('add', '-f', RECORD)
        self.check()

    def test_in_progress_sb01_remains_unchecked(self):
        self.progress(status='IN_PROGRESS')
        self.check()

    def test_missing_or_malformed_acceptance_is_rejected(self):
        task = self.progress()
        for receipt in (None, {}, '', [], {'subject_commit': self.subject}):
            with self.subTest(receipt=receipt):
                task['acceptance'] = receipt
                self.check('SB01: invalid acceptance')
        del task['acceptance']
        self.check('SB01: invalid acceptance')

    def test_subject_must_be_full_lowercase_commit_sha(self):
        task = self.progress()
        for subject in ('', 'main', 'HEAD', 'a' * 39, 'a' * 41, 'A' * 40, 'g' * 40, None, 123):
            with self.subTest(subject=subject):
                task['acceptance']['subject_commit'] = subject
                self.check('SB01: invalid acceptance subject_commit')

    def test_nonaccepted_tasks_cannot_carry_acceptance(self):
        for state in ('PLANNED', 'IN_PROGRESS'):
            with self.subTest(state=state):
                self.tasks['SB01']['status'] = state
                self.tasks['SB01']['acceptance'] = None
                self.registry.update(status='DESIGN_ONLY' if state == 'PLANNED' else 'DEVELOPMENT',
                                     implementation_status='NOT_IMPLEMENTED' if state == 'PLANNED' else 'IN_PROGRESS')
                self.check('SB01: acceptance requires ACCEPTED')

    def test_missing_or_private_evidence_record_is_rejected(self):
        self.progress()
        (self.repo / RECORD).unlink()
        self.check('SB01: invalid acceptance evidence_record')
        self.write(RECORD, '# Private ignored receipt\n')
        self.write('docs/reviews/.gitignore', '*.md\n')
        self.check('SB01: invalid acceptance evidence_record')

    def test_evidence_record_requires_relative_markdown_beneath_reviews(self):
        task = self.progress()
        for path in ('', None, 123, '../outside.md', 'docs/reviews/../../../outside.md',
                     'docs/reviews/../sb01.md', str(self.repo / RECORD),
                     'README.md', 'docs/reviews', 'docs/reviews/record.txt'):
            with self.subTest(path=path):
                task['acceptance']['evidence_record'] = path
                self.check('SB01: invalid acceptance evidence_record')

    def test_evidence_file_or_parent_symlink_is_rejected(self):
        task = self.progress()
        real = self.write('docs/reviews/real.md', '# Real receipt\n')
        link = self.repo / RECORD
        link.unlink()
        link.symlink_to(real)
        self.check('SB01: invalid acceptance evidence_record')
        link.unlink()
        indexed = self.write('docs/reviews/alias/real.md', '# Indexed receipt\n')
        self.git('add', 'docs/reviews/alias/real.md')
        indexed.unlink()
        indexed.parent.rmdir()
        indexed.parent.symlink_to(real.parent, target_is_directory=True)
        task['acceptance']['evidence_record'] = 'docs/reviews/alias/real.md'
        self.check('SB01: invalid acceptance evidence_record')

    def test_checkbox_must_match_accepted_state(self):
        todo = self.repo / 'TODO.md'
        todo.write_text(todo.read_text().replace('- [ ] [SB01:', '- [x] [SB01:'))
        self.check('SB01: root TODO checkbox differs from task status')
        self.progress()
        todo.write_text(todo.read_text().replace('- [x] [SB01:', '- [ ] [SB01:'))
        self.check('SB01: root TODO checkbox differs from task status')

    def test_checked_task_still_has_prerequisites_validated(self):
        self.progress()
        todo = self.repo / 'TODO.md'
        todo.write_text(todo.read_text().replace('prerequisites: none.', 'prerequisites: SB02.', 1))
        self.check('SB01: root TODO prerequisites drift')

    def test_unknown_task_state_is_rejected(self):
        self.progress(status='QUALIFIED')
        self.check('SB01: unknown task status')

    def test_progress_requires_all_mandatory_prerequisites_accepted(self):
        for state in ('IN_PROGRESS', 'ACCEPTED'):
            with self.subTest(state=state):
                self.progress(task_id='SB02', status=state)
                self.check('SB02: mandatory prerequisites not ACCEPTED')
                self.tasks['SB02'].pop('acceptance', None)

    def test_accepted_prerequisite_allows_dependent_progress(self):
        self.progress()
        self.progress(task_id='SB02', status='IN_PROGRESS')
        self.check()

    def test_in_progress_prerequisite_does_not_allow_dependent_progress(self):
        self.progress(status='IN_PROGRESS')
        self.progress(task_id='SB02', status='IN_PROGRESS')
        self.check('SB02: mandatory prerequisites not ACCEPTED')

    def test_profile_gate_dependencies_are_deferred_to_selected_profile_checks(self):
        for task in ('SB01', 'SB02', 'SB03', 'BP01', 'TC01', 'TC02', 'TC03'):
            self.progress(task_id=task)
        self.assertEqual(self.tasks['BP09']['status'], 'PLANNED')
        # REQ-STATUS01: the chain completes TC-R02, so the valid fixture
        # carries its disposition.
        req = next(r for r in self.registry['requirements'] if r['id'] == 'TC-R02')
        req['status'] = 'DISPOSITIONED'
        req['disposition'] = {'verdict': 'SCOPED',
                              'reason': 'Fixture disposition for the profile-gate test chain.'}
        self.check()

    def test_top_execution_state_must_match_task_progress(self):
        for status, implementation in (('DEVELOPMENT', 'NOT_IMPLEMENTED'),
                                       ('DESIGN_ONLY', 'IN_PROGRESS'), ('QUALIFIED', 'NOT_IMPLEMENTED')):
            with self.subTest(status=status, implementation=implementation):
                self.registry.update(status=status, implementation_status=implementation)
                self.check('planning execution state differs from task progress')
        self.progress()
        for status, implementation in (('DESIGN_ONLY', 'NOT_IMPLEMENTED'),
                                       ('DEVELOPMENT', 'NOT_IMPLEMENTED'), ('DEVELOPMENT', 'IMPLEMENTED')):
            with self.subTest(status=status, implementation=implementation):
                self.registry.update(status=status, implementation_status=implementation)
                self.check('planning execution state differs from task progress')

    def test_task_progress_does_not_allow_runtime_qualification(self):
        self.progress()
        for field, value in (('qualification_status', 'PASS'), ('qualification_status', 'QUALIFIED'),
                             ('runnable', True), ('runnable', 0)):
            with self.subTest(field=field, value=value):
                self.registry.update(qualification_status='NOT_RUN', runnable=False)
                self.registry[field] = value
                self.check('planning qualification status')

    def test_requirements_profiles_and_source_obligations_remain_unqualified(self):
        self.progress()
        for section, status, error in (('requirements', 'ACCEPTED', 'requirement status'),
                                       ('profiles', 'QUALIFIED', 'profile status'),
                                       ('source_obligations', 'CLOSED', 'source mapping/status')):
            with self.subTest(section=section):
                entry = self.registry[section][0]
                original = entry['status']
                entry['status'] = status
                self.check(error)
                entry['status'] = original

    def test_progress_does_not_relax_regression_catalog_qualification(self):
        self.progress()
        path = self.repo / 'docs/research/2026-10-17-shared-libraries/regression-catalog.json'
        catalog = json.loads(path.read_text())
        catalog['runnable'] = True
        path.write_text(json.dumps(catalog, indent=2) + '\n')
        self.check('catalog qualification status')

    def test_extension_status_remains_planned_when_present(self):
        extension = self.registry['profile_extensions'][0]
        extension['status'] = 'PLANNED'
        self.check()
        extension['status'] = 'QUALIFIED'
        self.check('extension status')

    # REQ-STATUS01: requirement promotion rule. LX-R01 is owned by LX01
    # alone; accepting SB01/SB02/LX01 completes exactly that requirement
    # (no other requirement resolves over subsets of the chain).
    def accept_lx_chain(self):
        for task_id in ('SB01', 'SB02', 'LX01'):
            self.progress(task_id)
        return next(r for r in self.registry['requirements']
                    if r['id'] == 'LX-R01')

    def test_dispositioned_requirement_with_all_tasks_accepted_is_valid(self):
        req = self.accept_lx_chain()
        req['status'] = 'DISPOSITIONED'
        req['disposition'] = {
            'verdict': 'SCOPED',
            'reason': 'LX01 held-file increment accepted; mappings remain LX02 work.',
        }
        self.check()

    def test_all_accepted_tasks_without_disposition_is_rejected(self):
        self.accept_lx_chain()
        self.check('LX-R01: requirement with all tasks ACCEPTED must be DISPOSITIONED')

    def test_disposition_without_all_tasks_accepted_is_rejected(self):
        self.progress('SB01')
        req = next(r for r in self.registry['requirements'] if r['id'] == 'LX-R01')
        req['status'] = 'DISPOSITIONED'
        req['disposition'] = {'verdict': 'SCOPED', 'reason': 'x' * 40}
        self.check('LX-R01: requirement disposition requires all owner tasks ACCEPTED')

    def test_disposition_without_object_is_rejected(self):
        req = self.accept_lx_chain()
        req['status'] = 'DISPOSITIONED'
        self.check('LX-R01: requirement disposition must state verdict and reason')

    def test_disposition_with_bad_verdict_is_rejected(self):
        req = self.accept_lx_chain()
        req['status'] = 'DISPOSITIONED'
        req['disposition'] = {'verdict': 'DONE', 'reason': 'y' * 40}
        self.check('LX-R01: requirement disposition verdict must be SATISFIED, SCOPED or OPEN')

    def test_disposition_with_short_reason_is_rejected(self):
        req = self.accept_lx_chain()
        req['status'] = 'DISPOSITIONED'
        req['disposition'] = {'verdict': 'SCOPED', 'reason': 'too short'}
        self.check('LX-R01: requirement disposition reason must be substantive')

    def test_planned_requirement_with_disposition_is_rejected(self):
        req = next(r for r in self.registry['requirements'] if r['id'] == 'LX-R01')
        req['disposition'] = {'verdict': 'SCOPED', 'reason': 'z' * 40}
        self.check('LX-R01: PLANNED requirement must not carry a disposition')

    def test_unknown_requirement_status_is_rejected(self):
        req = next(r for r in self.registry['requirements'] if r['id'] == 'LX-R01')
        req['status'] = 'SATISFIED'
        self.check('requirement status must be PLANNED or DISPOSITIONED')

    # TRACE-AMEND01: dated amendments with hashed artifacts.
    def test_valid_new_amendment_is_accepted(self):
        blob = self.git('hash-object', 'TODO.md').stdout.strip()
        self.registry['plan_amendments'].append({
            'date': '2026-10-22',
            'summary': 'Fixture ratification record.',
            'artifacts': [{'path': 'TODO.md', 'blob_sha1': blob}],
            'task_ids': ['SB01'],
            'implementation_or_qualification_claim': False,
            'existing_task_ids_unchanged': True,
            'counts_unchanged': {'tasks': 86, 'requirements': 120,
                                 'source_obligations': 179},
        })
        self.check()

    def test_new_amendment_without_hashes_is_rejected(self):
        tag = f'amendment {len(self.registry["plan_amendments"])}'
        self.registry['plan_amendments'].append({
            'date': '2026-10-22',
            'summary': 'Unhashed record.',
            'counts_unchanged': {'tasks': 86, 'requirements': 120,
                                 'source_obligations': 179},
        })
        self.check(tag + ': entries dated 2026-10-22+ must list hashed artifacts')

    def test_new_amendment_with_wrong_blob_is_rejected(self):
        tag = f'amendment {len(self.registry["plan_amendments"])}'
        self.registry['plan_amendments'].append({
            'date': '2026-10-22',
            'summary': 'Wrong hash record.',
            'artifacts': [{'path': 'TODO.md', 'blob_sha1': '0' * 40}],
            'counts_unchanged': {'tasks': 86, 'requirements': 120,
                                 'source_obligations': 179},
        })
        self.check(tag + ': artifact TODO.md blob mismatch')

    def test_new_amendment_with_counts_drift_is_rejected(self):
        tag = f'amendment {len(self.registry["plan_amendments"])}'
        blob = self.git('hash-object', 'TODO.md').stdout.strip()
        self.registry['plan_amendments'].append({
            'date': '2026-10-22',
            'summary': 'Drifted counts record.',
            'artifacts': [{'path': 'TODO.md', 'blob_sha1': blob}],
            'counts_unchanged': {'tasks': 86, 'requirements': 121,
                                 'source_obligations': 179},
        })
        self.check(tag + ': counts_unchanged differs from registry counts')


if __name__ == '__main__':
    unittest.main()
