"""EX01 acceptance tests: real local Git, no worker or external service launch."""
import fcntl
import hashlib
import json
import os
import shutil
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


HELPER = Path(__file__).resolve().parents[2] / 'tools' / 'scopebase_job.py'
PLAN = 'docs/superpowers/plans/product.md'
SPEC = 'docs/superpowers/specs/product.md'
REGISTRY = 'docs/superpowers/plans/2026-10-17-scopebase-traceability.json'
POLICY = {
    'schema_version': 1,
    'roles': {
        'implementer': {'backend': 'native', 'model': 'gpt-6.1-sol',
                        'reasoning_effort': 'high', 'allowed_efforts': ['high', 'xhigh'], 'read_only': False},
        'implementer-escalated': {'backend': 'native', 'model': 'gpt-6.1-sol',
                                 'reasoning_effort': 'max', 'allowed_efforts': ['max'],
                                 'read_only': False, 'reason_required': True},
        'reviewer': {'backend': 'native', 'model': 'gpt-6.1-sol',
                     'reasoning_effort': 'high', 'allowed_efforts': ['high', 'xhigh'], 'read_only': True},
        'critical-reviewer': {'backend': 'native', 'model': 'gpt-6-astra',
                              'reasoning_effort': 'xhigh', 'allowed_efforts': ['high', 'xhigh', 'max'], 'read_only': True},
        'architecture': {'backend': 'native', 'model': 'gpt-6-astra',
                         'reasoning_effort': 'high', 'allowed_efforts': ['high', 'xhigh', 'max'], 'read_only': True},
        'mechanical': {'backend': 'native', 'model': 'gpt-6-luna',
                       'reasoning_effort': 'medium', 'allowed_efforts': ['medium', 'high'], 'read_only': False},
        'muse-reviewer': {'backend': 'muse', 'model': 'muse-spark-1.3',
                          'reasoning_effort': 'max', 'allowed_efforts': ['max'],
                          'contributor_mode': 'on', 'read_only': True},
    },
    'native_fork_turns': 'none', 'max_independent_implementation_lanes': 3,
    'heavy_build_slots': 1, 'muse_max_model_steps': 32,
}
GLOBAL = '## Global Constraints\n\n- Keep authority separate.\n- Never mark a missing cell passing.\n\n'
TASK = '### SB01: Intake\n\nUse independently checked source pins.\n\n- [ ] Preserve the license.\n\n'


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='scopebase jobs ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repository with spaces'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'EX01 Tests')
        self.git('config', 'user.email', 'test@example.invalid')
        self.write('.gitignore', '/.scopebase/\n/.worktrees/\n')
        self.write('AGENTS.md', 'Fixture repository rules: preserve source.\n')
        self.write(PLAN, '# Product plan\n\n**Spec:** [Product spec](../specs/product.md).\n\n' + GLOBAL +
                   '## Tasks\n\n' + TASK + '### SB02: Build\n\nRequires SB01.\n')
        self.write(SPEC, '# Product spec\n\nNo implicit acceptance.\n')
        self.write('orchestration/policy.json', json.dumps(POLICY))
        self.write('orchestration/common-rules.md', 'Preserve failed attempts; report exact tests.\n')
        for name in ('worker', 'reviewer', 'fix', 'report'):
            self.write(f'orchestration/templates/{name}.md', f'# {name.title()} template\n\nFixture {name} instructions.\n')
        self.registry = {'tasks': [
            {'id': 'SB01', 'title': 'Intake', 'plan': PLAN, 'depends_on': [], 'status': 'PLANNED'},
            {'id': 'SB02', 'title': 'Build', 'plan': PLAN, 'depends_on': ['SB01'], 'status': 'PLANNED'}]}
        self.write(REGISTRY, json.dumps(self.registry))
        self.write('src/first.txt', 'base\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture base')
        self.base = self.git('rev-parse', 'HEAD').stdout.strip()
        self.goal = Path(self.temp.name) / 'user goal.txt'
        self.goal.write_text('Prepare the independently useful intake component.\n')

    def write(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def git(self, *args, cwd=None, check=True):
        return subprocess.run(['git', '-C', str(cwd or self.repo), *args], text=True,
                              capture_output=True, check=check)

    def cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(HELPER), *map(str, args)], text=True, capture_output=True)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0, 'invalid invocation unexpectedly admitted')
        return result

    def prepare_args(self, job='first', role='implementer', paths=('src/first.txt',), task='SB01', extra=()):
        args = ['prepare', '--repo', self.repo, '--task', task, '--job=' + job,
                '--role', role, '--goal-file', self.goal]
        if paths:
            args += ['--write-path', *paths]
        return args + list(extra)

    def prepare(self, **kwargs):
        return self.cli(*self.prepare_args(**kwargs))

    def package(self, job='first', head='HEAD', ok=True):
        return self.cli('review-package', '--repo', self.repo, '--job', job, '--head', head, ok=ok)

    def commit_candidate(self, prepared):
        worktree = Path(prepared['worktree'])
        (worktree / 'src/first.txt').write_text('candidate\nsecond line\n')
        (worktree / 'src/payload.bin').write_bytes(bytes(range(256)) + b'\x00new')
        self.git('add', 'src', cwd=worktree)
        self.git('commit', '-qm', 'candidate change', cwd=worktree)
        return worktree, self.git('rev-parse', 'HEAD', cwd=worktree).stdout.strip()

    def test_prepare_binds_real_worktree_fresh_native_dispatch_and_exact_brief(self):
        prepared = self.prepare(paths=('src',))
        worktree = Path(prepared['worktree'])
        manifest = json.loads(Path(prepared['manifest']).read_text())
        dispatch = json.loads(Path(prepared['dispatch']).read_text())
        self.assertEqual(self.git('rev-parse', 'HEAD', cwd=worktree).stdout.strip(), self.base)
        self.assertIn(str(worktree), self.git('worktree', 'list', '--porcelain').stdout)
        self.assertEqual(manifest['base_commit'], self.base)
        self.assertEqual(manifest['execution_state'], 'PREPARED')
        self.assertEqual(manifest['allowed_paths'], ['src'])
        self.assertEqual(manifest['goal_sha256'], hashlib.sha256(self.goal.read_bytes()).hexdigest())
        self.assertEqual(dispatch['model'], 'gpt-6.1-sol')
        self.assertEqual(dispatch['reasoning_effort'], 'high')
        self.assertEqual(dispatch['fork_turns'], 'none')
        self.assertEqual(manifest['role'], 'implementer')
        brief = Path(prepared['brief']).read_text()
        self.assertIn(GLOBAL.strip(), brief)
        self.assertIn(TASK.strip(), brief)
        self.assertIn('orchestration/common-rules.md', brief)
        self.assertIn('orchestration/templates/report.md', brief)
        self.assertIn('independent', brief.lower())
        self.assertNotIn('Requires SB01.', brief)
        snapshot = Path(manifest['goal_snapshot'])
        self.goal.write_text('edited user text')
        self.assertEqual(snapshot.read_text(), 'Prepare the independently useful intake component.\n')
        self.assertEqual(Path(prepared['manifest']).stat().st_mode & 0o777, 0o600)
        for private in ('tmp', 'cargo-target', 'evidence'):
            self.assertEqual((Path(prepared['job']) / private).stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads((self.repo / REGISTRY).read_text())['tasks'][0]['status'], 'PLANNED')

    def test_unknown_role_effort_and_max_without_reason_refuse(self):
        cases = [('unknown', (), 'role'), ('implementer', ('--effort', 'max'), 'effort'),
                 ('implementer-escalated', (), 'reason'),
                 ('critical-reviewer', ('--effort', 'max'), 'reason')]
        for role, extra, expected in cases:
            with self.subTest(role=role, extra=extra):
                result = self.cli(*self.prepare_args(role=role, paths=() if 'reviewer' in role else ('src',),
                                                    extra=extra), ok=False)
                self.assertIn(expected, result.stderr.lower())
        prepared = self.prepare(role='implementer-escalated', extra=('--reason', 'Prior high attempt needs deeper analysis'))
        dispatch = json.loads(Path(prepared['dispatch']).read_text())
        self.assertEqual(dispatch['reasoning_effort'], 'max')
        self.assertEqual(dispatch['fork_turns'], 'none')

    def test_ownership_paths_reject_escape_globs_internals_and_implicit_writes(self):
        for paths in ((), ('../escape',), ('/tmp/escape',), ('.',), ('src/../escape',), ('src/*',),
                      ('.git/config',), ('.scopebase/jobs',), ('.worktrees/x',), ('src//bad',)):
            with self.subTest(paths=paths):
                result = self.cli(*self.prepare_args(paths=paths), ok=False)
                self.assertIn('path', result.stderr.lower())
        (self.repo / 'outside-link').symlink_to(Path(self.temp.name), target_is_directory=True)
        result = self.cli(*self.prepare_args(paths=('outside-link/escape',)), ok=False)
        self.assertIn('path', result.stderr.lower())
        self.assertFalse((self.repo / '.scopebase/jobs/first').exists())

    def test_duplicate_job_does_not_overwrite_evidence(self):
        prepared = self.prepare()
        evidence = Path(prepared['job']) / 'evidence/sentinel'
        evidence.write_text('preserved')
        before = Path(prepared['manifest']).read_bytes()
        result = self.cli(*self.prepare_args(), ok=False)
        self.assertIn('exist', result.stderr.lower())
        self.assertEqual(Path(prepared['manifest']).read_bytes(), before)
        self.assertEqual(evidence.read_text(), 'preserved')

    def test_overlapping_ownership_refuses_ancestor_and_descendant_only(self):
        self.prepare(paths=('src/first.txt',))
        for job, paths in (('ancestor', ('src',)), ('same', ('src/first.txt',))):
            result = self.cli(*self.prepare_args(job=job, paths=paths), ok=False)
            self.assertIn('overlap', result.stderr.lower())
        self.prepare(job='disjoint', paths=('src/second.txt',))
        self.prepare(job='lexically-similar', paths=('src/first.txt-suffix',))
        result = self.cli(*self.prepare_args(job='capacity', paths=('tests',)), ok=False)
        self.assertIn('lane', result.stderr.lower())

    def test_missing_prerequisite_refuses_but_readonly_future_analysis_is_allowed(self):
        result = self.cli(*self.prepare_args(task='SB02'), ok=False)
        self.assertIn('prerequisite', result.stderr.lower())
        future = self.prepare(task='SB02', role='critical-reviewer', paths=())
        self.assertEqual(json.loads(Path(future['manifest']).read_text())['allowed_paths'], [])
        result = self.cli(*self.prepare_args(job='writer-review', role='reviewer'), ok=False)
        self.assertIn('read', result.stderr.lower())
        # Acceptance comes only from the real task registry, never another job's process state.
        self.registry['tasks'][0]['status'] = 'ACCEPTED'
        self.write(REGISTRY, json.dumps(self.registry))
        self.git('add', REGISTRY)
        self.git('commit', '-qm', 'accept prerequisite fixture')
        self.prepare(job='ready', task='SB02')

    def test_shared_common_root_serializes_two_competing_processes(self):
        commands = [[sys.executable, str(HELPER), *map(str, self.prepare_args(job=job, paths=('src',)))]
                    for job in ('racer-one', 'racer-two')]
        processes = [subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for cmd in commands]
        outputs = [p.communicate(timeout=15) for p in processes]
        self.assertEqual(sorted(p.returncode for p in processes), [0, 64], outputs)
        loser = next(out[1] for p, out in zip(processes, outputs) if p.returncode)
        self.assertIn('overlap', loser.lower())
        jobs = list((self.repo / '.scopebase/jobs').glob('*/job.json'))
        self.assertEqual(len(jobs), 1)

    def test_controller_flock_blocks_admission_and_linked_worktree_shares_ownership(self):
        state = self.repo / '.scopebase'
        state.mkdir(mode=0o700)
        (state / 'controller.lock').touch(mode=0o600)
        with (state / 'controller.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            process = subprocess.Popen([sys.executable, str(HELPER), *map(str, self.prepare_args())],
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                blocked = False
                while process.poll() is None and time.monotonic() < deadline:
                    try:
                        blocked = 'lock' in Path(f'/proc/{process.pid}/wchan').read_text()
                    except FileNotFoundError:
                        break
                    if blocked:
                        break
                    time.sleep(0.01)
                self.assertTrue(blocked, 'preparation did not block on the actual controller flock')
                self.assertIsNone(process.poll(), 'admission bypassed the controller flock')
                self.assertFalse((state / 'jobs/first').exists())
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
            stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, stderr)
        prepared = json.loads(stdout)
        linked = Path(prepared['worktree'])
        args = self.prepare_args(job='linked', paths=('src',))
        args[2] = linked
        result = self.cli(*args, ok=False)
        self.assertIn('overlap', result.stderr.lower())

    def test_review_package_is_full_binary_diff_and_never_overwritten(self):
        prepared = self.prepare(paths=('src',))
        worktree, candidate = self.commit_candidate(prepared)
        package = self.package(head=candidate)
        package_dir = Path(package['package'])
        metadata = json.loads((package_dir / 'package.json').read_text())
        full_diff = (package_dir / 'diff.patch').read_bytes()
        self.assertEqual(metadata['base_commit'], self.base)
        self.assertEqual(metadata['candidate_commit'], candidate)
        expected = self.git('diff', '--binary', '--full-index', self.base, candidate, cwd=worktree).stdout
        self.assertEqual(full_diff.decode(), expected)
        self.assertIn(b'GIT binary patch', full_diff)
        self.assertIn('candidate change', (package_dir / 'commits.txt').read_text())
        self.assertIn('src/first.txt', (package_dir / 'stat.txt').read_text())
        self.assertEqual(metadata['diff_sha256'], hashlib.sha256(full_diff).hexdigest())
        result = self.package(head=candidate, ok=False)
        self.assertIn('exist', result.stderr.lower())
        self.assertEqual((package_dir / 'diff.patch').read_bytes(), full_diff)

    def test_review_rejects_dirty_untracked_stale_head_and_outside_ownership(self):
        prepared = self.prepare()
        worktree = Path(prepared['worktree'])
        (worktree / 'src/first.txt').write_text('dirty\n')
        self.assertIn('dirty', self.package(head=self.base, ok=False).stderr.lower())
        self.git('restore', 'src/first.txt', cwd=worktree)
        (worktree / 'untracked.txt').write_text('unknown source\n')
        self.assertIn('untracked', self.package(head=self.base, ok=False).stderr.lower())
        (worktree / 'untracked.txt').unlink()
        self.git('commit', '--allow-empty', '-qm', 'candidate', cwd=worktree)
        self.assertIn('head', self.package(head=self.base, ok=False).stderr.lower())
        (worktree / 'outside.txt').write_text('outside authority\n')
        self.git('add', 'outside.txt', cwd=worktree)
        self.git('commit', '-qm', 'outside authority', cwd=worktree)
        head = self.git('rev-parse', 'HEAD', cwd=worktree).stdout.strip()
        self.assertIn('allowed', self.package(head=head, ok=False).stderr.lower())

    def test_review_rejects_byte_different_policy_source_and_worktree_evidence(self):
        for number, rel in enumerate(('orchestration/policy.json', SPEC, PLAN)):
            with self.subTest(rel=rel):
                job = f'stale-{number}'
                self.prepare(job=job, role='reviewer', paths=())
                original = (self.repo / rel).read_bytes()
                (self.repo / rel).write_bytes(original + b'\nchanged\n')
                result = self.package(job=job, head=self.base, ok=False)
                self.assertIn('binding', result.stderr.lower())
                (self.repo / rel).write_bytes(original)
        prepared = self.prepare(job='worktree-changed', role='reviewer', paths=())
        (Path(prepared['worktree']) / SPEC).write_text('byte-different worktree contract\n')
        self.assertIn('binding', self.package(job='worktree-changed', head=self.base, ok=False).stderr.lower())

    def test_base_must_match_source_inputs_and_existing_branch_worktree_is_not_reused(self):
        self.write(SPEC, 'newer contract\n')
        self.git('add', SPEC)
        self.git('commit', '-qm', 'new spec')
        result = self.cli(*self.prepare_args(extra=('--base', self.base)), ok=False)
        self.assertIn('binding', result.stderr.lower())
        self.git('branch', 'scopebase/occupied')
        result = self.cli(*self.prepare_args(job='occupied'), ok=False)
        self.assertIn('branch', result.stderr.lower())
        self.assertFalse((self.repo / '.scopebase/jobs/occupied').exists())

    def test_ids_empty_goals_and_symlink_evidence_refuse(self):
        for job in ('../bad', '-bad', 'é', 'a' * 65):
            result = self.cli(*self.prepare_args(job=job), ok=False)
            self.assertIn('id', result.stderr.lower())
        self.goal.write_text('   \n')
        self.assertIn('goal', self.cli(*self.prepare_args(), ok=False).stderr.lower())
        self.goal.write_text('valid goal\n')
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (self.repo / '.scopebase/jobs').symlink_to(outside, target_is_directory=True)
        self.assertIn('symlink', self.cli(*self.prepare_args(), ok=False).stderr.lower())
        self.assertEqual(list(outside.iterdir()), [])

    def test_existing_shared_worktree_parent_is_preserved_and_new_worktree_is_private(self):
        parent = self.repo / '.worktrees'
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
        prepared = self.prepare()
        self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(Path(prepared['worktree']).stat().st_mode & 0o777, 0o700)

    def local_effect(self):
        marker = Path(self.temp.name) / 'unexpected-effect'
        executable = Path(self.temp.name) / 'local-effect'
        executable.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\n')
        executable.chmod(0o755)
        return executable, marker

    def test_repository_hooks_do_not_run_during_preparation(self):
        executable, marker = self.local_effect()
        hook = self.repo / '.git/hooks/post-checkout'
        hook.write_bytes(executable.read_bytes())
        hook.chmod(0o755)
        self.prepare()
        self.assertFalse(marker.exists(), 'preparation executed a repository hook')

    def test_checkout_does_not_run_configured_smudge_filters(self):
        executable, marker = self.local_effect()
        self.write('.gitattributes', 'src/*.txt filter=fixture\n')
        self.git('add', '.gitattributes')
        self.git('commit', '-qm', 'fixture filter attribute')
        self.git('config', 'filter.fixture.smudge', shlex.quote(str(executable)))
        prepared = self.prepare()
        self.assertFalse(marker.exists(), 'preparation invoked a checkout filter')
        self.assertEqual((Path(prepared['worktree']) / 'src/first.txt').read_text(), 'base\n')

    def test_review_does_not_run_external_diff_or_textconv(self):
        executable, marker = self.local_effect()
        self.git('config', 'diff.external', shlex.quote(str(executable)))
        self.git('config', 'diff.fixture.textconv', shlex.quote(str(executable)))
        self.write('.gitattributes', '*.txt diff=fixture\n')
        self.git('add', '.gitattributes')
        self.git('commit', '-qm', 'fixture diff config')
        prepared = self.prepare(paths=('src',))
        worktree, head = self.commit_candidate(prepared)
        package = self.package(head=head)
        self.assertFalse(marker.exists(), 'review package executed an external diff/textconv program')
        self.assertIn('GIT binary patch', (Path(package['package']) / 'diff.patch').read_text())

    def test_non_descendant_candidate_is_refused(self):
        prepared = self.prepare()
        worktree = Path(prepared['worktree'])
        orphan = self.git('commit-tree', self.base + '^{tree}', '-m', 'unrelated candidate').stdout.strip()
        self.git('reset', '--hard', orphan, cwd=worktree)
        result = self.package(head=orphan, ok=False)
        self.assertIn('descended', result.stderr.lower())
        self.assertFalse((Path(prepared['job']) / 'review-package').exists())

    def test_partial_preparation_failure_preserves_manifest_and_reserved_resources(self):
        fake_bin = Path(self.temp.name) / 'failing bin'
        fake_bin.mkdir()
        real_git = shutil.which('git')
        wrapper = fake_bin / 'git'
        wrapper.write_text('#!/bin/sh\nfor arg in "$@"; do\n'
                           'if [ "$arg" = "add" ]; then echo deliberate-fixture-worktree-failure >&2; exit 1; fi\n'
                           'done\nexec "' + real_git + '" "$@"\n')
        wrapper.chmod(0o755)
        result = subprocess.run([sys.executable, str(HELPER), *map(str, self.prepare_args())],
                                text=True, capture_output=True,
                                env=dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ['PATH']))
        self.assertEqual(result.returncode, 64, result.stderr)
        manifest_path = self.repo / '.scopebase/jobs/first/job.json'
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest['execution_state'], 'PREPARATION_FAILED')
        self.assertIn('deliberate-fixture-worktree-failure', manifest['preparation_error'])
        self.assertTrue((manifest_path.parent / 'goal.txt').is_file())
        self.assertTrue(Path(manifest['worktree']).is_dir(), 'reserved unknown worktree must be retained')
        self.assertIn('overlap', self.cli(*self.prepare_args(job='retry'), ok=False).stderr.lower())

    def test_invalid_policy_is_refused_without_preparing_a_job(self):
        bad = dict(POLICY, roles=dict(POLICY['roles'], unexpected=POLICY['roles']['implementer']))
        self.write('orchestration/policy.json', json.dumps(bad))
        self.assertIn('policy', self.cli('doctor', '--repo', self.repo, ok=False).stderr.lower())
        self.assertFalse((self.repo / '.scopebase').exists())

    def test_doctor_reports_optional_absence_without_launching_models(self):
        fake_bin = Path(self.temp.name) / 'local bin'
        fake_bin.mkdir()
        # Only --version is allowed: a doctor that starts a session leaves an observable marker.
        marker = Path(self.temp.name) / 'paid-call-marker'
        tool = fake_bin / 'codex'
        tool.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo codex-local-version; '
                        'else : > "' + str(marker) + '"; exit 9; fi\n')
        tool.chmod(0o755)
        for command in ('git', 'flock'):
            (fake_bin / command).symlink_to(shutil.which(command))
        env = dict(os.environ, PATH=str(fake_bin))
        result = subprocess.run([sys.executable, str(HELPER), 'doctor', '--repo', str(self.repo)],
                                text=True, capture_output=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn('optional_tools', report)
        self.assertIn('codex', report['optional_tools'])
        self.assertEqual(report['optional_tools']['muse']['status'], 'OPTIONAL_MISSING')
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
