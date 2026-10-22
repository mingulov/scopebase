"""EX01 acceptance tests: real local Git, no worker or external service launch."""
import fcntl
import hashlib
import importlib.util
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
_spec = importlib.util.spec_from_file_location('scopebase_job', HELPER)
job_helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(job_helper)

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
        'critical-reviewer': {'backend': 'native', 'model': 'gpt-6.1-sol',
                              'reasoning_effort': 'max', 'allowed_efforts': ['max'],
                              'read_only': True, 'reason_required': True},
        'architecture': {'backend': 'native', 'model': 'gpt-6.1-sol',
                         'reasoning_effort': 'max', 'allowed_efforts': ['max'],
                         'read_only': True, 'reason_required': True},
        'exceptional-reviewer': {'backend': 'native', 'model': 'gpt-6-astra',
                                 'reasoning_effort': 'xhigh', 'allowed_efforts': ['xhigh', 'max'],
                                 'read_only': True, 'reason_required': True},
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

    def writing_args(self, action='suspend-writing', job='first', generation=0, head=None,
                     reason='Writer finished; retained custody is unresolved', evidence=None):
        if evidence is None:
            evidence = Path(self.temp.name) / 'quiescence.txt'
            evidence.write_text('Controller confirms writer finished; retain all paths and resources.\n')
        args = [action, '--repo', self.repo, '--job', job, '--generation', generation,
                '--head', head or self.git('rev-parse', 'HEAD', cwd=self.repo / '.worktrees' / job).stdout.strip(),
                '--reason', reason, '--evidence-file', evidence]
        if action == 'suspend-writing':
            args.append('--write-quiescent')
        return args

    def snapshot(self, directory):
        return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob('*') if p.is_file()}

    def assert_no_job(self, name):
        self.assertFalse((self.repo / '.scopebase/jobs' / name).exists())
        self.assertFalse((self.repo / '.worktrees' / name).exists())
        self.assertNotEqual(self.git('show-ref', '--verify', 'refs/heads/scopebase/' + name,
                                     check=False).returncode, 0)

    def test_suspend_frees_writer_slot_but_preserves_original_job(self):
        first = self.prepare()
        self.prepare(job='second', paths=('src/second.txt',))
        self.prepare(job='third', paths=('src/third.txt',))
        refused = self.cli(*self.prepare_args(job='fourth', paths=('src/fourth.txt',)), ok=False)
        self.assertEqual(refused.returncode, 64)
        self.assertIn('lane', refused.stderr)
        self.assert_no_job('fourth')
        self.package()
        job = Path(first['job'])
        before = self.snapshot(job)
        policy_before = (self.repo / 'orchestration/policy.json').read_bytes()
        registry_before = (self.repo / REGISTRY).read_bytes()
        args = self.writing_args()
        evidence = Path(args[args.index('--evidence-file') + 1])
        evidence_bytes = evidence.read_bytes()
        result = self.cli(*args)
        self.assertEqual(result['writing_permission'], 'SUSPENDED')
        self.assertEqual(result['generation'], 1)
        self.assertEqual(result['path_ownership'], 'RETAINED')
        self.assertEqual(result['resource_retirement'], 'NOT_ATTESTED')
        self.assertEqual(result['worker_launch'], 'NOT_LAUNCHED')
        evidence.write_text('changed later input\n')
        self.assertEqual(Path(result['evidence_snapshot']).read_bytes(), evidence_bytes)
        self.prepare(job='fourth', paths=('src/fourth.txt',))
        for rel, content in before.items():
            self.assertEqual((job / rel).read_bytes(), content)
        self.assertTrue(Path(first['worktree']).is_dir())
        self.assertIn(str(first['worktree']), self.git('worktree', 'list', '--porcelain').stdout)
        self.assertEqual((self.repo / 'orchestration/policy.json').read_bytes(), policy_before)
        self.assertEqual((self.repo / REGISTRY).read_bytes(), registry_before)

    def test_suspended_claim_still_rejects_same_ancestor_descendant_paths(self):
        self.prepare(paths=('src/owned',))
        self.cli(*self.writing_args())
        for number, path in enumerate(('src/owned', 'src', 'src/owned/child')):
            name = 'overlap-' + str(number)
            result = self.cli(*self.prepare_args(job=name, paths=(path,)), ok=False)
            self.assertEqual(result.returncode, 64)
            self.assertIn('overlap', result.stderr)
            self.assert_no_job(name)
        self.prepare(job='similar', paths=('src/owned-other',))
        self.prepare(job='disjoint', paths=('tests',))

    def test_suspension_requires_explicit_quiescence_and_supported_subject(self):
        prepared = self.prepare()
        directory = Path(prepared['job'])
        worktree = Path(prepared['worktree'])
        args = self.writing_args()
        invalid_args = [args[:-1]]
        for flag, value in (('--generation', '-1'), ('--generation', 'true'), ('--generation', '1'),
                            ('--head', 'HEAD'), ('--head', self.base[:12]),
                            ('--reason', ''), ('--reason', '  '), ('--reason', 'x' * 65537), ('--reason', '\n' * 65535 + 'x'),
                            ('--reason', '\u0080' * 32768)):
            changed = list(args)
            changed[changed.index(flag) + 1] = value
            invalid_args.append(changed)
        evidence = Path(self.temp.name) / 'invalid evidence'
        for content in (b'', b' \n', b'NUL\0text', b'\xff', b'x' * 65537):
            evidence.write_bytes(content)
            changed = list(args)
            changed[changed.index('--evidence-file') + 1] = evidence
            self.assertEqual(self.cli(*changed, ok=False).returncode, 64)
        link = Path(self.temp.name) / 'evidence-link'
        link.symlink_to(evidence)
        fifo = Path(self.temp.name) / 'evidence-fifo'
        os.mkfifo(fifo)
        for value in ('relative.txt', link, fifo):
            changed = list(args)
            changed[changed.index('--evidence-file') + 1] = value
            invalid_args.append(changed)
        for changed in invalid_args:
            with self.subTest(args=changed[-3:]):
                self.assertEqual(self.cli(*changed, ok=False).returncode, 64)
                self.assertFalse((directory / 'writing').exists())
        manifest_path = directory / 'job.json'
        original = manifest_path.read_bytes()
        for field, value in (('execution_state', 'PREPARING'), ('execution_state', 'PREPARATION_FAILED'),
                             ('read_only', True), ('allowed_paths', []), ('worktree_git_dir', '/wrong'),
                             ('branch', 'wrong'), ('schema_version', True)):
            record = json.loads(original)
            record[field] = value
            manifest_path.write_text(json.dumps(record))
            self.assertEqual(self.cli(*args, ok=False).returncode, 64)
            self.assertFalse((directory / 'writing').exists())
        manifest_path.write_bytes(original)
        nul_reason = list(args)
        nul_reason[nul_reason.index('--reason') + 1] = 'invalid\0reason'
        self.assertEqual(job_helper.main(list(map(str, nul_reason))), 64)
        self.assertFalse((directory / 'writing').exists())
        for name in ('goal.txt', 'brief.md', 'dispatch.json'):
            artifact = directory / name
            saved_artifact = artifact.read_bytes()
            artifact.write_bytes(saved_artifact + b'changed')
            self.assertEqual(self.cli(*args, ok=False).returncode, 64)
            self.assertFalse((directory / 'writing').exists())
            artifact.write_bytes(saved_artifact)
        for flag in ('--assume-unchanged', '--skip-worktree'):
            self.git('update-index', flag, 'src/first.txt', cwd=worktree)
            self.assertEqual(self.cli(*args, ok=False).returncode, 64)
            self.git('update-index', flag.replace('--', '--no-', 1), 'src/first.txt', cwd=worktree)
        (worktree / 'src/first.txt').write_text('dirty\n')
        self.assertEqual(self.cli(*args, ok=False).returncode, 64)
        self.git('restore', 'src/first.txt', cwd=worktree)
        (worktree / 'untracked').write_text('source\n')
        self.assertEqual(self.cli(*args, ok=False).returncode, 64)
        (worktree / 'untracked').unlink()
        self.git('checkout', '--detach', '-q', cwd=worktree)
        self.assertEqual(self.cli(*args, ok=False).returncode, 64)
        self.git('checkout', '-q', 'scopebase/first', cwd=worktree)
        self.git('update-index', '--add', '--cacheinfo', '160000,' + self.base + ',submodule', cwd=worktree)
        self.git('commit', '-qm', 'gitlink fixture', cwd=worktree)
        self.assertEqual(self.cli(*self.writing_args(), ok=False).returncode, 64)
        self.assertFalse((directory / 'writing').exists())
        readonly = self.prepare(job='readonly', role='reviewer', paths=())
        self.assertEqual(self.cli(*self.writing_args(job='readonly'), ok=False).returncode, 64)
        self.assertFalse((Path(readonly['job']) / 'writing').exists())
        self.cli(*self.reconciliation_args())
        self.assertEqual(self.cli(*self.writing_args(), ok=False).returncode, 64)

    def test_resume_reacquires_capacity_and_retains_suspension_on_refusal(self):
        prepared = self.prepare()
        self.prepare(job='second', paths=('second',))
        self.prepare(job='third', paths=('third',))
        self.cli(*self.writing_args())
        self.prepare(job='fourth', paths=('fourth',))
        ledger = Path(prepared['job']) / 'writing'
        before = self.snapshot(ledger)
        result = self.cli(*self.writing_args('resume-writing', generation=1), ok=False)
        self.assertEqual(result.returncode, 64)
        self.assertIn('lane', result.stderr)
        self.assertEqual(self.snapshot(ledger), before)
        policy_path = self.repo / 'orchestration/policy.json'
        policy_before = policy_path.read_bytes()
        reduced_policy = json.loads(policy_before)
        reduced_policy['max_independent_implementation_lanes'] = 2
        policy_path.write_text(json.dumps(reduced_policy))
        reduced = self.cli(*self.writing_args('resume-writing', generation=1), ok=False)
        self.assertEqual(reduced.returncode, 64)
        self.assertIn('lane', reduced.stderr)
        policy_path.write_bytes(policy_before)
        self.cli(*self.reconciliation_args(job='second'))
        from unittest.mock import patch
        real_policy = job_helper.policy
        def policy_changes_after_read(repo):
            selected = real_policy(repo)
            policy_path.write_text(json.dumps(reduced_policy))
            return selected
        with patch.object(job_helper, 'policy', side_effect=policy_changes_after_read):
            self.assertEqual(job_helper.main(list(map(str, self.writing_args('resume-writing', generation=1)))), 64)
        self.assertFalse((Path(prepared['job']) / 'writing/events/00000002').exists())
        policy_path.write_bytes(policy_before)
        result = self.cli(*self.writing_args('resume-writing', generation=1))
        self.assertEqual(result['writing_permission'], 'ACTIVE')
        self.assertEqual(result['generation'], 2)
        refused = self.cli(*self.prepare_args(job='fifth', paths=('fifth',)), ok=False)
        self.assertEqual(refused.returncode, 64)
        self.assertIn('lane', refused.stderr)
        self.assert_no_job('fifth')

    def test_resume_only_skips_own_claim_and_never_changes_scope(self):
        first = self.prepare()
        other = self.prepare(job='other', paths=('other',))
        self.cli(*self.writing_args())
        manifest = Path(other['manifest'])
        original = manifest.read_bytes()
        # Deliberately conflicting retained fixture: do not edit any operational job.
        record = json.loads(original)
        record['allowed_paths'] = ['src']
        manifest.write_text(json.dumps(record))
        result = self.cli(*self.writing_args('resume-writing', generation=1), ok=False)
        self.assertEqual(result.returncode, 64)
        self.assertIn('overlap', result.stderr)
        self.assertFalse((Path(first['job']) / 'writing/events/00000002').exists())
        manifest.write_bytes(original)
        for extra in (('--write-path', 'new'), ('--role', 'reviewer'), ('--resources-retired',)):
            self.assertEqual(self.cli(*self.writing_args('resume-writing', generation=1),
                                      *extra, ok=False).returncode, 64)
        self.cli(*self.writing_args('resume-writing', generation=1))

    def test_repeat_suspend_resume_is_generation_bound_and_append_only(self):
        prepared = self.prepare()
        ledger = Path(prepared['job']) / 'writing'
        self.cli(*self.writing_args())
        first = self.snapshot(ledger / 'events/00000001')
        self.assertEqual(self.cli(*self.writing_args(generation=1), ok=False).returncode, 64)
        self.assertEqual(self.cli(*self.writing_args('resume-writing', generation=0), ok=False).returncode, 64)
        self.cli(*self.writing_args('resume-writing', generation=1))
        worktree = Path(prepared['worktree'])
        (worktree / 'src/first.txt').write_text('authorized active change\n')
        # ACTIVE state permits work, including dirty source and a later clean commit.
        self.prepare(job='during-active-edit', paths=('other',))
        self.git('add', 'src/first.txt', cwd=worktree)
        self.git('commit', '-qm', 'authorized active checkpoint', cwd=worktree)
        self.cli(*self.writing_args(generation=2))
        self.cli(*self.writing_args('resume-writing', generation=3))
        self.assertEqual(self.snapshot(ledger / 'events/00000001'), first)
        self.assertEqual(self.cli(*self.writing_args('resume-writing', generation=4), ok=False).returncode, 64)
        # Build a hand-authored, hash-linked valid history to the real on-disk bound.
        source = (ledger / 'events/00000003/source.json').read_bytes()
        previous = hashlib.sha256((ledger / 'events/00000004/event.json').read_bytes()).hexdigest()
        suspend = json.loads((ledger / 'events/00000003/event.json').read_bytes())
        resume = json.loads((ledger / 'events/00000004/event.json').read_bytes())
        for generation in range(5, 256):
            event = dict(suspend if generation % 2 else resume)
            event.update(generation=generation, previous_event_sha256=previous)
            if generation % 2 == 0:
                event['suspended_event_sha256'] = previous
            target = ledger / 'events' / f'{generation:08d}'
            target.mkdir(mode=0o700)
            for name, content in (('source.json', source), ('evidence.txt', b'Controller confirms writer finished; retain all paths and resources.\n'),
                                  ('event.json', (json.dumps(event, sort_keys=True, indent=2) + '\n').encode())):
                (target / name).write_bytes(content)
                (target / name).chmod(0o600)
            previous = hashlib.sha256((target / 'event.json').read_bytes()).hexdigest()
        head = json.loads((ledger / 'current.json').read_bytes())
        head.update(generation=255, event_sha256=previous)
        (ledger / 'current.json').write_text(json.dumps(head, sort_keys=True, indent=2) + '\n')
        self.cli(*self.writing_args('resume-writing', generation=255))
        before = self.snapshot(ledger)
        result = self.cli(*self.writing_args(generation=256), ok=False)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(self.snapshot(ledger), before)

    def test_suspended_source_drift_retains_writer_and_claim(self):
        prepared = self.prepare()
        self.cli(*self.writing_args())
        worktree = Path(prepared['worktree'])
        ledger = Path(prepared['job']) / 'writing'
        before = self.snapshot(ledger)
        def refused():
            for name, path in (('drift-disjoint', 'other'), ('drift-overlap', 'src')):
                result = self.cli(*self.prepare_args(job=name, paths=(path,)), ok=False)
                self.assertEqual(result.returncode, 64)
                self.assert_no_job(name)
            self.assertEqual(self.cli(*self.writing_args('resume-writing', generation=1), ok=False).returncode, 64)
            self.assertEqual(self.snapshot(ledger), before)
        (worktree / 'src/first.txt').write_text('drift\n')
        refused()
        self.git('restore', 'src/first.txt', cwd=worktree)
        (worktree / 'new-source').write_text('drift\n')
        refused()
        (worktree / 'new-source').unlink()
        self.git('commit', '--allow-empty', '-qm', 'moved suspended head', cwd=worktree)
        refused()
        self.git('reset', '--hard', self.base, cwd=worktree)
        self.git('checkout', '--detach', '-q', cwd=worktree)
        refused()
        self.git('checkout', '-q', 'scopebase/first', cwd=worktree)
        dotgit = worktree / '.git'
        identity = dotgit.read_bytes()
        dotgit.unlink()
        dotgit.symlink_to(self.repo / '.git')
        refused()
        dotgit.unlink()
        dotgit.write_bytes(identity)
        self.prepare(job='restored', paths=('other',))

    def test_corrupt_or_missing_writing_state_fails_closed(self):
        prepared = self.prepare()
        self.cli(*self.writing_args())
        self.cli(*self.writing_args('resume-writing', generation=1))
        job = Path(prepared['job'])
        ledger = job / 'writing'
        saved = self.snapshot(ledger)
        def restore():
            shutil.rmtree(ledger)
            ledger.mkdir(mode=0o700)
            (ledger / 'events').mkdir(mode=0o700)
            for rel, data in saved.items():
                path = ledger / rel
                path.parent.mkdir(mode=0o700, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o600)
        def refusal():
            result = self.cli(*self.prepare_args(job='invalid-ledger', paths=('other',)), ok=False)
            self.assertEqual(result.returncode, 64, result.stdout)
            self.assert_no_job('invalid-ledger')
            self.assertEqual(self.cli(*self.writing_args(generation=2), ok=False).returncode, 64)
        for rel in ('current.json', 'events/00000002/event.json', 'events/00000001/event.json',
                    'events/00000001/source.json', 'events/00000002/evidence.txt'):
            with self.subTest(missing=rel):
                (ledger / rel).unlink()
                refusal()
                restore()
        shutil.rmtree(ledger / 'events/00000002')
        refusal()  # Last RESUME must not disappear into prior SUSPEND authority.
        restore()
        event_path = ledger / 'events/00000002/event.json'
        for key, value in (('reason_sha256', '0' * 64), ('job_manifest_sha256', '0' * 64),
                           ('generation', True), ('previous_event_sha256', '0' * 64),
                           ('unknown', 'unsupported')):
            record = json.loads(event_path.read_bytes())
            record[key] = value
            event_path.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
            refusal()
            restore()
        for content in (b'{}' + b' ' * 131073,
                        saved['events/00000002/event.json'].replace(b'"schema_version": 1,', b'"schema_version": 1, "schema_version": 1,'),
                        json.dumps(json.loads(saved['events/00000002/event.json'])).encode()):
            event_path.write_bytes(content)
            refusal()
            restore()
        for rel in ('current.json.next', 'extra', 'events/00000003/extra', 'events/00000004/extra'):
            path = ledger / rel
            path.parent.mkdir(mode=0o700, exist_ok=True)
            path.write_text('partial/orphan\n')
            refusal()
            restore()
        path = ledger / 'events/00000001/evidence.txt'
        path.unlink()
        path.symlink_to(Path(self.temp.name) / 'quiescence.txt')
        refusal()
        restore()
        for rel, field, value in (('current.json', 'generation', True),
                                  ('current.json', 'schema_version', 2),
                                  ('current.json', 'unknown', 'field'),
                                  ('events/00000001/source.json', 'head_commit', 'HEAD'),
                                  ('events/00000002/event.json', 'other_active_writers', True),
                                  ('events/00000002/event.json', 'implementation_cap', 4)):
            record_path = ledger / rel
            record = json.loads(record_path.read_bytes())
            record[field] = value
            record_path.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
            refusal()
            restore()
        for rel in ('current.json', 'events/00000001/source.json', 'events/00000001/evidence.txt'):
            path = ledger / rel
            path.write_bytes(b'x' * (65537 if rel.endswith('txt') else 16385))
            refusal()
            restore()
        manifest_path = job / 'job.json'
        original_manifest = manifest_path.read_bytes()
        altered = json.loads(original_manifest)
        altered['allowed_paths'] = ['changed']
        manifest_path.write_text(json.dumps(altered))
        refusal()
        manifest_path.write_bytes(original_manifest)
        # A malformed ledger also refuses read-only preparation.
        (ledger / 'current.json').unlink()
        result = self.cli(*self.prepare_args(job='readonly-invalid', role='reviewer', paths=()), ok=False)
        self.assertEqual(result.returncode, 64)
        self.assert_no_job('readonly-invalid')

    def test_partial_transition_and_fsync_failure_preserve_claims(self):
        from unittest.mock import patch
        prepared = self.prepare()
        args = self.writing_args()
        # Inject failures in real filesystem operations, keeping all state/Git validation real.
        ledger = Path(prepared['job']) / 'writing'
        real_fsync = os.fsync
        for failed_call in range(1, 10):
            with self.subTest(fsync=failed_call):
                calls = 0
                def fail(fd):
                    nonlocal calls
                    calls += 1
                    if calls == failed_call:
                        raise OSError('deliberate publication fsync failure')
                    return real_fsync(fd)
                with patch.object(job_helper.os, 'fsync', side_effect=fail):
                    self.assertEqual(job_helper.main(list(map(str, args))), 64)
                self.assertTrue(ledger.exists())
                if (ledger / 'current.json').exists():
                    # A fully visible post-replace SUSPEND can be valid despite lost success.
                    self.assertEqual(json.loads((ledger / 'current.json').read_bytes())['generation'], 1)
                else:
                    refused = self.cli(*self.prepare_args(job='partial', paths=('other',)), ok=False)
                    self.assertEqual(refused.returncode, 64)
                    self.assert_no_job('partial')
                    self.assertEqual(self.cli(*args, ok=False).returncode, 64)
                shutil.rmtree(ledger)  # Only temporary fixture repair between independent injections.
        real_write = job_helper.durable_file
        for failed_write in range(1, 5):
            with self.subTest(file_write=failed_write):
                writes = 0
                def fail_write(path, content):
                    nonlocal writes
                    writes += 1
                    if writes == failed_write:
                        raise OSError('deliberate snapshot/head write failure')
                    return real_write(path, content)
                with patch.object(job_helper, 'durable_file', side_effect=fail_write):
                    self.assertEqual(job_helper.main(list(map(str, args))), 64)
                self.assertTrue((ledger / 'events/00000001').is_dir())
                self.assertEqual(self.cli(*self.prepare_args(job='partial-write', paths=('other',)), ok=False).returncode, 64)
                self.assert_no_job('partial-write')
                self.assertEqual(self.cli(*args, ok=False).returncode, 64)
                shutil.rmtree(ledger)
        # Failure at replacement leaves exclusive .next and event: admission must refuse.
        with patch.object(job_helper.os, 'replace', side_effect=OSError('head replace failure')):
            self.assertEqual(job_helper.main(list(map(str, args))), 64)
        self.assertTrue((ledger / 'current.json.next').exists())
        self.assertEqual(self.cli(*self.prepare_args(job='torn', paths=('other',)), ok=False).returncode, 64)
        shutil.rmtree(ledger)
        self.cli(*args)
        # A visible resume counts even if its final-directory fsync failed.
        real_sync = job_helper.sync_directory
        def fail_final(path):
            if path == ledger and (ledger / 'current.json').exists() and json.loads((ledger / 'current.json').read_bytes())['generation'] == 2:
                raise OSError('resume final directory fsync failure')
            return real_sync(path)
        resume_args = self.writing_args('resume-writing', generation=1)
        with patch.object(job_helper, 'sync_directory', side_effect=fail_final):
            self.assertEqual(job_helper.main(list(map(str, resume_args))), 64)
        self.prepare(job='second', paths=('second',))
        self.prepare(job='third', paths=('third',))
        result = self.cli(*self.prepare_args(job='fourth', paths=('fourth',)), ok=False)
        self.assertEqual(result.returncode, 64)
        self.assertIn('lane', result.stderr)

    def test_resume_and_prepare_race_for_one_slot_under_common_lock(self):
        prepared = self.prepare()
        self.prepare(job='second', paths=('second',))
        self.prepare(job='third', paths=('third',))
        self.cli(*self.writing_args())
        resume = self.writing_args('resume-writing', generation=1)
        prepare = self.prepare_args(job='racer', paths=('racer',))
        prepare[2] = Path(prepared['worktree'])
        processes = [subprocess.Popen([sys.executable, str(HELPER), *map(str, args)],
                                     text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for args in (resume, prepare)]
        outputs = [p.communicate(timeout=20) for p in processes]
        self.assertEqual(sorted(p.returncode for p in processes), [0, 64], outputs)
        if processes[0].returncode:
            self.assertFalse((Path(prepared['job']) / 'writing/events/00000002').exists())
        else:
            self.assert_no_job('racer')
        # Both transition commands must block on the same actual canonical lock.
        for action, generation in (('suspend-writing', 2), ('resume-writing', 1)):
            args = self.writing_args(action, generation=generation)
            before = self.snapshot(Path(prepared['job']))
            with (self.repo / '.scopebase/controller.lock').open('r+b') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                process = subprocess.Popen([sys.executable, str(HELPER), *map(str, args)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
                    self.assertTrue(blocked)
                    self.assertEqual(self.snapshot(Path(prepared['job'])), before)
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    process.communicate(timeout=20)

    def test_legacy_reconciliation_and_review_bindings_stay_compatible(self):
        prepared = self.prepare()
        package = self.package()
        metadata = (Path(package['package']) / 'package.json').read_bytes()
        manifest = Path(prepared['manifest']).read_bytes()
        self.cli(*self.writing_args())
        self.cli(*self.writing_args('resume-writing', generation=1))
        self.assertEqual(Path(prepared['manifest']).read_bytes(), manifest)
        self.assertEqual((Path(package['package']) / 'package.json').read_bytes(), metadata)
        self.assertEqual(json.loads(metadata)['job_manifest_sha256'], hashlib.sha256(manifest).hexdigest())
        self.cli(*self.writing_args(generation=2))
        ledger = Path(prepared['job']) / 'writing'
        before = self.snapshot(ledger)
        self.cli(*self.reconciliation_args())
        self.assertEqual(self.cli(*self.writing_args('resume-writing', generation=3), ok=False).returncode, 64)
        self.assertEqual(self.cli(*self.writing_args(generation=3), ok=False).returncode, 64)
        self.assertEqual(self.snapshot(ledger), before)
        # Final release remains valid even with later damaged historical writing evidence.
        (ledger / 'current.json').unlink()
        self.prepare(job='released', paths=('src',))

    def test_writing_operations_do_not_launch_or_modify_external_resources(self):
        prepared = self.prepare()
        directory = Path(prepared['job'])
        retained = directory / 'evidence/retained-lease'
        retained.write_text('unresolved resource custody\n')
        before = self.snapshot(directory)
        source = self.git('rev-parse', 'HEAD', cwd=Path(prepared['worktree'])).stdout
        fake_bin = Path(self.temp.name) / 'sentinels'
        fake_bin.mkdir()
        marker = Path(self.temp.name) / 'external-effect'
        for name in ('codex', 'muse', 'cargo', 'rustc', 'ssh', 'kill', 'pkill', 'flock'):
            path = fake_bin / name
            path.write_text('#!/bin/sh\n: > ' + shlex.quote(str(marker)) + '\nexit 97\n')
            path.chmod(0o755)
        (fake_bin / 'git').symlink_to(shutil.which('git'))
        self.git('config', 'core.fsmonitor', str(fake_bin / 'codex'))
        env = dict(os.environ, PATH=str(fake_bin))
        for args in (self.writing_args(), self.writing_args('resume-writing', generation=1)):
            result = subprocess.run([sys.executable, str(HELPER), *map(str, args)],
                                    capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['worker_launch'], 'NOT_LAUNCHED')
        self.git('config', '--unset', 'core.fsmonitor')
        self.assertFalse(marker.exists())
        for rel, content in before.items():
            self.assertEqual((directory / rel).read_bytes(), content)
        self.assertEqual(self.git('rev-parse', 'HEAD', cwd=Path(prepared['worktree'])).stdout, source)
        self.assertEqual(self.git('status', '--porcelain', cwd=Path(prepared['worktree'])).stdout, '')

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

    def test_default_critical_roles_use_sol_max(self):
        for role in ('critical-reviewer', 'architecture'):
            with self.subTest(role=role):
                prepared = self.prepare(job=role, role=role, paths=(),
                                        extra=('--reason', 'User-directed Sol max review to conserve Astra quota'))
                dispatch = json.loads(Path(prepared['dispatch']).read_text())
                self.assertEqual(dispatch['model'], 'gpt-6.1-sol')
                self.assertEqual(dispatch['reasoning_effort'], 'max')
                self.assertEqual(dispatch['fork_turns'], 'none')
                manifest = json.loads(Path(prepared['manifest']).read_text())
                self.assertTrue(manifest['read_only'])
                self.assertEqual(manifest['allowed_paths'], [])

    def test_astra_requires_explicit_exceptional_role_and_recorded_reason(self):
        result = self.cli(*self.prepare_args(job='exceptional', role='exceptional-reviewer',
                                            paths=()), ok=False)
        self.assertIn('reason', result.stderr.lower())
        self.assertFalse((self.repo / '.scopebase/jobs/exceptional').exists())
        reason = 'Sol max could not resolve conflicting unsafe lifetime proofs; serious memory-safety issue'
        prepared = self.prepare(job='exceptional', role='exceptional-reviewer', paths=(),
                                extra=('--reason', reason))
        dispatch = json.loads(Path(prepared['dispatch']).read_text())
        manifest = json.loads(Path(prepared['manifest']).read_text())
        self.assertEqual(dispatch['model'], 'gpt-6-astra')
        self.assertEqual(dispatch['reasoning_effort'], 'xhigh')
        self.assertTrue(manifest['read_only'])
        self.assertEqual(manifest['allowed_paths'], [])
        self.assertEqual(manifest['reason'], reason)

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
        future = self.prepare(task='SB02', role='critical-reviewer', paths=(),
                              extra=('--reason', 'Independent Sol max prerequisite review'))
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
        self.assertFalse((Path(prepared['job']) / 'reviews').exists())

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

    def reconciliation_args(self, job='first', retired=True, reason='Reviewed and inspected; no active resources remain', evidence=None):
        if evidence is None:
            evidence = Path(self.temp.name) / 'retirement evidence.txt'
            evidence.write_text('Fixture controller inspected resources; no processes, builds or guests remain.\n')
        args = ['reconcile', '--repo', self.repo, '--job', job, '--reason', reason,
                '--evidence-file', evidence]
        if retired:
            args.append('--resources-retired')
        return args

    def test_review_rejects_both_sides_of_owned_and_unowned_renames(self):
        self.write('outside.txt', 'outside source preserved in fixture\n')
        self.git('add', 'outside.txt')
        self.git('commit', '-qm', 'rename fixture')
        self.git('config', 'diff.renames', 'true')
        for job, source, destination, allowed in (
                ('inward', 'outside.txt', 'owned.txt', 'owned.txt'),
                ('outward', 'src/first.txt', 'other-outside.txt', 'src/first.txt')):
            with self.subTest(direction=job):
                prepared = self.prepare(job=job, paths=(allowed,))
                worktree = Path(prepared['worktree'])
                self.git('mv', source, destination, cwd=worktree)
                self.git('commit', '-qm', 'cross ownership rename', cwd=worktree)
                candidate = self.git('rev-parse', 'HEAD', cwd=worktree).stdout.strip()
                refusal = self.package(job=job, head=candidate, ok=False)
                self.assertIn('allowed', refusal.stderr.lower())
                self.assertFalse((Path(prepared['job']) / 'reviews' / candidate).exists())

    def test_all_86_actual_registry_tasks_have_exact_bounded_sections(self):
        actual_root = HELPER.parents[1]
        registry = json.loads((actual_root / REGISTRY).read_text())
        self.assertEqual(len(registry['tasks']), 86)
        self.write(REGISTRY, json.dumps(registry))
        for plan in {task['plan'] for task in registry['tasks']}:
            self.write(plan, (actual_root / plan).read_text())
        for task in registry['tasks']:
            with self.subTest(task=task['id']):
                extracted = job_helper.inputs(self.repo, task['id'])[3]
                plan = (self.repo / task['plan']).read_text()
                prefix = ('## Task ' if task['id'].startswith('CP') else
                          '## ' if task['id'].startswith('LX') else '### ') + task['id'] + ':'
                heading = next(line for line in plan.splitlines() if line.startswith(prefix))
                self.assertEqual(extracted.splitlines()[0], heading)
                self.assertIn('- [ ]', extracted)
                for other in registry['tasks']:
                    if other['id'] == task['id'] or other['plan'] != task['plan']:
                        continue
                    for line in plan.splitlines():
                        if line.startswith(('## ' + other['id'] + ':', '## Task ' + other['id'] + ':',
                                            '### ' + other['id'] + ':')):
                            self.assertNotIn(line, extracted)

    def test_task_heading_depth_exact_id_missing_and_duplicate_refusal(self):
        for heading in ('## SB01: Intake', '## Task SB01: Intake', '### SB01: Intake'):
            with self.subTest(heading=heading):
                self.write(PLAN, '# Plan\n\n' + GLOBAL + heading + '\n\nselected body\n\n' +
                           '#### Nested detail\n\nretained detail\n\n## Boundary\n\nexcluded tail\n')
                selected = job_helper.inputs(self.repo, 'SB01')[3]
                self.assertIn('retained detail', selected)
                self.assertNotIn('excluded tail', selected)
        for bad in ('### SB010: wrong ID\nbody\n', '### SB01x: wrong ID\nbody\n',
                    '### Task SB01: unsupported form\nbody\n',
                    '### SB01: first\nbody\n## Task SB01: duplicate\nother\n'):
            with self.subTest(malformed=bad):
                self.write(PLAN, '# Plan\n\n' + GLOBAL + bad)
                with self.assertRaises(job_helper.JobError):
                    job_helper.inputs(self.repo, 'SB01')

    def test_selected_base_tree_rejects_owned_symlink_before_any_job_reservation(self):
        outside = Path(self.temp.name) / 'outside authority'
        outside.mkdir()
        (outside / 'file.txt').write_text('must remain untouched\n')
        (self.repo / 'owned').symlink_to(outside, target_is_directory=True)
        self.git('add', 'owned')
        self.git('commit', '-qm', 'older symlink tree')
        older = self.git('rev-parse', 'HEAD').stdout.strip()
        (self.repo / 'owned').unlink()
        self.write('owned/file.txt', 'safe current source\n')
        self.git('add', 'owned')
        self.git('commit', '-qm', 'current regular tree')
        refusal = self.cli(*self.prepare_args(paths=('owned/file.txt',), extra=('--base', older)), ok=False)
        self.assertIn('path', refusal.stderr.lower())
        self.assertFalse((self.repo / '.scopebase/jobs/first').exists())
        self.assertFalse((self.repo / '.worktrees/first').exists())
        self.assertEqual((outside / 'file.txt').read_text(), 'must remain untouched\n')

    def test_populated_worktree_symlink_refuses_and_retains_failed_custody(self):
        self.write('owned/file.txt', 'safe committed file\n')
        self.git('add', 'owned')
        self.git('commit', '-qm', 'safe selected tree')
        outside = Path(self.temp.name) / 'outside authority'
        outside.mkdir()
        (outside / 'file.txt').write_text('must remain untouched\n')
        fake_bin = Path(self.temp.name) / 'mutating git bin'
        fake_bin.mkdir()
        wrapper = fake_bin / 'git'
        worktree = self.repo / '.worktrees/first'
        wrapper.write_text('#!' + sys.executable + '\nimport os, shutil, subprocess, sys\n'
                           'result = subprocess.call([' + repr(shutil.which('git')) + ', *sys.argv[1:]])\n'
                           'if result == 0 and "worktree" in sys.argv and "add" in sys.argv:\n'
                           '    owned = ' + repr(str(worktree / 'owned')) + '\n'
                           '    shutil.rmtree(owned)\n'
                           '    os.symlink(' + repr(str(outside)) + ', owned)\n'
                           'sys.exit(result)\n')
        wrapper.chmod(0o755)
        result = subprocess.run([sys.executable, str(HELPER), *map(str, self.prepare_args(paths=('owned/file.txt',)))],
                                text=True, capture_output=True,
                                env=dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ['PATH']))
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn('path', result.stderr.lower())
        manifest = json.loads((self.repo / '.scopebase/jobs/first/job.json').read_text())
        self.assertEqual(manifest['execution_state'], 'PREPARATION_FAILED')
        self.assertTrue((worktree / 'owned').is_symlink())
        self.assertIn('overlap', self.cli(*self.prepare_args(job='retry', paths=('owned/file.txt',)), ok=False).stderr.lower())
        self.assertEqual((outside / 'file.txt').read_text(), 'must remain untouched\n')
        self.cli(*self.reconciliation_args())
        self.prepare(job='after-abandonment', paths=('owned/file.txt',))
        self.assertTrue((worktree / 'owned').is_symlink(), 'reconciliation must not clean up retained evidence')

    def test_fix_commit_gets_fresh_candidate_package_and_preserves_prior_package(self):
        prepared = self.prepare(paths=('src',))
        worktree, first = self.commit_candidate(prepared)
        first_package = Path(self.package(head=first)['package'])
        saved = {path.name: path.read_bytes() for path in first_package.iterdir()}
        self.assertEqual(first_package, Path(prepared['job']) / 'reviews' / first)
        (worktree / 'src/first.txt').write_text('fixed candidate\n')
        self.git('add', 'src/first.txt', cwd=worktree)
        self.git('commit', '-qm', 'fix candidate', cwd=worktree)
        second = self.git('rev-parse', 'HEAD', cwd=worktree).stdout.strip()
        second_package = Path(self.package(head=second)['package'])
        self.assertEqual(second_package, Path(prepared['job']) / 'reviews' / second)
        self.assertEqual(saved, {path.name: path.read_bytes() for path in first_package.iterdir()})
        self.assertIn('exist', self.package(head=second, ok=False).stderr.lower())

    def test_only_explicit_valid_reconciliation_releases_prefix_and_lane(self):
        prepared = self.prepare(paths=('src',))
        self.prepare(job='second-lane', paths=('tests',))
        self.prepare(job='third-lane', paths=('bin',))
        self.assertIn('lane', self.cli(*self.prepare_args(job='fourth', paths=('tools',)), ok=False).stderr.lower())
        missing = self.cli(*self.reconciliation_args(retired=False), ok=False)
        self.assertIn('retired', missing.stderr.lower())
        self.assertIn('overlap', self.cli(*self.prepare_args(job='same-prefix', paths=('src',)), ok=False).stderr.lower())
        manifest = Path(prepared['manifest']).read_bytes()
        original_package = Path(self.package(head=self.base)['package'])
        package_metadata = (original_package / 'package.json').read_bytes()
        args = self.reconciliation_args()
        evidence = Path(args[args.index('--evidence-file') + 1])
        expected_evidence = evidence.read_bytes()
        result = self.cli(*args)
        record_path = Path(result['reconciliation'])
        record = json.loads(record_path.read_text())
        self.assertEqual(record['job_manifest_sha256'], hashlib.sha256(manifest).hexdigest())
        self.assertTrue(record['resources_retired'])
        self.assertEqual(Path(result['evidence_snapshot']).read_bytes(), expected_evidence)
        evidence.write_text('later user edit must not replace closure evidence\n')
        self.assertEqual(Path(result['evidence_snapshot']).read_bytes(), expected_evidence)
        self.assertEqual(Path(prepared['manifest']).read_bytes(), manifest)
        self.assertTrue(Path(prepared['worktree']).is_dir())
        self.assertEqual((original_package / 'package.json').read_bytes(), package_metadata)
        self.prepare(job='new-ownership', paths=('src',))
        self.assertIn('exist', self.cli(*self.prepare_args(), ok=False).stderr.lower())
        before = record_path.read_bytes()
        self.assertIn('exist', self.cli(*args, ok=False).stderr.lower())
        self.assertEqual(record_path.read_bytes(), before)
        self.assertEqual(json.loads((self.repo / REGISTRY).read_text())['tasks'][0]['status'], 'PLANNED')

    def test_invalid_reconciliation_inputs_and_tampered_record_keep_claims(self):
        prepared = self.prepare(paths=('src',))
        evidence = Path(self.temp.name) / 'closure.txt'
        for content in ('', '   \n', 'x' * 65537, '\x00invalid'):
            with self.subTest(invalid_evidence=len(content)):
                evidence.write_text(content)
                self.cli(*self.reconciliation_args(evidence=evidence), ok=False)
                self.assertFalse((Path(prepared['job']) / 'reconciliation.json').exists())
        evidence.write_text('independently inspected fixture resources retired\n')
        self.cli(*self.reconciliation_args(evidence=Path('relative-evidence')), ok=False)
        self.cli(*self.reconciliation_args(evidence=evidence, reason='  '), ok=False)
        self.assertIn('overlap', self.cli(*self.prepare_args(job='blocked', paths=('src',)), ok=False).stderr.lower())
        result = self.cli(*self.reconciliation_args(evidence=evidence))
        record_path = Path(result['reconciliation'])
        original = record_path.read_bytes()
        record = json.loads(original)
        for key, value in (('resources_retired', False), ('job_manifest_sha256', '0' * 64),
                           ('job_id', 'wrong-job')):
            with self.subTest(tamper=key):
                altered = dict(record, **{key: value})
                record_path.write_text(json.dumps(altered))
                refusal = self.cli(*self.prepare_args(job='tampered-' + key, paths=('src',)), ok=False)
                self.assertIn('reconciliation', refusal.stderr.lower())
                self.assertFalse((self.repo / '.scopebase/jobs' / ('tampered-' + key)).exists())
        record_path.write_bytes(original)
        snapshot = Path(result['evidence_snapshot'])
        snapshot.write_text('tampered snapshot\n')
        self.assertIn('reconciliation', self.cli(*self.prepare_args(job='tampered-snapshot', paths=('src',)), ok=False).stderr.lower())

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
