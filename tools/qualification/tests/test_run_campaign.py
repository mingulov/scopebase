# SPDX-License-Identifier: Apache-2.0
"""Unit checks for tools/qualification/run_campaign.py (TT06 campaign scaffolding).

TDD: these checks were authored before the runner and observed failing
(ModuleNotFoundError: no module named 'campaign_runner') prior to implementation.
"""
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    'campaign_runner', ROOT / 'tools/qualification/run_campaign.py')
c = importlib.util.module_from_spec(spec)
sys.modules['campaign_runner'] = c
spec.loader.exec_module(c)

PASS_STUB = (
    "import json,sys\n"
    "json.dump({'setup_ok': True, 'assertion': 'pass',"
    " 'work_items': int(sys.argv[1]), 'seed': 7,"
    " 'detail': 'stub-ok'}, open(sys.argv[2], 'w'))\n"
)
FAIL_STUB = (
    "import json,sys\n"
    "json.dump({'setup_ok': True, 'assertion': 'fail',"
    " 'work_items': int(sys.argv[1]), 'seed': 7,"
    " 'detail': 'stub-invariant-violated'}, open(sys.argv[2], 'w'))\n"
)
SETUP_FAIL_STUB = (
    "import json,sys\n"
    "json.dump({'setup_ok': False, 'assertion': 'error',"
    " 'work_items': 0, 'seed': 7,"
    " 'detail': 'stub-setup-denied'}, open(sys.argv[2], 'w'))\n"
)
SLEEP_STUB = "import time;time.sleep(30)\n"
CRASH_STUB = "import os;os._exit(137)\n"
# Forks a grandchild that writes a late poison record, then sleeps past any
# short timeout so the runner must retire the whole process group: killing
# only the direct child leaves the grandchild alive to poison a later
# invocation's fixed result path.
LATE_GRANDCHILD_STUB = (
    "import json,os,sys,time\n"
    "result = sys.argv[1]\n"
    "child = os.fork()\n"
    "if child == 0:\n"
    "    time.sleep(3)\n"
    "    json.dump({'setup_ok': True, 'assertion': 'pass', 'work_items': 8,\n"
    "     'detail': 'late-poison'}, open(result, 'w'))\n"
    "    os._exit(0)\n"
    "time.sleep(30)\n"
)
# Writes its own record immediately, then stays alive past the late-write
# instant of a previous invocation's surviving writer.
EARLY_WRITE_THEN_WAIT_STUB = (
    "import json,sys,time\n"
    "json.dump({'setup_ok': True, 'assertion': 'pass', 'work_items': 1,\n"
    " 'detail': 'own-result'}, open(sys.argv[1], 'w'))\n"
    "sys.stdout.flush()\n"
    "time.sleep(5)\n"
)
# Exits on its own after 2s without writing: exercises the timeout path
# with a child that needs no killing.
SELF_EXIT_STUB = (
    "import sys,time\n"
    "time.sleep(2)\n"
)
# Writes through the environment channel instead of argv substitution.
ENV_STUB = (
    "import json,os\n"
    "json.dump({'setup_ok': True, 'assertion': 'pass', 'work_items': 8,\n"
    " 'detail': 'env-ok'}, open(os.environ['CAMPAIGN_RESULT_FILE'], 'w'))\n"
)


def manifest(campaigns):
    return {'schema_version': 1, 'campaigns': campaigns}


def campaign(cid, argv, expected, limits=None, kind='state-model', **extra):
    entry = {
        'id': cid,
        'kind': kind,
        'target': {'argv': argv},
        'seed': 7,
        'version': 'stub-target 0.0.0',
        'limits': limits or {'time_secs': 60, 'max_work_items': 8,
                             'max_memory_bytes': 134217728},
        'domain_contract': 'stub contract: argv[1]=work_items argv[2]=result path',
        'artifact': 'stub-result.json',
        'expected_verdict': expected,
    }
    entry.update(extra)
    return entry


class CampaignRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.out = self.root / 'out'
        self.out.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write_stub(self, name, body):
        path = self.root / name
        path.write_text(body)
        return [sys.executable, str(path)]

    def write_manifest(self, data):
        path = self.root / 'campaigns.json'
        path.write_text(json.dumps(data))
        return path

    def run_entry(self, data, cid):
        return c.run_campaign(self.write_manifest(data), cid, self.out, root=self.root)

    def test_valid_manifest_loads_and_rejects_unknown_fields(self):
        argv = self.write_stub('s.py', PASS_STUB) + ['8', '{result}']
        data = manifest([campaign('ok', argv, 'EXHAUSTED')])
        loaded = c.load_manifest(self.write_manifest(data))
        self.assertEqual(len(loaded['campaigns']), 1)
        bad = campaign('bad', argv, 'EXHAUSTED')
        bad['surprise'] = 1
        with self.assertRaises(c.CampaignManifestError):
            self.run_entry(manifest([bad]), 'bad')

    def test_manifest_rejects_bad_bounds_and_verdicts(self):
        argv = self.write_stub('s.py', PASS_STUB) + ['8', '{result}']
        base = campaign('x', argv, 'EXHAUSTED')
        for mutate in [lambda e: e['limits'].update(time_secs=0),
                       lambda e: e['limits'].update(max_work_items=-1),
                       lambda e: e['limits'].pop('max_memory_bytes'),
                       lambda e: e.update(expected_verdict='GREEN'),
                       lambda e: e.update(kind='vibes'),
                       lambda e: e['target'].update(argv=[]),
                       lambda e: e.update(id='has space'),
                       lambda e: e.update(seed=-3)]:
            import copy
            entry = copy.deepcopy(base)
            mutate(entry)
            with self.subTest(entry=entry):
                with self.assertRaises(c.CampaignManifestError):
                    self.run_entry(manifest([entry]), 'x')

    def test_unknown_campaign_id_is_manifest_error(self):
        argv = self.write_stub('s.py', PASS_STUB) + ['8', '{result}']
        with self.assertRaises(c.CampaignManifestError):
            self.run_entry(manifest([campaign('ok', argv, 'EXHAUSTED')]), 'missing')

    def test_exhausted_finite_search_matches(self):
        argv = self.write_stub('ok.py', PASS_STUB) + ['8', '{result}']
        result = self.run_entry(manifest([campaign('finite', argv, 'EXHAUSTED')]), 'finite')
        self.assertEqual(result.verdict, 'EXHAUSTED')
        self.assertTrue(result.setup_ok)
        self.assertTrue(result.match)
        self.assertTrue(result.completed)
        self.assertEqual(result.work_items, 8)

    def test_partial_pass_is_time_bounded_not_exhausted(self):
        argv = self.write_stub('ok.py', PASS_STUB) + ['3', '{result}']
        result = self.run_entry(manifest([campaign('part', argv, 'TIME_BOUNDED')]), 'part')
        self.assertEqual(result.verdict, 'TIME_BOUNDED')
        self.assertFalse(result.completed)
        self.assertTrue(result.match)

    def test_failed_assertion_after_valid_setup(self):
        argv = self.write_stub('bad.py', FAIL_STUB) + ['8', '{result}']
        result = self.run_entry(manifest([campaign('m', argv, 'FAILED')]), 'm')
        self.assertEqual(result.verdict, 'FAILED')
        self.assertTrue(result.setup_ok)
        self.assertTrue(result.match)

    def test_bad_control_requires_valid_setup(self):
        # A mutant that crashes setup must NOT satisfy an expected FAILED verdict.
        argv = self.write_stub('setup.py', SETUP_FAIL_STUB) + ['0', '{result}']
        result = self.run_entry(manifest([campaign('m', argv, 'FAILED')]), 'm')
        self.assertEqual(result.verdict, 'SETUP_ERROR')
        self.assertFalse(result.setup_ok)
        self.assertFalse(result.match)
        argv = self.write_stub('crash.py', CRASH_STUB)
        result = self.run_entry(manifest([campaign('m', argv, 'FAILED')]), 'm')
        self.assertEqual(result.verdict, 'CRASH')
        self.assertFalse(result.match)

    def test_mismatch_reports_not_match(self):
        argv = self.write_stub('bad.py', FAIL_STUB) + ['8', '{result}']
        result = self.run_entry(manifest([campaign('m', argv, 'EXHAUSTED')]), 'm')
        self.assertEqual(result.verdict, 'FAILED')
        self.assertFalse(result.match)

    def test_timeout_is_time_bounded(self):
        argv = self.write_stub('sleep.py', SLEEP_STUB)
        limits = {'time_secs': 1, 'max_work_items': 8, 'max_memory_bytes': 134217728}
        result = self.run_entry(manifest([campaign('slow', argv, 'TIME_BOUNDED', limits)]), 'slow')
        self.assertEqual(result.verdict, 'TIME_BOUNDED')
        self.assertFalse(result.completed)
        self.assertTrue(result.match)

    def test_work_overrun_is_bound_exceeded(self):
        argv = self.write_stub('ok.py', PASS_STUB) + ['80', '{result}']
        result = self.run_entry(manifest([campaign('w', argv, 'BOUND_EXCEEDED')]), 'w')
        self.assertEqual(result.verdict, 'BOUND_EXCEEDED')
        self.assertTrue(result.match)

    def test_missing_binary_is_prerequisite_unmet(self):
        entry = campaign('p', ['/nonexistent-tt06-stub-binary', '{result}'], 'PREREQUISITE_UNMET')
        result = self.run_entry(manifest([entry]), 'p')
        self.assertEqual(result.verdict, 'PREREQUISITE_UNMET')
        self.assertTrue(result.match)

    def test_missing_prerequisite_command_is_prerequisite_unmet(self):
        argv = self.write_stub('ok.py', PASS_STUB) + ['8', '{result}']
        entry = campaign('p', argv, 'PREREQUISITE_UNMET',
                         prerequisites=['definitely-not-installed-tt06-tool-xyz'])
        result = self.run_entry(manifest([entry]), 'p')
        self.assertEqual(result.verdict, 'PREREQUISITE_UNMET')
        self.assertTrue(result.match)
        self.assertIn('prerequisite', result.detail.lower())

    def test_result_artifact_written_with_bounds_and_observation(self):
        argv = self.write_stub('ok.py', PASS_STUB) + ['8', '{result}']
        entry = campaign('finite', argv, 'EXHAUSTED')
        result = self.run_entry(manifest([entry]), 'finite')
        artifact = self.out / 'finite.json'
        self.assertTrue(artifact.is_file())
        data = json.loads(artifact.read_text())
        self.assertEqual(data['verdict'], 'EXHAUSTED')
        self.assertEqual(data['expected_verdict'], 'EXHAUSTED')
        self.assertEqual(data['limits']['max_work_items'], 8)
        self.assertEqual(data['limits']['time_secs'], 60)
        self.assertEqual(data['limits']['max_memory_bytes'], 134217728)
        self.assertIn('elapsed_secs', data['observed'])
        self.assertIn('peak_rss_bytes', data['observed'])
        self.assertIn('exit_code', data['observed'])
        self.assertEqual(data['seed'], 7)
        self.assertTrue(data['match'])
        self.assertEqual(result.to_json()['verdict'], 'EXHAUSTED')

    def test_memory_overrun_recorded_without_changing_deterministic_verdict(self):
        argv = self.write_stub('ok.py', PASS_STUB) + ['8', '{result}']
        limits = {'time_secs': 60, 'max_work_items': 8, 'max_memory_bytes': 1}
        result = self.run_entry(manifest([campaign('m', argv, 'EXHAUSTED', limits)]), 'm')
        self.assertEqual(result.verdict, 'EXHAUSTED')
        data = json.loads((self.out / 'm.json').read_text())
        self.assertTrue(data['observed']['memory_overrun'])

    def test_timeout_retires_process_group_and_isolates_result_paths(self):
        # F4: a surviving late writer from a timed-out invocation must not
        # poison a later invocation. The first run times out while its
        # grandchild sleeps; the second run starts before the late-write
        # instant, writes its own record, and stays alive past it. With a
        # fixed shared path and direct-child-only kill, the second run reads
        # the poison record (EXHAUSTED, work 8); with invocation-bound paths
        # and process-group retirement it reads its own (TIME_BOUNDED, work 1).
        slow_argv = self.write_stub('late.py', LATE_GRANDCHILD_STUB) + ['{result}']
        limits = {'time_secs': 1, 'max_work_items': 8, 'max_memory_bytes': 134217728}
        first = self.run_entry(
            manifest([campaign('race', slow_argv, 'TIME_BOUNDED', limits)]), 'race')
        self.assertEqual(first.verdict, 'TIME_BOUNDED')
        own_argv = self.write_stub('own.py', EARLY_WRITE_THEN_WAIT_STUB) + ['{result}']
        limits2 = {'time_secs': 10, 'max_work_items': 8, 'max_memory_bytes': 134217728}
        second = self.run_entry(
            manifest([campaign('race', own_argv, 'TIME_BOUNDED', limits2)]), 'race')
        self.assertEqual(second.verdict, 'TIME_BOUNDED')
        self.assertEqual(second.work_items, 1)
        self.assertEqual(second.detail, 'own-result')
        # No fixed shared partial path may remain: result paths are
        # invocation-bound.
        self.assertFalse((self.out / 'race.partial.json').exists())

    def test_result_path_env_channel_matches_argv_substitution(self):
        argv = self.write_stub('env.py', ENV_STUB)
        result = self.run_entry(manifest([campaign('finite', argv, 'EXHAUSTED')]), 'finite')
        self.assertEqual(result.verdict, 'EXHAUSTED')
        self.assertEqual(result.detail, 'env-ok')
        self.assertTrue(result.match)

    def test_retirement_failure_refuses_partial_result(self):
        # F4 follow-up: if process-group retirement cannot be confirmed
        # (killpg fails), the runner must fail closed with a gate-failing
        # CUSTODY_UNCONFIRMED verdict, never accept the partial or report
        # TIME_BOUNDED. The stub grandchild exits on its own after 3s; the
        # direct child is still killed best-effort, so no stray outlives
        # the test.
        real_killpg = os.killpg

        def boom(*args, **kwargs):
            raise OSError('simulated retirement failure')

        # B2: the bounded reap must run even when retirement fails, so the
        # direct child is reaped and pipes drained on every path. Observed
        # via a communicate spy rather than zombie sampling: CPython's
        # Popen destructor reaps opportunistically, which makes any
        # post-return zombie check pass with or without the reap.
        real_communicate = subprocess.Popen.communicate
        reap_timeouts = []

        def spy_comm(self, *args, **kwargs):
            reap_timeouts.append(kwargs.get('timeout'))
            return real_communicate(self, *args, **kwargs)

        os.killpg = boom
        subprocess.Popen.communicate = spy_comm
        try:
            slow_argv = self.write_stub('late.py', LATE_GRANDCHILD_STUB) + ['{result}']
            limits = {'time_secs': 1, 'max_work_items': 8,
                      'max_memory_bytes': 134217728}
            result = self.run_entry(
                manifest([campaign('race', slow_argv, 'TIME_BOUNDED', limits)]), 'race')
        finally:
            os.killpg = real_killpg
            subprocess.Popen.communicate = real_communicate
        self.assertEqual(result.verdict, 'CUSTODY_UNCONFIRMED')
        self.assertFalse(result.match)
        self.assertEqual(result.to_json()['gate'], 'fail')
        self.assertIn('retirement', result.detail)
        self.assertIn(c.REAP_TIMEOUT_SECS, reap_timeouts)

    def test_retired_group_confirmed_by_absence(self):
        # F4 follow-up: when the group is already gone at confirm time
        # (signal 0 raises ProcessLookupError), retirement counts as
        # confirmed and the normal timeout path applies. The stub exits on
        # its own after 2s so the bounded reap observes EOF; SIGKILL
        # delivery itself is faked, only the confirm branch is under test.
        real_killpg = os.killpg
        calls = []

        def flaky(pid, sig):
            calls.append(sig)
            if sig == 0:
                raise ProcessLookupError('group gone')
            return None

        os.killpg = flaky
        try:
            argv = self.write_stub('brief.py', SELF_EXIT_STUB) + ['{result}']
            limits = {'time_secs': 1, 'max_work_items': 8,
                      'max_memory_bytes': 134217728}
            result = self.run_entry(
                manifest([campaign('brief', argv, 'TIME_BOUNDED', limits)]), 'brief')
        finally:
            os.killpg = real_killpg
        self.assertEqual(result.verdict, 'TIME_BOUNDED')
        self.assertTrue(result.match)
        self.assertIn(0, calls)

    def test_non_session_kill_failure_still_reaps(self):
        # B2 non-session path: even when the direct-child kill itself
        # fails, the bounded reap must still run (and retirement is then
        # decided by what the reap observes). killpg is detached so the
        # POSIX group path is off; Popen.kill is forced to raise; the
        # stub exits alone after 2s, so the reap observes EOF and the
        # normal timeout path applies.
        real_killpg = os.killpg
        real_kill = subprocess.Popen.kill
        real_communicate = subprocess.Popen.communicate
        reap_timeouts = []

        def spy_comm(self, *args, **kwargs):
            reap_timeouts.append(kwargs.get('timeout'))
            return real_communicate(self, *args, **kwargs)

        def boom(self):
            raise OSError('simulated kill failure')

        del os.killpg
        subprocess.Popen.kill = boom
        subprocess.Popen.communicate = spy_comm
        try:
            argv = self.write_stub('brief.py', SELF_EXIT_STUB) + ['{result}']
            limits = {'time_secs': 1, 'max_work_items': 8,
                      'max_memory_bytes': 134217728}
            result = self.run_entry(
                manifest([campaign('brief', argv, 'TIME_BOUNDED', limits)]), 'brief')
        finally:
            os.killpg = real_killpg
            subprocess.Popen.kill = real_kill
            subprocess.Popen.communicate = real_communicate
        self.assertEqual(result.verdict, 'TIME_BOUNDED')
        self.assertTrue(result.match)
        self.assertIn(c.REAP_TIMEOUT_SECS, reap_timeouts)

    def test_reap_timeout_fails_closed(self):
        # The reap itself is bounded: pipes held past REAP_TIMEOUT_SECS
        # (kill delivery faked, target still running) refuse the result
        # with CUSTODY_UNCONFIRMED instead of hanging. Shortened bound
        # keeps the test fast; the captured proc is killed in cleanup.
        real_killpg = os.killpg
        real_reap = c.REAP_TIMEOUT_SECS
        procs = []
        real_communicate = subprocess.Popen.communicate

        def spy_comm(self, *args, **kwargs):
            procs.append(self)
            return real_communicate(self, *args, **kwargs)

        os.killpg = lambda *args, **kwargs: None
        subprocess.Popen.communicate = spy_comm
        c.REAP_TIMEOUT_SECS = 2
        try:
            slow_argv = self.write_stub('late.py', LATE_GRANDCHILD_STUB) + ['{result}']
            limits = {'time_secs': 1, 'max_work_items': 8,
                      'max_memory_bytes': 134217728}
            result = self.run_entry(
                manifest([campaign('race', slow_argv, 'TIME_BOUNDED', limits)]), 'race')
        finally:
            os.killpg = real_killpg
            subprocess.Popen.communicate = real_communicate
            c.REAP_TIMEOUT_SECS = real_reap
            for proc in procs:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except OSError:
                    pass
        self.assertEqual(result.verdict, 'CUSTODY_UNCONFIRMED')
        self.assertEqual(result.to_json()['gate'], 'fail')

    def test_custody_verdict_is_unexpectable(self):
        # B1: no manifest may declare CUSTODY_UNCONFIRMED as its expectation:
        # unconfirmed retirement is gate-failing regardless of expectation.
        entry = campaign('q', ['/bin/true', '{result}'], 'CUSTODY_UNCONFIRMED')
        with self.assertRaises(c.CampaignManifestError):
            c.validate_campaign(entry)

    def test_unbound_sanitizer_command_is_refused(self):
        # F5: a sanitizer campaign whose target is a plain command (not the
        # bound `cargo +<toolchain> miri run` form) must not execute as a
        # Miri campaign: no Miri verdict is accepted without the bound
        # command. The plain target below would report EXHAUSTED if run.
        argv = self.write_stub('ok.py', PASS_STUB) + ['8', '{result}']
        entry = campaign('miri-unbound', argv, 'PREREQUISITE_UNMET', kind='sanitizer')
        result = self.run_entry(manifest([entry]), 'miri-unbound')
        self.assertEqual(result.verdict, 'PREREQUISITE_UNMET')
        self.assertEqual(result.to_json()['gate'], 'incomplete')
        self.assertIn('bound', result.detail.lower())

    def test_prerequisite_unmet_is_gate_failing(self):
        # F5: PREREQUISITE_UNMET is an incomplete diagnostic: it may match its
        # documented expectation, but the command gate must not see success.
        import subprocess
        entry = campaign('p', ['/nonexistent-tt06-stub-binary', '{result}'],
                         'PREREQUISITE_UNMET')
        result = self.run_entry(manifest([entry]), 'p')
        self.assertEqual(result.verdict, 'PREREQUISITE_UNMET')
        self.assertTrue(result.match)
        self.assertEqual(result.to_json()['gate'], 'incomplete')
        mp = self.write_manifest(manifest([entry]))
        runner = str(ROOT / 'tools/qualification/run_campaign.py')
        proc = subprocess.run(
            [sys.executable, runner, '--manifest', str(mp),
             '--output-root', str(self.out), '--root', str(self.root),
             '--campaign', 'p'], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_cli_exit_codes(self):
        import subprocess
        argv = self.write_stub('ok.py', PASS_STUB) + ['8', '{result}']
        mp = self.write_manifest(manifest([campaign('finite', argv, 'EXHAUSTED')]))
        runner = str(ROOT / 'tools/qualification/run_campaign.py')
        base = [sys.executable, runner, '--manifest', str(mp),
                '--output-root', str(self.out), '--root', str(self.root)]
        ok = subprocess.run(base + ['--campaign', 'finite'], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        mp2 = self.write_manifest(manifest([campaign('finite', argv, 'FAILED')]))
        bad = subprocess.run(
            [sys.executable, runner, '--manifest', str(mp2),
             '--output-root', str(self.out), '--root', str(self.root),
             '--campaign', 'finite'], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1, bad.stderr)
        missing = subprocess.run(base + ['--campaign', 'nope'], capture_output=True, text=True)
        self.assertEqual(missing.returncode, 2, missing.stderr)


if __name__ == '__main__':
    unittest.main()
