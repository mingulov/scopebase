"""Lock acceptance uses real Linux flock and real child processes."""

import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "bin/scopebase-build"


class LockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scopebase lock ")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.lock_root = self.base / "locks with spaces"
        self.sentinel = self.base / "sentinel"

    def command(self, *args, resource="build", timeout=None, default=False):
        result = ["bash", str(WRAPPER)]
        if not default:
            result += ["--lock-root", str(self.lock_root)]
        result += ["--resource", resource]
        if timeout is not None:
            result += ["--timeout", str(timeout)]
        return result + ["--", *args]

    def run_command(self, code, **kwargs):
        return subprocess.run(self.command(sys.executable, "-c", code, **kwargs),
                              text=True, capture_output=True, timeout=10)

    def wait_for(self, predicate, processes=()):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            for process in processes:
                if process.poll() is not None:
                    output = process.communicate()
                    self.fail("holder exited before synchronization: " + repr(output))
            time.sleep(0.01)
        self.fail("child did not reach synchronization point")

    def start_holder(self):
        ready = self.base / "ready"
        release = self.base / "release"
        code = ("import pathlib,time; pathlib.Path(" + repr(str(ready)) + ").touch(); "
                "\nwhile not pathlib.Path(" + repr(str(release)) + ").exists(): time.sleep(.01)")
        process = subprocess.Popen(self.command(sys.executable, "-c", code),
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (release.touch(), self.reap(process)))
        self.wait_for(ready.exists, (process,))
        return process, release

    @staticmethod
    def reap(process):
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)

    @staticmethod
    def child_pids(pid):
        # Direct children via /proc (no pgrep dependency).
        kids = []
        taskdir = Path("/proc") / str(pid) / "task"
        if not taskdir.is_dir():
            return kids
        for tid in taskdir.iterdir():
            try:
                kids += [int(word) for word in (tid / "children").read_text().split()]
            except (FileNotFoundError, ProcessLookupError, ValueError):
                pass
        return kids

    def test_child_exit_75_runs_exactly_once_and_preserves_status(self):
        code = ("import pathlib,sys; p=pathlib.Path(" + repr(str(self.sentinel)) + "); "
                "p.write_text(p.read_text()+'x' if p.exists() else 'x'); sys.exit(75)")
        result = self.run_command(code)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(self.sentinel.read_text(), "x")

    def test_contended_timeout_launches_nothing(self):
        holder, release = self.start_holder()
        result = self.run_command("import pathlib; pathlib.Path(" + repr(str(self.sentinel)) + ").touch()",
                                  timeout=0.1)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse(self.sentinel.exists())
        release.touch()
        self.assertEqual(holder.wait(timeout=5), 0)

    def test_acquisition_timeout_does_not_limit_command_runtime(self):
        started = time.monotonic()
        result = self.run_command("import time; time.sleep(.15)", timeout=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - started, .15)

    def test_waiting_command_starts_after_release_once(self):
        holder, release = self.start_holder()
        code = "import pathlib; pathlib.Path(" + repr(str(self.sentinel)) + ").write_text('once')"
        waiter = subprocess.Popen(self.command(sys.executable, "-c", code, timeout=3),
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: self.reap(waiter))
        time.sleep(.1)
        self.assertFalse(self.sentinel.exists())
        release.touch()
        self.assertEqual(holder.wait(timeout=5), 0)
        self.assertEqual(waiter.wait(timeout=5), 0)
        self.assertEqual(self.sentinel.read_text(), "once")

    def test_different_resource_can_run_while_build_slot_held(self):
        self.start_holder()
        self.assertEqual(self.run_command("pass", resource="other", timeout=0).returncode, 0)

    def test_lock_fd_remains_inherited_if_controller_is_killed(self):
        holder, release = self.start_holder()
        holder.kill()
        holder.wait(timeout=5)
        result = self.run_command("pass", timeout=0)
        self.assertEqual(result.returncode, 75, result.stderr)
        release.touch()
        self.wait_for(lambda: self.run_command("pass", timeout=0).returncode == 0)

    def test_orphaned_grandchild_does_not_hold_lock(self):
        # An orphaned fork-child (no exec — the stray-probe S
        # shape that wedged three builds) must never inherit
        # the lock fd: after the wrapped command exits, a
        # contender must acquire immediately even though the
        # grandchild still sleeps.
        pidfile = self.base / "grandchild.pid"
        code = ("import os,sys,time,pathlib; pid=os.fork(); "
                "sys.exit(0) if pid else (os.close(0), os.close(1), os.close(2), "
                "pathlib.Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid())), time.sleep(30))")
        result = self.run_command(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        grandchild = int(pidfile.read_text())
        self.addCleanup(lambda: self._kill_grandchild(grandchild))
        # Grandchild alive (or at least recently so) AND the
        # lock free: the contender must launch.
        contender = self.run_command("pass", timeout=0)
        self.assertEqual(contender.returncode, 0, contender.stderr)

    def test_closed_stdio_launch_succeeds(self):
        # L136 launch half: a wrapper launched with stdio closed
        # must still run its command (CPython reopens /dev/null at
        # startup, so this pins launch-robustness, not fd
        # placement — placement is pinned in-process below).
        proc = subprocess.Popen(
            self.command(sys.executable, "-c", "pass"),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=lambda: [os.close(fd) for fd in (0, 1, 2)],
        )
        self.assertEqual(proc.wait(timeout=10), 0)

    def test_lock_fd_stays_above_stdio(self):
        # L136 placement half (in-process RED): with stdio closed
        # AFTER interpreter startup (the shape a non-reopening
        # python, or an in-process caller, would present), the
        # lock must still land above fd 2 — else close_fds
        # preserves it into the command as a standard stream and
        # an orphan keeping stdio wedges later builds.
        sys.path.insert(0, str(ROOT / "tools"))
        self.addCleanup(sys.path.remove, str(ROOT / "tools"))
        import build_lock
        import threading
        saved = [os.dup(fd) for fd in (0, 1, 2)]
        try:
            for fd in (0, 1, 2):
                os.close(fd)
            pidfile = self.base / "placement-grandchild.pid"
            code = ("import os,sys,time,pathlib; pid=os.fork(); "
                    "sys.exit(0) if pid else (pathlib.Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid())), time.sleep(30))")
            argv = ["--lock-root", str(self.lock_root), "--resource", "build",
                   "--", sys.executable, "-c", code]
            box = {}
            worker = threading.Thread(target=lambda: box.setdefault("rc", build_lock.main(argv)),
                                      daemon=True)
            worker.start()
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive(), "in-process wrapper must exit")
            self.assertEqual(box["rc"], 0)
        finally:
            for fd, saved_fd in zip((0, 1, 2), saved):
                try:
                    os.dup2(saved_fd, fd)
                finally:
                    os.close(saved_fd)
        grandchild = int(pidfile.read_text())
        self.addCleanup(lambda: self._kill_grandchild(grandchild))
        contender = self.run_command("pass", timeout=0)
        self.assertEqual(contender.returncode, 0, contender.stderr)

    @staticmethod
    def _kill_grandchild(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except PermissionError:
            return
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        except InterruptedError:
            pass

    def test_supervisor_ignores_sigint_and_holds_lease(self):
        # L135: SIGINT to the supervisor alone must not release the
        # slot (the command keeps running; the lease holds until it
        # exits). INT is ignored, never forwarded (the sleeper dies
        # on INT by default — its survival proves no forward).
        holder, release = self.start_holder()
        supervisors = self.child_pids(holder.pid)
        self.assertEqual(len(supervisors), 1)
        os.kill(supervisors[0], signal.SIGINT)
        time.sleep(.5)
        self.assertIsNone(holder.poll(), "wrapper must survive supervisor-INT")
        self.assertEqual(self.child_pids(holder.pid), supervisors,
                         "supervisor must survive its own INT")
        result = self.run_command("pass", timeout=0)
        self.assertEqual(result.returncode, 75, result.stderr)
        release.touch()
        self.assertEqual(holder.wait(timeout=5), 0)

    def test_supervisor_forwards_sigterm_and_holds_lease(self):
        # L135: SIGTERM to the supervisor must reach the command
        # (proven by the command's handler marker) while the lease
        # stays held until the command actually exits.
        got_term = self.base / "got-term"
        release = self.base / "release-term"
        code = ("import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, lambda s,f: pathlib.Path(" + repr(str(got_term)) + ").touch()); "
                "print('ready', flush=True); "
                "exec(\"while not pathlib.Path(" + repr(str(release)) + ").exists(): time.sleep(.01)\")")
        proc = subprocess.Popen(self.command(sys.executable, "-c", code),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: self.reap(proc))
        self.assertEqual(proc.stdout.readline().strip(), "ready")
        supervisors = self.child_pids(proc.pid)
        self.assertEqual(len(supervisors), 1)
        kids = self.child_pids(supervisors[0])
        self.assertEqual(len(kids), 1)
        self.addCleanup(release.touch)
        self.addCleanup(lambda: self._kill_grandchild(kids[0]))
        os.kill(supervisors[0], signal.SIGTERM)
        self.wait_for(got_term.exists)
        time.sleep(.2)
        self.assertIsNone(proc.poll(), "wrapper must survive supervisor-TERM")
        self.assertEqual(self.child_pids(proc.pid), supervisors,
                         "supervisor must wait out its command")
        result = self.run_command("pass", timeout=0)
        self.assertEqual(result.returncode, 75, result.stderr)
        # The command still runs (it trapped TERM): kill it, then
        # the supervisor must exit and free the slot.
        os.kill(kids[0], signal.SIGKILL)
        self.assertEqual(proc.wait(timeout=5), 137)
        self.wait_for(lambda: self.run_command("pass", timeout=0).returncode == 0)

    def test_supervisor_term_during_spawn_is_forwarded(self):
        # L137: a TERM landing while the supervisor spawns must
        # reach the command (stashed across Popen, drained after)
        # — never discarded by an ignore window. The scenario runs
        # in a FORKED CHILD (L141): all signal risk stays in the
        # child — the parent never touches dispositions, so even a
        # pathologically late kill can only fail this test loud
        # (child dead by signal), never terminate the suite. The
        # kill itself is gated on Popen ENTRY (L139): the mocked
        # Popen sets an event on entry and the killer fires at
        # entry+0.5s (inside the slowed 2s spawn) — install
        # strictly precedes Popen precedes the kill under any
        # scheduling. Delivery (not handling) is the contract: the
        # stashed TERM must TAKE EFFECT — the command dies by it
        # at birth (trap not installed yet — the usual outcome) or
        # traps it (marker). Vanishing (rc 0 + no marker) is the
        # L137 bug.
        import threading
        from unittest import mock
        got_term = self.base / "got-spawn-term"
        code = ("import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, lambda s,f: pathlib.Path(" + repr(str(got_term)) + ").touch()); "
                "time.sleep(3)")
        argv = ["--supervise-internal", "--lock-root", str(self.lock_root),
               "--resource", "build", "--", sys.executable, "-c", code]
        report_r, report_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            # Child: single-threaded here (no test threads exist
            # yet), so imports/threads below are fork-safe. NEVER
            # returns — reports through the pipe, then _exits (no
            # cleanup handlers — parent state is untouched).
            try:
                os.close(report_r)
                sys.path.insert(0, str(ROOT / "tools"))
                import build_lock
                real_popen = build_lock.subprocess.Popen
                entered = threading.Event()

                def slow_gated_popen(*args, **kwargs):
                    entered.set()
                    time.sleep(2)
                    return real_popen(*args, **kwargs)

                def kill_after_entry():
                    if entered.wait(timeout=10):
                        time.sleep(0.5)
                        os.kill(os.getpid(), signal.SIGTERM)

                saved = {sig: signal.getsignal(sig)
                         for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
                killer = threading.Thread(target=kill_after_entry, daemon=True)
                try:
                    with mock.patch.object(build_lock.subprocess, "Popen",
                                           side_effect=slow_gated_popen):
                        killer.start()
                        rc = build_lock.main(argv)
                finally:
                    for sig, disp in saved.items():
                        signal.signal(sig, disp)
                    killer.join(timeout=5)
                os.write(report_w, ("rc=%d marker=%d" % (rc, got_term.exists())).encode())
            except BaseException as error:
                os.write(report_w, ("error=%r" % (error,)).encode())
            finally:
                os.close(report_w)
            os._exit(0)
        # Parent: no signals, no dispositions — just collect.
        os.close(report_w)
        outcome, status, end = b"", None, time.monotonic() + 25
        while time.monotonic() < end:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done == pid:
                break
            time.sleep(0.05)
        else:
            # L142: the helper already reaps (a second waitpid
            # raises ChildProcessError and masks this timeout).
            self._kill_grandchild(pid)
            self.fail("scenario child stuck past 25s (killed)")
        while True:
            chunk = os.read(report_r, 256)
            if not chunk:
                break
            outcome += chunk
        os.close(report_r)
        self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                        "scenario child must exit 0, never die by signal "
                        "(contained, status %r)" % (status,))
        text = outcome.decode()
        self.assertTrue(text.startswith("rc="), "child error: %s" % text)
        fields = dict(part.split("=") for part in text.split())
        delivered = fields.get("rc") == "143" or fields.get("marker") == "1"
        self.assertTrue(delivered,
                        "TERM during spawn must take effect (death or trap), "
                        "never vanish (%s)" % text)

    def test_signal_status_is_preserved(self):
        result = self.run_command("import os,signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual(result.returncode, 143, result.stderr)

    def test_private_lock_root_and_file(self):
        self.assertEqual(self.run_command("pass").returncode, 0)
        self.assertEqual(stat.S_IMODE(self.lock_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.lock_root / "build.lock").stat().st_mode), 0o600)

    def test_default_lock_is_host_wide_across_working_directories(self):
        runtime = self.base / "runtime"
        runtime.mkdir(mode=0o700)
        env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime))
        ready = self.base / "default ready"
        release = self.base / "default release"
        code = ("import pathlib,time; pathlib.Path(" + repr(str(ready)) + ").touch(); "
                "\nwhile not pathlib.Path(" + repr(str(release)) + ").exists(): time.sleep(.01)")
        holder = subprocess.Popen(self.command(sys.executable, "-c", code, default=True), env=env,
                                  cwd=self.base, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (release.touch(), self.reap(holder)))
        self.wait_for(ready.exists, (holder,))
        other_cwd = self.base / "another checkout"
        other_cwd.mkdir()
        result = subprocess.run(self.command(sys.executable, "-c", "pass", default=True, timeout=0),
                                cwd=other_cwd, env=env, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertTrue((runtime / "scopebase-locks/build.lock").is_file())

    def test_root_and_lock_symlinks_refuse_without_launch(self):
        target = self.base / "target"
        target.mkdir()
        self.lock_root.symlink_to(target, target_is_directory=True)
        code = "import pathlib; pathlib.Path(" + repr(str(self.sentinel)) + ").touch()"
        self.assertEqual(self.run_command(code).returncode, 64)
        self.assertFalse(self.sentinel.exists())
        self.lock_root.unlink()
        self.lock_root.mkdir(mode=0o700)
        (self.lock_root / "build.lock").symlink_to(self.base / "untouched")
        self.assertEqual(self.run_command(code).returncode, 64)
        self.assertFalse(self.sentinel.exists())
        self.assertFalse((self.base / "untouched").exists())

    def test_invalid_arguments_are_usage_64(self):
        for options in (("--lock-root", "relative"), ("--resource", "../escape"),
                        ("--timeout", "-1"), ("--timeout", "nan"),
                        ("--timeout", "inf"), ("--unknown",), ()):
            with self.subTest(options=options):
                result = subprocess.run(["bash", str(WRAPPER), *options], capture_output=True)
                self.assertEqual(result.returncode, 64)


if __name__ == "__main__":
    unittest.main()
