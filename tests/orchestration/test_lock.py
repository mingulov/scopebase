"""Lock acceptance uses real Linux flock and real child processes."""

import os
from pathlib import Path
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
