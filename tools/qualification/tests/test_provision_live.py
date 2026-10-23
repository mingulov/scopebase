"""Live privileged mount tests for provision_fs (TT04_LIVE_MOUNTS=1).

These tests bind, observe, and unmount REAL filesystem objects
with sudo: they prove the owned-bind gate against genuine
mountinfo semantics (filesystem source, subtree root, covered
object identity) and prove the churn driver bind/restore cycle
and the traversal mount guard against a live mount. Everything
is strictly cleaned up (umount, driver quit/kill, rmtree) in
finally blocks; each test skips unless TT04_LIVE_MOUNTS=1 and
passwordless sudo mount/umount works.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import provision_fs as provision  # noqa: E402


def live_mounts_enabled():
    if os.environ.get("TT04_LIVE_MOUNTS") != "1":
        return False
    try:
        proc = subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, timeout=30)
    except OSError:
        return False
    return proc.returncode == 0


def sudo(*argv, timeout=60):
    return subprocess.run(["sudo", "-n", *argv], capture_output=True,
                          text=True, timeout=timeout)


@unittest.skipUnless(live_mounts_enabled(),
                     "TT04_LIVE_MOUNTS=1 and sudo -n required")
class LiveBindTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="provision-live-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_real_bind_owned_gate(self):
        churn = os.path.join(self.tmp, "churn")
        os.makedirs(churn)
        payload = os.path.join(churn, "payload-b")
        point = os.path.join(churn, "point")
        with open(payload, "wb") as handle:
            handle.write(b"live-payload\n")
        with open(point, "wb") as handle:
            handle.write(b"live-point\n")
        st = os.stat(payload)
        mounted = False
        try:
            proc = sudo("mount", "--bind", payload, point)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, point)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            # Genuine bind semantics: the source names the
            # filesystem, never the payload pathname.
            self.assertNotEqual(row["source"],
                                os.path.normpath(payload))
            self.assertTrue(provision.owned_bind_only(
                point, payload, st.st_dev, st.st_ino, table))
            self.assertTrue(provision.target_is_payload(
                point, payload, st.st_dev, st.st_ino))
            proc = sudo("umount", point)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = False
            table = provision.read_mount_table()
            self.assertFalse(provision.find_mounts(table, point))
            self.assertFalse(provision.owned_bind_only(
                point, payload, st.st_dev, st.st_ino, table))
        finally:
            if mounted:
                sudo("umount", point)

    def test_real_driver_bind_restore_cycle(self):
        run_root = os.path.join(self.tmp, "run")
        churn = os.path.join(run_root, "churn")
        os.makedirs(churn)
        payload = os.path.join(churn, "payload-b")
        point = os.path.join(churn, "point")
        with open(payload, "wb") as handle:
            handle.write(b"live-payload\n")
        with open(point, "wb") as handle:
            handle.write(b"live-point\n")
        st = os.stat(payload)
        driver = os.path.join(churn, "driver.py")
        with open(driver, "w") as handle:
            handle.write(provision.CHURN_DRIVER_PY)
        fifo = os.path.join(churn, "cmd.fifo")
        ack = os.path.join(churn, "ack.txt")
        ledger = os.path.join(churn, "ledger.log")
        os.mkfifo(fifo)
        child = subprocess.Popen(
            ["sudo", "-n", sys.executable, driver, run_root,
             fifo, ack, str(st.st_dev), str(st.st_ino)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True)
        try:
            provision.poll_text_contains(ledger, "driver-ready", 20)

            def drive(cmd):
                with open(ack, "w") as handle:
                    handle.write("")
                fd = os.open(fifo, os.O_WRONLY)
                try:
                    os.write(fd, (cmd + "\n").encode())
                finally:
                    os.close(fd)
                text = provision.poll_text_contains(
                    ack, f"{cmd} rc=", 20)
                for line in text.splitlines():
                    if line.startswith(f"{cmd} rc="):
                        return line
                raise AssertionError(f"no ack for {cmd}: {text!r}")

            line = drive("bind-b")
            self.assertIn("bind-b rc=0", line)
            with open(point, "rb") as handle:
                self.assertEqual(handle.read(), b"live-payload\n")
            line = drive("restore")
            self.assertIn("restore rc=0", line)
            with open(point, "rb") as handle:
                self.assertEqual(handle.read(), b"live-point\n")
            table = provision.read_mount_table()
            self.assertFalse(provision.find_mounts(table, point))
            line = drive("quit")
            self.assertIn("quit rc=0", line)
            child.wait(timeout=20)
        finally:
            if child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    pass
                try:
                    child.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            sudo("umount", point)

    def test_real_bind_refuses_aux_cleanup(self):
        try:
            probe = os.path.join("/dev/shm", "tt04-probe")
            os.makedirs(probe, exist_ok=True)
            os.rmdir(probe)
        except OSError:
            self.skipTest("no writable /dev/shm")
        root = tempfile.mkdtemp(prefix="tt04-", dir="/dev/shm")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        canary = os.path.join(root, "canary.txt")
        with open(canary, "wb") as handle:
            handle.write(b"canary\n")
        cover = os.path.join(self.tmp, "cover.txt")
        with open(cover, "wb") as handle:
            handle.write(b"cover\n")
        st = os.stat(root)
        aux = {"path": root, "dev": st.st_dev, "ino": st.st_ino}
        mounted = False
        try:
            proc = sudo("mount", "--bind", cover, canary)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            failure = provision.cleanup_aux_root(aux)
            self.assertIn("refusing traversal", failure)
        finally:
            if mounted:
                sudo("umount", canary)
        with open(canary, "rb") as handle:
            self.assertEqual(handle.read(), b"canary\n")


if __name__ == "__main__":
    unittest.main()
