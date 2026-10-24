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

    # S27-round3: a same-filesystem bind mounted AFTER the mount
    # snapshot shares the device and is absent from the set — the
    # descriptor-bound mount-ID check still refuses traversal, and
    # neither the source contents nor the shadowed files are
    # deleted through the bind.
    def test_real_bind_after_snapshot_refuses_traversal(self):
        tree = os.path.join(self.tmp, "tree")
        sub = os.path.join(tree, "sub")
        os.makedirs(sub, mode=0o700)
        os.chmod(tree, 0o700)
        os.chmod(sub, 0o700)
        shadowed = os.path.join(sub, "shadowed.txt")
        with open(shadowed, "wb") as handle:
            handle.write(b"shadowed\n")
        src = os.path.join(self.tmp, "src")
        os.makedirs(src, mode=0o700)
        marker = os.path.join(src, "marker.txt")
        with open(marker, "wb") as handle:
            handle.write(b"marker\n")
        # Same-filesystem premise: one shared device, so only the
        # mount ID distinguishes the bind.
        self.assertEqual(os.stat(src).st_dev, os.stat(tree).st_dev)
        # Snapshot FIRST, while no bind exists.
        snapshot = provision.mount_targets_under(tree)
        self.assertEqual(snapshot, frozenset())
        mounted = False
        try:
            proc = sudo("mount", "--bind", src, sub)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            root_fd = os.open(tree, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                        OSError, "mount boundary"):
                    provision.fd_clear_dir(root_fd, "", snapshot)
            finally:
                os.close(root_fd)
        finally:
            if mounted:
                bye = sudo("umount", sub)
                self.assertEqual(bye.returncode, 0, bye.stderr)
        with open(marker, "rb") as handle:
            self.assertEqual(handle.read(), b"marker\n")
        with open(shadowed, "rb") as handle:
            self.assertEqual(handle.read(), b"shadowed\n")

    # S17-round3 live: the real privileged retire-mount helper
    # detaches a real bind — the held-FD correspondence and
    # whole-table post-proof must not refuse the genuine happy
    # path (manifest-style record with the live mount ID).
    def test_live_retire_mount_via_helper(self):
        run = os.path.join(self.tmp, "run")
        point = os.path.join(run, "mnt")
        src = os.path.join(self.tmp, "src")
        os.makedirs(point, mode=0o700)
        os.makedirs(src, mode=0o700)
        os.chmod(run, 0o700)
        marker = os.path.join(src, "marker.txt")
        with open(marker, "wb") as handle:
            handle.write(b"marker\n")
        mounted = False
        try:
            proc = sudo("mount", "--bind", src, point)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, point)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertTrue(os.path.exists(
                os.path.join(point, "marker.txt")))
            proc = sudo(sys.executable, provision.__file__,
                        "retire-mount",
                        "--run-root", run, "--target", point,
                        "--fstype", row["fstype"],
                        "--source", row["source"],
                        "--mnt-id", str(row["mnt_id"]),
                        "--mount-root", row["root"])
            self.assertEqual(proc.returncode, 0,
                             proc.stdout + proc.stderr)
            self.assertIn("retired-mount", proc.stdout)
            mounted = False
            table = provision.read_mount_table()
            self.assertEqual(
                provision.find_mounts(table, point), [])
            self.assertFalse(os.path.exists(
                os.path.join(point, "marker.txt")))
        finally:
            if mounted:
                bye = sudo("umount", point)
                self.assertEqual(bye.returncode, 0, bye.stderr)

    # S17-round3 live: the real privileged retire-loop helper
    # detaches a real loop attach — the same-fd GET/CLR/GET
    # must clear the validated association. A wrong backing
    # identity first proves the refusal leaves the live
    # association untouched.
    def test_live_retire_loop_via_helper(self):
        run = os.path.join(self.tmp, "run")
        os.makedirs(run, mode=0o700)
        os.chmod(run, 0o700)
        image = os.path.join(run, "loop.img")
        with open(image, "wb") as handle:
            handle.truncate(8 << 20)
        st = os.stat(image)
        proc = sudo("losetup", "--find", "--show", image)
        if proc.returncode != 0:
            self.skipTest(f"losetup unavailable: {proc.stderr}")
        loop = proc.stdout.strip().split()[0]
        self.assertTrue(loop.startswith("/dev/loop"), loop)
        try:
            # Wrong identity: refuse without effect.
            bad = sudo(sys.executable, provision.__file__,
                       "retire-loop",
                       "--run-root", run, "--loop", loop,
                       "--backing-path", image,
                       "--backing-dev", str(st.st_dev),
                       "--backing-ino", str(st.st_ino + 1))
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("refusing", bad.stdout + bad.stderr)
            live = sudo("losetup", "-j", image)
            self.assertEqual(live.returncode, 0, live.stderr)
            self.assertIn(loop, live.stdout)
            # True identity: detach.
            good = sudo(sys.executable, provision.__file__,
                        "retire-loop",
                        "--run-root", run, "--loop", loop,
                        "--backing-path", image,
                        "--backing-dev", str(st.st_dev),
                        "--backing-ino", str(st.st_ino))
            self.assertEqual(good.returncode, 0,
                             good.stdout + good.stderr)
            self.assertIn("retired-loop", good.stdout)
            gone = sudo("losetup", "-j", image)
            self.assertNotIn(loop, gone.stdout)
        finally:
            sudo("losetup", "-d", loop)

    def _helper_ids(self, path):
        st = os.stat(path)
        return (str(st.st_dev), str(st.st_ino))

    def _run_root_argv(self, run):
        dev, ino = self._helper_ids(run)
        return ["--run-root", run, "--root-dev", dev,
                "--root-ino", ino]

    @staticmethod
    @staticmethod
    def _parse_mounted_line(line, target):
        # S77-round4: delegate to the product parser, so escaped
        # (LF-bearing) reports decode exactly like production.
        parsed = provision._parse_mounted_line(line, target)
        assert parsed is not None, (line, target)
        return parsed

    # S15-round3 live: attach-loop binds a real loop to the
    # verified image natively — losetup sees the association,
    # and retire-loop discharges it.
    def test_live_attach_loop_via_helper(self):
        run = os.path.join(self.tmp, "run")
        os.makedirs(run, mode=0o700)
        os.chmod(run, 0o700)
        image = os.path.join(run, "loop.img")
        with open(image, "wb") as handle:
            handle.truncate(8 << 20)
        dev, ino = self._helper_ids(image)
        proc = sudo(sys.executable, provision.__file__,
                    "attach-loop", *self._run_root_argv(run),
                    "--image", image, "--dev", dev, "--ino", ino)
        if proc.returncode != 0 and (
                "loop-control" in proc.stdout
                or "free loop" in proc.stdout):
            self.skipTest(f"loop unavailable: {proc.stdout}")
        self.assertEqual(proc.returncode, 0,
                         proc.stdout + proc.stderr)
        self.assertTrue(
            proc.stdout.startswith("attached-loop /dev/loop"),
            proc.stdout)
        loop = proc.stdout.split()[1]
        try:
            live = sudo("losetup", "-j", image)
            self.assertEqual(live.returncode, 0, live.stderr)
            self.assertIn(loop, live.stdout)
            bye = sudo(sys.executable, provision.__file__,
                       "retire-loop",
                       "--run-root", run, "--loop", loop,
                       "--backing-path", image,
                       "--backing-dev", dev,
                       "--backing-ino", ino)
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            self.assertIn("retired-loop", bye.stdout)
        finally:
            sudo("losetup", "-d", loop)

    # S15-round3 live: the full verified ext4 chain — make-ext4
    # formats via /dev/fd, attach-loop binds natively, mount-fs
    # mounts on held fds and owns the fresh root (the
    # unprivileged probe write proves the folded chown).
    def test_live_mount_ext4_chain(self):
        run = os.path.join(self.tmp, "run")
        point = os.path.join(run, "mnt")
        os.makedirs(point, mode=0o700)
        os.chmod(run, 0o700)
        image = os.path.join(run, "fs01.img")
        with open(image, "wb") as handle:
            handle.truncate(64 << 20)
        idev, iino = self._helper_ids(image)
        made = sudo(sys.executable, provision.__file__,
                    "make-ext4", *self._run_root_argv(run),
                    "--image", image, "--dev", idev, "--ino",
                    iino)
        self.assertEqual(made.returncode, 0,
                         made.stdout + made.stderr)
        self.assertIn("made-ext4", made.stdout)
        with open(image, "rb") as handle:
            handle.seek(0x438)
            self.assertEqual(handle.read(2), b"\x53\xef")
        bound = sudo(sys.executable, provision.__file__,
                     "attach-loop", *self._run_root_argv(run),
                     "--image", image, "--dev", idev, "--ino",
                     iino)
        if bound.returncode != 0 and (
                "loop-control" in bound.stdout
                or "free loop" in bound.stdout):
            self.skipTest(f"loop unavailable: {bound.stdout}")
        self.assertEqual(bound.returncode, 0,
                         bound.stdout + bound.stderr)
        loop = bound.stdout.split()[1]
        mounted = False
        try:
            tdev, tino = self._helper_ids(point)
            mnt = sudo(sys.executable, provision.__file__,
                       "mount-fs", *self._run_root_argv(run),
                       "--target", point,
                       "--target-dev", tdev, "--target-ino", tino,
                       "--fstype", "ext4", "--loop", loop,
                       "--backing-dev", idev, "--backing-ino",
                       iino, "--own-uid", str(os.geteuid()),
                       "--own-gid", str(os.getegid()))
            self.assertEqual(mnt.returncode, 0,
                             mnt.stdout + mnt.stderr)
            line = mnt.stdout.splitlines()[0]
            mnt_id, source, super_opts = self._parse_mounted_line(
                line, point)
            self.assertIn("rw", super_opts)
            # The kernel echoes the fd-bound source literally.
            self.assertTrue(source.startswith("/dev/fd/"), source)
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, point)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], mnt_id)
            self.assertEqual(rows[0]["fstype"], "ext4")
            self.assertEqual(rows[0]["source"], source)
            # Folded ownership: our own write lands.
            probe = os.path.join(point, "probe.txt")
            with open(probe, "w") as handle:
                handle.write("hello\n")
            self.assertEqual(os.stat(point).st_uid, os.geteuid())
            row = rows[0]
            bye = sudo(sys.executable, provision.__file__,
                       "retire-mount",
                       "--run-root", run, "--target", point,
                       "--fstype", row["fstype"],
                       "--source", row["source"],
                       "--mnt-id", str(row["mnt_id"]),
                       "--mount-root", row["root"])
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            self.assertIn("retired-mount", bye.stdout)
            mounted = False
            free = sudo(sys.executable, provision.__file__,
                        "retire-loop",
                        "--run-root", run, "--loop", loop,
                        "--backing-path", image,
                        "--backing-dev", idev,
                        "--backing-ino", iino)
            self.assertEqual(free.returncode, 0,
                             free.stdout + free.stderr)
        finally:
            if mounted:
                sudo("umount", point)
            sudo("losetup", "-d", loop)

    # S15-round3 live: mount-fs assembles a real overlay stack
    # from verified layers — the kernel records the /dev/fd
    # layer spellings, the merged view serves lower content,
    # and an upper write lands in our upper.
    def test_live_mount_overlay(self):
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        with open(os.path.join(role, "lower", "shared.txt"),
                  "w") as handle:
            handle.write("lower-original\n")
        target = os.path.join(role, "merged")
        # S81-round4: plant the binding canary the helper
        # requires for overlay post-mount binding.
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--canary", canary]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]
        mounted = False
        try:
            mnt = sudo(*argv)
            self.assertEqual(mnt.returncode, 0,
                             mnt.stdout + mnt.stderr)
            line = mnt.stdout.splitlines()[0]
            mnt_id, source, super_opts = self._parse_mounted_line(
                line, target)
            self.assertEqual(source, "overlay")
            self.assertIn("lowerdir=/dev/fd/", super_opts)
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], mnt_id)
            self.assertEqual(rows[0]["fstype"], "overlay")
            with open(os.path.join(target, "shared.txt")) as fh:
                self.assertEqual(fh.read(), "lower-original\n")
            with open(os.path.join(target, "upper-only.txt"),
                      "w") as handle:
                handle.write("upper-only\n")
            with open(os.path.join(role, "upper",
                                   "upper-only.txt")) as fh:
                self.assertEqual(fh.read(), "upper-only\n")
            row = rows[0]
            bye = sudo(sys.executable, provision.__file__,
                       "retire-mount",
                       "--run-root", run, "--target", target,
                       "--fstype", row["fstype"],
                       "--source", row["source"],
                       "--mnt-id", str(row["mnt_id"]),
                       "--mount-root", row["root"])
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            mounted = False
        finally:
            if mounted:
                sudo("umount", target)

    # S81-round4 live: a privileged replacement mounted inside
    # the helper's post-mount window is refused at the canary
    # gate before any chown. The foreign overlay carries a
    # plausible row (fstype/source both match, so only the
    # binding can refuse), serves wrong canary content, and is
    # left in place with its root ownership untouched although
    # --own-uid/gid was given. The delay hook opens the window
    # deterministically via `sudo env` (production run_sudo
    # passes no such variable).
    def test_live_mount_replacement_refuses_before_chown(self):
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        # Foreign stack: plausible overlay, wrong canary, and
        # root-owned upper so a folded chown would be visible.
        fx = os.path.join(run, "fx")
        for sub in ("flower", "fupper", "fwork"):
            os.makedirs(os.path.join(fx, sub), mode=0o700)
        with open(os.path.join(
                fx, "fupper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write("foreign-canary")
        fupper = os.path.join(fx, "fupper")
        own = sudo("chown", "0:0", fupper)
        self.assertEqual(own.returncode, 0, own.stderr)
        target = os.path.join(role, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--canary", canary,
               "--own-uid", str(os.geteuid()),
               "--own-gid", str(os.getegid())]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]

        def live_row():
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            if len(rows) == 1:
                return rows[0]
            return None

        def poll_row(timeout, different_super_from=None):
            # The kernel recycles mount IDs on umount, so the
            # replacement is told apart by its super options
            # (foreign upper path), never by mnt_id.
            deadline = time.time() + timeout
            while time.time() < deadline:
                row = live_row()
                if row is not None and (
                        different_super_from is None
                        or row["super"] != different_super_from):
                    return row
                time.sleep(0.2)
            return None

        helper = subprocess.Popen(
            ["sudo", "-n", "env",
             "S81_HELPER_POST_MOUNT_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_row(60)
            self.assertIsNotNone(
                first, "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the replacement "
                "window opened (delay hook inert?)")
            # Plant the privileged replacement inside the
            # helper's post-mount window.
            bye = sudo("umount", target)
            self.assertEqual(bye.returncode, 0, bye.stderr)
            opts = ("lowerdir=%s,upperdir=%s,workdir=%s"
                    % (os.path.join(fx, "flower"), fupper,
                       os.path.join(fx, "fwork")))
            plant = sudo("mount", "-t", "overlay", "overlay",
                         "-o", opts, target)
            self.assertEqual(plant.returncode, 0,
                             plant.stderr)
            second = poll_row(30,
                              different_super_from=first["super"])
            self.assertIsNotNone(
                second, "replacement mount never appeared")
            # Only the canary binding can refuse this row.
            self.assertEqual(second["fstype"], "overlay")
            self.assertEqual(second["source"], "overlay")
            # The root-owned merged view needs privilege
            # to read through.
            seen = sudo("cat", os.path.join(
                target, provision.MOUNT_CANARY_NAME))
            self.assertEqual(seen.returncode, 0,
                             seen.stderr)
            self.assertEqual(seen.stdout, "foreign-canary")
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            self.assertIn("canary mismatch", out)
            # No chown touched the stranger: root-owned upper
            # unchanged, occupant left in place.
            fst = os.stat(fupper)
            self.assertEqual((fst.st_uid, fst.st_gid),
                             (0, 0))
            self.assertEqual(live_row()["super"],
                             second["super"])
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", target)
            # Restore ownership so plain cleanup can rmtree.
            sudo("chown", "-R",
                 "%d:%d" % (os.geteuid(), os.getegid()), fx)

    # S74-round4 live: a target renamed around the effect is
    # reported as moved (mount ID + observed mountpoint),
    # never as a false "missing" failure. A live mountpoint
    # itself is EBUSY, so the rename moves the role directory
    # (parent) inside the post-mount delay window; the mount
    # follows to the new path. The handler cannot tell this
    # from the finding's pre-mount rename (both present as a
    # diff-added row at a non-verified name), so this
    # exercises the moved path on a real kernel move with no
    # extra hook. The ID in the report matches the live row.
    def test_live_mount_moved_target_reports_recovery_id(self):
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        target = os.path.join(role, "merged")
        role2 = os.path.join(run, "ov2")
        moved = os.path.join(role2, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--canary", canary]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]

        def live_rows_at(path):
            table = provision.read_mount_table()
            return provision.find_mounts(table, path)

        def poll_rows_at(path, timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                rows = live_rows_at(path)
                if rows:
                    return rows
                time.sleep(0.2)
            return []

        helper = subprocess.Popen(
            ["sudo", "-n", "env",
             "S81_HELPER_POST_MOUNT_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_rows_at(target, 60)
            self.assertEqual(len(first), 1,
                             "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the move window "
                "opened (delay hook inert?)")
            # Rename the role directory inside the helper's
            # post-mount window; the mount follows to the new
            # path (renaming the live mountpoint itself is
            # EBUSY, so the finding's window is pre-mount —
            # the handler sees the same diff either way).
            os.rename(role, role2)
            second = poll_rows_at(moved, 30)
            self.assertEqual(len(second), 1,
                             "moved mount never appeared")
            self.assertEqual(live_rows_at(target), [])
            with open(os.path.join(
                    moved, provision.MOUNT_CANARY_NAME)) as handle:
                self.assertEqual(handle.read(), canary)
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            self.assertIn("FAILED-MOVED", out)
            parsed = provision._parse_moved_report(out)
            self.assertIsNotNone(parsed, out)
            mnt_id, observed = parsed
            self.assertEqual(observed, moved)
            self.assertEqual(mnt_id, second[0]["mnt_id"])
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", moved)
            sudo("umount", target)

    # S75-round4 live: a real mixed-ownership caller-to-root
    # cleanup. The unprivileged pass meets the root-owned
    # workdir and escalates; the sudo'd remover — running as
    # root with SUDO_UID naming the controller — accepts the
    # controller's exclusive directories instead of rejecting
    # the normal user's tree, and retires everything.
    def test_live_cleanup_mixed_ownership_via_sudo(self):
        import json as _json
        import types as _types
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        run = os.path.join(self.tmp, "run")
        os.makedirs(os.path.join(run, "data"), mode=0o700)
        os.makedirs(os.path.join(run, "work"), mode=0o700)
        os.chmod(run, 0o700)
        with open(os.path.join(run, "data",
                               "note.txt"), "w") as handle:
            handle.write("controller data\n")
        # A root-owned workdir, as an overlay mount would
        # leave it: defeats the unprivileged pass.
        mk = sudo("chown", "0:0", os.path.join(run, "work"))
        self.assertEqual(mk.returncode, 0, mk.stderr)
        st = os.stat(run)
        manifest = os.path.join(self.tmp, "manifest.json")
        doc = provision.fresh_manifest(run, False)
        doc["run_root_identity"] = {"dev": st.st_dev,
                                    "ino": st.st_ino}
        with open(manifest, "w") as handle:
            handle.write(_json.dumps(doc))
        args = _types.SimpleNamespace(run_root=run,
                                      manifest=manifest)
        try:
            rc = provision.cleanup_command(args)
        finally:
            # Restore ownership so plain cleanup can rmtree
            # whatever a failure leaves behind.
            sudo("chown", "-R",
                 "%d:%d" % (os.geteuid(), os.getegid()), run)
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(run))

    # S76-round4 live: the same 0775 self-owned parent stays
    # admissible across the controller-to-helper UID transition.
    # The helper runs as root with SUDO_UID naming the
    # controller, so the privileged mount succeeds; pre-fix the
    # helper refused it as foreign-owned. Scrubbing SUDO_UID
    # restores the refusal, pinning the mechanism.
    def test_live_mount_under_shared_parent_cross_uid(self):
        base = os.path.join(self.tmp, "s76-shared")
        os.makedirs(base, mode=0o700)
        os.chmod(base, 0o775)
        run = os.path.join(base, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        with open(os.path.join(role, "lower", "shared.txt"),
                  "w") as handle:
            handle.write("lower-original\n")
        target = os.path.join(role, "merged")
        # S81-round4: plant the binding canary the helper
        # requires for overlay post-mount binding.
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--canary", canary]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]
        # Controller side admits the shared parent first.
        guard = provision.RootAuthority(run)
        try:
            guard.verify()
        finally:
            guard.close()
        # Without the controller identity the helper refuses.
        scrubbed = sudo("env", "-u", "SUDO_UID", *argv)
        self.assertEqual(scrubbed.returncode, 1,
                         scrubbed.stdout + scrubbed.stderr)
        self.assertIn("foreign owner", scrubbed.stdout)
        # With it (plain sudo) the mount succeeds.
        mounted = False
        try:
            mnt = sudo(*argv)
            self.assertEqual(mnt.returncode, 0,
                             mnt.stdout + mnt.stderr)
            line = mnt.stdout.splitlines()[0]
            mnt_id, source, _ = self._parse_mounted_line(
                line, target)
            self.assertEqual(source, "overlay")
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], mnt_id)
            with open(os.path.join(target, "shared.txt")) as fh:
                self.assertEqual(fh.read(), "lower-original\n")
            row = rows[0]
            bye = sudo(sys.executable, provision.__file__,
                       "retire-mount",
                       "--run-root", run, "--target", target,
                       "--fstype", row["fstype"],
                       "--source", row["source"],
                       "--mnt-id", str(row["mnt_id"]),
                       "--mount-root", row["root"])
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            mounted = False
        finally:
            if mounted:
                sudo("umount", target)

    # S77-round4 live: the full helper round trip with an
    # admitted LF target — mount, escaped success report,
    # fingerprint match against the live table, content check,
    # and retirement all carry the real newline.
    def test_live_mount_overlay_lf_target(self):
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "mer\nged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        with open(os.path.join(role, "lower", "shared.txt"),
                  "w") as handle:
            handle.write("lower-original\n")
        target = os.path.join(role, "mer\nged")
        # S81-round4: binding canary (LF name tests escape,
        # the canary itself stays plain).
        canary = "lf-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--canary", canary]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]
        mounted = False
        try:
            mnt = sudo(*argv)
            self.assertEqual(mnt.returncode, 0,
                             mnt.stdout + mnt.stderr)
            self.assertNotIn("\n", mnt.stdout.strip("\n"),
                             "report must stay one frame")
            line = mnt.stdout.splitlines()[0]
            mnt_id, source, super_opts = self._parse_mounted_line(
                line, target)
            self.assertEqual(source, "overlay")
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], mnt_id)
            with open(os.path.join(target, "shared.txt")) as fh:
                self.assertEqual(fh.read(), "lower-original\n")
            row = rows[0]
            bye = sudo(sys.executable, provision.__file__,
                       "retire-mount",
                       "--run-root", run, "--target", target,
                       "--fstype", row["fstype"],
                       "--source", row["source"],
                       "--mnt-id", str(row["mnt_id"]),
                       "--mount-root", row["root"])
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            mounted = False
        finally:
            if mounted:
                sudo("umount", target)


@unittest.skipUnless(live_mounts_enabled(),
                     "TT04_LIVE_MOUNTS=1 and sudo -n required")
class LiveProcTests(unittest.TestCase):
    # S22-round4 live: the full EPERM-to-escalation chain. A
    # root-owned sleep grandchild is pinnable by the
    # controller (descendant) but unsignallable (uid
    # mismatch — the direct pidfd signal provably returns
    # EPERM), so signal_owned escalates through the
    # re-pinning signal-proc helper and the process dies by
    # real effect. (The no-numeric-kill mechanism is pinned
    # unprivileged by
    # test_signal_owned_uses_pidfd_not_numeric, where os.kill
    # is rigged to explode.)
    def test_live_signal_escalates_and_kills_root_proc(self):
        import errno as _errno
        import signal as _signal
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        runner = subprocess.Popen(
            ["sudo", "-n", "sleep", "117"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            victim = self._poll_sudo_child(runner.pid, 10)
            self.assertEqual(
                os.stat(f"/proc/{victim}").st_uid, 0)
            pin = provision.pin_proc(victim)
            try:
                # The escalation trigger is real, not mocked.
                self.assertEqual(
                    provision._pidfd_send_signal(pin, 0),
                    _errno.EPERM)
                _, start = provision.stat_state_start(victim)
                self.assertTrue(provision.signal_owned(
                    victim, _signal.SIGTERM, pin, start))
            finally:
                os.close(pin)
            self.assertTrue(
                self._poll_gone(victim, 10),
                "root sleep survived the escalation")
            runner.wait(timeout=30)
        finally:
            sudo("pkill", "-KILL", "-f", "^sleep 117$")
            if runner.poll() is None:
                sudo("kill", "-KILL", str(runner.pid))
                runner.wait(timeout=30)

    @staticmethod
    def _poll_sudo_child(sudo_pid, timeout):
        deadline = time.time() + timeout
        path = f"/proc/{sudo_pid}/task/{sudo_pid}/children"
        while time.time() < deadline:
            try:
                with open(path) as handle:
                    kids = handle.read().split()
            except OSError:
                kids = []
            if kids:
                return int(kids[0])
            time.sleep(0.1)
        raise AssertionError("sudo child never appeared")

    @staticmethod
    def _poll_gone(pid, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not os.path.exists(f"/proc/{pid}"):
                return True
            time.sleep(0.1)
        return False


if __name__ == "__main__":
    unittest.main()
