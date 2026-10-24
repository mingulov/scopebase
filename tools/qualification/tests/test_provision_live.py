"""Live privileged mount tests for provision_fs (TT04_LIVE_MOUNTS=1).

These tests bind, observe, and unmount REAL filesystem objects
with sudo: they prove the owned-bind gate against genuine
mountinfo semantics (filesystem source, subtree root, covered
object identity) and prove the churn driver bind/restore cycle
and the traversal mount guard against a live mount. Everything
is strictly cleaned up (umount, driver quit/kill, rmtree) in
finally blocks; each test skips unless TT04_LIVE_MOUNTS=1 and
passwordless sudo mount/umount works.

S17-round5: every mount effect and every observation through a
live mount runs inside the keeper mount namespace (rprivate):
the kernel rejects MS_MOVE under shared ancestors, so the
reversible move-verify-detach retirement only works on a
private chain, and confinement keeps the host table clean.
LiveBindTests.setUp ensures the ns; sudo() then enters it for
every call (mount-indifferent commands — losetup, chown,
kill — behave identically inside), and reads/writes through
a live mount go through the ns_* helpers. Direct reads stay
only where no mount is live at that path at that moment.
"""

import json
import os
import pwd
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
        probes = [
            ["sudo", "-n", "true"],
            # S17-round5: confinement needs the namespace
            # tools through the same sudo path that uses
            # them (they may be absent from the user PATH
            # while present in sudo's secure_path).
            ["sudo", "-n", "unshare", "--version"],
            ["sudo", "-n", "nsenter", "--version"],
        ]
        for argv in probes:
            proc = subprocess.run(
                argv, capture_output=True, timeout=30)
            if proc.returncode != 0:
                return False
    except OSError:
        return False
    return True


def sudo(*argv, timeout=60, input=None):
    # S17-round5: once LiveBindTests.setUp ensures the keeper
    # ns, every sudo call enters it — mounts land on the
    # private chain move-verify-detach needs, and reads see
    # the mounts under test. Mount-indifferent commands
    # (losetup/chown/kill) behave identically inside (global
    # devices, same filesystem, same pid namespace).
    ns = provision._ns_active()
    prefix = (["sudo", "-n", "nsenter", f"--mount={ns}"]
              if ns is not None else ["sudo", "-n"])
    return subprocess.run(prefix + list(argv), capture_output=True,
                          text=True, timeout=timeout, input=input)


def live_ns():
    """The ensured keeper ns path, or a loud failure."""
    ns = provision._ns_active()
    if ns is None:
        raise AssertionError(
            "live mount ns not ensured (setUp must ensure)")
    return ns


def ns_text(path):
    """Read text THROUGH a live mount (inside the ns)."""
    seen = sudo("cat", path)
    if seen.returncode != 0:
        raise AssertionError(
            f"ns read of {path} failed: {seen.stderr}")
    return seen.stdout


def ns_exists(path):
    """Existence THROUGH a live mount (inside the ns)."""
    return sudo("test", "-e", path).returncode == 0


def ns_write_user(path, data):
    """Write text THROUGH a live mount as the calling user.

    S17-round5: runuser (same util-linux package as the
    nsenter this suite already requires) drops back to the
    controller identity inside the ns, so folded-ownership
    proofs keep their unprivileged writer.
    """
    user = pwd.getpwuid(os.geteuid()).pw_name
    done = sudo("runuser", "-u", user, "--", "tee", path,
                input=data)
    if done.returncode != 0 or done.stdout != data:
        raise AssertionError(
            f"ns user-write to {path} failed: "
            f"rc={done.returncode} err={done.stderr!r}")


def mount_live_at(target):
    """Live-table rows at target (in-ns once ensured)."""
    return provision.find_mounts(
        provision.read_mount_table(), target)


def retire_verified_mount(target, verified_mnt_id):
    """Best-effort umount of verified identity at target.

    S93-round5: a privileged test retires its mount on every
    post-effect failure — but only verified identity. Whatever
    is live at the test's own target must be the mount it
    verified (or nothing was verified yet — then whatever the
    helper left there). A foreign replacement is left alone,
    loudly visible, instead of unmounted. An unreadable table
    still attempts the umount (best effort: umount of a
    non-mount fails harmlessly). Returns True when the umount
    was attempted.
    """
    try:
        live = mount_live_at(target)
    except Exception:
        live = None
    if live is None or (live and (
            verified_mnt_id is None or
            live[0]["mnt_id"] == verified_mnt_id)):
        sudo("umount", target)
        return True
    return False


def signal_verified_proc(victim, signum):
    """Re-pin, re-verify, and signal one owned proc. (S92)

    Fresh pidfd pin plus fresh starttime, then the
    identity-verified signal_owned path (pidfd-bound signal,
    privileged-helper escalation on EPERM — no numeric kill at
    any stage). Returns True when a signal was sent, False when
    the process was already gone. ProcAbsent/ProcUnknown
    propagate (nothing signaled); AdmissionError propagates
    when identity cannot be verified. The fresh pin always
    closes — including on the error paths.
    """
    pin = provision.pin_proc(victim)
    try:
        _, start = provision.stat_state_start(victim)
        return provision.signal_owned(victim, signum, pin, start)
    finally:
        os.close(pin)


def ext4_arm_verdict(ext4_present, have_loop, have_mkfs):
    """E2E ext4-arm obligation. (G1-I3)

    Returns "verified" when the arm ran, "required" when the arm
    is missing on a loop+mkfs-capable host (the caller must
    fail, never pass), else "skipped" (the caller checks the
    FS01 skip reason instead).
    """
    if ext4_present:
        return "verified"
    if have_loop and have_mkfs:
        return "required"
    return "skipped"


def fs01_skip_reason_ok(reason):
    """True when an FS01 skip names its missing capability. (G1-I3)

    Genuine unavailability reasons name loop/losetup ("no free
    loop device", "loop-control not openable", "losetup
    refused/outcome uncertain") or mkfs ("missing mkfs.ext4
    tool"). Anything else — empty, unrelated, or a mount-stage
    failure (which implies loop worked) — is not a capability
    skip.
    """
    text = (reason or "").lower()
    if not text:
        return False
    return any(key in text
               for key in ("loop", "losetup", "mkfs"))


@unittest.skipUnless(live_mounts_enabled(),
                     "TT04_LIVE_MOUNTS=1 and sudo -n required")
class LiveBindTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="provision-live-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # S17-round5: join the keeper ns before any mount
        # effect or observation. Failure here is an ERROR,
        # not a skip: the platform prerequisites (sudo,
        # unshare, nsenter) were probed by the class gate,
        # so a failed ensure is a regression to fix.
        provision.ensure_mount_ns()

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
            # S17-round5: the stat arms of the gate see the
            # bind only inside the ns, so the REAL functions
            # run there (an in-ns process reads the ns table
            # directly for /proc/self/mountinfo).
            qualdir = os.path.dirname(provision.__file__)
            gate = sudo(
                sys.executable, "-c",
                "import os, sys\n"
                f"sys.path.insert(0, {qualdir!r})\n"
                "import provision_fs as provision\n"
                f"table = provision.read_mount_table()\n"
                f"print('OWNED', provision.owned_bind_only("
                f"{point!r}, {payload!r}, {st.st_dev}, "
                f"{st.st_ino}, table))\n"
                f"print('PAYLOAD', provision.target_is_payload("
                f"{point!r}, {payload!r}, {st.st_dev}, "
                f"{st.st_ino}))\n")
            self.assertEqual(gate.returncode, 0, gate.stderr)
            self.assertIn("OWNED True", gate.stdout)
            self.assertIn("PAYLOAD True", gate.stdout)
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
        # S17-round5: the driver binds inside the keeper ns
        # (its fifo/ledger/ack files are plain files, visible
        # in both views, so the drive() protocol is unchanged).
        child = subprocess.Popen(
            ["sudo", "-n", "nsenter", f"--mount={live_ns()}",
             sys.executable, driver, run_root,
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
            # S17-round5: through the live bind — the host
            # view still shows the covered file.
            self.assertEqual(ns_text(point), "live-payload\n")
            line = drive("restore")
            self.assertIn("restore rc=0", line)
            # S17-round5: read in-ns (discriminating — a
            # failed restore still shows the payload there).
            self.assertEqual(ns_text(point), "live-point\n")
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
        # Snapshot FIRST, while no bind exists (ns-routed:
        # also proves no leaked mount sits at the tree).
        snapshot = provision.mount_targets_under(tree)
        self.assertEqual(snapshot, frozenset())
        mounted = False
        try:
            proc = sudo("mount", "--bind", src, sub)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            # S17-round5: the guard's live arms are
            # descriptor-bound, so the REAL fd_clear_dir runs
            # inside the ns (where the bind lives) with the
            # same stale empty snapshot — the descriptor
            # mount-ID arm must still refuse traversal. The
            # probe runs as root via sudo; the S75/S76
            # controller identity keeps the exclusion gate
            # open for the controller's tree.
            qualdir = os.path.dirname(provision.__file__)
            probe = sudo(
                sys.executable, "-c",
                "import os, sys\n"
                f"sys.path.insert(0, {qualdir!r})\n"
                "import provision_fs as provision\n"
                f"fd = os.open({tree!r}, "
                "os.O_RDONLY | os.O_DIRECTORY)\n"
                "try:\n"
                "    provision.fd_clear_dir(fd, '', "
                "frozenset())\n"
                "    print('TRAVERSAL-COMPLETED')\n"
                "except OSError as exc:\n"
                "    print(f'TRAVERSAL-REFUSED: {exc}')\n"
                "finally:\n"
                "    os.close(fd)\n")
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertIn("mount boundary", probe.stdout)
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
            # S17-round5: through the live bind (in-ns).
            self.assertTrue(ns_exists(
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
            # S17-round5: move-verify-detach leaves no staging
            # residue behind in the run root.
            leftovers = [name for name in os.listdir(run)
                         if name.startswith(".tt04-retire-")]
            self.assertEqual(leftovers, [])
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
            # S71-round5: the REAL descriptor correspondence
            # against the live mount (in-ns: the host view
            # sees the covered dir). Match, wrong-node, and
            # changed-observation (doctored row ID) verdicts.
            qualdir = os.path.dirname(provision.__file__)
            corr = sudo(
                sys.executable, "-c",
                "import os, sys\n"
                f"sys.path.insert(0, {qualdir!r})\n"
                "import provision_fs as provision\n"
                f"row = {{'mnt_id': {mnt_id}}}\n"
                f"bad = {{'mnt_id': {mnt_id + 10000}}}\n"
                f"print('MATCH1', provision._mount_matches_loop("
                f"{point!r}, {loop!r}, row))\n"
                "print('MATCH2', "
                "provision._mount_matches_loop("
                f"{point!r}, '/dev/loop-control', row))\n"
                f"print('MATCH3', provision._mount_matches_loop("
                f"{point!r}, {loop!r}, bad))\n")
            self.assertEqual(corr.returncode, 0, corr.stderr)
            self.assertIn("MATCH1 True", corr.stdout)
            self.assertIn("MATCH2 False", corr.stdout)
            self.assertIn("MATCH3 False", corr.stdout)
            # Folded ownership: our own write lands
            # (S17-round5: through the live ext4 mount, so
            # the unprivileged write and the owner stat run
            # inside the ns).
            probe = os.path.join(point, "probe.txt")
            ns_write_user(probe, "hello\n")
            stat_p = sudo("stat", "-c", "%u", point)
            self.assertEqual(stat_p.returncode, 0,
                             stat_p.stderr)
            self.assertEqual(stat_p.stdout.strip(),
                             str(os.geteuid()))
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
        # S81-round5: plant the binding canary the helper
        # reads from held upper (never argv) for overlay
        # post-mount binding.
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
               "--fstype", "overlay"]
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
            # S17-round5: through the live overlay (the
            # upperdir read below stays direct — plain dir).
            self.assertEqual(
                ns_text(os.path.join(target, "shared.txt")),
                "lower-original\n")
            ns_write_user(
                os.path.join(target, "upper-only.txt"),
                "upper-only\n")
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

    # S81-round5 live: the helper pins the fresh mount
    # before its post-mount window opens, so a privileged
    # regular umount inside the window goes EBUSY — the swap
    # cannot even start, and the helper reports OUR mount
    # (ID, content, folded ownership all prove it).
    def test_live_mount_window_pin_blocks_umount(self):
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
        target = os.path.join(role, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
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

        def poll_row(timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                row = live_row()
                if row is not None:
                    return row
                time.sleep(0.2)
            return None

        helper = subprocess.Popen(
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
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
                "helper finished before the window opened "
                "(delay hook inert?)")
            # The swap cannot start: our pin holds EBUSY.
            bye = sudo("umount", target)
            self.assertNotEqual(bye.returncode, 0)
            self.assertIn("busy", bye.stderr.lower())
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 0, out)
            line = out.splitlines()[0]
            mnt_id, source, _ = self._parse_mounted_line(
                line, target)
            self.assertEqual(source, "overlay")
            # Reported OUR mount: live ID, content, and the
            # folded chown all agree.
            self.assertEqual(live_row()["mnt_id"], mnt_id)
            self.assertEqual(
                ns_text(os.path.join(
                    target, provision.MOUNT_CANARY_NAME)),
                canary)
            stat_p = sudo("stat", "-c", "%u", target)
            self.assertEqual(stat_p.stdout.strip(),
                             str(os.geteuid()))
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", target)

    # S81-round5 live: a lazy detach defeats the pin, but the
    # detached mount keeps its ID (no recycling while held),
    # so the pin cross-check refuses the replacement
    # deterministically — even carrying the COPIED correct
    # token. The refusal reason proves content-independence
    # (a mount change, never a canary mismatch), the
    # stranger is left in place, and no chown touches it
    # although --own-uid/gid was given.
    def test_live_mount_lazy_replacement_refuses_copied_token(
            self):
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
        # Foreign stack: plausible overlay, the COPIED
        # correct token (read from our upper, as any
        # privileged interposer could), and root-owned upper
        # so a folded chown would be visible.
        fx = os.path.join(run, "fx")
        for sub in ("flower", "fupper", "fwork"):
            os.makedirs(os.path.join(fx, sub), mode=0o700)
        with open(os.path.join(
                fx, "fupper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
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
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
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
            # Lazy detach + plant inside the window.
            bye = sudo("umount", "-l", target)
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
            self.assertEqual(second["fstype"], "overlay")
            self.assertEqual(second["source"], "overlay")
            # The plant really carries the copied token...
            seen = sudo("cat", os.path.join(
                target, provision.MOUNT_CANARY_NAME))
            self.assertEqual(seen.returncode, 0,
                             seen.stderr)
            self.assertEqual(seen.stdout, canary)
            # ...yet the helper refuses by acquisition (mount
            # change), never by content.
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            self.assertIn("FAILED-UNCERTAIN", out)
            self.assertIn("changed during effect", out)
            self.assertNotIn("canary mismatch", out)
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

    # S81-round6 live: a copied-token replacement planted
    # BEFORE the pin open refuses at the pin probe. The
    # clone carries our C1 token, so the pin opens it and
    # every content gate passes — but the fresh challenge
    # written through the pin drains to the clone's upper,
    # never to ours. The refusal precedes any chown (the
    # root-owned foreign upper is unchanged) and the clone
    # is left in place. Deterministic via the pre-pin delay
    # window (no blind preemption luck).
    def test_live_mount_pre_pin_clone_refuses_pin_probe(self):
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        canary = "live-canary-%d" % os.getpid()
        token_path = os.path.join(
            role, "upper", provision.MOUNT_CANARY_NAME)
        fd = os.open(token_path,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600)
        try:
            os.write(fd, canary.encode("ascii"))
        finally:
            os.close(fd)
        # Foreign clone: plausible overlay, the COPIED
        # correct token, and root-owned upper so a folded
        # chown would be visible.
        fx = os.path.join(run, "fx")
        for sub in ("flower", "fupper", "fwork"):
            os.makedirs(os.path.join(fx, sub), mode=0o700)
        with open(os.path.join(
                fx, "fupper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
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
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
             "S74_PRE_PIN_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_row(60)
            self.assertIsNotNone(
                first, "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the pre-pin window "
                "opened (delay hook inert?)")
            # Lazy detach + copied-token plant inside the
            # PRE-PIN window (ours is unpinned, so the lazy
            # detach destroys it — the clone is the sole
            # occupant when the pin opens).
            bye = sudo("umount", "-l", target)
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
            self.assertEqual(second["fstype"], "overlay")
            # The plant really carries the copied token...
            seen = sudo("cat", os.path.join(
                target, provision.MOUNT_CANARY_NAME))
            self.assertEqual(seen.returncode, 0,
                             seen.stderr)
            self.assertEqual(seen.stdout, canary)
            # ...yet the helper refuses at the pin probe
            # (drain failure), never by content.
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            self.assertIn("FAILED-UNCERTAIN", out)
            self.assertIn("pin probe", out)
            self.assertNotIn("canary mismatch", out)
            # The challenge reached the clone's upper (and
            # only there), 0600, root-written.
            listing = sudo("ls", "-a", fupper)
            self.assertEqual(listing.returncode, 0,
                             listing.stderr)
            probes = [
                name for name in listing.stdout.split()
                if name.startswith(
                    provision.MOUNT_PROBE_PREFIX)]
            self.assertEqual(len(probes), 1)
            mode = sudo("stat", "-c", "%a:%u",
                        os.path.join(fupper, probes[0]))
            self.assertEqual(mode.stdout.strip(), "600:0")
            self.assertEqual(
                [name for name in os.listdir(
                    os.path.join(role, "upper"))
                 if name.startswith(
                     provision.MOUNT_PROBE_PREFIX)], [])
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
               "--fstype", "overlay"]
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

        # S17-round5: the helper mounts inside the ns.
        helper = subprocess.Popen(
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
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
            # S17-round5: through the moved mount (in-ns).
            self.assertEqual(
                ns_text(os.path.join(
                    moved, provision.MOUNT_CANARY_NAME)),
                canary)
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

    # S74-round6 live: the role parent is renamed OUTSIDE the
    # run root BEFORE PIN acquisition (pre-pin delay window).
    # Mount through the held operand succeeds, the pin fails,
    # and table-difference recovery reports _HelperMoved with
    # the live ID + observed target. Reconcile keeps ID-keyed
    # pending custody; ACTUAL cleanup then fails loudly
    # (manual retirement) with the mount still live at the
    # escaped path and custody retained — never a silent
    # discharge past the empty name and the run-root-only
    # sweep. No chown touches the moved-but-unpinned mount
    # although --own-uid/gid was given.
    def test_live_mount_pre_pin_rename_outside_recovers(self):
        import contextlib
        import io
        import types
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
        escaped_role = os.path.join(self.tmp, "escaped")
        escaped = os.path.join(escaped_role, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--own-uid", "0", "--own-gid", "0"]
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
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
             "S74_PRE_PIN_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_rows_at(target, 60)
            self.assertEqual(len(first), 1,
                             "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the pre-pin window "
                "opened (delay hook inert?)")
            # Rename the role PARENT outside the run root
            # before pin acquisition; the mount follows.
            os.rename(role, escaped_role)
            second = poll_rows_at(escaped, 30)
            self.assertEqual(len(second), 1,
                             "moved mount never appeared")
            self.assertEqual(live_rows_at(target), [])
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            self.assertIn("FAILED-MOVED", out)
            parsed = provision._parse_moved_report(out)
            self.assertIsNotNone(parsed, out)
            mnt_id, observed = parsed
            self.assertEqual(observed, escaped)
            self.assertEqual(mnt_id, second[0]["mnt_id"])
            # No chown on the moved-but-unpinned mount: the
            # upper it carries is still controller-owned.
            fst = os.stat(os.path.join(escaped_role, "upper"))
            self.assertEqual((fst.st_uid, fst.st_gid),
                             (os.geteuid(), os.getegid()))
            # Reconcile through production code: the
            # controller normalizes the helper report and
            # keeps ID-keyed pending custody.
            manifest_path = os.path.join(self.tmp,
                                         "manifest.json")
            doc = provision.fresh_manifest(run, False)
            st = os.stat(run)
            doc["run_root_identity"] = {"dev": st.st_dev,
                                        "ino": st.st_ino}
            provision.record_pending_acquisition(doc, {
                "kind": "mount", "key": target, "role": "ov",
                "target": target, "fstype": "overlay",
                "source": "overlay", "expect_super": [],
                "canary": canary})
            failure = provision._normalize_mount_failure(
                target, helper.returncode, out, "")
            adopted = provision.reconcile_mount_effect(
                doc, run, "ov", target,
                {"fstype": "overlay", "source": "overlay",
                 "expect_super": []},
                canary=(provision.MOUNT_CANARY_NAME, canary),
                failure=failure)
            self.assertIsNone(adopted)
            pendings = doc["pending_acquisitions"]
            self.assertEqual(len(pendings), 1)
            self.assertEqual(pendings[0].get("mnt_id"), mnt_id)
            self.assertEqual(pendings[0].get("observed_target"),
                             escaped)
            with open(manifest_path, "w") as handle:
                json.dump(doc, handle)
            # ACTUAL cleanup: loud failure — the escaped
            # occupant is outside run-root containment, so the
            # binding re-check cannot rerun there (the
            # ns-canary helper rightly refuses outside paths)
            # and the mount is left in place, never retired
            # blind. Custody retained, never discharged.
            args = types.SimpleNamespace(run_root=run,
                                         manifest=manifest_path)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = provision.cleanup_command(args)
            self.assertEqual(rc, 1, buf.getvalue())
            self.assertIn("left in place", buf.getvalue())
            self.assertIn(escaped, buf.getvalue())
            live = live_rows_at(escaped)
            self.assertEqual(len(live), 1)
            self.assertEqual(live[0]["mnt_id"], mnt_id)
            kept = json.loads(open(manifest_path).read())
            self.assertEqual(
                len(kept["pending_acquisitions"]), 1)
            self.assertEqual(
                kept["pending_acquisitions"][0].get("mnt_id"),
                mnt_id)
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", escaped)
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
        # S81-round5: plant the binding canary the helper
        # reads from held upper (never argv) for overlay
        # post-mount binding.
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
               "--fstype", "overlay"]
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
            # S17-round5: through the live overlay (in-ns).
            self.assertEqual(
                ns_text(os.path.join(target, "shared.txt")),
                "lower-original\n")
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
        # S81-round5: binding canary, planted in upper
        # (LF name tests escape, the canary itself stays
        # plain and off argv).
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
               "--fstype", "overlay"]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]
        mounted = False
        verified_mnt_id = None
        try:
            mnt = sudo(*argv)
            # S93-round5: arm mount custody from the LIVE table,
            # not the report: a helper that mounts and then fails
            # verification still leaves an effect to retire.
            if mount_live_at(target):
                mounted = True
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
            verified_mnt_id = rows[0]["mnt_id"]
            # S17-round5: through the live overlay (in-ns).
            self.assertEqual(
                ns_text(os.path.join(target, "shared.txt")),
                "lower-original\n")
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
            # Discharge only after CONFIRMED retirement: the
            # live row must be gone, not merely reported gone.
            if not mount_live_at(target):
                mounted = False
        finally:
            if mounted:
                retire_verified_mount(target, verified_mnt_id)

    # S102-round6 live effect check: unprivileged and refused
    # entries never touch keeper infrastructure. The keeper
    # is killed first (stale pidfile left behind, so any
    # ensure would observably respawn); real default create,
    # legacy inspect and an invalid create then run — the
    # pidfile bytes stay stale, no new keeper sleep appears,
    # and the commands still report their own outcomes. The
    # keeper is re-ensured for later tests before returning.
    def test_live_unprivileged_entries_spawn_no_keeper(self):
        pidfile, _candir = provision._keeper_paths()
        try:
            with open(pidfile, "rb") as handle:
                stale = handle.read()
        except OSError:
            stale = None
        keeper_pid = None
        if stale is not None:
            try:
                keeper_pid = int(stale.split()[0])
            except (ValueError, IndexError):
                keeper_pid = None

        def sleepers():
            out = subprocess.run(
                ["pgrep", "-f", "^sleep infinity$"],
                capture_output=True, text=True)
            return {int(word) for word in out.stdout.split()
                    if word.isdigit()}

        before = sleepers()
        try:
            if keeper_pid is not None:
                sudo("kill", "-KILL", str(keeper_pid))
                deadline = time.time() + 15
                while time.time() < deadline:
                    if not os.path.exists(
                            f"/proc/{keeper_pid}"):
                        break
                    time.sleep(0.2)
                self.assertFalse(
                    os.path.exists(f"/proc/{keeper_pid}"),
                    "keeper survived SIGKILL")
            tool = provision.__file__
            run = os.path.join(self.tmp, "plain")
            manifest = os.path.join(self.tmp, "plain.json")
            first = subprocess.run(
                [sys.executable, tool, "create",
                 "--manifest", manifest, "--run-root", run],
                capture_output=True, text=True, timeout=300)
            self.assertEqual(first.returncode, 0,
                             first.stdout + first.stderr)
            second = subprocess.run(
                [sys.executable, tool, "inspect",
                 "--manifest", manifest, "--run-root", run],
                capture_output=True, text=True, timeout=300)
            self.assertEqual(second.returncode, 0,
                             second.stdout + second.stderr)
            third = subprocess.run(
                [sys.executable, tool, "create",
                 "--manifest", manifest, "--run-root",
                 "/etc/shadow"],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(third.returncode, 2,
                             third.stdout + third.stderr)
            # No keeper infrastructure appeared: the pidfile
            # still holds the stale record (or is still
            # absent) and no new sleeper exists.
            try:
                with open(pidfile, "rb") as handle:
                    now = handle.read()
            except OSError:
                now = None
            self.assertEqual(now, stale)
            self.assertTrue(sleepers() <= before)
        finally:
            provision._MOUNT_NS = None
            provision._MOUNT_NS_IDENTITY = None
            provision.ensure_mount_ns()

    # S100/S103-round6 live: killing the keeper drops every
    # later routing decision loudly, and the next ensure
    # respawns exactly one verified keeper (new identity,
    # canary present, routed reads work) — no dual keepers,
    # no silent adoption of the stale record.
    def test_live_keeper_respawn_recovers(self):
        pidfile, _ = provision._keeper_paths()
        with open(pidfile, "rb") as handle:
            old = handle.read().split()
        old_pid = int(old[0])
        sudo("kill", "-KILL", str(old_pid))
        deadline = time.time() + 15
        while time.time() < deadline:
            if not os.path.exists(f"/proc/{old_pid}"):
                break
            time.sleep(0.2)
        self.assertFalse(os.path.exists(f"/proc/{old_pid}"))
        # Routed decisions on the stale cache refuse loudly.
        with self.assertRaises(provision.AdmissionError):
            provision.read_mount_table()
        # The next ensure respawns + verifies a fresh keeper.
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        nspath = provision.ensure_mount_ns()
        with open(pidfile, "rb") as handle:
            new = handle.read().split()
        new_pid = int(new[0])
        self.assertNotEqual(new_pid, old_pid)
        self.assertEqual(nspath, f"/proc/{new_pid}/ns/mnt")
        rows = provision.read_mount_table()
        self.assertIsInstance(rows, list)
        self.assertFalse(os.path.exists(f"/proc/{old_pid}"))

    # S99-round6 end to end: real privileged create, inspect
    # and cleanup through the production entry points (main,
    # including the in-namespace re-exec), with independent
    # device/mount correspondence — files stat onto their
    # mounts (not the covered parents), the loop still binds
    # the image, the host table stays clean, and cleanup
    # discharges everything. The ext4 arms adapt when loop
    # support is unavailable (skip recorded, overlay still
    # fully verified).
    def test_live_privileged_create_inspect_cleanup_e2e(self):
        tool = provision.__file__
        run = os.path.join(self.tmp, "run")
        manifest = os.path.join(self.tmp, "manifest.json")

        def tool_run(*args, timeout=600):
            return subprocess.run(
                [sys.executable, tool, *args],
                capture_output=True, text=True,
                timeout=timeout)

        def ns_stat(path):
            out = sudo(sys.executable, "-c",
                       "import os, sys\n"
                       f"st = os.stat({path!r})\n"
                       "print(st.st_dev, st.st_ino)")
            self.assertEqual(out.returncode, 0,
                             out.stdout + out.stderr)
            dev, ino = out.stdout.split()
            return (int(dev), int(ino))

        created = tool_run(
            "create", "--manifest", manifest,
            "--run-root", run, "--privileged")
        self.assertEqual(created.returncode, 0,
                         created.stdout + created.stderr)
        try:
            with open(manifest) as handle:
                doc = json.load(handle)
            # The manifest binds the keeper it provisioned in.
            mode = doc.get("mount_ns")
            self.assertIsInstance(mode, dict)
            pidfile, _ = provision._keeper_paths()
            with open(pidfile) as handle:
                recorded = handle.read().split()
            self.assertEqual(
                (mode["pid"], mode["nsid"]),
                (int(recorded[0]), int(recorded[1])))
            mounts = {entry["target"]: entry
                      for entry in doc.get("mounts", [])}
            # Overlay correspondence (always available): the
            # shared file stats onto the mount, which differs
            # from the covered parent — three channels agree
            # (manifest row, ns table, in-ns stat).
            overseen = [target for target in mounts
                        if target.endswith("/merged")]
            self.assertGreaterEqual(len(overseen), 1)
            table = provision.read_mount_table()
            with open("/proc/self/mountinfo") as handle:
                host = handle.read()
            for target in overseen:
                self.assertNotIn(target, host)
                rows = provision.find_mounts(table, target)
                self.assertEqual(len(rows), 1)
                self.assertEqual(
                    rows[0]["mnt_id"],
                    mounts[target]["mnt_id"])
                parent = os.path.dirname(target)
                file_dev, _ = ns_stat(os.path.join(
                    target, "shared.txt"))
                mnt_dev, _ = ns_stat(target)
                parent_dev, _ = ns_stat(parent)
                self.assertEqual(file_dev, mnt_dev)
                self.assertNotEqual(mnt_dev, parent_dev)
            # Ext4 correspondence when loop provisioned it:
            # exactly one loop device backs our image (sysfs
            # scan — no manifest strings), and the mount's
            # device numbers name that loop (major 7).
            ext4_mnt = os.path.join(run, "ext4", "mnt")
            if ext4_mnt in mounts:
                import glob
                import re
                images = glob.glob(
                    os.path.join(run, "ext4", "*.img"))
                self.assertEqual(len(images), 1)
                image = images[0]
                ours = []
                for path in glob.glob(
                        "/sys/block/loop*/loop/backing_file"):
                    try:
                        with open(path) as handle:
                            content = handle.read().strip()
                    except OSError:
                        continue
                    if content == image:
                        ours.append(path)
                self.assertEqual(len(ours), 1)
                loopnum = int(
                    re.search(r"loop(\d+)", ours[0]).group(1))
                file_dev, _ = ns_stat(
                    os.path.join(ext4_mnt, "a.bin"))
                mnt_dev, _ = ns_stat(ext4_mnt)
                parent_dev, _ = ns_stat(
                    os.path.join(run, "ext4"))
                self.assertEqual(file_dev, mnt_dev)
                self.assertNotEqual(mnt_dev, parent_dev)
                self.assertEqual(os.major(mnt_dev), 7)
                self.assertEqual(os.minor(mnt_dev), loopnum)
            else:
                # G1-I3: the ext4 arm must not be silently
                # optional — on a loop+mkfs-capable host a
                # missing arm is breakage, not a pass.
                loop_probe = sudo("losetup", "-f")
                have_loop = loop_probe.returncode == 0
                have_mkfs = (
                    shutil.which("mkfs.ext4") is not None)
                verdict = ext4_arm_verdict(
                    False, have_loop, have_mkfs)
                if verdict == "required":
                    self.fail(
                        "ext4 arm missing on a loop-capable "
                        "host (FS01 cell: "
                        f"{doc.get('cells', {}).get('FS01')!r})")
                self.assertIn("FS01", doc.get("cells", {}))
                reason = doc["cells"]["FS01"].get("reason", "")
                self.assertTrue(
                    fs01_skip_reason_ok(reason),
                    "FS01 skip names no missing capability: "
                    f"{reason!r}")
            # Churn's driver (a raw-Popen child of
            # create) was born inside the keeper namespace —
            # its bind mounts land in-ns by inheritance.
            drivers = [
                proc for proc in doc.get("procs", [])
                if proc.get("role") == "churn-driver"
                and os.path.exists(f"/proc/{proc['pid']}")]
            self.assertGreaterEqual(len(drivers), 1)
            link = sudo(
                "readlink",
                f"/proc/{drivers[0]['pid']}/ns/mnt")
            self.assertEqual(link.returncode, 0,
                             link.stdout + link.stderr)
            self.assertEqual(link.stdout.strip(),
                             f"mnt:[{mode['nsid']}]")
            # Provisioned procs are independently alive.
            for proc in doc.get("procs", [])[:4]:
                self.assertTrue(
                    os.path.exists(f"/proc/{proc['pid']}"),
                    proc)
            inspected = tool_run(
                "inspect", "--manifest", manifest,
                "--run-root", run)
            self.assertEqual(inspected.returncode, 0,
                             inspected.stdout +
                             inspected.stderr)
            self.assertIn("admitted", inspected.stdout)
        finally:
            cleaned = tool_run(
                "cleanup", "--manifest", manifest,
                "--run-root", run)
            self.assertEqual(cleaned.returncode, 0,
                             cleaned.stdout + cleaned.stderr)
            self.assertFalse(os.path.exists(run))
            table = provision.read_mount_table()
            leftovers = [
                row for row in table
                if row["target"].startswith(run + "/")]
            self.assertEqual(leftovers, [])
            with open("/proc/self/mountinfo") as handle:
                host = handle.read()
            self.assertNotIn(run + "/", host)


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
        runner = None
        victim = None
        try:
            runner = subprocess.Popen(
                ["sudo", "-n", "sleep", "117"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
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
            # S92-round5: retire ONLY owned tasks through
            # retained authorities — no host-wide pkill, no
            # numeric kill. The root victim (if the test failed
            # before killing it) is re-pinned and re-verified
            # by identity, then signaled through the
            # escalation helper; a reused number refuses
            # (AdmissionError) instead of signaling a
            # stranger. The sudo runner is our own child,
            # killed through the retained Popen handle
            # (unreaped while held — the number cannot be
            # recycled underneath).
            if victim is not None:
                try:
                    signal_verified_proc(
                        victim, _signal.SIGKILL)
                except (provision.ProcAbsent,
                        provision.ProcUnknown,
                        provision.AdmissionError):
                    pass
                if not self._poll_gone(victim, 10):
                    sys.stderr.write(
                        "WARNING: owned victim %d survived "
                        "S92 cleanup\n" % victim)
            if runner is not None and runner.poll() is None:
                runner.kill()
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


class MountCustodyTests(unittest.TestCase):
    # S93-round5: the mount-custody state machine, without
    # privilege. The live table and sudo are scripted; no mount,
    # namespace, or sudo is touched. Ungated: these run in the
    # default suite, while the live classes above skip without
    # TT04_LIVE_MOUNTS=1.
    def _row(self, mnt_id):
        return {"mnt_id": mnt_id, "source": "overlay",
                "fstype": "overlay", "root": "/"}

    def test_retire_attempts_when_unverified_and_live(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        return_value=[self._row(41)]):
            self.assertTrue(
                retire_verified_mount("/t", None))
        sudo_mock.assert_called_once_with("umount", "/t")

    def test_retire_skips_when_absent(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        return_value=[]):
            self.assertFalse(
                retire_verified_mount("/t", 41))
        sudo_mock.assert_not_called()

    def test_retire_attempts_when_id_matches(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        return_value=[self._row(41)]):
            self.assertTrue(
                retire_verified_mount("/t", 41))
        sudo_mock.assert_called_once_with("umount", "/t")

    def test_retire_skips_foreign_replacement(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        return_value=[self._row(99)]):
            self.assertFalse(
                retire_verified_mount("/t", 41))
        sudo_mock.assert_not_called()

    def test_retire_attempts_when_table_unreadable(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        side_effect=OSError("ns gone")):
            self.assertTrue(
                retire_verified_mount("/t", 41))
        sudo_mock.assert_called_once_with("umount", "/t")


class ProcCustodyTests(unittest.TestCase):
    # S92-round5: the owned-proc retirement helper, without
    # privilege. Pin/stat/signal/close are scripted; no task is
    # touched. Ungated like MountCustodyTests above.
    def test_signal_sends_through_fresh_pin(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7) as pin_mock, \
             mock.patch.object(
                provision, "stat_state_start",
                return_value=("S", 1234)), \
             mock.patch.object(
                provision, "signal_owned",
                return_value=True) as signal_mock, \
             mock.patch("os.close") as close_mock:
            self.assertTrue(signal_verified_proc(4242, 9))
        pin_mock.assert_called_once_with(4242)
        signal_mock.assert_called_once_with(4242, 9, 7, 1234)
        close_mock.assert_called_once_with(7)

    def test_signal_reports_gone_at_signal(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7), \
             mock.patch.object(
                provision, "stat_state_start",
                return_value=("S", 1234)), \
             mock.patch.object(
                provision, "signal_owned",
                return_value=False), \
             mock.patch("os.close") as close_mock:
            self.assertFalse(signal_verified_proc(4242, 9))
        close_mock.assert_called_once_with(7)

    def test_signal_propagates_absent_without_close(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                side_effect=provision.ProcAbsent("gone")), \
             mock.patch("os.close") as close_mock:
            with self.assertRaises(provision.ProcAbsent):
                signal_verified_proc(4242, 9)
        close_mock.assert_not_called()

    def test_signal_closes_pin_on_identity_refusal(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7), \
             mock.patch.object(
                provision, "stat_state_start",
                return_value=("S", 1234)), \
             mock.patch.object(
                provision, "signal_owned",
                side_effect=provision.AdmissionError(
                    "changed")), \
             mock.patch("os.close") as close_mock:
            with self.assertRaises(provision.AdmissionError):
                signal_verified_proc(4242, 9)
        close_mock.assert_called_once_with(7)

    def test_signal_closes_pin_on_stat_failure(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7), \
             mock.patch.object(
                provision, "stat_state_start",
                side_effect=provision.ProcAbsent("gone")), \
             mock.patch("os.close") as close_mock:
            with self.assertRaises(provision.ProcAbsent):
                signal_verified_proc(4242, 9)
        close_mock.assert_called_once_with(7)


class Ext4ArmVerdictTests(unittest.TestCase):
    # G1-I3: the E2E ext4-arm obligation, pinned without live
    # mounts (the live E2E test calls these helpers). The arm
    # is required on loop+mkfs-capable hosts; otherwise the
    # FS01 skip reason must name the missing capability.
    def test_verdict_matrix(self):
        self.assertEqual(
            ext4_arm_verdict(True, True, True), "verified")
        self.assertEqual(
            ext4_arm_verdict(True, False, False), "verified")
        self.assertEqual(
            ext4_arm_verdict(False, True, True), "required")
        self.assertEqual(
            ext4_arm_verdict(False, False, True), "skipped")
        self.assertEqual(
            ext4_arm_verdict(False, True, False), "skipped")
        self.assertEqual(
            ext4_arm_verdict(False, False, False), "skipped")

    def test_skip_reason_matrix(self):
        self.assertTrue(fs01_skip_reason_ok(
            "missing mkfs.ext4 tool"))
        self.assertTrue(fs01_skip_reason_ok(
            "losetup refused: rc=1 loop-control not openable"))
        self.assertTrue(fs01_skip_reason_ok(
            "no free loop device: [Errno 19] No such device"))
        self.assertTrue(fs01_skip_reason_ok(
            "losetup outcome uncertain and backing identity "
            "matches several loops"))
        self.assertFalse(fs01_skip_reason_ok(""))
        self.assertFalse(fs01_skip_reason_ok(None))
        # Mount-stage failures imply loop worked: not a
        # capability skip, so they must not pass as one.
        self.assertFalse(fs01_skip_reason_ok(
            "ext4 mount not admitted (foreign replacement)"))
        self.assertFalse(fs01_skip_reason_ok(
            "some unrelated failure"))


if __name__ == "__main__":
    unittest.main()
