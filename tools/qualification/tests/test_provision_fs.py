# SPDX-License-Identifier: Apache-2.0
"""TT04 filesystem provisioner checks for tools/qualification/provision_fs.py.

TDD: authored before the tool and observed failing (FileNotFoundError:
missing tools/qualification/provision_fs.py) prior to implementation.

Only deterministic, unprivileged negatives live here: foreign-path
refusals, grant discipline, manifest tamper detection, idempotent
cleanup and the pure mountinfo/admission predicates. Live privileged
provisioning is exercised by the operator route, never by this file.
"""
import errno
import fcntl
import importlib.util
import json
import os
import struct
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

HELPERS = Path(__file__).resolve().parent / "tt05_helpers.py"
hspec = importlib.util.spec_from_file_location("tt05_helpers", HELPERS)
h = importlib.util.module_from_spec(hspec)
sys.modules["tt05_helpers"] = h
hspec.loader.exec_module(h)

provision = h.load("provision_fs", "tools/qualification/provision_fs.py")


def _loop_fd_script(get_items, clr_errno=None, open_backings=None):
    """Hermetic ioctl seam for loop-retire tests. (S17-round3)

    Routes /dev/loop* opens to stand-in fds (recording every
    open), scripts LOOP_GET_STATUS64 replies, and logs every
    ioctl by fd. Returns (fake_open, fake_ioctl, log); log
    holds ('open', path, fd), ('ioctl', fd, req) and
    ('clr-victim', fd, backing) entries. Non-loop opens and
    foreign-fd ioctls delegate to the real calls, so the patch
    is safe process-wide for the test's duration.

    get_items: per-GET replies — ('id', dev, ino), ('enxio',)
        or ('eacces',) — consumed in call order, unless
        open_backings is given.
    clr_errno: None (CLR succeeds) or an errno the CLR raises.
    open_backings: node-swap model — each routed open pops one
        backing identity ((dev, ino) or None when free); every
        fd answers GETs from its own backing, and CLR records
        its fd's backing as the victim before freeing it.
    """
    real_open = os.open
    real_ioctl = fcntl.ioctl
    log = []
    standins = {}
    gets = list(get_items)
    router = list(open_backings) if open_backings is not None else None
    per_fd = {}

    def fake_open(path, flags, *args):
        if isinstance(path, str) and path.startswith("/dev/loop"):
            fd = real_open("/dev/null", os.O_RDWR)
            log.append(("open", path, fd))
            standins[fd] = path
            if router is not None:
                per_fd[fd] = router.pop(0) if router else None
            return fd
        return real_open(path, flags, *args)

    def fake_ioctl(fd, req, *args):
        if fd in standins and req in (provision.LOOP_GET_STATUS64,
                                      provision.LOOP_CLR_FD):
            log.append(("ioctl", fd, req))
            if req == provision.LOOP_CLR_FD:
                victim = per_fd.get(fd, "scripted")
                log.append(("clr-victim", fd, victim))
                if router is not None:
                    per_fd[fd] = None
                if clr_errno is not None:
                    raise OSError(clr_errno,
                                  os.strerror(clr_errno))
                return 0
            if router is not None:
                backing = per_fd.get(fd)
                if backing is None:
                    raise OSError(errno.ENXIO, "no such device")
                struct.pack_into("<QQ", args[0], 0, *backing)
                return 0
            item = gets.pop(0)
            if item[0] == "enxio":
                raise OSError(errno.ENXIO, "no such device")
            if item[0] == "eacces":
                raise OSError(errno.EACCES, "denied")
            struct.pack_into("<QQ", args[0], 0, item[1], item[2])
            return 0
        return real_ioctl(fd, req, *args)

    return fake_open, fake_ioctl, log
ROOT = h.ROOT


def run_tool(*argv, env=None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(ROOT / "tools/qualification/provision_fs.py"), *argv],
        capture_output=True,
        text=True,
        env=merged,
        cwd=str(ROOT),
    )


def real_mnt_id(path):
    """Live mount ID of a real dir (genuine mnt binding in tests)."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return provision._mnt_id_of(fd)
    finally:
        os.close(fd)


class PlanTests(unittest.TestCase):
    def test_plan_is_readonly_and_lists_every_cell(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            out = Path(tmp) / "plan.json"
            proc = run_tool(
                "plan", "--manifest", str(out), "--run-root", str(run_root)
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            # Read-only: no fixture state is created by plan.
            self.assertFalse(run_root.exists())
            plan = json.loads(out.read_text())
            self.assertEqual(plan["schema"], "tt04-fs-plan-v1")
            names = [cell["name"] for cell in plan["cells"]]
            for expected in (
                "FS01", "FS02", "FS03", "FS04", "FS05",
                "FS06", "FS07", "FS08", "FS09", "FS10",
            ):
                self.assertIn(expected, names)
            for cell in plan["cells"]:
                self.assertIn(cell["disposition"], ("runnable", "needs-privilege", "unsupported"))
                self.assertTrue(cell["requires"], cell["name"])
                self.assertTrue(cell["evidence"], cell["name"])

    def test_plan_refuses_foreign_run_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "plan.json"
            for foreign in ("/etc/tt04", "/proc/tt04", "/sys/tt04", "/dev/tt04"):
                proc = run_tool(
                    "plan", "--manifest", str(out), "--run-root", foreign
                )
                self.assertEqual(proc.returncode, 2, foreign)
                self.assertIn("foreign run-root", proc.stderr)

    def test_plan_refuses_dotdot_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "plan.json"
            proc = run_tool(
                "plan", "--manifest", str(out),
                "--run-root", str(Path(tmp) / ".." / "escape"),
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("foreign run-root", proc.stderr)


class CreateTests(unittest.TestCase):
    def test_default_create_attempts_no_privileged_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            manifest = Path(tmp) / "manifest.json"
            proc = run_tool(
                "create", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(manifest.read_text())
            self.assertEqual(data["schema"], "tt04-fs-manifest-v1")
            self.assertFalse(data["privilege_granted"])
            for name, cell in data["cells"].items():
                if cell.get("needs_privilege"):
                    self.assertEqual(cell["status"], "skipped", name)
                    self.assertIn("--privileged", cell["reason"])
            # No mount namespace side effects without the grant.
            self.assertEqual(data["mounts"], [])

    def test_create_refuses_second_run_without_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            manifest = Path(tmp) / "manifest.json"
            first = run_tool(
                "create", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            second = run_tool(
                "create", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(second.returncode, 2, second.stdout)
            self.assertIn("already provisioned", second.stderr)
            cleanup = run_tool(
                "cleanup", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(cleanup.returncode, 0, cleanup.stderr)

    def test_privileged_create_fails_closed_without_sudo(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            manifest = Path(tmp) / "manifest.json"
            empty_path = Path(tmp) / "emptybin"
            empty_path.mkdir()
            proc = run_tool(
                "create", "--privileged",
                "--manifest", str(manifest), "--run-root", str(run_root),
                env={"PATH": str(empty_path)},
            )
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("missing sudo", proc.stderr)
            self.assertFalse(manifest.exists())
            self.assertFalse(run_root.exists())

    def test_create_refuses_foreign_run_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            proc = run_tool(
                "create", "--manifest", str(manifest),
                "--run-root", "/etc/tt04-foreign",
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("foreign run-root", proc.stderr)
            self.assertFalse(manifest.exists())


class InspectTests(unittest.TestCase):
    def test_inspect_accepts_fresh_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            manifest = Path(tmp) / "manifest.json"
            created = run_tool(
                "create", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            proc = run_tool(
                "inspect", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("admitted", proc.stdout)
            cleanup = run_tool(
                "cleanup", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(cleanup.returncode, 0, cleanup.stderr)

    def test_inspect_detects_tampered_file_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            manifest = Path(tmp) / "manifest.json"
            created = run_tool(
                "create", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            data = json.loads(manifest.read_text())
            try:
                target = run_root / "plain" / "a.bin"
                self.assertTrue(target.exists())
                data["files"][0]["sha256"] = "00" * 32
                manifest.write_text(json.dumps(data, indent=2))
                proc = run_tool(
                    "inspect", "--manifest", str(manifest),
                    "--run-root", str(run_root),
                )
                self.assertEqual(proc.returncode, 1, proc.stdout)
                self.assertIn("plain-a", proc.stdout + proc.stderr)
            finally:
                cleanup = run_tool(
                    "cleanup", "--manifest", str(manifest),
                    "--run-root", str(run_root),
                )
                # Tampered manifests still clean up owned state by identity.
                self.assertEqual(cleanup.returncode, 0, cleanup.stderr)

    def test_inspect_rejects_foreign_mount_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            run_root.mkdir()
            st = os.stat(run_root)
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(json.dumps({
                "schema": "tt04-fs-manifest-v1",
                "run_id": "forged",
                "run_root": str(run_root),
                "created_utc": "2026-10-23T00:00:00+00:00",
                "euid": 1000,
                "privilege_granted": False,
                "kernel": {},
                "cells": {},
                "run_root_identity": {"dev": st.st_dev, "ino": st.st_ino},
                "mounts": [{
                    "role": "evil",
                    "source": "overlay",
                    "target": "/etc/tt04-evil",
                    "fstype": "overlay",
                    "options": "",
                    "mnt_id": 1,
                }],
                "procs": [],
                "files": [],
                "evidence": {},
            }))
            proc = run_tool(
                "inspect", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("foreign", proc.stdout + proc.stderr)


class CleanupTests(unittest.TestCase):
    def test_cleanup_removes_owned_state_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            manifest = Path(tmp) / "manifest.json"
            created = run_tool(
                "create", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertTrue(run_root.exists())
            first = run_tool(
                "cleanup", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertFalse(run_root.exists())
            second = run_tool(
                "cleanup", "--manifest", str(manifest),
                "--run-root", str(run_root),
            )
            self.assertEqual(second.returncode, 0, second.stderr)

    def test_cleanup_refuses_foreign_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(json.dumps({
                "schema": "tt04-fs-manifest-v1",
                "run_id": "forged",
                "run_root": "/etc",
                "created_utc": "2026-10-23T00:00:00+00:00",
                "euid": 1000,
                "privilege_granted": False,
                "kernel": {},
                "cells": {},
                "mounts": [],
                "procs": [],
                "files": [],
                "evidence": {},
            }))
            proc = run_tool(
                "cleanup", "--manifest", str(manifest),
                "--run-root", str(Path(tmp) / "run"),
            )
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("foreign run-root", proc.stderr)
            self.assertTrue(Path("/etc").exists())


class ReplacementCustodyTests(unittest.TestCase):
    """F08: cleanup refuses replacement resources; F09: recovery
    custody exists before effects and survives failures."""

    def fresh_paths(self):
        tmp = Path(tempfile.mkdtemp(prefix="provision-f08-"))
        self.addCleanup(
            shutil.rmtree, tmp, ignore_errors=True)
        return tmp, str(tmp / "run"), str(tmp / "manifest.json")

    def create_unprivileged(self, run_root, manifest):
        proc = run_tool("create", "--run-root", run_root,
                        "--manifest", manifest)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc

    def test_cleanup_refuses_replaced_run_root(self):
        tmp, run_root, manifest = self.fresh_paths()
        self.create_unprivileged(run_root, manifest)
        # Swap the recorded root for a fresh directory with a canary.
        shutil.rmtree(run_root)
        os.makedirs(run_root)
        canary = os.path.join(run_root, "canary.txt")
        Path(canary).write_text("canary")
        proc = run_tool("cleanup", "--run-root", run_root,
                        "--manifest", manifest)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("replacement refused", proc.stdout + proc.stderr)
        self.assertTrue(os.path.exists(canary),
                        "replacement directory must survive refusal")

    def test_cleanup_refuses_symlinked_run_root(self):
        tmp, run_root, manifest = self.fresh_paths()
        self.create_unprivileged(run_root, manifest)
        outside = tmp / "outside"
        outside.mkdir()
        (outside / "canary.txt").write_text("canary")
        shutil.rmtree(run_root)
        os.symlink(str(outside), run_root)
        proc = run_tool("cleanup", "--run-root", run_root,
                        "--manifest", manifest)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("replacement refused", proc.stdout + proc.stderr)
        self.assertEqual((outside / "canary.txt").read_text(), "canary")
        self.assertTrue(os.path.islink(run_root),
                        "symlink must survive refusal")

    def test_cleanup_one_mount_refuses_replacement(self):
        from unittest import mock
        run_root = "/tmp/provision-replacement-case"
        entry = {"target": f"{run_root}/mnt", "mnt_id": 111,
                 "fstype": "ext4", "source": "/dev/loop9",
                 "actual_super": "rw|", "expect_super": []}
        replaced = [{"target": f"{run_root}/mnt", "mnt_id": 222,
                     "fstype": "tmpfs", "source": "tmpfs",
                     "super": "rw|"}]
        with mock.patch.object(provision, "read_mount_table",
                               return_value=replaced):
            with mock.patch.object(provision, "run_sudo") as sudo:
                failure = provision.cleanup_one_mount(entry, run_root)
        self.assertIn("replacement refused", failure)
        sudo.assert_not_called()
        # Matching identity still unmounts via the retire helper;
        # a gone mount is a no-op.
        live = [{"target": f"{run_root}/mnt", "mnt_id": 111,
                 "fstype": "ext4", "source": "/dev/loop9",
                 "super": "rw|"}]
        with mock.patch.object(provision, "read_mount_table",
                               return_value=live):
            with mock.patch.object(
                    provision, "run_sudo",
                    return_value=(0, "retired-mount x\n", "")) as sudo:
                self.assertIsNone(
                    provision.cleanup_one_mount(entry, run_root))
                argv = sudo.call_args[0][0]
                self.assertIn("retire-mount", argv)
                self.assertNotIn("umount", argv)
        with mock.patch.object(provision, "read_mount_table",
                               return_value=[]):
            with mock.patch.object(provision, "run_sudo") as sudo:
                self.assertIsNone(
                    provision.cleanup_one_mount(entry, run_root))
                sudo.assert_not_called()

    # S18-round3: string-level loop-identity tests — the kernel
    # ioctl is unavailable here, so the sysfs fallback governs
    # (hermetic: no /dev dependence in any uid).
    @mock.patch.object(
        provision, "read_loop_backing_id",
        side_effect=provision.LoopIdUnavailable("test"))
    def test_cleanup_loop_device_refuses_reused_name(self, _loop_id):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root = tmp
            img = str(Path(tmp) / "ext4.img")
            Path(img).write_bytes(b"image-bytes")
            st = os.stat(img)
            backing = {"path": img, "dev": st.st_dev, "ino": st.st_ino}
            other = str(Path(tmp) / "other.img")
            Path(other).write_bytes(b"other-bytes")
            # Different backing pathname: reused loop name refuses.
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=other):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_loop_device(
                        "/dev/loop7", backing, run_root)
            self.assertIn("refusing detach", failure)
            sudo.assert_not_called()
            # R19: same pathname, DIFFERENT inode (fresh image at the
            # reused path) refuses by identity, never detaches.
            os.unlink(img)
            Path(img).write_bytes(b"fresh-image-bytes")
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=img):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_loop_device(
                        "/dev/loop7", backing, run_root)
            self.assertIn("identity changed", failure)
            sudo.assert_not_called()
            # Matching path AND identity detaches via the retire
            # helper; a gone device is a no-op; a stale
            # string-form record fails closed.
            st2 = os.stat(img)
            backing2 = {"path": img, "dev": st2.st_dev, "ino": st2.st_ino}
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=img):
                with mock.patch.object(
                        provision, "run_sudo",
                        return_value=(0, "retired-loop x\n", "")) as sudo:
                    self.assertIsNone(provision.cleanup_loop_device(
                        "/dev/loop7", backing2, run_root))
                    argv = sudo.call_args[0][0]
                    self.assertIn("retire-loop", argv)
                    self.assertNotIn("losetup", argv)
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=None):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    self.assertIsNone(provision.cleanup_loop_device(
                        "/dev/loop7", backing2, run_root))
                    sudo.assert_not_called()
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=img):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_loop_device(
                        "/dev/loop7", img, run_root)
            self.assertIn("no recorded backing", failure)
            sudo.assert_not_called()

    def test_cleanup_refuses_dotdot_subvolume(self):
        tmp, run_root, manifest = self.fresh_paths()
        self.create_unprivileged(run_root, manifest)
        doc = json.loads(Path(manifest).read_text())
        doc["evidence"]["btrfs_subvolumes"] = [".."]
        Path(manifest).write_text(json.dumps(doc))
        proc = run_tool("cleanup", "--run-root", run_root,
                        "--manifest", manifest)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("foreign subvolume refused",
                      proc.stdout + proc.stderr)
        self.assertTrue(os.path.isdir(run_root),
                        "root must survive subvolume refusal")

    def test_create_refuses_missing_manifest_parent_without_effects(self):
        tmp = Path(tempfile.mkdtemp(prefix="provision-f09-"))
        self.addCleanup(
            shutil.rmtree, tmp, ignore_errors=True)
        run_root = str(tmp / "run")
        manifest = str(tmp / "no-such-dir" / "manifest.json")
        proc = run_tool("create", "--run-root", run_root,
                        "--manifest", manifest)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("manifest not creatable", proc.stderr)
        self.assertFalse(os.path.exists(run_root),
                         "no anchor residue on manifest failure")
        self.assertFalse(os.path.exists(manifest))

    def test_create_failure_preserves_partial_manifest(self):
        import types
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        args = types.SimpleNamespace(run_root=run_root,
                                     manifest=manifest,
                                     privileged=False)
        real = provision.create_unprivileged

        def boom(manifest_doc, root):
            real(manifest_doc, root)
            raise provision.AdmissionError("injected mid-create failure")

        with mock.patch.object(provision, "create_unprivileged",
                               side_effect=boom):
            rc = provision.create_command(args)
        self.assertEqual(rc, 2)
        self.assertIsNone(provision._PERSIST)
        doc = json.loads(Path(manifest).read_text())
        self.assertEqual(doc["status"], "failed")
        self.assertIn("injected mid-create failure", doc["error"])
        self.assertTrue(doc["files"],
                        "partial custody must persist acquisitions")
        st = os.stat(run_root)
        self.assertEqual(doc["run_root_identity"],
                         {"dev": st.st_dev, "ino": st.st_ino})
        # The partial manifest retires what it records.
        self.assertEqual(provision.cleanup_command(args), 0)
        self.assertFalse(os.path.exists(run_root))

    def test_cleanup_missing_manifest_with_residue_refuses(self):
        tmp = Path(tempfile.mkdtemp(prefix="provision-f09-"))
        self.addCleanup(
            shutil.rmtree, tmp, ignore_errors=True)
        run_root = str(tmp / "run")
        manifest = str(tmp / "manifest.json")
        os.makedirs(run_root)
        Path(run_root, "residue.txt").write_text("residue")
        proc = run_tool("cleanup", "--run-root", run_root,
                        "--manifest", manifest)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("residue without manifest", proc.stdout)
        self.assertTrue(os.path.exists(run_root),
                        "residue must survive refusal")
        shutil.rmtree(run_root)
        proc = run_tool("cleanup", "--run-root", run_root,
                        "--manifest", manifest)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("nothing provisioned", proc.stdout)

    def test_manifest_records_lifecycle_and_identity(self):
        tmp, run_root, manifest = self.fresh_paths()
        self.create_unprivileged(run_root, manifest)
        doc = json.loads(Path(manifest).read_text())
        self.assertEqual(doc["status"], "complete")
        st = os.stat(run_root)
        self.assertEqual(doc["run_root_identity"],
                         {"dev": st.st_dev, "ino": st.st_ino})
        proc = run_tool("cleanup", "--run-root", run_root,
                        "--manifest", manifest)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class MountinfoPredicateTests(unittest.TestCase):
    ROW = (
        "45 1 0:35 /@ / rw,noatime shared:1 - btrfs /dev/sda3 "
        "rw,compress=zstd:3,subvolid=256,subvol=/@"
    )

    def test_parse_valid_row(self):
        row = provision.parse_mountinfo_row(self.ROW)
        self.assertEqual(row["mnt_id"], 45)
        self.assertEqual(row["target"], "/")
        self.assertEqual(row["fstype"], "btrfs")
        self.assertEqual(row["source"], "/dev/sda3")
        self.assertIn("subvol=/@", row["super"])

    def test_parse_rejects_malformed_rows(self):
        for bad in ("", "45 1", "45 1 0:35 /@ / rw shared:1 btrfs x y",
                    "xx 1 0:35 /@ / rw shared:1 - btrfs /dev/sda3 rw"):
            with self.assertRaises(provision.AdmissionError, msg=bad):
                provision.parse_mountinfo_row(bad)

    def test_find_mounts_returns_every_row_at_target(self):
        table = [provision.parse_mountinfo_row(self.ROW)]
        hits = provision.find_mounts(table, "/")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["mnt_id"], 45)
        self.assertEqual(provision.find_mounts(table, "/etc"), [])
        # Prefix matches are not mount matches.
        self.assertEqual(provision.find_mounts([], "/"), [])
        stacked = table + [dict(table[0], mnt_id=99)]
        self.assertEqual(len(provision.find_mounts(stacked, "/")), 2)

    def test_contained_rejects_escapes(self):
        self.assertTrue(provision.contained("/tmp/run/a", "/tmp/run"))
        self.assertTrue(provision.contained("/tmp/run", "/tmp/run"))
        self.assertFalse(provision.contained("/tmp/run2", "/tmp/run"))
        self.assertFalse(provision.contained("/tmp/run/../etc", "/tmp/run"))
        self.assertFalse(provision.contained("/etc", "/tmp/run"))

    def test_admit_mount_checks_identity(self):
        table = [provision.parse_mountinfo_row(self.ROW)]
        record = {"role": "root", "target": "/", "fstype": "btrfs",
                  "source": "/dev/sda3", "mnt_id": 45}
        provision.admit_mount(record, table, "/")
        with self.assertRaises(provision.AdmissionError):
            provision.admit_mount({**record, "mnt_id": 46}, table, "/")
        with self.assertRaises(provision.AdmissionError):
            provision.admit_mount({**record, "fstype": "ext4"}, table, "/")
        with self.assertRaises(provision.AdmissionError):
            provision.admit_mount({**record, "target": "/etc"}, table, "/")


class RereviewCustodyTests(unittest.TestCase):
    """R14-R24/R42: descriptor-bound retirement, stacked-mount and
    reuse refusal, timeout custody, shell-free wrappers, exclusive
    manifest updates, decoded mount paths, denial-vs-absence."""

    def fresh_paths(self):
        tmp = Path(tempfile.mkdtemp(prefix="provision-rb7-"))
        self.addCleanup(
            shutil.rmtree, tmp, ignore_errors=True)
        return tmp, str(tmp / "run"), str(tmp / "manifest.json")

    # R24: mountinfo escapes decode before any containment check.
    def test_unescape_decodes_octal_escapes(self):
        row = provision.parse_mountinfo_row(
            "45 1 0:35 /@/a\\040b /mnt/x\\040y rw shared:1 - ext4 "
            "/dev/sda\\0401 rw")
        self.assertEqual(row["target"], "/mnt/x y")
        self.assertEqual(row["source"], "/dev/sda 1")
        self.assertEqual(provision.unescape_mountinfo("a\\134b"), "a\\b")
        self.assertEqual(provision.unescape_mountinfo("a\\011b"), "a\tb")
        self.assertEqual(provision.unescape_mountinfo("a\\012b"), "a\nb")

    def test_unescape_refuses_unknown_escape(self):
        for bad in ("a\\099b", "a\\", "a\\04", "\\777"):
            with self.assertRaises(provision.AdmissionError, msg=bad):
                provision.unescape_mountinfo(bad)

    def test_escaped_space_mount_stays_inside_guard(self):
        # A space-bearing run-root with a foreign descendant mount:
        # the escaped row must decode to a contained target, or the
        # foreign-mount guard would miss it.
        row = provision.parse_mountinfo_row(
            "77 1 0:41 / /tmp/run\\040x/foreign rw shared:1 - "
            "tmpfs tmpfs rw")
        self.assertTrue(
            provision.contained(row["target"], "/tmp/run x"),
            f"escaped mount evades guard: {row['target']!r}")

    # R17: stacked mounts refuse; the lower row never stands in
    # for the mount a pathname umount would remove.
    def test_admit_mount_refuses_stacked_targets(self):
        from unittest import mock
        run_root = "/tmp/provision-stacked-case"
        target = f"{run_root}/mnt"
        record = {"target": target, "mnt_id": 111, "fstype": "ext4",
                  "source": "/dev/loop9", "expect_super": []}
        stacked = [
            {"target": target, "mnt_id": 111, "fstype": "ext4",
             "source": "/dev/loop9", "super": "rw|"},
            {"target": target, "mnt_id": 222, "fstype": "tmpfs",
             "source": "tmpfs", "super": "rw|"},
        ]
        with self.assertRaisesRegex(provision.AdmissionError,
                                    "ambiguous stacked mount"):
            provision.admit_mount(record, stacked, run_root)
        with mock.patch.object(provision, "read_mount_table",
                               return_value=stacked):
            with mock.patch.object(provision, "run_sudo") as sudo:
                failure = provision.cleanup_one_mount(record, run_root)
        self.assertIn("ambiguous stacked mount", failure)
        sudo.assert_not_called()

    # R18: churn teardown only retires the recorded payload bind.
    def churn_record(self, tmp):
        run_root = str(tmp / "run")
        point = os.path.join(run_root, "churn", "point")
        payload = os.path.join(run_root, "churn", "payload-b")
        os.makedirs(os.path.dirname(point), exist_ok=True)
        Path(payload).write_bytes(b"payload-b")
        Path(point).write_bytes(b"point")
        st = os.stat(payload)
        churn = {"fifo": os.path.join(run_root, "churn", "cmd.fifo"),
                 "ack": os.path.join(run_root, "churn", "ack.txt"),
                 "ledger": os.path.join(run_root, "churn", "ledger.log"),
                 "point": point, "bind_source": payload,
                 "bind_source_dev": st.st_dev,
                 "bind_source_ino": st.st_ino}
        return run_root, churn

    def test_churn_point_absent_is_noop(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=[]):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    self.assertIsNone(provision.cleanup_churn_point(
                        churn, run_root))
                    sudo.assert_not_called()

    # S19: realistic bind rows — the source names the
    # filesystem, the bound object is proven by live identity.
    def churn_live_row(self, churn, source="/dev/sda3",
                       fstype="ext4", root="/@/churn/payload-b"):
        return {"target": churn["point"], "mnt_id": 9,
                "root": root, "fstype": fstype, "source": source,
                "super": "rw|"}

    def test_churn_point_refuses_foreign_occupant(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            live = [self.churn_live_row(churn, source="/foreign",
                                        fstype="tmpfs", root="/")]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_churn_point(
                        churn, run_root)
            self.assertIn("bind object identity changed", failure)
            sudo.assert_not_called()

    def test_churn_point_refuses_stacked_mounts(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            row = self.churn_live_row(churn)
            live = [row, dict(row, mnt_id=10)]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_churn_point(
                        churn, run_root)
            self.assertIn("stacked mounts", failure)
            sudo.assert_not_called()

    def test_churn_point_refuses_fabricated_source(self):
        from unittest import mock
        # A row whose source names the payload file is fabricated:
        # real binds list the filesystem source. Even with the
        # object identity matching (hardlinked point), it refuses.
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            os.unlink(churn["point"])
            os.link(churn["bind_source"], churn["point"])
            live = [{"target": churn["point"], "mnt_id": 9,
                     "root": "/", "fstype": "ext4",
                     "source": churn["bind_source"], "super": "rw|"}]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_churn_point(
                        churn, run_root)
            self.assertIn("fabricated mount", failure)
            sudo.assert_not_called()

    def test_churn_point_refuses_resourced_source(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            # Same payload pathname, fresh inode: not our bind.
            os.unlink(churn["bind_source"])
            Path(churn["bind_source"]).write_bytes(b"fresh")
            live = [self.churn_live_row(churn)]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_churn_point(
                        churn, run_root)
            self.assertIn("bind object identity changed", failure)
            sudo.assert_not_called()

    def test_churn_point_unmounts_owned_bind(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            # A bind covers the point with the payload object: the
            # hardlink reproduces that identity without privilege.
            os.unlink(churn["point"])
            os.link(churn["bind_source"], churn["point"])
            live = [self.churn_live_row(churn)]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(
                        provision, "run_sudo",
                        return_value=(0, "retired-mount x\n",
                                      "")) as sudo:
                    self.assertIsNone(provision.cleanup_churn_point(
                        churn, run_root))
                    argv = sudo.call_args[0][0]
                    self.assertIn("retire-mount", argv)
                    self.assertNotIn("umount", argv)

    def driver_functions(self, *names):
        import ast
        # Exercise the SHIPPED driver code: extract every function
        # from the driver source (the gate calls its siblings) and
        # return the requested ones.
        tree = ast.parse(provision.CHURN_DRIVER_PY)
        wanted = [node for node in tree.body
                  if isinstance(node, ast.FunctionDef)]
        self.assertTrue({n.name for n in wanted} >= set(names))
        module = ast.Module(body=wanted, type_ignores=[])
        namespace = {"os": os}
        exec(compile(module, "<driver>", "exec"), namespace)  # noqa: S102
        return [namespace[name] for name in names]

    def test_driver_restore_gate_checks_owned_bind(self):
        from unittest import mock
        (gate,) = self.driver_functions("owned_bind_only")
        with tempfile.TemporaryDirectory() as tmp:
            point = str(Path(tmp) / "point")
            payload = str(Path(tmp) / "payload-b")
            Path(payload).write_bytes(b"payload")
            Path(point).write_bytes(b"point")
            st = os.stat(payload)
            owned = (f"90 1 0:50 /@/x/payload-b {point} rw shared:1 "
                     f"- ext4 /dev/sda3 rw\n")
            fabricated = (f"90 1 0:50 / {point} rw shared:1 - ext4 "
                          f"{payload} rw\n")
            foreign = (f"90 1 0:50 / {point} rw shared:1 - tmpfs "
                       f"/foreign rw\n")
            table = Path(tmp) / "mountinfo"
            env = {"TT04_MOUNTINFO": str(table)}
            # Mounted state: the point shows the payload object.
            os.unlink(point)
            os.link(payload, point)
            table.write_text(owned)
            with mock.patch.dict(os.environ, env):
                self.assertTrue(
                    gate(point, payload, st.st_dev, st.st_ino))
            # The OLD fabricated shape (source names the payload)
            # refuses even with matching identity.
            table.write_text(fabricated)
            with mock.patch.dict(os.environ, env):
                self.assertFalse(
                    gate(point, payload, st.st_dev, st.st_ino))
            # Unmounted state: the point shows its own object.
            os.unlink(point)
            Path(point).write_bytes(b"point")
            table.write_text(owned)
            with mock.patch.dict(os.environ, env):
                self.assertFalse(
                    gate(point, payload, st.st_dev, st.st_ino))
            # Foreign occupant: the point shows a foreign object.
            table.write_text(foreign)
            with mock.patch.dict(os.environ, env):
                self.assertFalse(
                    gate(point, payload, st.st_dev, st.st_ino))
            os.unlink(point)
            os.link(payload, point)
            table.write_text(owned + owned.replace("90 1 ", "91 1 "))
            with mock.patch.dict(os.environ, env):
                self.assertFalse(
                    gate(point, payload, st.st_dev, st.st_ino))
            with mock.patch.dict(os.environ, {"TT04_MOUNTINFO": str(
                    Path(tmp) / "no-such-table")}):
                self.assertFalse(
                    gate(point, payload, st.st_dev, st.st_ino))

    def test_driver_unescape_matches_host(self):
        (unescape,) = self.driver_functions("unescape_mnt")
        cases = ["a\\040b", "a\\011b", "a\\012b", "a\\134b",
                 "plain", "\\040\\134", "/@/x\\040y/z"]
        for case in cases:
            self.assertEqual(unescape(case),
                             provision.unescape_mountinfo(case),
                             case)
        for bad in ("a\\099b", "a\\", "a\\04", "\\777"):
            self.assertIsNone(unescape(bad), bad)
            with self.assertRaises(provision.AdmissionError, msg=bad):
                provision.unescape_mountinfo(bad)

    def test_driver_detaches_in_process(self):
        # The restore path must not shell out to umount between
        # validation and effect: the shipped driver detaches via
        # in-process umount2.
        self.assertIn("umount2", provision.CHURN_DRIVER_PY)
        self.assertNotIn('"umount"', provision.CHURN_DRIVER_PY)
        self.assertNotIn("'umount'", provision.CHURN_DRIVER_PY)

    # R20: aux roots are identity-bound at acquisition.
    def test_cleanup_aux_root_retires_owned_tree(self):
        if not (os.path.isdir("/dev/shm")
                and os.access("/dev/shm", os.W_OK)):
            self.skipTest("/dev/shm not writable here")
        aux = tempfile.mkdtemp(prefix="tt04-", dir="/dev/shm")
        self.addCleanup(shutil.rmtree, aux, ignore_errors=True)
        os.makedirs(os.path.join(aux, "lower"), mode=0o755)
        Path(aux, "lower", "shared.txt").write_text("shared")
        st = os.stat(aux)
        record = {"path": aux, "dev": st.st_dev, "ino": st.st_ino}
        self.assertIsNone(provision.cleanup_aux_root(record))
        self.assertFalse(os.path.exists(aux))

    def test_cleanup_aux_root_unlinks_links_without_following(self):
        if not (os.path.isdir("/dev/shm")
                and os.access("/dev/shm", os.W_OK)):
            self.skipTest("/dev/shm not writable here")
        with tempfile.TemporaryDirectory() as tmp:
            canary = Path(tmp) / "canary.txt"
            canary.write_text("canary")
            aux = tempfile.mkdtemp(prefix="tt04-", dir="/dev/shm")
            self.addCleanup(shutil.rmtree, aux, ignore_errors=True)
            os.symlink(str(canary), os.path.join(aux, "file-link"))
            os.symlink(tmp, os.path.join(aux, "dir-link"))
            st = os.stat(aux)
            record = {"path": aux, "dev": st.st_dev, "ino": st.st_ino}
            self.assertIsNone(provision.cleanup_aux_root(record))
            self.assertFalse(os.path.exists(aux))
            self.assertEqual(canary.read_text(), "canary")

    def test_cleanup_aux_root_refuses_replacement(self):
        if not (os.path.isdir("/dev/shm")
                and os.access("/dev/shm", os.W_OK)):
            self.skipTest("/dev/shm not writable here")
        aux = tempfile.mkdtemp(prefix="tt04-", dir="/dev/shm")
        self.addCleanup(shutil.rmtree, aux, ignore_errors=True)
        st = os.stat(aux)
        record = {"path": aux, "dev": st.st_dev, "ino": st.st_ino}
        moved = aux + "-orig"
        os.rename(aux, moved)
        self.addCleanup(shutil.rmtree, moved, ignore_errors=True)
        os.makedirs(aux)
        canary = os.path.join(aux, "canary.txt")
        Path(canary).write_text("canary")
        failure = provision.cleanup_aux_root(record)
        self.assertIn("replacement refused", failure)
        self.assertEqual(Path(canary).read_text(), "canary")
        self.assertTrue(os.path.isdir(moved))

    def test_cleanup_aux_root_missing_is_noop(self):
        record = {"path": "/dev/shm/tt04-no-such-aux-abcdef",
                  "dev": 1, "ino": 2}
        self.assertIsNone(provision.cleanup_aux_root(record))
        self.assertIn("malformed",
                      provision.cleanup_aux_root("/dev/shm/tt04-x"))
        self.assertIn("foreign", provision.cleanup_aux_root(
            {"path": "/tmp/tt04-x", "dev": 1, "ino": 2}))

    # R21: timeouts are custody-preserving failures, never escapes;
    # unrecorded sleepers are killed, never orphaned.
    def test_run_sudo_reports_timeout(self):
        from unittest import mock
        with mock.patch.object(
                provision.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(
                    ["sudo", "-n", "true"], 120)):
            rc, _, err = provision.run_sudo(["true"], timeout=120)
        self.assertEqual(rc, 124)
        self.assertIn("timed out", err)

    # S18-round3: string-level loop-identity tests — the kernel
    # ioctl is unavailable here, so the sysfs fallback governs
    # (hermetic: no /dev dependence in any uid).
    @mock.patch.object(
        provision, "read_loop_backing_id",
        side_effect=provision.LoopIdUnavailable("test"))
    def test_ext4_mount_timeout_detaches_loop_and_persists(self, _loop_id):
        import types
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if "make-ext4" in argv:
                return (0, "made-ext4 x\n", "")
            if "attach-loop" in argv:
                return (0, "attached-loop /dev/loop9\n", "")
            if "retire-loop" in argv:
                return (0, "retired-loop /dev/loop9\n", "")
            if "mount-fs" in argv:
                return (124, "", "sudo timed out after 120s: mount-fs")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        provision._PERSIST = manifest
        guard = provision.RootAuthority(run_root)
        provision._ROOT_GUARD = guard
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                with mock.patch.object(provision.shutil, "which",
                                       return_value="/sbin/x"):
                    image = os.path.join(run_root, "ext4", "fs01.img")
                    with mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image):
                        with mock.patch.object(
                                provision, "read_mount_table",
                                return_value=[]):
                            provision.provision_ext4(doc, run_root)
        finally:
            provision._PERSIST = None
            provision._ROOT_GUARD = None
            guard.close()
        # The attached loop is detached on the mount timeout: no
        # orphan. The detach is ownership-verified (the mocked
        # backing matches the created image) and runs through the
        # retire helper — no bare losetup -d. Custody was
        # persisted BEFORE the mount call.
        helper_calls = [c for c in calls if "retire-loop" in c]
        self.assertEqual(len(helper_calls), 1)
        self.assertFalse(any(c[:2] == ["losetup", "-d"] for c in calls))
        self.assertIn("timed out", doc["cells"]["FS01"]["reason"])
        persisted = json.loads(Path(manifest).read_text())
        self.assertEqual(persisted["evidence"]["ext4_loop"],
                         "/dev/loop9")
        backing = persisted["evidence"]["ext4_loop_backing"]
        self.assertEqual(backing["path"],
                         os.path.join(run_root, "ext4", "fs01.img"))
        self.assertIn("dev", backing)
        self.assertIn("ino", backing)

    def test_spawn_sleeper_kills_tree_when_leaf_missing(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            report = str(Path(tmp) / "sleeper.report")
            # A real pipe carrying the ready line: the bounded
            # readiness poll needs a pollable stream.
            reader, writer = os.pipe()
            try:
                os.write(writer, b"ready\n")
                stdout = os.fdopen(reader, "rb")
            finally:
                os.close(writer)
            child = mock.Mock()
            child.pid = 424242
            child.stdout = stdout
            try:
                with mock.patch.object(provision.subprocess, "Popen",
                                       return_value=child):
                    with mock.patch.object(
                            provision, "resolve_leaf",
                            side_effect=provision.AdmissionError(
                                "no stable leaf")):
                        with mock.patch.object(
                                provision, "kill_tree",
                                return_value=True) as killer:
                            with self.assertRaises(
                                    provision.AdmissionError):
                                provision.spawn_sleeper(
                                    Path(tmp) / "helper.py",
                                    str(Path(tmp) / "target.bin"),
                                    report, ["wrapper"])
                killer.assert_called_once_with("sleeper-wrapper", 424242)
            finally:
                stdout.close()

    # S21-round4: a spawn failure refreshes the armed wrapper
    # record in place (one persist, observed starttime kept)
    # instead of dropping then re-recording — the durable set
    # never holds neither mid-transition.
    def test_spawn_failure_refreshes_armed_record(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            report = str(Path(tmp) / "sleeper.report")
            reader, writer = os.pipe()
            try:
                os.write(writer, b"ready\n")
                stdout = os.fdopen(reader, "rb")
            finally:
                os.close(writer)
            child = mock.Mock()
            child.pid = 424242
            child.stdout = stdout
            path = os.path.join(tmp, "manifest.json")
            doc = provision.fresh_manifest(tmp, True)
            provision.save_manifest(doc, path)
            provision._PERSIST = path
            saves = []
            real_save = provision.save_manifest

            def counting_save(manifest, where):
                saves.append(where)
                return real_save(manifest, where)

            try:
                with mock.patch.object(provision.subprocess,
                                       "Popen",
                                       return_value=child), \
                        mock.patch.object(
                            provision, "resolve_leaf",
                            side_effect=provision.AdmissionError(
                                "no stable leaf")), \
                        mock.patch.object(
                            provision, "kill_tree",
                            return_value=False), \
                        mock.patch.object(
                            provision, "stat_state_start",
                            return_value=("R", 555)), \
                        mock.patch.object(
                            provision, "save_manifest",
                            side_effect=counting_save):
                    with self.assertRaises(
                            provision.AdmissionError):
                        provision.spawn_sleeper(
                            Path(tmp) / "helper.py",
                            str(Path(tmp) / "target.bin"),
                            report, ["wrapper"], doc,
                            role="w", leaf_role="wl")
            finally:
                stdout.close()
                provision._PERSIST = None
            # Arm (1) + refresh (1): pre-fix the failure wrote
            # drop + record (3 total).
            self.assertEqual(len(saves), 2)
            kept = doc["pending_procs"]
            self.assertEqual(len(kept), 1)
            self.assertEqual(kept[0]["pid"], 424242)
            self.assertEqual(kept[0]["starttime"], 555)
            self.assertIn("not proven gone", kept[0]["detail"])
            disk = json.loads(Path(path).read_text())
            self.assertEqual(len(disk["pending_procs"]), 1)

    def test_kill_tree_kills_wrapper_and_descendants(self):
        child = subprocess.Popen(
            ["sh", "-c", "sleep 60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            import time as _time
            deadline = _time.time() + 10
            while (_time.time() < deadline
                   and not provision.child_pids(child.pid)):
                _time.sleep(0.05)
            self.assertTrue(provision.child_pids(child.pid),
                            "fixture produced no child to kill")
            self.assertTrue(provision.kill_tree("test-tree",
                                                child.pid, timeout=5))
            child.wait(timeout=10)
            self.assertEqual(provision.child_pids(child.pid), [])
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()
        # An already-dead root is vacuously gone.
        self.assertTrue(provision.kill_tree("test-dead", child.pid))

    # S104-round6: a recycled root number holding a stranger is
    # never pinned, signalled, or descended into; the original
    # is proven gone and the stranger survives untouched.
    def test_kill_tree_recycled_root_never_signals_stranger(self):
        stranger = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _, live_start = provision.stat_state_start(
                stranger.pid)
            armed = {stranger.pid: live_start + 1000000}
            self.assertTrue(provision.kill_tree(
                "test-recycled", stranger.pid, timeout=5,
                armed=armed))
            self.assertIsNone(
                stranger.poll(),
                "recycled number must not be signalled")
        finally:
            try:
                stranger.kill()
            except OSError:
                pass
            stranger.wait()

    # S104-round6: a known leaf reparented away from an absent
    # wrapper still reconciles independently — it is signalled
    # and proven gone even though the root walk finds nothing.
    def test_kill_tree_reconciles_reparented_known_leaf(self):
        leaf = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _, leaf_start = provision.stat_state_start(leaf.pid)
            dead = subprocess.Popen(["true"])
            dead.wait()
            armed = {dead.pid: 1, leaf.pid: leaf_start}
            self.assertTrue(provision.kill_tree(
                "test-reparented", dead.pid, timeout=10,
                armed=armed))
            self.assertIsNotNone(
                leaf.poll(), "known leaf must be retired")
        finally:
            try:
                leaf.kill()
            except OSError:
                pass
            leaf.wait()

    # R22: run-root text never becomes privileged shell code.
    def test_bind_wrapper_treats_paths_as_argv(self):
        evil_alt = "/tmp/tt04; touch CANARY; #"
        evil_view = "/tmp/with space/view"
        wrapper = provision.bind_view_wrapper(evil_alt, evil_view)
        script = wrapper[wrapper.index("-c") + 1]
        self.assertNotIn(evil_alt, script)
        self.assertNotIn(evil_view, script)
        self.assertIn(evil_alt, wrapper)
        self.assertIn(evil_view, wrapper)
        # LIVE: run the shipped script with a stub mount; the
        # metacharacters must arrive as inert argv and no canary
        # may appear outside.
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "bin"
            stub.mkdir()
            log = Path(tmp) / "mount-args.txt"
            (stub / "mount").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$@" > '
                f"{log}\n")
            (stub / "mount").chmod(0o755)
            canary = Path(tmp) / "CANARY"
            env = dict(os.environ)
            env["PATH"] = f"{stub}{os.pathsep}{env['PATH']}"
            proc = subprocess.run(
                ["sh", "-c", script, "tt04-view",
                 evil_alt, evil_view, "/bin/true"],
                capture_output=True, text=True, env=env,
                cwd=tmp, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(canary.exists(),
                             "shell metacharacters executed")
            self.assertEqual(
                log.read_text().splitlines(),
                ["--bind", evil_alt, evil_view])

    # R23: manifest updates use exclusive unpredictable temp files.
    def test_save_manifest_ignores_predictable_tmp_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = str(Path(tmp) / "manifest.json")
            victim = Path(tmp) / "victim.txt"
            victim.write_text("victim")
            # The OLD predictable name, preplanted as a symlink.
            os.symlink(str(victim),
                       f"{manifest}.tmp-{os.getpid()}")
            provision.save_manifest({"k": "v"}, manifest)
            self.assertEqual(victim.read_text(), "victim")
            self.assertEqual(
                json.loads(Path(manifest).read_text()), {"k": "v"})
            self.assertTrue(os.path.islink(
                f"{manifest}.tmp-{os.getpid()}"))

    def test_save_manifest_replaces_manifest_symlink_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = str(Path(tmp) / "manifest.json")
            victim = Path(tmp) / "victim.txt"
            victim.write_text("victim")
            os.symlink(str(victim), manifest)
            provision.save_manifest({"k": "v"}, manifest)
            self.assertFalse(os.path.islink(manifest))
            self.assertEqual(
                json.loads(Path(manifest).read_text()), {"k": "v"})
            self.assertEqual(victim.read_text(), "victim")

    def test_save_manifest_cleans_temp_on_replace_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A directory AT the manifest path: os.replace fails.
            manifest = str(Path(tmp) / "adir")
            os.makedirs(manifest)
            with self.assertRaises(provision.AdmissionError):
                provision.save_manifest({"k": "v"}, manifest)
            leftovers = [p.name for p in Path(tmp).iterdir()
                         if p.name.startswith(".tt04-manifest-")]
            self.assertEqual(leftovers, [])

    # R42: denial is unresolved cleanup, never a false retire.
    def test_denied_run_root_fails_not_retired(self):
        tmp, _, manifest = self.fresh_paths()
        sub = tmp / "sub"
        sub.mkdir()
        run_root = str(sub / "run")
        created = run_tool("create", "--manifest", manifest,
                           "--run-root", run_root)
        self.assertEqual(created.returncode, 0, created.stderr)
        os.chmod(sub, 0)
        try:
            proc = run_tool("cleanup", "--manifest", manifest,
                            "--run-root", run_root)
        finally:
            os.chmod(sub, 0o755)
        self.assertEqual(proc.returncode, 1,
                         proc.stdout + proc.stderr)
        self.assertIn("not provably absent",
                      proc.stdout + proc.stderr)
        self.assertTrue(os.path.isdir(run_root),
                        "denied root must survive, never report retired")
        proc = run_tool("cleanup", "--manifest", manifest,
                        "--run-root", run_root)
        self.assertEqual(proc.returncode, 0,
                         proc.stdout + proc.stderr)
        self.assertFalse(os.path.exists(run_root))

    def test_loop_backing_denial_raises_not_detached(self):
        from unittest import mock
        with mock.patch("builtins.open",
                        side_effect=PermissionError("denied")):
            with self.assertRaises(provision.AdmissionError):
                provision.read_loop_backing("/dev/loop7")
        with mock.patch("builtins.open",
                        side_effect=FileNotFoundError("gone")):
            self.assertIsNone(
                provision.read_loop_backing("/dev/loop7"))

    # R15/R16: descriptor-relative retirement, no sudo for plain
    # fixtures, privileged re-exec only on denial.
    def test_plain_fixture_cleanup_never_calls_sudo(self):
        import types
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        # Hide btrfs(8) from create: subvolume teardown
        # legitimately needs privilege, and this test pins the
        # plain-file path (R15: no sudo chmod/chown/rm fallback).
        emptybin = tmp / "emptybin"
        emptybin.mkdir()
        created = run_tool("create", "--manifest", manifest,
                           "--run-root", run_root,
                           env={"PATH": str(emptybin)})
        self.assertEqual(created.returncode, 0, created.stderr)
        args = types.SimpleNamespace(run_root=run_root,
                                     manifest=manifest)
        with mock.patch.object(
                provision, "run_sudo",
                side_effect=AssertionError("sudo must not run")):
            self.assertEqual(provision.cleanup_command(args), 0)
        self.assertFalse(os.path.exists(run_root))

    def test_remove_pinned_tree_clears_nested_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir(mode=0o755)
            (tree / "sub").mkdir(mode=0o755)
            (tree / "sub" / "deep").mkdir(mode=0o755)
            (tree / "sub" / "deep" / "f.txt").write_text("f")
            (tree / "top.txt").write_text("top")
            canary = Path(tmp) / "canary.txt"
            canary.write_text("canary")
            os.symlink(str(canary), tree / "file-link")
            os.symlink(tmp, tree / "dir-link")
            st = os.stat(tree)
            parent_fd = os.open(
                base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                self.assertIsNone(provision.remove_pinned_tree(
                    parent_fd, "tree", (st.st_dev, st.st_ino)))
            finally:
                os.close(parent_fd)
            self.assertFalse(os.path.exists(tree))
            self.assertEqual(canary.read_text(), "canary")

    def test_remove_pinned_tree_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir()
            (tree / "owned.txt").write_text("owned")
            st = os.stat(tree)
            expected = (st.st_dev, st.st_ino)
            os.rename(tree, base / "orig")
            tree.mkdir()
            canary = tree / "canary.txt"
            canary.write_text("canary")
            parent_fd = os.open(
                base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                failure = provision.remove_pinned_tree(
                    parent_fd, "tree", expected)
            finally:
                os.close(parent_fd)
            self.assertIn("replacement refused", failure)
            self.assertEqual(canary.read_text(), "canary")
            self.assertTrue((base / "orig").is_dir())

    def test_remove_pinned_tree_refuses_hardlinked_entry(self):
        # S13: the nested unlink proof fires on multi-linked
        # entries. A hardlink planted inside the tree would
        # survive any single unlink, so removal refuses loudly
        # instead of reporting success over a surviving inode.
        # (Pre-proof code returned None, unlinking both names
        # across two visits.) The fifo exercises the O_PATH
        # walk: holding it never opens its data, so the walk
        # cannot block on it.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir(mode=0o755)
            (tree / "sub").mkdir(mode=0o755)
            (tree / "sub" / "f.txt").write_text("f")
            (tree / "a.txt").write_text("linked")
            os.link(tree / "a.txt", tree / "b.txt")
            os.mkfifo(tree / "pipe")
            st = os.stat(tree)
            parent_fd = os.open(
                base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                failure = provision.remove_pinned_tree(
                    parent_fd, "tree", (st.st_dev, st.st_ino))
            finally:
                os.close(parent_fd)
            self.assertIn("replaced during removal", failure)
            # The refused removal unlinked at most the
            # first-visited name (readdir order is unspecified);
            # the inode itself survives — that survival is
            # exactly what the proof reports.
            survivor = [
                p for p in (tree / "a.txt", tree / "b.txt")
                if p.exists() and p.read_text() == "linked"]
            self.assertTrue(
                survivor,
                "refused removal destroyed the inode it claimed "
                "survived")

    def test_remove_pinned_tree_refuses_shared_nested_dir(self):
        # S13-round3: a loosened nested directory refuses before
        # deleting inside it — another UID could rename under a
        # group/other-writable directory. The nested content and
        # the tree stand fully intact (pre-gate code cleared and
        # removed the whole tree here).
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir(mode=0o755)
            sub = tree / "sub"
            sub.mkdir(mode=0o755)
            (sub / "precious.txt").write_text("precious")
            os.chmod(sub, 0o777)
            st = os.stat(tree)
            parent_fd = os.open(
                base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                failure = provision.remove_pinned_tree(
                    parent_fd, "tree", (st.st_dev, st.st_ino))
            finally:
                os.close(parent_fd)
            self.assertIn("not exclusive", failure)
            self.assertEqual((sub / "precious.txt").read_text(),
                             "precious")
            self.assertTrue(tree.is_dir())

    def test_remove_pinned_tree_refuses_unexcluded_parent(self):
        # S13-round3: a group/other-writable non-sticky parent
        # refuses before clearing anything (fail fast, tree fully
        # in place). Pre-gate code cleared and removed the whole
        # tree here.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir(mode=0o755)
            (tree / "owned.txt").write_text("owned")
            os.chmod(base, 0o775)
            st = os.stat(tree)
            parent_fd = os.open(
                base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                failure = provision.remove_pinned_tree(
                    parent_fd, "tree", (st.st_dev, st.st_ino))
            finally:
                os.close(parent_fd)
            self.assertIn("not excluded", failure)
            self.assertEqual((tree / "owned.txt").read_text(), "owned")
            self.assertTrue(tree.is_dir())

    def test_remove_pinned_tree_allows_sticky_shared_parent(self):
        # S13-round3: the designed shared shape — a sticky parent
        # holding our own entry — still removes: sticky rename
        # needs entry ownership, which only our euid has, so no
        # foreign swapper can be inside the window. Pins the
        # admission against over-refusal regressions.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir(mode=0o755)
            (tree / "sub").mkdir(mode=0o755)
            (tree / "sub" / "f.txt").write_text("f")
            os.chmod(base, 0o1777)
            st = os.stat(tree)
            parent_fd = os.open(
                base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                self.assertIsNone(provision.remove_pinned_tree(
                    parent_fd, "tree", (st.st_dev, st.st_ino)))
            finally:
                os.close(parent_fd)
            self.assertFalse(os.path.exists(tree))

    def test_removal_refuses_foreign_owned_sticky_parent(self):
        # S13-round4: a foreign-owned sticky parent with a
        # privileged remover. The parent owner bypasses the
        # sticky bit, so the sticky exception needs a trusted
        # parent owner too — otherwise the remover's final
        # rmdir deletes the owner's replacement while the
        # post-unlink proof only detects it afterwards. A
        # root-owned sticky parent (e.g. /dev/shm) stays
        # admitted. Pre-fix the verdict was "" (excluded).
        from unittest import mock
        alien = 65000 if os.geteuid() != 65000 else 65001

        def stat_of(mode, uid):
            return os.stat_result(
                (0o040000 | mode, 1, 2, 2, uid, 100, 0, 0, 0, 0))

        def verdict(parent_uid):
            fakes = [stat_of(0o1755, parent_uid),
                     stat_of(0o755, 0)]
            with mock.patch.object(
                    provision.os, "fstat",
                    side_effect=fakes), \
                    mock.patch.object(
                        provision.os, "geteuid", return_value=0):
                return provision._removal_excluded(11, 12)

        # Privileged remover, foreign-owned sticky parent: a
        # hard refusal (no privilege level closes the window),
        # never a privileged-retry "denied:".
        failure = verdict(alien)
        self.assertIn("not excluded", failure)
        self.assertNotIn("denied:", failure)
        # Root-owned sticky parent stays excluded.
        self.assertEqual(verdict(0), "")

    def test_removal_gates_survive_uid_transition(self):
        # S75-round4: the exclusion policy is valid across the
        # caller-to-root cleanup transition. Evaluated as root
        # with SUDO_UID naming the controller, the
        # controller's exclusive directories pass both gates
        # (sticky or exclusive parent); without the controller
        # identity they deny; a genuinely foreign owner still
        # denies. Pre-fix the transition verdicts were denials.
        from unittest import mock
        me = os.geteuid()
        if me == 0:
            self.skipTest("no controller/helper UID transition for root")
        alien = 65000 if me != 65000 else 65001
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir(mode=0o700)
            (tree / "f.txt").write_text("f")

            def verdicts(mode):
                os.chmod(base, mode)
                parent_fd = os.open(
                    base,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                root_fd = os.open(
                    tree,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    with mock.patch.object(
                            provision.os, "geteuid",
                            return_value=0), \
                            mock.patch.dict(
                                provision.os.environ,
                                {"SUDO_UID": str(me)}):
                        transition = provision._removal_excluded(
                            parent_fd, root_fd)
                        provision._require_exclusive_dir(
                            root_fd, "tree")
                    with mock.patch.object(
                            provision.os, "geteuid",
                            return_value=0), \
                            mock.patch.dict(
                                provision.os.environ, {},
                                clear=True):
                        scrubbed = provision._removal_excluded(
                            parent_fd, root_fd)
                        with self.assertRaises(OSError):
                            provision._require_exclusive_dir(
                                root_fd, "tree")
                    with mock.patch.object(
                            provision.os, "geteuid",
                            return_value=0), \
                            mock.patch.dict(
                                provision.os.environ,
                                {"SUDO_UID": str(alien)}):
                        foreign = provision._removal_excluded(
                            parent_fd, root_fd)
                    return (transition, scrubbed, foreign)
                finally:
                    os.close(parent_fd)
                    os.close(root_fd)

            for mode in (0o700, 0o1777):
                with self.subTest(mode=oct(mode)):
                    transition, scrubbed, foreign = verdicts(mode)
                    self.assertEqual(transition, "")
                    self.assertIn("denied:", scrubbed)
                    self.assertIn("denied:", foreign)

    def test_retire_helper_roundtrip_across_uid_transition(self):
        # S75-round4: the retire-helper command end to end under
        # a mocked caller-to-root transition — with SUDO_UID
        # naming the owner the privileged removal retires the
        # user-owned tree; without it the helper refuses with
        # the tree standing.
        from unittest import mock
        import types
        me = os.geteuid()
        if me == 0:
            self.skipTest("no controller/helper UID transition for root")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir(mode=0o700)
            (tree / "sub").mkdir(mode=0o700)
            (tree / "sub" / "f.txt").write_text("f")
            st = os.stat(tree)
            args = types.SimpleNamespace(
                parent=str(base), name="tree", dev=st.st_dev,
                ino=st.st_ino)
            with mock.patch.object(
                    provision.os, "geteuid", return_value=0), \
                    mock.patch.dict(
                        provision.os.environ,
                        {"SUDO_UID": str(me)}):
                self.assertEqual(
                    provision.retire_helper_command(args), 0)
            self.assertFalse(os.path.exists(tree))
            # Without the controller identity the helper
            # refuses and the tree stands.
            tree.mkdir(mode=0o700)
            (tree / "canary.txt").write_text("canary")
            st = os.stat(tree)
            args = types.SimpleNamespace(
                parent=str(base), name="tree", dev=st.st_dev,
                ino=st.st_ino)
            with mock.patch.object(
                    provision.os, "geteuid", return_value=0), \
                    mock.patch.dict(
                        provision.os.environ, {}, clear=True):
                self.assertEqual(
                    provision.retire_helper_command(args), 1)
            self.assertEqual(
                (tree / "canary.txt").read_text(), "canary")

    def test_retire_helper_roundtrip_and_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir(mode=0o700)
            tree = base / "tree"
            tree.mkdir(mode=0o755)
            (tree / "sub").mkdir(mode=0o755)
            (tree / "sub" / "f.txt").write_text("f")
            st = os.stat(tree)
            # Unprivileged end-to-end of the helper sudo would run.
            proc = run_tool(
                "retire-helper", "--parent", str(base),
                "--name", "tree", "--dev", str(st.st_dev),
                "--ino", str(st.st_ino))
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("retired tree", proc.stdout)
            self.assertFalse(os.path.exists(tree))
            # Wrong identity refuses with the tree standing.
            tree.mkdir(mode=0o755)
            (tree / "canary.txt").write_text("canary")
            proc = run_tool(
                "retire-helper", "--parent", str(base),
                "--name", "tree", "--dev", str(st.st_dev),
                "--ino", str(st.st_ino + 1000000))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("FAILED", proc.stdout)
            self.assertEqual((tree / "canary.txt").read_text(),
                             "canary")

    def test_retire_helper_rejects_bad_spellings(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ("../x", "a/b", "", ".", ".."):
                proc = run_tool(
                    "retire-helper", "--parent", str(tmp),
                    "--name", bad, "--dev", "1", "--ino", "2")
                self.assertEqual(proc.returncode, 1, bad)
                self.assertIn("bad helper name", proc.stdout)
            proc = run_tool(
                "retire-helper", "--parent", "relative",
                "--name", "x", "--dev", "1", "--ino", "2")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("not absolute", proc.stdout)


class SecondReviewTests(unittest.TestCase):
    """S15-S28: retained root authority, bounded admission,
    protected manifest publication, denial-vs-absence, owned
    rollback, timeout reconcile, single-process retirement,
    process custody/pinning, bounded readiness, traversal
    mount guards."""

    def fresh_paths(self):
        tmp = Path(tempfile.mkdtemp(prefix="provision-sb5-"))
        self.addCleanup(
            shutil.rmtree, tmp, ignore_errors=True)
        return tmp, str(tmp / "run"), str(tmp / "manifest.json")

    # S15: creation, writes, privileged calls, and inspection bind
    # to the retained root descriptor.
    def test_root_authority_refuses_swapped_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir()
            auth = provision.RootAuthority(str(root))
            try:
                auth.verify()
                auth.write_bytes("a.txt", b"a")
                self.assertEqual((root / "a.txt").read_bytes(), b"a")
                # Swap the pathname for a fresh directory: every
                # further operation fails loudly, and nothing lands
                # in the replacement.
                os.rename(root, Path(tmp) / "orig")
                root.mkdir()
                with self.assertRaises(provision.RootReplacedError):
                    auth.verify()
                with self.assertRaises(provision.RootReplacedError):
                    auth.write_bytes("held.txt", b"held")
                self.assertFalse((root / "held.txt").exists())
                self.assertEqual(
                    (Path(tmp) / "orig" / "a.txt").read_bytes(), b"a")
            finally:
                auth.close()

    def test_root_authority_rejects_escapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir()
            auth = provision.RootAuthority(str(root))
            try:
                for bad in ("", "../x", "/abs", "a/../../x", "a\x00b",
                            "sub/../kept.txt"):
                    with self.assertRaises(
                            provision.RootAuthorityError, msg=bad):
                        auth.write_bytes(bad, b"x")
            finally:
                auth.close()

    def test_inspect_refuses_swapped_root(self):
        tmp, run_root, manifest = self.fresh_paths()
        created = run_tool("create", "--manifest", manifest,
                           "--run-root", run_root)
        self.assertEqual(created.returncode, 0, created.stderr)
        os.rename(run_root, str(tmp / "orig"))
        os.makedirs(run_root)
        Path(run_root, "canary.txt").write_text("canary")
        proc = run_tool("inspect", "--manifest", manifest,
                        "--run-root", run_root)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("replacement refused", proc.stdout)

    def test_create_fails_when_root_swapped_mid_create(self):
        import types
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        args = types.SimpleNamespace(run_root=run_root,
                                     manifest=manifest,
                                     privileged=False)
        real = provision.create_unprivileged

        def swap_after_create(manifest_doc, root):
            real(manifest_doc, root)
            os.rename(root, str(tmp / "orig"))
            os.makedirs(root)

        with mock.patch.object(provision, "create_unprivileged",
                               side_effect=swap_after_create):
            rc = provision.create_command(args)
        self.assertEqual(rc, 2)
        doc = json.loads(Path(manifest).read_text())
        self.assertEqual(doc["status"], "failed")
        self.assertIn("replaced", doc["error"])

    # S28: one nonblocking open, descriptor type/identity check,
    # capped read — devices, FIFOs, growth, replacements.
    def test_record_file_refuses_special_objects_fast(self):
        import time as _time
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"files": []}
            zero = str(Path(tmp) / "zero")
            os.symlink("/dev/zero", zero)
            start = _time.time()
            with self.assertRaises(provision.AdmissionError):
                provision.record_file(manifest, "zero", zero)
            self.assertLess(_time.time() - start, 5)
            fifo = str(Path(tmp) / "pipe")
            os.mkfifo(fifo)
            start = _time.time()
            with self.assertRaises(provision.AdmissionError):
                provision.record_file(manifest, "fifo", fifo)
            self.assertLess(_time.time() - start, 5)
            self.assertEqual(manifest["files"], [])

    def test_record_file_refuses_oversize_and_growth(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"files": []}
            big = Path(tmp) / "big.bin"
            big.write_bytes(b"x" * (provision.MAX_FILE_BYTES + 1))
            with self.assertRaises(provision.AdmissionError):
                provision.record_file(manifest, "big", str(big))
            # Size-zero pseudofiles still hit the read cap.
            with self.assertRaises(provision.AdmissionError):
                provision.read_regular_capped("/proc/self/mountinfo", 10)
            reader, writer = os.pipe()
            try:
                os.write(writer, b"y" * 100)
                with self.assertRaises(provision.AdmissionError):
                    provision.read_capped_from_fd(reader, 10)
            finally:
                os.close(reader)
                os.close(writer)
            ok = Path(tmp) / "ok.bin"
            ok.write_bytes(b"ok")
            provision.record_file(manifest, "ok", str(ok))
            self.assertEqual(manifest["files"][0]["size"], 2)

    def test_admit_file_refuses_replacement_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"files": []}
            target = str(Path(tmp) / "a.bin")
            Path(target).write_bytes(b"bytes")
            provision.record_file(manifest, "a", target)
            record = manifest["files"][0]
            provision.admit_file(record, tmp)
            os.unlink(target)
            os.symlink("/dev/null", target)
            with self.assertRaises(provision.AdmissionError):
                provision.admit_file(record, tmp)
            os.unlink(target)
            os.makedirs(target)
            with self.assertRaises(provision.AdmissionError):
                provision.admit_file(record, tmp)

    def test_load_manifest_refuses_special_and_oversize(self):
        import time as _time
        with tempfile.TemporaryDirectory() as tmp:
            zero = str(Path(tmp) / "manifest.json")
            os.symlink("/dev/zero", zero)
            start = _time.time()
            with self.assertRaises(provision.AdmissionError):
                provision.load_manifest(zero, tmp)
            self.assertLess(_time.time() - start, 5)
            big = str(Path(tmp) / "big.json")
            Path(big).write_bytes(b"{" + b"x" * provision.MAX_FILE_BYTES)
            with self.assertRaises(provision.AdmissionError):
                provision.load_manifest(big, tmp)

    # S26: mountinfo and loop backing decode byte-preserving.
    def test_mountinfo_preserves_non_utf8_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root_b = os.path.join(os.fsencode(tmp), b"run\xffx")
            os.mkdir(root_b)
            root = os.fsdecode(root_b)
            target_b = root_b + b"/foreign"
            line = (b"77 1 0:41 / " + target_b
                    + b" rw shared:1 - tmpfs tmpfs rw\n")
            table = Path(tmp) / "mountinfo"
            table.write_bytes(line)
            rows = provision.read_mount_table(str(table))
            self.assertEqual(len(rows), 1)
            self.assertNotIn("�", rows[0]["target"])
            self.assertTrue(
                provision.contained(rows[0]["target"], root),
                f"non-UTF-8 mount evades guard: {rows[0]['target']!r}")

    def test_driver_gate_preserves_non_utf8_bytes(self):
        import ast
        from unittest import mock
        tree = ast.parse(provision.CHURN_DRIVER_PY)
        wanted = [node for node in tree.body
                  if isinstance(node, ast.FunctionDef)]
        module = ast.Module(body=wanted, type_ignores=[])
        namespace = {"os": os}
        exec(compile(module, "<driver>", "exec"), namespace)  # noqa: S102
        gate = namespace["owned_bind_only"]
        with tempfile.TemporaryDirectory() as tmp:
            point_b = os.path.join(os.fsencode(tmp), b"po\xffint")
            payload_b = os.path.join(os.fsencode(tmp), b"pay\xffload")
            with open(payload_b, "wb") as handle:
                handle.write(b"payload")
            os.link(payload_b, point_b)
            point, payload = (os.fsdecode(point_b),
                              os.fsdecode(payload_b))
            st = os.stat(payload_b)
            line = (b"90 1 0:50 /@/x " + point_b
                    + b" rw shared:1 - ext4 /dev/sda3 rw\n")
            table = Path(tmp) / "mountinfo"
            table.write_bytes(line)
            with mock.patch.dict(os.environ, {"TT04_MOUNTINFO": str(table)}):
                self.assertTrue(
                    gate(point, payload, st.st_dev, st.st_ino))

    # S25: protected publication directory + temp identity proof.
    def test_save_manifest_refuses_shared_unprotected_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared"
            shared.mkdir()
            os.chmod(shared, 0o777)
            self.assertFalse(shared.stat().st_mode & 0o1000)
            manifest = str(shared / "manifest.json")
            with self.assertRaisesRegex(
                    provision.AdmissionError, "unprotected"):
                provision.save_manifest({"k": "v"}, manifest)
            self.assertFalse(os.path.exists(manifest))
            leftovers = [p.name for p in shared.iterdir()
                         if p.name.startswith(".tt04-manifest-")]
            self.assertEqual(leftovers, [])
            # Group-writable (umask 002 collaboration dirs) and
            # sticky world-writable (/tmp-style) parents publish.
            for mode, name in ((0o775, "group"), (0o1777, "sticky")):
                parent = Path(tmp) / name
                parent.mkdir()
                os.chmod(parent, mode)
                target = str(parent / "manifest.json")
                provision.save_manifest({"k": "v"}, target)
                self.assertEqual(
                    json.loads(Path(target).read_text()), {"k": "v"})

    def test_save_manifest_proves_temp_identity(self):
        from unittest import mock
        # Barrier-controlled post-creation replacement: swap the
        # temp file after its fsync, before publish. Publication
        # must refuse and must not unlink the foreign file.
        with tempfile.TemporaryDirectory() as tmp:
            manifest = str(Path(tmp) / "manifest.json")
            attacker = Path(tmp) / "attacker.json"
            attacker.write_bytes(b'{"evil": true}')
            orig_fsync = os.fsync
            swapped = []

            def hook(fd):
                if not swapped:
                    swapped.append(True)
                    temps = [p for p in Path(tmp).iterdir()
                             if p.name.startswith(".tt04-manifest-")]
                    self.assertEqual(len(temps), 1)
                    os.replace(str(attacker), str(temps[0]))
                return orig_fsync(fd)

            with mock.patch.object(provision.os, "fsync",
                                   side_effect=hook):
                with self.assertRaisesRegex(
                        provision.AdmissionError, "replaced"):
                    provision.save_manifest({"k": "v"}, manifest)
            self.assertFalse(os.path.exists(manifest))
            temps = [p for p in Path(tmp).iterdir()
                     if p.name.startswith(".tt04-manifest-")]
            self.assertEqual(len(temps), 1)
            self.assertEqual(temps[0].read_bytes(), b'{"evil": true}')

    # S20: proven absence vs denial at cleanup entry.
    def test_cleanup_denied_manifest_and_root_fails(self):
        tmp, _, manifest = self.fresh_paths()
        sub = tmp / "sub"
        sub.mkdir()
        run_root = str(sub / "run")
        manifest = str(sub / "manifest.json")
        created = run_tool("create", "--manifest", manifest,
                           "--run-root", run_root)
        self.assertEqual(created.returncode, 0, created.stderr)
        os.chmod(sub, 0)
        try:
            proc = run_tool("cleanup", "--manifest", manifest,
                            "--run-root", run_root)
        finally:
            os.chmod(sub, 0o755)
        self.assertEqual(proc.returncode, 1,
                         proc.stdout + proc.stderr)
        self.assertIn("not provably",
                      proc.stdout + proc.stderr)
        self.assertTrue(os.path.isdir(run_root),
                        "denied residue must survive, never retire")
        proc = run_tool("cleanup", "--manifest", manifest,
                        "--run-root", run_root)
        self.assertEqual(proc.returncode, 0,
                         proc.stdout + proc.stderr)
        self.assertFalse(os.path.exists(run_root))

    # S18: the recorded backing is the held image, verified live.
    # S18-round3: string-level loop-identity tests — the kernel
    # ioctl is unavailable here, so the sysfs fallback governs
    # (hermetic: no /dev dependence in any uid).
    @mock.patch.object(
        provision, "read_loop_backing_id",
        side_effect=provision.LoopIdUnavailable("test"))
    def test_losetup_backing_swap_detected(self, _loop_id):
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if "make-ext4" in argv:
                return (0, "made-ext4 x\n", "")
            if "attach-loop" in argv:
                # Replace the image between attach and identity
                # recording: same spelling, fresh inode.
                image = os.path.join(run_root, "ext4", "fs01.img")
                os.unlink(image)
                Path(image).write_bytes(b"replacement-image")
                return (0, "attached-loop /dev/loop9\n", "")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        provision._PERSIST = manifest
        guard = provision.RootAuthority(run_root)
        provision._ROOT_GUARD = guard
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                with mock.patch.object(provision.shutil, "which",
                                       return_value="/sbin/x"):
                    image = os.path.join(run_root, "ext4", "fs01.img")
                    with mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image):
                        provision.provision_ext4(doc, run_root)
        finally:
            provision._PERSIST = None
            provision._ROOT_GUARD = None
            guard.close()
        # The replacement inode is never recorded as ours; the
        # acquisition stays pending and no mount is attempted.
        self.assertIn("not ours", doc["cells"]["FS01"]["reason"])
        self.assertNotIn("ext4_loop", doc["evidence"])
        pending = [e for e in doc["pending_acquisitions"]
                   if e["kind"] == "loop"]
        self.assertEqual(len(pending), 1)
        self.assertFalse(any("mount-fs" in c for c in calls))

    # S16: rollback removes only provably-owned occupants.
    # S18-round3: string-level loop-identity tests — the kernel
    # ioctl is unavailable here, so the sysfs fallback governs
    # (hermetic: no /dev dependence in any uid).
    @mock.patch.object(
        provision, "read_loop_backing_id",
        side_effect=provision.LoopIdUnavailable("test"))
    def test_ext4_rollback_preserves_stacked_mount(self, _loop_id):
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if "make-ext4" in argv:
                return (0, "made-ext4 x\n", "")
            if "attach-loop" in argv:
                return (0, "attached-loop /dev/loop9\n", "")
            if "retire-mount" in argv:
                return (1, "", "FAILED: ambiguous stacked mount")
            if "retire-loop" in argv:
                return (0, "retired-loop /dev/loop9\n", "")
            if "mount-fs" in argv:
                tgt = argv[argv.index("--target") + 1]
                return (0, f"mounted {tgt} mnt=1 "
                           f"source=/dev/loop9 super=rw|\n", "")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        provision._PERSIST = manifest
        guard = provision.RootAuthority(run_root)
        provision._ROOT_GUARD = guard
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                with mock.patch.object(provision.shutil, "which",
                                       return_value="/sbin/x"):
                    image = os.path.join(run_root, "ext4", "fs01.img")
                    mnt = os.path.join(run_root, "ext4", "mnt")
                    row = {"target": mnt, "mnt_id": 1,
                           "root": "/", "fstype": "ext4",
                           "source": "/dev/loop9", "super": "rw|"}
                    stacked = [row, dict(row, mnt_id=2)]
                    with mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image):
                        with mock.patch.object(
                                provision, "read_mount_table",
                                return_value=stacked):
                            provision.provision_ext4(doc, run_root)
        finally:
            provision._PERSIST = None
            provision._ROOT_GUARD = None
            guard.close()
        # The foreign top mount is not removed: no bare umount,
        # and custody stays pending.
        self.assertFalse(any(c[:1] == ["umount"] for c in calls))
        self.assertFalse(any(c[:2] == ["losetup", "-d"] for c in calls))
        self.assertTrue(any("retire-mount" in c for c in calls))
        self.assertIn("pending", doc["cells"]["FS01"]["reason"])
        pending = [e for e in doc["pending_acquisitions"]
                   if e["kind"] == "mount" and e["key"] == mnt]
        self.assertEqual(len(pending), 1)

    def test_overlay_rollback_preserves_foreign_mount(self):
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if "mount-fs" in argv:
                tgt = argv[argv.index("--target") + 1]
                return (0, f"mounted {tgt} mnt=1 "
                           f"source=overlay super=rw|\n", "")
            if "retire-mount" in argv:
                return (1, "", "FAILED: ambiguous stacked mount")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        doc["cells"]["FS04"] = {"status": "skipped",
                                "needs_privilege": True, "reason": ""}
        provision._PERSIST = manifest
        guard = provision.RootAuthority(run_root)
        provision._ROOT_GUARD = guard
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                merged = os.path.join(run_root, "ov-xino-off",
                                      "merged")
                row = {"target": merged, "mnt_id": 1,
                       "root": "/", "fstype": "overlay",
                       "source": "overlay", "super": "rw|"}
                stacked = [row, dict(row, mnt_id=2)]
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=stacked):
                    ok = provision.mount_overlay(
                        doc, run_root, "ov-xino-off",
                        ",xino=off,metacopy=off", "FS04")
        finally:
            provision._PERSIST = None
            provision._ROOT_GUARD = None
            guard.close()
        self.assertFalse(ok)
        self.assertFalse(any(c[:1] == ["umount"] for c in calls))
        self.assertIn("pending", doc["cells"]["FS04"]["reason"])
        pending = [e for e in doc["pending_acquisitions"]
                   if e["kind"] == "mount" and e["key"] == merged]
        self.assertEqual(len(pending), 1)

    # S74-round4 end to end: the helper reports FAILED-MOVED and
    # the overlay arm keeps ID-keyed pending custody (mount ID
    # plus observed mountpoint) with an uncertain cell — the
    # moved mount is never dropped from the manifest.
    def test_overlay_moved_mount_keeps_id_custody(self):
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)

        def fake_sudo(argv, timeout=120):
            if "mount-fs" in argv:
                tgt = argv[argv.index("--target") + 1]
                return (1, f"FAILED-MOVED: mnt=42 observed={tgt}2 "
                           f"target moved during mount\n", "")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        doc["cells"]["FS04"] = {"status": "skipped",
                                "needs_privilege": True, "reason": ""}
        provision._PERSIST = manifest
        guard = provision.RootAuthority(run_root)
        provision._ROOT_GUARD = guard
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                merged = os.path.join(run_root, "ov-xino-off",
                                      "merged")
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[]):
                    ok = provision.mount_overlay(
                        doc, run_root, "ov-xino-off",
                        ",xino=off,metacopy=off", "FS04")
        finally:
            provision._PERSIST = None
            provision._ROOT_GUARD = None
            guard.close()
        self.assertFalse(ok)
        self.assertIn("custody kept pending",
                      doc["cells"]["FS04"]["reason"])
        pending = [e for e in doc["pending_acquisitions"]
                   if e["kind"] == "mount" and e["key"] == merged]
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["mnt_id"], 42)
        self.assertEqual(pending[0]["observed_target"],
                         f"{merged}2")
        self.assertIn("canary", pending[0])

    # S23: uncertain timeout outcomes reconcile through kernel
    # identity, never the lost reply.
    def test_reconcile_loop_attach_adopts_clears_or_retains(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            doc = provision.fresh_manifest(tmp, True)
            doc["pending_acquisitions"] = [{
                "kind": "loop", "key": image, "image": image,
                "dev": st.st_dev, "ino": st.st_ino}]
            with mock.patch.object(
                    provision, "scan_loop_by_backing",
                    return_value=(["/dev/loop9"], False)):
                self.assertEqual(
                    provision.reconcile_loop_attach(
                        doc, image, st.st_dev, st.st_ino),
                    "/dev/loop9")
            self.assertEqual(doc["evidence"]["ext4_loop"],
                             "/dev/loop9")
            self.assertEqual(doc["pending_acquisitions"], [])
            doc["pending_acquisitions"] = [{
                "kind": "loop", "key": image, "image": image,
                "dev": st.st_dev, "ino": st.st_ino}]
            with mock.patch.object(
                    provision, "scan_loop_by_backing",
                    return_value=([], False)):
                self.assertIsNone(provision.reconcile_loop_attach(
                    doc, image, st.st_dev, st.st_ino))
            self.assertEqual(doc["pending_acquisitions"], [])
            doc["pending_acquisitions"] = [{
                "kind": "loop", "key": image, "image": image,
                "dev": st.st_dev, "ino": st.st_ino}]
            with mock.patch.object(
                    provision, "scan_loop_by_backing",
                    return_value=(["/dev/loop9", "/dev/loop10"], False)):
                self.assertIsNone(provision.reconcile_loop_attach(
                    doc, image, st.st_dev, st.st_ino))
            self.assertEqual(len(doc["pending_acquisitions"]), 1)

    def test_losetup_timeout_adopts_attached_loop(self):
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if "make-ext4" in argv:
                return (0, "made-ext4 x\n", "")
            if "attach-loop" in argv:
                # Attached, but the device name never came back.
                return (124, "", "sudo timed out after 120s: attach")
            if "mount-fs" in argv:
                tgt = argv[argv.index("--target") + 1]
                return (0, f"mounted {tgt} mnt=7 "
                           f"source=/dev/loop9 super=rw|\n", "")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        provision._PERSIST = manifest
        guard = provision.RootAuthority(run_root)
        provision._ROOT_GUARD = guard
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                with mock.patch.object(provision.shutil, "which",
                                       return_value="/sbin/x"):
                    mnt = os.path.join(run_root, "ext4", "mnt")
                    row = {"target": mnt, "mnt_id": 7,
                           "root": "/", "fstype": "ext4",
                           "source": "/dev/loop9", "super": "rw|"}
                    with mock.patch.object(
                            provision, "scan_loop_by_backing",
                            return_value=(["/dev/loop9"], False)):
                        with mock.patch.object(
                                provision, "read_mount_table",
                                return_value=[row]):
                            provision.provision_ext4(doc, run_root)
        finally:
            provision._PERSIST = None
            provision._ROOT_GUARD = None
            guard.close()
        self.assertEqual(doc["cells"]["FS01"]["status"], "provisioned")
        self.assertEqual(doc["evidence"]["ext4_loop"], "/dev/loop9")
        self.assertEqual(doc["pending_acquisitions"], [])
        self.assertTrue(any(e["role"] == "ext4-fs01"
                            for e in doc["mounts"]))

    # S18-round3: string-level loop-identity tests — the kernel
    # ioctl is unavailable here, so the sysfs fallback governs
    # (hermetic: no /dev dependence in any uid).
    @mock.patch.object(
        provision, "read_loop_backing_id",
        side_effect=provision.LoopIdUnavailable("test"))
    def test_mount_timeout_keeps_pending_custody(self, _loop_id):
        # S74-round4 contract change: a mount timeout means the
        # effect may have fired (the helper reported nothing),
        # so pending custody is kept — never discharged from
        # target absence — while the loop still detaches and
        # the reason still names the timeout. (Previously the
        # empty table dropped the pending record, leaking a
        # mount that had moved off its target.)
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)

        def fake_sudo(argv, timeout=120):
            if "make-ext4" in argv:
                return (0, "made-ext4 x\n", "")
            if "attach-loop" in argv:
                return (0, "attached-loop /dev/loop9\n", "")
            if "retire-loop" in argv:
                return (0, "retired-loop /dev/loop9\n", "")
            if "mount-fs" in argv:
                return (124, "", "sudo timed out after 120s: mount-fs")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        provision._PERSIST = manifest
        guard = provision.RootAuthority(run_root)
        provision._ROOT_GUARD = guard
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                with mock.patch.object(provision.shutil, "which",
                                       return_value="/sbin/x"):
                    image = os.path.join(run_root, "ext4", "fs01.img")
                    with mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image):
                        with mock.patch.object(
                                provision, "read_mount_table",
                                return_value=[]):
                            provision.provision_ext4(doc, run_root)
        finally:
            provision._PERSIST = None
            provision._ROOT_GUARD = None
            guard.close()
        # Timeout: custody kept, loop detached, honest reason.
        self.assertIn("timed out", doc["cells"]["FS01"]["reason"])
        self.assertIn("custody kept pending",
                      doc["cells"]["FS01"]["reason"])
        kept = [e for e in doc["pending_acquisitions"]
                if e.get("kind") == "mount"]
        self.assertEqual(len(kept), 1)
        self.assertIn("uncertain", kept[0]["detail"])

    # S17: validation/effect-boundary substitutions refuse; every
    # effect is post-verified; no bare umount/detach exists.
    def test_retire_mount_validates_effect_boundary(self):
        from unittest import mock
        # S17-round3: the retire path snapshots the target
        # directory's mount ID at open, so the fixture is a real
        # directory and mocked rows carry its real mount ID.
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            held = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                ours = provision._mnt_id_of(held)
            finally:
                os.close(held)
            expected = {"mnt_id": ours, "fstype": "ext4",
                        "source": "/dev/loop9", "expect_super": []}
            ok = {"target": target, "mnt_id": ours, "root": "/",
                  "fstype": "ext4", "source": "/dev/loop9",
                  "super": "rw|"}
            foreign = {"target": target, "mnt_id": ours + 1000,
                       "root": "/", "fstype": "tmpfs",
                       "source": "tmpfs", "super": "rw|"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ok], [foreign]]):
                with mock.patch.object(
                        provision, "_umount2") as detach:
                    failure = provision.retire_mount_now(
                        target, expected, run_root)
            self.assertIn("between validation and effect", failure)
            detach.assert_not_called()

    def test_retire_mount_verifies_post_effect(self):
        from unittest import mock
        # S17-round3: real directory fixture (see above); the
        # post-effect assertions are unchanged.
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            held = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                ours = provision._mnt_id_of(held)
            finally:
                os.close(held)
            expected = {"mnt_id": ours, "fstype": "ext4",
                        "source": "/dev/loop9", "expect_super": []}
            ok = {"target": target, "mnt_id": ours, "root": "/",
                  "fstype": "ext4", "source": "/dev/loop9",
                  "super": "rw|"}
            # S17-round5: move-verify-detach — fixed staging
            # path, scripted move, four table reads (validate,
            # effect, staging, post); the detach addresses
            # staging, never the shared target.
            staging = os.path.join(run_root, "staging")
            staged = dict(ok, target=staging)
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ok], [ok], [staged],
                                 [staged]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            return_value=None) as detach:
                    failure = provision.retire_mount_now(
                        target, expected, run_root)
            self.assertIn("still live", failure)
            detach.assert_called_once_with(staging)
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ok], [ok], [staged], []]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            return_value=None):
                    self.assertIsNone(provision.retire_mount_now(
                        target, expected, run_root))

    # S17-round3: the ioctl seam is scripted hermetically
    # (no /dev dependence in any uid) — the final
    # kernel-identity validate, the CLR, and the post-proof all
    # address one held device fd.
    def test_retire_loop_validates_effect_boundary(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            backing = {"path": image, "dev": st.st_dev,
                       "ino": st.st_ino}
            other = str(Path(tmp) / "other.img")
            Path(other).write_bytes(b"other")
            ost = os.stat(other)

            def run(sysfs, script, clr_errno=None):
                fake_open, fake_ioctl, log = _loop_fd_script(
                    script, clr_errno=clr_errno)
                with mock.patch.object(provision,
                                       "read_loop_backing",
                                       side_effect=sysfs), \
                        mock.patch.object(provision.os, "open",
                                          side_effect=fake_open), \
                        mock.patch.object(provision.fcntl, "ioctl",
                                          side_effect=fake_ioctl):
                    return (provision.retire_loop_now(
                        "/dev/loop7", backing, tmp), log)

            # Foreign identity at the final kernel gate (after
            # the last sysfs observation): refuse, CLR never
            # issued.
            failure, log = run(
                [image], [("id", ost.st_dev, ost.st_ino)])
            self.assertIn("between validation and effect", failure)
            self.assertFalse(any(
                e[0] == "ioctl" and
                e[2] == provision.LOOP_CLR_FD for e in log))
            # Still attached after the effect: the CLR ran but
            # the binding persists — custody retained.
            failure, log = run(
                [image],
                [("id", st.st_dev, st.st_ino),
                 ("id", st.st_dev, st.st_ino)])
            self.assertIn("still attached", failure)
            self.assertIn("custody retained", failure)
            # Happy path: validate, CLR, ENXIO proof.
            result, log = run(
                [image],
                [("id", st.st_dev, st.st_ino), ("enxio",)])
            self.assertIsNone(result)
            clrs = [e for e in log
                    if e[0] == "ioctl" and
                    e[2] == provision.LOOP_CLR_FD]
            self.assertEqual(len(clrs), 1)

    def test_retire_helpers_absent_is_noop(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=[]):
                with mock.patch.object(provision, "_umount2") as detach:
                    self.assertIsNone(provision.retire_mount_now(
                        f"{tmp}/mnt", {"fstype": "ext4",
                                       "source": "/dev/loop9",
                                       "expect_super": []}, tmp))
                    detach.assert_not_called()
            backing = {"path": f"{tmp}/fs01.img", "dev": 1, "ino": 2}
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=None):
                with mock.patch.object(
                        provision, "_loop_clr_fd_on") as detach:
                    self.assertIsNone(provision.retire_loop_now(
                        "/dev/loop7", backing, tmp))
                    detach.assert_not_called()

    def test_retire_cli_wires_absent_and_foreign(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_tool(
                "retire-mount", "--run-root", tmp,
                "--target", f"{tmp}/mnt",
                "--fstype", "ext4", "--source", "/dev/loop9")
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("retired-mount", proc.stdout)
            proc = run_tool(
                "retire-mount", "--run-root", tmp,
                "--target", "/etc/tt04-evil",
                "--fstype", "ext4", "--source", "/dev/loop9")
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("foreign", proc.stdout)
            proc = run_tool(
                "retire-loop", "--run-root", tmp,
                "--loop", "/dev/loopTT04nope",
                "--backing-path", f"{tmp}/fs01.img",
                "--backing-dev", "1", "--backing-ino", "2")
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("retired-loop", proc.stdout)

    # S21: unknowns and survivors keep custody; absence is proven.
    def test_kill_owned_unknown_is_not_gone(self):
        from unittest import mock
        child = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            _, start = provision.stat_state_start(child.pid)
            with mock.patch.object(
                    provision, "stat_state_start",
                    side_effect=provision.ProcUnknown("denied")):
                with mock.patch("os.kill") as killer:
                    with self.assertRaises(provision.ProcUnknown):
                        provision.kill_owned("test", child.pid, start)
                    killer.assert_not_called()
            # Still alive: nothing was signalled.
            provision.stat_state_start(child.pid)
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()

    def test_kill_owned_absence_is_gone(self):
        child = subprocess.Popen(
            ["true"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        child.wait()
        self.assertTrue(provision.kill_owned("test", child.pid, 1))

    def test_kill_tree_unknown_discovery_is_not_gone(self):
        from unittest import mock
        child = subprocess.Popen(
            ["sh", "-c", "sleep 60"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            import time as _time
            deadline = _time.time() + 10
            while (_time.time() < deadline
                   and not provision.child_pids(child.pid)):
                _time.sleep(0.05)
            self.assertTrue(provision.child_pids(child.pid))
            real = provision.child_pids_with_errors

            def tainted(ppid):
                found, _ = real(ppid)
                return found, 1

            with mock.patch.object(provision, "child_pids_with_errors",
                                   side_effect=tainted):
                self.assertFalse(
                    provision.kill_tree("test", child.pid, timeout=5))
            child.wait(timeout=10)
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()

    def test_spawn_failure_persists_pending_when_tree_survives(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            report = str(Path(tmp) / "sleeper.report")
            reader, writer = os.pipe()
            try:
                os.write(writer, b"nope\n")
                stdout = os.fdopen(reader, "rb")
            finally:
                os.close(writer)
            child = mock.Mock()
            child.pid = 424242
            child.stdout = stdout
            doc = provision.fresh_manifest(tmp, True)
            try:
                with mock.patch.object(provision.subprocess, "Popen",
                                       return_value=child):
                    with mock.patch.object(
                            provision, "kill_tree",
                            return_value=False):
                        with self.assertRaises(
                                provision.AdmissionError):
                            provision.spawn_sleeper(
                                Path(tmp) / "helper.py",
                                str(Path(tmp) / "target.bin"),
                                report, ["wrapper"], doc)
            finally:
                stdout.close()
            self.assertEqual(len(doc["pending_procs"]), 1)
            pending = doc["pending_procs"][0]
            self.assertEqual(pending["pid"], 424242)
            self.assertIn("not proven gone", pending["detail"])

    def test_cleanup_reports_unidentified_live_pending(self):
        import types
        child = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            tmp, run_root, manifest = self.fresh_paths()
            os.makedirs(run_root, mode=0o755)
            st = os.stat(run_root)
            doc = provision.fresh_manifest(run_root, False)
            doc["run_root_identity"] = {"dev": st.st_dev,
                                        "ino": st.st_ino}
            doc["pending_procs"] = [{
                "role": "stray", "pid": child.pid,
                "starttime": None, "detail": "never identified"}]
            Path(manifest).write_text(json.dumps(doc))
            args = types.SimpleNamespace(run_root=run_root,
                                         manifest=manifest)
            self.assertEqual(provision.cleanup_command(args), 1)
            self.assertTrue(os.path.isdir(run_root))
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()
        # Once the stray exits, the pending record converges.
        self.assertEqual(provision.cleanup_command(args), 0)
        self.assertFalse(os.path.exists(run_root))

    # S22: signals ride retained pins; reuse cannot redirect them.
    def test_kill_owned_refuses_reused_identity(self):
        from unittest import mock
        child = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            _, start = provision.stat_state_start(child.pid)
            with mock.patch("os.kill") as killer:
                # S21-round5: the refusal is the typed
                # identity-change outcome (the only outcome a
                # caller may treat as proven-stale).
                with self.assertRaisesRegex(
                        provision.ProcIdentityChanged,
                        "starttime changed"):
                    provision.kill_owned("test", child.pid,
                                         start + 10 ** 9)
                killer.assert_not_called()
            provision.stat_state_start(child.pid)
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()

    def test_pin_held_across_signal(self):
        import signal as _signal
        child = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            _, start = provision.stat_state_start(child.pid)
            orig_send = provision._pidfd_send_signal
            checked = []

            def checking_send(pin_fd, signum):
                # S22-round4: the signal addresses a pidfd, never
                # the numeric pid — exit+reap+reuse past the last
                # observation fails closed instead of redirecting.
                self.assertEqual(
                    os.readlink(f"/proc/self/fd/{pin_fd}"),
                    "anon_inode:[pidfd]")
                checked.append(signum)
                return orig_send(pin_fd, signum)

            from unittest import mock
            with mock.patch("os.kill") as killer, \
                    mock.patch.object(
                        provision, "_pidfd_send_signal",
                        side_effect=checking_send):
                self.assertTrue(
                    provision.kill_owned("test", child.pid, start,
                                         timeout=5))
                killer.assert_not_called()
            self.assertTrue(checked)
            child.wait(timeout=10)
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()

    def test_signal_owned_requires_open_pin(self):
        import signal as _signal
        from unittest import mock
        pid = os.getpid()
        _, start = provision.stat_state_start(pid)
        pin = provision.pin_proc(pid)
        os.close(pin)
        with mock.patch("os.kill") as killer:
            with self.assertRaises(provision.ProcUnknown):
                provision.signal_owned(pid, _signal.SIGTERM, pin,
                                       start)
            killer.assert_not_called()
        with mock.patch("os.kill") as killer:
            with self.assertRaises(provision.AdmissionError):
                provision.signal_owned(pid, _signal.SIGTERM, None,
                                       start)
            killer.assert_not_called()

    # S22-round4: signals ride pidfds, never numeric pids — a
    # live child is signalled with os.kill rigged to explode
    # (no numeric path exists to redirect), and exit+reap past
    # the final observation converges to gone: the dead pin
    # fails ESRCH instead of addressing whoever reused the
    # number.
    def test_signal_owned_uses_pidfd_not_numeric(self):
        import errno as _errno
        import signal as _signal
        from unittest import mock
        child = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            _, start = provision.stat_state_start(child.pid)
            pin = provision.pin_proc(child.pid)
            try:
                def no_numeric(pid, signum):
                    raise AssertionError(
                        "numeric kill attempted")

                with mock.patch("os.kill",
                                side_effect=no_numeric):
                    self.assertTrue(provision.signal_owned(
                        child.pid, _signal.SIGTERM, pin, start))
                child.wait(timeout=10)
                self.assertEqual(child.returncode,
                                 -_signal.SIGTERM)
                # Exit+reap past the final observation: gone,
                # with no numeric attempt.
                with mock.patch("os.kill",
                                side_effect=no_numeric):
                    self.assertFalse(provision.signal_owned(
                        child.pid, _signal.SIGKILL, pin, start))
                # The reuse-proof primitive itself: a dead pin
                # fails closed.
                self.assertEqual(
                    provision._pidfd_send_signal(
                        pin, _signal.SIGKILL),
                    _errno.ESRCH)
            finally:
                os.close(pin)
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()

    # S22-round4: the raw-syscall fallback signals when the
    # libc wrapper is absent — the handle mock exposes only
    # syscall, so attribute lookup fails exactly as on an old
    # glibc.
    def test_pidfd_send_signal_syscall_fallback(self):
        import ctypes as _ctypes
        from unittest import mock
        child = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            pin = provision.pin_proc(child.pid)
            try:
                real_libc = _ctypes.CDLL("libc.so.6",
                                         use_errno=True)
                handle = mock.Mock(spec=["syscall"])
                handle.syscall = real_libc.syscall
                with mock.patch.object(
                        provision, "_libc_handle",
                        return_value=handle):
                    # Signal 0 checks existence, effects none.
                    self.assertIsNone(
                        provision._pidfd_send_signal(pin, 0))
            finally:
                os.close(pin)
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()

    # S22-round4: EPERM escalates through a re-pinning helper,
    # never a numeric sudo kill — the helper argv carries
    # pid+starttime+signum, the pin stays open across the
    # call, and helper reports map to sent/gone/identity
    # change/unknown.
    def test_signal_owned_eperm_escalates_via_helper(self):
        import errno as _errno
        import signal as _signal
        import sys as _sys
        from unittest import mock
        child = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            _, start = provision.stat_state_start(child.pid)
            pin = provision.pin_proc(child.pid)
            try:
                calls = []

                def fake_sudo(argv, timeout=120):
                    # The pin stays open across the escalation.
                    os.fstat(pin)
                    calls.append(list(argv))
                    return fake_sudo.result

                cases = [
                    ((0, f"signalled {child.pid}\n", ""),
                     True, None),
                    ((0, f"proc-gone {child.pid}\n", ""),
                     False, None),
                    ((1, "FAILED: identity changed (live=1 "
                      "expected=2)\n", ""),
                     None, provision.AdmissionError),
                    ((1, "FAILED: boom\n", ""),
                     None, provision.ProcUnknown),
                ]
                for result, want, exc in cases:
                    fake_sudo.result = result
                    with mock.patch.object(
                            provision, "_pidfd_send_signal",
                            return_value=_errno.EPERM), \
                            mock.patch.object(
                                provision, "run_sudo",
                                side_effect=fake_sudo):
                        if exc is None:
                            self.assertEqual(
                                provision.signal_owned(
                                    child.pid, _signal.SIGTERM,
                                    pin, start),
                                want)
                        else:
                            with self.assertRaises(exc):
                                provision.signal_owned(
                                    child.pid, _signal.SIGTERM,
                                    pin, start)
                self.assertEqual(len(calls), 4)
                for argv in calls:
                    self.assertEqual(
                        argv,
                        [_sys.executable,
                         os.path.abspath(provision.__file__),
                         "signal-proc",
                         "--pid", str(child.pid),
                         "--starttime", str(start),
                         "--signum",
                         str(int(_signal.SIGTERM))])
            finally:
                os.close(pin)
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()

    # S22-round4: the signal-proc helper pins, verifies, and
    # signals in one privileged process — live children die by
    # real effect, the reaped report gone, starttime skew
    # refuses without signalling, and bad argv refuses.
    def test_signal_proc_command(self):
        import contextlib as _contextlib
        import io as _io
        import signal as _signal
        import types as _types
        child = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            _, start = provision.stat_state_start(child.pid)
            args = _types.SimpleNamespace(
                pid=str(child.pid), starttime=str(start),
                signum=str(int(_signal.SIGTERM)))
            out = _io.StringIO()
            with _contextlib.redirect_stdout(out):
                rc = provision.signal_proc_command(args)
            self.assertEqual(rc, 0)
            self.assertIn(f"signalled {child.pid}",
                          out.getvalue())
            child.wait(timeout=10)
            self.assertEqual(child.returncode,
                             -_signal.SIGTERM)
        finally:
            try:
                child.kill()
            except OSError:
                pass
            child.wait()
        # Reaped: gone, no signal attempted.
        out = _io.StringIO()
        with _contextlib.redirect_stdout(out):
            rc = provision.signal_proc_command(args)
        self.assertEqual(rc, 0)
        self.assertIn("proc-gone", out.getvalue())
        # Live child, wrong starttime: identity refusal, child
        # untouched.
        child2 = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            _, start2 = provision.stat_state_start(child2.pid)
            bad = _types.SimpleNamespace(
                pid=str(child2.pid),
                starttime=str(start2 + 10 ** 9),
                signum=str(int(_signal.SIGTERM)))
            out = _io.StringIO()
            with _contextlib.redirect_stdout(out):
                rc = provision.signal_proc_command(bad)
            self.assertEqual(rc, 1)
            self.assertIn("identity changed", out.getvalue())
            provision.stat_state_start(child2.pid)
        finally:
            try:
                child2.kill()
            except OSError:
                pass
            child2.wait()
        # Bad argv refuses.
        template = dict(pid="123", starttime="456",
                        signum="15")
        for key, value in (("pid", "-1"), ("pid", "x"),
                           ("starttime", "-5"),
                           ("signum", "0"), ("signum", "999"),
                           ("signum", "TERM")):
            with self.subTest(key=key, value=value):
                argv = dict(template)
                argv[key] = value
                out = _io.StringIO()
                with _contextlib.redirect_stdout(out):
                    rc = provision.signal_proc_command(
                        _types.SimpleNamespace(**argv))
                self.assertEqual(rc, 1)
                self.assertIn("bad signal-proc argv",
                              out.getvalue())

    # S24: readiness is a bounded poll; custody is armed at spawn.
    def test_readline_bounded_shapes(self):
        reader, writer = os.pipe()
        try:
            os.write(writer, b"ready\n")
            with os.fdopen(reader, "rb") as stream:
                reader = None
                self.assertEqual(
                    provision.readline_bounded(stream, 5, 4096),
                    b"ready\n")
        finally:
            os.close(writer)
            if reader is not None:
                os.close(reader)
        reader, writer = os.pipe()
        os.close(writer)
        try:
            with os.fdopen(reader, "rb") as stream:
                reader = None
                self.assertEqual(
                    provision.readline_bounded(stream, 5, 4096), b"")
        finally:
            if reader is not None:
                os.close(reader)

    def test_spawn_sleeper_bounds_blocked_readiness(self):
        import time as _time
        with tempfile.TemporaryDirectory() as tmp:
            report = str(Path(tmp) / "sleeper.report")
            doc = provision.fresh_manifest(tmp, True)
            start = _time.time()
            with self.assertRaisesRegex(
                    provision.AdmissionError, "never became ready"):
                provision.spawn_sleeper(
                    str(Path(tmp) / "helper.py"),
                    str(Path(tmp) / "target.bin"), report,
                    ["sh", "-c", "sleep 30", "tt04-test"], doc,
                    ready_timeout=2)
            elapsed = _time.time() - start
            self.assertLess(
                elapsed, 20,
                f"blocked readiness took {elapsed:.1f}s (unbounded?)")
            # The tree was proven gone: no pending custody remains.
            self.assertEqual(doc["pending_procs"], [])

    def test_spawn_sleeper_caps_readiness_flood(self):
        import time as _time
        with tempfile.TemporaryDirectory() as tmp:
            report = str(Path(tmp) / "sleeper.report")
            doc = provision.fresh_manifest(tmp, True)
            start = _time.time()
            with self.assertRaises(provision.AdmissionError):
                provision.spawn_sleeper(
                    str(Path(tmp) / "helper.py"),
                    str(Path(tmp) / "target.bin"), report,
                    ["sh", "-c",
                     "while :; do "
                     "printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; "
                     "done", "tt04-test"],
                    doc, ready_timeout=10, ready_max_bytes=1024)
            self.assertLess(_time.time() - start, 20)
            self.assertEqual(doc["pending_procs"], [])

    # S19: the host gate and the shipped driver gate agree.
    def test_owned_bind_host_matches_driver(self):
        import ast
        from unittest import mock
        tree = ast.parse(provision.CHURN_DRIVER_PY)
        wanted = [node for node in tree.body
                  if isinstance(node, ast.FunctionDef)]
        module = ast.Module(body=wanted, type_ignores=[])
        namespace = {"os": os}
        exec(compile(module, "<driver>", "exec"), namespace)  # noqa: S102
        gate = namespace["owned_bind_only"]
        with tempfile.TemporaryDirectory() as tmp:
            point = str(Path(tmp) / "point")
            payload = str(Path(tmp) / "payload-b")
            Path(payload).write_bytes(b"payload")
            Path(point).write_bytes(b"point")
            st = os.stat(payload)
            row = {"target": point, "mnt_id": 9,
                   "root": "/@/x", "fstype": "ext4",
                   "source": "/dev/sda3", "super": "rw|"}
            table = Path(tmp) / "mountinfo"
            env = {"TT04_MOUNTINFO": str(table)}
            # Mounted: hardlink reproduces the covered identity.
            os.unlink(point)
            os.link(payload, point)
            table.write_text(
                f"90 1 0:50 /@/x {point} rw shared:1 - ext4 "
                f"/dev/sda3 rw\n")
            with mock.patch.dict(os.environ, env):
                driver_says = gate(point, payload,
                                   st.st_dev, st.st_ino)
            host_says = provision.owned_bind_only(
                point, payload, st.st_dev, st.st_ino, [row])
            self.assertTrue(driver_says)
            self.assertEqual(host_says, driver_says)
            # Unmounted: both refuse the same row.
            os.unlink(point)
            Path(point).write_bytes(b"point")
            with mock.patch.dict(os.environ, env):
                driver_says = gate(point, payload,
                                   st.st_dev, st.st_ino)
            host_says = provision.owned_bind_only(
                point, payload, st.st_dev, st.st_ino, [row])
            self.assertFalse(driver_says)
            self.assertEqual(host_says, driver_says)

    # S27: mounts refuse traversal — same-fs binds included.
    def test_aux_cleanup_refuses_mounted_child(self):
        from unittest import mock
        try:
            probe = Path("/dev/shm") / "tt04-probe"
            probe.mkdir(exist_ok=True)
            probe.rmdir()
        except OSError:
            self.skipTest("no writable /dev/shm")
        root = Path(tempfile.mkdtemp(prefix="tt04-", dir="/dev/shm"))
        try:
            sub = root / "sub"
            sub.mkdir()
            canary = sub / "canary.txt"
            canary.write_bytes(b"canary")
            st = os.stat(root)
            aux = {"path": str(root), "dev": st.st_dev,
                   "ino": st.st_ino}
            live = [{"target": str(sub), "mnt_id": 9,
                     "root": "/", "fstype": "ext4",
                     "source": "/dev/sda3", "super": "rw|"}]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                failure = provision.cleanup_aux_root(aux)
            self.assertIn("refusing traversal", failure)
            self.assertEqual(canary.read_bytes(), b"canary")
            self.assertTrue(root.is_dir())
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_traversal_refuses_planted_mount(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            sub = tree / "sub"
            tree.mkdir(mode=0o755)
            sub.mkdir(mode=0o755)
            canary = sub / "canary.txt"
            canary.write_bytes(b"canary")
            (tree / "top.txt").write_bytes(b"top")
            expected = (os.stat(tree).st_dev, os.stat(tree).st_ino)
            parent_fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                live = [{"target": str(sub), "mnt_id": 9,
                         "root": "/", "fstype": "ext4",
                         "source": "/dev/sda3", "super": "rw|"}]
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=live):
                    failure = provision.remove_pinned_tree(
                        parent_fd, "tree", expected, str(tree))
            finally:
                os.close(parent_fd)
            self.assertIn("mount boundary", failure)
            self.assertEqual(canary.read_bytes(), b"canary")
            self.assertTrue((tree / "top.txt").exists())

    def test_traversal_refuses_mounted_file(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            tree.mkdir(mode=0o755)
            covered = tree / "covered.txt"
            covered.write_bytes(b"covered")
            expected = (os.stat(tree).st_dev, os.stat(tree).st_ino)
            parent_fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                live = [{"target": str(covered), "mnt_id": 9,
                         "root": "/@/f", "fstype": "ext4",
                         "source": "/dev/sda3", "super": "rw|"}]
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=live):
                    failure = provision.remove_pinned_tree(
                        parent_fd, "tree", expected, str(tree))
            finally:
                os.close(parent_fd)
            self.assertIn("mount boundary", failure)
            self.assertEqual(covered.read_bytes(), b"covered")

    def test_aux_cleanup_planted_between_guard_and_walk(self):
        from unittest import mock
        try:
            probe = Path("/dev/shm") / "tt04-probe"
            probe.mkdir(exist_ok=True)
            probe.rmdir()
        except OSError:
            self.skipTest("no writable /dev/shm")
        root = Path(tempfile.mkdtemp(prefix="tt04-", dir="/dev/shm"))
        try:
            sub = root / "sub"
            sub.mkdir()
            canary = sub / "canary.txt"
            canary.write_bytes(b"canary")
            st = os.stat(root)
            aux = {"path": str(root), "dev": st.st_dev,
                   "ino": st.st_ino}
            planted = [{"target": str(sub), "mnt_id": 9,
                        "root": "/", "fstype": "ext4",
                        "source": "/dev/sda3", "super": "rw|"}]
            # Clean at the pre-guard, planted at the walk: the
            # traversal-time check refuses anyway.
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[], planted]):
                failure = provision.cleanup_aux_root(aux)
            self.assertIn("mount boundary", failure)
            self.assertEqual(canary.read_bytes(), b"canary")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    # Pending mounts reconcile in cleanup, never blindly.
    # S74-round6: an ID-less pending with nothing at its
    # target is UNCERTAIN (the effect may have fired and the
    # mount moved) — cleanup fails loudly and keeps custody
    # (pending retained, run root kept), never discharges
    # silently from target absence.
    def test_cleanup_reconciles_pending_mounts(self):
        import types
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root, mode=0o755)
        st = os.stat(run_root)
        doc = provision.fresh_manifest(run_root, False)
        doc["run_root_identity"] = {"dev": st.st_dev, "ino": st.st_ino}
        target = os.path.join(run_root, "ext4", "mnt")
        doc["pending_acquisitions"] = [{
            "kind": "mount", "key": target, "role": "ext4-fs01",
            "target": target, "fstype": "ext4",
            "source": "/dev/loop9", "expect_super": []}]
        Path(manifest).write_text(json.dumps(doc))
        args = types.SimpleNamespace(run_root=run_root,
                                     manifest=manifest)
        with mock.patch.object(provision, "read_mount_table",
                               return_value=[]):
            self.assertEqual(provision.cleanup_command(args), 1)
        self.assertTrue(os.path.exists(run_root))
        kept = json.loads(Path(manifest).read_text())
        self.assertEqual(len(kept["pending_acquisitions"]), 1)

    def test_cleanup_reports_unresolved_pending_mount(self):
        import types
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        st = os.stat(run_root)
        doc = provision.fresh_manifest(run_root, False)
        doc["run_root_identity"] = {"dev": st.st_dev, "ino": st.st_ino}
        target = os.path.join(run_root, "ext4", "mnt")
        doc["pending_acquisitions"] = [{
            "kind": "mount", "key": target, "role": "ext4-fs01",
            "target": target, "fstype": "ext4",
            "source": "/dev/loop9", "expect_super": []}]
        Path(manifest).write_text(json.dumps(doc))
        args = types.SimpleNamespace(run_root=run_root,
                                     manifest=manifest)
        foreign = {"target": target, "mnt_id": 9, "root": "/",
                   "fstype": "tmpfs", "source": "tmpfs",
                   "super": "rw|"}
        with mock.patch.object(provision, "read_mount_table",
                               return_value=[foreign]):
            self.assertEqual(provision.cleanup_command(args), 1)
        self.assertTrue(os.path.isdir(run_root))


class ThirdReviewTests(unittest.TestCase):
    """Round-3 provision findings: S15/S17/S18/S21/S22/S23/S25/S27/S62."""

    @staticmethod
    def _stat(mode, uid):
        return os.stat_result(
            (0o040000 | mode, 1, 2, 2, uid, 100, 0, 0, 0, 0))

    # S25-round3: a sticky parent's foreign owner bypasses the sticky
    # bit (dir owners may rename anyone's entries), so the shared
    # allowance requires a trusted owner (us or root) whenever the
    # parent grants rename rights beyond the owner. Matrix over the
    # shared helper plus an end-to-end foreign-owner refusal.
    # S25-round4: the owner check no longer depends on the write
    # bits — a foreign-owned 0755/01755 parent lets its owner
    # substitute the temp after the identity proof for any
    # privileged caller, so every parent needs a trusted owner.
    def test_manifest_parent_owner_matrix(self):
        me = os.geteuid()
        alien = 65000 if me != 65000 else 65001
        cases = [
            # (mode, uid, accepted?)
            (0o700, me, True),
            (0o755, me, True),
            (0o775, me, True),    # group trust doctrine (unchanged)
            (0o1777, me, True),   # /tmp-style, owned by us
            (0o1777, 0, True),    # /tmp-style, root trusted
            (0o1777, alien, False),  # THE finding: foreign sticky owner
            (0o775, alien, False),   # same class, group-writable
            (0o777, me, False),   # existing unprotected rule
            (0o777, alien, False),
            (0o755, alien, False),  # round4: unshared foreign owner
            (0o1755, alien, False),  # refuses at the gate too
        ]
        for mode, uid, accepted in cases:
            with self.subTest(mode=oct(mode), uid=uid):
                refusal = provision._manifest_parent_refusal(
                    self._stat(mode, uid), "/parent")
                if accepted:
                    self.assertIsNone(refusal)
                else:
                    self.assertIsNotNone(refusal)
                    if uid == alien:
                        self.assertIn("foreign owner", refusal)

    def test_save_manifest_refuses_foreign_owned_sticky_parent(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "sticky"
            parent.mkdir()
            os.chmod(parent, 0o1777)
            manifest = str(parent / "manifest.json")
            real_fstat = os.fstat
            calls = []

            def fake_fstat(fd):
                st = real_fstat(fd)
                calls.append(fd)
                if len(calls) == 1:
                    # First fstat is the parent gate: report a
                    # foreign owner (the sticky-dir bypass).
                    tup = (st.st_mode, st.st_ino, st.st_dev,
                           st.st_nlink, 65000, st.st_gid, st.st_size,
                           int(st.st_atime), int(st.st_mtime),
                           int(st.st_ctime))
                    return os.stat_result(tup)
                return st

            with mock.patch.object(provision.os, "fstat",
                                   side_effect=fake_fstat):
                with self.assertRaisesRegex(
                        provision.AdmissionError, "foreign owner"):
                    provision.save_manifest({"k": "v"}, manifest)
            self.assertFalse(os.path.exists(manifest))
            leftovers = [p.name for p in parent.iterdir()
                         if p.name.startswith(".tt04-manifest-")]
            self.assertEqual(leftovers, [])

    def test_save_manifest_privileged_refuses_foreign_755_parent(self):
        # S25-round4: the foreign-owner privileged publication
        # case. A privileged caller (mocked euid 0) under a
        # foreign-owned 0755 parent refuses at the gate: root
        # (DAC override) could create the temp, and the parent
        # owner could then substitute it after the identity
        # proof, before the rename. Pre-fix the gate passed
        # (owner check scoped to shared parents) and the
        # publication succeeded outright here.
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "priv"
            parent.mkdir()
            os.chmod(parent, 0o755)
            manifest = str(parent / "manifest.json")
            real_fstat = os.fstat
            calls = []

            def fake_fstat(fd):
                st = real_fstat(fd)
                calls.append(fd)
                if len(calls) == 1:
                    # First fstat is the parent gate: report a
                    # foreign owner on the unshared parent.
                    tup = (st.st_mode, st.st_ino, st.st_dev,
                           st.st_nlink, 65000, st.st_gid, st.st_size,
                           int(st.st_atime), int(st.st_mtime),
                           int(st.st_ctime))
                    return os.stat_result(tup)
                return st

            with mock.patch.object(provision.os, "fstat",
                                   side_effect=fake_fstat), \
                    mock.patch.object(provision.os, "geteuid",
                                       return_value=0):
                with self.assertRaisesRegex(
                        provision.AdmissionError, "foreign owner"):
                    provision.save_manifest({"k": "v"}, manifest)
            self.assertFalse(os.path.exists(manifest))
            leftovers = [p.name for p in parent.iterdir()
                         if p.name.startswith(".tt04-manifest-")]
            self.assertEqual(leftovers, [])

    # S18-round3: the deleted-B/restored-A counterexample. The loop
    # holds deleted B (sysfs: "img (deleted)") while A is restored
    # live at img with the held identity: stripping the suffix and
    # stating the name returns A and false-admits. Kernel backing
    # identity (LOOP_GET_STATUS64) governs; the pathname fallback
    # refuses every " (deleted)" value as unprovable.
    def test_loop_verify_deleted_restored_counterexample(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            img = str(Path(tmp) / "fs01.img")
            Path(img).write_bytes(b"image-A")
            image_st = os.stat(img)
            other = str(Path(tmp) / "other.img")
            Path(other).write_bytes(b"image-B")
            st_b = os.stat(other)
            deleted = f"{img} (deleted)"
            unavail = provision.LoopIdUnavailable("test")
            # Fallback B/A: refuse.
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    side_effect=unavail):
                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=deleted):
                    self.assertFalse(provision.verify_loop_backing(
                        "/dev/loop9", img, image_st))
            # Kernel-primary mismatch: ioctl reports B while the
            # pathname states A — identity governs: refuse.
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    return_value=(st_b.st_dev, st_b.st_ino)):
                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=img):
                    self.assertFalse(provision.verify_loop_backing(
                        "/dev/loop9", img, image_st))
            # Kernel-primary match despite a hostile sysfs string.
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    return_value=(image_st.st_dev,
                                  image_st.st_ino)):
                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value="/elsewhere/evil (deleted)"):
                    self.assertTrue(provision.verify_loop_backing(
                        "/dev/loop9", img, image_st))
            # Fallback live-name match: admit (kept behavior).
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    side_effect=unavail):
                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=img):
                    self.assertTrue(provision.verify_loop_backing(
                        "/dev/loop9", img, image_st))
            # Provably detached (ioctl None): refuse.
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    return_value=None):
                self.assertFalse(provision.verify_loop_backing(
                    "/dev/loop9", img, image_st))

    # S18-round3: same counterexample through the retire-path
    # verifier (which takes the already-read sysfs value).
    def test_retire_loop_deleted_restored_counterexample(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            img = str(Path(tmp) / "fs01.img")
            Path(img).write_bytes(b"image-A")
            image_st = os.stat(img)
            other = str(Path(tmp) / "other.img")
            Path(other).write_bytes(b"image-B")
            st_b = os.stat(other)
            backing = {"path": img, "dev": image_st.st_dev,
                       "ino": image_st.st_ino}
            unavail = provision.LoopIdUnavailable("test")
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    side_effect=unavail):
                self.assertFalse(provision.loop_backing_verified(
                    "/dev/loop9", f"{img} (deleted)", backing))
                self.assertTrue(provision.loop_backing_verified(
                    "/dev/loop9", img, backing))
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    return_value=(st_b.st_dev, st_b.st_ino)):
                self.assertFalse(provision.loop_backing_verified(
                    "/dev/loop9", img, backing))
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    return_value=(image_st.st_dev,
                                  image_st.st_ino)):
                self.assertTrue(provision.loop_backing_verified(
                    "/dev/loop9", "/elsewhere/evil (deleted)",
                    backing))

    # S18-round3: the cleanup path refuses the B/A state and never
    # reaches the detach helper; the live-name match still detaches.
    def test_cleanup_loop_deleted_restored_refuses_detach(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            img = str(Path(tmp) / "fs01.img")
            Path(img).write_bytes(b"image-A")
            image_st = os.stat(img)
            backing = {"path": img, "dev": image_st.st_dev,
                       "ino": image_st.st_ino}
            unavail = provision.LoopIdUnavailable("test")
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    side_effect=unavail):
                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=f"{img} (deleted)"):
                    with mock.patch.object(
                            provision, "retire_loop_via_helper"
                            ) as helper:
                        result = provision.cleanup_loop_device(
                            "/dev/loop9", backing, tmp)
            self.assertIsNotNone(result)
            helper.assert_not_called()
            with mock.patch.object(
                    provision, "read_loop_backing_id",
                    side_effect=unavail):
                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=img):
                    with mock.patch.object(
                            provision, "retire_loop_via_helper",
                            return_value=None) as helper:
                        result = provision.cleanup_loop_device(
                            "/dev/loop9", backing, tmp)
            self.assertIsNone(result)
            helper.assert_called_once()

    # S23-round3: attachment + lost response + unlinked backing.
    # The loop still holds the image while the pathname is gone
    # (stat ENOENT): kernel identity adopts it, while an unreadable
    # kernel status makes the scan explicitly incomplete and pending
    # custody is retained — never dropped on an empty result.
    def test_reconcile_lost_response_unlinked_backing(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            deleted = f"{image} (deleted)"
            os.unlink(image)

            def pending_doc():
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [{
                    "kind": "loop", "key": image, "image": image,
                    "dev": st.st_dev, "ino": st.st_ino}]
                return doc

            # Kernel identity adopts the deleted backing.
            doc = pending_doc()
            with mock.patch.object(provision.os, "listdir",
                                   return_value=["sda", "loop9"]):
                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=deleted):
                    with mock.patch.object(
                            provision, "read_loop_backing_id",
                            return_value=(st.st_dev, st.st_ino)):
                        loop = provision.reconcile_loop_attach(
                            doc, image, st.st_dev, st.st_ino)
            self.assertEqual(loop, "/dev/loop9")
            self.assertEqual(doc["pending_acquisitions"], [])
            # Unreadable kernel status: incomplete scan retains.
            doc = pending_doc()
            with mock.patch.object(provision.os, "listdir",
                                   return_value=["sda", "loop9"]):
                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=deleted):
                    with mock.patch.object(
                            provision, "read_loop_backing_id",
                            side_effect=provision.LoopIdUnavailable(
                                "test")):
                        loop = provision.reconcile_loop_attach(
                            doc, image, st.st_dev, st.st_ino)
                        matches, incomplete = \
                            provision.scan_loop_by_backing(
                                st.st_dev, st.st_ino)
            self.assertIsNone(loop)
            self.assertEqual(len(doc["pending_acquisitions"]), 1)
            self.assertEqual(matches, [])
            self.assertTrue(incomplete)

    # S23-round4: a missing device node is unknown, never
    # detached — removing /dev/loopN leaves the kernel loop
    # live, so the kernel-identity read raises instead of
    # returning the ENXIO-detached None.
    def test_loop_backing_id_missing_node_is_unknown(self):
        from unittest import mock
        real_open = os.open

        def fake_open(path, *args, **kwargs):
            if path == "/dev/loop9":
                raise FileNotFoundError(
                    2, "No such file", "/dev/loop9")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(provision.os, "open",
                               side_effect=fake_open):
            with self.assertRaisesRegex(
                    provision.LoopIdUnavailable,
                    "never detached"):
                provision.read_loop_backing_id("/dev/loop9")

    # S23-round4: a sysfs-live candidate whose device node is
    # missing marks the scan incomplete (never a detached
    # skip), so reconcile retains custody — unless the live
    # backing stats to the query identity through the pathname
    # fallback, which still adopts. Pre-fix the candidate
    # skipped as detached and the empty scan dropped custody.
    def test_scan_loop_missing_node_marks_incomplete(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            real_open = os.open

            def fake_open(path, *args, **kwargs):
                if path == "/dev/loop9":
                    raise FileNotFoundError(
                        2, "No such file", "/dev/loop9")
                return real_open(path, *args, **kwargs)

            def pending_doc():
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [{
                    "kind": "loop", "key": image, "image": image,
                    "dev": st.st_dev, "ino": st.st_ino}]
                return doc

            # Backing unlinked: sysfs-live plus a missing node
            # is unassessable — incomplete, retained.
            deleted = f"{image} (deleted)"
            os.unlink(image)
            doc = pending_doc()
            with mock.patch.object(provision.os, "listdir",
                                   return_value=["loop9"]), \
                    mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=deleted), \
                    mock.patch.object(provision.os, "open",
                                       side_effect=fake_open):
                matches, incomplete = \
                    provision.scan_loop_by_backing(
                        st.st_dev, st.st_ino)
                loop = provision.reconcile_loop_attach(
                    doc, image, st.st_dev, st.st_ino)
            self.assertEqual(matches, [])
            self.assertTrue(incomplete)
            self.assertIsNone(loop)
            self.assertEqual(len(doc["pending_acquisitions"]),
                             1)
            # Backing linked and matching: the pathname
            # fallback still adopts the nodeless loop.
            Path(image).write_bytes(b"image")
            st2 = os.stat(image)
            doc = pending_doc()
            doc["pending_acquisitions"][0]["dev"] = st2.st_dev
            doc["pending_acquisitions"][0]["ino"] = st2.st_ino
            with mock.patch.object(provision.os, "listdir",
                                   return_value=["loop9"]), \
                    mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=image), \
                    mock.patch.object(provision.os, "open",
                                       side_effect=fake_open):
                matches, incomplete = \
                    provision.scan_loop_by_backing(
                        st2.st_dev, st2.st_ino)
            self.assertEqual(matches, ["/dev/loop9"])
            self.assertFalse(incomplete)

    # S23-round4: cleanup repeats the retention, not the
    # discharge — a pending loop whose candidate is
    # sysfs-live with a missing node reports manual
    # retirement instead of silently dropping.
    def test_cleanup_pending_loop_missing_node_keeps_custody(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            deleted = f"{image} (deleted)"
            os.unlink(image)
            real_open = os.open

            def fake_open(path, *args, **kwargs):
                if path == "/dev/loop9":
                    raise FileNotFoundError(
                        2, "No such file", "/dev/loop9")
                return real_open(path, *args, **kwargs)

            doc = provision.fresh_manifest(tmp, True)
            doc["pending_acquisitions"] = [{
                "kind": "loop", "key": image, "image": image,
                "dev": st.st_dev, "ino": st.st_ino}]
            with mock.patch.object(provision.os, "listdir",
                                   return_value=["loop9"]), \
                    mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=deleted), \
                    mock.patch.object(provision.os, "open",
                                       side_effect=fake_open):
                failures = (
                    provision.cleanup_pending_acquisitions(
                        doc, tmp))
            self.assertEqual(len(failures), 1)
            self.assertIn("incomplete", failures[0])
            self.assertIn("manual retirement required",
                          failures[0])
            self.assertEqual(len(doc["pending_acquisitions"]),
                             1)

    # S23-round3: an EACCES backing candidate (real permissions, no
    # mocks on stat) makes the scan incomplete and retains custody.
    def test_reconcile_unreadable_backing_candidate_retains(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            sub = Path(tmp) / "denied"
            sub.mkdir()
            image = str(sub / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            os.chmod(sub, 0)
            try:
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [{
                    "kind": "loop", "key": image, "image": image,
                    "dev": st.st_dev, "ino": st.st_ino}]
                with mock.patch.object(
                        provision.os, "listdir",
                        return_value=["loop9"]):
                    with mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image):
                        with mock.patch.object(
                                provision, "read_loop_backing_id",
                                side_effect=provision
                                .LoopIdUnavailable("test")):
                            loop = provision.reconcile_loop_attach(
                                doc, image, st.st_dev, st.st_ino)
                            matches, incomplete = \
                                provision.scan_loop_by_backing(
                                    st.st_dev, st.st_ino)
            finally:
                os.chmod(sub, 0o700)
            self.assertIsNone(loop)
            self.assertEqual(len(doc["pending_acquisitions"]), 1)
            self.assertEqual(matches, [])
            self.assertTrue(incomplete)

    # S21-round3: pending-to-admitted handoff is transactional. The
    # spawn arms pendings for wrapper AND leaf; the caller drops
    # them only after admitting both. A record_proc failure in the
    # middle keeps both pendings — no live process loses custody.
    def test_sleeper_handoff_keeps_pending_on_admit_failure(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            report = str(Path(tmp) / "sleeper.report")
            reader, writer = os.pipe()
            try:
                os.write(writer, b"ready\n")
                stdout = os.fdopen(reader, "rb")
            finally:
                os.close(writer)
            child = mock.Mock()
            child.pid = 424242
            child.stdout = stdout
            doc = provision.fresh_manifest(tmp, True)
            try:
                with mock.patch.object(provision.subprocess, "Popen",
                                       return_value=child):
                    with mock.patch.object(
                            provision, "resolve_leaf",
                            return_value=424243):
                        wrap, sleep = provision.spawn_sleeper(
                            Path(tmp) / "helper.py",
                            str(Path(tmp) / "target.bin"),
                            report, ["wrapper"], doc,
                            role="w-wrapper", leaf_role="w-sleeper")
            finally:
                stdout.close()
            self.assertEqual((wrap, sleep), (424242, 424243))
            # Caller admits the wrapper, then the leaf admission
            # fails (identity unreadable) before any drop runs.
            calls = []

            def fake_record(manifest, role, pid):
                calls.append(role)
                if role == "w-sleeper":
                    raise provision.ProcUnknown("denied")
                return {"role": role, "pid": pid}

            with mock.patch.object(provision, "record_proc",
                                   side_effect=fake_record):
                provision.record_proc(doc, "w-wrapper", wrap)
                with self.assertRaises(provision.ProcUnknown):
                    provision.record_proc(doc, "w-sleeper", sleep)
            self.assertEqual(calls, ["w-wrapper", "w-sleeper"])
            kept = {(e["role"], e["pid"])
                    for e in doc["pending_procs"]}
            self.assertIn(("w-wrapper", 424242), kept)
            self.assertIn(("w-sleeper", 424243), kept)

    # S21-round3: every unsuccessful retirement persists custody,
    # including a False (survivor) result — never a silent drop.
    def test_retire_false_persists_pending(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            doc = provision.fresh_manifest(tmp, True)
            with mock.patch.object(provision, "pin_proc",
                                   return_value=999):
                with mock.patch.object(
                        provision, "stat_state_start",
                        return_value=("R", 12345)):
                    with mock.patch.object(
                            provision, "kill_owned",
                            return_value=False) as killer:
                        result = provision.retire_fresh_proc(
                            "nested-test", 424242, doc)
            self.assertFalse(result)
            killer.assert_called_once_with(
                "nested-test", 424242, 12345, 10)
            self.assertEqual(len(doc["pending_procs"]), 1)
            pending = doc["pending_procs"][0]
            self.assertEqual(
                (pending["role"], pending["pid"],
                 pending["starttime"]),
                ("nested-test", 424242, 12345))

    # S21-round3: the nested caller retires both ends even when one
    # retirement refuses on identity change (whose occupant is
    # provably gone-or-foreign), and the evidence still records.
    def test_nested_retire_continues_past_refusal(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            doc = provision.fresh_manifest(tmp, True)
            auth = mock.Mock()
            auth.abspath.side_effect = lambda p: f"/tmp/{p}"
            with mock.patch.object(
                    provision, "spawn_sleeper",
                    return_value=(111, 222)):
                with mock.patch.object(
                        provision, "proc_identity",
                        side_effect=provision.ProcUnknown(
                            "denied")):
                    with mock.patch.object(
                            provision, "retire_fresh_proc",
                            side_effect=[
                                provision.ProcIdentityChanged(
                                    "starttime changed"),
                                True]) as retire:
                        result = provision.try_nested_pidns(
                            doc, auth, "/tmp/helper.py")
            self.assertFalse(result)
            self.assertEqual(retire.call_count, 2)
            first, second = retire.call_args_list
            self.assertEqual(first.args[0], "nested-pidns-sleeper")
            self.assertEqual(
                second.args[0], "nested-pidns-sleeper-wrapper")
            self.assertIn("identity unreadable",
                          doc["evidence"]["nested_pidns"])

    # S21-round4: the nested identity-failure path keeps each
    # spawn pending armed across its retirement — every
    # retirement observes its record still present in memory
    # and on disk (pre-fix both dropped first, so a crash
    # between the drops and the retirements lost custody).
    # Proven-gone ends drop; an identity-change refusal drops
    # the proven-stale record and still retires the other end.
    def test_nested_identity_path_keeps_pendings_armed(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            doc = provision.fresh_manifest(tmp, True)
            auth = mock.Mock()
            auth.abspath.side_effect = lambda p: f"/tmp/{p}"
            seed = [
                {"role": "nested-pidns-sleeper-wrapper",
                 "pid": 111, "starttime": 100,
                 "detail": "sleeper wrapper armed"},
                {"role": "nested-pidns-sleeper", "pid": 222,
                 "starttime": 200,
                 "detail": "sleeper leaf armed"},
            ]
            path = os.path.join(tmp, "manifest.json")

            def run(retire_side_effect):
                doc["pending_procs"] = [dict(e) for e in seed]
                provision.save_manifest(doc, path)
                provision._PERSIST = path
                try:
                    with mock.patch.object(
                            provision, "spawn_sleeper",
                            return_value=(111, 222)), \
                            mock.patch.object(
                                provision, "proc_identity",
                                side_effect=provision.
                                AdmissionError("unreadable")), \
                            mock.patch.object(
                                provision, "retire_fresh_proc",
                                side_effect=retire_side_effect):
                        return provision.try_nested_pidns(
                            doc, auth, "/tmp/helper.py")
                finally:
                    provision._PERSIST = None

            seen = []
            disk_seen = []

            def observing_retire(role, pid, manifest,
                                 timeout=10):
                seen.append({(e["role"], e["pid"])
                             for e in manifest["pending_procs"]})
                disk = json.loads(Path(path).read_text())
                disk_seen.append(
                    {(e["role"], e["pid"])
                     for e in disk["pending_procs"]})
                return {"nested-pidns-sleeper": False,
                        "nested-pidns-sleeper-wrapper": True}[role]

            self.assertFalse(run(observing_retire))
            both = {("nested-pidns-sleeper-wrapper", 111),
                    ("nested-pidns-sleeper", 222)}
            # Both retirements observed both spawn records
            # armed, in memory and durably.
            self.assertEqual(seen, [both, both])
            self.assertEqual(disk_seen, [both, both])
            # Survivor kept, proven-gone dropped.
            kept = {(e["role"], e["pid"])
                    for e in doc["pending_procs"]}
            self.assertEqual(kept, {("nested-pidns-sleeper",
                                     222)})
            self.assertIn("identity unreadable",
                          doc["evidence"]["nested_pidns"])
            # Identity-change refusal drops the proven-stale
            # record and still retires the other end.
            calls = []

            def raising_retire(role, pid, manifest,
                               timeout=10):
                calls.append(role)
                if role == "nested-pidns-sleeper":
                    raise provision.ProcIdentityChanged(
                        "starttime changed")
                return True

            self.assertFalse(run(raising_retire))
            self.assertEqual(
                calls,
                ["nested-pidns-sleeper",
                 "nested-pidns-sleeper-wrapper"])
            self.assertEqual(doc["pending_procs"], [])

    # S21-round5: a persistence/publication failure inside the
    # retirement's refresh is NOT an identity change — it
    # propagates with both spawn pendings retained (pre-fix the
    # broad `except AdmissionError` dropped them, and a later
    # successful save durably removed live processes).
    def test_nested_persist_failure_propagates_with_custody(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            doc = provision.fresh_manifest(tmp, True)
            auth = mock.Mock()
            auth.abspath.side_effect = lambda p: f"/tmp/{p}"
            doc["pending_procs"] = [
                {"role": "nested-pidns-sleeper-wrapper",
                 "pid": 111, "starttime": 100,
                 "detail": "sleeper wrapper armed"},
                {"role": "nested-pidns-sleeper", "pid": 222,
                 "starttime": 200,
                 "detail": "sleeper leaf armed"},
            ]
            path = os.path.join(tmp, "manifest.json")
            provision.save_manifest(doc, path)
            provision._PERSIST = path
            try:
                with mock.patch.object(
                        provision, "spawn_sleeper",
                        return_value=(111, 222)), \
                        mock.patch.object(
                            provision, "proc_identity",
                            side_effect=provision.
                            AdmissionError("unreadable")), \
                        mock.patch.object(
                            provision, "retire_fresh_proc",
                            side_effect=provision.
                            AdmissionError(
                                "manifest not publishable")):
                    with self.assertRaises(
                            provision.AdmissionError):
                        provision.try_nested_pidns(
                            doc, auth, "/tmp/helper.py")
            finally:
                provision._PERSIST = None
            kept = {(e["role"], e["pid"])
                    for e in doc["pending_procs"]}
            self.assertEqual(kept, {
                ("nested-pidns-sleeper-wrapper", 111),
                ("nested-pidns-sleeper", 222)})

    # S21-round4: the nested unsupported-depth path keeps both
    # spawn pendings armed across the tree kill — the kill
    # observes both records (pre-fix both dropped first);
    # failure refreshes each in place (one persist per record,
    # prior starttime preserved when unobserved), success
    # drops both after the proven-gone result.
    def test_nested_depth_path_refreshes_around_kill(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            doc = provision.fresh_manifest(tmp, True)
            auth = mock.Mock()
            auth.abspath.side_effect = lambda p: f"/tmp/{p}"
            seed = [
                {"role": "nested-pidns-sleeper-wrapper",
                 "pid": 111, "starttime": 100,
                 "detail": "sleeper wrapper armed"},
                {"role": "nested-pidns-sleeper", "pid": 222,
                 "starttime": 200,
                 "detail": "sleeper leaf armed"},
            ]
            path = os.path.join(tmp, "manifest.json")

            def fake_stat(pid):
                if pid == 111:
                    return ("R", 999)
                raise provision.ProcAbsent("gone")

            def run(kill_result):
                doc["pending_procs"] = [dict(e) for e in seed]
                provision.save_manifest(doc, path)
                provision._PERSIST = path
                seen = []
                seen_armed = []
                saves = []
                real_save = provision.save_manifest

                def counting_save(manifest, where):
                    saves.append(where)
                    return real_save(manifest, where)

                def observing_kill(role, root, timeout=10,
                                   armed=None):
                    seen.append(
                        {(e["role"], e["pid"])
                         for e in doc["pending_procs"]})
                    seen_armed.append(armed)
                    return kill_result

                try:
                    with mock.patch.object(
                            provision, "spawn_sleeper",
                            return_value=(111, 222)), \
                            mock.patch.object(
                                provision, "proc_identity",
                                return_value={"nspid": [
                                    "1", "2"]}), \
                            mock.patch.object(
                                provision, "kill_tree",
                                side_effect=observing_kill), \
                            mock.patch.object(
                                provision, "stat_state_start",
                                side_effect=fake_stat), \
                            mock.patch.object(
                                provision, "save_manifest",
                                side_effect=counting_save):
                        result = provision.try_nested_pidns(
                            doc, auth, "/tmp/helper.py")
                finally:
                    provision._PERSIST = None
                return (result, seen, seen_armed, saves)

            both = {("nested-pidns-sleeper-wrapper", 111),
                    ("nested-pidns-sleeper", 222)}
            result, seen, seen_armed, saves = run(False)
            self.assertFalse(result)
            self.assertEqual(seen, [both])
            # S104-round6: the established spawn identities
            # ride into retirement.
            self.assertEqual(seen_armed, [{111: 100, 222: 200}])
            # One persist per in-place refresh (pre-fix: two
            # drops plus two records).
            self.assertEqual(len(saves), 2)
            by_role = {e["role"]: e
                       for e in doc["pending_procs"]}
            self.assertEqual(set(by_role), {
                "nested-pidns-sleeper-wrapper",
                "nested-pidns-sleeper"})
            for entry in by_role.values():
                self.assertIn("not proven gone",
                              entry["detail"])
            # S91-round5: the wrapper's armed starttime 100 is
            # preserved despite the differing observation 999
            # (a recycled number), with the conflict noted.
            self.assertEqual(
                by_role["nested-pidns-sleeper-wrapper"]
                ["starttime"], 100)
            self.assertIn(
                "identity conflict",
                by_role["nested-pidns-sleeper-wrapper"]
                ["detail"])
            self.assertEqual(
                by_role["nested-pidns-sleeper"]["starttime"],
                200)
            self.assertIn("NSpid depth",
                          doc["evidence"]["nested_pidns"])
            result, seen, seen_armed, saves = run(True)
            self.assertFalse(result)
            self.assertEqual(seen, [both])
            self.assertEqual(seen_armed, [{111: 100, 222: 200}])
            self.assertEqual(doc["pending_procs"], [])

    # S21-round4: pending-proc refresh replaces in memory and
    # persists once — a crash between drop and record can no
    # longer strand a live process without custody. A None
    # starttime preserves the prior record's. S91-round5: a
    # differing observation never replaces a known starttime
    # (recycled number) — the armed value is kept with the
    # conflict noted; fresh identity is adopted only when none
    # was established.
    def test_refresh_pending_proc_persists_once(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "manifest.json")
            doc = provision.fresh_manifest(tmp, True)
            doc["pending_procs"] = [
                {"role": "a", "pid": 1, "starttime": 100,
                 "detail": "old-a"},
                {"role": "b", "pid": 2, "starttime": 200,
                 "detail": "old-b"},
            ]
            provision.save_manifest(doc, path)
            provision._PERSIST = path
            saves = []
            real_save = provision.save_manifest

            def counting_save(manifest, where):
                saves.append(where)
                return real_save(manifest, where)

            try:
                with mock.patch.object(
                        provision, "save_manifest",
                        side_effect=counting_save):
                    provision.refresh_pending_proc(
                        doc, "a", 1, 777, "new-a")
            finally:
                provision._PERSIST = None
            self.assertEqual(len(saves), 1)
            by_role = {e["role"]: e
                       for e in doc["pending_procs"]}
            self.assertEqual(by_role["a"]["starttime"], 100)
            self.assertIn("identity conflict",
                          by_role["a"]["detail"])
            self.assertIn("new-a", by_role["a"]["detail"])
            self.assertEqual(by_role["b"]["detail"], "old-b")
            disk = json.loads(Path(path).read_text())
            self.assertEqual(len(disk["pending_procs"]), 2)
            # None preserves the prior starttime; an absent
            # record appends; an unestablished (None) identity
            # adopts the fresh observation.
            provision._PERSIST = None
            provision.refresh_pending_proc(
                doc, "a", 1, None, "newer-a")
            by_role = {e["role"]: e
                       for e in doc["pending_procs"]}
            self.assertEqual(by_role["a"]["starttime"], 100)
            provision.refresh_pending_proc(
                doc, "c", 3, 300, "fresh-c")
            self.assertEqual(len(doc["pending_procs"]), 3)
            doc["pending_procs"].append(
                {"role": "d", "pid": 4, "starttime": None,
                 "detail": "unidentified"})
            provision.refresh_pending_proc(
                doc, "d", 4, 400, "identified")
            by_role = {e["role"]: e
                       for e in doc["pending_procs"]}
            self.assertEqual(by_role["d"]["starttime"], 400)

    # S91-round5: fallback retirement never signals a recycled
    # occupant — an armed starttime that disagrees with the
    # fresh observation refuses the signal, preserves the
    # armed identity, and leaves the stranger alive. A
    # matching armed identity still proceeds to the kill.
    def test_retire_fresh_proc_refuses_recycled_occupant(self):
        import subprocess
        from unittest import mock
        stranger = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        owned = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            _, owned_start = provision.stat_state_start(
                owned.pid)
            with tempfile.TemporaryDirectory() as tmp:
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_procs"] = [
                    {"role": "recycled-role",
                     "pid": stranger.pid, "starttime": 1,
                     "detail": "armed"},
                    {"role": "owned-role", "pid": owned.pid,
                     "starttime": owned_start,
                     "detail": "armed"},
                ]
                path = os.path.join(tmp, "manifest.json")
                provision.save_manifest(doc, path)
                provision._PERSIST = path
                try:
                    with mock.patch.object(
                            provision, "kill_owned",
                            return_value=True) as kill, \
                            mock.patch.object(
                                provision, "signal_owned",
                                side_effect=AssertionError(
                                    "signalled stranger")):
                        refused = provision.retire_fresh_proc(
                            "recycled-role", stranger.pid, doc)
                        kill.assert_not_called()
                        matched = provision.retire_fresh_proc(
                            "owned-role", owned.pid, doc)
                finally:
                    provision._PERSIST = None
                self.assertFalse(refused)
                self.assertTrue(matched)
                kill.assert_called_once_with(
                    "owned-role", owned.pid, owned_start, 10)
                by_role = {e["role"]: e
                           for e in doc["pending_procs"]}
                self.assertEqual(
                    by_role["recycled-role"]["starttime"], 1)
                self.assertIn("identity conflict",
                              by_role["recycled-role"]["detail"])
                self.assertIsNone(stranger.poll())
                self.assertIsNone(owned.poll())
        finally:
            stranger.kill()
            stranger.wait()
            owned.kill()
            owned.wait()

    # S22-round3: the pin discipline the finding questions is the
    # implemented one — an exit under (or before) the pin converges
    # to gone without signalling: reaped and zombie children both
    # prove gone with os.kill never attempted.
    def test_kill_owned_exited_child_proves_gone_without_signal(self):
        import subprocess
        from unittest import mock
        reaped = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        _, reaped_start = provision.stat_state_start(reaped.pid)
        reaped.kill()
        reaped.wait()
        zombie = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        _, zombie_start = provision.stat_state_start(zombie.pid)
        zombie.kill()
        try:
            with mock.patch("os.kill") as killer:
                self.assertTrue(provision.kill_owned(
                    "test", reaped.pid, reaped_start, timeout=1))
                self.assertTrue(provision.kill_owned(
                    "test", zombie.pid, zombie_start, timeout=1))
                killer.assert_not_called()
        finally:
            zombie.wait()

    # S27-round3: a same-filesystem bind mounted AFTER the mount
    # snapshot shares the device and is absent from the set — the
    # walk must still refuse via the descriptor-bound mount ID.
    # The foreign mount ID below simulates that post-snapshot
    # bind (a real one is covered live in test_provision_live).
    def test_clear_dir_refuses_post_snapshot_same_fs_bind(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tree"
            sub = root / "sub"
            victim = sub / "victim.txt"
            root.mkdir(mode=0o700)
            sub.mkdir(mode=0o700)
            victim.write_bytes(b"shadowed-by-bind\n")
            root_fd = os.open(
                root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                # Empty snapshot (bind mounted after it) + a
                # foreign mount ID on the child: refuse, keep all.
                def fake_mnt(fd):
                    if fd == root_fd:
                        return 100
                    return 200
                with mock.patch.object(
                        provision, "_mnt_id_of",
                        side_effect=fake_mnt):
                    with self.assertRaisesRegex(
                            OSError, "mount boundary"):
                        provision.fd_clear_dir(
                            root_fd, "", frozenset())
                self.assertTrue(victim.exists())
                self.assertTrue(sub.exists())
                # Control: the same tree with no mock clears
                # normally — the refusal above came from the mount
                # identity, not the tree shape.
                provision.fd_clear_dir(root_fd, "", frozenset())
                self.assertFalse(sub.exists())
            finally:
                os.close(root_fd)

    # S62-round3: a SOLE foreign mount after a successful create
    # must not be adopted — record_mount compares the row against
    # the expected acquisition (source/type/super), not just
    # absence/stacking.
    # S62-round4: rollback refresh replaces the pending record
    # in memory and persists once, preserving the complete
    # acquisition evidence (fingerprint mnt_id plus the prior
    # record's canary/loop_backing). Durable boundaries: the
    # refresh persists exactly once (no drop/record crash
    # window), and a persistence failure leaves the on-disk
    # record intact (pre-fix the drop had already persisted,
    # stranding the live mount without custody).
    def test_rollback_refresh_persists_once_with_evidence(self):
        from unittest import mock
        for evidence_key, evidence_val in (
                ("canary", "abc123"),
                ("loop_backing", {"path": "/i", "dev": 7,
                                  "ino": 8})):
            with self.subTest(evidence=evidence_key):
                with tempfile.TemporaryDirectory() as tmp:
                    mnt = os.path.join(tmp, "mnt")
                    os.makedirs(mnt)
                    path = os.path.join(tmp, "manifest.json")
                    doc = provision.fresh_manifest(tmp, True)
                    doc["pending_acquisitions"] = [{
                        "kind": "mount", "key": mnt,
                        "role": "role", "target": mnt,
                        "fstype": "overlay", "source": "overlay",
                        "expect_super": [],
                        evidence_key: evidence_val,
                        "detail": "pre-admission",
                    }]
                    provision.save_manifest(doc, path)
                    provision._PERSIST = path
                    try:
                        fingerprint = {
                            "fstype": "overlay",
                            "source": "overlay", "mnt_id": 99,
                            "expect_super": [
                                "rw,lowerdir=/dev/fd/9"]}
                        row = {"target": mnt, "mnt_id": 99,
                               "root": "/", "fstype": "overlay",
                               "source": "overlay", "super": "rw"}
                        saves = []
                        real_save = provision.save_manifest

                        def counting_save(manifest, where):
                            saves.append(where)
                            return real_save(manifest, where)

                        # Refusal arm: a live row the helper
                        # refuses to retire.
                        with mock.patch.object(
                                provision, "read_mount_table",
                                return_value=[row]), \
                                mock.patch.object(
                                    provision,
                                    "retire_mount_via_helper",
                                    return_value=(
                                        "refused: foreign")), \
                                mock.patch.object(
                                    provision, "save_manifest",
                                    side_effect=counting_save):
                            note = provision.rollback_owned_mount(
                                doc, tmp, "role", mnt,
                                fingerprint)
                        self.assertIn("custody kept pending",
                                      note)
                        self.assertEqual(len(saves), 1)
                        kept = [e for e in
                                doc["pending_acquisitions"]
                                if e.get("key") == mnt]
                        self.assertEqual(len(kept), 1)
                        self.assertEqual(kept[0]["mnt_id"], 99)
                        self.assertEqual(kept[0][evidence_key],
                                         evidence_val)
                        self.assertIn("refused",
                                      kept[0]["detail"])
                        disk = json.loads(
                            Path(path).read_text())
                        pending = [e for e in disk[
                            "pending_acquisitions"]]
                        self.assertEqual(len(pending), 1)
                        self.assertEqual(pending[0]["mnt_id"],
                                         99)
                        self.assertEqual(
                            pending[0][evidence_key],
                            evidence_val)
                        # Failure boundary: persistence fails
                        # mid-refresh — the on-disk record stays
                        # intact (still the refusal refresh from
                        # above, never an empty pending set).
                        with mock.patch.object(
                                provision, "read_mount_table",
                                side_effect=provision.
                                AdmissionError("no table")), \
                                mock.patch.object(
                                    provision, "save_manifest",
                                    side_effect=provision.
                                    AdmissionError("no disk")):
                            with self.assertRaises(
                                    provision.AdmissionError):
                                provision.rollback_owned_mount(
                                    doc, tmp, "role", mnt,
                                    fingerprint)
                        disk = json.loads(
                            Path(path).read_text())
                        pending = [e for e in disk[
                            "pending_acquisitions"]]
                        self.assertEqual(len(pending), 1)
                        self.assertIn("refused",
                                      pending[0]["detail"])
                    finally:
                        provision._PERSIST = None

    # S74-round4: mount-failure taxonomy — moved reports parse
    # to (ID, observed location); timeouts, crashes, and
    # inconclusive helper post-reads are uncertain (keep);
    # only pre-effect refusals (plain FAILED, sudo exec
    # failure, rc==0 verified-but-unparseable) reconcile-drop.
    def test_classify_mount_failure_taxonomy(self):
        cls = provision._classify_mount_failure
        moved = ("mount /t moved during create (mnt=42 "
                 "observed=/o2): target moved")
        self.assertEqual(cls(moved), ("moved", 42, "/o2"))
        # Escaped observed locations decode.
        esc = provision._escape_report_field("/o 2/x")
        moved_esc = ("mount /t moved during create (mnt=7 "
                     f"observed={esc}): moved")
        self.assertEqual(cls(moved_esc), ("moved", 7, "/o 2/x"))
        # Truncated structure degrades to uncertain, keeping
        # the ID when it survived.
        self.assertEqual(
            cls("mount /t moved during create (mnt=9 "
                "observed-unknown): truncated"),
            ("uncertain", 9, None))
        self.assertEqual(
            cls("mount /t moved during create (garbage"),
            ("uncertain", None, None))
        # Uncertain markers.
        self.assertEqual(
            cls("mount /t effect uncertain after create: "
                "sudo timed out after 120s"),
            ("uncertain", None, None))
        # Refused class: pre-effect, exec failure, rc==0
        # verified-but-unparseable.
        self.assertEqual(
            cls("mount /t refused: rc=1 FAILED: no canary"),
            ("refused", None, None))
        self.assertEqual(
            cls("mount /t refused: rc=127 sudo exec failed"),
            ("refused", None, None))
        self.assertEqual(
            cls("mount /t report unparseable: mounted ???"),
            ("refused", None, None))
        self.assertEqual(cls(""), ("refused", None, None))
        self.assertEqual(cls(None), ("refused", None, None))

    # S74-round4: mount-fs failure normalization — helper
    # MOVED/UNCERTAIN lines, timeouts, and crashes become
    # keep-custody reports; pre-effect FAILED and sudo exec
    # failures stay refused-class.
    def test_mount_failure_normalization(self):
        from unittest import mock
        import types
        with tempfile.TemporaryDirectory() as tmp:
            guard = types.SimpleNamespace(dev=1, ino=2)
            target = os.path.join(tmp, "mnt")

            def attempt(rc, out, err):
                with mock.patch.object(
                        provision, "run_sudo",
                        return_value=(rc, out, err)):
                    return provision.mount_fs_via_helper(
                        tmp, guard, target, 3, 4, "overlay",
                        layers=[])

            reported, failure = attempt(
                1, "FAILED-MOVED: mnt=42 observed=/o2 moved\n",
                "")
            self.assertIsNone(reported)
            self.assertIn("moved during create", failure)
            kind, mid, obs = provision._classify_mount_failure(
                failure)
            self.assertEqual((kind, mid, obs),
                             ("moved", 42, "/o2"))

            reported, failure = attempt(
                1, "FAILED-UNCERTAIN: missing after create\n",
                "")
            self.assertIsNone(reported)
            self.assertIn("effect uncertain after create",
                          failure)

            reported, failure = attempt(
                124, "", "sudo timed out after 120s: mount-fs")
            self.assertIsNone(reported)
            self.assertIn("effect uncertain after create",
                          failure)
            self.assertIn("timed out", failure)

            reported, failure = attempt(
                1, "", "Traceback (most recent call last): boom")
            self.assertIsNone(reported)
            self.assertIn("effect uncertain after create",
                          failure)

            reported, failure = attempt(
                1, "FAILED: overlay needs 3 layers\n", "")
            self.assertIsNone(reported)
            self.assertIn("refused: rc=1", failure)

            reported, failure = attempt(
                127, "", "sudo exec failed: nope")
            self.assertIsNone(reported)
            self.assertIn("refused: rc=127", failure)

    # S74-round4: reconcile honors the failure taxonomy — moved
    # and uncertain outcomes refresh (never drop) pending
    # custody with the reported recovery identity; refused
    # outcomes keep the legacy adopt-or-drop behavior.
    def test_reconcile_mount_failure_taxonomy(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            fingerprint = {"fstype": "overlay",
                           "source": "overlay",
                           "expect_super": []}

            def doc_with_pending():
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [{
                    "kind": "mount", "key": mnt, "role": "role",
                    "target": mnt, "fstype": "overlay",
                    "source": "overlay", "expect_super": [],
                    "canary": "abc123",
                    "detail": "pre-admission",
                }]
                return doc

            moved = ("mount /t moved during create (mnt=42 "
                     f"observed={mnt}2): moved")
            doc = doc_with_pending()
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]):
                self.assertIsNone(
                    provision.reconcile_mount_effect(
                        doc, tmp, "role", mnt, fingerprint,
                        canary=(provision.MOUNT_CANARY_NAME,
                                "abc123"),
                        failure=moved))
            kept = doc["pending_acquisitions"]
            self.assertEqual(len(kept), 1)
            self.assertEqual(kept[0]["mnt_id"], 42)
            self.assertEqual(kept[0]["observed_target"],
                             f"{mnt}2")
            self.assertEqual(kept[0]["canary"], "abc123")
            self.assertIn("moved", kept[0]["detail"])
            # Uncertain: kept with a fresh detail, no ID.
            doc = doc_with_pending()
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]):
                self.assertIsNone(
                    provision.reconcile_mount_effect(
                        doc, tmp, "role", mnt, fingerprint,
                        failure="mount /t effect uncertain "
                                "after create: timeout"))
            kept = doc["pending_acquisitions"]
            self.assertEqual(len(kept), 1)
            self.assertNotIn("mnt_id", kept[0])
            self.assertIn("uncertain", kept[0]["detail"])
            # Refused with nothing live: legacy drop.
            doc = doc_with_pending()
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]):
                self.assertIsNone(
                    provision.reconcile_mount_effect(
                        doc, tmp, "role", mnt, fingerprint,
                        failure="mount /t refused: rc=1 "
                                "FAILED: no canary"))
            self.assertEqual(doc["pending_acquisitions"], [])

    def test_record_mount_refuses_sole_foreign_replacement(self):
        from unittest import mock
        expected = {"fstype": "ext4", "source": "/dev/loop9",
                    "expect_super": ["rw|"]}
        with tempfile.TemporaryDirectory() as tmp:
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            base = {"target": mnt, "mnt_id": 42, "root": "/",
                    "fstype": "ext4", "source": "/dev/loop9",
                    "super": "rw|"}
            variants = [
                ("foreign source",
                 dict(base, source="/dev/loop7"), True),
                ("foreign fstype",
                 dict(base, fstype="xfs"), True),
                ("foreign super",
                 dict(base, super="ro|"), True),
                ("expected occupant", dict(base), False),
            ]
            for name, row, refused in variants:
                with self.subTest(name):
                    doc = provision.fresh_manifest(tmp, True)
                    with mock.patch.object(
                            provision, "read_mount_table",
                            return_value=[row]):
                        if refused:
                            with self.assertRaisesRegex(
                                    provision.AdmissionError,
                                    "does not match expected"):
                                provision.record_mount(
                                    doc, tmp, "role", mnt,
                                    expected=expected)
                            self.assertEqual(doc["mounts"], [])
                        else:
                            provision.record_mount(
                                doc, tmp, "role", mnt,
                                expected=expected)
                            self.assertEqual(len(doc["mounts"]), 1)
                            self.assertEqual(
                                doc["mounts"][0]["source"],
                                "/dev/loop9")

    # S62-round3 end to end: successful mount command + a single
    # foreign mount at the target — admission refuses, pending
    # custody is retained (admission commits before the drop),
    # and no chown or file writes touch the foreign target.
    @mock.patch.object(
        provision, "read_loop_backing_id",
        side_effect=provision.LoopIdUnavailable("test"))
    def test_ext4_success_path_ignores_foreign_mount(self, _loop_id):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            manifest = os.path.join(tmp, "manifest.json")
            os.makedirs(run_root)
            calls = []

            def fake_sudo(argv, timeout=120):
                calls.append(list(argv))
                if "make-ext4" in argv:
                    return (0, "made-ext4 x\n", "")
                if "attach-loop" in argv:
                    return (0, "attached-loop /dev/loop9\n", "")
                if "retire-mount" in argv:
                    return (1, "", "FAILED: foreign occupant refused")
                if "retire-loop" in argv:
                    return (0, "retired-loop /dev/loop9\n", "")
                if "mount-fs" in argv:
                    # The helper mounted ours (mnt 42, fd-spelling
                    # source); the admission read below sees the
                    # foreign replacement (mnt 77) instead.
                    tgt = argv[argv.index("--target") + 1]
                    return (
                        0, f"mounted {tgt} mnt=42 "
                           f"source=/dev/fd/9 super=rw|\n", "")
                raise AssertionError(f"unexpected sudo: {argv}")

            doc = provision.fresh_manifest(run_root, True)
            provision._PERSIST = manifest
            guard = provision.RootAuthority(run_root)
            provision._ROOT_GUARD = guard
            try:
                with mock.patch.object(provision, "run_sudo",
                                       side_effect=fake_sudo):
                    with mock.patch.object(
                            provision.shutil, "which",
                            return_value="/sbin/x"):
                        image = os.path.join(
                            run_root, "ext4", "fs01.img")
                        mnt = os.path.join(run_root, "ext4", "mnt")
                        # Sole occupant is foreign: our mount was
                        # replaced before the admission read.
                        foreign = {"target": mnt, "mnt_id": 77,
                                   "root": "/", "fstype": "ext4",
                                   "source": "/dev/loop7",
                                   "super": "rw|"}
                        with mock.patch.object(
                                provision, "read_loop_backing",
                                return_value=image):
                            with mock.patch.object(
                                    provision, "read_mount_table",
                                    return_value=[foreign]):
                                provision.provision_ext4(
                                    doc, run_root)
            finally:
                provision._PERSIST = None
                provision._ROOT_GUARD = None
                guard.close()
            self.assertIn("not admitted",
                          doc["cells"]["FS01"]["reason"])
            self.assertEqual(doc["mounts"], [])
            # No privileged or content effects on the foreign
            # target: no chown, no file writes.
            self.assertFalse(any(c[:1] == ["chown"] for c in calls))
            self.assertFalse(os.path.exists(
                os.path.join(mnt, "a.bin")))
            self.assertFalse(os.path.exists(
                os.path.join(mnt, "alias.bin")))
            self.assertFalse(os.path.exists(
                os.path.join(mnt, "b.bin")))
            # Pending custody retained (exactly one record: the
            # rollback replaces, not duplicates).
            pending = [e for e in doc["pending_acquisitions"]
                       if e["kind"] == "mount" and e["key"] == mnt]
            self.assertEqual(len(pending), 1)

    # S17-round3: the loop validate, CLR, and post-proof share
    # ONE held device fd — a single open, GET/CLR/GET all on
    # that fd, no pathname re-resolution between validation and
    # effect. The old shape (validate-GET on one fd, CLR on a
    # freshly opened fd) opens three times and fails this.
    def test_retire_loop_effect_shares_validating_fd(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            backing = {"path": image, "dev": st.st_dev,
                       "ino": st.st_ino}
            fake_open, fake_ioctl, log = _loop_fd_script(
                [("id", st.st_dev, st.st_ino), ("enxio",)])
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=image), \
                    mock.patch.object(provision.os, "open",
                                      side_effect=fake_open), \
                    mock.patch.object(provision.fcntl, "ioctl",
                                      side_effect=fake_ioctl):
                self.assertIsNone(provision.retire_loop_now(
                    "/dev/loop7", backing, tmp))
            opens = [e for e in log if e[0] == "open"]
            self.assertEqual(len(opens), 1)
            held = opens[0][2]
            seq = [(e[1], e[2]) for e in log if e[0] == "ioctl"]
            self.assertEqual(
                seq, [(held, provision.LOOP_GET_STATUS64),
                      (held, provision.LOOP_CLR_FD),
                      (held, provision.LOOP_GET_STATUS64)])

    # S17-round3: device-node swap between validation and effect
    # (a root attacker re-resolving /dev/loopN at the final
    # boundary). Both sysfs validations see ours, but the
    # effect-time device open resolves to the foreign device.
    # S17-round4 fix: the old shape's effect-time open is its
    # ONLY open (inside _loop_clr_fd), so the swap must
    # redirect the FIRST routed open — the previous
    # [ours, ours, foreign] model never delivered foreign to
    # the old code and passed vacuously. The new shape
    # validates on its single held fd, sees the foreign
    # association, and refuses with no CLR; the old shape
    # cleared the foreign victim and reported discharged.
    def test_retire_loop_nodeswap_clears_validated_backing(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            backing = {"path": image, "dev": st.st_dev,
                       "ino": st.st_ino}
            other = str(Path(tmp) / "other.img")
            Path(other).write_bytes(b"other")
            ost = os.stat(other)
            foreign = (ost.st_dev, ost.st_ino)
            fake_open, fake_ioctl, log = _loop_fd_script(
                [], open_backings=[foreign])
            with mock.patch.object(
                    provision, "read_loop_backing",
                    side_effect=[image, image, None]), \
                    mock.patch.object(provision.os, "open",
                                      side_effect=fake_open), \
                    mock.patch.object(provision.fcntl, "ioctl",
                                      side_effect=fake_ioctl):
                failure = provision.retire_loop_now(
                    "/dev/loop7", backing, tmp)
            self.assertIn("refusing detach", failure)
            victims = [e[2] for e in log if e[0] == "clr-victim"]
            self.assertEqual(victims, [])

    # S17-round4: a recorded mount whose path vanished (renamed
    # away) but whose ID is still live anywhere — including
    # outside the run root — is a moved mount, not a
    # discharge. The helper's absence arm scans the whole
    # table before returning None.
    def test_retire_mount_vanished_path_id_live_reports_moved(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            os.makedirs(run_root)
            target = os.path.join(run_root, "mnt")  # absent
            expected = {"mnt_id": 4242, "fstype": "ext4",
                        "source": "x", "expect_super": []}
            row = {"target": "/elsewhere", "mnt_id": 4242,
                   "root": "/", "fstype": "ext4", "source": "x",
                   "super": "rw"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]):
                failure = provision.retire_mount_now(
                    target, expected, run_root)
            self.assertIn("moved (mnt=4242", failure)
            self.assertIn("/elsewhere", failure)
            self.assertIn("manual retirement required", failure)
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]):
                self.assertIsNone(provision.retire_mount_now(
                    target, expected, run_root))

    # S17-round4: the caller-side absence arm
    # (cleanup_one_mount) applies the same whole-table ID
    # scan — the public cleanup route cannot discharge a
    # moved mount through the helper/result gap.
    def test_cleanup_one_mount_absent_id_live_reports_moved(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            os.makedirs(run_root)
            entry = {"target": os.path.join(run_root, "mnt"),
                     "mnt_id": 111, "fstype": "ext4",
                     "source": "/dev/loop9", "actual_super": "rw|",
                     "expect_super": []}
            moved = [{"target": "/outside-run-root",
                      "mnt_id": 111, "root": "/",
                      "fstype": "ext4", "source": "/dev/loop9",
                      "super": "rw|"}]
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=moved):
                with mock.patch.object(
                        provision, "run_sudo") as sudo:
                    failure = provision.cleanup_one_mount(
                        entry, run_root)
            sudo.assert_not_called()
            self.assertIn("moved (mnt=111", failure)
            self.assertIn("manual retirement required", failure)
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]):
                self.assertIsNone(provision.cleanup_one_mount(
                    entry, run_root))

    # S17-round4: the public cleanup command reports a
    # recorded mount whose ID survives outside the run root
    # as moved/manual — end to end through cleanup_command,
    # not just the helper or the caller in isolation.
    def test_cleanup_reports_recorded_move_outside_run_root(
            self):
        from unittest import mock
        import contextlib
        import io
        import types
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            os.makedirs(run_root, mode=0o755)
            orig = os.path.join(run_root, "mnt")
            os.makedirs(orig)
            st = os.stat(run_root)
            manifest = os.path.join(tmp, "manifest.json")
            doc = provision.fresh_manifest(run_root, False)
            doc["run_root_identity"] = {"dev": st.st_dev,
                                        "ino": st.st_ino}
            doc["mounts"] = [{
                "target": orig, "mnt_id": 4242,
                "fstype": "ext4", "source": "/dev/loop9",
                "actual_super": "rw|", "expect_super": []}]
            Path(manifest).write_text(json.dumps(doc))
            args = types.SimpleNamespace(run_root=run_root,
                                         manifest=manifest)
            row = {"target": "/outside-run-root",
                   "mnt_id": 4242, "root": "/",
                   "fstype": "ext4", "source": "/dev/loop9",
                   "super": "rw|"}
            out = io.StringIO()
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]), \
                    contextlib.redirect_stdout(out):
                rc = provision.cleanup_command(args)
            self.assertEqual(rc, 1)
            self.assertIn("moved (mnt=4242", out.getvalue())
            self.assertIn("manual retirement required",
                          out.getvalue())

    # S17-round4: the mount-mutation lock serializes helpers —
    # a second acquirer blocks until the first releases (flock
    # on separate descriptions, including threads).
    def test_mount_exclock_serializes_helpers(self):
        import threading
        import time
        with tempfile.TemporaryDirectory() as tmp:
            fd_a = provision._mount_exclock_acquire(tmp)
            acquired = []

            def take():
                fd = provision._mount_exclock_acquire(tmp)
                acquired.append(True)
                provision._mount_exclock_release(fd)

            worker = threading.Thread(target=take)
            worker.start()
            try:
                time.sleep(0.2)
                self.assertEqual(acquired, [])
            finally:
                provision._mount_exclock_release(fd_a)
            worker.join(timeout=5)
            self.assertEqual(acquired, [True])

    # S17-round4: both mount-mutating CLIs take the lock —
    # retire-mount (detach path) and mount-fs (create path)
    # leave the lockfile behind, released.
    def test_mount_commands_take_exclock(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            os.makedirs(run_root)
            lock = os.path.join(
                run_root, provision.MOUNT_EXCLOCK_NAME)
            res = run_tool(
                "retire-mount", "--run-root", run_root,
                "--target", os.path.join(run_root, "mnt"),
                "--mnt-id", "4242", "--fstype", "ext4",
                "--source", "none")
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(lock))
            fd = os.open(lock, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
            target = os.path.join(run_root, "tgt")
            os.makedirs(target)
            rst = os.stat(run_root)
            tst = os.stat(target)
            res = run_tool(
                "mount-fs", "--run-root", run_root,
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--target", target,
                "--target-dev", str(tst.st_dev),
                "--target-ino", str(tst.st_ino),
                "--fstype", "bogus")
            self.assertEqual(res.returncode, 1)
            self.assertIn("unsupported fstype",
                          (res.stdout + res.stderr).lower()
                          .replace("-", " "))
            self.assertTrue(os.path.exists(lock))

    # S17-round4: interposition alarm — our row is gone after
    # the detach but a foreign row sits at our target that was
    # not there before the effect: a racer stacked after we
    # detached ours. Retain custody, never report discharged.
    # (S17-round5: the detach addresses verified staging, so
    # the old "our umount took the foreign top" reading is
    # excluded by construction; the alarm now covers
    # post-detach stacking at the target.)
    def test_retire_mount_foreign_appeared_alarms(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            foreign = {"target": target, "mnt_id": held + 1000,
                       "root": "/", "fstype": "tmpfs",
                       "source": "tmpfs", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            staged = dict(ours, target=staging)
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours], [staged],
                                 [foreign]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            return_value=None) as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            detach.assert_called_once_with(staging)
            self.assertIn("occupant changed", failure)
            self.assertIn("custody retained", failure)
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours], [staged],
                                 []]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            return_value=None):
                    self.assertIsNone(
                        provision.retire_mount_now(
                            target, record, run_root))

    # S17-round3: replica replacement after the open — the row
    # matches everything a rollback-style record (no mnt_id)
    # checks, but its mount ID differs from the snapshot taken
    # at open. The old shape admits and unmounts the replica;
    # the correspondence check refuses with no effect.
    def test_retire_mount_replica_after_open_refuses(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "fstype": "ext4",
                      "source": "/dev/loop9", "expect_super": []}
            replica = {"target": target, "mnt_id": held + 1000,
                       "root": "/", "fstype": "ext4",
                       "source": "/dev/loop9", "super": "rw|"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[replica], [replica]]):
                with mock.patch.object(
                        provision, "_umount2") as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            detach.assert_not_called()
            self.assertIn("refusing", failure)

    # S17-round3 positive control: the open-time snapshot and
    # both table observations agree — the detach proceeds (both
    # manifest-style records with mnt_id and rollback-style
    # records without).
    def test_retire_mount_held_fd_agreement_detaches(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            ours = {"target": target, "mnt_id": held, "root": "/",
                    "fstype": "ext4", "source": "/dev/loop9",
                    "super": "rw|"}
            records = [
                {"target": target, "mnt_id": held,
                 "fstype": "ext4", "source": "/dev/loop9",
                 "expect_super": []},
                {"target": target, "fstype": "ext4",
                 "source": "/dev/loop9", "expect_super": []},
            ]
            # S17-round5: the detach addresses verified
            # staging, never the shared target.
            staging = os.path.join(run_root, "staging")
            staged = dict(ours, target=staging)
            for record in records:
                with self.subTest(mnt_id=("manifest"
                                          if "mnt_id" in record
                                          else "rollback")):
                    with mock.patch.object(
                            provision, "read_mount_table",
                            side_effect=[[ours], [ours],
                                         [staged], []]):
                        with mock.patch.object(
                                provision, "_retire_stage_dir",
                                return_value=staging), \
                                mock.patch.object(
                                    provision, "_mount_move",
                                    return_value=None), \
                                mock.patch.object(
                                    provision, "_umount2",
                                    return_value=None
                                    ) as detach:
                            self.assertIsNone(
                                provision.retire_mount_now(
                                    target, record, run_root))
                    detach.assert_called_once_with(staging)

    # S17-round3: our mount moved away after the final
    # observation — the target reads clear but our mount ID is
    # still live elsewhere. Target-scoped post-proof reports
    # discharged and leaks custody; the whole-table proof
    # retains it.
    def test_retire_mount_moved_away_retains_custody(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            elsewhere = os.path.join(run_root, "elsewhere")
            os.makedirs(elsewhere)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            expected = {"target": target, "mnt_id": held,
                        "fstype": "ext4", "source": "/dev/loop9",
                        "expect_super": []}
            ours = {"target": target, "mnt_id": held, "root": "/",
                    "fstype": "ext4", "source": "/dev/loop9",
                    "super": "rw|"}
            moved = dict(ours, target=elsewhere)
            # S17-round5: the move to staging verifies, then
            # ours moves away before the post-proof — the
            # whole-table proof still retains custody.
            staging = os.path.join(run_root, "staging")
            staged = dict(ours, target=staging)
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours], [staged],
                                 [moved]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            return_value=errno.ENOENT):
                    failure = provision.retire_mount_now(
                        target, expected, run_root)
            self.assertIsNotNone(failure)
            self.assertIn("still live", failure)
            self.assertIn("custody retained", failure)
            self.assertIn("elsewhere", failure)

    # S17-round3: foreign stack landing after the move —
    # ours is still live at staging and a foreign mount
    # stacks at the (now plain) target; the post-proof
    # retains custody. A failed umount likewise defers to
    # the post-proof: ours live means retained, never a
    # bare refusal. (S17-round5: the detach addresses
    # staging, so a foreign top at the target can no longer
    # be detached by our umount.)
    def test_retire_mount_stack_after_final_retains(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            expected = {"target": target, "mnt_id": held,
                        "fstype": "ext4", "source": "/dev/loop9",
                        "expect_super": []}
            ours = {"target": target, "mnt_id": held, "root": "/",
                    "fstype": "ext4", "source": "/dev/loop9",
                    "super": "rw|"}
            foreign = {"target": target, "mnt_id": held + 1000,
                       "root": "/", "fstype": "tmpfs",
                       "source": "tmpfs", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            staged = dict(ours, target=staging)
            post = [staged]
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours], [staged],
                                 post]):
                def detach(where):
                    # Concurrent stacking at the actual final
                    # effect boundary: the foreign mount lands
                    # at the target after our move; ours is
                    # still live at staging.
                    post.append(foreign)
                    return None
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            side_effect=detach) as unmounter:
                    failure = provision.retire_mount_now(
                        target, expected, run_root)
            unmounter.assert_called_once_with(staging)
            self.assertIn("still live", failure)
            self.assertIn("custody retained", failure)
            # Failed umount + ours live: post-proof decides.
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours], [staged],
                                 [staged]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            return_value=errno.EBUSY):
                    failure = provision.retire_mount_now(
                        target, expected, run_root)
            self.assertIn("still live", failure)
            self.assertIn("custody retained", failure)

    # S17-round5: a swapped-in foreign mount reaches staging —
    # it is moved BACK to the target and reported loudly; no
    # detach ever addresses it (the round-5 post-empty
    # schedule: unmount-ours + mount-B + detach-B + empty
    # table can no longer return None).
    def test_retire_mount_staging_foreign_moves_back(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            swapped = {"target": staging,
                       "mnt_id": held + 1000, "root": "/",
                       "fstype": "tmpfs", "source": "tmpfs",
                       "super": "rw|"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours],
                                 [swapped]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None) as move, \
                        mock.patch.object(
                            provision, "_umount2") as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            detach.assert_not_called()
            self.assertEqual(
                move.call_args_list,
                [mock.call(target, staging),
                 mock.call(staging, target)])
            self.assertIn("staging holds foreign", failure)
            self.assertIn(f"mnt={held + 1000}", failure)
            self.assertIn("moved back", failure)
            self.assertIn("custody retained", failure)

    # S17-round5: an empty or stacked staging is left
    # untouched and loud — no move-back shuffle of an
    # ambiguous occupant, no detach.
    def test_retire_mount_staging_surprise_stays_loud(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            staged = dict(ours, target=staging)
            other = dict(staged, mnt_id=held + 1000)

            def attempt(stage_rows):
                with mock.patch.object(
                        provision, "read_mount_table",
                        side_effect=[[ours], [ours],
                                     stage_rows]):
                    with mock.patch.object(
                            provision, "_retire_stage_dir",
                            return_value=staging), \
                            mock.patch.object(
                                provision, "_mount_move",
                                return_value=None) as move, \
                            mock.patch.object(
                                provision, "_umount2"
                                ) as detach:
                        failure = provision.retire_mount_now(
                            target, record, run_root)
                return (failure, move, detach)

            failure, move, detach = attempt([])
            detach.assert_not_called()
            move.assert_called_once_with(target, staging)
            self.assertIn("staging empty", failure)
            self.assertIn("custody retained", failure)
            failure, move, detach = attempt([staged, other])
            detach.assert_not_called()
            move.assert_called_once_with(target, staging)
            self.assertIn("2 stacked", failure)
            self.assertIn("left untouched", failure)

    # S17-round5: a failed move refuses before any further
    # observation — no staging read, no detach.
    def test_retire_mount_move_failure_refuses(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=errno.EBUSY), \
                        mock.patch.object(
                            provision, "_umount2") as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            detach.assert_not_called()
            self.assertIn("not moved to staging", failure)

    # S17-round5: a foreign staging occupant the move-back
    # cannot restore is stranded loudly — the message names
    # the staging path and the foreign ID for manual
    # recovery; still no detach.
    def test_retire_mount_moveback_failure_reports_stranded(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            swapped = {"target": staging,
                       "mnt_id": held + 1000, "root": "/",
                       "fstype": "tmpfs", "source": "tmpfs",
                       "super": "rw|"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours],
                                 [swapped]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            side_effect=[None,
                                         errno.EBUSY]), \
                        mock.patch.object(
                            provision, "_umount2") as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            detach.assert_not_called()
            self.assertIn("move-back failed", failure)
            self.assertIn(staging, failure)
            self.assertIn(f"mnt={held + 1000}", failure)
            self.assertIn("manual recovery required", failure)

    # S17-round5: an unreadable staging table moves back and
    # stays loud — the unverifiable move is never detached.
    def test_retire_mount_staging_unverifiable_moves_back(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours],
                                 provision.AdmissionError(
                                     "denied")]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None) as move, \
                        mock.patch.object(
                            provision, "_umount2") as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            detach.assert_not_called()
            self.assertEqual(move.call_count, 2)
            self.assertIn("staging unverifiable", failure)
            self.assertIn("moved back", failure)
            self.assertIn("custody retained", failure)

    # S17-round5: staging dirs are exclusive, private, and
    # unpredictable.
    def test_retire_stage_dir_is_private_and_unique(self):
        with tempfile.TemporaryDirectory() as run_root:
            first = provision._retire_stage_dir(run_root)
            second = provision._retire_stage_dir(run_root)
            try:
                self.assertNotEqual(first, second)
                for path in (first, second):
                    st = os.stat(path)
                    self.assertTrue(stat.S_ISDIR(st.st_mode))
                    self.assertEqual(
                        stat.S_IMODE(st.st_mode), 0o700)
            finally:
                os.rmdir(first)
                os.rmdir(second)

    # S17-round3: our mount already moved away at the FIRST
    # observation — the target reads clear but the recorded
    # mount ID is live elsewhere. A manifest-style record
    # (with mnt_id) retains custody; a genuinely absent mount
    # (ID nowhere) still discharges.
    def test_retire_mount_early_moveaway_retains_custody(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            elsewhere = os.path.join(run_root, "elsewhere")
            os.makedirs(elsewhere)
            expected = {"target": target, "mnt_id": 424242,
                        "fstype": "ext4", "source": "/dev/loop9",
                        "expect_super": []}
            moved = {"target": elsewhere, "mnt_id": 424242,
                     "root": "/", "fstype": "ext4",
                     "source": "/dev/loop9", "super": "rw|"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[moved]):
                with mock.patch.object(
                        provision, "_umount2") as detach:
                    failure = provision.retire_mount_now(
                        target, expected, run_root)
            detach.assert_not_called()
            self.assertIsNotNone(failure)
            self.assertIn("still live", failure)
            self.assertIn("custody retained", failure)
            self.assertIn("elsewhere", failure)
            # Genuinely absent: the ID is nowhere — discharge.
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]):
                with mock.patch.object(
                        provision, "_umount2") as detach:
                    self.assertIsNone(provision.retire_mount_now(
                        target, expected, run_root))
            detach.assert_not_called()

    # S17-round6: FORCED post-staging-verification stack — the
    # hook plants B atop verified staging exactly at the
    # detach call (deterministic, in-window by construction:
    # the hook IS the _umount2 call). The detach takes the
    # stacker's top; the post-proof finds our ID alive — loud,
    # custody retained, never silent.
    def test_retire_mount_forced_stack_stays_loud(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            staged = dict(ours, target=staging)
            planted = []

            def hook(victim):
                # The plant lands inside the window (stack B
                # atop verified staging); the kernel detaches
                # the top — B — and reports success.
                planted.append(victim)
                return None

            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours], [staged],
                                 [staged]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            side_effect=hook) as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            self.assertEqual(planted, [staging])
            detach.assert_called_once_with(staging)
            self.assertIsNotNone(failure)
            self.assertIn("still live after detach", failure)
            self.assertIn("custody retained", failure)

    # S17-round6: FORCED post-staging-verification
    # move-away+replace — the hook moves ours to a spare
    # location and plants B at staging exactly at the detach
    # call. The detach takes B; the whole-table post-proof
    # finds our ID live elsewhere — loud, custody retained.
    def test_retire_mount_forced_moveaway_replace_loud(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            spare = os.path.join(run_root, "spare")
            os.makedirs(spare)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            staged = dict(ours, target=staging)
            moved = dict(ours, target=spare)
            planted = []

            def hook(victim):
                planted.append(victim)
                return None

            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours], [staged],
                                 [moved]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            side_effect=hook) as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            self.assertEqual(planted, [staging])
            detach.assert_called_once_with(staging)
            self.assertIsNotNone(failure)
            self.assertIn("still live after detach", failure)
            self.assertIn("spare", failure)
            self.assertIn("custody retained", failure)

    # S17-round6: FORCED post-staging-verification
    # detach+replace with a busy-pinned B — the hook detaches
    # ours, plants B at staging and holds B busy, so our
    # detach EBUSY's and B survives. Previously silent None
    # (stranded); now the staging-occupant alarm names the
    # staging path and the foreign ID — loud, left in place,
    # never detached, never silent.
    def test_retire_mount_forced_busy_replace_alarms(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            staged = dict(ours, target=staging)
            occupant = {"target": staging,
                        "mnt_id": held + 1000, "root": "/",
                        "fstype": "tmpfs", "source": "tmpfs",
                        "super": "rw|"}
            planted = []

            def hook(victim):
                planted.append(victim)
                return errno.EBUSY

            with mock.patch.object(
                    provision, "read_mount_table",
                    side_effect=[[ours], [ours], [staged],
                                 [occupant]]):
                with mock.patch.object(
                        provision, "_retire_stage_dir",
                        return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            return_value=None), \
                        mock.patch.object(
                            provision, "_umount2",
                            side_effect=hook) as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
            self.assertEqual(planted, [staging])
            detach.assert_called_once_with(staging)
            self.assertIsNotNone(failure)
            self.assertIn("staging still occupied", failure)
            self.assertIn(staging, failure)
            self.assertIn(f"mnt={held + 1000}", failure)
            self.assertIn("left in place", failure)
            self.assertIn("manual recovery required", failure)

    # S17-round6: RESIDUAL PIN — forced detach+replace with a
    # QUIESCENT B is indistinguishable from a clean retire in
    # every kernel observable (our umount detaches the plant,
    # final table empty, our ID gone — exactly the clean
    # shape), so the mechanism returns None for both. This
    # test PINS that parity: it fails-good if the mechanism
    # ever distinguishes the cases (re-grade the S17-round6
    # residual then — a failure here is progress, not
    # regression).
    # S124-round8: the plant is a STATEFUL mount/effect model,
    # not bookkeeping — a fake kernel substitutes B at the
    # effect boundary, records the actually-removed mount ID
    # (the victim oracle), and derives every later table read
    # from that state. The residual stays distinct from a
    # verified closure: parity is pinned, and the oracle
    # proves which mount each run detached.
    def test_retire_mount_detach_replace_residual_pinned(self):
        from unittest import mock

        class Kernel:
            """Fake mount table with an effect boundary."""

            def __init__(self, rows):
                self.mounts = [dict(row) for row in rows]
                self.removed = []

            def table(self):
                return [dict(row) for row in self.mounts]

            def move(self, src, dst):
                for row in self.mounts:
                    if row["target"] == src:
                        row["target"] = dst
                return None

            def umount(self, victim):
                for row in list(self.mounts):
                    if row["target"] == victim:
                        self.mounts.remove(row)
                        self.removed.append(row["mnt_id"])
                return None

        with tempfile.TemporaryDirectory() as run_root:
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                held = provision._mnt_id_of(probe)
            finally:
                os.close(probe)
            record = {"target": target, "mnt_id": held,
                      "fstype": "ext4", "source": "/dev/loop9",
                      "expect_super": []}
            ours = {"target": target, "mnt_id": held,
                    "root": "/", "fstype": "ext4",
                    "source": "/dev/loop9", "super": "rw|"}
            staging = os.path.join(run_root, "staging")
            # The attacker's quiescent plant B: substituted at
            # our random staging path inside the
            # verify-to-detach window (after ours was detached
            # by the same party), so our umount detaches B,
            # not ours.
            b_row = {"target": staging,
                     "mnt_id": held + 5000, "root": "/",
                     "fstype": "tmpfs", "source": "tmpfs",
                     "super": "rw|"}

            def attempt(plant):
                kernel = Kernel([ours])
                swapped = []

                def umount(victim):
                    if plant and not swapped:
                        # Attacker window step: detach ours,
                        # plant quiescent B at staging — then
                        # the mechanism's detach removes B.
                        kernel.mounts = [
                            row for row in kernel.mounts
                            if row["mnt_id"] != held]
                        kernel.mounts.append(dict(b_row))
                        swapped.append(True)
                    return kernel.umount(victim)

                with mock.patch.object(
                        provision, "read_mount_table",
                        side_effect=lambda: kernel.table()), \
                        mock.patch.object(
                            provision, "_retire_stage_dir",
                            return_value=staging), \
                        mock.patch.object(
                            provision, "_mount_move",
                            side_effect=kernel.move), \
                        mock.patch.object(
                            provision, "_umount2",
                            side_effect=umount) as detach:
                    failure = provision.retire_mount_now(
                        target, record, run_root)
                detach.assert_called_once_with(staging)
                return (failure, kernel)

            planted_outcome, planted_kernel = attempt(True)
            clean_outcome, clean_kernel = attempt(False)
            # Victim oracle: the planted run detached B's ID,
            # the clean run detached ours — the runs differ in
            # the stimulus, not just bookkeeping.
            self.assertEqual(planted_kernel.removed,
                             [held + 5000])
            self.assertEqual(clean_kernel.removed, [held])
            # Residual parity pinned: both silent None.
            self.assertIsNone(planted_outcome)
            self.assertEqual(planted_outcome, clean_outcome)

    # S15-round3: binding a run-root under a parent anyone
    # untrusted can rename in is refused — the (dev,ino)
    # authority still detects a swapped root, but roots are
    # only bound under contained parents (same doctrine as
    # manifest parents: sticky+trusted shared is contained).
    # S25-round4: unshared foreign-owned parents refuse too —
    # the owner check no longer depends on the write bits.
    def test_root_authority_parent_matrix(self):
        me = os.geteuid()
        alien = 65000 if me != 65000 else 65001
        cases = [
            # (mode, uid, accepted?)
            (0o700, me, True),
            (0o755, me, True),
            (0o775, me, True),    # group trust doctrine
            (0o1777, me, True),
            (0o1777, 0, True),    # /tmp-style, root trusted
            (0o1777, alien, False),
            (0o775, alien, False),
            (0o777, me, False),
            (0o777, alien, False),
            (0o755, alien, False),  # round4: unshared foreign owner
            (0o1755, alien, False),  # refuses at the gate too
        ]
        for mode, uid, accepted in cases:
            with self.subTest(mode=oct(mode), uid=uid):
                refusal = provision._run_root_parent_refusal(
                    self._stat(mode, uid), "/parent")
                if accepted:
                    self.assertIsNone(refusal)
                else:
                    self.assertIsNotNone(refusal)

    # S76-round4: the same directory stays admissible across the
    # controller-to-helper UID transition. My 0775 parent is
    # admitted by me (controller); re-evaluated as root with
    # SUDO_UID=me (helper) it stays admitted; without the
    # controller identity the helper still refuses a foreign
    # owner; malformed SUDO_UID never widens trust.
    def test_parent_policy_survives_uid_transition(self):
        from unittest import mock
        me = os.geteuid()
        if me == 0:
            self.skipTest("no controller/helper UID transition for root")
        alien = 65000 if me != 65000 else 65001
        check = provision._run_root_parent_refusal
        mine = self._stat(0o775, me)
        foreign = self._stat(0o775, alien)
        # Controller side: my 0775 parent admitted.
        self.assertIsNone(check(mine, "/parent"))
        # Helper side: euid 0 + SUDO_UID=me admits the same dir.
        with mock.patch.object(
                provision.os, "geteuid", return_value=0), \
                mock.patch.dict(
                    provision.os.environ,
                    {"SUDO_UID": str(me)}):
            self.assertIsNone(check(mine, "/parent"))
            # Genuinely foreign owners still refuse.
            self.assertIsNotNone(check(foreign, "/parent"))
        # Helper side without the controller identity: refuse.
        with mock.patch.object(
                provision.os, "geteuid", return_value=0), \
                mock.patch.dict(
                    provision.os.environ, {}, clear=True):
            self.assertIsNotNone(check(mine, "/parent"))
        # Malformed SUDO_UID never widens trust.
        for bogus in ("", "root", "-1", "1;2", " 12"):
            with self.subTest(sudo_uid=bogus):
                with mock.patch.object(
                        provision.os, "geteuid",
                        return_value=0), \
                        mock.patch.dict(
                            provision.os.environ,
                            {"SUDO_UID": bogus}):
                    self.assertIsNotNone(check(mine, "/parent"))

    def test_root_authority_refuses_untrusted_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Real unprotected parent: the bind refuses.
            shared = Path(tmp) / "shared"
            shared.mkdir(mode=0o777)
            os.chmod(shared, 0o777)
            root = shared / "run"
            root.mkdir()
            with self.assertRaisesRegex(
                    provision.RootAuthorityError, "parent"):
                provision.RootAuthority(str(root))
            # Real private parent: the bind succeeds.
            private = Path(tmp) / "private"
            private.mkdir(mode=0o700)
            root = private / "run"
            root.mkdir()
            guard = provision.RootAuthority(str(root))
            try:
                guard.verify()
            finally:
                guard.close()

    # S15-round3: privileged creation is descriptor-bound inside
    # a narrowly scoped helper. make-ext4 opens the image
    # itself, verifies the caller's (dev,ino), and runs mkfs on
    # /dev/fd/N — a swapped operand refuses with no effect.
    def test_make_ext4_refuses_foreign_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            run.mkdir()
            image = run / "fs01.img"
            image.write_bytes(b"sentinel" + bytes(1 << 20))
            st = os.stat(image)
            rst = os.stat(run)
            # Wrong operand identity: refuse, image untouched.
            proc = run_tool(
                "make-ext4", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--image", str(image),
                "--dev", str(st.st_dev),
                "--ino", str(st.st_ino + 1))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("FAILED", proc.stdout)
            self.assertEqual(image.read_bytes()[:8], b"sentinel")
            # Wrong ROOT identity: refuse without touching.
            proc = run_tool(
                "make-ext4", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino + 1),
                "--image", str(image),
                "--dev", str(st.st_dev),
                "--ino", str(st.st_ino))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("FAILED", proc.stdout)
            self.assertEqual(image.read_bytes()[:8], b"sentinel")

    def test_make_ext4_outside_root_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            run.mkdir()
            rst = os.stat(run)
            outside = Path(tmp) / "outside.img"
            outside.write_bytes(b"sentinel" + bytes(1 << 20))
            ost = os.stat(outside)
            proc = run_tool(
                "make-ext4", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--image", str(outside),
                "--dev", str(ost.st_dev),
                "--ino", str(ost.st_ino))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("FAILED", proc.stdout)
            self.assertEqual(outside.read_bytes()[:8], b"sentinel")
            # Symlink operand: never followed.
            target = Path(tmp) / "target.img"
            target.write_bytes(b"sentinel" + bytes(1 << 20))
            link = run / "link.img"
            link.symlink_to(target)
            lst = os.stat(target)
            proc = run_tool(
                "make-ext4", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--image", str(link),
                "--dev", str(lst.st_dev),
                "--ino", str(lst.st_ino))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("FAILED", proc.stdout)
            self.assertEqual(target.read_bytes()[:8], b"sentinel")

    @unittest.skipUnless(shutil.which("mkfs.ext4"),
                         "mkfs.ext4 required")
    def test_make_ext4_formats_verified_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            run.mkdir()
            image = run / "fs01.img"
            with open(image, "wb") as handle:
                handle.truncate(64 << 20)
            st = os.stat(image)
            rst = os.stat(run)
            proc = run_tool(
                "make-ext4", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--image", str(image),
                "--dev", str(st.st_dev),
                "--ino", str(st.st_ino))
            self.assertEqual(
                proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("made-ext4", proc.stdout)
            # Genuine ext4 superblock magic at 0x438, same file.
            with open(image, "rb") as handle:
                handle.seek(0x438)
                self.assertEqual(handle.read(2), b"\x53\xef")
            now = os.stat(image)
            self.assertEqual((now.st_dev, now.st_ino),
                             (st.st_dev, st.st_ino))

    # S15-round3: attach-loop binds a free loop device to the
    # verified image natively (LOOP_CONFIGURE on a
    # self-opened fd) — a swapped operand refuses before any
    # loop device is touched. (Happy path is privileged: live.)
    def test_attach_loop_refuses_foreign_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            run.mkdir()
            image = run / "fs01.img"
            image.write_bytes(b"sentinel" + bytes(1 << 20))
            st = os.stat(image)
            rst = os.stat(run)
            proc = run_tool(
                "attach-loop", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--image", str(image),
                "--dev", str(st.st_dev),
                "--ino", str(st.st_ino + 1))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("identity mismatch", proc.stdout)
            proc = run_tool(
                "attach-loop", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino + 1),
                "--image", str(image),
                "--dev", str(st.st_dev),
                "--ino", str(st.st_ino))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("FAILED", proc.stdout)

    # S73-round4: attach post-verify never clears — a mismatch
    # (rebound foreign) or an unreadable/detached status
    # refuses and leaves the device in place for reconcile.
    # Rollback may retire only an association whose ownership
    # remains established, so no CLR fires on any refusal
    # path; the configured fd is retained through validation
    # (each device opened exactly once) and always closed.
    def test_configure_loop_post_verify_never_clears(self):
        from unittest import mock
        real_open = os.open
        opened = []
        closed = []
        next_fd = [100]

        def fake_open(path, flags, *args, **kwargs):
            if path in ("/dev/loop-control", "/dev/loop9"):
                fd = next_fd[0]
                next_fd[0] += 1
                opened.append((path, fd))
                return fd
            return real_open(path, *args, **kwargs)

        def fake_close(fd):
            closed.append(fd)

        def fake_ioctl(fd, op, *args):
            if op == provision.LOOP_CTL_GET_FREE:
                return 9
            return 0

        def attempt(status):
            opened.clear()
            closed.clear()
            next_fd[0] = 100
            # None means ENXIO-detached (drive by value, not
            # the exception arm).
            get_kwargs = ({"side_effect": status}
                          if isinstance(status, Exception)
                          else {"return_value": status})
            with mock.patch.object(provision.os, "open",
                                   side_effect=fake_open), \
                    mock.patch.object(provision.os, "close",
                                       side_effect=fake_close), \
                    mock.patch.object(provision.fcntl, "ioctl",
                                       side_effect=fake_ioctl), \
                    mock.patch.object(
                        provision, "_loop_get_status_on",
                        **get_kwargs) as get, \
                    mock.patch.object(
                        provision, "_loop_clr_fd_on") as clr:
                try:
                    loop = provision._configure_free_loop(
                        50, 11, 22)
                except provision._HelperFail as exc:
                    return (None, str(exc), get, clr)
                return (loop, "", get, clr)

        def check_single_open(get):
            by_path = dict(opened)
            self.assertEqual(
                sorted(by_path), ["/dev/loop-control",
                                  "/dev/loop9"])
            loop_fd = by_path["/dev/loop9"]
            # Validated on the retained fd, never a reopen.
            get.assert_called_once_with(loop_fd)
            self.assertEqual(set(closed),
                             set(by_path.values()))

        # Mismatch (rebound foreign): refuse, never clear.
        loop, reason, get, clr = attempt((33, 44))
        self.assertIsNone(loop)
        self.assertIn("mismatch", reason)
        self.assertIn("never cleared", reason)
        clr.assert_not_called()
        check_single_open(get)
        # Unreadable status: refuse, never clear.
        loop, reason, get, clr = attempt(
            provision.LoopIdUnavailable("EACCES"))
        self.assertIsNone(loop)
        self.assertIn("unverifiable", reason)
        clr.assert_not_called()
        check_single_open(get)
        # Detached after configure: refuse, nothing to clear.
        loop, reason, get, clr = attempt(None)
        self.assertIsNone(loop)
        self.assertIn("detached after configure", reason)
        clr.assert_not_called()
        check_single_open(get)
        # Match: the bound device reports.
        loop, reason, get, clr = attempt((11, 22))
        self.assertEqual(loop, "/dev/loop9")
        clr.assert_not_called()
        check_single_open(get)

    # S15-round3: the helper-reported mount ID joins the
    # adoption fingerprint — a same-source/type row with a
    # different mount ID (a replacement after the helper's
    # post-verify) refuses.
    def test_fingerprint_honors_reported_mount_id(self):
        row = {"target": "/t", "mnt_id": 42, "root": "/",
               "fstype": "ext4", "source": "/dev/loop9",
               "super": "rw,relatime"}
        self.assertTrue(provision.mount_fingerprint_matches(
            row, {"fstype": "ext4", "source": "/dev/loop9",
                  "mnt_id": 42, "expect_super": ["rw,relatime"]}))
        self.assertFalse(provision.mount_fingerprint_matches(
            row, {"fstype": "ext4", "source": "/dev/loop9",
                  "mnt_id": 77, "expect_super": ["rw,relatime"]}))
        # Uncertain paths omit the ID: matching without it.
        self.assertTrue(provision.mount_fingerprint_matches(
            row, {"fstype": "ext4", "source": "/dev/loop9",
                  "expect_super": []}))

    # S71-round4: mount-to-loop correspondence — the live
    # filesystem's device ID must equal the recorded loop
    # node's own device ID. Mismatch (foreign loop at our
    # target), unreadable target, missing loop, non-block
    # loop, or symlinked loop all refuse.
    def test_mount_matches_loop_identity(self):
        from unittest import mock

        def node(mode, dev=0, rdev=0):
            entry = mock.Mock()
            entry.st_mode = mode
            entry.st_dev = dev
            entry.st_rdev = rdev
            return entry

        def attempt(target, loop, mid=42, live=42,
                    loop_fd=None):
            fds = iter([101, 102])
            opened = []

            def fake_open(path, flags, *args, **kwargs):
                opened.append(path)
                if path == "/mnt":
                    if isinstance(target, Exception):
                        raise target
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    return next(fds)
                if path == "/dev/loop9":
                    if isinstance(loop, Exception):
                        raise loop
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    return next(fds)
                raise AssertionError(path)

            def fake_fstat(fd):
                if fd == 101:
                    if isinstance(target, Exception):
                        raise target
                    return target
                if isinstance(loop, Exception):
                    raise loop
                return loop

            with mock.patch.object(
                    provision.os, "open",
                    side_effect=fake_open), \
                    mock.patch.object(
                        provision.os, "fstat",
                        side_effect=fake_fstat), \
                    mock.patch.object(
                        provision, "_mnt_id_of",
                        return_value=live), \
                    mock.patch.object(
                        provision.os, "stat",
                        side_effect=AssertionError(
                            "pathname stat")):
                got = provision._mount_matches_loop(
                    "/mnt", "/dev/loop9",
                    {"mnt_id": mid}, loop_fd)
            return (got, opened)

        loop = stat.S_IFBLK | 0o660
        got, opened = attempt(
            node(0o40755, dev=0x0709),
            node(loop, rdev=0x0709))
        self.assertTrue(got)
        self.assertEqual(opened, ["/mnt", "/dev/loop9"])
        # Foreign loop B mounted while ours (A) stays bound.
        self.assertFalse(attempt(
            node(0o40755, dev=0x070B),
            node(loop, rdev=0x0709))[0])
        # S71-round5: the live mount ID differs from the
        # selected row's (a swapped-in stranger): refuse even
        # with matching devices.
        self.assertFalse(attempt(
            node(0o40755, dev=0x0709),
            node(loop, rdev=0x0709),
            mid=42, live=43)[0])
        # Unreadable target / missing loop / non-block loop /
        # symlinked loop: retain uncertainty.
        self.assertFalse(attempt(
            PermissionError(13, "denied"),
            node(loop, rdev=0x0709))[0])
        self.assertFalse(attempt(
            node(0o40755, dev=0x0709),
            FileNotFoundError(2, "gone"))[0])
        self.assertFalse(attempt(
            node(0o40755, dev=0x0709),
            node(stat.S_IFREG | 0o644, rdev=0x0709))[0])
        self.assertFalse(attempt(
            node(0o40755, dev=0x0709),
            node(stat.S_IFLNK | 0o777, rdev=0x0709))[0])
        # S81-round5: with a retained loop fd the node is
        # never re-opened — a device-name substitution (same
        # spelling, swapped node) decides by the descriptor.
        got, opened = attempt(
            node(0o40755, dev=0x0709),
            node(loop, rdev=0x0709), loop_fd=77)
        self.assertTrue(got)
        self.assertEqual(opened, ["/mnt"])
        # Same spelling, but the HELD description is another
        # device: refuse (the pathname stat, which would
        # match, is never consulted — it explodes above).
        self.assertFalse(attempt(
            node(0o40755, dev=0x0709),
            node(loop, rdev=0x0708), loop_fd=77)[0])

    # S71-round6: loop_single_fd_proof opens the node once,
    # verifies the backing on that fd, runs the
    # correspondence on that same fd, and closes it —
    # exactly one open, one backing GET, one close, and the
    # correspondence fd equals the GET fd. Detached
    # (ENXIO) and unreadable nodes keep the round-5 sysfs
    # fallback; rebound, unopenable and detached-everywhere
    # nodes refuse without consulting the correspondence.
    def test_loop_single_fd_proof(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            backing = {"path": image, "dev": st.st_dev,
                       "ino": st.st_ino}
            row = {"target": os.path.join(tmp, "mnt"),
                   "mnt_id": 9, "root": "/", "fstype": "ext4",
                   "source": "/dev/loop9", "super": "rw"}

            def attempt(script, correspond=True,
                        open_err=None, live=True):
                sysfs = image if live is True else live
                fake_open, fake_ioctl, log = _loop_fd_script(
                    script)
                real_open = fake_open
                closes = []

                def counting_open(path, flags, *args):
                    if open_err is not None and path == \
                            "/dev/loop9":
                        raise open_err
                    return real_open(path, flags, *args)

                real_close = os.close

                def counting_close(fd):
                    closes.append(fd)
                    real_close(fd)

                with mock.patch.object(
                        provision, "read_loop_backing",
                        return_value=sysfs), \
                        mock.patch.object(
                            provision, "_mount_matches_loop",
                            return_value=correspond) as corr, \
                        mock.patch.object(
                            provision.os, "open",
                            side_effect=counting_open), \
                        mock.patch.object(
                            provision.fcntl, "ioctl",
                            side_effect=fake_ioctl), \
                        mock.patch.object(
                            provision.os, "close",
                            side_effect=counting_close):
                    got = provision.loop_single_fd_proof(
                        row["target"], "/dev/loop9", row,
                        backing)
                return (got, corr, log, closes)

            got, corr, log, closes = attempt(
                [("id", st.st_dev, st.st_ino)])
            self.assertTrue(got)
            opens = [e[2] for e in log if e[0] == "open"]
            gets = [e[1] for e in log if e[0] == "ioctl"]
            self.assertEqual(len(opens), 1)
            self.assertEqual(gets, opens)
            corr.assert_called_once_with(
                row["target"], "/dev/loop9", row,
                loop_fd=opens[0])
            self.assertIn(opens[0], closes)
            # Detached at the GET while sysfs still names our
            # image: the round-5 sysfs fallback still applies
            # (identical semantics — only the fd split
            # changed), so correspondence decides on the
            # retained fd.
            got, corr, log, closes = attempt([("enxio",)])
            self.assertTrue(got)
            opens = [e[2] for e in log if e[0] == "open"]
            corr.assert_called_once_with(
                row["target"], "/dev/loop9", row,
                loop_fd=opens[0])
            # Detached everywhere (sysfs gone too): refuse,
            # and correspondence never runs.
            got, corr, log, closes = attempt(
                [("enxio",)], live=None)
            self.assertFalse(got)
            corr.assert_not_called()
            # S109-round8: unreadable status with sysfs
            # naming our image REFUSES — the sysfs fallback
            # reads /sys/block/<mutable-basename>, not the
            # retained descriptor, so it could prove a
            # different device's backing than the one the
            # correspondence proof observes (swapped node).
            got, corr, log, closes = attempt([("eacces",)])
            self.assertFalse(got)
            corr.assert_not_called()
            # Unreadable status and foreign sysfs: refuse.
            other = str(Path(tmp) / "other.img")
            Path(other).write_bytes(b"other")
            got, corr, log, closes = attempt(
                [("eacces",)], live=other)
            self.assertFalse(got)
            corr.assert_not_called()
            # Rebound to a foreign image: refuse.
            got, corr, log, closes = attempt(
                [("id", st.st_dev, st.st_ino + 1)])
            self.assertFalse(got)
            corr.assert_not_called()
            # Bound and sitting on it, but the correspondence
            # fails: refuse (fd still opened once, closed).
            got, corr, log, closes = attempt(
                [("id", st.st_dev, st.st_ino)],
                correspond=False)
            self.assertFalse(got)
            opens = [e[2] for e in log if e[0] == "open"]
            corr.assert_called_once_with(
                row["target"], "/dev/loop9", row,
                loop_fd=opens[0])
            self.assertIn(opens[0], closes)
            # Node unopenable: refuse without any ioctl.
            got, corr, log, closes = attempt(
                [], open_err=FileNotFoundError(2, "gone"))
            self.assertFalse(got)
            corr.assert_not_called()
            self.assertEqual(
                [e for e in log if e[0] == "ioctl"], [])

    # S15-round3: a /dev/fd/N row source matches a recorded
    # loop-device source by shape — but shape alone never
    # adopts; the loop must still bind the recorded image.
    def test_fd_spelling_loop_shape(self):
        shape = provision._fd_spelling_loop_shape
        fp = {"fstype": "ext4", "source": "/dev/loop9"}
        self.assertTrue(shape(
            {"fstype": "ext4", "source": "/dev/fd/9"}, fp))
        self.assertFalse(shape(
            {"fstype": "ext4", "source": "/dev/loop9"}, fp))
        self.assertFalse(shape(
            {"fstype": "xfs", "source": "/dev/fd/9"}, fp))
        self.assertFalse(shape(
            {"fstype": "ext4", "source": "/dev/fd/9"},
            {"fstype": "ext4", "source": "overlay"}))

    def test_reconcile_fd_spelling_requires_live_binding(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            backing = {"path": image, "dev": st.st_dev,
                       "ino": st.st_ino}
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            row = {"target": mnt, "mnt_id": 9, "root": "/",
                   "fstype": "ext4", "source": "/dev/fd/9",
                   "super": "rw,relatime"}
            fingerprint = {"fstype": "ext4",
                           "source": "/dev/loop9",
                           "expect_super": []}

            # S71-round6: the loop-device syscalls run through
            # the hermetic seam — one stand-in fd serves the
            # backing GET and the correspondence runs on that
            # same fd (loop_fd=), so the log correlation below
            # proves the single-FD chain per path.
            def attempt(ident, correspond=True):
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [{
                    "kind": "mount", "key": mnt,
                    "target": mnt}]
                fake_open, fake_ioctl, log = _loop_fd_script(
                    [("id", ident[0], ident[1])])
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image), \
                        mock.patch.object(
                            provision, "_mount_matches_loop",
                            return_value=correspond) as corr, \
                        mock.patch.object(provision.os, "open",
                                          side_effect=fake_open), \
                        mock.patch.object(
                            provision.fcntl, "ioctl",
                            side_effect=fake_ioctl):
                    got = provision.reconcile_mount_effect(
                        doc, tmp, "ext4-fs01", mnt, fingerprint,
                        loop="/dev/loop9", loop_backing=backing)
                return (got, doc, corr, log)

            def assert_single_fd(corr, log):
                opens = [e[2] for e in log if e[0] == "open"]
                gets = [e[1] for e in log
                        if e[0] == "ioctl"]
                self.assertEqual(len(opens), 1)
                self.assertEqual(gets, opens)
                corr.assert_called_once_with(
                    mnt, "/dev/loop9", row, loop_fd=opens[0])

            # Loop still binds our image and the mounted
            # filesystem sits on it: adopt under the observed fd
            # spelling.
            got, doc, corr, log = attempt(
                (st.st_dev, st.st_ino))
            assert_single_fd(corr, log)
            self.assertEqual(got, row)
            self.assertEqual(doc["pending_acquisitions"], [])
            self.assertEqual(doc["mounts"][0]["source"],
                             "/dev/fd/9")
            # S71-round4: loop bound but a foreign filesystem at
            # our target (no mount-to-loop correspondence):
            # retain, never populate the stranger.
            got, doc, corr, log = attempt(
                (st.st_dev, st.st_ino), correspond=False)
            self.assertIsNone(got)
            self.assertEqual(len(doc["pending_acquisitions"]),
                             1)
            assert_single_fd(corr, log)
            # Loop rebound to a foreign image: retain — the
            # backing GET already fails, so correspondence
            # never runs on the rebound node.
            got, doc, corr, log = attempt(
                (st.st_dev, st.st_ino + 1))
            self.assertIsNone(got)
            self.assertEqual(len(doc["pending_acquisitions"]),
                             1)
            corr.assert_not_called()
            # Shape without loop proof: retain.
            doc = provision.fresh_manifest(tmp, True)
            doc["pending_acquisitions"] = [{
                "kind": "mount", "key": mnt, "target": mnt}]
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]):
                self.assertIsNone(
                    provision.reconcile_mount_effect(
                        doc, tmp, "ext4-fs01", mnt, fingerprint))
            self.assertEqual(len(doc["pending_acquisitions"]),
                             1)

    # S71-round5: correspondence runs on EVERY loop-backed
    # adoption — an exact-spelling row (a device-node rename
    # defeats both the spelling and the current-binding
    # check) adopts only with the descriptor proof.
    def test_reconcile_exact_source_requires_correspondence(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            backing = {"path": image, "dev": st.st_dev,
                       "ino": st.st_ino}
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            row = {"target": mnt, "mnt_id": 9, "root": "/",
                   "fstype": "ext4", "source": "/dev/loop9",
                   "super": "rw,relatime"}
            fingerprint = {"fstype": "ext4",
                           "source": "/dev/loop9",
                           "expect_super": []}

            # S71-round6: hermetic loop seam — the GET
            # reply carries our backing identity and the log
            # proves the correspondence ran on that same fd.
            def attempt(correspond):
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [{
                    "kind": "mount", "key": mnt,
                    "target": mnt}]
                fake_open, fake_ioctl, log = _loop_fd_script(
                    [("id", st.st_dev, st.st_ino)])
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image), \
                        mock.patch.object(
                            provision, "_mount_matches_loop",
                            return_value=correspond) as corr, \
                        mock.patch.object(provision.os, "open",
                                          side_effect=fake_open), \
                        mock.patch.object(
                            provision.fcntl, "ioctl",
                            side_effect=fake_ioctl):
                    got = provision.reconcile_mount_effect(
                        doc, tmp, "ext4-fs01", mnt,
                        fingerprint, loop="/dev/loop9",
                        loop_backing=backing)
                return (got, doc, corr, log)

            def assert_single_fd(corr, log):
                opens = [e[2] for e in log if e[0] == "open"]
                gets = [e[1] for e in log
                        if e[0] == "ioctl"]
                self.assertEqual(len(opens), 1)
                self.assertEqual(gets, opens)
                corr.assert_called_once_with(
                    mnt, "/dev/loop9", row, loop_fd=opens[0])

            # Exact spelling, loop bound, correspondence
            # proven: adopt.
            got, doc, corr, log = attempt(True)
            self.assertEqual(got, row)
            self.assertEqual(doc["pending_acquisitions"], [])
            assert_single_fd(corr, log)
            # Exact spelling and bound loop, but the mounted
            # filesystem is not on that node (renamed node):
            # retain, never adopt the stranger.
            got, doc, corr, log = attempt(False)
            self.assertIsNone(got)
            self.assertEqual(len(doc["pending_acquisitions"]),
                             1)
            assert_single_fd(corr, log)

    # S81-round4: post-mount loop binding — a plausible
    # foreign row (matching fstype, fd-shaped source) refuses
    # unless the mounted filesystem sits on our recorded loop.
    # Driven in-process with a mocked mount table (no
    # privileges); the live suite plants a real replacement.
    def test_post_verify_mount_requires_loop_binding(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            row = {"target": mnt, "mnt_id": 42, "root": "/",
                   "fstype": "ext4", "source": "/dev/fd/9",
                   "super": "rw"}

            def attempt(dev_match):
                fds = iter([101, 102])

                def fake_open(path, flags, *args, **kwargs):
                    if path in (mnt, "/dev/loop9"):
                        return next(fds)
                    raise AssertionError(path)

                def fake_fstat(fd):
                    entry = mock.Mock()
                    if fd == 101:
                        entry.st_dev = (0x0709 if dev_match
                                        else 0x070B)
                        return entry
                    entry.st_mode = stat.S_IFBLK | 0o660
                    entry.st_rdev = 0x0709
                    return entry

                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "_pin_fresh_mount",
                            return_value=(999, 42)), \
                        mock.patch.object(
                            provision.os, "open",
                            side_effect=fake_open), \
                        mock.patch.object(
                            provision.os, "fstat",
                            side_effect=fake_fstat), \
                        mock.patch.object(
                            provision, "_mnt_id_of",
                            return_value=42):
                    return provision._post_verify_mount(
                        mnt, "ext4", "/dev/loop9",
                        loop="/dev/loop9")

            got, pin = attempt(True)
            self.assertEqual(got, row)
            self.assertEqual(pin, 999)
            with self.assertRaises(
                    provision._HelperUncertain) as ctx:
                attempt(False)
            self.assertIn("not on /dev/loop9",
                          str(ctx.exception))

    # S81-round4: post-mount canary binding — a plausible
    # foreign row (matching fstype/source) refuses unless our
    # exact upper canary shows through the occupant. Wrong
    # content and absent canary both refuse before any chown.
    def test_post_verify_mount_requires_canary_binding(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            mid = real_mnt_id(mnt)
            row = {"target": mnt, "mnt_id": mid, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw,lowerdir=/dev/fd/9"}

            def attempt():
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "_pin_fresh_mount",
                            return_value=(999, mid)):
                    return provision._post_verify_mount(
                        mnt, "overlay", "overlay",
                        canary="abc123")

            Path(mnt,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"abc123")
            got, pin = attempt()
            self.assertEqual(got, row)
            self.assertEqual(pin, 999)
            Path(mnt,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"foreign")
            with self.assertRaises(
                    provision._HelperUncertain) as ctx:
                attempt()
            self.assertIn("canary mismatch",
                          str(ctx.exception))
            os.unlink(os.path.join(
                mnt, provision.MOUNT_CANARY_NAME))
            with self.assertRaises(provision._HelperUncertain):
                attempt()

    # S81-round5: overlay mount-fs without a planted upper
    # canary refuses before any effect (binding is mandatory,
    # never silently skipped) — and the expectation comes
    # from the held upper fd, never from argv.
    def test_mount_fs_overlay_requires_canary(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            role = run / "ov"
            for sub in ("lower", "upper", "work", "merged"):
                (role / sub).mkdir(parents=True)
            rst = os.stat(run)
            tst = os.stat(role / "merged")
            layers = []
            for name in ("lower", "upper", "work"):
                st = os.stat(role / name)
                layers += ["--layer",
                           f"{name}={role / name}:"
                           f"{st.st_dev}:{st.st_ino}"]
            proc = run_tool(
                "mount-fs", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--target", str(role / "merged"),
                "--target-dev", str(tst.st_dev),
                "--target-ino", str(tst.st_ino),
                "--fstype", "overlay", *layers)
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("upper canary unreadable", proc.stdout)
            # The token travels by planted file, never argv: a
            # --canary flag no longer exists to snoop.
            proc = run_tool(
                "mount-fs", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--target", str(role / "merged"),
                "--target-dev", str(tst.st_dev),
                "--target-ino", str(tst.st_ino),
                "--fstype", "overlay", "--canary", "abc123",
                *layers)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("unrecognized arguments",
                          proc.stderr)

    # S81-round5: the overlay binding expectation reads from
    # the held upper fd (real dirs, no mocks) — missing,
    # empty, and non-ascii plants refuse pre-effect.
    def test_read_upper_canary_from_held_fd(self):
        with tempfile.TemporaryDirectory() as tmp:
            upper = os.path.join(tmp, "upper")
            os.makedirs(upper)
            ufd = os.open(upper, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                        provision._HelperFail, "unreadable"):
                    provision._read_upper_canary(ufd)
                Path(upper,
                     provision.MOUNT_CANARY_NAME).write_bytes(
                         b"tok-9")
                self.assertEqual(
                    provision._read_upper_canary(ufd),
                    "tok-9")
                Path(upper,
                     provision.MOUNT_CANARY_NAME).write_bytes(
                         b"")
                with self.assertRaisesRegex(
                        provision._HelperFail, "empty"):
                    provision._read_upper_canary(ufd)
                Path(upper,
                     provision.MOUNT_CANARY_NAME).write_bytes(
                         b"\xff\xfe")
                with self.assertRaisesRegex(
                        provision._HelperFail, "ascii"):
                    provision._read_upper_canary(ufd)
            finally:
                os.close(ufd)

    # S81-round5: _mount_overlay_now pins the expectation
    # from upper before the effect and hands it (not argv) to
    # post-verify; mount(2) never runs without it.
    def test_mount_overlay_now_flows_upper_expected(self):
        import types
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run = os.path.join(tmp, "run")
            role = os.path.join(run, "ov")
            target = os.path.join(role, "merged")
            for sub in ("lower", "upper", "work", "merged"):
                os.makedirs(os.path.join(role, sub))
            Path(role, "upper",
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"planted-token")
            layers = []
            for name in ("lower", "upper", "work"):
                st = os.stat(os.path.join(role, name))
                layers.append(
                    f"{name}={role}/{name}:{st.st_dev}:"
                    f"{st.st_ino}")
            args = types.SimpleNamespace(
                run_root=run, target=target, layer=layers,
                extra_opts="", aux_root=None, canary=None)
            row = {"target": target, "mnt_id": 7, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw"}
            with mock.patch.object(
                    provision, "_mount2",
                    return_value=None) as mount, \
                    mock.patch.object(
                        provision, "_post_verify_mount",
                        return_value=(row, 777)) as post:
                got = provision._mount_overlay_now(
                    args, run, 55)
            self.assertEqual(got, (row, 777))
            mount.assert_called_once()
            self.assertEqual(
                post.call_args[1]["canary"], "planted-token")
            # No plant: pre-effect refusal, mount never runs.
            os.unlink(os.path.join(
                role, "upper", provision.MOUNT_CANARY_NAME))
            with mock.patch.object(
                    provision, "_mount2") as mount, \
                    mock.patch.object(
                        provision, "_post_verify_mount"
                    ) as post:
                with self.assertRaisesRegex(
                        provision._HelperFail, "upper canary"):
                    provision._mount_overlay_now(args, run, 55)
                mount.assert_not_called()
                post.assert_not_called()

    # S81-round6: a copied-token replacement planted BEFORE
    # the pin open (the clone carries our C1 token, so the
    # pin opens it and every round-5 gate passes) refuses at
    # the pin probe: the fresh challenge written through the
    # pin drains to the clone's upper, never to ours. The
    # refusal precedes any pin return, so no caller can chown
    # or report the clone. Unprivileged: plain directories
    # stand in for the clone view (merged) and our upper.
    def test_overlay_pre_pin_clone_refuses_pin_probe(self):
        import types
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run = os.path.join(tmp, "run")
            role = os.path.join(run, "ov")
            target = os.path.join(role, "merged")
            for sub in ("lower", "upper", "work", "merged"):
                os.makedirs(os.path.join(role, sub))
            upper = os.path.join(role, "upper")
            Path(upper,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"our-token")
            # The clone's merged view: our copied C1.
            Path(target,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"our-token")
            layers = []
            for name in ("lower", "upper", "work"):
                st = os.stat(os.path.join(role, name))
                layers.append(
                    f"{name}={role}/{name}:{st.st_dev}:"
                    f"{st.st_ino}")
            args = types.SimpleNamespace(
                run_root=run, target=target, layer=layers,
                extra_opts="", aux_root=None, canary=None)
            mid = real_mnt_id(target)
            clone = {"target": target, "mnt_id": mid,
                     "root": "/", "fstype": "overlay",
                     "source": "overlay", "super": "rw"}
            target_fd = os.open(
                target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                        provision, "_mount2",
                        return_value=None), \
                        mock.patch.object(
                            provision, "read_mount_table",
                            side_effect=[[], [clone]]):
                    with self.assertRaisesRegex(
                            provision._HelperUncertain,
                            "pin probe absent from our upper"):
                        provision._mount_overlay_now(
                            args, run, target_fd)
            finally:
                os.close(target_fd)
            # The challenge WAS written through the pin (into
            # the clone view) but never reached our upper —
            # a drain failure, not a write failure.
            probes_in_clone = [
                name for name in os.listdir(target)
                if name.startswith(
                    provision.MOUNT_PROBE_PREFIX)]
            self.assertEqual(len(probes_in_clone), 1)
            self.assertEqual(
                [name for name in os.listdir(upper)
                 if name.startswith(
                     provision.MOUNT_PROBE_PREFIX)], [])
            self.assertEqual(
                Path(target,
                     provision.MOUNT_CANARY_NAME).read_bytes(),
                b"our-token")

    # S81-round6: the pin probe passes when the pinned mount
    # drains to our upper — the challenge written through the
    # pin reads back from the held upper fd, and the mount
    # reports with its pin. Unprivileged: the upper spec
    # names the same directory the pin opens (a perfect-drain
    # model); the live suite proves it on a real overlay.
    def test_overlay_pin_probe_passes_draining_mount(self):
        import types
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run = os.path.join(tmp, "run")
            role = os.path.join(run, "ov")
            target = os.path.join(role, "merged")
            for sub in ("lower", "upper", "work", "merged"):
                os.makedirs(os.path.join(role, sub))
            Path(target,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"our-token")
            layers = []
            for name in ("lower", "work"):
                st = os.stat(os.path.join(role, name))
                layers.append(
                    f"{name}={role}/{name}:{st.st_dev}:"
                    f"{st.st_ino}")
            st = os.stat(target)
            layers.append(f"upper={target}:{st.st_dev}:"
                          f"{st.st_ino}")
            args = types.SimpleNamespace(
                run_root=run, target=target, layer=layers,
                extra_opts="", aux_root=None, canary=None)
            mid = real_mnt_id(target)
            row = {"target": target, "mnt_id": mid,
                   "root": "/", "fstype": "overlay",
                   "source": "overlay", "super": "rw"}
            target_fd = os.open(
                target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                        provision, "_mount2",
                        return_value=None), \
                        mock.patch.object(
                            provision, "read_mount_table",
                            side_effect=[[], [row]]):
                    got, pin_fd = provision._mount_overlay_now(
                        args, run, target_fd)
            finally:
                os.close(target_fd)
            try:
                self.assertEqual(got, row)
                os.fstat(pin_fd)
                probes = [
                    name for name in os.listdir(target)
                    if name.startswith(
                        provision.MOUNT_PROBE_PREFIX)]
                self.assertEqual(len(probes), 1)
                self.assertEqual(
                    os.stat(os.path.join(target, probes[0])
                           ).st_mode & 0o777, 0o600)
            finally:
                os.close(pin_fd)

    # S81-round6: the pre-mount token file is created 0600 —
    # a world-readable token hands every local user the
    # content for a copied-token pre-pin clone.
    def test_overlay_canary_file_created_private(self):
        import types
        from unittest import mock
        tmp = tempfile.mkdtemp(prefix="provision-s81-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run_root = os.path.join(tmp, "run")
        manifest = os.path.join(tmp, "manifest.json")
        os.makedirs(run_root)

        def fake_sudo(argv, timeout=120):
            if "mount-fs" in argv:
                return (1, "", "FAILED: nope")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        doc["cells"]["FS04"] = {"status": "skipped",
                                "needs_privilege": True,
                                "reason": ""}
        provision._PERSIST = manifest
        guard = provision.RootAuthority(run_root)
        provision._ROOT_GUARD = guard
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[]):
                    provision.mount_overlay(
                        doc, run_root, "ov-xino-off",
                        ",xino=off,metacopy=off", "FS04")
        finally:
            provision._PERSIST = None
            provision._ROOT_GUARD = None
            guard.close()
        token = os.path.join(run_root, "ov-xino-off", "upper",
                             provision.MOUNT_CANARY_NAME)
        self.assertEqual(os.stat(token).st_mode & 0o777, 0o600)

    # S74-round4: table-diff post-verify — a target renamed
    # around mount(2) is found at its observed mountpoint by
    # table difference, gates-checked there, and reported as
    # moved (mount ID + observed target) instead of a false
    # "missing" failure. Unprivileged: real canary files under
    # plain directories stand in for the occupant (no mount);
    # the live suite renames a real mount.
    def test_post_verify_mount_reports_moved_target(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            orig = os.path.join(tmp, "merged")
            moved = os.path.join(tmp, "merged2")
            os.makedirs(orig)
            os.makedirs(moved)
            mid = real_mnt_id(moved)
            Path(moved,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"abc123")
            row = {"target": moved, "mnt_id": mid, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, mid)):
                with self.assertRaises(
                        provision._HelperMoved) as ctx:
                    provision._post_verify_mount(
                        orig, "overlay", "overlay",
                        canary="abc123", pre=frozenset())
            self.assertEqual(ctx.exception.mnt_id, mid)
            self.assertEqual(ctx.exception.observed, moved)
            # A pre-existing occupant under the moved mount:
            # stacked at the observed name, uncertain.
            covered = dict(row, mnt_id=mid + 100,
                           source="tmpfs", fstype="tmpfs")
            pre_covered = frozenset([(
                mid + 100, moved, "tmpfs", "tmpfs", "rw",
                "/")])
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[covered, row]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, mid)):
                with self.assertRaisesRegex(
                        provision._HelperUncertain,
                        "ambiguous stacked mount"):
                    provision._post_verify_mount(
                        orig, "overlay", "overlay",
                        canary="abc123", pre=pre_covered)
            # At the verified name the same row succeeds.
            row_at_orig = dict(row, target=orig)
            Path(orig,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"abc123")
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row_at_orig]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, mid)):
                got, pin = provision._post_verify_mount(
                    orig, "overlay", "overlay",
                    canary="abc123", pre=frozenset())
                self.assertEqual(got, row_at_orig)
                self.assertEqual(pin, 999)

    # S108-round8: clone+moved combination — a pre-pin
    # replacement (copied token, different upper) at a moved
    # target must NOT gain acquisition authority. The
    # pin-probe challenge runs before any _HelperMoved report;
    # the unbound clone refuses instead.
    def test_post_verify_clone_moved_combination_refuses(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            orig = os.path.join(tmp, "merged")
            moved = os.path.join(tmp, "merged2")
            upper = os.path.join(tmp, "upper")
            os.makedirs(orig)
            os.makedirs(moved)
            os.makedirs(upper)
            mid = real_mnt_id(moved)
            Path(moved,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"abc123")
            row = {"target": moved, "mnt_id": mid, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw"}
            pin_fd = os.open(moved,
                             os.O_RDONLY | os.O_DIRECTORY)
            upper_fd = os.open(upper,
                               os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "_pin_fresh_mount",
                            return_value=(pin_fd, mid)):
                    with self.assertRaisesRegex(
                            provision._HelperUncertain,
                            "pin probe"):
                        provision._post_verify_mount(
                            orig, "overlay", "overlay",
                            canary="abc123", pre=frozenset(),
                            upper_fd=upper_fd)
            finally:
                os.close(upper_fd)
            # The probe reached the pinned (clone) mount but is
            # absent from OUR upper — the refusal is the
            # binding proof, not a missing write.
            probes = [name for name in os.listdir(moved)
                      if name.startswith(
                          provision.MOUNT_PROBE_PREFIX)]
            self.assertEqual(len(probes), 1)
            self.assertEqual(os.listdir(upper), [])

    # S74-round6: the pin open itself fails (target renamed
    # before the pin, possibly out of the run root) — the
    # added row passing every binding gate is still recovered
    # with its mount ID and observed target (_HelperMoved),
    # never an ID-less uncertainty. Unprivileged: real canary
    # files under plain directories stand in for the
    # occupant; the live suite renames a real mount pre-pin
    # and runs actual cleanup.
    #
    # S108-round8: that recovery grants acquisition authority,
    # so overlay candidates (token-copyable, no held-upper
    # binding without a pin) report _HelperUncertain with the
    # observed ID/location for manual retirement — never a
    # moved report that pending cleanup could auto-retire.
    def test_post_verify_pin_failure_recovers_moved(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            orig = os.path.join(tmp, "merged")
            moved = os.path.join(tmp, "merged2")
            os.makedirs(orig)
            os.makedirs(moved)
            mid = real_mnt_id(moved)
            Path(moved,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"abc123")
            row = {"target": moved, "mnt_id": mid, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw"}
            pin_exc = provision._HelperUncertain(
                "fresh mount not pinnable (gone)")
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        side_effect=pin_exc):
                with self.assertRaises(
                        provision._HelperUncertain) as ctx:
                    provision._post_verify_mount(
                        orig, "overlay", "overlay",
                        canary="abc123", pre=frozenset())
            # S108-round8: unverified observation, not
            # acquisition — but the observed ID/location stay
            # in the message for manual retirement.
            seen = str(ctx.exception)
            self.assertIn(f"mnt={mid}", seen)
            self.assertIn(moved, seen)
            self.assertIn("manual", seen)
            # Nothing gate-passing: the ORIGINAL pin failure
            # propagates (identity preserved), never a
            # fabricated move.
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        side_effect=pin_exc):
                with self.assertRaises(
                        provision._HelperUncertain) as ctx:
                    provision._post_verify_mount(
                        orig, "overlay", "overlay",
                        canary="abc123", pre=frozenset())
            self.assertIn("not pinnable", str(ctx.exception))
            # Two gate-passing added rows: ambiguous, never a
            # guessed move.
            moved_b = os.path.join(tmp, "merged3")
            os.makedirs(moved_b)
            Path(moved_b,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"abc123")
            row_b = dict(row, target=moved_b)
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row, row_b]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        side_effect=pin_exc):
                with self.assertRaisesRegex(
                        provision._HelperUncertain,
                        "ambiguous moved mount"):
                    provision._post_verify_mount(
                        orig, "overlay", "overlay",
                        canary="abc123", pre=frozenset())
            # A same-content row already in pre is not
            # "added": no recovery off stale rows.
            pre = frozenset([(mid, moved, "overlay",
                              "overlay", "rw", "/")])
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        side_effect=pin_exc):
                with self.assertRaises(
                        provision._HelperUncertain) as ctx:
                    provision._post_verify_mount(
                        orig, "overlay", "overlay",
                        canary="abc123", pre=pre)
            self.assertIn("not pinnable", str(ctx.exception))

    # S81-round5: diff selection narrows added rows to our
    # pinned ID first — a parallel job's mount in the same
    # window is ignored, never ambiguous. An empty diff falls
    # through to the pathname proof — a same-name replacement
    # still fails with the established binding reasons.
    def test_post_verify_mount_diff_fallbacks(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            mnt = os.path.join(tmp, "mnt")
            other = os.path.join(tmp, "other")
            os.makedirs(mnt)
            os.makedirs(other)
            mid = real_mnt_id(mnt)
            for place in (mnt, other):
                Path(place,
                     provision.MOUNT_CANARY_NAME).write_bytes(
                         b"abc123")

            def mkrow(target, mnt_id):
                return {"target": target, "mnt_id": mnt_id,
                        "root": "/", "fstype": "overlay",
                        "source": "overlay", "super": "rw"}

            # Two added rows, ours pinned: the stranger is
            # ignored, ours verifies.
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[mkrow(mnt, mid),
                                  mkrow(other, mid + 1)]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, mid)):
                got, pin = provision._post_verify_mount(
                    mnt, "overlay", "overlay",
                    canary="abc123", pre=frozenset())
                self.assertEqual(got["mnt_id"], mid)
                self.assertEqual(got["target"], mnt)
                self.assertEqual(pin, 999)
            # Two added rows with the SAME ID: impossible in
            # a real table — defensive refusal, never a pick.
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[mkrow(mnt, mid),
                                  mkrow(other, mid)]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, mid)):
                with self.assertRaisesRegex(
                        provision._HelperUncertain,
                        "duplicate mount ID"):
                    provision._post_verify_mount(
                        mnt, "overlay", "overlay",
                        canary="abc123", pre=frozenset())
            # No added row but a foreign same-name occupant:
            # the pathname proof fails with the S81 reason.
            Path(mnt,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"foreign")
            row = mkrow(mnt, mid)
            pre = frozenset([(
                mid, mnt, "overlay", "overlay", "rw", "/")])
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, mid)):
                with self.assertRaisesRegex(
                        provision._HelperUncertain,
                        "canary mismatch"):
                    provision._post_verify_mount(
                        mnt, "overlay", "overlay",
                        canary="abc123", pre=pre)
            # No added row and nothing at the name: uncertain
            # (the effect fired — never a plain refusal).
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, mid)):
                with self.assertRaisesRegex(
                        provision._HelperUncertain,
                        "missing after create"):
                    provision._post_verify_mount(
                        mnt, "overlay", "overlay",
                        canary="abc123", pre=frozenset())
                # Plain _HelperFail still catches (subclass).
                with self.assertRaises(provision._HelperFail):
                    provision._post_verify_mount(
                        mnt, "overlay", "overlay",
                        canary="abc123", pre=frozenset())

    # S81-round5: a replacement carrying the COPIED correct
    # token still refuses — the pin cross-check binds the
    # report to the acquisition independently of replayable
    # content (the stranger's fresh ID never equals the
    # pinned one: no recycling while ours is alive).
    def test_post_verify_mount_copied_token_still_refuses(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            pinned = 7701
            stranger = {"target": mnt, "mnt_id": 7702,
                        "root": "/", "fstype": "overlay",
                        "source": "overlay", "super": "rw"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[stranger]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, pinned)), \
                    mock.patch.object(
                        provision, "_canary_matches",
                        return_value=True):
                with self.assertRaisesRegex(
                        provision._HelperUncertain,
                        "changed during effect"):
                    provision._post_verify_mount(
                        mnt, "overlay", "overlay",
                        canary="abc123", pre=frozenset())
                # Same verdict on the pathname path (no diff):
                # the content passes, the acquisition does not.
                with self.assertRaisesRegex(
                        provision._HelperUncertain,
                        "changed during effect"):
                    provision._post_verify_mount(
                        mnt, "overlay", "overlay",
                        canary="abc123")

    # S81-round5: pin ownership — post-verify closes the pin
    # on every raise and transfers it open on success (the
    # caller chowns + reports through it, then closes).
    def test_post_verify_mount_pin_ownership(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            row = {"target": mnt, "mnt_id": 42, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw"}
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, 42)), \
                    mock.patch.object(
                        provision, "_canary_matches",
                        return_value=True), \
                    mock.patch.object(
                        provision.os, "close") as close:
                got, pin = provision._post_verify_mount(
                    mnt, "overlay", "overlay",
                    canary="abc123")
                self.assertEqual((got, pin), (row, 999))
                close.assert_not_called()
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[]), \
                    mock.patch.object(
                        provision, "_pin_fresh_mount",
                        return_value=(999, 42)), \
                    mock.patch.object(
                        provision.os, "close") as close:
                with self.assertRaises(
                        provision._HelperUncertain):
                    provision._post_verify_mount(
                        mnt, "overlay", "overlay",
                        canary="abc123")
                close.assert_called_once_with(999)

    def test_pending_mount_fd_spelling_retires_when_bound(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            row = {"target": mnt, "mnt_id": 9, "root": "/",
                   "fstype": "ext4", "source": "/dev/fd/9",
                   "super": "rw,relatime"}
            entry = {"kind": "mount", "key": mnt, "target": mnt,
                     "fstype": "ext4", "source": "/dev/loop9",
                     "expect_super": [],
                     "loop_backing": {
                         "path": image, "dev": st.st_dev,
                         "ino": st.st_ino}}

            # S71-round6: hermetic loop seam; the log
            # correlation proves the correspondence ran on the
            # same fd the backing GET answered on.
            def attempt(ident, correspond=True):
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [dict(entry)]
                fake_open, fake_ioctl, log = _loop_fd_script(
                    [("id", ident[0], ident[1])])
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image), \
                        mock.patch.object(
                            provision, "_mount_matches_loop",
                            return_value=correspond) as corr, \
                        mock.patch.object(
                            provision, "cleanup_one_mount",
                            return_value=None) as retire, \
                        mock.patch.object(provision.os, "open",
                                          side_effect=fake_open), \
                        mock.patch.object(
                            provision.fcntl, "ioctl",
                            side_effect=fake_ioctl):
                    failures = (
                        provision.cleanup_pending_acquisitions(
                            doc, tmp))
                return (failures, retire, corr, log)

            def assert_single_fd(corr, log):
                opens = [e[2] for e in log if e[0] == "open"]
                gets = [e[1] for e in log
                        if e[0] == "ioctl"]
                self.assertEqual(len(opens), 1)
                self.assertEqual(gets, opens)
                corr.assert_called_once_with(
                    mnt, "/dev/loop9", row, loop_fd=opens[0])

            failures, retire, corr, log = attempt(
                (st.st_dev, st.st_ino))
            self.assertEqual(failures, [])
            retire.assert_called_once()
            self.assertEqual(
                retire.call_args[0][0]["source"], "/dev/fd/9")
            assert_single_fd(corr, log)
            # S71-round4: loop bound but a foreign filesystem at
            # our target (no mount-to-loop correspondence): the
            # stranger is left in place, never unmounted.
            failures, retire, corr, log = attempt(
                (st.st_dev, st.st_ino), correspond=False)
            self.assertEqual(len(failures), 1)
            self.assertIn("not provably ours", failures[0])
            retire.assert_not_called()
            assert_single_fd(corr, log)
            # Rebound loop: the backing GET already fails, so
            # correspondence never runs on the rebound node.
            failures, retire, corr, log = attempt(
                (st.st_dev, st.st_ino + 1))
            self.assertEqual(len(failures), 1)
            self.assertIn("not provably ours", failures[0])
            retire.assert_not_called()
            corr.assert_not_called()

    # S71-round5: recovery adoption gates the exact arm too —
    # an exact-spelling row retires only when the recorded
    # loop still binds our image AND the occupant sits on
    # that node. (The exact arm previously checked neither.)
    def test_pending_mount_exact_spelling_requires_binding(
            self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            image = str(Path(tmp) / "fs01.img")
            Path(image).write_bytes(b"image")
            st = os.stat(image)
            mnt = os.path.join(tmp, "mnt")
            os.makedirs(mnt)
            row = {"target": mnt, "mnt_id": 9, "root": "/",
                   "fstype": "ext4", "source": "/dev/loop9",
                   "super": "rw,relatime"}
            entry = {"kind": "mount", "key": mnt, "target": mnt,
                     "fstype": "ext4", "source": "/dev/loop9",
                     "expect_super": [],
                     "loop_backing": {
                         "path": image, "dev": st.st_dev,
                         "ino": st.st_ino}}

            # S71-round6: hermetic loop seam; the log
            # correlation proves the correspondence ran on the
            # same fd the backing GET answered on.
            def attempt(ident, correspond=True):
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [dict(entry)]
                fake_open, fake_ioctl, log = _loop_fd_script(
                    [("id", ident[0], ident[1])])
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "read_loop_backing",
                            return_value=image), \
                        mock.patch.object(
                            provision, "_mount_matches_loop",
                            return_value=correspond) as corr, \
                        mock.patch.object(
                            provision, "cleanup_one_mount",
                            return_value=None) as retire, \
                        mock.patch.object(provision.os, "open",
                                          side_effect=fake_open), \
                        mock.patch.object(
                            provision.fcntl, "ioctl",
                            side_effect=fake_ioctl):
                    failures = (
                        provision.cleanup_pending_acquisitions(
                            doc, tmp))
                return (failures, retire, corr, log)

            def assert_single_fd(corr, log):
                opens = [e[2] for e in log if e[0] == "open"]
                gets = [e[1] for e in log
                        if e[0] == "ioctl"]
                self.assertEqual(len(opens), 1)
                self.assertEqual(gets, opens)
                corr.assert_called_once_with(
                    mnt, "/dev/loop9", row, loop_fd=opens[0])

            failures, retire, corr, log = attempt(
                (st.st_dev, st.st_ino))
            self.assertEqual(failures, [])
            retire.assert_called_once()
            assert_single_fd(corr, log)
            # Bound loop, wrong occupant: left in place.
            failures, retire, corr, log = attempt(
                (st.st_dev, st.st_ino), correspond=False)
            self.assertEqual(len(failures), 1)
            self.assertIn("not provably ours", failures[0])
            retire.assert_not_called()
            assert_single_fd(corr, log)
            # Exact spelling, rebound loop: left in place —
            # the backing GET already fails, so
            # correspondence never runs on the rebound node.
            failures, retire, corr, log = attempt(
                (st.st_dev, st.st_ino + 1))
            self.assertEqual(len(failures), 1)
            self.assertIn("not provably ours", failures[0])
            retire.assert_not_called()
            corr.assert_not_called()

    # S72-round4: pending overlay cleanup carries the
    # acquisition canary — a foreign same-type overlay/overlay row
    # at our target (wrong canary content) is left in place, never
    # unmounted; exact content retires.
    def test_pending_overlay_cleanup_requires_canary(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            merged = os.path.join(tmp, "merged")
            os.makedirs(merged)
            mid = real_mnt_id(merged)
            row = {"target": merged, "mnt_id": mid, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw,lowerdir=/dev/fd/9"}
            entry = {"kind": "mount", "key": merged,
                     "target": merged, "fstype": "overlay",
                     "source": "overlay", "expect_super": [],
                     "canary": "abc123"}

            def attempt():
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [dict(entry)]
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "cleanup_one_mount",
                            return_value=None) as retire:
                    failures = (
                        provision.cleanup_pending_acquisitions(
                            doc, tmp))
                return (failures, retire, doc)

            # Foreign same-type occupant (wrong canary): refuse.
            Path(merged, ".tt04-mount-canary").write_bytes(
                b"foreign")
            failures, retire, doc = attempt()
            self.assertEqual(len(failures), 1)
            self.assertIn("not provably ours", failures[0])
            retire.assert_not_called()
            self.assertEqual(len(doc["pending_acquisitions"]), 1)
            # Our occupant (exact canary): retire.
            Path(merged, ".tt04-mount-canary").write_bytes(
                b"abc123")
            failures, retire, doc = attempt()
            self.assertEqual(failures, [])
            retire.assert_called_once()
            self.assertEqual(
                retire.call_args[0][0]["mnt_id"], mid)

    # S72-round5: a recorded mount ID that is gone from the
    # whole table is never swapped for a same-fingerprint
    # occupant's — the replacement is refused (even with a
    # matching canary) and the known ID preserved. A matching
    # ID still adopts.
    def test_pending_mount_known_id_refuses_replacement(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            merged = os.path.join(tmp, "merged")
            os.makedirs(merged)
            Path(merged, ".tt04-mount-canary").write_bytes(
                b"abc123")
            known = real_mnt_id(merged)
            stranger = known + 100

            def attempt(mid):
                row = {"target": merged, "mnt_id": mid,
                       "root": "/", "fstype": "overlay",
                       "source": "overlay",
                       "super": "rw,lowerdir=/dev/fd/9"}
                entry = {"kind": "mount", "key": merged,
                         "target": merged, "fstype": "overlay",
                         "source": "overlay", "expect_super": [],
                         "canary": "abc123", "mnt_id": known}
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [entry]
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=[row]), \
                        mock.patch.object(
                            provision, "cleanup_one_mount",
                            return_value=None) as retire:
                    failures = (
                        provision.cleanup_pending_acquisitions(
                            doc, tmp))
                return (failures, retire, doc)

            failures, retire, doc = attempt(stranger)
            self.assertEqual(len(failures), 1)
            self.assertIn(f"recorded mount-ID {known}",
                          failures[0])
            self.assertIn(f"occupant has ID {stranger}",
                          failures[0])
            self.assertIn("replacement refused", failures[0])
            retire.assert_not_called()
            kept = doc["pending_acquisitions"][0]
            self.assertEqual(kept["mnt_id"], known)
            failures, retire, doc = attempt(known)
            self.assertEqual(failures, [])
            retire.assert_called_once()
            self.assertEqual(
                retire.call_args[0][0]["mnt_id"], known)

    # S74-round5: rollback never discharges a helper-reported
    # mount ID that is still live elsewhere (the role
    # directory renamed after the report) — custody refreshes
    # with the observed location. A truly absent mount still
    # drops.
    def test_rollback_owned_mount_keeps_moved_id(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            os.makedirs(run_root)
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            fingerprint = {"fstype": "ext4",
                           "source": "/dev/loop9",
                           "expect_super": [], "mnt_id": 42}

            def attempt(table):
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [{
                    "kind": "mount", "key": target,
                    "target": target, "mnt_id": 42,
                    "detail": "acquiring"}]
                path = os.path.join(tmp, "manifest.json")
                provision.save_manifest(doc, path)
                provision._PERSIST = path
                try:
                    with mock.patch.object(
                            provision, "read_mount_table",
                            return_value=table):
                        note = provision.rollback_owned_mount(
                            doc, run_root, "ext4-fs01", target,
                            fingerprint)
                finally:
                    provision._PERSIST = None
                return (note, doc)

            moved = [{"target": "/elsewhere", "mnt_id": 42,
                      "root": "/", "fstype": "ext4",
                      "source": "/dev/loop9", "super": "rw"}]
            note, doc = attempt(moved)
            self.assertIn("custody kept pending", note)
            kept = doc["pending_acquisitions"]
            self.assertEqual(len(kept), 1)
            self.assertEqual(kept[0]["mnt_id"], 42)
            self.assertEqual(kept[0]["observed_target"],
                             "/elsewhere")
            note, doc = attempt([])
            self.assertIn("already absent", note)
            self.assertEqual(doc["pending_acquisitions"], [])

    # S74-round5: reconciliation never absence-discharges a
    # known mount ID that is still live elsewhere, even for a
    # refused-class failure. Truly-absent still drops.
    def test_reconcile_keeps_known_id_on_refused_failure(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            os.makedirs(run_root)
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            fingerprint = {"fstype": "ext4",
                           "source": "/dev/loop9",
                           "expect_super": [], "mnt_id": 42}
            refused = (f"mount {target} refused: rc=1 "
                       f"pre-effect denial")

            def attempt(table):
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [{
                    "kind": "mount", "key": target,
                    "target": target, "mnt_id": 42,
                    "detail": "acquiring"}]
                path = os.path.join(tmp, "manifest.json")
                provision.save_manifest(doc, path)
                provision._PERSIST = path
                try:
                    with mock.patch.object(
                            provision, "read_mount_table",
                            return_value=table):
                        adopted = (
                            provision.reconcile_mount_effect(
                                doc, run_root, "ext4-fs01",
                                target, fingerprint,
                                failure=refused))
                finally:
                    provision._PERSIST = None
                return (adopted, doc)

            moved = [{"target": "/elsewhere", "mnt_id": 42,
                      "root": "/", "fstype": "ext4",
                      "source": "/dev/loop9", "super": "rw"}]
            adopted, doc = attempt(moved)
            self.assertIsNone(adopted)
            kept = doc["pending_acquisitions"]
            self.assertEqual(len(kept), 1)
            self.assertEqual(kept[0]["mnt_id"], 42)
            adopted, doc = attempt([])
            self.assertIsNone(adopted)
            self.assertEqual(doc["pending_acquisitions"], [])

    # S74-round5: ownership-stage failures are post-effect —
    # _own_fresh_root raises _HelperUncertain (the mount fired
    # and verified before this stage), and mount-fs reports
    # FAILED-UNCERTAIN so the caller keeps custody.
    def test_own_fresh_root_failures_are_post_effect(self):
        import types
        args = types.SimpleNamespace(
            own_uid=1000, own_gid=None, target="/tmp/x")
        with self.assertRaises(provision._HelperUncertain):
            provision._own_fresh_root(args, "/tmp", 999)

    def test_mount_fs_reports_uncertain_after_ownership_failure(
            self):
        import contextlib
        import io
        import types
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            os.makedirs(run_root)
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            rst = os.stat(run_root)
            tst = os.stat(target)
            args = types.SimpleNamespace(
                run_root=run_root, root_dev=rst.st_dev,
                root_ino=rst.st_ino, target=target,
                target_dev=tst.st_dev, target_ino=tst.st_ino,
                fstype="ext4", loop="/dev/loop9",
                backing_dev=1, backing_ino=2, layer=[],
                extra_opts="", aux_root=None, aux_dev=None,
                aux_ino=None, own_uid=1000, own_gid=None)
            row = {"target": target, "mnt_id": 42,
                   "root": "/", "fstype": "ext4",
                   "source": "/dev/loop9", "super": "rw"}
            out = io.StringIO()
            with mock.patch.object(
                    provision, "_mount_ext4_now",
                    return_value=(row, 999)), \
                    contextlib.redirect_stdout(out):
                rc = provision.mount_fs_command(args)
            self.assertEqual(rc, 1)
            self.assertIn("FAILED-UNCERTAIN", out.getvalue())

    # S74-round4: ID-keyed pending recovery — a moved mount is
    # found by its carried mount ID wherever it sits. A
    # binding-proven occupant reports manual retirement with
    # the live location (never auto-unmounted off-nominal); a
    # binding-refused occupant is left in place; a vanished ID
    # at an empty original heals silently.
    def test_pending_mount_moved_recovers_by_id(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            orig = os.path.join(tmp, "merged")
            moved = os.path.join(tmp, "merged2")
            os.makedirs(orig)
            os.makedirs(moved)
            mid = real_mnt_id(moved)
            row = {"target": moved, "mnt_id": mid, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw"}
            entry = {"kind": "mount", "key": orig,
                     "target": orig, "fstype": "overlay",
                     "source": "overlay", "expect_super": [],
                     "canary": "abc123", "mnt_id": mid,
                     "observed_target": moved,
                     "detail": "target moved during mount"}

            def attempt(table):
                doc = provision.fresh_manifest(tmp, True)
                doc["pending_acquisitions"] = [dict(entry)]
                with mock.patch.object(
                        provision, "read_mount_table",
                        return_value=table), \
                        mock.patch.object(
                            provision, "cleanup_one_mount",
                            return_value=None) as retire:
                    failures = (
                        provision.cleanup_pending_acquisitions(
                            doc, tmp))
                return (failures, retire)

            # Moved, binding proven at the live location:
            # manual retirement with the location named.
            Path(moved, provision.MOUNT_CANARY_NAME).write_bytes(
                b"abc123")
            failures, retire = attempt([row])
            self.assertEqual(len(failures), 1)
            self.assertIn(f"moved (mnt={mid}", failures[0])
            self.assertIn(moved, failures[0])
            self.assertIn("manual retirement required",
                          failures[0])
            retire.assert_not_called()
            # Moved, occupant replaced (wrong canary): left in
            # place, never unmounted.
            Path(moved, provision.MOUNT_CANARY_NAME).write_bytes(
                b"foreign")
            failures, retire = attempt([row])
            self.assertEqual(len(failures), 1)
            self.assertIn("not provably ours", failures[0])
            retire.assert_not_called()
            # ID vanished and nothing at the original: silent
            # (the effect is gone; nothing to recover).
            failures, retire = attempt([])
            self.assertEqual(failures, [])
            retire.assert_not_called()

    # S74-round4: the unrecorded-mount sweep knows moved-but-
    # custodied mounts by their observed location — cleanup
    # reports the manual retirement once, never an additional
    # "unrecorded mount" stray for the same occupant.
    def test_cleanup_suppresses_observed_moved_mount(self):
        from unittest import mock
        import contextlib
        import io
        import types
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            os.makedirs(run_root, mode=0o755)
            orig = os.path.join(run_root, "merged")
            moved = os.path.join(run_root, "merged2")
            os.makedirs(orig)
            os.makedirs(moved)
            Path(moved,
                 provision.MOUNT_CANARY_NAME).write_bytes(
                     b"abc123")
            st = os.stat(run_root)
            manifest = os.path.join(tmp, "manifest.json")
            doc = provision.fresh_manifest(run_root, False)
            doc["run_root_identity"] = {"dev": st.st_dev,
                                        "ino": st.st_ino}
            mid = real_mnt_id(moved)
            doc["pending_acquisitions"] = [{
                "kind": "mount", "key": orig, "target": orig,
                "fstype": "overlay", "source": "overlay",
                "expect_super": [], "canary": "abc123",
                "mnt_id": mid, "observed_target": moved,
                "detail": "target moved during mount"}]
            Path(manifest).write_text(json.dumps(doc))
            args = types.SimpleNamespace(run_root=run_root,
                                         manifest=manifest)
            row = {"target": moved, "mnt_id": mid, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw"}
            out = io.StringIO()
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]), \
                    contextlib.redirect_stdout(out):
                rc = provision.cleanup_command(args)
            self.assertEqual(rc, 1)
            self.assertIn("manual retirement required",
                          out.getvalue())
            self.assertNotIn("unrecorded mount",
                             out.getvalue())

    # S15-round3: the mounted-line parser binds the report to
    # the request — malformed lines and wrong targets refuse.
    def test_parse_mounted_line(self):
        parse = provision._parse_mounted_line
        self.assertEqual(
            parse("mounted /t mnt=42 source=/dev/fd/9 "
                  "super=rw,relatime\n", "/t"),
            (42, "/dev/fd/9", "rw,relatime"))
        self.assertEqual(
            parse("mounted /a b/mnt mnt=7 source=overlay "
                  "super=rw|x\n", "/a b/mnt"),
            (7, "overlay", "rw|x"))
        self.assertEqual(
            parse("mounted /x mnt=1 mnt=7 source=overlay "
                  "super=rw\n", "/x mnt=1"),
            (7, "overlay", "rw"))
        for bad, target in [
                ("", "/t"),
                ("FAILED: nope\n", "/t"),
                ("mounted /t mnt=42 super=rw\n", "/t"),
                ("mounted /t mnt=42 source=\n", "/t"),
                ("mounted /t mnt=x source=s super=rw\n", "/t"),
                ("mounted /t mnt=42 source=s super=\n", "/t"),
                ("mounted /t mnt=42 source=a b super=rw\n",
                 "/t"),
                ("mounted /t mnt=42 source=s super=a b\n", "/t"),
                ("mounted /other mnt=42 source=s super=rw\n",
                 "/t"),
        ]:
            with self.subTest(line=bad):
                self.assertIsNone(parse(bad, target))

    # S77-round4: the helper success report survives admitted
    # line separators — format/parse round-trips a LF target
    # (plus space, tab, CR, and backslash) exactly, instead of
    # splitting the report before its fingerprint fields. Raw
    # line separators and unknown escapes refuse.
    def test_mounted_line_escapes_line_separators(self):
        parse = provision._parse_mounted_line
        format_line = provision._format_mounted_line
        targets = [
            "/tmp/a\nb/mnt",
            "/tmp/a\rb/mnt",
            "/tmp/a\tb mnt",
            "/tmp/a\\b/mnt",
            "/x mnt=1\nsource=x super=y",
        ]
        for target in targets:
            with self.subTest(target=target):
                line = format_line(
                    target, 42, "/dev/fd/9", "rw,relatime")
                self.assertNotIn("\n", line)
                self.assertNotIn("\r", line)
                self.assertEqual(
                    parse(line + "\n", target),
                    (42, "/dev/fd/9", "rw,relatime"))
        # Escaped separators inside source/super decode too.
        line = format_line(
            "/t", 7, "/dev/with space\n", "a\tb")
        self.assertEqual(
            parse(line + "\n", "/t"),
            (7, "/dev/with space\n", "a\tb"))
        # Raw separators and unknown escapes refuse.
        for bad, target in [
                ("mounted /a\nb mnt=1 source=s super=rw\n",
                 "/a\nb"),
                ("mounted /a\rb mnt=1 source=s super=rw\n",
                 "/a\rb"),
                ("mounted /t mnt=1 source=s\\q super=rw\n",
                 "/t"),
                ("mounted /t mnt=1 source=s super=rw\\1\n",
                 "/t"),
                ("mounted /t\\ mnt=1 source=s super=rw\n",
                 "/t\\"),
        ]:
            with self.subTest(line=bad):
                self.assertIsNone(parse(bad, target))

    # S15-round3: uncertain-path overlay adoption requires the
    # pre-mount canary to show through merged with exact
    # content — absent, wrong, symlinked, or oversized content
    # retains pending custody.
    def test_reconcile_overlay_requires_canary(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            merged = os.path.join(tmp, "merged")
            os.makedirs(merged)
            doc = provision.fresh_manifest(tmp, True)
            doc["pending_acquisitions"] = [{
                "kind": "mount", "key": merged, "role": "ov",
                "target": merged, "fstype": "overlay",
                "source": "overlay"}]
            mid = real_mnt_id(merged)
            row = {"target": merged, "mnt_id": mid, "root": "/",
                   "fstype": "overlay", "source": "overlay",
                   "super": "rw,lowerdir=/dev/fd/9"}
            fingerprint = {"fstype": "overlay",
                           "source": "overlay",
                           "expect_super": []}
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]):
                # No canary file: retain.
                self.assertIsNone(
                    provision.reconcile_mount_effect(
                        doc, tmp, "ov", merged, fingerprint,
                        canary=(".c", "abc123")))
                self.assertEqual(len(doc["pending_acquisitions"]),
                                 1)
                # Wrong content: retain.
                Path(merged, ".c").write_bytes(b"nope")
                self.assertIsNone(
                    provision.reconcile_mount_effect(
                        doc, tmp, "ov", merged, fingerprint,
                        canary=(".c", "abc123")))
                self.assertEqual(len(doc["pending_acquisitions"]),
                                 1)
                # Exact content: adopt.
                Path(merged, ".c").write_bytes(b"abc123")
                self.assertEqual(
                    provision.reconcile_mount_effect(
                        doc, tmp, "ov", merged, fingerprint,
                        canary=(".c", "abc123")),
                    row)
                self.assertEqual(doc["pending_acquisitions"], [])
                self.assertTrue(any(
                    e["target"] == merged for e in doc["mounts"]))
            # Symlinked canary: refuse even with right content
            # behind the link.
            doc["pending_acquisitions"] = [{
                "kind": "mount", "key": merged, "role": "ov",
                "target": merged, "fstype": "overlay",
                "source": "overlay"}]
            doc["mounts"] = []
            os.unlink(os.path.join(merged, ".c"))
            real = os.path.join(tmp, "real")
            Path(real).write_bytes(b"abc123")
            os.symlink(real, os.path.join(merged, ".c"))
            with mock.patch.object(
                    provision, "read_mount_table",
                    return_value=[row]):
                self.assertIsNone(
                    provision.reconcile_mount_effect(
                        doc, tmp, "ov", merged, fingerprint,
                        canary=(".c", "abc123")))
                self.assertEqual(len(doc["pending_acquisitions"]),
                                 1)

    def test_attach_loop_outside_root_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            run.mkdir()
            rst = os.stat(run)
            outside = Path(tmp) / "outside.img"
            outside.write_bytes(b"sentinel" + bytes(1 << 20))
            ost = os.stat(outside)
            proc = run_tool(
                "attach-loop", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--image", str(outside),
                "--dev", str(ost.st_dev),
                "--ino", str(ost.st_ino))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("outside run-root", proc.stdout)
            target = Path(tmp) / "target.img"
            target.write_bytes(b"sentinel" + bytes(1 << 20))
            link = run / "link.img"
            link.symlink_to(target)
            lst = os.stat(target)
            proc = run_tool(
                "attach-loop", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--image", str(link),
                "--dev", str(lst.st_dev),
                "--ino", str(lst.st_ino))
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("FAILED", proc.stdout)

    # S15-round3: mount-fs mounts via mount(2) on helper-opened
    # fds (/dev/fd/N source, target, and overlay layers) after
    # verifying every operand's (dev,ino) — anything swapped
    # refuses before the mount call. (Happy paths privileged:
    # live.)
    def _layer_spec(self, name, path):
        st = os.stat(path)
        return f"{name}={path}:{st.st_dev}:{st.st_ino}"

    def test_mount_fs_refuses_foreign_target_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            target = run / "mnt"
            target.mkdir(parents=True)
            tst = os.stat(target)
            rst = os.stat(run)
            proc = run_tool(
                "mount-fs", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--target", str(target),
                "--target-dev", str(tst.st_dev),
                "--target-ino", str(tst.st_ino + 1),
                "--fstype", "ext4",
                "--loop", "/dev/loop9999",
                "--backing-dev", "1", "--backing-ino", "2")
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("identity mismatch", proc.stdout)

    # S15-round4: the ext4 mount opens the loop device exactly
    # once — the backing validation and the mount source
    # address the same held descriptor, so a device-node
    # substitution between two opens cannot redirect the
    # source. Pre-fix this saw two opens (validate, then
    # mount) with the mount sourcing the unvalidated second.
    def test_mount_ext4_validates_and_mounts_one_loop_fd(self):
        from unittest import mock
        import types
        opened = []
        validated = []
        mounted = []
        next_fd = [100]

        def fake_open(path, flags, *args, **kwargs):
            opened.append(path)
            fd = next_fd[0]
            next_fd[0] += 1
            return fd

        def fake_status(fd):
            validated.append(fd)
            return (11, 22)

        def fake_mount(source, target, fstype, flags, data):
            mounted.append((source, target))
            return None

        args = types.SimpleNamespace(
            loop="/dev/loop9", backing_dev=11, backing_ino=22,
            target="/t")
        row = {"target": "/t", "mnt_id": 1, "root": "/",
               "fstype": "ext4", "source": "/dev/loop9",
               "super": "rw"}
        with mock.patch.object(provision.os, "open",
                               side_effect=fake_open), \
                mock.patch.object(provision, "_loop_get_status_on",
                                   side_effect=fake_status), \
                mock.patch.object(provision, "_mount2",
                                   side_effect=fake_mount), \
                mock.patch.object(provision, "_snapshot_mount_rows",
                                   return_value=frozenset()), \
                mock.patch.object(provision, "_post_verify_mount",
                                   return_value=(row, 777)
                                   ) as post:
            got = provision._mount_ext4_now(args, "/run", 55)
        self.assertEqual(got, (row, 777))
        loop_opens = [p for p in opened if p == "/dev/loop9"]
        self.assertEqual(len(loop_opens), 1)
        self.assertEqual(validated, [100])
        self.assertEqual(mounted,
                         [(f"/dev/fd/100", "/dev/fd/55")])
        post.assert_called_once()
        # S81-round5: the SAME fd verifies — post-verify
        # receives the retained description, never re-opens.
        self.assertEqual(
            post.call_args[1]["loop_fd"], 100)
        self.assertEqual(
            post.call_args[1]["backing"], (11, 22))

    def test_mount_fs_refuses_bad_fstype(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            target = run / "mnt"
            target.mkdir(parents=True)
            tst = os.stat(target)
            rst = os.stat(run)
            proc = run_tool(
                "mount-fs", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--target", str(target),
                "--target-dev", str(tst.st_dev),
                "--target-ino", str(tst.st_ino),
                "--fstype", "xfs")
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("unsupported fstype", proc.stdout)

    def test_mount_fs_overlay_refuses_foreign_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            role = run / "ov"
            target = role / "merged"
            for sub in ("lower", "upper", "work", "merged"):
                (role / sub).mkdir(parents=True)
            tst = os.stat(target)
            rst = os.stat(run)
            good = [self._layer_spec(n, role / n)
                    for n in ("lower", "upper", "work")]
            bad_lower = list(good)
            lst = os.stat(role / "lower")
            bad_lower[0] = (f"lower={role / 'lower'}:"
                            f"{lst.st_dev}:{lst.st_ino + 1}")
            argv = ["mount-fs", "--run-root", str(run),
                   "--root-dev", str(rst.st_dev),
                   "--root-ino", str(rst.st_ino),
                   "--target", str(target),
                   "--target-dev", str(tst.st_dev),
                   "--target-ino", str(tst.st_ino),
                   "--fstype", "overlay"]
            for spec in bad_lower:
                argv += ["--layer", spec]
            proc = run_tool(*argv)
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("identity mismatch", proc.stdout)

    def test_mount_fs_layer_outside_roots_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            role = run / "ov"
            target = role / "merged"
            for sub in ("upper", "work", "merged"):
                (role / sub).mkdir(parents=True)
            aux = Path(tmp) / "aux"
            lower = aux / "lower"
            lower.mkdir(parents=True)
            tst = os.stat(target)
            rst = os.stat(run)
            specs = [self._layer_spec("lower", lower),
                     self._layer_spec("upper", role / "upper"),
                     self._layer_spec("work", role / "work")]
            argv = ["mount-fs", "--run-root", str(run),
                   "--root-dev", str(rst.st_dev),
                   "--root-ino", str(rst.st_ino),
                   "--target", str(target),
                   "--target-dev", str(tst.st_dev),
                   "--target-ino", str(tst.st_ino),
                   "--fstype", "overlay"]
            # S81-round5: planted (not argv) for the as-root
            # success branch.
            (role / "upper" / provision.MOUNT_CANARY_NAME).write_bytes(
                b"abc123")
            for spec in specs:
                argv += ["--layer", spec]
            # No aux root declared: the outside lower refuses.
            proc = run_tool(*argv)
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("outside", proc.stdout)
            # Declared aux root: verification passes and the
            # helper reaches mount(2) — unprivileged that is
            # EPERM; as root the mount genuinely succeeds.
            ast = os.stat(aux)
            argv += ["--aux-root", str(aux),
                    "--aux-dev", str(ast.st_dev),
                    "--aux-ino", str(ast.st_ino)]
            proc = run_tool(*argv)
            if os.geteuid() == 0:
                self.assertEqual(
                    proc.returncode, 0,
                    proc.stdout + proc.stderr)
                self.assertIn("mounted", proc.stdout)
                bye = subprocess.run(
                    ["umount", str(target)], capture_output=True,
                    text=True, timeout=60)
                self.assertEqual(bye.returncode, 0, bye.stderr)
            else:
                self.assertEqual(proc.returncode, 1, proc.stdout)
                self.assertIn("Operation not permitted",
                              proc.stdout)

    def test_mount_fs_ext4_refuses_foreign_loop_backing(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            target = run / "mnt"
            target.mkdir(parents=True)
            tst = os.stat(target)
            rst = os.stat(run)
            proc = run_tool(
                "mount-fs", "--run-root", str(run),
                "--root-dev", str(rst.st_dev),
                "--root-ino", str(rst.st_ino),
                "--target", str(target),
                "--target-dev", str(tst.st_dev),
                "--target-ino", str(tst.st_ino),
                "--fstype", "ext4",
                "--loop", "/dev/loop9999",
                "--backing-dev", "1", "--backing-ino", "2")
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("FAILED", proc.stdout)
            self.assertNotIn("Operation not permitted",
                             proc.stdout)


class MountNsTests(unittest.TestCase):
    """S17-round5 keeper mount-namespace confinement (all mocked)."""

    def test_parse_keeper_state_matrix(self):
        good = "1234 99 " + "ab" * 16 + "\n"
        self.assertEqual(
            provision._parse_keeper_state(good.encode()),
            (1234, 99, "ab" * 16))
        for bad in (b"", b"1 2\n", b"0 99 " + b"ab" * 16,
                    b"12 99 " + b"zz" * 16, b"12 99 short",
                    b"\xff\xfe garbage", b"12 0 " + b"ab" * 16):
            self.assertIsNone(
                provision._parse_keeper_state(bad), bad)

    def test_ensure_spawns_and_records(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        canary = "ab" * 16
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            candir = os.path.join(tmp, "canary")
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, candir)), \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        return_value=(1234, 99, canary, 555)
                        ) as spawn, \
                    mock.patch.object(
                        provision, "_publish_keeper_state"
                        ) as publish:
                nspath = provision.ensure_mount_ns()
            # S103-round6: spawn publishes (atomically, inside
            # _spawn_keeper); ensure only routes + caches.
            spawn.assert_called_once_with(
                os.geteuid(), candir, pidfile)
            publish.assert_not_called()
            self.assertEqual(nspath, "/proc/1234/ns/mnt")
            self.assertEqual(provision._MOUNT_NS, nspath)
            self.assertEqual(provision._MOUNT_NS_IDENTITY,
                             (1234, 99, 555, canary))
            # S100-round6: the cache revalidates on every call
            # (cheap starttime anchor — no spawn, no disk,
            # no elevated subprocess).
            with mock.patch.object(
                    provision, "_spawn_keeper",
                    side_effect=AssertionError("respawned")), \
                    mock.patch.object(
                        provision, "_keeper_starttime",
                        return_value=555) as anchor, \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        side_effect=AssertionError(
                            "elevated")):
                self.assertEqual(
                    provision.ensure_mount_ns(), nspath)
            anchor.assert_called_once_with(1234)

    def test_ensure_reuses_live_keeper(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        canary = "cd" * 16
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text(f"4321 77 {canary}\n")
            os.chmod(pidfile, 0o600)
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[77]") as link, \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=True) as check, \
                    mock.patch.object(
                        provision, "_keeper_starttime",
                        return_value=777), \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        side_effect=AssertionError(
                            "respawned")):
                nspath = provision.ensure_mount_ns()
            link.assert_called_once_with(4321)
            check.assert_called_once_with(
                "/proc/4321/ns/mnt", canary)
            self.assertEqual(nspath, "/proc/4321/ns/mnt")
            self.assertEqual(provision._MOUNT_NS_IDENTITY,
                             (4321, 77, 777, canary))
            self.assertEqual(
                Path(pidfile).read_text(), f"4321 77 {canary}\n")

    def test_ensure_respawns_on_dead_keeper(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        canary = "cd" * 16
        fresh = "ef" * 16
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text(f"4321 77 {canary}\n")
            os.chmod(pidfile, 0o600)
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value=None), \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        side_effect=AssertionError(
                            "checked dead")) as check, \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        return_value=(111, 22, fresh, 999)
                        ) as spawn:
                nspath = provision.ensure_mount_ns()
            check.assert_not_called()
            # S103-round6: spawn publishes; ensure caches.
            spawn.assert_called_once_with(
                os.geteuid(), tmp, pidfile)
            self.assertEqual(nspath, "/proc/111/ns/mnt")
            self.assertEqual(provision._MOUNT_NS_IDENTITY,
                             (111, 22, 999, fresh))

    def test_ensure_respawns_on_canary_mismatch(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        canary = "cd" * 16
        fresh = "ef" * 16
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text(f"4321 77 {canary}\n")
            os.chmod(pidfile, 0o600)
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[77]"), \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=False), \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        return_value=(111, 22, fresh, 999)
                        ) as spawn:
                nspath = provision.ensure_mount_ns()
            # S103-round6: spawn publishes; ensure caches.
            spawn.assert_called_once_with(
                os.geteuid(), tmp, pidfile)
            self.assertEqual(nspath, "/proc/111/ns/mnt")
            self.assertEqual(provision._MOUNT_NS_IDENTITY,
                             (111, 22, 999, fresh))

    # S100-round6: a cached keeper whose pid died or was
    # recycled (starttime anchor mismatch) drops the cache
    # and re-verifies from the pidfile — the stale path is
    # never routed into. Here the pidfile still records the
    # same keeper with a FRESH anchor: full link+canary
    # re-verification re-adopts it with the new starttime.
    def test_ensure_drops_recycled_cache(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        canary = "cd" * 16
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text(f"4321 77 {canary}\n")
            os.chmod(pidfile, 0o600)
            provision._MOUNT_NS = "/proc/4321/ns/mnt"
            provision._MOUNT_NS_IDENTITY = (
                4321, 77, 111, canary)
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch.object(
                        provision, "_keeper_starttime",
                        side_effect=[222, 222, 222]) as anchor, \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[77]") as link, \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=True) as check, \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        side_effect=AssertionError(
                            "respawned")):
                nspath = provision.ensure_mount_ns()
            # First anchor read (cache, 111 expected) fails;
            # the pidfile adopt then reads pre and post
            # (S100-round7: equal, so the fresh one records).
            self.assertEqual(anchor.call_args_list,
                             [mock.call(4321), mock.call(4321),
                              mock.call(4321)])
            link.assert_called_once_with(4321)
            check.assert_called_once_with(
                "/proc/4321/ns/mnt", canary)
            self.assertEqual(nspath, "/proc/4321/ns/mnt")
            self.assertEqual(provision._MOUNT_NS_IDENTITY,
                             (4321, 77, 222, canary))

    # S100-round6: the starttime anchor reads the world-readable
    # field and fails closed on gone/unparseable pids.
    def test_keeper_starttime_matrix(self):
        mine = provision._keeper_starttime(os.getpid())
        self.assertIsInstance(mine, int)
        self.assertGreater(mine, 0)
        self.assertIsNone(provision._keeper_starttime(2 ** 30))
        self.assertIsNone(provision._keeper_starttime("bogus"))
        self.assertIsNone(provision._keeper_starttime(None))

    # S103-round6: exclusion lives on the dedicated lockfile;
    # an alien lock refuses before any pidfile read or spawn.
    # (S107-round8: the pidfile record itself is now also
    # authenticated — same-descriptor owner/type — before any
    # namespace entry; link + canary authenticate the keeper.)
    def test_ensure_refuses_alien_lock(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        alien = 1 if os.geteuid() == 0 else 0
        fake = mock.Mock()
        fake.st_uid = alien
        fake.st_mode = stat.S_IFREG | 0o600
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text("1 2 deadbeef\n")
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch("os.fstat", return_value=fake), \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        side_effect=AssertionError(
                            "spawned for alien")):
                with self.assertRaisesRegex(
                        provision.AdmissionError, "lock alien"):
                    provision.ensure_mount_ns()
            self.assertIsNone(provision._MOUNT_NS)

    # S107-round8: a foreign-owned PID record is refused BEFORE
    # any namespace entry — link+canary never run on it, so no
    # privileged nsenter/readlink executes against an
    # attacker-chosen pid/nsid. Both ensure and bind authenticate
    # the record (same-descriptor owner/type) first.
    def test_keeper_foreign_pidfile_refused_before_ns_entry(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        canary = "cd" * 16
        alien = 1 if os.geteuid() == 0 else 0
        real_open = os.open
        real_fstat = os.fstat
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text(f"4321 77 {canary}\n")
            pid_fds = set()

            def spy_open(path, flags, *args):
                fd = real_open(path, flags, *args)
                if isinstance(path, str) and path == pidfile:
                    pid_fds.add(fd)
                return fd

            def fake_fstat(fd):
                if fd in pid_fds:
                    owned = mock.Mock()
                    owned.st_uid = alien
                    owned.st_mode = stat.S_IFREG | 0o600
                    return owned
                return real_fstat(fd)

            def attempt(entry):
                provision._MOUNT_NS = None
                provision._MOUNT_NS_IDENTITY = None
                with mock.patch.object(
                        provision, "_keeper_paths",
                        return_value=(pidfile, tmp)), \
                        mock.patch("os.open",
                                   side_effect=spy_open), \
                        mock.patch("os.fstat",
                                   side_effect=fake_fstat), \
                        mock.patch.object(
                            provision, "_read_ns_link",
                            return_value="mnt:[77]") as link, \
                        mock.patch.object(
                            provision, "_ns_has_canary",
                            return_value=True) as check, \
                        mock.patch.object(
                            provision, "_keeper_starttime",
                            return_value=777), \
                        mock.patch.object(
                            provision, "_spawn_keeper",
                            side_effect=AssertionError(
                                "spawned for alien")):
                    with self.assertRaisesRegex(
                            provision.AdmissionError, "alien"):
                        entry()
                link.assert_not_called()
                check.assert_not_called()

            attempt(provision.bind_mount_ns)
            pid_fds.clear()
            attempt(provision.ensure_mount_ns)
            self.assertIsNone(provision._MOUNT_NS)

    # S121-round8: a preplanted FIFO at the pidfile path never
    # hangs setup — the record opens nonblocking and the
    # same-descriptor type check refuses it. (Both entries:
    # ensure holds the shared lock across the read, so a hang
    # there would wedge every setup.)
    def test_keeper_fifo_pidfile_refused_without_hang(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            os.mkfifo(pidfile, 0o644)
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        side_effect=AssertionError(
                            "spawned for fifo")):
                provision._MOUNT_NS = None
                provision._MOUNT_NS_IDENTITY = None
                with self.assertRaisesRegex(
                        provision.AdmissionError,
                        "regular file"):
                    provision.bind_mount_ns()
                provision._MOUNT_NS = None
                provision._MOUNT_NS_IDENTITY = None
                with self.assertRaisesRegex(
                        provision.AdmissionError,
                        "regular file"):
                    provision.ensure_mount_ns()
            self.assertIsNone(provision._MOUNT_NS)

    def test_spawn_keeper_reports_identity(self):
        from unittest import mock
        canary = "ef" * 16
        child = mock.Mock()
        child.stdout.readline.return_value = (
            f"READY 7777 {canary}\n")
        fake_sel = mock.Mock()
        fake_sel.select.return_value = [True]
        with tempfile.TemporaryDirectory() as tmp:
            candir = os.path.join(tmp, "canary")
            pidfile = os.path.join(tmp, "ns.pid")
            before = len(provision._KEEPERS)
            with mock.patch.object(
                    provision.subprocess, "Popen",
                    return_value=child) as popen, \
                    mock.patch.object(
                        provision.selectors,
                        "DefaultSelector",
                        return_value=fake_sel), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[55]") as link, \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=True) as check, \
                    mock.patch.object(
                        provision, "_keeper_starttime",
                        return_value=31337), \
                    mock.patch.object(
                        provision, "kill_tree") as retired:
                result = provision._spawn_keeper(
                    os.geteuid(), candir, pidfile)
            self.assertEqual(result, (7777, 55, canary, 31337))
            link.assert_called_once_with(7777)
            check.assert_called_once_with(
                "/proc/7777/ns/mnt", canary)
            self.assertIn(child, provision._KEEPERS)
            self.assertEqual(len(provision._KEEPERS), before + 1)
            retired.assert_not_called()
            # S103-round6: success publishes atomically.
            self.assertEqual(
                Path(pidfile).read_text(),
                f"7777 55 {canary}\n")
            self.assertEqual(
                stat.S_IMODE(os.stat(pidfile).st_mode), 0o600)
            argv = popen.call_args[0][0]
            self.assertEqual(argv[:5],
                             ["sudo", "-n", "unshare", "-m",
                              "bash"])
            # The canary is generated inside, never on cmdline.
            self.assertNotIn(canary, " ".join(argv))
            st = os.stat(candir)
            self.assertTrue(stat.S_ISDIR(st.st_mode))
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)

    def test_spawn_keeper_garbage_and_timeout_refuse(self):
        from unittest import mock

        def attempt(line, selected):
            child = mock.Mock()
            child.stdout.readline.return_value = line
            fake_sel = mock.Mock()
            fake_sel.select.return_value = selected
            with tempfile.TemporaryDirectory() as tmp:
                with mock.patch.object(
                        provision.subprocess, "Popen",
                        return_value=child), \
                        mock.patch.object(
                            provision.selectors,
                            "DefaultSelector",
                            return_value=fake_sel), \
                        mock.patch.object(
                            provision, "kill_tree",
                            return_value=True) as retired:
                    with self.assertRaises(
                            provision.AdmissionError):
                        provision._spawn_keeper(
                            os.geteuid(),
                            os.path.join(tmp, "canary"),
                            os.path.join(tmp, "ns.pid"))
            # S103-round6: failure retires the whole tree,
            # not just the direct child.
            retired.assert_called_once_with(
                "keeper-spawn", child.pid, 10)
            child.wait.assert_called_once_with(timeout=10)

        attempt("GARBAGE\n", [True])
        attempt("", [])

    def test_spawn_keeper_canary_gate_refuses(self):
        # A fresh pid with no recorded nsid to compare against
        # must still prove its namespace is ours: a recycled
        # pid's namespace lacks canary-<secret>, so the spawn
        # is refused and the child reaped, never recorded.
        from unittest import mock
        canary = "aa" * 16
        child = mock.Mock()
        child.stdout.readline.return_value = (
            f"READY 8888 {canary}\n")
        fake_sel = mock.Mock()
        fake_sel.select.return_value = [True]
        with tempfile.TemporaryDirectory() as tmp:
            before = len(provision._KEEPERS)
            with mock.patch.object(
                    provision.subprocess, "Popen",
                    return_value=child), \
                    mock.patch.object(
                        provision.selectors,
                        "DefaultSelector",
                        return_value=fake_sel), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[66]"), \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=False), \
                    mock.patch.object(
                        provision, "kill_tree",
                        return_value=True) as retired:
                with self.assertRaisesRegex(
                        provision.AdmissionError,
                        "lacks our canary"):
                    provision._spawn_keeper(
                        os.geteuid(),
                        os.path.join(tmp, "canary"),
                        os.path.join(tmp, "ns.pid"))
            self.assertEqual(len(provision._KEEPERS), before)
        retired.assert_called_once_with(
            "keeper-spawn", child.pid, 10)
        child.wait.assert_called_once_with(timeout=10)

    # S102-round6: bind adopts the recorded keeper (fully
    # verified) and never spawns — no record, dead record,
    # or identity mismatch refuses instead of substituting.
    def test_bind_mount_ns_matrix(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        canary = "cd" * 16

        def attempt(raw, link="mnt:[77]", canary_ok=True,
                    start=777, expected=None):
            provision._MOUNT_NS = None
            provision._MOUNT_NS_IDENTITY = None
            with tempfile.TemporaryDirectory() as tmp:
                pidfile = os.path.join(tmp, "ns.pid")
                if raw is not None:
                    Path(pidfile).write_text(raw)
                with mock.patch.object(
                        provision, "_keeper_paths",
                        return_value=(pidfile, tmp)), \
                        mock.patch.object(
                            provision, "_read_ns_link",
                            return_value=link), \
                        mock.patch.object(
                            provision, "_ns_has_canary",
                            return_value=canary_ok), \
                        mock.patch.object(
                            provision, "_keeper_starttime",
                            return_value=start), \
                        mock.patch.object(
                            provision, "_spawn_keeper",
                            side_effect=AssertionError(
                                "spawned on bind")):
                    return provision.bind_mount_ns(
                        expected=expected)

        mode = {"pid": 4321, "nsid": 77, "starttime": 777}
        got = attempt(f"4321 77 {canary}\n", expected=mode)
        self.assertEqual(got, "/proc/4321/ns/mnt")
        self.assertEqual(provision._MOUNT_NS_IDENTITY,
                         (4321, 77, 777, canary))
        # Legacy boolean: adopt-current without identity.
        got = attempt(f"4321 77 {canary}\n", expected=True)
        self.assertEqual(got, "/proc/4321/ns/mnt")
        # No record: refuse, never spawn.
        with self.assertRaisesRegex(
                provision.AdmissionError, "no keeper recorded"):
            attempt(None)
        # Dead record: refuse, never substitute fresh.
        with self.assertRaisesRegex(
                provision.AdmissionError,
                "dead or unverifiable"):
            attempt(f"4321 77 {canary}\n", link=None)
        # Wrong namespace proof: refuse.
        with self.assertRaisesRegex(
                provision.AdmissionError,
                "dead or unverifiable"):
            attempt(f"4321 77 {canary}\n", canary_ok=False)
        # Identity mismatch: refuse substitution.
        with self.assertRaisesRegex(
                provision.AdmissionError,
                "refusing substitution"):
            attempt(f"4321 77 {canary}\n", expected={
                "pid": 4321, "nsid": 78, "starttime": 777})

    # S122-round8: only PROVEN absence reads as "no keeper
    # recorded" (typed KeeperAbsent) — corrupt contents, a
    # symlinked record, and unreadable records refuse as
    # AdmissionError, never as host-continuation permission.
    def test_bind_keeper_state_classification(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        canary = "cd" * 16
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")

            def attempt(raw=None, link=None):
                provision._MOUNT_NS = None
                provision._MOUNT_NS_IDENTITY = None
                if raw is not None:
                    Path(pidfile).write_text(raw)
                with mock.patch.object(
                        provision, "_keeper_paths",
                        return_value=(pidfile, tmp)), \
                        mock.patch.object(
                            provision, "_spawn_keeper",
                            side_effect=AssertionError(
                                "spawned on bind")):
                    return provision.bind_mount_ns()

            # Proven absence: typed, still matching the
            # historical message.
            with self.assertRaises(
                    provision.KeeperAbsent) as ctx:
                attempt(None)
            self.assertIn("no keeper recorded",
                          str(ctx.exception))
            # Corrupt contents: unreadable, never absent.
            with self.assertRaises(
                    provision.AdmissionError) as ctx:
                attempt("garbage not-a-record\n")
            self.assertNotIsInstance(
                ctx.exception, provision.KeeperAbsent)
            self.assertNotIn("no keeper recorded",
                             str(ctx.exception))
            # Symlinked record: unreadable, never absent.
            os.unlink(pidfile)
            os.symlink(os.path.join(tmp, "victim"), pidfile)
            with self.assertRaises(
                    provision.AdmissionError) as ctx:
                attempt()
            self.assertNotIsInstance(
                ctx.exception, provision.KeeperAbsent)
            self.assertNotIn("no keeper recorded",
                             str(ctx.exception))
            # Denied record: unreadable, never absent.
            os.unlink(pidfile)
            Path(pidfile).write_text(
                f"4321 77 {canary}\n")
            real_open = os.open

            def denied_open(path, flags, *args):
                if isinstance(path, str) and path == pidfile:
                    raise PermissionError(
                        errno.EACCES, "denied")
                return real_open(path, flags, *args)

            provision._MOUNT_NS = None
            provision._MOUNT_NS_IDENTITY = None
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch("os.open",
                               side_effect=denied_open):
                with self.assertRaises(
                        provision.AdmissionError) as ctx:
                    provision.bind_mount_ns()
            self.assertNotIsInstance(
                ctx.exception, provision.KeeperAbsent)
            self.assertNotIn("no keeper recorded",
                             str(ctx.exception))

    # S122-round8: ensure refuses a corrupt record instead of
    # respawning over it (a respawn would orphan the live
    # keeper and break every fixture bound to it).
    def test_ensure_refuses_corrupt_pidfile(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text("torn record\n")
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        side_effect=AssertionError(
                            "spawned for corrupt")):
                with self.assertRaisesRegex(
                        provision.AdmissionError, "corrupt"):
                    provision.ensure_mount_ns()
            self.assertIsNone(provision._MOUNT_NS)

    # S100-round7: a keeper that dies and recycles between the
    # canary check and the anchor read must not bind the
    # stranger's starttime — the pre/post anchor reads differ
    # and the spawn is refused (tree retired, never recorded).
    # Neuter check: with a single anchor read the spawn binds
    # fine and this test fails (no refusal to catch).
    def test_spawn_keeper_recycled_during_verify_refuses(self):
        from unittest import mock
        canary = "aa" * 16
        child = mock.Mock()
        child.stdout.readline.return_value = (
            f"READY 8888 {canary}\n")
        fake_sel = mock.Mock()
        fake_sel.select.return_value = [True]
        with tempfile.TemporaryDirectory() as tmp:
            before = len(provision._KEEPERS)
            with mock.patch.object(
                    provision.subprocess, "Popen",
                    return_value=child), \
                    mock.patch.object(
                        provision.selectors,
                        "DefaultSelector",
                        return_value=fake_sel), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[66]"), \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=True), \
                    mock.patch.object(
                        provision, "_keeper_starttime",
                        side_effect=[111, 222]), \
                    mock.patch.object(
                        provision, "kill_tree",
                        return_value=True) as retired:
                with self.assertRaisesRegex(
                        provision.AdmissionError,
                        "recycled during verification"):
                    provision._spawn_keeper(
                        os.geteuid(),
                        os.path.join(tmp, "canary"),
                        os.path.join(tmp, "ns.pid"))
            self.assertEqual(len(provision._KEEPERS), before)
        retired.assert_called_once_with(
            "keeper-spawn", child.pid, 10)
        child.wait.assert_called_once_with(timeout=10)

    # S100-round7: bind reads the anchor twice around the
    # link+canary verification — a recycle mid-verify refuses
    # instead of binding the stranger's starttime.
    def test_bind_recycled_during_verify_refuses(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        canary = "cd" * 16
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text(f"4321 77 {canary}\n")
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[77]"), \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=True), \
                    mock.patch.object(
                        provision, "_keeper_starttime",
                        side_effect=[111, 222]), \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        side_effect=AssertionError(
                            "spawned on bind")):
                with self.assertRaisesRegex(
                        provision.AdmissionError,
                        "recycled during bind"):
                    provision.bind_mount_ns()
            self.assertIsNone(provision._MOUNT_NS)
            self.assertIsNone(provision._MOUNT_NS_IDENTITY)

    # S100-round7: ensure treats a mid-verify recycle like a
    # dead keeper — the pidfile record is dropped and a fresh
    # keeper is spawned (never adopted with a stranger's
    # anchor).
    def test_ensure_respawns_on_anchor_recycle(self):
        from unittest import mock
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        canary = "cd" * 16
        fresh = "ef" * 16
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            Path(pidfile).write_text(f"4321 77 {canary}\n")
            os.chmod(pidfile, 0o600)
            with mock.patch.object(
                    provision, "_keeper_paths",
                    return_value=(pidfile, tmp)), \
                    mock.patch.object(
                        provision, "_keeper_starttime",
                        side_effect=[111, 222]), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[77]"), \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=True), \
                    mock.patch.object(
                        provision, "_spawn_keeper",
                        return_value=(111, 22, fresh, 999)
                        ) as spawn:
                nspath = provision.ensure_mount_ns()
            spawn.assert_called_once_with(
                os.geteuid(), tmp, pidfile)
            self.assertEqual(nspath, "/proc/111/ns/mnt")
            self.assertEqual(provision._MOUNT_NS_IDENTITY,
                             (111, 22, 999, fresh))

    # S101-round6: unmanifested entry binds opportunistically
    # (residue scans see the ns table), runs unensured when
    # no keeper was ever recorded, and refuses on a
    # recorded-but-unverifiable keeper or unresolved
    # evidence (never a clean-host misread).
    # S99-round6: inside the bound namespace, sudo skips
    # nsenter (inheritance, no redirect possible — the
    # routing gate is skipped too), and membership is
    # identity-compared per call.
    def test_inside_fast_paths(self):
        from unittest import mock
        ident = (9, 77, 555, "c" * 32)
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  ident), \
                mock.patch.object(provision, "_ROOT_GUARD",
                                  None), \
                mock.patch("os.readlink",
                           return_value="mnt:[77]"), \
                mock.patch.object(
                    provision, "_keeper_routing_verified",
                    side_effect=AssertionError("gated")), \
                mock.patch.object(provision.subprocess, "run",
                                  return_value=mock.Mock(
                                      returncode=0, stdout="",
                                      stderr="")) as run:
            self.assertTrue(provision._inside_keeper_ns())
            provision.run_sudo(["true"])
            self.assertNotIn("nsenter", run.call_args[0][0])
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  ident), \
                mock.patch("os.readlink",
                           return_value="mnt:[78]"):
            self.assertFalse(provision._inside_keeper_ns())
        for ns, identity in ((None, None), ("direct", None),
                             ("/proc/9/ns/mnt", None)):
            with mock.patch.object(provision, "_MOUNT_NS",
                                   ns), \
                    mock.patch.object(
                        provision, "_MOUNT_NS_IDENTITY",
                        identity):
                self.assertFalse(provision._inside_keeper_ns())
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  ident), \
                mock.patch("os.readlink",
                           side_effect=OSError("gone")):
            self.assertFalse(provision._inside_keeper_ns())

    # S99-round6: inside processes read the table and canaries
    # directly (their own view) — no dump, no re-exec.
    def test_inside_reads_directly(self):
        from unittest import mock
        ident = (9, 77, 555, "c" * 32)
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  ident), \
                mock.patch("os.readlink",
                           return_value="mnt:[77]"), \
                mock.patch.object(provision.subprocess, "run",
                                  side_effect=AssertionError(
                                      "dumped")):
            rows = provision.read_mount_table()
            self.assertIsInstance(rows, list)
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, provision.MOUNT_CANARY_NAME).write_bytes(
                b"tok")
            mid = real_mnt_id(tmp)
            with mock.patch.object(
                    provision, "_MOUNT_NS",
                    "/proc/9/ns/mnt"), \
                    mock.patch.object(
                        provision, "_MOUNT_NS_IDENTITY",
                        ident), \
                    mock.patch("os.readlink",
                               return_value="mnt:[77]"), \
                    mock.patch.object(
                        provision, "run_sudo",
                        side_effect=AssertionError(
                            "re-execed")):
                self.assertTrue(provision._canary_matches(
                    tmp, provision.MOUNT_CANARY_NAME, "tok",
                    expect_mnt_id=mid))

    # S99-round6: the re-exec argv joins the bound ns as root
    # then drops to the invoking user for the same command;
    # only TMPDIR/HOME cross the boundary.
    def test_reexec_inside_ns_argv(self):
        from unittest import mock
        pw = mock.Mock()
        pw.pw_name = "ctrl"
        pw.pw_dir = "/home/ctrl"
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  (9, 77, 555, "c" * 32)), \
                mock.patch.object(provision.os, "getuid",
                                  return_value=1000), \
                mock.patch.object(provision.os, "geteuid",
                                  return_value=1000), \
                mock.patch.object(provision.pwd, "getpwuid",
                                  return_value=pw) as lookup, \
                mock.patch.object(provision.sys, "argv",
                                  ["provision_fs.py", "create",
                                   "--run-root", "/tmp/r"]), \
                mock.patch.object(provision.sys, "executable",
                                  "/usr/bin/python3"), \
                mock.patch.object(provision.os, "execvp") as exe, \
                mock.patch.dict(provision.os.environ,
                                {"TMPDIR": "/tmp/x"}, clear=True):
            provision._reexec_inside_ns()
        lookup.assert_called_once_with(1000)
        self.assertEqual(
            exe.call_args[0][0], "sudo")
        # NEW-1-round8: the join proves the pinned ns (same
        # sudo invocation, nsid from identity) before dropping
        # to the controller.
        self.assertEqual(
            exe.call_args[0][1],
            ["sudo", "-n", "env", "TMPDIR=/tmp/x",
             "HOME=/home/ctrl", "sh", "-c",
             provision._ns_pin_proof_script(),
             "/proc/9/ns/mnt", "77",
             "runuser", "-u",
             "ctrl", "--", "/usr/bin/python3",
             os.path.abspath("provision_fs.py"), "create",
             "--run-root", "/tmp/r"])
        # Unresolvable controller: loud, never outside.
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision.pwd, "getpwuid",
                                  side_effect=KeyError(1000)):
            with self.assertRaisesRegex(
                    provision.AdmissionError,
                    "cannot resolve controller user"):
                provision._reexec_inside_ns()
        # NEW-1-round8: unbound identity refuses the re-exec
        # join loudly (never joins).
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision,
                                  "_MOUNT_NS_IDENTITY", None), \
                mock.patch.object(provision.os, "execvp",
                                  side_effect=AssertionError(
                                      "joined")):
            with self.assertRaisesRegex(
                    provision.AdmissionError,
                    "unbound"):
                provision._reexec_inside_ns()

    # S99-round6: entry is a no-op inside; outside it re-execs
    # (failures fail the command, never run it outside).
    def test_enter_keeper_ns_matrix(self):
        from unittest import mock
        with mock.patch.object(
                provision, "_inside_keeper_ns",
                return_value=True), \
                mock.patch.object(
                    provision, "_reexec_inside_ns",
                    side_effect=AssertionError("re-execed")):
            self.assertIsNone(
                provision._enter_keeper_ns("create"))
        with mock.patch.object(
                provision, "_inside_keeper_ns",
                return_value=False), \
                mock.patch.object(
                    provision, "_reexec_inside_ns",
                    return_value=None) as reexec:
            self.assertIsNone(
                provision._enter_keeper_ns("cleanup"))
            reexec.assert_called_once_with()
        for boom in (OSError("no sudo"),
                     provision.AdmissionError("no user")):
            with mock.patch.object(
                    provision, "_inside_keeper_ns",
                    return_value=False), \
                    mock.patch.object(
                        provision, "_reexec_inside_ns",
                        side_effect=boom):
                self.assertEqual(
                    provision._enter_keeper_ns("inspect"), 1)

    def test_main_unmanifested_routing(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            man = os.path.join(tmp, "m.json")
            run = os.path.join(tmp, "run")
            os.makedirs(run)
            # Recorded keeper: bind + enter + command.
            with mock.patch.object(
                    provision, "load_manifest",
                    side_effect=provision.
                    AdmissionError("missing")), \
                    mock.patch.object(
                        provision, "bind_mount_ns",
                        return_value="/proc/9/ns/mnt") as bind, \
                    mock.patch.object(
                        provision, "_enter_keeper_ns",
                        return_value=None) as enter, \
                    mock.patch.object(
                        provision, "cleanup_command",
                        return_value=13) as cleanup:
                rc = provision.main(
                    ["cleanup", "--manifest", man,
                     "--run-root", run])
            self.assertEqual(rc, 13)
            bind.assert_called_once_with()
            enter.assert_called_once_with("cleanup")
            cleanup.assert_called_once()
            # Never recorded: unensured command, no refuse.
            # S122-round8: the gate is the TYPED absence
            # outcome, not the message text.
            with mock.patch.object(
                    provision, "load_manifest",
                    side_effect=provision.
                    AdmissionError("missing")), \
                    mock.patch.object(
                        provision, "bind_mount_ns",
                        side_effect=provision.KeeperAbsent(
                            "no keeper recorded (gone)")), \
                    mock.patch.object(
                        provision, "_keeper_paths",
                        return_value=(os.path.join(tmp, "np"),
                                     tmp)), \
                    mock.patch.object(
                        provision, "cleanup_command",
                        return_value=13) as cleanup:
                rc = provision.main(
                    ["cleanup", "--manifest", man,
                     "--run-root", run])
            self.assertEqual(rc, 13)
            cleanup.assert_called_once()
            # Recorded-but-dead: refuse upfront.
            with mock.patch.object(
                    provision, "load_manifest",
                    side_effect=provision.
                    AdmissionError("missing")), \
                    mock.patch.object(
                        provision, "bind_mount_ns",
                        side_effect=provision.AdmissionError(
                            "recorded keeper dead")), \
                    mock.patch.object(
                        provision, "cleanup_command",
                        side_effect=AssertionError(
                            "scanned without ns")):
                rc = provision.main(
                    ["cleanup", "--manifest", man,
                     "--run-root", run])
            self.assertEqual(rc, 1)
            # S122-round8: corrupt keeper state refuses
            # upfront — never host-side continuation.
            with mock.patch.object(
                    provision, "load_manifest",
                    side_effect=provision.
                    AdmissionError("missing")), \
                    mock.patch.object(
                        provision, "bind_mount_ns",
                        side_effect=provision.AdmissionError(
                            "mount-ns pidfile corrupt; "
                            "refusing")), \
                    mock.patch.object(
                        provision, "cleanup_command",
                        side_effect=AssertionError(
                            "scanned past corrupt state")):
                rc = provision.main(
                    ["cleanup", "--manifest", man,
                     "--run-root", run])
            self.assertEqual(rc, 1)
            # S101-round6 G1-I4: leftover unresolved keeper
            # evidence refuses even when no keeper was ever
            # recorded — residue in an unreachable namespace
            # must never read as a clean host.
            with mock.patch.object(
                    provision, "load_manifest",
                    side_effect=provision.
                    AdmissionError("missing")), \
                    mock.patch.object(
                        provision, "bind_mount_ns",
                        side_effect=provision.KeeperAbsent(
                            "no keeper recorded (gone)")), \
                    mock.patch.object(
                        provision, "_keeper_paths",
                        return_value=(os.path.join(tmp, "np"),
                                     tmp)), \
                    mock.patch.object(
                        provision, "cleanup_command",
                        side_effect=AssertionError(
                            "scanned past unresolved")):
                Path(os.path.join(tmp, "np.unresolved")).write_text(
                    "9 77 deadbeef unresolved-test\n")
                rc = provision.main(
                    ["cleanup", "--manifest", man,
                     "--run-root", run])
            self.assertEqual(rc, 1)

    # S103-round6: atomic keeper publication — exact bytes,
    # 0600, tmp cleaned, symlink-safe replace; short writes
    # and unwritable dirs fail with no pidfile left behind.
    def test_publish_keeper_state_matrix(self):
        from unittest import mock
        canary = "ab" * 16
        with tempfile.TemporaryDirectory() as tmp:
            candir = os.path.join(tmp, "canary")
            os.mkdir(candir, 0o700)
            pidfile = os.path.join(tmp, "ns.pid")
            provision._publish_keeper_state(
                pidfile, candir, 1234, 99, canary)
            self.assertEqual(
                Path(pidfile).read_text(),
                f"1234 99 {canary}\n")
            self.assertEqual(
                stat.S_IMODE(os.stat(pidfile).st_mode), 0o600)
            self.assertEqual(os.listdir(candir), [])
            # Replaces a stale record with the fresh one.
            provision._publish_keeper_state(
                pidfile, candir, 111, 22, "ef" * 16)
            self.assertEqual(
                Path(pidfile).read_text(),
                f"111 22 {'ef' * 16}\n")
            # Replaces an attacker symlink; the victim keeps
            # its bytes (rename swaps the link, never follows).
            victim = os.path.join(tmp, "victim.txt")
            Path(victim).write_bytes(b"victim-bytes")
            os.unlink(pidfile)
            os.symlink(victim, pidfile)
            provision._publish_keeper_state(
                pidfile, candir, 1234, 99, canary)
            self.assertFalse(os.path.islink(pidfile))
            self.assertEqual(
                Path(victim).read_bytes(), b"victim-bytes")
            self.assertEqual(
                Path(pidfile).read_text(),
                f"1234 99 {canary}\n")
            # A short write fails with no pidfile and no tmp.
            os.unlink(pidfile)
            with mock.patch("os.write", return_value=0):
                with self.assertRaisesRegex(
                        provision.AdmissionError, "short write"):
                    provision._publish_keeper_state(
                        pidfile, candir, 1234, 99, canary)
            self.assertFalse(os.path.exists(pidfile))
            self.assertEqual(os.listdir(candir), [])
            # An unwritable candir fails closed.
            with self.assertRaisesRegex(
                    provision.AdmissionError, "unwritable"):
                provision._publish_keeper_state(
                    pidfile, os.path.join(tmp, "missing"),
                    1234, 99, canary)
            self.assertFalse(os.path.exists(pidfile))
            # A stale same-pid tmp is cleaned and retried.
            stale = os.path.join(
                candir, f"keeper.{os.getpid()}.tmp")
            Path(stale).write_bytes(b"stale")
            provision._publish_keeper_state(
                pidfile, candir, 1234, 99, canary)
            self.assertEqual(
                Path(pidfile).read_text(),
                f"1234 99 {canary}\n")
            # An alien tmp refuses instead of unlinking it.
            Path(stale).write_bytes(b"stale")
            alien = mock.Mock()
            alien.st_uid = 0 if os.geteuid() != 0 else 1
            with mock.patch("os.lstat", return_value=alien):
                with self.assertRaisesRegex(
                        provision.AdmissionError, "alien"):
                    provision._publish_keeper_state(
                        pidfile, candir, 1234, 99, canary)
            # G1-I5: the refusal unlinked nothing — the alien
            # tmp and the published pidfile are untouched.
            self.assertEqual(Path(stale).read_bytes(), b"stale")
            self.assertEqual(
                Path(pidfile).read_text(),
                f"1234 99 {canary}\n")

    # S103-round6: failure-after-READY rolls the verified
    # keeper back — the whole tree is retired (never an
    # orphaned live keeper with no record), and a tree that
    # cannot be proven retired leaves durable unresolved
    # evidence naming pid/nsid/canary for manual recovery.
    def test_spawn_keeper_publication_failure_rolls_back(self):
        from unittest import mock
        canary = "ef" * 16

        def attempt(tree_gone):
            child = mock.Mock()
            child.stdout.readline.return_value = (
                f"READY 7777 {canary}\n")
            fake_sel = mock.Mock()
            fake_sel.select.return_value = [True]
            with tempfile.TemporaryDirectory() as tmp:
                candir = os.path.join(tmp, "canary")
                pidfile = os.path.join(tmp, "ns.pid")
                before = len(provision._KEEPERS)
                with mock.patch.object(
                        provision.subprocess, "Popen",
                        return_value=child), \
                        mock.patch.object(
                            provision.selectors,
                            "DefaultSelector",
                            return_value=fake_sel), \
                        mock.patch.object(
                            provision, "_read_ns_link",
                            return_value="mnt:[55]"), \
                        mock.patch.object(
                            provision, "_ns_has_canary",
                            return_value=True), \
                        mock.patch.object(
                            provision, "_keeper_starttime",
                            return_value=31337), \
                        mock.patch.object(
                            provision, "_publish_keeper_state",
                            side_effect=provision.
                            AdmissionError("disk full")), \
                        mock.patch.object(
                            provision, "kill_tree",
                            return_value=tree_gone
                            ) as retired:
                    with self.assertRaisesRegex(
                            provision.AdmissionError,
                            "publication failed") as ctx:
                        provision._spawn_keeper(
                            os.geteuid(), candir, pidfile)
                retired.assert_called_once_with(
                    "keeper-spawn", child.pid, 10)
                self.assertEqual(len(provision._KEEPERS),
                                 before)
                self.assertFalse(os.path.exists(pidfile))
                if tree_gone:
                    # G1-I6: proven retirement leaves no
                    # unresolved residue — checked while the
                    # tmpdir is still alive (the old code
                    # returned the path but both call sites
                    # discarded it after teardown).
                    self.assertFalse(
                        os.path.exists(f"{pidfile}.unresolved"))
                return (str(ctx.exception),
                        os.path.join(tmp, "ns.pid.unresolved"))

        # G1-I6: these calls sat at attempt-body indent (dead
        # code after its return — nothing ever ran them).
        # Dedented to method level so the proven/unproven
        # paths execute and the residue checks bite.
        # Proven retired: loud failure, no residue.
        message, _ = attempt(True)
        self.assertNotIn("not proven gone", message)
        # Unproven: durable unresolved evidence.
        message, _ = attempt(False)
        self.assertIn("not proven gone", message)

        # The evidence path is exercised for real: a False
        # rollback leaves pid/nsid/canary on disk.
        child = mock.Mock()
        child.stdout.readline.return_value = (
            f"READY 7777 {canary}\n")
        fake_sel = mock.Mock()
        fake_sel.select.return_value = [True]
        with tempfile.TemporaryDirectory() as tmp:
            candir = os.path.join(tmp, "canary")
            pidfile = os.path.join(tmp, "ns.pid")
            with mock.patch.object(
                    provision.subprocess, "Popen",
                    return_value=child), \
                    mock.patch.object(
                        provision.selectors,
                        "DefaultSelector",
                        return_value=fake_sel), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[55]"), \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=True), \
                    mock.patch.object(
                        provision, "_keeper_starttime",
                        return_value=31337), \
                    mock.patch.object(
                        provision, "_publish_keeper_state",
                        side_effect=provision.
                        AdmissionError("disk full")), \
                    mock.patch.object(
                        provision, "kill_tree",
                        return_value=False):
                with self.assertRaises(
                        provision.AdmissionError):
                    provision._spawn_keeper(
                        os.geteuid(), candir, pidfile)
            seen = Path(f"{pidfile}.unresolved").read_text()
            self.assertIn("7777", seen)
            self.assertIn("55", seen)
            self.assertIn(canary, seen)

    # S103-round6 G1-I7: an unproven rollback names the keeper
    # itself (pid/nsid for manual retirement — the sudo pid
    # alone misdirects), and a failed evidence write is loud
    # in the alarm (never a silent double fault).
    def test_spawn_keeper_rollback_failure_names_keeper(self):
        from unittest import mock
        canary = "ef" * 16

        def attempt(preserved):
            child = mock.Mock()
            child.stdout.readline.return_value = (
                f"READY 7777 {canary}\n")
            fake_sel = mock.Mock()
            fake_sel.select.return_value = [True]
            with tempfile.TemporaryDirectory() as tmp:
                candir = os.path.join(tmp, "canary")
                pidfile = os.path.join(tmp, "ns.pid")
                with mock.patch.object(
                        provision.subprocess, "Popen",
                        return_value=child), \
                        mock.patch.object(
                            provision.selectors,
                            "DefaultSelector",
                            return_value=fake_sel), \
                        mock.patch.object(
                            provision, "_read_ns_link",
                            return_value="mnt:[55]"), \
                        mock.patch.object(
                            provision, "_ns_has_canary",
                            return_value=True), \
                        mock.patch.object(
                            provision, "_keeper_starttime",
                            return_value=31337), \
                        mock.patch.object(
                            provision, "_publish_keeper_state",
                            side_effect=provision.
                            AdmissionError("disk full")), \
                        mock.patch.object(
                            provision, "kill_tree",
                            return_value=False), \
                        mock.patch.object(
                            provision, "_preserve_keeper_evidence",
                            return_value=preserved) as keep:
                    with self.assertRaisesRegex(
                            provision.AdmissionError,
                            "publication failed") as ctx:
                        provision._spawn_keeper(
                            os.geteuid(), candir, pidfile)
                keep.assert_called_once_with(
                    pidfile, 7777, 55, canary,
                    mock.ANY)
                return str(ctx.exception)

        message = attempt(True)
        self.assertIn("not proven gone", message)
        self.assertIn("keeper pid=7777", message)
        self.assertIn("nsid=55", message)
        self.assertNotIn("NOT preserved", message)
        # A failed evidence write is loud, not silent.
        message = attempt(False)
        self.assertIn("keeper pid=7777", message)
        self.assertIn("NOT preserved", message)

    # S120-round8: pre-publication spawn failures keep every
    # scrap of keeper identity — a canary failure with an
    # unproven rollback names the keeper and preserves
    # evidence (not just the sudo wrapper pid).
    def test_spawn_keeper_canary_failure_keeps_identity(self):
        from unittest import mock
        canary = "aa" * 16
        child = mock.Mock()
        child.stdout.readline.return_value = (
            f"READY 8888 {canary}\n")
        fake_sel = mock.Mock()
        fake_sel.select.return_value = [True]
        with tempfile.TemporaryDirectory() as tmp:
            candir = os.path.join(tmp, "canary")
            pidfile = os.path.join(tmp, "ns.pid")
            with mock.patch.object(
                    provision.subprocess, "Popen",
                    return_value=child), \
                    mock.patch.object(
                        provision.selectors,
                        "DefaultSelector",
                        return_value=fake_sel), \
                    mock.patch.object(
                        provision, "_read_ns_link",
                        return_value="mnt:[66]"), \
                    mock.patch.object(
                        provision, "_ns_has_canary",
                        return_value=False), \
                    mock.patch.object(
                        provision, "kill_tree",
                        return_value=False) as retired:
                with self.assertRaisesRegex(
                        provision.AdmissionError,
                        "lacks our canary") as ctx:
                    provision._spawn_keeper(
                        os.geteuid(), candir, pidfile)
            retired.assert_called_once_with(
                "keeper-spawn", child.pid, 10)
            message = str(ctx.exception)
            self.assertIn("keeper pid=8888", message)
            self.assertIn("nsid=66", message)
            seen = Path(f"{pidfile}.unresolved").read_text()
            self.assertIn("8888", seen)
            self.assertIn("66", seen)
            self.assertIn(canary, seen)

    # S120-round8: selector setup and stdout-reading failures
    # roll back inside the same custody boundary — the tree
    # is retired and the failure reports as AdmissionError,
    # never an escaping raw exception with a live keeper.
    def test_spawn_keeper_spawn_io_rolls_back(self):
        from unittest import mock

        def attempt(select=None, line=None):
            child = mock.Mock()
            if line is not None:
                child.stdout.readline.return_value = line
            else:
                child.stdout.readline.side_effect = OSError(
                    "stdout lost")
            fake_sel = mock.Mock()
            if select is None:
                fake_sel.select.side_effect = OSError(
                    "selector lost")
            else:
                fake_sel.select.return_value = select
            with tempfile.TemporaryDirectory() as tmp:
                with mock.patch.object(
                        provision.subprocess, "Popen",
                        return_value=child), \
                        mock.patch.object(
                            provision.selectors,
                            "DefaultSelector",
                            return_value=fake_sel), \
                        mock.patch.object(
                            provision, "kill_tree",
                            return_value=True) as retired:
                    with self.assertRaises(
                            provision.AdmissionError):
                        provision._spawn_keeper(
                            os.geteuid(),
                            os.path.join(tmp, "canary"),
                            os.path.join(tmp, "ns.pid"))
            retired.assert_called_once_with(
                "keeper-spawn", child.pid, 10)
            child.wait.assert_called_with(timeout=10)

        attempt(select=None)
        attempt(select=[True])

    # S103-round6 G1-I7: the evidence writer reports whether
    # the record landed, so callers can surface a failure.
    def test_preserve_keeper_evidence_reports_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            self.assertIs(
                provision._preserve_keeper_evidence(
                    pidfile, 7777, 55, "ef" * 16,
                    "test-reason"),
                True)
            self.assertIn(
                "7777 55",
                Path(f"{pidfile}.unresolved").read_text())
            self.assertIs(
                provision._preserve_keeper_evidence(
                    os.path.join(tmp, "missing", "ns.pid"),
                    7777, 55, "ef" * 16, "test-reason"),
                False)

    def test_read_ns_link_none_on_failure(self):
        # Dead pid (nonzero exit), missing sudo (OSError) and
        # sudo hang (timeout) all read as None — never raise —
        # so the caller falls through to respawn.
        from unittest import mock
        proc = mock.Mock(returncode=1, stdout="")
        with mock.patch.object(
                provision.subprocess, "run",
                return_value=proc) as run:
            self.assertIsNone(provision._read_ns_link(4321))
        argv = run.call_args[0][0]
        self.assertEqual(
            argv, ["sudo", "-n", "readlink",
                  "/proc/4321/ns/mnt"])
        with mock.patch.object(
                provision.subprocess, "run",
                side_effect=OSError("no sudo")):
            self.assertIsNone(provision._read_ns_link(4321))
        with mock.patch.object(
                provision.subprocess, "run",
                side_effect=provision.subprocess.TimeoutExpired(
                    "sudo", 30)):
            self.assertIsNone(provision._read_ns_link(4321))

    # NEW-1-round8: every nsenter join proves the bound
    # namespace from OUTSIDE (same sudo invocation opens the
    # ns path — pinning the namespace object — verifies the
    # pinned description against the verified nsid, and joins
    # through the pinned fd, all binaries host-resolved). A
    # recycled pid joins a wrong namespace whose ino differs,
    # so the effect never runs there — and no joined-ns
    # binary or path is ever trusted (the S114 in-join gate's
    # flaw). (An unprivileged controller cannot retain the
    # keeper's ns fd directly — opening a root process's ns
    # file fails EACCES, verified live — so the open happens
    # inside the same sudo invocation as the join.)
    def test_ns_pin_proof_pass_and_refusals(self):
        script = provision._ns_pin_proof_script()
        own = os.readlink("/proc/self/ns/mnt")
        own_nsid = own.split("[")[1].rstrip("]")
        mine = "/proc/self/ns/mnt"
        with tempfile.TemporaryDirectory() as tmp:
            # Stub nsenter: unprivileged setns always fails
            # (even for our own ns, verified live), so the
            # join step is stubbed — the stub demands the
            # pinned-fd target, reports the description it
            # actually inherited, then execs the payload. All
            # arms run with the stub on PATH so a broken
            # proof would visibly exec the payload (the arms
            # discriminate the PROOF, not nsenter privilege).
            stub = os.path.join(tmp, "nsenter")
            Path(stub).write_text(
                "#!/bin/sh\n"
                "[ \"$1\" = \"--mount=/proc/self/fd/3\" ] "
                "|| exit 7\n"
                "readlink /proc/self/fd/3\n"
                "shift\n"
                "exec \"$@\"\n")
            os.chmod(stub, 0o755)
            env = dict(os.environ)
            env["PATH"] = tmp + os.pathsep + env.get(
                "PATH", "")

            def run(nspath, nsid, *payload):
                return subprocess.run(
                    ["sh", "-c", script, nspath, nsid,
                     *payload],
                    capture_output=True, text=True,
                    timeout=30, env=env)

            # Pinned namespace: the join runs through the
            # pinned fd (carrying exactly our ns) and the
            # payload runs with argv intact.
            proc = run(mine, own_nsid, "echo", "PINNED-HI")
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout,
                             f"{own}\nPINNED-HI\n")
            # Wrong namespace (identity mismatch, the recycle
            # scenario): refuse before any join or effect.
            proc = run(mine, str(int(own_nsid) + 1000000000),
                       "echo", "PINNED-HI")
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn("PINNED-HI", proc.stdout)
            # Missing ns path: refuse, never exec.
            proc = run("/proc/99999999/ns/mnt", own_nsid,
                       "echo", "PINNED-HI")
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn("PINNED-HI", proc.stdout)
            # Empty payload: refuse (never a bare nsenter
            # shell in the keeper ns).
            proc = run(mine, own_nsid)
            self.assertNotEqual(proc.returncode, 0)

    # NEW-1-round8: a routed join without verified identity
    # is unbound and refused loudly (never joined).
    def test_gated_nsenter_unbound_identity_refuses(self):
        with mock.patch.object(provision,
                               "_MOUNT_NS_IDENTITY", None):
            with self.assertRaisesRegex(
                    provision.AdmissionError, "unbound"):
                provision._gated_nsenter_argv(
                    "/proc/9/ns/mnt", ["true"])

    # NEW-1-round8: the route proof must not trust binaries
    # resolved inside the joined namespace. A recycled-into
    # attacker ns can cover sh/cut/grep (covered cut yields
    # a non-empty canary, covered grep always passes) and
    # sail any proof that executes them post-join. This test
    # runs the proof portion of the routed argv with exactly
    # those covers on PATH: pre-fix the payload runs (the
    # bypass); post-fix the proof refuses (it opens and
    # verifies the ns from OUTSIDE, consulting no
    # joined-ns binary or path).
    def test_covered_binaries_cannot_sail_route_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            cover = os.path.join(tmp, "cover")
            os.mkdir(cover)
            cut = os.path.join(cover, "cut")
            Path(cut).write_text("#!/bin/sh\necho BOGUSCANARY\n")
            grep = os.path.join(cover, "grep")
            Path(grep).write_text("#!/bin/sh\nexit 0\n")
            os.chmod(cut, 0o755)
            os.chmod(grep, 0o755)
            env = dict(os.environ)
            env["PATH"] = cover + os.pathsep + env.get(
                "PATH", "")
            # The "attacker's" namespace: our own mount ns,
            # whose identity provably differs from the
            # recorded keeper nsid (the recycle scenario).
            own = os.readlink("/proc/self/ns/mnt")
            own_nsid = int(own.split("[")[1].rstrip("]"))
            attacker_nsid = own_nsid + 1000000000
            with mock.patch.object(
                    provision, "_MOUNT_NS_IDENTITY",
                    (os.getpid(), attacker_nsid, None,
                     "c" * 32)):
                argv = provision._gated_nsenter_argv(
                    "/proc/self/ns/mnt",
                    ["echo", "COVERED-SHOULD-NOT-RUN"])
            # The proof portion: everything from the proof
            # shell onward (old in-join gate and new outside
            # proof share this argv shape).
            at = argv.index("-c")
            proc = subprocess.run(
                argv[at - 1:], capture_output=True, text=True,
                timeout=30, env=env)
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn("COVERED-SHOULD-NOT-RUN",
                             proc.stdout)

    def test_run_sudo_nsenter_prefix_and_backstop(self):
        from unittest import mock
        proc = mock.Mock(returncode=0, stdout="ok\n", stderr="")
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  (9, 77, 555, "c" * 32)), \
                mock.patch.object(provision, "_ROOT_GUARD",
                                  None), \
                mock.patch.object(provision, "_keeper_starttime",
                                  return_value=555), \
                mock.patch.object(provision.subprocess, "run",
                                  return_value=proc) as run:
            rc, out, _ = provision.run_sudo(["true"])
            argv = run.call_args[0][0]
            # NEW-1-round8: the routed effect runs behind the
            # pinned-ns proof (same sudo invocation opens and
            # verifies before the join; nsid from identity).
            self.assertEqual(
                argv,
                ["sudo", "-n", "sh", "-c",
                 provision._ns_pin_proof_script(),
                 "/proc/9/ns/mnt", "77", "true"])
            self.assertEqual((rc, out), (0, "ok\n"))
        with mock.patch.object(provision, "_MOUNT_NS", None), \
                mock.patch.object(provision, "_ROOT_GUARD",
                                  None):
            rc, _, err = provision.run_sudo(
                ["python3", "provision_fs.py", "mount-fs"])
            self.assertEqual(rc, 127)
            self.assertIn("not ensured", err)
            with mock.patch.object(provision.subprocess, "run",
                                   return_value=proc) as run:
                provision.run_sudo(["true"])
            self.assertEqual(run.call_args[0][0][:3],
                             ["sudo", "-n", "true"])
        with mock.patch.object(provision, "_MOUNT_NS",
                               "direct"), \
                mock.patch.object(provision, "_ROOT_GUARD",
                                  None), \
                mock.patch.object(provision.subprocess, "run",
                                  return_value=proc) as run:
            provision.run_sudo(["x", "retire-mount"])
            self.assertNotIn("nsenter", run.call_args[0][0])
        # S100-round6: a dead/recycled keeper (starttime
        # anchor mismatch) refuses routed sudo — never a
        # silent redirect into another namespace.
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  (9, 77, 555, "c" * 32)), \
                mock.patch.object(provision, "_ROOT_GUARD",
                                  None), \
                mock.patch.object(provision, "_keeper_starttime",
                                  return_value=None), \
                mock.patch.object(provision.subprocess, "run",
                                  side_effect=AssertionError(
                                      "redirected")):
            rc, _, err = provision.run_sudo(["true"])
            self.assertEqual(rc, 127)
            self.assertIn("keeper ns changed or died", err)

    def test_read_mount_table_ns_routing(self):
        from unittest import mock
        body = ("8419 8260 0:35 / /tmp/x/mnt rw,noatime - btrfs "
                "/dev/sda3 rw\n")
        proc = mock.Mock(returncode=0, stdout=body.encode(),
                         stderr=b"")
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  (9, 77, 555, "c" * 32)), \
                mock.patch.object(provision, "_keeper_starttime",
                                  return_value=555):
            with mock.patch.object(provision.subprocess, "run",
                                   return_value=proc) as run:
                rows = provision.read_mount_table()
            argv = run.call_args[0][0]
            # NEW-1-round8: table observations are proven too
            # (they feed effects).
            self.assertEqual(
                argv,
                ["sudo", "-n", "sh", "-c",
                 provision._ns_pin_proof_script(),
                 "/proc/9/ns/mnt", "77",
                 "cat", "/proc/self/mountinfo"])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], 8419)
            # Explicit fixture paths always read direct.
            with tempfile.NamedTemporaryFile(
                    "w", suffix=".info", delete=False) as handle:
                handle.write(body)
                fixture = handle.name
            try:
                with mock.patch.object(
                        provision.subprocess, "run",
                        side_effect=AssertionError("sudo")):
                    rows = provision.read_mount_table(fixture)
            finally:
                os.unlink(fixture)
            self.assertEqual(rows[0]["mnt_id"], 8419)
        # S100-round6: a dead/recycled keeper raises instead
        # of reading another namespace's table (or the host's).
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"), \
                mock.patch.object(provision, "_MOUNT_NS_IDENTITY",
                                  (9, 77, 555, "c" * 32)), \
                mock.patch.object(provision, "_keeper_starttime",
                                  return_value=999), \
                mock.patch.object(provision.subprocess, "run",
                                  side_effect=AssertionError(
                                      "redirected")):
            with self.assertRaisesRegex(
                    provision.AdmissionError,
                    "keeper ns changed or died"):
                provision.read_mount_table()

    def test_ns_canary_command(self):
        import contextlib
        import io
        import types
        with tempfile.TemporaryDirectory() as tmp:
            run_root = os.path.join(tmp, "run")
            target = os.path.join(run_root, "mnt")
            os.makedirs(target)
            Path(target, "canary").write_bytes(b"tok123")
            mid = real_mnt_id(target)

            def run(**kw):
                base = {"run_root": run_root,
                        "target": target, "name": "canary",
                        "expect_mnt_id": str(mid)}
                base.update(kw)
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = provision.ns_canary_command(
                        types.SimpleNamespace(**base))
                return (rc, out.getvalue())

            rc, out = run()
            self.assertEqual(rc, 0)
            self.assertEqual(out.strip(), b"tok123".hex())
            # S81-round5: a swapped-in stranger (live ID
            # differs from the caller's row) refuses before
            # any byte is reported.
            rc, out = run(expect_mnt_id=str(mid + 100))
            self.assertEqual(rc, 1)
            self.assertIn("mount mismatch", out)
            self.assertEqual(run(name="nope")[0], 1)
            self.assertEqual(run(name="../escape")[0], 1)
            self.assertEqual(
                run(run_root="/etc", target="/etc",
                    name="x")[0], 1)
            self.assertEqual(run(expect_mnt_id="bogus")[0], 1)
            self.assertEqual(run(expect_mnt_id="")[0], 1)

    def test_canary_matches_routed(self):
        from unittest import mock
        with mock.patch.object(provision, "_MOUNT_NS",
                               "/proc/9/ns/mnt"):
            with mock.patch.object(
                    provision, "run_sudo",
                    return_value=(0, b"tok123".hex() + "\n",
                                  "")) as sudo:
                self.assertTrue(provision._canary_matches(
                    "/tmp/r/mnt", "canary", "tok123", "/tmp/r",
                    expect_mnt_id=42))
            argv = sudo.call_args[0][0]
            self.assertIn("ns-canary", argv)
            self.assertNotIn("tok123", " ".join(argv))
            self.assertIn("--expect-mnt-id", argv)
            self.assertIn("42", argv)
            with mock.patch.object(
                    provision, "run_sudo",
                    return_value=(1, "FAILED", "")):
                self.assertFalse(provision._canary_matches(
                    "/tmp/r/mnt", "canary", "tok123", "/tmp/r",
                    expect_mnt_id=42))
            with mock.patch.object(
                    provision, "run_sudo",
                    side_effect=AssertionError("sudo")):
                self.assertFalse(provision._canary_matches(
                    "/tmp/r/mnt", "canary", "tok123"))
                # S81-round5: no expected ID, no read — the
                # helper is never even invoked.
                self.assertFalse(provision._canary_matches(
                    "/tmp/r/mnt", "canary", "tok123", "/tmp/r"))

    # S101/S102-round6: grant-first dispatch matrix — usage
    # refusals and unprivileged creates never touch keeper
    # infrastructure; privileged creates ensure (hard failure,
    # never warn-continue); inspect/cleanup bind recorded
    # keepers only (never spawn); legacy manifests run
    # direct; helpers and plan stay outside entirely.
    def test_main_grant_first_dispatch(self):
        from unittest import mock

        def attempt(argv, manifest=None):
            with mock.patch.object(
                    provision, "ensure_mount_ns") as ensure, \
                    mock.patch.object(
                        provision, "bind_mount_ns") as bind, \
                    mock.patch.object(
                        provision, "_refuse_without_sudo_grant",
                        return_value=None), \
                    mock.patch.object(
                        provision, "_enter_keeper_ns",
                        return_value=None) as enter, \
                    mock.patch.object(
                        provision, "load_manifest",
                        return_value=manifest), \
                    mock.patch.object(
                        provision, "create_command",
                        return_value=11) as create, \
                    mock.patch.object(
                        provision, "inspect_command",
                        return_value=12) as inspect, \
                    mock.patch.object(
                        provision, "cleanup_command",
                        return_value=13) as cleanup:
                rc = provision.main(argv)
            return (rc, ensure, bind, enter,
                    create, inspect, cleanup)

        # Foreign run-root: usage refusal before any setup.
        (rc, ensure, bind, enter,
         create, inspect, cleanup) = attempt(
            ["create", "--manifest", "m",
             "--run-root", "/etc/shadow"])
        self.assertEqual(rc, 2)
        ensure.assert_not_called()
        bind.assert_not_called()
        create.assert_not_called()
        # Unprivileged create: validated, no keeper effects.
        with tempfile.TemporaryDirectory() as tmp:
            man = os.path.join(tmp, "m.json")
            run = os.path.join(tmp, "run")
            (rc, ensure, bind, enter,
             create, inspect, cleanup) = attempt(
                ["create", "--manifest", man,
                 "--run-root", run])
            self.assertEqual(rc, 11)
            ensure.assert_not_called()
            bind.assert_not_called()
            create.assert_called_once()
            # Privileged create: ensure, enter, provision.
            (rc, ensure, bind, enter,
             create, inspect, cleanup) = attempt(
                ["create", "--manifest", man,
                 "--run-root", run, "--privileged"])
            self.assertEqual(rc, 11)
            ensure.assert_called_once_with()
            bind.assert_not_called()
            enter.assert_called_once_with("create")
            create.assert_called_once()
            # Existing manifest: refusal before ensure.
            Path(man).write_text("{}")
            (rc, ensure, bind, enter,
             create, inspect, cleanup) = attempt(
                ["create", "--manifest", man,
                 "--run-root", run, "--privileged"])
            self.assertEqual(rc, 2)
            ensure.assert_not_called()
        # Inspect/cleanup, legacy manifest: direct, no bind.
        (rc, ensure, bind, enter,
         create, inspect, cleanup) = attempt(
            ["inspect", "--manifest", "m",
             "--run-root", "/tmp/r"], manifest={})
        self.assertEqual(rc, 12)
        ensure.assert_not_called()
        bind.assert_not_called()
        inspect.assert_called_once()
        # Ns-native manifest: bind with the recorded identity
        # (never ensure/spawn), then enter.
        mode = {"pid": 9, "nsid": 77, "starttime": 555}
        (rc, ensure, bind, enter,
         create, inspect, cleanup) = attempt(
            ["cleanup", "--manifest", "m",
             "--run-root", "/tmp/r"],
            manifest={"mount_ns": mode})
        self.assertEqual(rc, 13)
        ensure.assert_not_called()
        bind.assert_called_once_with(expected=mode)
        enter.assert_called_once_with("cleanup")
        cleanup.assert_called_once()
        # Helpers and plan: no ns setup at all.
        with mock.patch.object(
                provision, "ensure_mount_ns") as ensure, \
                mock.patch.object(
                    provision, "bind_mount_ns") as bind, \
                mock.patch.object(
                    provision, "plan_command",
                    return_value=0), \
                mock.patch.object(
                    provision, "signal_proc_command",
                    return_value=0):
            provision.main(["plan", "--manifest", "m",
                            "--run-root", "/tmp/r"])
            provision.main(["signal-proc", "--pid", "1",
                            "--starttime", "2", "--signum",
                            "15"])
        ensure.assert_not_called()
        bind.assert_not_called()

    def test_main_ensure_failure_fails_create(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            man = os.path.join(tmp, "m.json")
            run = os.path.join(tmp, "run")
            with mock.patch.object(
                    provision, "ensure_mount_ns",
                    side_effect=provision.
                    AdmissionError("nope")), \
                    mock.patch.object(
                        provision,
                        "_refuse_without_sudo_grant",
                        return_value=None), \
                    mock.patch.object(
                        provision, "_enter_keeper_ns") as enter, \
                    mock.patch.object(
                        provision, "create_command",
                        side_effect=AssertionError(
                            "provisioned without ns")):
                rc = provision.main(
                    ["create", "--manifest", man,
                     "--run-root", run, "--privileged"])
        self.assertEqual(rc, 1)
        enter.assert_not_called()

    def test_main_bind_failure_refuses_cleanup(self):
        from unittest import mock
        mode = {"pid": 9, "nsid": 77, "starttime": 555}
        with mock.patch.object(
                provision, "bind_mount_ns",
                side_effect=provision.
                AdmissionError("recorded keeper dead")), \
                mock.patch.object(
                    provision, "load_manifest",
                    return_value={"mount_ns": mode}), \
                mock.patch.object(
                    provision, "_enter_keeper_ns") as enter, \
                mock.patch.object(
                    provision, "cleanup_command",
                    side_effect=AssertionError(
                        "cleaned without ns")):
            rc = provision.main(["cleanup", "--manifest", "m",
                                 "--run-root", "/tmp/r"])
        self.assertEqual(rc, 1)
        enter.assert_not_called()


    def test_manifest_ns_mode(self):
        old_ns = provision._MOUNT_NS
        old_ident = provision._MOUNT_NS_IDENTITY
        self.addCleanup(setattr, provision, "_MOUNT_NS", old_ns)
        self.addCleanup(
            setattr, provision, "_MOUNT_NS_IDENTITY", old_ident)
        # S100-round6: unensured creation binds no keeper
        # (False); an ensured creation records the identity.
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        with tempfile.TemporaryDirectory() as tmp:
            doc = provision.fresh_manifest(tmp, True)
        self.assertEqual(doc["mount_ns"], False)
        provision._MOUNT_NS = "/proc/9/ns/mnt"
        provision._MOUNT_NS_IDENTITY = (9, 77, 555, "c" * 32)
        with tempfile.TemporaryDirectory() as tmp:
            bound = provision.fresh_manifest(tmp, True)
        self.assertEqual(bound["mount_ns"],
                         {"pid": 9, "nsid": 77,
                          "starttime": 555})
        # Matching binding applies cleanly.
        provision._apply_manifest_ns_mode(bound)
        self.assertEqual(provision._MOUNT_NS, "/proc/9/ns/mnt")
        # A substituted keeper (different pid/nsid) refuses —
        # never a silent adoption of another namespace.
        other = dict(
            bound, mount_ns={"pid": 10, "nsid": 78,
                             "starttime": 556})
        with self.assertRaisesRegex(
                provision.AdmissionError, "refusing substitution"):
            provision._apply_manifest_ns_mode(other)
        # Unensured recovery of an ns-native manifest refuses
        # — never a host-table fallback.
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        with self.assertRaisesRegex(
                provision.AdmissionError,
                "refusing host-table fallback"):
            provision._apply_manifest_ns_mode(bound)
        # Round-5 boolean manifests adopt the current binding
        # (still ensured, never the host table).
        provision._MOUNT_NS = "/proc/9/ns/mnt"
        provision._MOUNT_NS_IDENTITY = (9, 77, 555, "c" * 32)
        provision._apply_manifest_ns_mode({"mount_ns": True})
        self.assertEqual(provision._MOUNT_NS, "/proc/9/ns/mnt")
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None
        with self.assertRaisesRegex(
                provision.AdmissionError,
                "refusing host-table fallback"):
            provision._apply_manifest_ns_mode({"mount_ns": True})
        # Legacy manifests clean up direct.
        provision._apply_manifest_ns_mode({})
        self.assertEqual(provision._MOUNT_NS, "direct")


if __name__ == "__main__":
    unittest.main()
