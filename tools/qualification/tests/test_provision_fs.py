# SPDX-License-Identifier: Apache-2.0
"""TT04 filesystem provisioner checks for tools/qualification/provision_fs.py.

TDD: authored before the tool and observed failing (FileNotFoundError:
missing tools/qualification/provision_fs.py) prior to implementation.

Only deterministic, unprivileged negatives live here: foreign-path
refusals, grant discipline, manifest tamper detection, idempotent
cleanup and the pure mountinfo/admission predicates. Live privileged
provisioning is exercised by the operator route, never by this file.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HELPERS = Path(__file__).resolve().parent / "tt05_helpers.py"
hspec = importlib.util.spec_from_file_location("tt05_helpers", HELPERS)
h = importlib.util.module_from_spec(hspec)
sys.modules["tt05_helpers"] = h
hspec.loader.exec_module(h)

provision = h.load("provision_fs", "tools/qualification/provision_fs.py")
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

    def test_cleanup_loop_device_refuses_reused_name(self):
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
        os.makedirs(os.path.join(aux, "lower"))
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

    def test_ext4_mount_timeout_detaches_loop_and_persists(self):
        import types
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if argv[0] == "mkfs.ext4":
                return (0, "", "")
            if argv[0] == "losetup" and argv[1] == "--find":
                return (0, "/dev/loop9\n", "")
            if "retire-loop" in argv:
                return (0, "retired-loop /dev/loop9\n", "")
            if argv[0] == "mount":
                return (124, "", "sudo timed out after 120s: mount")
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
            base.mkdir()
            tree = base / "tree"
            (tree / "sub" / "deep").mkdir(parents=True)
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
            base.mkdir()
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
            base.mkdir()
            tree = base / "tree"
            (tree / "sub").mkdir(parents=True)
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

    def test_retire_helper_roundtrip_and_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            tree = base / "tree"
            (tree / "sub").mkdir(parents=True)
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
            tree.mkdir()
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
    def test_losetup_backing_swap_detected(self):
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if argv[0] == "mkfs.ext4":
                return (0, "", "")
            if argv[0] == "losetup" and argv[1] == "--find":
                # Replace the image between attach and identity
                # recording: same spelling, fresh inode.
                image = os.path.join(run_root, "ext4", "fs01.img")
                os.unlink(image)
                Path(image).write_bytes(b"replacement-image")
                return (0, "/dev/loop9\n", "")
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
        self.assertFalse(any(c[0] == "mount" for c in calls))

    # S16: rollback removes only provably-owned occupants.
    def test_ext4_rollback_preserves_stacked_mount(self):
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if argv[0] == "mkfs.ext4":
                return (0, "", "")
            if argv[0] == "losetup" and argv[1] == "--find":
                return (0, "/dev/loop9\n", "")
            if "retire-mount" in argv:
                return (1, "", "FAILED: ambiguous stacked mount")
            if "retire-loop" in argv:
                return (0, "retired-loop /dev/loop9\n", "")
            if argv[0] == "mount":
                return (0, "", "")
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
            if argv[0] == "mount":
                return (0, "", "")
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
                    return_value=["/dev/loop9"]):
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
                    return_value=[]):
                self.assertIsNone(provision.reconcile_loop_attach(
                    doc, image, st.st_dev, st.st_ino))
            self.assertEqual(doc["pending_acquisitions"], [])
            doc["pending_acquisitions"] = [{
                "kind": "loop", "key": image, "image": image,
                "dev": st.st_dev, "ino": st.st_ino}]
            with mock.patch.object(
                    provision, "scan_loop_by_backing",
                    return_value=["/dev/loop9", "/dev/loop10"]):
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
            if argv[0] == "mkfs.ext4":
                return (0, "", "")
            if argv[0] == "losetup" and argv[1] == "--find":
                # Attached, but the device name never came back.
                return (124, "", "sudo timed out after 120s: losetup")
            if argv[0] == "mount":
                return (0, "", "")
            if argv[0] == "chown":
                return (0, "", "")
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
                            return_value=["/dev/loop9"]):
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

    def test_mount_timeout_without_effect_detaches_loop(self):
        from unittest import mock
        tmp, run_root, manifest = self.fresh_paths()
        os.makedirs(run_root)

        def fake_sudo(argv, timeout=120):
            if argv[0] == "mkfs.ext4":
                return (0, "", "")
            if argv[0] == "losetup" and argv[1] == "--find":
                return (0, "/dev/loop9\n", "")
            if "retire-loop" in argv:
                return (0, "retired-loop /dev/loop9\n", "")
            if argv[0] == "mount":
                return (124, "", "sudo timed out after 120s: mount")
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
        # No mount took effect: pending cleared, loop detached,
        # honest timeout reason.
        self.assertIn("timed out", doc["cells"]["FS01"]["reason"])
        self.assertEqual(doc["pending_acquisitions"], [])

    # S17: validation/effect-boundary substitutions refuse; every
    # effect is post-verified; no bare umount/detach exists.
    def test_retire_mount_validates_effect_boundary(self):
        from unittest import mock
        target = "/tmp/provision-s17/mnt"
        run_root = "/tmp/provision-s17"
        expected = {"mnt_id": 1, "fstype": "ext4",
                    "source": "/dev/loop9", "expect_super": []}
        ok = {"target": target, "mnt_id": 1, "root": "/",
              "fstype": "ext4", "source": "/dev/loop9",
              "super": "rw|"}
        foreign = {"target": target, "mnt_id": 2, "root": "/",
                   "fstype": "tmpfs", "source": "tmpfs",
                   "super": "rw|"}
        with mock.patch.object(
                provision, "read_mount_table",
                side_effect=[[ok], [foreign]]):
            with mock.patch.object(provision, "_umount2") as detach:
                failure = provision.retire_mount_now(
                    target, expected, run_root)
        self.assertIn("between validation and effect", failure)
        detach.assert_not_called()

    def test_retire_mount_verifies_post_effect(self):
        from unittest import mock
        target = "/tmp/provision-s17/mnt"
        run_root = "/tmp/provision-s17"
        expected = {"mnt_id": 1, "fstype": "ext4",
                    "source": "/dev/loop9", "expect_super": []}
        ok = {"target": target, "mnt_id": 1, "root": "/",
              "fstype": "ext4", "source": "/dev/loop9",
              "super": "rw|"}
        with mock.patch.object(
                provision, "read_mount_table",
                side_effect=[[ok], [ok], [ok]]):
            with mock.patch.object(provision, "_umount2",
                                   return_value=None) as detach:
                failure = provision.retire_mount_now(
                    target, expected, run_root)
        self.assertIn("still live", failure)
        detach.assert_called_once_with(target)
        with mock.patch.object(
                provision, "read_mount_table",
                side_effect=[[ok], [ok], []]):
            with mock.patch.object(provision, "_umount2",
                                   return_value=None):
                self.assertIsNone(provision.retire_mount_now(
                    target, expected, run_root))

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
            with mock.patch.object(
                    provision, "read_loop_backing",
                    side_effect=[image, other]):
                with mock.patch.object(
                        provision, "_loop_clr_fd") as detach:
                    failure = provision.retire_loop_now(
                        "/dev/loop7", backing, tmp)
            self.assertIn("between validation and effect", failure)
            detach.assert_not_called()
            with mock.patch.object(
                    provision, "read_loop_backing",
                    side_effect=[image, image, image]):
                with mock.patch.object(
                        provision, "_loop_clr_fd",
                        return_value=None):
                    failure = provision.retire_loop_now(
                        "/dev/loop7", backing, tmp)
            self.assertIn("still attached", failure)
            with mock.patch.object(
                    provision, "read_loop_backing",
                    side_effect=[image, image, None]):
                with mock.patch.object(
                        provision, "_loop_clr_fd",
                        return_value=None) as detach:
                    self.assertIsNone(provision.retire_loop_now(
                        "/dev/loop7", backing, tmp))
                    detach.assert_called_once_with("/dev/loop7")

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
                        provision, "_loop_clr_fd") as detach:
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
            os.makedirs(run_root)
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
                with self.assertRaisesRegex(
                        provision.AdmissionError, "starttime changed"):
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
            orig_kill = os.kill
            checked = []

            def checking_kill(pid, signum):
                pidfds = 0
                for fd in os.listdir("/proc/self/fd"):
                    try:
                        if os.readlink(f"/proc/self/fd/{fd}") == \
                                "anon_inode:[pidfd]":
                            pidfds += 1
                    except OSError:
                        pass
                checked.append(pidfds)
                assert pidfds >= 1, "signal without a held pidfd"
                return orig_kill(pid, signum)

            from unittest import mock
            with mock.patch("os.kill", side_effect=checking_kill):
                self.assertTrue(
                    provision.kill_owned("test", child.pid, start,
                                         timeout=5))
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
            sub.mkdir(parents=True)
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
            tree.mkdir()
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
    def test_cleanup_reconciles_pending_mounts(self):
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
        with mock.patch.object(provision, "read_mount_table",
                               return_value=[]):
            self.assertEqual(provision.cleanup_command(args), 0)
        self.assertFalse(os.path.exists(run_root))

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


if __name__ == "__main__":
    unittest.main()
