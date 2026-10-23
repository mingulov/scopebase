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
        with mock.patch.object(provision, "run_sudo") as sudo:
            failure = provision.cleanup_one_mount(
                entry, replaced, run_root)
        self.assertIn("replacement refused", failure)
        sudo.assert_not_called()
        # Matching identity still unmounts; a gone mount is a no-op.
        live = [{"target": f"{run_root}/mnt", "mnt_id": 111,
                 "fstype": "ext4", "source": "/dev/loop9",
                 "super": "rw|"}]
        with mock.patch.object(provision, "run_sudo",
                               return_value=(0, "", "")) as sudo:
            self.assertIsNone(
                provision.cleanup_one_mount(entry, live, run_root))
            sudo.assert_called_once_with(["umount", f"{run_root}/mnt"])
        with mock.patch.object(provision, "run_sudo") as sudo:
            self.assertIsNone(
                provision.cleanup_one_mount(entry, [], run_root))
            sudo.assert_not_called()

    def test_cleanup_loop_device_refuses_reused_name(self):
        from unittest import mock
        with mock.patch.object(provision, "read_loop_backing",
                               return_value="/tmp/other.img"):
            with mock.patch.object(provision, "run_sudo") as sudo:
                failure = provision.cleanup_loop_device(
                    "/dev/loop7", "/tmp/run/ext4.img")
        self.assertIn("refusing detach", failure)
        sudo.assert_not_called()
        # Matching backing detaches; a gone device is a no-op.
        with mock.patch.object(provision, "read_loop_backing",
                               return_value="/tmp/run/ext4.img"):
            with mock.patch.object(provision, "run_sudo",
                                   return_value=(0, "", "")) as sudo:
                self.assertIsNone(provision.cleanup_loop_device(
                    "/dev/loop7", "/tmp/run/ext4.img"))
                sudo.assert_called_once_with(["losetup", "-d",
                                              "/dev/loop7"])
        with mock.patch.object(provision, "read_loop_backing",
                               return_value=None):
            with mock.patch.object(provision, "run_sudo") as sudo:
                self.assertIsNone(provision.cleanup_loop_device(
                    "/dev/loop7", "/tmp/run/ext4.img"))
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

    def test_find_mount_matches_exact_target(self):
        table = [provision.parse_mountinfo_row(self.ROW)]
        hit = provision.find_mount(table, "/")
        self.assertIsNotNone(hit)
        self.assertIsNone(provision.find_mount(table, "/etc"))
        # Prefix matches are not mount matches.
        self.assertIsNone(provision.find_mount([], "/"))

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


if __name__ == "__main__":
    unittest.main()
