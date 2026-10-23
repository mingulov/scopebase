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
