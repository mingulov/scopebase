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
        with tempfile.TemporaryDirectory() as tmp:
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
                        "/dev/loop7", backing)
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
                        "/dev/loop7", backing)
            self.assertIn("identity changed", failure)
            sudo.assert_not_called()
            # Matching path AND identity detaches; a gone device is
            # a no-op; a stale string-form record fails closed.
            st2 = os.stat(img)
            backing2 = {"path": img, "dev": st2.st_dev, "ino": st2.st_ino}
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=img):
                with mock.patch.object(provision, "run_sudo",
                                       return_value=(0, "", "")) as sudo:
                    self.assertIsNone(provision.cleanup_loop_device(
                        "/dev/loop7", backing2))
                    sudo.assert_called_once_with(["losetup", "-d",
                                                  "/dev/loop7"])
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=None):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    self.assertIsNone(provision.cleanup_loop_device(
                        "/dev/loop7", backing2))
                    sudo.assert_not_called()
            with mock.patch.object(provision, "read_loop_backing",
                                   return_value=img):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_loop_device(
                        "/dev/loop7", img)
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
        with mock.patch.object(provision, "run_sudo") as sudo:
            failure = provision.cleanup_one_mount(
                record, stacked, run_root)
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

    def test_churn_point_refuses_foreign_occupant(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            live = [{"target": churn["point"], "mnt_id": 9,
                     "fstype": "tmpfs", "source": "/foreign",
                     "super": "rw|"}]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_churn_point(
                        churn, run_root)
            self.assertIn("foreign mount", failure)
            sudo.assert_not_called()

    def test_churn_point_refuses_stacked_mounts(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            row = {"target": churn["point"], "mnt_id": 9,
                   "fstype": "ext4", "source": churn["bind_source"],
                   "super": "rw|"}
            live = [row, dict(row, mnt_id=10)]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_churn_point(
                        churn, run_root)
            self.assertIn("stacked mounts", failure)
            sudo.assert_not_called()

    def test_churn_point_refuses_resourced_source(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            # Same source pathname, fresh inode: not our bind.
            os.unlink(churn["bind_source"])
            Path(churn["bind_source"]).write_bytes(b"fresh")
            live = [{"target": churn["point"], "mnt_id": 9,
                     "fstype": "ext4", "source": churn["bind_source"],
                     "super": "rw|"}]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(provision, "run_sudo") as sudo:
                    failure = provision.cleanup_churn_point(
                        churn, run_root)
            self.assertIn("source identity changed", failure)
            sudo.assert_not_called()

    def test_churn_point_unmounts_owned_bind(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            run_root, churn = self.churn_record(Path(tmp))
            live = [{"target": churn["point"], "mnt_id": 9,
                     "fstype": "ext4", "source": churn["bind_source"],
                     "super": "rw|"}]
            with mock.patch.object(provision, "read_mount_table",
                                   return_value=live):
                with mock.patch.object(
                        provision, "run_sudo",
                        return_value=(0, "", "")) as sudo:
                    self.assertIsNone(provision.cleanup_churn_point(
                        churn, run_root))
                    sudo.assert_called_once_with(
                        ["umount", churn["point"]])

    def test_driver_restore_gate_checks_owned_bind(self):
        import ast
        from unittest import mock
        # Exercise the SHIPPED driver gate: extract owned_bind_only
        # from the driver source and run it against fake tables.
        tree = ast.parse(provision.CHURN_DRIVER_PY)
        wanted = [node for node in tree.body
                  if isinstance(node, ast.FunctionDef)
                  and node.name == "owned_bind_only"]
        self.assertEqual(len(wanted), 1)
        module = ast.Module(body=wanted, type_ignores=[])
        namespace = {"os": os}
        exec(compile(module, "<driver>", "exec"), namespace)  # noqa: S102
        gate = namespace["owned_bind_only"]
        point, payload = "/run/churn/point", "/run/churn/payload-b"
        owned = (f"90 1 0:50 / {point} rw shared:1 - ext4 "
                 f"{payload} rw\n")
        foreign = (f"90 1 0:50 / {point} rw shared:1 - tmpfs "
                 f"/foreign rw\n")
        with tempfile.TemporaryDirectory() as tmp:
            table = Path(tmp) / "mountinfo"
            table.write_text(owned)
            with mock.patch.dict(os.environ,
                                 {"TT04_MOUNTINFO": str(table)}):
                self.assertTrue(gate(point, payload))
            table.write_text(foreign)
            with mock.patch.dict(os.environ,
                                 {"TT04_MOUNTINFO": str(table)}):
                self.assertFalse(gate(point, payload))
            table.write_text(owned + owned.replace("90 1 ", "91 1 "))
            with mock.patch.dict(os.environ,
                                 {"TT04_MOUNTINFO": str(table)}):
                self.assertFalse(gate(point, payload))
            with mock.patch.dict(os.environ, {"TT04_MOUNTINFO": str(
                    Path(tmp) / "no-such-table")}):
                self.assertFalse(gate(point, payload))

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
        calls = []

        def fake_sudo(argv, timeout=120):
            calls.append(list(argv))
            if argv[0] == "mkfs.ext4":
                return (0, "", "")
            if argv[0] == "losetup" and argv[1] == "--find":
                return (0, "/dev/loop9\n", "")
            if argv[0] == "losetup" and argv[1] == "-d":
                return (0, "", "")
            if argv[0] == "mount":
                return (124, "", "sudo timed out after 120s: mount")
            raise AssertionError(f"unexpected sudo: {argv}")

        doc = provision.fresh_manifest(run_root, True)
        provision._PERSIST = manifest
        try:
            with mock.patch.object(provision, "run_sudo",
                                   side_effect=fake_sudo):
                with mock.patch.object(provision.shutil, "which",
                                       return_value="/sbin/x"):
                    provision.provision_ext4(doc, run_root)
        finally:
            provision._PERSIST = None
        # The attached loop is detached on the mount timeout: no
        # orphan. Custody was persisted BEFORE the mount call.
        self.assertIn(["losetup", "-d", "/dev/loop9"], calls)
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
            stdout = mock.Mock()
            stdout.readline.return_value = b"ready\n"
            child = mock.Mock()
            child.pid = 424242
            child.stdout = stdout
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
            with self.assertRaises(OSError):
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


if __name__ == "__main__":
    unittest.main()
