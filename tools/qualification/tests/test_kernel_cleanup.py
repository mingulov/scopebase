# SPDX-License-Identifier: Apache-2.0
"""TT05 cleanup-inspection checks for tools/qualification/inspect_cleanup.py.

TDD: authored before the tool and observed failing (FileNotFoundError:
missing tools/qualification/kernel_common.py) prior to implementation.
"""
import hashlib
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

common = h.load("kernel_common", "tools/qualification/kernel_common.py")
admit = h.load("admit_object", "tools/qualification/admit_object.py")
guest = h.load("run_guest", "tools/qualification/run_guest.py")
insp = h.load("inspect_cleanup", "tools/qualification/inspect_cleanup.py")

TOOL = h.ROOT / "tools/qualification/inspect_cleanup.py"


def writer():
    return (
        "import json,sys\n"
        "json.dump({'setup_ok': True, 'assertion': 'pass',"
        " 'detail': 'stub-ok'}, open(sys.argv[1], 'w'))\n"
    )


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.leases = self.root / "leases"
        self.leases.mkdir()
        self.obj = self.root / "demo.bpf.o"
        self.obj.write_bytes(h.build_elf())
        manifest = self.root / "manifest.json"
        manifest.write_bytes(h.manifest_bytes([h.object_entry(self.obj)]))
        profile = self.root / "profile.json"
        profile.write_bytes(h.profile_bytes())
        self.admission = self.root / "admission.json"
        self.admission.write_text(json.dumps(
            admit.admit_object(str(manifest), str(self.obj), str(profile))))
        self.env = self.root / "env.json"
        self.env.write_bytes(h.env_bytes([h.cell(
            "plain", workload=h.workload(
                [sys.executable, "-c", writer(), "{result}"]),
            release_probes=["no-owned-procs", "run-root-retired"])]))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cell(self, name="run-root", foreign=()):
        out = self.root / name
        manifest = guest.run_guest(
            str(self.admission), str(self.env), str(out),
            cell="plain", lease_root=str(self.leases), holder="tt05-test",
            foreign=[str(p) for p in foreign])
        self.assertEqual(manifest["status"], "PASS")
        return out

    def test_clean_run_inspects_clean(self):
        out = self.run_cell()
        report = insp.inspect_cleanup(str(out / "run.json"), lease_root=str(self.leases))
        self.assertEqual(report["verdict"], "CLEAN")
        self.assertFalse(report["retired"])

    def test_foreign_pin_is_not_cleanup_target(self):
        # A foreign sentinel inside the owned run root survives inspection
        # and retirement byte-identical; it is never residue.
        out = self.root / "run-root"
        out.mkdir()
        pin = out / "foreign-pin"
        pin.write_bytes(b"not-ours-do-not-touch")
        # Reused roots raise: the run must not proceed.
        with self.assertRaises(common.KernelError) as ctx:
            guest.run_guest(
                str(self.admission), str(self.env), str(out),
                cell="plain", lease_root=str(self.leases), holder="tt05-test",
                foreign=[str(pin)])
        self.assertIn("run-root-exists", str(ctx.exception))
        # Real flow: pre-created roots raise; the run must not proceed.
        out2 = self.root / "run-root-2"
        out2.mkdir()
        with self.assertRaises(common.KernelError):
            guest.run_guest(str(self.admission), str(self.env), str(out2),
                            cell="plain", lease_root=str(self.leases), holder="tt05-test")
        out2.rmdir()
        guest.run_guest(str(self.admission), str(self.env), str(out2),
                        cell="plain", lease_root=str(self.leases), holder="tt05-test")
        # Planting after the run is undeclared residue, not a foreign pin.
        (out2 / "late-pin").write_bytes(b"late")
        report = insp.inspect_cleanup(str(out2 / "run.json"), lease_root=str(self.leases))
        self.assertEqual(report["verdict"], "RESIDUE")
        # Declared foreign pins (inside or outside the root) are preserved.
        outside = self.root / "outside-pin"
        outside.write_bytes(b"foreign-bytes")
        out3 = self.root / "run-root-3"
        manifest3 = guest.run_guest(
            str(self.admission), str(self.env), str(out3),
            cell="plain", lease_root=str(self.leases), holder="tt05-test",
            foreign=[str(outside)])
        self.assertEqual(manifest3["status"], "PASS")
        report3 = insp.inspect_cleanup(str(out3 / "run.json"), lease_root=str(self.leases))
        self.assertEqual(report3["verdict"], "CLEAN")
        retired = insp.inspect_cleanup(
            str(out3 / "run.json"), lease_root=str(self.leases), retire=True)
        self.assertEqual(retired["verdict"], "RETIRED_CLEAN")
        self.assertTrue(retired["retired"])
        self.assertEqual(outside.read_bytes(), b"foreign-bytes")
        self.assertTrue((out3 / "run.json").exists())
        self.assertFalse((out3 / "stage" / "admitted-object").exists())

    def test_disturbed_foreign_pin_fails(self):
        outside = self.root / "outside-pin"
        outside.write_bytes(b"foreign-bytes")
        out3 = self.root / "run-root-3"
        guest.run_guest(str(self.admission), str(self.env), str(out3),
                        cell="plain", lease_root=str(self.leases), holder="tt05-test",
                        foreign=[str(outside)])
        outside.write_bytes(b"tampered")
        report = insp.inspect_cleanup(str(out3 / "run.json"), lease_root=str(self.leases))
        self.assertEqual(report["verdict"], "FOREIGN_DISTURBED")

    def test_residue_blocks_retire(self):
        out = self.run_cell()
        (out / "mystery.o").write_bytes(b"unaccounted")
        report = insp.inspect_cleanup(
            str(out / "run.json"), lease_root=str(self.leases), retire=True)
        self.assertEqual(report["verdict"], "RESIDUE")
        self.assertFalse(report["retired"])
        self.assertTrue((out / "mystery.o").exists())

    def test_dirty_cell_blocks_clean_verdict(self):
        bad_env = self.root / "bad-env.json"
        bad_env.write_bytes(h.env_bytes([h.cell(
            "dirtycell",
            workload=h.workload([sys.executable, "-c",
                                 "import json,sys;json.dump({'setup_ok': True,"
                                 " 'assertion': 'fail', 'detail': 'boom'},"
                                 " open(sys.argv[1], 'w'))", "{result}"]))]))
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(bad_env), str(out),
            cell="dirtycell", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "FAIL")
        report = insp.inspect_cleanup(str(out / "run.json"), lease_root=str(self.leases))
        self.assertEqual(report["verdict"], "DIRTY_CELL")

    def test_held_lease_blocks_clean_verdict(self):
        out = self.run_cell()
        held = common.acquire_lease(
            str(self.leases), "plain", "other", "run-other", ["plain"])
        try:
            report = insp.inspect_cleanup(str(out / "run.json"), lease_root=str(self.leases))
            self.assertEqual(report["verdict"], "STILL_LEASED")
        finally:
            common.release_lease(held, True, "test done")

    def test_accept_clean_recovers_dirty_cell(self):
        bad_env = self.root / "bad-env.json"
        bad_env.write_bytes(h.env_bytes([h.cell(
            "recovery",
            workload=h.workload([sys.executable, "-c",
                                 "import json,sys;json.dump({'setup_ok': True,"
                                 " 'assertion': 'fail', 'detail': 'boom'},"
                                 " open(sys.argv[1], 'w'))", "{result}"]))]))
        out = self.root / "run-root"
        guest.run_guest(str(self.admission), str(bad_env), str(out),
                        cell="recovery", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(common.lease_status(str(self.leases), "recovery")["state"], "dirty")
        # Retire the failed run's owned files first, then accept clean.
        retired = insp.inspect_cleanup(
            str(out / "run.json"), lease_root=str(self.leases), retire=True)
        self.assertEqual(retired["verdict"], "RETIRED_DIRTY")
        accepted = insp.inspect_cleanup(
            str(out / "run.json"), lease_root=str(self.leases),
            accept_clean="recovery")
        self.assertTrue(accepted["flipped"])
        self.assertEqual(common.lease_status(str(self.leases), "recovery")["state"], "clean")
        # The cell runs again after explicit acceptance.
        ok_env = self.root / "ok-env.json"
        ok_env.write_bytes(h.env_bytes([h.cell(
            "recovery",
            workload=h.workload([sys.executable, "-c", writer(), "{result}"]))]))
        out2 = self.root / "run-root-2"
        manifest = guest.run_guest(
            str(self.admission), str(ok_env), str(out2),
            cell="recovery", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "PASS")

    def test_accept_clean_refused_while_leased(self):
        out = self.run_cell()
        held = common.acquire_lease(
            str(self.leases), "plain", "other", "run-other", ["plain"])
        try:
            with self.assertRaises(common.KernelError) as ctx:
                insp.inspect_cleanup(str(out / "run.json"), lease_root=str(self.leases),
                                     accept_clean="plain")
            self.assertIn("still-leased", str(ctx.exception))
        finally:
            common.release_lease(held, True, "test done")

    def test_cli_verdicts(self):
        out = self.run_cell()
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(out / "run.json"),
             "--lease-root", str(self.leases)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("CLEAN", proc.stdout)
        (out / "extra").write_bytes(b"x")
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(out / "run.json"),
             "--lease-root", str(self.leases)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("RESIDUE", proc.stdout)


if __name__ == "__main__":
    unittest.main()
