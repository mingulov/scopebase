# SPDX-License-Identifier: Apache-2.0
"""TT05 cell-lease checks for tools/qualification/kernel_common.py leases.

TDD: authored before the tool and observed failing (FileNotFoundError:
missing tools/qualification/kernel_common.py) prior to implementation.
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

common = h.load("kernel_common", "tools/qualification/kernel_common.py")


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.leases = Path(self.tmp.name) / "leases"
        self.leases.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_acquire_release_clean(self):
        lease = common.acquire_lease(str(self.leases), "cell-a", "holder-1", "run-1", ["cell-a"])
        record = json.loads((self.leases / "cell-a" / "lease.json").read_text())
        self.assertEqual(record["holder"], "holder-1")
        self.assertTrue(record["exclusive"])
        self.assertEqual(record["run_id"], "run-1")
        common.release_lease(lease, True, "test done")
        self.assertFalse((self.leases / "cell-a" / "lease.json").exists())
        state = json.loads((self.leases / "cell-a" / "state.json").read_text())
        self.assertEqual(state["state"], "clean")
        # Re-acquire works after a clean release.
        lease2 = common.acquire_lease(str(self.leases), "cell-a", "holder-2", "run-2", ["cell-a"])
        common.release_lease(lease2, True, "test done")

    def test_lease_exhaustion_refused(self):
        lease = common.acquire_lease(str(self.leases), "cell-a", "holder-1", "run-1", ["cell-a"])
        try:
            with self.assertRaises(common.KernelError) as ctx:
                common.acquire_lease(str(self.leases), "cell-a", "holder-2", "run-2", ["cell-a"])
            self.assertIn("lease-exhausted", str(ctx.exception))
            self.assertIn("holder-1", str(ctx.exception))
        finally:
            common.release_lease(lease, True, "test done")

    def test_lease_exhaustion_across_processes(self):
        # Hold the lease in a child process; the parent's acquire must refuse.
        script = (
            "import sys,time;"
            "sys.path.insert(0,sys.argv[1]);"
            "import kernel_common as k;"
            "lease=k.acquire_lease(sys.argv[2],'cell-x','child-holder','run-x',['cell-x']);"
            "print('HELD',flush=True);time.sleep(30)"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", script, str(h.ROOT / "tools/qualification"), str(self.leases)],
            stdout=subprocess.PIPE, text=True,
        )
        try:
            line = child.stdout.readline()
            child.stdout.close()
            self.assertEqual(line.strip(), "HELD")
            with self.assertRaises(common.KernelError) as ctx:
                common.acquire_lease(str(self.leases), "cell-x", "parent", "run-p", ["cell-x"])
            self.assertIn("lease-exhausted", str(ctx.exception))
        finally:
            child.kill()
            child.wait()

    def test_dirty_cell_reuse_refused(self):
        lease = common.acquire_lease(str(self.leases), "cell-a", "holder-1", "run-1", ["cell-a"])
        common.release_lease(lease, False, "workload failed")
        with self.assertRaises(common.KernelError) as ctx:
            common.acquire_lease(str(self.leases), "cell-a", "holder-2", "run-2", ["cell-a"])
        self.assertIn("dirty-cell", str(ctx.exception))
        state = json.loads((self.leases / "cell-a" / "state.json").read_text())
        self.assertEqual(state["state"], "dirty")
        self.assertIn("workload failed", json.dumps(state["history"]))

    def test_unleased_release_refused(self):
        lease = common.acquire_lease(str(self.leases), "cell-a", "holder-1", "run-1", ["cell-a"])
        common.release_lease(lease, True, "test done")
        # Releasing twice is an unleased access: nothing is held.
        with self.assertRaises(common.KernelError) as ctx:
            common.release_lease(lease, True, "second release")
        self.assertIn("unleased-access", str(ctx.exception))

    def test_foreign_holder_release_refused(self):
        lease = common.acquire_lease(str(self.leases), "cell-a", "holder-1", "run-1", ["cell-a"])
        try:
            forged = common.Lease(
                cell="cell-a", holder="holder-2", run_id="run-2",
                lease_dir=str(self.leases / "cell-a"), fd=lease.fd,
            )
            with self.assertRaises(common.KernelError) as ctx:
                common.release_lease(forged, True, "forged release")
            self.assertIn("unleased-access", str(ctx.exception))
        finally:
            common.release_lease(lease, True, "test done")

    def test_stale_lease_record_refused(self):
        cell_dir = self.leases / "cell-a"
        cell_dir.mkdir()
        (cell_dir / "lock").touch()
        # Lock is free but a lease record lingers: refuse, do not adopt.
        (cell_dir / "lease.json").write_text(json.dumps({"holder": "ghost", "run_id": "run-g"}))
        (cell_dir / "state.json").write_text(json.dumps({"state": "clean", "history": []}))
        with self.assertRaises(common.KernelError) as ctx:
            common.acquire_lease(str(self.leases), "cell-a", "holder-1", "run-1", ["cell-a"])
        self.assertIn("stale-lease-record", str(ctx.exception))

    def test_state_history_bounded(self):
        for index in range(40):
            lease = common.acquire_lease(
                str(self.leases), "cell-a", f"holder-{index}", f"run-{index}", ["cell-a"])
            common.release_lease(lease, True, f"cycle {index}")
        state = json.loads((self.leases / "cell-a" / "state.json").read_text())
        self.assertLessEqual(len(state["history"]), 32)

    def test_invalid_cell_name_refused(self):
        with self.assertRaises(common.KernelError):
            common.acquire_lease(str(self.leases), "../escape", "holder", "run", ["x"])
        with self.assertRaises(common.KernelError):
            common.acquire_lease(str(self.leases), "", "holder", "run", ["x"])

    def test_lease_status_probe(self):
        probe = common.lease_status(str(self.leases), "cell-new")
        self.assertFalse(probe["held"])
        self.assertEqual(probe["state"], "clean")
        lease = common.acquire_lease(str(self.leases), "cell-new", "holder-1", "run-1", ["cell-new"])
        try:
            probe = common.lease_status(str(self.leases), "cell-new")
            self.assertTrue(probe["held"])
            self.assertEqual(probe["holder"], "holder-1")
        finally:
            common.release_lease(lease, True, "test done")


if __name__ == "__main__":
    unittest.main()
