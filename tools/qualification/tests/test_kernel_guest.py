# SPDX-License-Identifier: Apache-2.0
"""TT05 guest-orchestration checks for tools/qualification/run_guest.py.

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

TOOL = h.ROOT / "tools/qualification/run_guest.py"
PROBE = h.ROOT / "tools/qualification/workloads/cell_probe.py"


def result_writer(result, setup_ok=True, assertion="pass", detail="stub", extra_stdout=""):
    return (
        "import json,sys\n"
        f"print({extra_stdout!r})\n"
        "json.dump({'setup_ok': %s, 'assertion': %r, 'detail': %r}, open(sys.argv[1], 'w'))\n"
        % (setup_ok, assertion, detail)
    )


class GuestTests(unittest.TestCase):
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
        self.obj_sha = hashlib.sha256(self.obj.read_bytes()).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def env(self, cells):
        path = self.root / "env.json"
        path.write_bytes(h.env_bytes(cells))
        return path

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(TOOL), *args], capture_output=True, text=True)

    def test_identity_cell_runs_here(self):
        # The unprivileged object-identity probe executes in this environment.
        argv = [sys.executable, str(PROBE), "identity",
               "--object", "{stage}/admitted-object",
               "--expect-sha256", "{object_sha256}",
               "--expect-kind", "{object_kind}",
               "--result", "{result}"]
        env = self.env([h.cell("probe-cell", workload=h.workload(argv))])
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(out),
            cell="probe-cell", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "PASS")
        self.assertEqual(manifest["transfer_sha256"], self.obj_sha)
        staged = out / "stage" / "admitted-object"
        self.assertEqual(hashlib.sha256(staged.read_bytes()).hexdigest(), self.obj_sha)
        self.assertTrue(any(op["op"] == "lease-acquire" and op["ok"] for op in manifest["ops"]))
        self.assertTrue(any(op["op"] == "execute" and op["ok"] for op in manifest["ops"]))
        # Lease released and cell clean after a passing run.
        probe = common.lease_status(str(self.leases), "probe-cell")
        self.assertFalse(probe["held"])
        self.assertEqual(probe["state"], "clean")

    def test_capability_cell_runs_here(self):
        argv = [sys.executable, str(PROBE), "capabilities", "--result", "{result}"]
        env = self.env([h.cell("caps-cell", workload=h.workload(argv))])
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(out),
            cell="caps-cell", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "PASS")
        result = manifest["workload"]["result"]
        self.assertTrue(result["setup_ok"])
        self.assertIn("kernel_release", result)

    def test_privileged_cell_skips_with_exact_reason(self):
        env = self.env([h.cell("priv-cell", kind="host-privileged",
                                requirements=["root-euid"])])
        out = self.root / "run-root"
        proc = self.run_cli(str(self.admission), str(env), str(out),
                            "--cell", "priv-cell", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        manifest = json.loads((out / "run.json").read_text())
        self.assertEqual(manifest["status"], "SKIP")
        self.assertEqual(
            manifest["reason"],
            "SKIP (cell-gated): priv-cell requires root-euid "
            "(see docs/testing/kernel-cells.md)",
        )
        self.assertIn("SKIP (cell-gated): priv-cell requires root-euid", proc.stdout)
        # A skip dirties nothing and holds no lease.
        probe = common.lease_status(str(self.leases), "priv-cell")
        self.assertFalse(probe["held"])
        self.assertEqual(probe["state"], "clean")

    def test_skip_names_first_missing_capability(self):
        missing_tool = "tt05-no-such-tool-xyz"
        env = self.env([h.cell("tool-cell", requirements=[f"tool:{missing_tool}"])])
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(out),
            cell="tool-cell", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "SKIP")
        self.assertIn(f"tool-cell requires tool:{missing_tool}", manifest["reason"])

    def test_present_requirements_do_not_gate(self):
        env = self.env([h.cell("tool-ok", requirements=["tool:sh"],
                                workload=h.workload(
                                    [sys.executable, "-c", result_writer("x"),
                                     "{result}"]))])
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(out),
            cell="tool-ok", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "PASS")

    def test_active_excluded_target_is_required(self):
        # bpfel-v4 admission is active on a cell excluding exactly it: refused,
        # never silently skipped or run.
        env = self.env([h.cell("guarded", kind="host-privileged",
                                requirements=["root-euid"],
                                excluded_targets=["isa:bpfel-v4"])])
        out = self.root / "run-root"
        proc = self.run_cli(str(self.admission), str(env), str(out),
                            "--cell", "guarded", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("active-excluded-target", proc.stderr)
        manifest = json.loads((out / "run.json").read_text())
        self.assertEqual(manifest["status"], "REFUSED")
        # The same admission runs on a cell without that exclusion.
        env2 = self.env([h.cell("open", workload=h.workload(
            [sys.executable, "-c", result_writer("x"), "{result}"]))])
        out2 = self.root / "run-root-2"
        manifest2 = guest.run_guest(
            str(self.admission), str(env2), str(out2),
            cell="open", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest2["status"], "PASS")

    def test_no_reproducer_is_incomplete(self):
        # A requirement-free semantic cell with no bound workload is
        # INCOMPLETE, never a vacuous pass.
        env = self.env([h.cell("semantic", kind="owned-guest",
                                needs_reproducer=True, workload=None)])
        out = self.root / "run-root"
        proc = self.run_cli(str(self.admission), str(env), str(out),
                            "--cell", "semantic", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        manifest = json.loads((out / "run.json").read_text())
        self.assertEqual(manifest["status"], "INCOMPLETE")
        self.assertIn("no-reproducer", manifest["reason"])

    def test_workload_without_reproducer_need_runs(self):
        env = self.env([h.cell("plain", workload=h.workload(
            [sys.executable, "-c", result_writer("x"), "{result}"]))])
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(out),
            cell="plain", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "PASS")

    def test_lease_exhaustion_refuses_run(self):
        held = common.acquire_lease(
            str(self.leases), "busy", "other-holder", "run-other", ["busy"])
        try:
            env = self.env([h.cell("busy", workload=h.workload(
                [sys.executable, "-c", result_writer("x"), "{result}"]))])
            out = self.root / "run-root"
            proc = self.run_cli(str(self.admission), str(env), str(out),
                                "--cell", "busy", "--lease-root", str(self.leases),
                                "--holder", "tt05-test")
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("lease-exhausted", proc.stderr)
            manifest = json.loads((out / "run.json").read_text())
            self.assertEqual(manifest["status"], "REFUSED")
        finally:
            common.release_lease(held, True, "test done")

    def test_dirty_cell_reuse_refused(self):
        # A failing workload marks the cell dirty; the next run refuses.
        script = result_writer("x", assertion="fail", detail="boom")
        env = self.env([h.cell("flaky", workload=h.workload(
            [sys.executable, "-c", script, "{result}"]))])
        first = self.root / "run-1"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(first),
            cell="flaky", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "FAIL")
        self.assertEqual(common.lease_status(str(self.leases), "flaky")["state"], "dirty")
        second = self.root / "run-2"
        proc = self.run_cli(str(self.admission), str(env), str(second),
                            "--cell", "flaky", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("dirty-cell", proc.stderr)

    def test_failing_workload_is_loud_fail(self):
        script = result_writer("x", assertion="fail", detail="semantic-broken")
        env = self.env([h.cell("failcell", workload=h.workload(
            [sys.executable, "-c", script, "{result}"]))])
        out = self.root / "run-root"
        proc = self.run_cli(str(self.admission), str(env), str(out),
                            "--cell", "failcell", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        manifest = json.loads((out / "run.json").read_text())
        self.assertEqual(manifest["status"], "FAIL")

    def test_missing_result_is_broken_control(self):
        env = self.env([h.cell("noresult", workload=h.workload(
            [sys.executable, "-c", "import sys", "{result}"]))])
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(out),
            cell="noresult", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "FAIL")
        self.assertIn("result", manifest["reason"])

    def test_setup_failure_is_not_a_pass(self):
        script = result_writer("x", setup_ok=False, assertion="error", detail="denied")
        env = self.env([h.cell("setupcell", workload=h.workload(
            [sys.executable, "-c", script, "{result}"]))])
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(out),
            cell="setupcell", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "SETUP_ERROR")

    def test_unexplained_skip_text_fails(self):
        script = result_writer("x", extra_stdout="SKIP: felt like it")
        env = self.env([h.cell("sketchy", workload=h.workload(
            [sys.executable, "-c", script, "{result}"]))])
        out = self.root / "run-root"
        manifest = guest.run_guest(
            str(self.admission), str(env), str(out),
            cell="sketchy", lease_root=str(self.leases), holder="tt05-test")
        self.assertEqual(manifest["status"], "FAIL")
        self.assertIn("skip", manifest["reason"])

    def test_transfer_drift_refused(self):
        # Bytes changed after admission never reach the workload: the staged
        # copy is re-hashed and the run refuses on drift.
        env = self.env([h.cell("plain", workload=h.workload(
            [sys.executable, "-c", result_writer("x"), "{result}"]))])
        blob = bytearray(self.obj.read_bytes())
        blob[80] ^= 0x01
        self.obj.write_bytes(bytes(blob))
        out = self.root / "run-root"
        proc = self.run_cli(str(self.admission), str(env), str(out),
                            "--cell", "plain", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("transfer-drift", proc.stderr)
        manifest = json.loads((out / "run.json").read_text())
        self.assertEqual(manifest["status"], "REFUSED")

    def test_unknown_cell_is_usage_error(self):
        env = self.env([h.cell("real")])
        out = self.root / "run-root"
        proc = self.run_cli(str(self.admission), str(env), str(out),
                            "--cell", "ghost", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(out.exists())

    def test_existing_run_root_refused(self):
        env = self.env([h.cell("plain", workload=h.workload(
            [sys.executable, "-c", result_writer("x"), "{result}"]))])
        out = self.root / "run-root"
        out.mkdir()
        with self.assertRaises(common.KernelError) as ctx:
            guest.run_guest(str(self.admission), str(env), str(out),
                            cell="plain", lease_root=str(self.leases), holder="tt05-test")
        self.assertIn("run-root-exists", str(ctx.exception))

    def test_unknown_requirement_is_invalid(self):
        env = self.env([h.cell("weird", requirements=["teleport"])])
        out = self.root / "run-root"
        proc = self.run_cli(str(self.admission), str(env), str(out),
                            "--cell", "weird", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown-requirement", proc.stderr)

    def test_shipped_environment_reconciles(self):
        env_path = h.ROOT / "profiles/environments/kernel-v1.json"
        cells, _ = guest.parse_environment(str(env_path))
        self.assertEqual(
            [c["name"] for c in cells],
            ["host-object-identity", "host-capability-probe", "host-bpf-load",
             "owned-guest-debian13", "host-license-gpl-activity",
             "host-license-nongpl-refusal", "host-license-helperfree-baseline"])

    def test_shipped_unprivileged_cells_pass_here(self):
        env_path = h.ROOT / "profiles/environments/kernel-v1.json"
        for index, cell in enumerate(("host-object-identity", "host-capability-probe")):
            out = self.root / f"shipped-{index}"
            manifest = guest.run_guest(
                str(self.admission), str(env_path), str(out),
                cell=cell, lease_root=str(self.leases), holder="tt05-test")
            self.assertEqual(manifest["status"], "PASS", cell)

    def test_shipped_gated_cells_never_pass_vacuously(self):
        # In this environment the gated cells skip; on a capable host they
        # go INCOMPLETE (no bound reproducer). Either way they never PASS
        # vacuously and the reason always names the cell.
        env_path = h.ROOT / "profiles/environments/kernel-v1.json"
        cells, _ = guest.parse_environment(str(env_path))
        gated = [c for c in cells if c["workload"] is None]
        self.assertEqual(len(gated), 5)
        for index, cell in enumerate(gated):
            missing = next((req for req in cell["requirements"]
                            if not guest.probe_requirement(req)[0]), None)
            out = self.root / f"shipped-gated-{index}"
            manifest = guest.run_guest(
                str(self.admission), str(env_path), str(out),
                cell=cell["name"], lease_root=str(self.leases), holder="tt05-test")
            self.assertIn(cell["name"], manifest["reason"])
            if missing is None:
                self.assertEqual(manifest["status"], "INCOMPLETE", cell["name"])
                self.assertIn("no-reproducer", manifest["reason"])
            else:
                self.assertEqual(manifest["status"], "SKIP", cell["name"])
                self.assertIn(missing, manifest["reason"])

    def test_duplicate_cell_names_invalid(self):
        env = self.env([h.cell("dup"), h.cell("dup")])
        out = self.root / "run-root"
        proc = self.run_cli(str(self.admission), str(env), str(out),
                            "--cell", "dup", "--lease-root", str(self.leases),
                            "--holder", "tt05-test")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("duplicate-cell", proc.stderr)


if __name__ == "__main__":
    unittest.main()
