# SPDX-License-Identifier: Apache-2.0
"""Unit checks for tools/qualification/measure_resources.py (TT09).

TDD: authored alongside the sampler contract; sampler failures stay
failures, bounds assert N/N+1 per dimension, and timing comparison never
gates caps.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    'measure_resources', ROOT / 'tools/qualification/measure_resources.py')
m = importlib.util.module_from_spec(spec)
sys.modules['measure_resources'] = m
spec.loader.exec_module(m)

U64 = 2**64 - 1


def ok_sample(**over):
    base = {
        "status": "ok",
        "pid": 1,
        "epoch": 0,
        "resident_bytes": 100,
        "peak_resident_bytes": 100,
        "current_fds": 5,
        "workers": 1,
        "tasks_observed": 1,
        "mappings": 10,
        "io_syscalls": 7,
        "unobserved": ["peak_fds"],
    }
    base.update(over)
    return base


def bounds(**over):
    base = {"domain": "linux", "byte_cap": U64, "work_cap": U64,
            "memory_cap": U64, "time_ms_cap": U64}
    base.update(over)
    return base


class SampleTests(unittest.TestCase):
    def test_sample_self_ok(self):
        result = m.sample_process(os.getpid(), 3)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["epoch"], 3)
        self.assertGreater(result["resident_bytes"], 0)
        self.assertGreaterEqual(result["peak_resident_bytes"], result["resident_bytes"])
        self.assertGreaterEqual(result["current_fds"], 0)
        self.assertGreaterEqual(result["io_syscalls"], 0)
        self.assertIn("peak_fds", result["unobserved"])

    def test_sample_nonexistent_pid_typed_never_ok(self):
        # 2**22 exceeds any realistic pid_max; absence is deterministic.
        result = m.sample_process(2**22, 0)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "no_such_process")

    def test_sample_invalid_pid(self):
        for bad in (0, -1, "42", True):
            with self.subTest(pid=bad):
                result = m.sample_process(bad, 0)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["reason"], "invalid_pid")

    def test_fold_peaks_exact(self):
        folded = m.fold_peaks([ok_sample(resident_bytes=10, io_syscalls=3),
                               ok_sample(resident_bytes=30, io_syscalls=1)])
        self.assertEqual(folded["status"], "ok")
        self.assertEqual(folded["count"], 2)
        self.assertEqual(folded["peaks"]["resident_bytes"], 30)
        self.assertEqual(folded["peaks"]["io_syscalls"], 3)

    def test_fold_refuses_partial_peaks_naming_index(self):
        folded = m.fold_peaks([ok_sample(), {"status": "error", "reason": "denied"}])
        self.assertEqual(folded["status"], "error")
        self.assertEqual(folded["reason"], "unfoldable")
        self.assertIn("sample 1", folded["detail"])


class CheckTests(unittest.TestCase):
    def test_bytes_n_passes_nplus1_fails(self):
        self.assertEqual(m.check_bounds(ok_sample(resident_bytes=100), bounds(byte_cap=100), 0)["status"], "pass")
        failed = m.check_bounds(ok_sample(resident_bytes=101), bounds(byte_cap=100), 0)
        self.assertEqual(failed["status"], "fail")
        self.assertEqual(failed["violations"], [{"dimension": "bytes", "observed": 101, "cap": 100}])

    def test_work_n_passes_nplus1_fails(self):
        self.assertEqual(m.check_bounds(ok_sample(io_syscalls=7), bounds(work_cap=7), 0)["status"], "pass")
        failed = m.check_bounds(ok_sample(io_syscalls=8), bounds(work_cap=7), 0)
        self.assertEqual([v["dimension"] for v in failed["violations"]], ["work"])

    def test_memory_n_passes_nplus1_fails(self):
        self.assertEqual(m.check_bounds(ok_sample(peak_resident_bytes=64), bounds(memory_cap=64), 0)["status"], "pass")
        failed = m.check_bounds(ok_sample(peak_resident_bytes=65), bounds(memory_cap=64), 0)
        self.assertEqual([v["dimension"] for v in failed["violations"]], ["memory"])

    def test_time_n_passes_nplus1_fails_and_is_separate(self):
        self.assertEqual(m.check_bounds(ok_sample(), bounds(time_ms_cap=50), 50)["status"], "pass")
        failed = m.check_bounds(ok_sample(), bounds(time_ms_cap=50), 51)
        self.assertEqual(failed["status"], "fail")
        self.assertEqual([v["dimension"] for v in failed["violations"]], ["time"])

    def test_all_dimensions_listed_in_order(self):
        failed = m.check_bounds(
            ok_sample(resident_bytes=11, io_syscalls=11, peak_resident_bytes=11),
            bounds(byte_cap=10, work_cap=10, memory_cap=10, time_ms_cap=10), 11)
        self.assertEqual([v["dimension"] for v in failed["violations"]],
                         ["bytes", "work", "memory", "time"])

    def test_split_sum_overflow_overruns_even_max_cap(self):
        sample = ok_sample()
        del sample["resident_bytes"]
        sample["retained_bytes"] = U64
        sample["working_bytes"] = 1
        failed = m.check_bounds(sample, bounds(), 0)
        self.assertEqual(failed["status"], "fail")
        self.assertEqual(failed["violations"][0]["dimension"], "bytes")
        self.assertEqual(failed["violations"][0]["observed"], U64)

    def test_failed_sample_never_checks(self):
        result = m.check_bounds({"status": "error", "reason": "denied"}, bounds(), 0)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "invalid_input")

    def test_bad_bounds_rejected(self):
        for bad in (bounds(byte_cap=-1), bounds(work_cap=U64 + 1), {"domain": "x"}):
            with self.subTest(bounds=bad):
                result = m.check_bounds(ok_sample(), bad, 0)
                self.assertEqual(result["status"], "error")


class TimingTests(unittest.TestCase):
    def test_slower_observed_is_reported_never_failed(self):
        result = m.compare_timing({"timing_ns": [100, 100, 100]},
                                  {"timing_ns": [10000, 10000, 10000]})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["verdict"], "reported")
        self.assertFalse(result["gates_caps"])
        self.assertEqual(result["median_ratio_observed_over_baseline"], 100.0)

    def test_faster_observed_is_reported_never_passed(self):
        result = m.compare_timing({"timing_ns": [100, 200, 300]},
                                  {"timing_ns": [10, 10, 10]})
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["gates_caps"])
        self.assertEqual(result["baseline"]["median"], 200)
        self.assertEqual(result["observed"]["min"], 10)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/qualification/measure_resources.py"), *args],
            capture_output=True, text=True)

    def test_cli_sample_check_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample_path = os.path.join(tmp, "s.json")
            out_path = os.path.join(tmp, "c.json")
            bounds_path = os.path.join(tmp, "b.json")
            proc = self.run_cli("sample", "--pid", str(os.getpid()), "--epoch", "0", "--out", sample_path)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(bounds_path, "w") as handle:
                json.dump(bounds(), handle)
            proc = self.run_cli("check", "--sample", sample_path, "--bounds", bounds_path,
                                "--elapsed-ms", "0", "--out", out_path)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out_path) as handle:
                self.assertEqual(json.load(handle)["status"], "pass")

    def test_cli_check_fail_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample_path = os.path.join(tmp, "s.json")
            out_path = os.path.join(tmp, "c.json")
            bounds_path = os.path.join(tmp, "b.json")
            with open(sample_path, "w") as handle:
                json.dump(ok_sample(resident_bytes=5), handle)
            with open(bounds_path, "w") as handle:
                json.dump(bounds(byte_cap=4), handle)
            proc = self.run_cli("check", "--sample", sample_path, "--bounds", bounds_path,
                                "--elapsed-ms", "0", "--out", out_path)
            self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_cli_sample_dead_pid_exit_1_with_typed_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "s.json")
            proc = self.run_cli("sample", "--pid", str(2**22), "--epoch", "0", "--out", out_path)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            with open(out_path) as handle:
                self.assertEqual(json.load(handle)["reason"], "no_such_process")

    def test_cli_bad_manifest_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample_path = os.path.join(tmp, "s.json")
            out_path = os.path.join(tmp, "c.json")
            with open(sample_path, "w") as handle:
                json.dump(ok_sample(), handle)
            with open(os.path.join(tmp, "b.json"), "w") as handle:
                handle.write("{not json")
            proc = self.run_cli("check", "--sample", sample_path, "--bounds",
                                os.path.join(tmp, "b.json"), "--elapsed-ms", "0", "--out", out_path)
            self.assertEqual(proc.returncode, 2, proc.stderr)


if __name__ == "__main__":
    unittest.main()
