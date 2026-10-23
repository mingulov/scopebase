#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT09 bounded resource instrumentation and same-environment comparison.

sample_process(pid, epoch) -> dict observes one Linux process through
/proc with bounded reads. Sampler failures stay failures (status "error"
with a typed reason); a failed observation is never a zero sample.

check_bounds(sample, bounds, elapsed_ms) -> dict asserts the four bound
dimensions separately (bytes/work/memory/time) with N-passes/N+1-fails
semantics and u64-overflow emulation matching scopebase-testkit's
resource.rs. A time overrun never implies a byte/work/memory verdict.

fold_peaks(samples) -> dict computes exact peaks across ok samples; one
failed sample fails the fold, naming its index, rather than skipping
silently.

compare_timing(baseline, observed) -> dict reports distribution summaries
and ratios. It never gates caps: the result always carries
{"gates_caps": False, "verdict": "reported"}.

CLI: sample | check | compare-time. Exit 0 wrote/passed, 1 executed but
failed (cap overrun, unobservable target, incomplete fold), 2 usage or
manifest/input error.

NEW (no donor slice): no donor project carries this qualification
instrumentation; per-domain baselines live in profiles/performance-v1.json.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

UINT64_MAX = 2**64 - 1
PROC_FILE_CAP = 1 << 20  # 1 MiB per /proc file read
FD_COUNT_CAP = 65536
TASK_COUNT_CAP = 65536
MAPS_LINE_CAP = 1 << 20
JSON_INPUT_CAP = 1 << 16  # 64 KiB manifests/samples

DIMENSIONS = ("bytes", "work", "memory", "time")


def _err(reason: str, detail: str) -> dict:
    return {"status": "error", "reason": reason, "detail": detail}


def _read_capped(path: str, cap: int = PROC_FILE_CAP) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise _Truncated(path)
    return data


class _Truncated(Exception):
    pass


def _count_dir(path: str, cap: int) -> int:
    count = 0
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.name in (".", ".."):
                continue
            count += 1
            if count > cap:
                raise _Truncated(path)
    return count


def sample_process(pid: int, epoch: int) -> dict:
    """Observe one process. Never synthesizes a sample on failure."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return _err("invalid_pid", f"pid must be a positive int, got {pid!r}")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        return _err("invalid_epoch", f"epoch must be a non-negative int, got {epoch!r}")
    base = f"/proc/{pid}"
    try:
        status_raw = _read_capped(os.path.join(base, "status")).decode("utf-8", "strict")
    except FileNotFoundError:
        return _err("no_such_process", f"{base}/status is absent: process gone or never existed")
    except PermissionError as exc:
        return _err("denied", f"{base}/status refused: {exc}")
    except OSError as exc:
        return _err("io", f"{base}/status unreadable: {exc}")
    except _Truncated:
        return _err("truncated", f"{base}/status exceeds {PROC_FILE_CAP} bytes")
    try:
        kv: dict[str, str] = {}
        for line in status_raw.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                kv[key.strip()] = value.strip()
        resident_kb = int(kv["VmRSS"].split()[0])
        peak_kb = int(kv["VmHWM"].split()[0])
        workers = int(kv["Threads"])
    except (KeyError, IndexError, ValueError) as exc:
        return _err("unparseable", f"{base}/status lacks VmRSS/VmHWM/Threads: {exc}")
    try:
        tasks = _count_dir(os.path.join(base, "task"), TASK_COUNT_CAP)
    except FileNotFoundError:
        return _err("no_such_process", f"{base}/task vanished mid-sample")
    except PermissionError as exc:
        return _err("denied", f"{base}/task refused: {exc}")
    except OSError as exc:
        return _err("io", f"{base}/task unreadable: {exc}")
    except _Truncated:
        return _err("truncated", f"{base}/task exceeds {TASK_COUNT_CAP} entries")
    try:
        fds = _count_dir(os.path.join(base, "fd"), FD_COUNT_CAP)
    except FileNotFoundError:
        return _err("no_such_process", f"{base}/fd vanished mid-sample")
    except PermissionError as exc:
        return _err("denied", f"{base}/fd refused: {exc}")
    except OSError as exc:
        return _err("io", f"{base}/fd unreadable: {exc}")
    except _Truncated:
        return _err("truncated", f"{base}/fd exceeds {FD_COUNT_CAP} entries")
    try:
        maps_raw = _read_capped(os.path.join(base, "maps"))
        maps_lines = maps_raw.count(b"\n")
        if maps_lines > MAPS_LINE_CAP:
            raise _Truncated(os.path.join(base, "maps"))
    except FileNotFoundError:
        return _err("no_such_process", f"{base}/maps vanished mid-sample")
    except PermissionError as exc:
        return _err("denied", f"{base}/maps refused: {exc}")
    except OSError as exc:
        return _err("io", f"{base}/maps unreadable: {exc}")
    except _Truncated:
        return _err("truncated", f"{base}/maps exceeds {MAPS_LINE_CAP} lines")
    try:
        io_raw = _read_capped(os.path.join(base, "io")).decode("utf-8", "strict")
        io_kv: dict[str, int] = {}
        for line in io_raw.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                io_kv[key.strip()] = int(value.strip())
        io_syscalls = io_kv["syscr"] + io_kv["syscw"]
    except FileNotFoundError:
        return _err("no_such_process", f"{base}/io vanished mid-sample")
    except PermissionError as exc:
        return _err("denied", f"{base}/io refused: {exc}")
    except (OSError, KeyError, ValueError) as exc:
        return _err("io", f"{base}/io unreadable: {exc}")
    except _Truncated:
        return _err("truncated", f"{base}/io exceeds {PROC_FILE_CAP} bytes")
    return {
        "status": "ok",
        "pid": pid,
        "epoch": epoch,
        "resident_bytes": resident_kb * 1024,
        "peak_resident_bytes": peak_kb * 1024,
        "current_fds": fds,
        "workers": workers,
        "tasks_observed": tasks,
        "mappings": maps_lines,
        "io_syscalls": io_syscalls,
        # /proc cannot supply these; callers must not treat them as zero.
        "unobserved": ["peak_fds", "peak_workers", "peak_mappings", "links", "attempts"],
    }


def fold_peaks(samples: list) -> dict:
    """Exact per-field maxima across ok samples. Any failed sample fails
    the fold with its index; nothing is skipped silently."""
    if not isinstance(samples, list) or not samples:
        return _err("invalid_input", "fold needs a non-empty sample list")
    peaks = {"resident_bytes": 0, "peak_resident_bytes": 0, "current_fds": 0,
             "workers": 0, "mappings": 0, "io_syscalls": 0}
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict) or sample.get("status") != "ok":
            reason = sample.get("reason", "not_ok") if isinstance(sample, dict) else "not_a_sample"
            return _err("unfoldable", f"sample {index} is not ok ({reason}); fold refuses partial peaks")
        for field in peaks:
            value = sample.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return _err("invalid_input", f"sample {index} field {field} is not a uint: {value!r}")
            peaks[field] = max(peaks[field], value)
    return {"status": "ok", "count": len(samples), "peaks": peaks}


def _u64(name: str, value) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > UINT64_MAX:
        raise ValueError(f"{name} must be a u64, got {value!r}")
    return value


def u64_add(a: int, b: int) -> tuple[int, bool]:
    """Checked u64 addition mirroring resource.rs. Returns (sum, overflowed);
    on overflow the sum is saturated to UINT64_MAX (itself an overrun)."""
    total = a + b
    if total > UINT64_MAX:
        return UINT64_MAX, True
    return total, False


def _dimension_inputs(sample: dict) -> dict:
    """Map an ok sample onto the four bound dimensions. Bytes accepts either
    a direct resident_bytes reading or an explicit retained/working split
    (checked u64 addition, overflow overruns)."""
    if sample.get("status") != "ok":
        raise ValueError(f"cannot check a failed sample ({sample.get('reason')})")
    if "retained_bytes" in sample or "working_bytes" in sample:
        retained = _u64("retained_bytes", sample.get("retained_bytes"))
        working = _u64("working_bytes", sample.get("working_bytes"))
        current, overflowed = u64_add(retained, working)
        byte_overflow = overflowed
    else:
        current = _u64("resident_bytes", sample.get("resident_bytes"))
        byte_overflow = False
    return {
        "bytes": (current, byte_overflow),
        "work": (_u64("io_syscalls", sample.get("io_syscalls")), False),
        "memory": (_u64("peak_resident_bytes", sample.get("peak_resident_bytes")), False),
    }


def check_bounds(sample: dict, bounds: dict, elapsed_ms: int) -> dict:
    """Assert each dimension separately. Returns pass/fail with the exact
    violated dimensions in bytes/work/memory/time order."""
    try:
        dims = _dimension_inputs(sample)
        caps = {
            "bytes": _u64("byte_cap", bounds.get("byte_cap")),
            "work": _u64("work_cap", bounds.get("work_cap")),
            "memory": _u64("memory_cap", bounds.get("memory_cap")),
            "time": _u64("time_ms_cap", bounds.get("time_ms_cap")),
        }
        elapsed = _u64("elapsed_ms", elapsed_ms)
    except (ValueError, AttributeError) as exc:
        return _err("invalid_input", str(exc))
    domain = bounds.get("domain", "?")
    violations = []
    for name in ("bytes", "work", "memory"):
        observed, overflowed = dims[name]
        if overflowed or observed > caps[name]:
            violations.append({"dimension": name, "observed": observed, "cap": caps[name]})
    if elapsed > caps["time"]:
        violations.append({"dimension": "time", "observed": elapsed, "cap": caps["time"]})
    if violations:
        return {"status": "fail", "domain": domain, "violations": violations}
    return {"status": "pass", "domain": domain, "violations": []}


def _dist(values: list) -> dict:
    ordered = sorted(values)
    total = sum(ordered)
    return {
        "count": len(ordered),
        "min": ordered[0],
        "median": ordered[len(ordered) // 2],
        "mean": total / len(ordered),
        "max": ordered[-1],
    }


def compare_timing(baseline: dict, observed: dict) -> dict:
    """Report-only timing comparison. Never gates caps: a slower observed
    run is reported, never failed, and a faster one is never passed."""
    try:
        base = _dist(_u64_list(baseline.get("timing_ns")))
        obs = _dist(_u64_list(observed.get("timing_ns")))
    except ValueError as exc:
        return _err("invalid_input", str(exc))
    ratio = obs["median"] / base["median"] if base["median"] else None
    return {
        "status": "ok",
        "verdict": "reported",
        "gates_caps": False,
        "baseline": base,
        "observed": obs,
        "median_ratio_observed_over_baseline": ratio,
        "note": "Timing informs scheduling/cost review only; cap verdicts come from check_bounds.",
    }


def _u64_list(values) -> list:
    if not isinstance(values, list) or not values:
        raise ValueError("timing_ns must be a non-empty list")
    out = []
    for value in values:
        out.append(_u64("timing_ns[]", value))
    return out


def _load_json_capped(path: str, what: str) -> dict:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ValueError(f"{what} {path} unreadable: {exc}") from exc
    if size > JSON_INPUT_CAP:
        raise ValueError(f"{what} {path} is {size} bytes, cap {JSON_INPUT_CAP}")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{what} {path} is not valid JSON: {exc}") from exc


def _write_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=1, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TT09 bounded resource measurement")
    sub = parser.add_subparsers(dest="command", required=True)
    p_sample = sub.add_parser("sample", help="sample one pid")
    p_sample.add_argument("--pid", type=int, required=True)
    p_sample.add_argument("--epoch", type=int, required=True)
    p_sample.add_argument("--out", required=True)
    p_check = sub.add_parser("check", help="assert bounds on a sample")
    p_check.add_argument("--sample", required=True)
    p_check.add_argument("--bounds", required=True)
    p_check.add_argument("--elapsed-ms", type=int, required=True)
    p_check.add_argument("--out", required=True)
    p_cmp = sub.add_parser("compare-time", help="report-only timing comparison")
    p_cmp.add_argument("--baseline", required=True)
    p_cmp.add_argument("--observed", required=True)
    p_cmp.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "sample":
            result = sample_process(args.pid, args.epoch)
            _write_json(args.out, result)
            return 0 if result["status"] == "ok" else 1
        if args.command == "check":
            sample = _load_json_capped(args.sample, "sample")
            bounds = _load_json_capped(args.bounds, "bounds")
            result = check_bounds(sample, bounds, args.elapsed_ms)
            _write_json(args.out, result)
            if result["status"] == "pass":
                return 0
            return 1 if result["status"] == "fail" else 2
        baseline = _load_json_capped(args.baseline, "baseline")
        observed = _load_json_capped(args.observed, "observed")
        result = compare_timing(baseline, observed)
        _write_json(args.out, result)
        return 0 if result["status"] == "ok" else 2
    except ValueError as exc:
        print(f"measure_resources: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
