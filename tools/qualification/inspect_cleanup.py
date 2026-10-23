#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT05 independent cleanup inspection: verify retirement, never assume it.

inspect_cleanup(run_manifest_path, lease_root=None, retire=False,
                accept_clean=None) -> CleanupReport.

Default is read-only. Checks, in verdict precedence:

- run root present with exactly the manifest's owned file set (any extra
  or missing owned file is RESIDUE; forensics deleted by hand report
  RUN_ROOT_MISSING/RUN_ROOT_TAMPERED, never clean)
- every declared foreign pin byte-identical (else FOREIGN_DISTURBED;
  foreign pins are never cleanup targets and never residue)
- recorded workload pids reaped (starttime-compared against recorded
  /proc starttimes, so pid reuse cannot forge a live process)
- with --lease-root: no live lease for the cell (else STILL_LEASED) and
  the cell state clean (else DIRTY_CELL)

--retire removes owned files except run.json (foreign pins, even inside
the root, are never touched), then verifies the declared release probes
that apply post-retirement. Declared but unprobeable probes fail
retirement closed (PROBE_INCOMPLETE): an unreadable bpffs is not an
empty bpffs. --accept-clean CELL flips a dirty cell to clean only after
re-verifying lease-free, residue-free and foreign-intact, with an audit
entry; it refuses while leased or while residue/foreign damage stands.

Verdicts: CLEAN, RETIRED_CLEAN, RETIRED_DIRTY (files retired, cell
state still dirty: run --accept-clean next), RESIDUE, RUN_ROOT_MISSING,
RUN_ROOT_TAMPERED, FOREIGN_DISTURBED, STILL_LEASED, DIRTY_CELL,
STILL_ALIVE, PROBE_INCOMPLETE.

Donor slices (all user-owned; Grant: OWNER-2026-10-23):
- K6 ADAPT: kryprobe-ws w001 @ d153f3aaf9a3931337b47c9e1b046c692da55083,
  `kryprobe/scripts/sudo_lane.py` lines 699-738 (cleanup verification:
  owned children reaped and owned mounts removed before any complete
  summary; cleanup errors fail the receipt).

Exit codes: 0 clean-family verdict, 1 problems found, 2 usage error.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernel_common as kc  # noqa: E402

RUN_FIELDS = ("schema", "run_id", "cell", "cell_kind", "release_probes",
              "admission", "environment_sha256", "lease", "started_utc",
              "finished_utc", "kernel_release", "euid", "status", "reason",
              "transfer_sha256", "workload", "gate_evidence",
              "foreign_paths", "ops", "files")


def parse_run_manifest(path):
    doc, _ = kc.load_json(path)
    if not isinstance(doc, dict):
        kc.refuse("invalid-json", "run manifest must be an object")
    kc.check_no_unknown(doc, RUN_FIELDS, "run manifest")
    if doc.get("schema") != kc.SCHEMA_RUN:
        kc.refuse("invalid-kind", f"run manifest schema must be {kc.SCHEMA_RUN}")
    if not isinstance(doc.get("files"), list) or "run.json" not in doc["files"]:
        kc.refuse("invalid-run", "run manifest files must list run.json")
    if not isinstance(doc.get("foreign_paths"), list):
        kc.refuse("invalid-run", "run manifest foreign_paths must be a list")
    cell = doc.get("cell")
    if not kc.is_label(cell, 96):
        kc.refuse("invalid-run", "run manifest cell is not an identifier")
    return doc


def _owned_files(root):
    files = set()
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        files.add(str(path.relative_to(root)))
    return files


def _pid_alive(pid, starttime):
    try:
        with open(f"/proc/{pid}/stat") as stream:
            current = stream.read().rsplit(") ", 1)[1].split()[19]
    except (OSError, IndexError):
        return False
    if starttime is None:
        return True
    return current == starttime


def inspect_cleanup(run_manifest_path, lease_root=None, retire=False,
                    accept_clean=None):
    manifest_path = Path(run_manifest_path)
    if manifest_path.is_symlink():
        kc.refuse("run-manifest-symlink", f"{run_manifest_path} is a symlink")
    if not manifest_path.is_file() or manifest_path.name != "run.json":
        kc.refuse("bad-run-manifest", f"{run_manifest_path} is not a run.json file")
    if accept_clean is not None and lease_root is None:
        kc.refuse("usage", "--accept-clean needs --lease-root")
    manifest = parse_run_manifest(manifest_path)
    root = manifest_path.parent
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:512]})

    if not root.is_dir() or root.is_symlink():
        check("run-root-present", False, f"{root} is gone or a symlink")
        return _report(manifest, "RUN_ROOT_MISSING", checks, retired=False)
    check("run-root-present", True, str(root))
    actual = _owned_files(root)
    expected = set(manifest["files"])
    # A valid retirement marker switches the expected shape: only the
    # receipt pair remains. Anything else is tamper, never clean.
    retired_shape = False
    marker_path = root / "retirement.json"
    if marker_path.exists() or marker_path.is_symlink():
        marker = _read_retirement(marker_path, manifest["run_id"])
        if marker is None:
            check("retirement-marker", False, "retirement.json invalid or foreign")
            return _report(manifest, "RUN_ROOT_TAMPERED", checks, retired=True)
        check("retirement-marker", True, f"retired {marker['retired_utc']}")
        retired_shape = True
        expected = {"run.json", "retirement.json"}
    missing = sorted(expected - actual - {"run.json"})
    # run.json itself is being read, so it is present by construction.
    extra = sorted(actual - expected)
    foreign_inside = {str(Path(p["path"]).relative_to(root))
                      for p in manifest["foreign_paths"]
                      if _within(root, p["path"])}
    extra = [path for path in extra if path not in foreign_inside]
    if missing:
        check("owned-set", False, f"missing owned files: {missing}")
    elif extra:
        check("owned-set", False, f"undeclared files: {extra}")
    else:
        check("owned-set", True, f"{len(expected)} owned files accounted")
    foreign_ok = True
    for pin in manifest["foreign_paths"]:
        target = Path(pin["path"])
        if target.is_symlink() or not target.is_file():
            check(f"foreign:{pin['path']}", False, "pin missing or symlink")
            foreign_ok = False
            continue
        actual_sha = kc.digest_file(target)
        if actual_sha != pin["sha256"]:
            check(f"foreign:{pin['path']}", False,
                  f"pin changed: {actual_sha} != {pin['sha256']}")
            foreign_ok = False
        else:
            check(f"foreign:{pin['path']}", True, "byte-identical")
    if not manifest["foreign_paths"]:
        check("foreign-pins", True, "none declared")
    workload = manifest.get("workload") or {}
    pid = workload.get("pid")
    if pid is None:
        check("no-owned-procs", True, "no workload pid recorded")
        procs_ok = True
    elif not isinstance(pid, int) or pid <= 0:
        check("no-owned-procs", False, f"recorded pid {pid!r} implausible")
        procs_ok = False
    elif _pid_alive(pid, workload.get("pid_starttime")):
        check("no-owned-procs", False, f"workload pid {pid} still alive")
        procs_ok = False
    else:
        check("no-owned-procs", True, f"workload pid {pid} reaped")
        procs_ok = True
    lease_held, lease_holder, cell_state = False, None, None
    if lease_root is not None:
        status = kc.lease_status(lease_root, manifest["cell"])
        lease_held, lease_holder = status["held"], status["holder"]
        cell_state = status["state"]
        check("lease-released", not lease_held,
              f"held by {lease_holder}" if lease_held else "lock free, no holder")
        check("cell-clean", cell_state == "clean", f"state={cell_state}")
    else:
        check("lease-released", True, "not checked: no lease root supplied")
        check("cell-clean", True, "not checked: no lease root supplied")

    residue = bool(missing) or bool(extra)
    if accept_clean is not None:
        return _accept_clean(manifest, manifest["cell"], lease_root, checks,
                             residue, foreign_ok, lease_held)
    if retire:
        return _retire(manifest, root, expected, foreign_inside, checks,
                       residue, foreign_ok, procs_ok, lease_root,
                       lease_held, cell_state, retired_shape)
    if missing or not manifest_path.is_file():
        return _report(manifest, "RUN_ROOT_TAMPERED", checks, retired=retired_shape)
    if not foreign_ok:
        return _report(manifest, "FOREIGN_DISTURBED", checks, retired=retired_shape)
    if not procs_ok:
        return _report(manifest, "STILL_ALIVE", checks, retired=retired_shape)
    if residue:
        return _report(manifest, "RESIDUE", checks, retired=retired_shape)
    if lease_held:
        return _report(manifest, "STILL_LEASED", checks, retired=retired_shape)
    if cell_state == "dirty":
        base = "RETIRED_DIRTY" if retired_shape else "DIRTY_CELL"
        return _report(manifest, base, checks, retired=retired_shape)
    base = "RETIRED_CLEAN" if retired_shape else "CLEAN"
    return _report(manifest, base, checks, retired=retired_shape)


def _within(root, path):
    try:
        Path(path).relative_to(root)
        return True
    except ValueError:
        return False


def _report(manifest, verdict, checks, retired, flipped=False):
    return {"schema": kc.SCHEMA_CLEANUP, "run_id": manifest["run_id"],
            "cell": manifest["cell"], "verdict": verdict, "checks": checks,
            "retired": retired, "flipped": flipped,
            "inspected_utc": kc.utcnow()}


def _read_retirement(marker_path, run_id):
    try:
        doc, _ = kc.load_json(marker_path)
    except (OSError, kc.KernelError):
        return None
    if not isinstance(doc, dict) or doc.get("schema") != "scopebase-kernel-retirement/v1":
        return None
    if doc.get("run_id") != run_id or not isinstance(doc.get("retired_utc"), str):
        return None
    if not isinstance(doc.get("retired_files"), list):
        return None
    return doc


def _retire(manifest, root, expected, foreign_inside, checks, residue,
            foreign_ok, procs_ok, lease_root, lease_held, cell_state,
            retired_shape):
    if residue:
        return _report(manifest, "RESIDUE", checks, retired=retired_shape)
    if not foreign_ok:
        return _report(manifest, "FOREIGN_DISTURBED", checks, retired=retired_shape)
    if not procs_ok:
        return _report(manifest, "STILL_ALIVE", checks, retired=retired_shape)
    if retired_shape:
        checks.append({"check": "run-root-retired", "ok": True,
                       "detail": "already retired: marker valid, shape holds"})
    else:
        # Remove owned files except run.json; foreign pins are never
        # targets, even when they sit inside the owned root.
        retired_files = []
        for relative in sorted(expected):
            if relative == "run.json":
                continue
            target = root / relative
            if str(Path(relative)) in foreign_inside:
                continue
            try:
                if target.is_symlink() or not target.is_file():
                    continue
                target.unlink()
                retired_files.append(relative)
            except OSError:
                continue
        # Remove now-empty owned directories (stage/logs); never the root.
        for child in sorted(root.iterdir()):
            if child.name == "run.json":
                continue
            child_path = str(child.relative_to(root))
            if child_path in foreign_inside:
                continue
            try:
                if child.is_dir() and not child.is_symlink():
                    import shutil as _shutil
                    remaining = [p for p in child.rglob("*")
                                 if str(p.relative_to(root)) not in foreign_inside
                                 and (p.is_symlink() or p.is_file())]
                    if not remaining:
                        _shutil.rmtree(child)
            except OSError:
                pass
        kc.write_json_atomic(root / "retirement.json", {
            "schema": "scopebase-kernel-retirement/v1",
            "run_id": manifest["run_id"],
            "retired_utc": kc.utcnow(),
            "retired_files": sorted(retired_files),
        })
        remaining = _owned_files(root) - foreign_inside
        if remaining != {"run.json", "retirement.json"}:
            checks.append({"check": "run-root-retired", "ok": False,
                           "detail": f"owned files linger: {sorted(remaining)}"})
            return _report(manifest, "RESIDUE", checks, retired=True)
    checks.append({"check": "run-root-retired", "ok": True,
                   "detail": "only run.json retained"})
    if "bpffs-empty" in manifest["release_probes"]:
        try:
            entries = os.listdir("/sys/fs/bpf")
        except OSError:
            checks.append({"check": "bpffs-empty", "ok": False,
                           "detail": "bpffs unreadable: cannot establish empty"})
            return _report(manifest, "PROBE_INCOMPLETE", checks, retired=True)
        if entries:
            checks.append({"check": "bpffs-empty", "ok": False,
                           "detail": f"bpffs holds: {entries[:8]}"})
            return _report(manifest, "RESIDUE", checks, retired=True)
        checks.append({"check": "bpffs-empty", "ok": True, "detail": "bpffs empty"})
    if lease_held:
        return _report(manifest, "STILL_LEASED", checks, retired=True)
    if cell_state == "dirty":
        return _report(manifest, "RETIRED_DIRTY", checks, retired=True)
    return _report(manifest, "RETIRED_CLEAN", checks, retired=True)


def _accept_clean(manifest, cell, lease_root, checks, residue,
                  foreign_ok, lease_held):
    if cell != manifest["cell"]:
        kc.refuse("cell-mismatch",
                   f"run cell {manifest['cell']} != accept target {cell}")
    if lease_held:
        kc.refuse("still-leased", f"cell {cell} is leased; cannot accept clean")
    if residue:
        kc.refuse("residue-present", f"cell {cell} run has residue; retire first")
    if not foreign_ok:
        kc.refuse("foreign-disturbed", "foreign pins disturbed; cannot accept clean")
    state = kc.read_cell_state(lease_root, cell)
    if state.get("state") != "dirty":
        checks.append({"check": "accept-clean", "ok": True,
                       "detail": "cell already clean: no flip"})
        return _report(manifest, "CLEAN", checks, retired=False, flipped=False)
    kc.write_cell_state(lease_root, cell, "clean",
                        {"utc": kc.utcnow(), "holder": "inspect_cleanup",
                         "run_id": manifest["run_id"], "state": "clean",
                         "note": "operator-accepted after independent inspection"})
    checks.append({"check": "accept-clean", "ok": True,
                   "detail": "dirty -> clean with audit entry"})
    return _report(manifest, "CLEAN", checks, retired=False, flipped=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect kernel-cell cleanup.")
    parser.add_argument("run_manifest_path")
    parser.add_argument("--lease-root", default=None)
    parser.add_argument("--retire", action="store_true")
    parser.add_argument("--accept-clean", default=None)
    args = parser.parse_args(argv)
    try:
        report = inspect_cleanup(args.run_manifest_path,
                                 lease_root=args.lease_root,
                                 retire=args.retire,
                                 accept_clean=args.accept_clean)
    except kc.KernelError as error:
        print(f"inspect_cleanup: usage error: {error}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as error:
        print(f"inspect_cleanup: usage error: {error}", file=sys.stderr)
        return 2
    print(f"inspect_cleanup: {report['verdict']} cell {report['cell']} "
          f"run {report['run_id']}")
    for entry in report["checks"]:
        if not entry["ok"]:
            print(f"  FAIL {entry['check']}: {entry['detail']}")
    return 0 if report["verdict"] in ("CLEAN", "RETIRED_CLEAN") else 1


if __name__ == "__main__":
    sys.exit(main())
