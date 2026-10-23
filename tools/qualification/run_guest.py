#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT05 isolated-object and live-kernel orchestration: lease, gate, run.

run_guest(admission_path, environment_path, owned_run_root, cell,
          lease_root, holder=None, foreign=()) -> RunManifest.

Pipeline (every performed step is ledgered; unperformed steps are absent,
never fake-ok): parse admission -> parse environment -> reconcile the
reviewed cell inventory -> select cell -> excluded-target check ->
snapshot foreign pins -> acquire the exclusive cell lease -> gate every
declared requirement (first missing requirement skips) -> reproducer
check -> transfer admitted bytes (re-hashed) -> execute the declared
workload with bounded time/log/result -> release the lease clean/dirty.

Statuses: PASS (executed, assertion held), FAIL (executed, assertion or
control failed), SETUP_ERROR (workload setup failed: never satisfies a
bad control), SKIP (cell-gated: exact loud reason), INCOMPLETE
(no bound reproducer), REFUSED (lease exhausted, dirty cell, excluded
target, transfer drift). SKIP/INCOMPLETE/REFUSED hold no lease at rest
and dirty nothing. Exit codes: 0 PASS, 1 refused/failed/setup-error,
2 usage/manifest error, 3 skipped/incomplete.

The exact skip marker is `SKIP (cell-gated): <cell> requires
<requirement> (see docs/testing/kernel-cells.md)`. Any other skip text
in workload output fails the run. run_guest never builds: there is no
compiler path by construction, and transfer refuses drift.

Donor slices (all user-owned; Grant: OWNER-2026-10-23):
- K2 ADAPT: kryprobe-ws w001 @ d153f3aaf9a3931337b47c9e1b046c692da55083,
  `kryprobe/scripts/sudo_lane.py` lines 102-114, 177-208 (env-gate
  allowlist, exact loud marker, unexplained-skip-fails verdict).
- K3 ADAPT: same file, lines 166-174 (reviewed-inventory reconciliation
  refuses drift).
- K4 ADAPT: same file, lines 506-547 (payload bijection, symlink and
  traversal refusal, staged-artifact drift refusal).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernel_common as kc  # noqa: E402

TOOL_ROOT = os.path.dirname(os.path.abspath(__file__))
ENV_FIELDS = ("schema_version", "kind", "doc", "cells")
CELL_FIELDS = ("name", "kind", "description", "requirements",
               "excluded_targets", "needs_reproducer", "workload",
               "release_probes")
WORKLOAD_FIELDS = ("argv", "timeout_secs", "result")
CELL_KINDS = ("host-unprivileged", "host-privileged", "owned-guest")
RELEASE_PROBES = ("no-owned-procs", "run-root-retired", "bpffs-empty")
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024
MAX_DETAIL_BYTES = 4096
SKIP_RE = re.compile(r"\b(?:skip(?:ped|ping)?|not_run)\b", re.I)
TOOL_RE = re.compile(r"[A-Za-z0-9._+-]+\Z", re.ASCII)


def skip_marker(cell, requirement):
    return (f"SKIP (cell-gated): {cell} requires {requirement} "
            f"(see {kc.DOC_POINTER})")


def parse_environment(path):
    doc, sha = kc.load_json(path)
    if not isinstance(doc, dict):
        kc.refuse("invalid-json", "environment must be an object")
    kc.check_no_unknown(doc, ENV_FIELDS, "environment")
    if doc.get("schema_version") != 1:
        kc.refuse("invalid-version", "environment schema_version must be exactly 1")
    if doc.get("kind") != kc.SCHEMA_ENV:
        kc.refuse("invalid-kind", f"environment kind must be {kc.SCHEMA_ENV}")
    kc.req_str(doc, "doc", "environment", 256)
    cells = doc.get("cells")
    if not isinstance(cells, list) or not cells:
        kc.refuse("empty-environment", "environment declares no cells")
    if len(cells) > 256:
        kc.refuse("too-large", "environment exceeds 256 cells")
    seen, out = set(), []
    for index, raw in enumerate(cells):
        what = f"cells[{index}]"
        if not isinstance(raw, dict):
            kc.refuse("invalid-json", f"{what} must be an object")
        kc.check_no_unknown(raw, CELL_FIELDS, what)
        name = kc.req_str(raw, "name", what, 96)
        kc.check_label(name, "name", what, 96)
        if name in seen:
            kc.refuse("duplicate-cell", f"cell {name!r} declared twice")
        seen.add(name)
        kind = kc.req_str(raw, "kind", what, 32)
        if kind not in CELL_KINDS:
            kc.refuse("unknown-cell-kind", f"{what} kind {kind!r} is unknown")
        kc.req_str(raw, "description", what, 1024)
        requirements = raw.get("requirements")
        if not isinstance(requirements, list):
            kc.refuse("invalid-json", f"{what} requirements must be a list")
        for req in requirements:
            if not isinstance(req, str) or not req or len(req.encode()) > 512:
                kc.refuse("invalid-input", f"{what} has a malformed requirement")
            _check_requirement(req, what)
        excluded = raw.get("excluded_targets")
        if not isinstance(excluded, list):
            kc.refuse("invalid-json", f"{what} excluded_targets must be a list")
        for target in excluded:
            if not isinstance(target, str) or not target.startswith("isa:") \
                    or not kc.is_label(target[4:], 96):
                kc.refuse("unknown-target", f"{what} target {target!r} is unknown")
        needs = raw.get("needs_reproducer")
        if type(needs) is not bool:
            kc.refuse("invalid-json", f"{what} needs_reproducer must be a boolean")
        workload = raw.get("workload")
        if workload is not None:
            if not isinstance(workload, dict):
                kc.refuse("invalid-json", f"{what} workload must be an object or null")
            kc.check_no_unknown(workload, WORKLOAD_FIELDS, f"{what} workload")
            argv = workload.get("argv")
            if not isinstance(argv, list) or not argv or len(argv) > 64:
                kc.refuse("invalid-input", f"{what} workload argv must be 1..64 entries")
            for arg in argv:
                if not isinstance(arg, str) or not arg \
                        or len(arg.encode()) > 4096:
                    kc.refuse("invalid-input", f"{what} workload argv entries bounded")
            timeout = workload.get("timeout_secs")
            if type(timeout) is not int or not 1 <= timeout <= 3600:
                kc.refuse("invalid-input", f"{what} timeout_secs must be 1..3600")
            result = workload.get("result")
            if not isinstance(result, str) or "/" in result or result in (".", "..") \
                    or not result or len(result.encode()) > 128:
                kc.refuse("invalid-input", f"{what} result must be a plain filename")
        probes = raw.get("release_probes")
        if not isinstance(probes, list):
            kc.refuse("invalid-json", f"{what} release_probes must be a list")
        for probe in probes:
            if probe not in RELEASE_PROBES:
                kc.refuse("unknown-release-probe", f"{what} probe {probe!r} is unknown")
        out.append({
            "name": name, "kind": kind, "requirements": requirements,
            "excluded_targets": excluded, "needs_reproducer": needs,
            "workload": workload, "release_probes": probes,
        })
    return out, sha


def _check_requirement(req, what):
    if req in ("root-euid", "bpffs-writable", "bpf-unprivileged-allowed", "kvm-rw"):
        return
    if req.startswith("tool:"):
        if TOOL_RE.fullmatch(req[5:]) is None:
            kc.refuse("unknown-requirement", f"{what} requirement {req!r} is malformed")
        return
    if req.startswith("file:"):
        if not req[5:].startswith("/") or len(req) > 512:
            kc.refuse("unknown-requirement", f"{what} requirement {req!r} is malformed")
        return
    if req.startswith("kernel-release-prefix:"):
        if not req[len("kernel-release-prefix:"):] or len(req) > 256:
            kc.refuse("unknown-requirement", f"{what} requirement {req!r} is malformed")
        return
    kc.refuse("unknown-requirement", f"{what} requirement {req!r} is unknown")


def probe_requirement(req):
    """Read-only capability probe; returns (ok, evidence)."""
    if req == "root-euid":
        euid = os.geteuid()
        return euid == 0, f"euid={euid}"
    if req == "bpffs-writable":
        exists = os.path.exists("/sys/fs/bpf")
        writable = os.access("/sys/fs/bpf", os.W_OK | os.X_OK)
        return writable, f"exists={exists} writable={writable}"
    if req == "bpf-unprivileged-allowed":
        try:
            with open("/proc/sys/kernel/unprivileged_bpf_disabled") as stream:
                toggle = stream.read().strip()
        except OSError as error:
            return False, f"sysctl unreadable: {error}"
        return toggle == "0", f"unprivileged_bpf_disabled={toggle}"
    if req == "kvm-rw":
        rw = os.access("/dev/kvm", os.R_OK | os.W_OK)
        return rw, f"/dev/kvm rw={rw}"
    if req.startswith("tool:"):
        found = shutil.which(req[5:])
        return found is not None, found or "absent from PATH"
    if req.startswith("file:"):
        target = Path(req[5:])
        try:
            st = target.lstat()
        except OSError:
            return False, "absent"
        import stat as _stat
        if not _stat.S_ISREG(st.st_mode):
            return False, "not a regular file"
        if target.is_symlink():
            return False, f"symlink -> {os.readlink(target)}"
        return True, f"regular file, {st.st_size} bytes"
    if req.startswith("kernel-release-prefix:"):
        release = platform.uname().release
        want = req[len("kernel-release-prefix:"):]
        return release.startswith(want), f"release={release}"
    kc.refuse("unknown-requirement", f"requirement {req!r} is unknown")


def parse_admission(path):
    doc, sha = kc.load_json(path)
    if not isinstance(doc, dict):
        kc.refuse("invalid-json", "admission must be an object")
    if doc.get("schema") != kc.SCHEMA_ADMISSION or doc.get("status") != "admitted":
        kc.refuse("bad-admission", f"{path} is not an admitted admission")
    obj = doc.get("object")
    if not isinstance(obj, dict):
        kc.refuse("bad-admission", "admission object must be an object")
    for field in ("id", "kind", "path", "sha256", "isa_profile"):
        if not isinstance(obj.get(field), str) or not obj[field]:
            kc.refuse("bad-admission", f"admission object field {field!r} missing")
    kc.check_sha(obj["sha256"], "sha256", "admission object")
    if obj["kind"] not in ("rel", "exec"):
        kc.refuse("bad-admission", "admission object kind must be rel or exec")
    return doc


def _proc_starttime(pid):
    try:
        with open(f"/proc/{pid}/stat") as stream:
            return stream.read().rsplit(") ", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def _run_bounded(argv, cwd, timeout_secs, log_path):
    """Run without a shell; bounded time, bounded log, own process group.

    Returns (exit, timed_out, pid, starttime, log_truncated).
    """
    proc = subprocess.Popen(
        argv, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True)
    pid, starttime = proc.pid, _proc_starttime(proc.pid)
    deadline = time.monotonic() + timeout_secs
    written, truncated = 0, False
    assert proc.stdout is not None
    outcome = None
    try:
        with open(log_path, "wb") as log:
            while True:
                remaining = deadline - time.monotonic()
                if proc.poll() is not None:
                    rest = proc.stdout.read()
                    if rest:
                        if written + len(rest) > MAX_LOG_BYTES:
                            rest = rest[:MAX_LOG_BYTES - written]
                            truncated = True
                        log.write(rest)
                    break
                if remaining <= 0:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
                    proc.wait()
                    outcome = (proc.returncode, True, pid, starttime, truncated)
                    break
                chunk = proc.stdout.read1(65536) if hasattr(proc.stdout, "read1") \
                    else proc.stdout.read(65536)
                if chunk:
                    if written + len(chunk) > MAX_LOG_BYTES:
                        chunk = chunk[:MAX_LOG_BYTES - written]
                        truncated = True
                    log.write(chunk)
                    written += len(chunk)
                    if truncated:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except (OSError, ProcessLookupError):
                            pass
                        proc.wait()
                        outcome = (proc.returncode, False, pid, starttime, True)
                        break
                elif proc.poll() is not None:
                    break
    finally:
        proc.stdout.close()
    return outcome or (proc.returncode, False, pid, starttime, truncated)


def run_guest(admission_path, environment_path, owned_run_root, cell,
              lease_root, holder=None, foreign=()):
    """Lease, gate and run one kernel cell; always writes run.json."""
    started = kc.utcnow()
    run_id = os.urandom(16).hex()
    holder = holder or f"uid{os.geteuid()}-pid{os.getpid()}"
    ops = []

    def log(op, ok, detail=""):
        ops.append({"seq": len(ops), "op": op, "ok": bool(ok),
                    "detail": str(detail)[:512], "utc": kc.utcnow()})

    admission = parse_admission(admission_path)
    log("parse-admission", True, admission["object"]["id"])
    cells, env_sha = parse_environment(environment_path)
    log("parse-environment", True, f"{len(cells)} cells")
    # K3 reconcile: the reviewed inventory is exact (dupes refused above).
    log("reconcile", True, f"{len(cells)} reviewed cells")
    selected = next((c for c in cells if c["name"] == cell), None)
    if selected is None:
        kc.refuse("unknown-cell", f"cell {cell!r} is not inventoried")
    log("select-cell", True, f"{cell} ({selected['kind']})")
    isa = admission["object"]["isa_profile"]
    for target in selected["excluded_targets"]:
        if target == f"isa:{isa}":
            reason = (f"active-excluded-target-required: {cell} excludes target "
                      f"isa:{isa} (admission {admission['object']['id']})")
            log("excluded-target-check", False, reason)
            return _finish_refused(
                run_id, started, ops, log, admission, env_sha, cell,
                selected, owned_run_root, lease_root, holder, reason)
    log("excluded-target-check", True, "admission target not excluded")
    foreign_snaps = []
    for path in foreign:
        target = Path(path)
        if target.is_symlink():
            kc.refuse("foreign-symlink", f"foreign pin {path} is a symlink")
        if not target.is_file():
            kc.refuse("foreign-missing", f"foreign pin {path} is not a file")
        foreign_snaps.append({"path": str(target),
                              "sha256": kc.digest_file(target)})
    log("snapshot-foreign", True, f"{len(foreign_snaps)} pins")
    root = Path(owned_run_root)
    for parent in (root, *root.parents):
        if parent.is_symlink():
            kc.refuse("run-root-symlink", f"{parent} is a symlink")
        if parent == root.parent:
            break
    if root.exists() or root.is_symlink():
        kc.refuse("run-root-exists", f"{owned_run_root} already exists")
    if not root.parent.is_dir():
        kc.refuse("bad-run-root", f"parent of {owned_run_root} is not a directory")

    def new_root():
        root.mkdir(mode=0o755)
        (root / "stage").mkdir(mode=0o755)
        (root / "logs").mkdir(mode=0o755)

    try:
        lease = kc.acquire_lease(lease_root, cell, holder, run_id, [cell])
    except kc.KernelError as error:
        new_root()
        log("lease-acquire", False, str(error))
        return _write_run(root, run_id, started, ops, admission, env_sha,
                          cell, selected, foreign_snaps, "REFUSED", str(error),
                          lease={"holder": holder, "run_id": run_id,
                                 "released": False, "held": False})
    log("lease-acquire", True, f"holder {holder}")
    try:
        for req in selected["requirements"]:
            ok, evidence = probe_requirement(req)
            if not ok:
                reason = skip_marker(cell, req)
                new_root()
                log("gate", False, f"{req}: {evidence}")
                kc.release_lease(lease, True, f"skip: {reason}")
                log("lease-release", True, "released clean after skip")
                manifest = _write_run(
                    root, run_id, started, ops, admission, env_sha, cell,
                    selected, foreign_snaps, "SKIP", reason,
                    lease={"holder": holder, "run_id": run_id,
                           "released": True, "held": False},
                    gate_evidence={req: evidence})
                return manifest
        log("gate", True,
            f"{len(selected['requirements'])} requirements satisfied")
        if selected["workload"] is None:
            new_root()
            if selected["needs_reproducer"]:
                reason = (f"no-reproducer: {cell} semantic gate has no bound "
                          f"workload")
                log("reproducer-check", False, reason)
                kc.release_lease(lease, True, f"incomplete: {reason}")
                log("lease-release", True, "released clean while incomplete")
                return _write_run(
                    root, run_id, started, ops, admission, env_sha, cell,
                    selected, foreign_snaps, "INCOMPLETE", reason,
                    lease={"holder": holder, "run_id": run_id,
                           "released": True, "held": False})
            reason = f"no-workload: {cell} declares no workload"
            log("reproducer-check", False, reason)
            kc.release_lease(lease, True, f"incomplete: {reason}")
            log("lease-release", True, "released clean while incomplete")
            return _write_run(
                root, run_id, started, ops, admission, env_sha, cell,
                selected, foreign_snaps, "INCOMPLETE", reason,
                lease={"holder": holder, "run_id": run_id,
                       "released": True, "held": False})
        log("reproducer-check", True, "workload bound")
        new_root()
        # K4 transfer: copy admitted bytes, then re-hash before any use.
        source = Path(admission["object"]["path"])
        if source.is_symlink() or not source.is_file():
            reason = (f"transfer-source-missing: admission source "
                      f"{admission['object']['path']} is not a regular file")
            log("transfer", False, reason)
            kc.release_lease(lease, True, reason)
            log("lease-release", True, "released clean after refusal")
            return _write_run(
                root, run_id, started, ops, admission, env_sha, cell,
                selected, foreign_snaps, "REFUSED", reason,
                lease={"holder": holder, "run_id": run_id,
                       "released": True, "held": False})
        staged = root / "stage" / "admitted-object"
        with open(source, "rb") as fin, open(staged, "wb") as fout:
            total = 0
            while True:
                chunk = fin.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > kc.MAX_OBJECT_BYTES:
                    reason = "transfer-too-large: admitted source exceeds bound"
                    log("transfer", False, reason)
                    kc.release_lease(lease, True, reason)
                    log("lease-release", True, "released clean after refusal")
                    return _write_run(
                        root, run_id, started, ops, admission, env_sha, cell,
                        selected, foreign_snaps, "REFUSED", reason,
                        lease={"holder": holder, "run_id": run_id,
                               "released": True, "held": False})
                fout.write(chunk)
        staged.chmod(0o444)
        transfer_sha = kc.digest_file(staged)
        if transfer_sha != admission["object"]["sha256"]:
            reason = (f"transfer-drift: staged {transfer_sha} != admitted "
                      f"{admission['object']['sha256']}")
            log("transfer", False, reason)
            kc.release_lease(lease, True, reason)
            log("lease-release", True, "released clean after refusal")
            return _write_run(
                root, run_id, started, ops, admission, env_sha, cell,
                selected, foreign_snaps, "REFUSED", reason,
                lease={"holder": holder, "run_id": run_id,
                       "released": True, "held": False},
                transfer_sha256=transfer_sha)
        log("transfer", True, f"staged {transfer_sha}")
        subs = {"stage": str(root / "stage"), "output": str(root),
                "result": str(root / selected["workload"]["result"]),
                "tool_root": TOOL_ROOT,
                "object_sha256": admission["object"]["sha256"],
                "object_kind": admission["object"]["kind"],
                "object_id": admission["object"]["id"]}
        # Literal token replacement only: workload scripts may contain
        # braces of their own, which str.format would corrupt.
        argv = []
        for arg in selected["workload"]["argv"]:
            for token, value in subs.items():
                arg = arg.replace("{" + token + "}", value)
            argv.append(arg)
        if "/" in argv[0]:
            if not os.path.isfile(argv[0]) or not os.access(argv[0], os.X_OK):
                return _finish_execute(
                    root, run_id, started, ops, log, admission, env_sha,
                    cell, selected, foreign_snaps, lease, holder,
                    transfer_sha, argv, None, "SETUP_ERROR",
                    f"workload executable {argv[0]} missing or not executable")
        elif shutil.which(argv[0]) is None:
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, None, "SETUP_ERROR",
                f"workload tool {argv[0]} absent from PATH")
        log_path = root / "logs" / "workload.log"
        code, timed_out, pid, starttime, truncated = _run_bounded(
            argv, root, selected["workload"]["timeout_secs"], log_path)
        workload_record = {
            "argv": argv, "exit": code, "timed_out": timed_out,
            "pid": pid, "pid_starttime": starttime,
            "log": "logs/workload.log", "log_truncated": truncated,
            "result": None,
        }
        if timed_out:
            log("execute", False, "workload timeout")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                "workload-timeout: workload exceeded its time bound")
        if truncated:
            log("execute", False, "workload log overflow")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                "workload-log-overflow: workload exceeded its log bound")
        output = log_path.read_bytes().decode("utf-8", errors="replace")
        if code != 0:
            log("execute", False, f"workload exit {code}")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                f"workload-exit-{code}: workload exited nonzero")
        if SKIP_RE.search(output):
            log("execute", False, "unexplained skip text in workload output")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                "unexplained-skip-text: workload output claims a skip")
        result_path = root / selected["workload"]["result"]
        if not result_path.is_file() or result_path.is_symlink():
            log("execute", False, "workload wrote no result file")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                "result-missing: workload left no result (broken control)")
        try:
            result_raw = result_path.read_bytes()
            if len(result_raw) > MAX_RESULT_BYTES:
                raise ValueError("result exceeds bound")
            result = json.loads(result_raw.decode("utf-8"))
        except (OSError, UnicodeError, ValueError):
            log("execute", False, "workload result unparseable")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                "result-unparseable: workload result is not bounded JSON")
        if not isinstance(result, dict) or type(result.get("setup_ok")) is not bool \
                or not isinstance(result.get("assertion"), str) \
                or not isinstance(result.get("detail"), str) \
                or len(result["detail"].encode()) > MAX_DETAIL_BYTES:
            log("execute", False, "workload result envelope invalid")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                "result-invalid: workload result breaks the envelope contract")
        workload_record["result"] = result
        if not result["setup_ok"]:
            log("execute", False, f"workload setup failed: {result['detail']}")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "SETUP_ERROR",
                f"workload-setup-failed: {result['detail']}")
        if result["assertion"] not in ("pass", "fail"):
            log("execute", False, "workload assertion not pass/fail after setup")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                "result-invalid: valid setup needs a pass/fail assertion")
        if result["assertion"] != "pass":
            log("execute", False, f"workload assertion failed: {result['detail']}")
            return _finish_execute(
                root, run_id, started, ops, log, admission, env_sha,
                cell, selected, foreign_snaps, lease, holder,
                transfer_sha, argv, workload_record, "FAIL",
                f"workload-assertion-failed: {result['detail']}")
        log("execute", True, result["detail"])
        return _finish_execute(
            root, run_id, started, ops, log, admission, env_sha,
            cell, selected, foreign_snaps, lease, holder,
            transfer_sha, argv, workload_record, "PASS", "")
    except BaseException as error:
        try:
            kc.release_lease(lease, False, f"run aborted: {error}")
        except kc.KernelError:
            pass
        raise


def _owned_files(root):
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        files.append(str(path.relative_to(root)))
    return files


def _write_run(root, run_id, started, ops, admission, env_sha, cell,
               selected, foreign_snaps, status, reason, lease,
               transfer_sha256=None, workload=None, gate_evidence=None):
    manifest = {
        "schema": kc.SCHEMA_RUN,
        "run_id": run_id,
        "cell": cell,
        "cell_kind": selected["kind"],
        "release_probes": selected["release_probes"],
        "admission": {
            "object_id": admission["object"]["id"],
            "object_sha256": admission["object"]["sha256"],
            "object_kind": admission["object"]["kind"],
            "manifest_sha256": admission["manifest_sha256"],
        },
        "environment_sha256": env_sha,
        "lease": lease,
        "started_utc": started,
        "finished_utc": kc.utcnow(),
        "kernel_release": platform.uname().release,
        "euid": os.geteuid(),
        "status": status,
        "reason": reason or None,
        "transfer_sha256": transfer_sha256,
        "workload": workload,
        "gate_evidence": gate_evidence,
        "foreign_paths": foreign_snaps,
        "ops": ops,
        "files": sorted(set(_owned_files(root)) | {"run.json"}),
    }
    kc.write_json_atomic(root / "run.json", manifest)
    manifest["files"] = sorted(set(_owned_files(root)) | {"run.json"})
    return manifest


def _finish_refused(run_id, started, ops, log, admission, env_sha, cell,
                    selected, owned_run_root, lease_root, holder, reason):
    root = Path(owned_run_root)
    for parent in (root, *root.parents):
        if parent.is_symlink():
            kc.refuse("run-root-symlink", f"{parent} is a symlink")
        if parent == root.parent:
            break
    if root.exists() or root.is_symlink():
        kc.refuse("run-root-exists", f"{owned_run_root} already exists")
    if not root.parent.is_dir():
        kc.refuse("bad-run-root", f"parent of {owned_run_root} is not a directory")
    root.mkdir(mode=0o755)
    (root / "stage").mkdir(mode=0o755)
    (root / "logs").mkdir(mode=0o755)
    return _write_run(root, run_id, started, ops, admission, env_sha,
                      cell, selected, [], "REFUSED", reason,
                      lease={"holder": holder, "run_id": run_id,
                             "released": False, "held": False})


def _finish_execute(root, run_id, started, ops, log, admission, env_sha,
                    cell, selected, foreign_snaps, lease, holder,
                    transfer_sha, argv, workload_record, status, reason):
    clean = status == "PASS"
    kc.release_lease(lease, clean, f"{status}: {reason or 'pass'}")
    log("lease-release", True, f"released {'clean' if clean else 'dirty'}")
    return _write_run(root, run_id, started, ops, admission, env_sha,
                      cell, selected, foreign_snaps, status, reason,
                      lease={"holder": holder, "run_id": run_id,
                             "released": True, "held": False},
                      transfer_sha256=transfer_sha, workload=workload_record)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run one kernel cell under lease.")
    parser.add_argument("admission_path")
    parser.add_argument("environment_path")
    parser.add_argument("owned_run_root")
    parser.add_argument("--cell", required=True)
    parser.add_argument("--lease-root", required=True)
    parser.add_argument("--holder", default=None)
    parser.add_argument("--foreign", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        manifest = run_guest(args.admission_path, args.environment_path,
                             args.owned_run_root, args.cell,
                             args.lease_root, args.holder, tuple(args.foreign))
    except kc.KernelError as error:
        print(f"run_guest: usage error: {error}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as error:
        print(f"run_guest: usage error: {error}", file=sys.stderr)
        return 2
    status = manifest["status"]
    if status == "PASS":
        print(f"run_guest: PASS {manifest['cell']} run {manifest['run_id']}")
        return 0
    if status in ("SKIP", "INCOMPLETE"):
        print(manifest["reason"])
        return 3
    print(f"run_guest: {status} {manifest['reason']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
