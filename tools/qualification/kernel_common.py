#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT05 shared kernel-cell prelude: strict JSON, hashing and cell leases.

Stdlib only. Every TT05 qualification tool imports this module; tools stay
single-purpose over one shared lease/parse implementation.

Donor slices (all user-owned; Grant: OWNER-2026-10-23):
- K1 PORT: kryprobe-ws w001 @ d153f3aaf9a3931337b47c9e1b046c692da55083,
  `kryprobe/scripts/sudo_lane.py` lines 121-126 (chunked sha256 digest).
- K5 ADAPT: same file, lines 577-599 (O_RDONLY/CREAT lock open plus
  flock LOCK_EX|LOCK_NB exclusive lane hold with a structured receipt).
- K7 ADAPT: kryprobe-ws w000 @ 934d685cd42335fc98f71948b68758f24b02a7f2,
  `leases/LEASE.json` (whole file) and `leases/kcrypto-m1-05-guest.json`
  (lease-1 record: exclusive holder, lock_file, resources, release probe).
Strictness mirrors in-repo TC03 strict_value/check_no_unknown plus
tools/qualification/check_catalog.py duplicate-field refusal.
"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path

TOOL_VERSION = "0.1.0"
SCHEMA_ADMISSION = "scopebase-kernel-admission/v1"
SCHEMA_RUN = "scopebase-kernel-run/v1"
SCHEMA_LEASE = "scopebase-kernel-lease/v1"
SCHEMA_CLEANUP = "scopebase-kernel-cleanup/v1"
SCHEMA_ENV = "scopebase_kernel_cells_v1"
DOC_POINTER = "docs/testing/kernel-cells.md"

MAX_DOC_BYTES = 1024 * 1024
MAX_OBJECT_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 100_000
STATE_HISTORY = 32

LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z", re.ASCII)
SHA_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class KernelError(ValueError):
    """Exact refusal: str(exc) is '<code>: <detail>'."""


def refuse(code, detail=""):
    raise KernelError(f"{code}: {detail}" if detail else code)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest_file(path, max_bytes=MAX_OBJECT_BYTES):
    """Chunked SHA-256 hex of a regular file (K1)."""
    sha = hashlib.sha256()
    total = 0
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > max_bytes:
                refuse("too-large", f"{path} exceeds {max_bytes} bytes")
            sha.update(chunk)
    return sha.hexdigest()


def _reject_dupes(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            refuse("duplicate-field", f"duplicate key {key!r}")
        out[key] = value
    return out


def _check_shape(node):
    stack = [(node, 0)]
    seen = 0
    while stack:
        value, depth = stack.pop()
        seen += 1
        if seen > MAX_NODES:
            refuse("too-large", "document exceeds node bound")
        if depth > MAX_DEPTH:
            refuse("too-large", "document exceeds depth bound")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)


def load_json(path, max_bytes=MAX_DOC_BYTES):
    """Strict JSON: UTF-8, duplicate-field refusal, size/depth bounds.

    Returns (document, sha256hex of raw bytes).
    """
    raw = Path(path).read_bytes()
    if len(raw) > max_bytes:
        refuse("too-large", f"{path} exceeds {max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        refuse("invalid-json", f"{path} is not strict UTF-8")
    try:
        doc = json.loads(text, object_pairs_hook=_reject_dupes)
    except KernelError:
        raise
    except (ValueError, RecursionError):
        refuse("invalid-json", f"{path} does not parse")
    _check_shape(doc)
    return doc, hashlib.sha256(raw).hexdigest()


def check_no_unknown(obj, allowed, what):
    unknown = set(obj) - set(allowed)
    if unknown:
        refuse("unknown-field", f"{what} has unknown fields: {sorted(unknown)}")


def req_str(obj, field, what, max_len=512, nonempty=True):
    value = obj.get(field)
    if not isinstance(value, str):
        refuse("invalid-json", f"{what} field {field!r} must be a string")
    if nonempty and not value:
        refuse("invalid-input", f"{what} field {field!r} must be nonempty")
    if len(value.encode("utf-8")) > max_len:
        refuse("invalid-input", f"{what} field {field!r} exceeds {max_len} bytes")
    return value


def req_int(obj, field, what, lo=None, hi=None):
    value = obj.get(field)
    if type(value) is not int:
        refuse("invalid-json", f"{what} field {field!r} must be an integer")
    if (lo is not None and value < lo) or (hi is not None and value > hi):
        refuse("invalid-input", f"{what} field {field!r} out of range")
    return value


def is_label(text, cap):
    return (
        isinstance(text, str)
        and 0 < len(text.encode("utf-8")) <= cap
        and LABEL_RE.fullmatch(text) is not None
    )


def check_label(text, field, what, cap):
    if not is_label(text, cap):
        refuse("invalid-id", f"{what} field {field!r} is not a bounded identifier")
    return text


def check_sha(text, field, what):
    if not isinstance(text, str) or SHA_RE.fullmatch(text) is None:
        refuse("invalid-sha256", f"{what} field {field!r} must be lowercase hex64")
    return text


def write_json_atomic(path, obj):
    """Write JSON via temp file plus atomic rename (parent must exist)."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def _cell_dir(lease_root, cell):
    check_label(cell, "cell", "lease", 96)
    root = Path(lease_root)
    if not root.is_dir() or root.is_symlink():
        refuse("bad-lease-root", f"{lease_root} is not a directory")
    cell_dir = root / cell
    if cell_dir.is_symlink():
        refuse("bad-lease-root", f"cell dir {cell} is a symlink")
    cell_dir.mkdir(exist_ok=True)
    return cell_dir


class Lease:
    """A held exclusive cell lease: open flock fd plus holder identity."""

    def __init__(self, cell, holder, run_id, lease_dir, fd):
        self.cell = cell
        self.holder = holder
        self.run_id = run_id
        self.lease_dir = lease_dir
        self.fd = fd
        self.released = False


def read_cell_state(lease_root, cell):
    cell_dir = _cell_dir(lease_root, cell)
    state_path = cell_dir / "state.json"
    if not state_path.exists():
        return {"state": "clean", "history": []}
    try:
        doc, _ = load_json(state_path)
    except KernelError:
        refuse("bad-cell-state", f"cell {cell} state.json does not parse strictly")
    if doc.get("state") not in ("clean", "dirty"):
        refuse("bad-cell-state", f"cell {cell} state is not clean/dirty")
    return doc


def write_cell_state(lease_root, cell, state, entry):
    cell_dir = _cell_dir(lease_root, cell)
    doc = read_cell_state(lease_root, cell)
    doc["state"] = state
    history = doc.get("history", [])
    history.append(entry)
    doc["history"] = history[-STATE_HISTORY:]
    doc["updated_utc"] = utcnow()
    write_json_atomic(cell_dir / "state.json", doc)


def acquire_lease(lease_root, cell, holder, run_id, resources):
    """Hold a cell exclusively (K5/K7): flock NB plus lease-1 record.

    Refusals: lease-exhausted (names the holder), dirty-cell,
    stale-lease-record (lock free but a record lingers: operator must
    inspect, never silently adopted).
    """
    if not holder or len(holder.encode()) > 256:
        refuse("invalid-input", "holder must be a nonempty bounded string")
    cell_dir = _cell_dir(lease_root, cell)
    lock_path = cell_dir / "lock"
    # K5: O_RDONLY avoids protected_regular denial on sticky dirs; create
    # only when the lock does not exist yet.
    try:
        fd = os.open(lock_path, os.O_RDONLY)
    except FileNotFoundError:
        fd = os.open(lock_path, os.O_RDONLY | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        held = "(unknown holder)"
        try:
            record, _ = load_json(cell_dir / "lease.json")
            held = str(record.get("holder", held))
        except (OSError, KernelError):
            pass
        refuse("lease-exhausted", f"cell {cell} held by {held}")
    lease = Lease(cell, holder, run_id, str(cell_dir), fd)
    try:
        state = read_cell_state(lease_root, cell)
        if state.get("state") == "dirty":
            refuse("dirty-cell", f"cell {cell} is dirty; inspect before reuse")
        if (cell_dir / "lease.json").exists():
            refuse("stale-lease-record",
                   f"cell {cell} lock free but lease.json lingers")
        record = {
            "schema": SCHEMA_LEASE,
            "cell": cell,
            "exclusive": True,
            "holder": holder,
            "run_id": run_id,
            "resources": list(resources),
            "lock_file": str(lock_path),
            "since_utc": utcnow(),
            "pid": os.getpid(),
        }
        try:
            with open(cell_dir / "lease.json", "x") as stream:
                stream.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
        except FileExistsError:
            refuse("stale-lease-record",
                   f"cell {cell} lock free but lease.json lingers")
    except BaseException:
        os.close(fd)
        lease.released = True
        raise
    return lease


def release_lease(lease, clean, note):
    """Release a held lease (holder-verified) and record clean/dirty.

    Anything but the recorded holder releasing a live record is
    unleased-access and is refused.
    """
    if lease.released:
        refuse("unleased-access", f"cell {lease.cell} lease already released")
    try:
        try:
            record, _ = load_json(Path(lease.lease_dir) / "lease.json")
        except OSError:
            refuse("unleased-access", f"cell {lease.cell} has no live lease record")
        if record.get("holder") != lease.holder or record.get("run_id") != lease.run_id:
            refuse("unleased-access",
                   f"cell {lease.cell} held by another holder")
        (Path(lease.lease_dir) / "lease.json").unlink()
        write_cell_state(
            str(Path(lease.lease_dir).parent), lease.cell,
            "clean" if clean else "dirty",
            {"utc": utcnow(), "holder": lease.holder, "run_id": lease.run_id,
             "state": "clean" if clean else "dirty", "note": note[:256]},
        )
    finally:
        lease.released = True
        try:
            os.close(lease.fd)
        except OSError:
            pass


def lease_status(lease_root, cell):
    """Non-acquiring probe: held/holder plus clean/dirty state."""
    cell_dir = _cell_dir(lease_root, cell)
    state = read_cell_state(lease_root, cell).get("state", "clean")
    lock_path = cell_dir / "lock"
    if not lock_path.exists():
        return {"held": False, "holder": None, "state": state}
    try:
        fd = os.open(lock_path, os.O_RDONLY)
    except FileNotFoundError:
        return {"held": False, "holder": None, "state": state}
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            holder = None
            try:
                record, _ = load_json(cell_dir / "lease.json")
                holder = record.get("holder")
            except (OSError, KernelError):
                pass
            return {"held": True, "holder": holder, "state": state}
        fcntl.flock(fd, fcntl.LOCK_UN)
        return {"held": False, "holder": None, "state": state}
    finally:
        os.close(fd)
