# SPDX-License-Identifier: Apache-2.0
"""TT04 real filesystem provisioner: plan|create|inspect|cleanup.

``retire-helper`` is privileged-internal (cleanup re-execs this file
under sudo for fd-bound removal); it is never invoked by hand.

Only operates on named owned disposable resources under an explicitly
supplied run-root. Privileged mounts/sleepers are created solely under
``create --privileged`` with working ``sudo -n``; the default create
provisions only unprivileged fixtures (plain files, best-effort btrfs
subvolumes/snapshots) and records every privileged cell skipped with
its exact missing grant. Exit codes: 0 ok, 1 verification/admission
failure, 2 usage/grant/foreign-path refusal.

Donor lineage: host capability reads (Yama scope, CapEff hex) ADAPT the
KryProbe host_rows read idiom (crates/kryprobe-privilege/src/probe/
host_rows.rs @d153f3aa lines 118-127 yama_scope, 130-152 cap_state:
unreadable/unparseable stays a recorded unknown, never a failure).
Mount/cleanup orchestration is NEW per the frozen TT04 FS01-FS10 table;
no donor implements a filesystem provisioner.
"""
import argparse
import ctypes
import datetime
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCHEMA_MANIFEST = "tt04-fs-manifest-v1"
SCHEMA_PLAN = "tt04-fs-plan-v1"
MAX_PATH = 4095
MAX_MOUNTS = 32
MAX_PROCS = 16
MAX_FILES = 128
MAX_FILE_BYTES = 1 << 20
ERR_TAIL = 500
# S24: sleeper readiness is a bounded poll, never an open readline.
READY_TIMEOUT = 30
READY_MAX_BYTES = 4096
# Small operational reads (reports, acks, ledger polls).
SMALL_CAP = 65536
# Chroot payload copy ceiling (busybox is ~1-2 MiB).
COPY_CAP = 16 << 20
# LOOP_CLR_FD ioctl number (linux/loop.h: 0x4C01, stable across
# arches). S17-round3: this was 0x4C81 — every CLR failed EINVAL
# and only mocked tests covered it; the live retire test pins
# the true constant against the kernel.
LOOP_CLR_FD = 0x4C01
# LOOP_CTL_GET_FREE (loop-control) and LOOP_CONFIGURE ioctl numbers
# (linux/loop.h), stable across arches. Used by the attach-loop
# create helper (S15); verified live against the kernel.
LOOP_CTL_GET_FREE = 0x4C82
LOOP_CONFIGURE = 0x4C0A
# MS_RELATIME mount flag (linux/mount.h: 1<<21); the mount-fs
# helper passes it explicitly like mount(8) defaults.
MS_RELATIME = 1 << 21
# Overlay extra mount options allowed through mount-fs (S15):
# plain key[=value] items; anything else is refused rather
# than passed to the kernel data string.
_OVERLAY_EXTRA_RE = re.compile(r"[A-Za-z0-9_=,.-]+")
# LOOP_GET_STATUS64 ioctl number (linux/loop.h), stable across
# arches, plus the loop_info64 size. Only lo_device/lo_inode (the
# first two u64) are read: the kernel-held backing identity.
LOOP_GET_STATUS64 = 0x4C05
LOOP_INFO64_SIZE = 232

ALLOWED_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")

CELLS = [
    {"name": "FS01", "needs_privilege": True,
     "requires": ["sudo -n true", "mkfs.ext4", "loop device"],
     "evidence": ["ext4 loop mount record", "hardlink/rename/delete observations"]},
    {"name": "FS02", "needs_privilege": False,
     "requires": ["btrfs(8)", "btrfs-backed run-root"],
     "evidence": ["subvolume/snapshot stat rows", "stat-vs-maps split readings"]},
    {"name": "FS03", "needs_privilege": False,
     "requires": ["btrfs(8)", "btrfs-backed run-root"],
     "evidence": ["snapshot-pinned colliding (maps-dev, ino) pair"]},
    {"name": "FS04", "needs_privilege": True,
     "requires": ["sudo -n true", "overlay in /proc/filesystems"],
     "evidence": ["xino=off mount record", "lower/upper/work layout"]},
    {"name": "FS05", "needs_privilege": True,
     "requires": ["sudo -n true", "overlay in /proc/filesystems"],
     "evidence": ["xino=on mount record", "aligned/split observations"]},
    {"name": "FS06", "needs_privilege": True,
     "requires": ["FS04 provisioned mounts", "unprivileged merged write"],
     "evidence": ["upper-layer copy-up artifact", "old-FD/new-path divergence"]},
    {"name": "FS07", "needs_privilege": True,
     "requires": ["sudo -n true", "metacopy-capable kernel"],
     "evidence": ["metacopy mount record or exercised mount refusal"]},
    {"name": "FS08", "needs_privilege": True,
     "requires": ["sudo -n true", "unshare(1)", "mount(8)"],
     "evidence": ["foreign-mount sleeper", "pidns sleeper NSpid", "churn ledger"]},
    {"name": "FS09", "needs_privilege": False,
     "requires": ["non-root caller for DAC denial", "/proc/1 for map_files denial"],
     "evidence": ["mode-000 refusal stage", "pid-1 map_files EPERM"]},
    {"name": "FS10", "needs_privilege": False,
     "requires": ["ptrace of own child (yama scope <= 1)"],
     "evidence": ["syscall ledger with planted transient mmap"]},
]


class AdmissionError(Exception):
    pass


class LoopIdUnavailable(AdmissionError):
    """LOOP_GET_STATUS64 unreadable: unknown, never detached.

    S18/S23: a subclass of AdmissionError, so existing handlers
    keep their refuse/retain behavior, while identity checks catch
    it specifically to fall back to the (sound-for-stable-states)
    sysfs pathname verification.
    """


class ProcAbsent(AdmissionError):
    """The process is provably gone (ESRCH/ENOENT)."""


class ProcUnknown(AdmissionError):
    """The process state is unobservable (denial/I/O/malformed).

    S21: unknowns are retained custody, never treated as absent.
    """


class ProcIdentityChanged(AdmissionError):
    """The pinned number is proven to be a different process. (S21-round5)

    Whoever was there before is gone-or-foreign: the OLD
    identity is no longer signalled, and its stale record may
    be dropped. Unlike a persistence/publication
    AdmissionError (which must propagate with custody
    retained), this outcome proves the drop is sound.
    """


class RootAuthorityError(AdmissionError):
    """The retained run-root authority was lost or replaced. (S15)"""


class RootReplacedError(RootAuthorityError):
    """The run-root pathname no longer names the held directory.

    Unlike other authority errors (missing fixture parents, failed
    writes), a replacement means effects may already have landed
    in a foreign directory: provisioners must abort the create,
    never degrade a single cell.
    """


def fail2(message):
    print(f"provision_fs: {message}", file=sys.stderr)
    return 2


def tail(text):
    text = (text or "")[-ERR_TAIL:]
    return text.strip().replace("\n", " | ")


def read_capped_from_fd(fd, cap):
    """Read all of an open fd, refusing past ``cap`` bytes. (S28)

    The read is one loop over the SAME descriptor the caller
    opened and fstat'ed, so a file that grows between stat and
    read is caught by the cap rather than silently admitted.
    """
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise AdmissionError(
                f"file exceeds {cap} byte admission cap")
        chunks.append(chunk)
    return b"".join(chunks)


def read_regular_capped(path, cap=MAX_FILE_BYTES):
    """Atomically open, type-check, and capped-read a file. (S28)

    One ``open`` (``O_NONBLOCK`` so a FIFO never blocks us), one
    ``fstat`` on that fd (non-regular types refuse before any
    read — ``/dev/zero`` included, regardless of size), one size
    pre-check, one capped read. Symlinks resolve at open, as
    before; the identity recorded is whatever the open reached.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        raise AdmissionError(f"file not openable: {path}: {exc}")
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise AdmissionError(f"file not statable: {path}: {exc}")
        if not stat.S_ISREG(st.st_mode):
            raise AdmissionError(
                f"not a regular file: {path}")
        if st.st_size > cap:
            raise AdmissionError(
                f"file exceeds {cap} byte admission cap: {path}")
        # O_NONBLOCK only matters for FIFOs/sockets, which the
        # regular check already refused; clear it for a plain read.
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
        except OSError as exc:
            raise AdmissionError(f"file not readable: {path}: {exc}")
        data = read_capped_from_fd(fd, cap)
    finally:
        os.close(fd)
    return data, st


def contained(path, root):
    try:
        p = os.path.normpath(path)
        r = os.path.normpath(root)
    except Exception:
        return False
    return p == r or p.startswith(r + os.sep)


def check_run_root(raw):
    """Admit only explicitly spelled paths under disposable roots.

    Lexical ``..`` is rejected even when it would normalize inside: the
    caller must pass an already-resolved path.
    """
    if not raw or len(raw) > MAX_PATH or "\x00" in raw:
        return None
    parts = Path(raw).parts
    if ".." in parts or not os.path.isabs(raw):
        return None
    norm = os.path.normpath(raw)
    if norm == "/":
        return None
    for root in ALLOWED_ROOTS:
        if contained(norm, root):
            return norm
    tmpdir = os.environ.get("TMPDIR", "")
    if tmpdir and os.path.isabs(tmpdir) and contained(norm, os.path.normpath(tmpdir)):
        return norm
    return None


def unescape_mountinfo(field):
    """Decode kernel mountinfo octal escapes (space \\040, tab \\011,
    newline \\012, backslash \\134). Unknown escapes refuse: a path
    the kernel spelled in a way we cannot decode must never be
    compared containment-style against the run-root. (R24)"""
    out = []
    i = 0
    while i < len(field):
        char = field[i]
        if char != "\\":
            out.append(char)
            i += 1
            continue
        esc = field[i + 1:i + 4]
        if esc == "040":
            out.append(" ")
        elif esc == "011":
            out.append("\t")
        elif esc == "012":
            out.append("\n")
        elif esc == "134":
            out.append("\\")
        else:
            raise AdmissionError(
                f"undecodable mountinfo escape: {field[:80]!r}")
        i += 4
    return "".join(out)


def parse_mountinfo_row(line):
    parts = line.split(" - ")
    if len(parts) != 2:
        raise AdmissionError(f"mountinfo row without separator: {line[:80]!r}")
    pre, post = parts[0].split(), parts[1].split()
    if len(pre) < 6 or len(post) != 3:
        raise AdmissionError(f"malformed mountinfo row: {line[:80]!r}")
    try:
        mnt_id = int(pre[0])
    except ValueError:
        raise AdmissionError(f"non-numeric mnt_id: {line[:80]!r}")
    # R24: decode BEFORE any containment comparison, or an escaped
    # foreign mount under a space-bearing run-root evades the guard.
    # S19: the mount root (pre[3]) is part of the row: for bind
    # mounts it names the bound subtree while `source` stays the
    # filesystem source.
    return {
        "mnt_id": mnt_id,
        "root": unescape_mountinfo(pre[3]),
        "target": unescape_mountinfo(pre[4]),
        "fstype": post[0],
        "source": unescape_mountinfo(post[1]),
        "super": post[2],
    }


def read_mount_table(path="/proc/self/mountinfo"):
    # S26: decode with surrogateescape (os.fsdecode), never
    # errors="replace": filenames may carry non-UTF-8 bytes, and a
    # foreign mount under such a run-root must compare byte-identical
    # against the surrogate-preserving run-root spelling. `replace`
    # decoding collapses distinct byte spellings to U+FFFD and the
    # containment guard misses the mount.
    #
    # S17-round5: under confinement all our mounts live in the
    # keeper ns — the host table would miss them, so route
    # through the ns dump. Explicit fixture paths always read
    # direct (unit tests stay hermetic).
    ns = _ns_active()
    if (ns is not None and path == "/proc/self/mountinfo"
            and not _inside_keeper_ns()):
        # S99-round6: inside processes read the table directly
        # (it IS the ns table); only outsiders dump through
        # nsenter, gated on the keeper anchor.
        if not _keeper_routing_verified():
            raise AdmissionError(
                "keeper ns changed or died; refusing routed "
                "table read (never a silent redirect or host "
                "fallback)")
        text = _dump_ns_mount_table(ns)
    else:
        try:
            with open(path, "rb") as handle:
                text = os.fsdecode(handle.read())
        except OSError as exc:
            raise AdmissionError(f"mount table unreadable: {exc}")
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            rows.append(parse_mountinfo_row(line))
    return rows


def find_mounts(table, target):
    """Every row mounted at `target`, in table order (lower mounts
    first). Callers must refuse ambiguity: with stacked mounts the
    first row is NOT the mount a pathname umount would remove."""
    return [row for row in table if row["target"] == target]


def admit_mount(record, table, run_root):
    target = record.get("target", "")
    if not target or len(target) > MAX_PATH or not contained(target, run_root):
        raise AdmissionError(f"foreign mount target: {target[:80]!r}")
    rows = find_mounts(table, target)
    if not rows:
        raise AdmissionError(f"mount not present: {target}")
    if len(rows) > 1:
        # R17: stacked mounts at one target. Validating the lower
        # row while cleanup unmounts the top one would retire a
        # foreign mount, so ambiguity refuses outright.
        raise AdmissionError(
            f"ambiguous stacked mount at {target}: "
            f"{len(rows)} rows, refusing")
    row = rows[0]
    if (record.get("mnt_id") is not None
            and row["mnt_id"] != record.get("mnt_id")):
        raise AdmissionError(
            f"mnt_id changed for {target}: live={row['mnt_id']} "
            f"manifest={record.get('mnt_id')}"
        )
    if row["fstype"] != record.get("fstype"):
        raise AdmissionError(f"fstype changed for {target}")
    if row["source"] != record.get("source"):
        raise AdmissionError(f"source changed for {target}")
    if ("root" in record and record["root"] is not None
            and row["root"] != record["root"]):
        raise AdmissionError(f"mount root changed for {target}")
    for want in record.get("expect_super", []):
        if want not in row["super"]:
            raise AdmissionError(
                f"mount {target} lost super option {want[:60]!r}")
    return row


def read_text_capped(path, cap=4096):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(cap)
    except OSError:
        return None


def poll_text_contains(path, needle, timeout, cap=SMALL_CAP):
    """Poll a small text file until it contains `needle` (S24/S28).

    Every sample is a capped regular-file read, so a swapped-in
    FIFO can neither block the poll nor feed unbounded bytes; a
    missing file reads as empty until the deadline. Returns the
    text on success, else raises AdmissionError.
    """
    import time as _time
    deadline = _time.time() + timeout
    while True:
        try:
            data, _ = read_regular_capped(path, cap)
            text = data.decode("utf-8", errors="replace")
        except AdmissionError as exc:
            message = str(exc)
            if "not openable" in message and not os.path.lexists(path):
                text = ""
            else:
                raise AdmissionError(
                    f"polled file {path} refused: {exc}")
        if needle in text:
            return text
        if _time.time() >= deadline:
            raise AdmissionError(
                f"polled file {path} never showed {needle[:40]!r}")
        _time.sleep(0.05)


def host_capabilities():
    """Read-only capability survey; unknowns stay recorded, never fatal."""
    caps = {
        "kernel_release": read_text_capped("/proc/sys/kernel/osrelease") or "unknown",
        "euid": os.geteuid(),
        "overlay": False,
        "btrfs": False,
        "yama_scope": "unknown",
        "capeff": "unknown",
        "sudo_n": False,
        "btrfs_version": "unknown",
        "unprivileged_userns_clone": "unknown",
    }
    caps["kernel_release"] = caps["kernel_release"].strip()
    filesystems = read_text_capped("/proc/filesystems", 65536) or ""
    caps["overlay"] = "overlay" in filesystems.split()
    caps["btrfs"] = "btrfs" in filesystems.split()
    yama = read_text_capped("/proc/sys/kernel/yama/ptrace_scope", 64)
    if yama is not None:
        try:
            caps["yama_scope"] = int(yama.strip())
        except ValueError:
            caps["yama_scope"] = f"unparseable:{yama.strip()[:16]}"
    status = read_text_capped("/proc/self/status", 65536)
    if status:
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                try:
                    bits = int(line.split(":", 1)[1].strip(), 16)
                except ValueError:
                    caps["capeff"] = "unparseable"
                else:
                    caps["capeff"] = f"{bits:#x}"
                break
    if shutil.which("sudo") is not None:
        try:
            proc = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=30,
            )
            caps["sudo_n"] = proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            caps["sudo_n"] = False
    if shutil.which("btrfs") is not None:
        try:
            proc = subprocess.run(
                ["btrfs", "--version"], capture_output=True,
                text=True, timeout=30,
            )
            caps["btrfs_version"] = (proc.stdout or proc.stderr or "").strip()[:80]
        except (OSError, subprocess.TimeoutExpired):
            pass
    clone = read_text_capped("/proc/sys/kernel/unprivileged_userns_clone", 64)
    if clone is not None:
        caps["unprivileged_userns_clone"] = clone.strip()[:16]
    return caps


def proc_identity(pid):
    """Owned-process identity: starttime (last-paren field 22), exe, NSpid.

    stat/status are world-readable; the exe link of a root-spawned
    sleeper is EACCES to the observer and stays a recorded unknown.

    S21: absence and observation failure are distinct. Proven
    absence raises ProcAbsent; denial, I/O failure, or malformed
    content raises ProcUnknown. Callers must never treat an
    unknown as a gone process.
    """
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8",
                  errors="replace") as handle:
            stat = handle.read(4096)
        with open(f"/proc/{pid}/status", "r", encoding="utf-8",
                  errors="replace") as handle:
            status = handle.read(65536)
    except FileNotFoundError:
        raise ProcAbsent(f"proc {pid} absent")
    except OSError as exc:
        raise ProcUnknown(f"proc {pid} unreadable: {exc}")
    if not stat or not status:
        raise ProcUnknown(f"proc {pid} has empty stat/status")
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = None
    try:
        after = stat.rsplit(")", 1)[1].split()
        starttime = int(after[19])
    except (IndexError, ValueError):
        raise ProcUnknown(f"proc {pid} stat unparseable")
    nspid = None
    for line in status.splitlines():
        if line.startswith("NSpid:"):
            nspid = line.split(":", 1)[1].split()
            break
    if nspid is None:
        raise ProcUnknown(f"proc {pid} lacks NSpid")
    return {"pid": pid, "starttime": starttime, "exe": exe, "nspid": nspid}


def plan_command(args):
    run_root = check_run_root(args.run_root)
    if run_root is None:
        return fail2(f"foreign run-root: {args.run_root[:80]!r}")
    host = host_capabilities()
    cells = []
    for cell in CELLS:
        if cell["needs_privilege"]:
            if host["sudo_n"]:
                disp = "runnable"
            else:
                disp = "needs-privilege"
        else:
            disp = "runnable"
        cells.append({
            "name": cell["name"],
            "disposition": disp,
            "requires": cell["requires"],
            "evidence": cell["evidence"],
        })
    plan = {"schema": SCHEMA_PLAN, "run_root": run_root,
            "host": host, "cells": cells}
    Path(args.manifest).write_text(json.dumps(plan, indent=2) + "\n")
    print(f"planned {len(cells)} cells for {run_root}")
    return 0


# S17-round5: helpers confined to the keeper mount namespace.
# While _MOUNT_NS is unensured these refuse loudly (never a
# silent host-ns mount); loop helpers are global and stay
# ungated (nsenter is harmless for them once ensured).
_MOUNT_NS_COMMANDS = frozenset(
    {"mount-fs", "retire-mount", "retire-helper"})


def run_sudo(argv, timeout=120):
    # S15: while a create holds the run-root authority, every
    # privileged effect is bracketed by re-verification of the held
    # root, so a swapped root fails the create loudly instead of
    # collecting effects into a replacement.
    guard = _ROOT_GUARD
    if guard is not None:
        guard.verify()
    ns = _ns_active()
    if _MOUNT_NS is None and _MOUNT_NS_COMMANDS.intersection(argv):
        return (127, "",
                "mount ns not ensured; refusing mount helper")
    if ns is not None and _inside_keeper_ns():
        # S99-round6: already inside — plain sudo inherits our
        # namespace (no redirect possible, so no routing gate
        # either: membership is the authority, and the
        # keeper's later death cannot move us elsewhere).
        full = ["sudo", "-n", *argv]
    else:
        if ns is not None and not _keeper_routing_verified():
            return (127, "",
                    "keeper ns changed or died; refusing routed "
                    "sudo (never a silent redirect)")
        full = (["sudo", "-n", "nsenter", f"--mount={ns}", *argv]
                if ns is not None else ["sudo", "-n", *argv])
    try:
        proc = subprocess.run(
            full, capture_output=True,
            text=True, timeout=timeout,
        )
    except OSError as exc:
        return (127, "", f"sudo exec failed: {exc}")
    except subprocess.TimeoutExpired:
        # R21: TimeoutExpired is NOT an OSError; without this arm a
        # hung privileged call bypasses every OSError handler and
        # orphans custody (e.g. an attached loop before its mount).
        return (124, "",
                f"sudo timed out after {timeout}s: "
                f"{' '.join(argv)[:120]}")
    finally:
        if guard is not None:
            guard.verify()
    return (proc.returncode, proc.stdout or "", proc.stderr or "")


# F09: incremental recovery persistence. create_command sets _PERSIST to
# the manifest path once the exclusive recovery record exists; every
# acquisition record below then persists immediately, so a later
# failure (or crash between steps) keeps custody of what is live.
# Single-threaded CLI: no locking needed.
_PERSIST = None


# S15: retained run-root authority. create_command opens the freshly
# created root once (O_DIRECTORY|O_NOFOLLOW) and every fixture
# creation below goes through that descriptor; privileged calls are
# bracketed by re-verification (see run_sudo). Swapping the root
# pathname mid-create can neither redirect descriptor-bound writes
# (they land in the held directory) nor pass silently (the pathname
# no longer matches the held identity).
_ROOT_GUARD = None


# S17-round5: mount-namespace confinement. All privileged mount
# effects and every mount observation run inside a dedicated
# keeper mount namespace (rprivate), entered via nsenter: the
# kernel rejects MS_MOVE under shared ancestors (verified live:
# EINVAL), so only a private chain allows the reversible move
# that move-verify-detach needs; and confinement blinds every
# host actor without nsenter from our table entirely. Our own
# helpers stay serialized by the exclock inside it.
#
# `_MOUNT_NS` is None in unensured mode (unit tests, helpers
# already inside, non-mount flows), "direct" for explicit
# legacy host-table mode (pre-ns manifests only), and the
# keeper ns path (/proc/<pid>/ns/mnt) once ensured. Only real
# entry points ensure (CLI create/cleanup/inspect via main,
# live setUp); unit tests never set it and stay direct.
# run_sudo refuses mount-confined helpers while unensured
# (loud, never a silent host-ns mount).
#
# S100-round6: the path is never trusted alone — every
# ensured `_MOUNT_NS` carries `_MOUNT_NS_IDENTITY`
# (pid, nsid, starttime, canary), verified at bind time and
# re-verified on every ensure call (link + canary mount) and
# cheaply before every ns-routed operation (unprivileged
# /proc/PID/stat starttime: a recycled pid never shares the
# recorded starttime, so observations and effects cannot be
# redirected into another namespace silently). A path without
# identity is unbound and refused.
_MOUNT_NS = None
_MOUNT_NS_IDENTITY = None

# Keeper children we spawned and intentionally orphan (they own
# the persistent namespaces). Retained so GC never reaps the
# Popen handles mid-run; the keepers outlive us by design.
_KEEPERS = []


def _keeper_paths():
    euid = os.geteuid()
    return (f"/tmp/scopebase-mntns-{euid}.pid",
            f"/tmp/scopebase-mnscanary-{euid}")


def _parse_keeper_state(raw):
    """Parse pidfile bytes; None when absent or malformed."""
    try:
        text = raw.decode("ascii").strip()
    except UnicodeError:
        return None
    parts = text.split()
    if len(parts) != 3:
        return None
    pid_s, nsid_s, canary = parts
    if (not pid_s.isdigit() or not nsid_s.isdigit()
            or len(canary) != 32
            or any(c not in "0123456789abcdef" for c in canary)):
        return None
    pid, nsid = int(pid_s), int(nsid_s)
    if pid <= 1 or nsid <= 0:
        return None
    return (pid, nsid, canary)


def _read_ns_link(pid):
    """Host-side readlink of a keeper candidate's mount ns.

    Raw subprocess (foundation primitive, like
    _ns_has_canary): the keeper runs as root, so an
    unprivileged os.readlink of /proc/<pid>/ns/mnt always
    fails with EACCES — the link must be read elevated.
    Returns the link target (e.g. "mnt:[4026534942]") or
    None when unreadable (dead pid, no sudo); never raises.
    """
    try:
        proc = subprocess.run(
            ["sudo", "-n", "readlink", f"/proc/{pid}/ns/mnt"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _ns_has_canary(nspath, canary):
    """True when the joined ns shows our canary mount. (S17-round5)

    Raw subprocess (foundation primitive — must not depend on
    _MOUNT_NS state or run_sudo). Raises AdmissionError when
    the check itself cannot run; a missing canary is False
    (stale/wrong ns → respawn), never an error.
    """
    try:
        proc = subprocess.run(
            ["sudo", "-n", "nsenter", f"--mount={nspath}",
             "grep", "-q", f"canary-{canary}",
             "/proc/self/mountinfo"],
            capture_output=True, timeout=30)
    except OSError as exc:
        raise AdmissionError(f"mount-ns canary check failed: {exc}")
    except subprocess.TimeoutExpired:
        raise AdmissionError("mount-ns canary check timed out")
    return proc.returncode == 0


def _keeper_starttime(pid):
    """Unprivileged /proc/PID/stat starttime, or None. (S100)

    Field 22 (start_time, jiffies since boot): world-readable,
    no subprocess. Two lives of one pid never share it (pid
    wrap spans millions of forks across many jiffies), so it
    anchors the cached keeper against PID reuse between the
    expensive (link + canary) verifications. None when the
    pid is gone or unreadable — unknown, never verified.
    """
    try:
        with open(f"/proc/{int(pid)}/stat", "r") as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
    except (OSError, ValueError, IndexError, TypeError):
        return None
    if len(fields) < 20:
        return None
    try:
        return int(fields[19])
    except ValueError:
        return None


def _keeper_routing_verified():
    """True when ns-routed ops may use the cached keeper. (S100)

    The cached identity's pid must still show the recorded
    starttime — a dead/recycled keeper fails here (loud
    AdmissionError at the operation), never redirects into
    another namespace. Unensured/direct modes have no routing
    to verify (callers check _ns_active() first); a cached
    path without identity is unbound and fails.
    """
    if _MOUNT_NS is None or _MOUNT_NS == "direct":
        return False
    if _MOUNT_NS_IDENTITY is None:
        return False
    pid, _nsid, starttime, _canary = _MOUNT_NS_IDENTITY
    if starttime is None:
        return False
    return _keeper_starttime(pid) == starttime


def _verify_recorded_keeper(state):
    """nspath for a live recorded keeper, else None. (S100)

    Shared by ensure (spawn fallback) and bind (no-spawn):
    the pid must be alive in the recorded namespace (elevated
    link read) AND the namespace must show our canary mount
    (pid/nsid reuse alone cannot pass). Never raises for a
    dead/wrong keeper (returns None); the canary check's own
    execution failure propagates as AdmissionError.
    """
    pid, nsid, canary = state
    nspath = f"/proc/{pid}/ns/mnt"
    live = _read_ns_link(pid)
    if live != f"mnt:[{nsid}]":
        return None
    if not _ns_has_canary(nspath, canary):
        return None
    return nspath


def _publish_keeper_state(pidfile, candir, pid, nsid, canary):
    """Atomically publish the keeper record. (S103-round6)

    Write-temp-in-candir (0700, euid-private: no sticky-/tmp
    games) + rename over the pidfile + fsyncs. The write loop
    checks completeness (a short write is a failure, never a
    torn record); rename replaces anything — including an
    attacker symlink — with our regular file (O_EXCL tmp, no
    following). Raises AdmissionError (caller rolls the keeper
    back); never leaves a torn pidfile behind.
    """
    blob = f"{pid} {nsid} {canary}\n".encode("ascii")
    tmp = os.path.join(candir, f"keeper.{os.getpid()}.tmp")
    for _attempt in range(2):
        try:
            fd = os.open(tmp,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            break
        except FileExistsError:
            # Stale tmp from a crashed same-pid predecessor
            # (private dir: safe to clean and retry once).
            try:
                st = os.lstat(tmp)
            except OSError:
                continue
            if st.st_uid != os.geteuid():
                raise AdmissionError(
                    "mount-ns publish tmp alien; refusing")
            try:
                os.unlink(tmp)
            except OSError as exc:
                raise AdmissionError(
                    f"mount-ns publish tmp stuck: {exc}")
            continue
        except OSError as exc:
            raise AdmissionError(
                f"mount-ns pidfile unwritable: {exc}")
    else:
        raise AdmissionError(
            "mount-ns publish tmp stuck; refusing")
    try:
        try:
            view = memoryview(blob)
            while view:
                try:
                    done = os.write(fd, view)
                except OSError as exc:
                    raise AdmissionError(
                        f"mount-ns pidfile unwritable: {exc}")
                if done <= 0:
                    raise AdmissionError(
                        "mount-ns pidfile short write; refusing")
                view = view[done:]
            try:
                os.fsync(fd)
            except OSError as exc:
                raise AdmissionError(
                    f"mount-ns pidfile unsyncable: {exc}")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.rename(tmp, pidfile)
        except OSError as exc:
            raise AdmissionError(
                f"mount-ns pidfile unwritable: {exc}")
        try:
            dir_fd = os.open(os.path.dirname(pidfile) or ".",
                             os.O_RDONLY | os.O_DIRECTORY
                             | os.O_CLOEXEC)
        except OSError as exc:
            raise AdmissionError(
                f"mount-ns pidfile dir unsyncable: {exc}")
        try:
            try:
                os.fsync(dir_fd)
            except OSError as exc:
                raise AdmissionError(
                    f"mount-ns pidfile dir unsyncable: {exc}")
        finally:
            try:
                os.close(dir_fd)
            except OSError:
                pass
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _preserve_keeper_evidence(pidfile, pid, nsid, canary, reason):
    """Append unresolved-keeper evidence; never raises. (S103)

    A keeper that outlives a failed publication/rollback is
    recorded (0600, O_APPEND) with everything an operator
    needs to retire it by hand — a live root sleeper is never
    forgotten silently. Failures here must not mask the
    original error, so they are swallowed.
    """
    path = f"{pidfile}.unresolved"
    line = (f"{pid} {nsid} {canary} {reason}\n").encode(
        "ascii", "replace")
    try:
        fd = os.open(path,
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        return
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            return
        if st.st_uid != os.geteuid():
            return
        try:
            while line:
                done = os.write(fd, line)
                if done <= 0:
                    return
                line = line[done:]
        except OSError:
            return
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _spawn_keeper(euid, candir, publish_to):
    """Spawn the keeper ns; return (pid, nsid, canary, starttime).

    S17-round5: the keeper reports pid+canary on stdout (single
    READY line); the canary is generated inside (never on any
    cmdline, never pre-plantable). Raises AdmissionError on any
    failure.
    S100-round6: also returns the keeper's /proc starttime —
    the cheap reuse anchor every later routing decision
    checks. A keeper that vanishes between READY and the
    anchor read fails (tree retired by fail()), never a
    half-published identity.
    S103-round6: publication is part of the spawn (required
    `publish_to` pidfile path): a verified keeper whose
    record cannot be published atomically is rolled back
    (whole tree retired, never an orphaned live keeper with
    no record), and a tree that cannot be proven retired
    leaves durable unresolved evidence for manual recovery.
    """
    try:
        os.mkdir(candir, 0o700)
    except FileExistsError:
        try:
            st = os.lstat(candir)
        except OSError as exc:
            raise AdmissionError(f"mount-ns canary dir: {exc}")
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != euid:
            raise AdmissionError(
                "mount-ns canary dir alien; refusing")
    except OSError as exc:
        raise AdmissionError(f"mount-ns canary dir: {exc}")
    script = (
        "mount --make-rprivate / && "
        "C=$(head -c 16 /dev/urandom | od -An -tx1 | "
        "tr -d ' \\n') && "
        f"mount -t tmpfs canary-$C {candir} && "
        "echo \"READY $BASHPID $C\" && exec sleep infinity")
    try:
        child = subprocess.Popen(
            ["sudo", "-n", "unshare", "-m", "bash", "-c", script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
    except OSError as exc:
        raise AdmissionError(f"mount-ns keeper not spawning: {exc}")

    def fail(msg, evidence=None):
        # S103-round6: retire the WHOLE tree (sudo→unshare→
        # bash→sleep), never just the direct child — killing
        # sudo alone orphans the keeper sleep and its
        # namespace. kill_tree pins before signalling (safe
        # against reparenting) and escalates on EPERM for the
        # root-owned members; the Popen handle is retained so
        # the root number cannot recycle (no armed map).
        try:
            tree_gone = kill_tree("keeper-spawn", child.pid, 10)
        except Exception:
            tree_gone = False
        if not tree_gone and evidence is not None:
            _preserve_keeper_evidence(publish_to, *evidence,
                                      msg)
        # wait(), not communicate(): the keeper's grandchildren
        # (sudo→unshare→bash→sleep) inherit the pipes, so
        # communicate would block for pipe EOF until they exit
        # (the full timeout, every time); wait reaps only the
        # SIGKILLed direct child. stderr is drained
        # non-blocking below, for the diagnostic suffix only.
        try:
            child.wait(timeout=10)
        except Exception:
            pass
        err = ""
        try:
            err_fd = child.stderr.fileno()
            os.set_blocking(err_fd, False)
            try:
                chunk = os.read(err_fd, 65536)
            finally:
                os.set_blocking(err_fd, True)
            err = chunk.decode("utf-8", "replace")
        except Exception:
            err = ""
        for stream in (child.stdout, child.stderr):
            try:
                stream.close()
            except Exception:
                pass
        detail = (f" [{err.strip()[:200]}]"
                  if err and err.strip() else "")
        if not tree_gone:
            detail += (f" [keeper tree at pid {child.pid} not "
                       f"proven gone; inspect before retrying]")
        raise AdmissionError(f"{msg}{detail}")

    sel = selectors.DefaultSelector()
    sel.register(child.stdout, selectors.EVENT_READ)
    try:
        if not sel.select(timeout=15):
            fail("mount-ns keeper spawn timed out")
        line = child.stdout.readline()
    finally:
        sel.close()
    child.stdout.close()
    parts = line.strip().split()
    if (len(parts) != 3 or parts[0] != "READY"
            or not parts[1].isdigit()
            or len(parts[2]) != 32
            or any(c not in "0123456789abcdef"
                   for c in parts[2])):
        fail("mount-ns keeper reported garbage; refusing")
    pid = int(parts[1])
    canary = parts[2]
    if pid <= 1:
        fail("mount-ns keeper pid absurd")
    link = _read_ns_link(pid)
    if (link is None or not link.startswith("mnt:[")
            or not link.endswith("]")
            or not link[5:-1].isdigit()):
        fail("mount-ns keeper ns unreadable")
    nsid = int(link[5:-1])
    if nsid <= 0:
        fail("mount-ns keeper ns absurd")
    # Spawn-path canary gate: the pid is seconds old and the
    # nsid above has nothing recorded to compare against, so
    # only the secret mount proves this pid's namespace is
    # ours (a recycled pid's namespace lacks canary-<secret>).
    nspath = f"/proc/{pid}/ns/mnt"
    try:
        fresh_ok = _ns_has_canary(nspath, canary)
    except AdmissionError as exc:
        fail(f"mount-ns keeper canary check failed: {exc}")
    if not fresh_ok:
        fail("mount-ns keeper ns lacks our canary; refusing")
    starttime = _keeper_starttime(pid)
    if starttime is None:
        fail("mount-ns keeper vanished after READY; refusing")
    try:
        _publish_keeper_state(publish_to, candir, pid, nsid,
                              canary)
    except AdmissionError as exc:
        fail(f"mount-ns keeper publication failed ({exc})",
             evidence=(pid, nsid, canary))
    _KEEPERS.append(child)
    return (pid, nsid, canary, starttime)


def _revalidate_cached_keeper():
    """Cached nspath when the keeper is provably ours. (S100)

    The in-memory cache revalidates on every ensure call — a
    cached path is never trusted indefinitely. Same-process
    reuse needs only the starttime anchor (no subprocess): a
    process's namespaces are fixed for life, so a live pid
    with the recorded starttime is the verified keeper and
    its namespace is unchanged; a dead or recycled pid drops
    the cache (the caller falls through to the pidfile, which
    re-verifies link + canary). Returns the nspath, or None
    when the cache must be rebuilt.
    """
    if _MOUNT_NS is None or _MOUNT_NS == "direct":
        return _MOUNT_NS
    if _MOUNT_NS_IDENTITY is None:
        return None
    pid, _nsid, starttime, _canary = _MOUNT_NS_IDENTITY
    if starttime is None:
        return None
    if _keeper_starttime(pid) != starttime:
        return None
    return _MOUNT_NS


def ensure_mount_ns():
    """Join (or spawn) the keeper mount namespace. (S17-round5)

    Idempotent per process (cached in _MOUNT_NS); concurrent
    processes serialize on the pidfile flock, so no dual
    keepers. Returns the ns path (/proc/<pid>/ns/mnt). A
    recorded keeper is trusted only when its pid is alive in
    the recorded namespace (link read elevated — the keeper
    is root-owned, unprivileged readlink always gets EACCES)
    AND the namespace shows our canary mount (pid/nsid reuse
    alone cannot pass). Raises
    AdmissionError when no keeper can be verified (no sudo,
    spawn failure, alien pidfile) — callers treat that as
    mount-unsupported, never as license to use the host table
    for ns mounts.

    S100-round6: the cache revalidates on every call (a dead
    or recycled keeper drops to the pidfile, never routes
    into another namespace), and every ensured path carries
    the verified identity tuple (pid, nsid, starttime,
    canary) for cheap per-operation routing checks and
    manifest binding.
    """
    global _MOUNT_NS, _MOUNT_NS_IDENTITY
    if _MOUNT_NS == "direct":
        return "direct"
    if _MOUNT_NS is not None:
        nspath = _revalidate_cached_keeper()
        if nspath is not None:
            return nspath
        _MOUNT_NS = None
        _MOUNT_NS_IDENTITY = None
    euid = os.geteuid()
    pidfile, candir = _keeper_paths()
    # S103-round6: the mutual-exclusion lock lives on a
    # dedicated lockfile (never renamed), not on the pidfile
    # (rename-published): an flock on a renamed-away inode
    # would silently stop excluding. The pidfile itself is
    # untrusted input — read nofollow (a symlink reads as
    # absent and is replaced at publish), authenticated by
    # link + canary, never by container ownership.
    lockpath = f"{pidfile}.lock"
    try:
        lock_fd = os.open(lockpath,
                          os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                          0o600)
    except OSError as exc:
        raise AdmissionError(f"mount-ns lock: {exc}")
    try:
        st = os.fstat(lock_fd)
        if st.st_uid != euid or not stat.S_ISREG(st.st_mode):
            raise AdmissionError(
                "mount-ns lock alien; refusing")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            try:
                read_fd = os.open(pidfile,
                                  os.O_RDONLY | os.O_NOFOLLOW
                                  | os.O_CLOEXEC)
            except FileNotFoundError:
                raw = b""
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    # Symlink: treat as absent (respawn
                    # replaces it at publish).
                    raw = b""
                else:
                    raise AdmissionError(
                        f"mount-ns pidfile unreadable: {exc}")
            else:
                try:
                    raw = os.read(read_fd, 4096)
                except OSError as exc:
                    raise AdmissionError(
                        f"mount-ns pidfile unreadable: {exc}")
                finally:
                    try:
                        os.close(read_fd)
                    except OSError:
                        pass
            state = _parse_keeper_state(raw)
            if state is not None:
                nspath = _verify_recorded_keeper(state)
                if nspath is not None:
                    pid, nsid, canary = state
                    starttime = _keeper_starttime(pid)
                    if starttime is not None:
                        _MOUNT_NS = nspath
                        _MOUNT_NS_IDENTITY = (
                            pid, nsid, starttime, canary)
                        return nspath
                    # Verified but the anchor read raced its
                    # death: treat as dead, fall to respawn.
            pid, nsid, canary, starttime = _spawn_keeper(
                euid, candir, pidfile)
            _MOUNT_NS = f"/proc/{pid}/ns/mnt"
            _MOUNT_NS_IDENTITY = (pid, nsid, starttime,
                                  canary)
            return _MOUNT_NS
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def bind_mount_ns(expected=None):
    """Adopt the RECORDED keeper; never spawn. (S102-round6)

    For inspect/cleanup (and any other non-creating entry):
    acquire existing bound authority (pidfile record, fully
    verified: link + canary + starttime anchor) without
    creating replacement infrastructure. `expected` is the
    manifest's {"pid","nsid","starttime"} dict (or None when
    the manifest predates identity): a recorded keeper that
    is not the expected one raises instead of substituting.
    Lockless by design (rename-published records never tear);
    a concurrent ensure racing this bind surfaces as a stale
    record that fails verification — loud, converging on
    retry. Raises AdmissionError when no keeper is recorded,
    verifiable, or matches.
    """
    global _MOUNT_NS, _MOUNT_NS_IDENTITY
    if _MOUNT_NS == "direct":
        raise AdmissionError(
            "keeper ns bind requested in direct mode; refusing")
    if _MOUNT_NS is not None:
        nspath = _revalidate_cached_keeper()
        if nspath is None:
            _MOUNT_NS = None
            _MOUNT_NS_IDENTITY = None
        else:
            _check_expected_keeper(expected)
            return nspath
    pidfile, _candir = _keeper_paths()
    try:
        read_fd = os.open(pidfile,
                          os.O_RDONLY | os.O_NOFOLLOW
                          | os.O_CLOEXEC)
    except OSError as exc:
        raise AdmissionError(
            f"no keeper recorded ({exc}); refusing to create "
            f"one for a non-creating command")
    try:
        try:
            raw = os.read(read_fd, 4096)
        except OSError as exc:
            raise AdmissionError(
                f"mount-ns pidfile unreadable: {exc}")
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
    state = _parse_keeper_state(raw)
    if state is None:
        raise AdmissionError(
            "no keeper recorded; refusing to create one for a "
            "non-creating command")
    nspath = _verify_recorded_keeper(state)
    if nspath is None:
        raise AdmissionError(
            "recorded keeper dead or unverifiable; refusing "
            "to substitute a fresh namespace")
    pid, nsid, canary = state
    starttime = _keeper_starttime(pid)
    if starttime is None:
        raise AdmissionError(
            "recorded keeper vanished during bind; refusing")
    _MOUNT_NS = nspath
    _MOUNT_NS_IDENTITY = (pid, nsid, starttime, canary)
    _check_expected_keeper(expected)
    return nspath


def _check_expected_keeper(expected):
    """Raise unless the bound keeper is the expected one. (S100)

    `expected` is a manifest {"pid","nsid","starttime"} dict,
    True (round-5, adopt-current), or None (no manifest say).
    """
    if expected is None or expected is True:
        return
    if _MOUNT_NS_IDENTITY is None:
        raise AdmissionError(
            "keeper ns unbound; refusing host-table fallback")
    pid, nsid, starttime = _MOUNT_NS_IDENTITY[0:3]
    if (expected.get("pid") != pid
            or expected.get("nsid") != nsid
            or expected.get("starttime") != starttime):
        raise AdmissionError(
            f"keeper ns mismatch (manifest pid="
            f"{expected.get('pid')} nsid={expected.get('nsid')} "
            f"vs bound pid={pid} nsid={nsid}); refusing "
            f"substitution")


def _inside_keeper_ns():
    """True when already inside the bound namespace. (S99)

    Compares /proc/self/ns/mnt (unprivileged, one readlink)
    to the bound nsid — identity-based, so a re-exec'd
    process provably terminates the re-exec chain. Unensured
    and direct modes are never "inside" (nothing to join).
    """
    if (_MOUNT_NS is None or _MOUNT_NS == "direct"
            or _MOUNT_NS_IDENTITY is None):
        return False
    try:
        here = os.readlink("/proc/self/ns/mnt")
    except OSError:
        return False
    return here == f"mnt:[{_MOUNT_NS_IDENTITY[1]}]"


def _reexec_inside_ns():
    """Re-exec this CLI inside the keeper namespace. (S99)

    sudo → nsenter (join the bound ns) → runuser (drop back
    to the invoking uid: the controller stays unprivileged,
    only its mount view changes) → this script with the same
    argv. Only TMPDIR and HOME cross the sudo boundary (both
    needed for path admission); SUDO_UID lands as our own
    euid (harmless: already in the trusted set). Raises
    AdmissionError when the controller user is unresolvable;
    os.execvp raises OSError when the exec itself fails —
    both fail the command loudly, never run it outside.
    """
    nspath = _MOUNT_NS
    euid = os.geteuid()
    try:
        pw = pwd.getpwuid(euid)
    except KeyError:
        raise AdmissionError(
            f"cannot resolve controller user {euid}; refusing "
            f"to run outside the keeper ns")
    script = os.path.abspath(sys.argv[0])
    prog = sys.executable or "python3"
    if not os.path.isabs(prog):
        prog = os.path.abspath(prog)
    env = [f"TMPDIR={os.environ.get('TMPDIR', '/tmp')}",
           f"HOME={pw.pw_dir}"]
    argv = ["sudo", "-n", "env", *env, "nsenter",
           f"--mount={nspath}", "runuser", "-u", pw.pw_name,
           "--", prog, script, *sys.argv[1:]]
    os.execvp("sudo", argv)


def _dump_ns_mount_table(nspath):
    """Read the keeper-ns mount table. (S17-round5)

    Raw subprocess (foundation primitive). Returns decoded
    text; raises AdmissionError when the dump cannot run.
    """
    try:
        proc = subprocess.run(
            ["sudo", "-n", "nsenter", f"--mount={nspath}",
             "cat", "/proc/self/mountinfo"],
            capture_output=True, timeout=30)
    except OSError as exc:
        raise AdmissionError(f"mount table unreadable: {exc}")
    except subprocess.TimeoutExpired:
        raise AdmissionError("mount table unreadable: dump timed out")
    if proc.returncode != 0:
        raise AdmissionError(
            f"mount table unreadable: {tail(os.fsdecode(proc.stderr or b''))}")
    return os.fsdecode(proc.stdout)


def _ns_active():
    """Keeper ns path when confined, else None. (S17-round5)"""
    if _MOUNT_NS is None or _MOUNT_NS == "direct":
        return None
    return _MOUNT_NS


def _apply_manifest_ns_mode(manifest):
    """Select ns or legacy host-table mode. (S17-round5)

    Manifests written by this code carry mount_ns (ns-native);
    older ephemeral manifests lack it and their mounts (if
    any) live on the host table — those clean up direct.
    Removal criterion: delete the legacy arm once no supported
    flow can present a pre-ns manifest.

    S100-round6: an identity-carrying manifest ({"pid","nsid",
    "starttime"}) additionally BINDS recovery to that keeper:
    unensured mode or a bound keeper with a different (pid,
    nsid, starttime) raises instead of silently substituting
    a fresh or recycled keeper for the run's namespace (a
    respawned keeper's empty table would discharge live
    mounts of an alive-but-unverifiable predecessor). True
    (round-5, no identity) adopts the current binding, which
    must still be ensured — never the host table.
    """
    global _MOUNT_NS
    mode = manifest.get("mount_ns")
    if not mode:
        _MOUNT_NS = "direct"
        return
    if (_MOUNT_NS is None or _MOUNT_NS == "direct"
            or _MOUNT_NS_IDENTITY is None):
        raise AdmissionError(
            "keeper ns unavailable for ns-native manifest; "
            "refusing host-table fallback")
    if isinstance(mode, dict):
        _check_expected_keeper(mode)


class RootAuthority:
    """A held run-root directory plus its recorded identity."""

    def __init__(self, path):
        # S15-round3: refuse to bind under a parent anyone
        # untrusted can rename in (best-effort stat of the
        # parent spelling; the (dev,ino) authority below is the
        # binding, this gate just declines hostile soil).
        parent = os.path.dirname(path) or "."
        try:
            pst = os.stat(parent)
        except OSError as exc:
            raise RootAuthorityError(
                f"run-root parent not statable: {parent}: {exc}")
        refusal = _run_root_parent_refusal(pst, parent)
        if refusal is not None:
            raise RootAuthorityError(refusal)
        try:
            fd = os.open(
                path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise RootAuthorityError(
                f"run-root not openable: {path}: {exc}")
        try:
            st = os.fstat(fd)
        except OSError as exc:
            os.close(fd)
            raise RootAuthorityError(
                f"run-root not statable: {path}: {exc}")
        if not stat.S_ISDIR(st.st_mode):
            os.close(fd)
            raise RootAuthorityError(
                f"run-root is not a directory: {path}")
        self.path = path
        self.fd = fd
        self.dev = st.st_dev
        self.ino = st.st_ino

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def verify(self):
        """The held fd and the pathname still name the same dir."""
        try:
            held = os.fstat(self.fd)
        except OSError as exc:
            raise RootReplacedError(
                f"run-root authority lost for {self.path}: {exc}")
        if ((held.st_dev, held.st_ino) != (self.dev, self.ino)
                or not stat.S_ISDIR(held.st_mode)):
            raise RootReplacedError(
                f"run-root authority changed for {self.path}")
        try:
            live = os.stat(self.path)
        except FileNotFoundError:
            raise RootReplacedError(
                f"run-root missing mid-create: {self.path}")
        except OSError as exc:
            raise RootReplacedError(
                f"run-root unverifiable mid-create {self.path}: {exc}")
        if (live.st_dev, live.st_ino) != (self.dev, self.ino):
            raise RootReplacedError(
                f"run-root replaced mid-create: {self.path}: "
                f"live=({live.st_dev},{live.st_ino}) "
                f"held=({self.dev},{self.ino})")

    def _split(self, rel):
        if not rel or len(rel) > MAX_PATH or "\x00" in rel:
            raise RootAuthorityError(f"bad fixture path: {rel[:60]!r}")
        if os.path.isabs(rel):
            raise RootAuthorityError(f"fixture path not relative: {rel[:60]!r}")
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if not parts or ".." in parts:
            raise RootAuthorityError(f"fixture path escapes root: {rel[:60]!r}")
        for part in parts:
            if len(part) > 255:
                raise RootAuthorityError(
                    f"fixture name too long: {part[:60]!r}")
        return parts

    def _open_parent(self, parts, create_missing):
        """Open the directory holding `parts[-1]`; caller closes."""
        cur = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                try:
                    nxt = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=cur)
                except FileNotFoundError:
                    if not create_missing:
                        raise RootAuthorityError(
                            f"fixture parent missing: {part!r}")
                    try:
                        os.mkdir(part, 0o755, dir_fd=cur)
                    except OSError as exc:
                        raise RootAuthorityError(
                            f"fixture mkdir failed: {part!r}: {exc}")
                    nxt = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=cur)
                except OSError as exc:
                    raise RootAuthorityError(
                        f"fixture parent not openable: {part!r}: {exc}")
                os.close(cur)
                cur = nxt
            return cur
        except BaseException:
            os.close(cur)
            raise

    def abspath(self, rel):
        return os.path.join(self.path, *self._split(rel))

    def mkdirs(self, rel):
        """makedirs -p, descriptor-bound; returns the absolute path."""
        self.verify()
        parts = self._split(rel)
        parent = self._open_parent(parts, True)
        try:
            try:
                os.mkdir(parts[-1], 0o755, dir_fd=parent)
            except FileExistsError:
                pass
            except OSError as exc:
                raise RootAuthorityError(
                    f"fixture mkdir failed: {rel[:60]!r}: {exc}")
        finally:
            os.close(parent)
        self.verify()
        return self.abspath(rel)

    def _reopen(self, parts):
        """Open the dir named by `parts` (possibly empty); caller closes."""
        cur = os.dup(self.fd)
        try:
            for part in parts:
                nxt = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=cur)
                os.close(cur)
                cur = nxt
            return cur
        except BaseException:
            os.close(cur)
            raise

    def mkdir(self, rel, exist_ok=False):
        self.verify()
        parts = self._split(rel)
        parent = self._open_parent(parts, True)
        try:
            try:
                os.mkdir(parts[-1], 0o755, dir_fd=parent)
            except FileExistsError:
                if not exist_ok:
                    raise RootAuthorityError(
                        f"fixture already exists: {rel[:60]!r}")
        except OSError as exc:
            raise RootAuthorityError(
                f"fixture mkdir failed: {rel[:60]!r}: {exc}")
        finally:
            os.close(parent)
        self.verify()
        return self.abspath(rel)

    def write_bytes(self, rel, data, mode=0o644):
        """Create-or-fail a fixture file; refuses overwrites. (S15)"""
        self.verify()
        parts = self._split(rel)
        parent = self._open_parent(parts, True)
        try:
            try:
                fd = os.open(parts[-1],
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             mode, dir_fd=parent)
            except FileExistsError:
                raise RootAuthorityError(
                    f"fixture already exists: {rel[:60]!r}")
            except OSError as exc:
                raise RootAuthorityError(
                    f"fixture not writable: {rel[:60]!r}: {exc}")
            try:
                view = memoryview(data)
                while view:
                    done = os.write(fd, view)
                    view = view[done:]
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(parent)
        self.verify()
        return self.abspath(rel)

    def open_new(self, rel, mode=0o644):
        """Open an O_EXCL fixture file, returning (fd, abspath).

        S18: the caller holds the fd across privileged attachment
        so the recorded backing identity is the opened file, not a
        later pathname stat.
        """
        self.verify()
        parts = self._split(rel)
        parent = self._open_parent(parts, True)
        try:
            try:
                fd = os.open(parts[-1],
                             os.O_RDWR | os.O_CREAT | os.O_EXCL,
                             mode, dir_fd=parent)
            except FileExistsError:
                raise RootAuthorityError(
                    f"fixture already exists: {rel[:60]!r}")
            except OSError as exc:
                raise RootAuthorityError(
                    f"fixture not creatable: {rel[:60]!r}: {exc}")
        finally:
            os.close(parent)
        return fd, self.abspath(rel)

    def mkfifo(self, rel):
        self.verify()
        parts = self._split(rel)
        parent = self._open_parent(parts, True)
        try:
            try:
                os.mkfifo(parts[-1], 0o644, dir_fd=parent)
            except FileExistsError:
                try:
                    st = os.stat(parts[-1], dir_fd=parent,
                                 follow_symlinks=False)
                except OSError:
                    raise RootAuthorityError(
                        f"fixture fifo blocked: {rel[:60]!r}")
                if not stat.S_ISFIFO(st.st_mode):
                    raise RootAuthorityError(
                        f"fixture fifo replaced: {rel[:60]!r}")
                try:
                    os.unlink(parts[-1], dir_fd=parent)
                    os.mkfifo(parts[-1], 0o644, dir_fd=parent)
                except OSError as exc:
                    raise RootAuthorityError(
                        f"fixture fifo failed: {rel[:60]!r}: {exc}")
            except OSError as exc:
                raise RootAuthorityError(
                    f"fixture fifo failed: {rel[:60]!r}: {exc}")
        finally:
            os.close(parent)
        self.verify()
        return self.abspath(rel)

    def link(self, src_rel, dst_rel):
        """Hardlink two names in one directory, descriptor-bound."""
        self.verify()
        src, dst = self._split(src_rel), self._split(dst_rel)
        if src[:-1] != dst[:-1]:
            raise RootAuthorityError("fixture link spans directories")
        parent = self._open_parent(src, False)
        try:
            try:
                os.link(src[-1], dst[-1],
                        src_dir_fd=parent, dst_dir_fd=parent)
            except OSError as exc:
                raise RootAuthorityError(
                    f"fixture link failed: {dst_rel[:60]!r}: {exc}")
        finally:
            os.close(parent)
        self.verify()

    def stat(self, rel, follow=True):
        parts = self._split(rel)
        parent = self._open_parent(parts, False)
        try:
            try:
                return os.stat(parts[-1], dir_fd=parent,
                               follow_symlinks=follow)
            except OSError as exc:
                raise RootAuthorityError(
                    f"fixture not statable: {rel[:60]!r}: {exc}")
        finally:
            os.close(parent)

    def copy_from(self, src_path, rel, cap=COPY_CAP):
        """Copy an outside payload in, capped, descriptor-bound."""
        self.verify()
        try:
            src = os.open(src_path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as exc:
            raise RootAuthorityError(
                f"copy source not openable: {src_path[:60]!r}: {exc}")
        try:
            try:
                st = os.fstat(src)
            except OSError as exc:
                raise RootAuthorityError(
                    f"copy source not statable: {src_path[:60]!r}: {exc}")
            if not stat.S_ISREG(st.st_mode):
                raise RootAuthorityError(
                    f"copy source not regular: {src_path[:60]!r}")
            if st.st_size > cap:
                raise RootAuthorityError(
                    f"copy source exceeds {cap} bytes: "
                    f"{src_path[:60]!r}")
            flags = fcntl.fcntl(src, fcntl.F_GETFL)
            fcntl.fcntl(src, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
            parts = self._split(rel)
            parent = self._open_parent(parts, True)
            try:
                try:
                    dst = os.open(parts[-1],
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 0o777 & st.st_mode or 0o755,
                                 dir_fd=parent)
                except FileExistsError:
                    raise RootAuthorityError(
                        f"fixture already exists: {rel[:60]!r}")
                try:
                    total = 0
                    while True:
                        chunk = os.read(src, 65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > cap:
                            raise RootAuthorityError(
                                f"copy grew past {cap} bytes: "
                                f"{src_path[:60]!r}")
                        view = memoryview(chunk)
                        while view:
                            done = os.write(dst, view)
                            view = view[done:]
                    os.fsync(dst)
                finally:
                    os.close(dst)
            finally:
                os.close(parent)
        finally:
            os.close(src)
        self.verify()
        return self.abspath(rel)


def _require_guard():
    guard = _ROOT_GUARD
    if guard is None:
        raise RootAuthorityError(
            "no retained run-root authority (provisioners run "
            "inside create_command)")
    return guard


def guard_verify():
    """Re-verify the retained root when one is held, else no-op."""
    if _ROOT_GUARD is not None:
        _ROOT_GUARD.verify()


def _trusted_parent_owners():
    """UIDs trusted to own a shared run-root/manifest parent. (S76)

    Us plus root, plus — inside a sudo helper — the invoking
    controller (SUDO_UID): a controller-admitted parent stays
    admissible when the privileged helper re-binds the same
    directory, instead of turning foreign-owned at the UID
    transition and refusing every privileged operation for an
    already admitted root. The controller is the authorized
    operator for this invocation (it named this run-root), and
    the (dev,ino) verify brackets still detect mid-run swaps;
    only genuinely foreign owners refuse. SUDO_UID honors only
    a well-formed numeric UID; outside sudo it is absent and
    the set is unchanged. Honoring it for a non-root euid is
    harmless: unprivileged callers fail the privileged effects
    themselves at the kernel boundary.
    """
    owners = {os.geteuid(), 0}
    sudo_uid = os.environ.get("SUDO_UID", "")
    if sudo_uid.isdigit():
        owners.add(int(sudo_uid))
    return owners


def _manifest_parent_refusal(pst, parent, label="manifest parent"):
    """Refusal reason for a manifest parent stat, or None when accepted.

    S25-round3: a sticky parent's foreign owner bypasses the sticky
    bit (directory owners may rename anyone's entries), and a
    group-writable parent's foreign owner renames directly — either
    can substitute the temp file after the identity proof and before
    the publish rename. Whenever the parent grants rename rights
    beyond its owner (group or world write bits), the owner must be
    trusted: us, root, or the sudo-invoking controller (S76).
    Group members stay trusted by the S25 doctrine, and unshared
    parents need no owner check (only the owner and root can mutate
    them at all).

    S25-round4: the owner check no longer depends on the write
    bits. A foreign-owned 0755/01755 parent is equally unsafe
    for a privileged caller — root (or DAC override) creates
    the temp file, and the parent owner renames over it after
    the identity proof, before the rename — so every parent
    needs a trusted owner. For unprivileged callers this only
    moves the refusal earlier (creation would fail later
    anyway); for privileged callers it closes the hole.
    """
    if not stat.S_ISDIR(pst.st_mode):
        return (f"{label} not a directory: "
                f"{parent[:80]!r}")
    if pst.st_uid not in _trusted_parent_owners():
        return (f"{label} has a foreign owner: "
                f"{parent[:80]!r} (owner {pst.st_uid}); "
                f"use a private directory")
    if ((pst.st_mode & stat.S_IWOTH)
            and not (pst.st_mode & stat.S_ISVTX)):
        return (f"{label} is shared and unprotected: "
                f"{parent[:80]!r} (mode {oct(pst.st_mode & 0o7777)}); "
                f"use a private directory")
    return None


def _run_root_parent_refusal(pst, parent):
    """Refusal reason for a run-root parent stat, or None when accepted.

    S15-round3: the run-root bind requires a contained parent —
    the same doctrine as manifest parents. A directory anyone
    untrusted can rename in lets an attacker swap the run-root
    pathname between the guard's verify brackets; the (dev,ino)
    authority still detects the swap, but binding under such a
    parent is refused outright instead of merely detected.
    Sticky+trusted-owner shared parents (/tmp-style) stay
    accepted: strict owner-only parents would forbid the
    disposable roots themselves.
    """
    return _manifest_parent_refusal(pst, parent,
                                    label="run-root parent")


def save_manifest(manifest, path):
    """Atomically replace the manifest (tmp write, fsync, rename).

    R23: the temp file is created exclusively under an
    unpredictable name in the manifest's own directory — a
    preplanted symlink at a predictable tmp name is never
    followed, and ``os.replace`` swaps (not follows) a link at
    the manifest path itself.

    S25: publication is descriptor-bound to the held parent and
    refused in shared unprotected directories. A world-writable
    parent without the sticky bit would let any other actor
    replace the temp file between creation and rename
    (unpredictable names stop preplanting, not post-creation
    replacement), so such parents refuse before anything is
    written. Group-writable parents stay accepted — group
    membership is an explicit trust relation (and under
    user-private-group schemes the group holds only the owner)
    — and the temp identity proof below guards the residual
    race in every parent: the temp identity is proven (fstat at
    write vs lstat at publish) before the rename, and cleanup
    unlinks only the proven temp.

    S25-round3: shared parents (group or world writable) additionally
    require a trusted owner — us or root. A sticky directory's
    foreign owner bypasses the sticky bit and could substitute the
    temp after the identity proof, before the rename; such parents
    refuse at the gate (see ``_manifest_parent_refusal``).
    S25-round4: every parent needs a trusted owner, independently
    of the write bits — a foreign-owned unshared parent is unsafe
    for privileged callers (see ``_manifest_parent_refusal``).
    """
    parent = os.path.dirname(os.path.abspath(path)) or "."
    base = os.path.basename(os.path.abspath(path))
    if not base or base in (".", "..") or "/" in base:
        raise AdmissionError(f"bad manifest name: {base[:60]!r}")
    try:
        parent_fd = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise AdmissionError(
            f"manifest parent not openable: {parent[:80]!r}: {exc}")
    try:
        try:
            pst = os.fstat(parent_fd)
        except OSError as exc:
            raise AdmissionError(
                f"manifest parent not statable: {parent[:80]!r}: {exc}")
        refusal = _manifest_parent_refusal(pst, parent)
        if refusal is not None:
            raise AdmissionError(refusal)
        tmp = f".tt04-manifest-{secrets.token_hex(8)}"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise AdmissionError(
                f"manifest temp not creatable: {exc}")
        written = None
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(manifest, indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
                written = os.fstat(handle.fileno())
            try:
                live = os.stat(tmp, dir_fd=parent_fd,
                               follow_symlinks=False)
            except OSError as exc:
                raise AdmissionError(
                    f"manifest temp vanished before publish: {exc}")
            if ((live.st_dev, live.st_ino) != (written.st_dev, written.st_ino)
                    or not stat.S_ISREG(live.st_mode)):
                raise AdmissionError(
                    "manifest temp replaced before publish; refusing")
            try:
                os.replace(tmp, base, src_dir_fd=parent_fd,
                           dst_dir_fd=parent_fd)
            except OSError as exc:
                raise AdmissionError(f"manifest not publishable: {exc}")
            try:
                os.fsync(parent_fd)
            except OSError:
                pass
        except BaseException:
            if written is not None:
                try:
                    rest = os.stat(tmp, dir_fd=parent_fd,
                                   follow_symlinks=False)
                except OSError:
                    rest = None
                if (rest is not None and (rest.st_dev, rest.st_ino)
                        == (written.st_dev, written.st_ino)):
                    try:
                        os.unlink(tmp, dir_fd=parent_fd)
                    except OSError:
                        pass
            raise
    finally:
        os.close(parent_fd)


def _persist_now(manifest):
    if _PERSIST is not None:
        save_manifest(manifest, _PERSIST)


def record_mount(manifest, run_root, role, target, expect_super=(),
                 expected=None):
    table = read_mount_table()
    rows = find_mounts(table, target)
    if not rows:
        raise AdmissionError(f"mount missing after create: {target}")
    if len(rows) > 1:
        raise AdmissionError(
            f"ambiguous stacked mount at {target}: refusing record")
    row = rows[0]
    if expected is not None and not mount_fingerprint_matches(
            row, expected):
        # S62: a sole foreign replacement after a successful
        # create must not be adopted — the row has to match the
        # retained acquisition identity (source/type/super).
        raise AdmissionError(
            f"mount at {target} does not match expected "
            f"acquisition ({row['fstype']},{row['source']}); "
            f"refusing record")
    if len(manifest["mounts"]) >= MAX_MOUNTS:
        raise AdmissionError("mount cap exceeded")
    manifest["mounts"].append({
        "role": role, "source": row["source"], "target": row["target"],
        "fstype": row["fstype"], "options": "",
        "actual_super": row["super"][:512], "mnt_id": row["mnt_id"],
        "root": row["root"][:512],
        "expect_super": [s[:256] for s in expect_super],
    })
    _persist_now(manifest)


def record_proc(manifest, role, pid):
    if len(manifest["procs"]) >= MAX_PROCS:
        raise AdmissionError("proc cap exceeded")
    ident = proc_identity(pid)
    ident["role"] = role
    manifest["procs"].append(ident)
    _persist_now(manifest)
    return ident


def record_pending_proc(manifest, role, pid, starttime, detail):
    """Persist an unretired-process recovery record. (S21/S24)

    Used when a spawn produced a live process that could not be
    fully admitted or retired: the pid (plus its starttime when
    observed) stays in the manifest so cleanup reports — and, when
    identity is known, retries — the retirement instead of
    dropping the process from custody.
    """
    manifest.setdefault("pending_procs", []).append({
        "role": role, "pid": pid, "starttime": starttime,
        "detail": detail[:256],
    })
    _persist_now(manifest)


def drop_pending_proc(manifest, role, pid):
    manifest["pending_procs"] = [
        entry for entry in manifest.get("pending_procs", [])
        if not (entry.get("role") == role and entry.get("pid") == pid)]
    _persist_now(manifest)


def refresh_pending_proc(manifest, role, pid, starttime, detail):
    """Replace a pending-proc record in memory; persist once. (S21-round4)

    A drop followed by a record persists twice, and a crash (or
    a failed second save) between them leaves a live process
    absent from the durable pending set. Refresh removes the
    matching record and appends its replacement in memory, then
    persists a single atomic manifest — the durable set holds
    the old or the new record, never neither. A None starttime
    preserves the prior record's (the process was never
    re-observed).

    S91-round5: a known (non-None) starttime is NEVER replaced
    by a different observation — the number may have been
    recycled under the armed record, and adopting the new
    value would authorize signalling a stranger. On conflict
    the armed value is kept and the conflict is noted; fresh
    identity is adopted only when none was established.
    """
    old_start = None
    kept = []
    for entry in manifest.get("pending_procs", []):
        if entry.get("role") == role and entry.get("pid") == pid:
            old_start = entry.get("starttime")
            continue
        kept.append(entry)
    if (old_start is not None and starttime is not None
            and starttime != old_start):
        detail = (f"identity conflict: armed starttime "
                  f"{old_start}, observed {starttime}; "
                  f"{detail}")[:256]
        starttime = old_start
    manifest["pending_procs"] = kept
    manifest["pending_procs"].append({
        "role": role, "pid": pid,
        "starttime": (starttime if starttime is not None
                      else old_start),
        "detail": detail[:256],
    })
    _persist_now(manifest)


def record_pending_acquisition(manifest, entry):
    """Persist an uncertain kernel acquisition. (S16/S23)

    Recorded BEFORE the effect it guards (loop attach, mount) so a
    timeout or crash between effect and response keeps custody;
    dropped once the outcome is reconciled.
    """
    manifest.setdefault("pending_acquisitions", []).append(entry)
    _persist_now(manifest)


def drop_pending_acquisition(manifest, kind, key):
    manifest["pending_acquisitions"] = [
        entry for entry in manifest.get("pending_acquisitions", [])
        if not (entry.get("kind") == kind and entry.get("key") == key)]
    _persist_now(manifest)


def refresh_pending_acquisition(manifest, kind, key, entry):
    """Replace a pending record in memory; persist once. (S62-round4)

    A drop followed by a record persists twice, and a crash (or
    a failed second save) between them leaves the live object
    absent from the durable pending set. Refresh removes the
    matching record and appends its replacement in memory, then
    persists a single atomic manifest — the durable set holds
    the old or the new record, never neither.
    """
    manifest["pending_acquisitions"] = [
        old for old in manifest.get("pending_acquisitions", [])
        if not (old.get("kind") == kind and old.get("key") == key)]
    manifest["pending_acquisitions"].append(entry)
    _persist_now(manifest)


def record_file(manifest, role, path):
    if len(manifest["files"]) >= MAX_FILES:
        raise AdmissionError("file cap exceeded")
    data, st = read_regular_capped(path, MAX_FILE_BYTES)
    manifest["files"].append({
        "role": role, "path": path, "dev": st.st_dev,
        "ino": st.st_ino, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    })
    _persist_now(manifest)


def pattern_bytes(seed, size):
    return bytes(((i * 31 + seed) % 251 + 1) for i in range(size))


def create_unprivileged(manifest, run_root):
    auth = _require_guard()
    auth.mkdir("plain")
    auth.write_bytes("plain/a.bin", pattern_bytes(1, 8192))
    auth.write_bytes("plain/b.bin", pattern_bytes(2, 8192))
    record_file(manifest, "plain-a", auth.abspath("plain/a.bin"))
    record_file(manifest, "plain-b", auth.abspath("plain/b.bin"))
    manifest["cells"]["FS09"] = {
        "status": "provisioned", "needs_privilege": False,
        "detail": "plain fixtures; denial is exercised live by the cell",
    }
    manifest["cells"]["FS10"] = {
        "status": "provisioned", "needs_privilege": False,
        "detail": "ptrace preflight runs live in the cell",
    }
    provision_btrfs(manifest, run_root)


def provision_btrfs(manifest, run_root):
    skip = lambda reason: manifest["cells"].update({
        "FS02": {"status": "skipped", "needs_privilege": False, "reason": reason},
        "FS03": {"status": "skipped", "needs_privilege": False, "reason": reason}})
    if shutil.which("btrfs") is None:
        skip("missing btrfs(8) tool")
        return
    auth = _require_guard()
    try:
        auth.mkdir("btrfs")
        sv_a = auth.abspath("btrfs/svA")

        def run_btrfs(argv):
            auth.verify()
            try:
                return subprocess.run(
                    argv, capture_output=True, text=True, timeout=60)
            finally:
                auth.verify()

        proc = run_btrfs(["btrfs", "subvolume", "create", sv_a])
        if proc.returncode != 0:
            skip(f"btrfs subvolume create refused: {tail(proc.stderr)}")
            return
        for name in ("svB",):
            proc = run_btrfs(
                ["btrfs", "subvolume", "create",
                 auth.abspath(f"btrfs/{name}")])
            if proc.returncode != 0:
                skip(f"btrfs subvolume create refused: {tail(proc.stderr)}")
                return
        for sv, seed in (("svA", 11), ("svB", 12)):
            auth.write_bytes(f"btrfs/{sv}/f", pattern_bytes(seed, 8192))
        proc = run_btrfs(
            ["btrfs", "subvolume", "snapshot", sv_a,
             auth.abspath("btrfs/snapA")])
        if proc.returncode != 0:
            skip(f"btrfs snapshot refused: {tail(proc.stderr)}")
            return
        # S13: externally created subvolumes inherit ambient modes;
        # narrow them (never widen) so the deletion gate admits the
        # tree this cell just built.
        for sub in ("svA", "svB", "snapA"):
            sub_path = auth.abspath(f"btrfs/{sub}")
            mode = os.stat(sub_path).st_mode
            if mode & 0o022:
                os.chmod(sub_path, mode & ~0o022)
        manifest["evidence"]["btrfs_subvolumes"] = ["svA", "svB", "snapA"]
        record_file(manifest, "btrfs-svA-f", auth.abspath("btrfs/svA/f"))
        record_file(manifest, "btrfs-svB-f", auth.abspath("btrfs/svB/f"))
        record_file(manifest, "btrfs-snapA-f", auth.abspath("btrfs/snapA/f"))
        manifest["cells"]["FS02"] = {
            "status": "provisioned", "needs_privilege": False,
            "detail": "svA/svB/snapA with two-page files; "
                      "collision is verified live by the cell oracle",
        }
        manifest["cells"]["FS03"] = {
            "status": "provisioned", "needs_privilege": False,
            "detail": "snapshot-pinned svA-f/snapA-f collision pair",
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        skip(f"btrfs provisioning I/O failed: {exc}")


def strip_deleted_suffix(path):
    if path.endswith(" (deleted)"):
        return path[: -len(" (deleted)")]
    return path


def verify_loop_backing(loop, image, image_st):
    """True when the kernel's live loop association is our image.

    S18-round3: kernel backing identity first —
    read_loop_backing_id compares the loop's held (dev, ino)
    against the fstat of the held image descriptor with no
    pathname resolution, so a deleted-B/restored-A swap cannot
    spoof it. When the device node is unreadable the sysfs
    pathname fallback governs (sound for stable states; deleted
    backings refuse as unprovable). Any mismatch, missing
    association, or unreadable backing refuses.
    """
    if not loop or not str(loop).startswith("/dev/loop"):
        return False
    try:
        ident = read_loop_backing_id(loop)
    except LoopIdUnavailable:
        ident = "unavailable"
    if ident is None:
        return False
    if ident != "unavailable":
        return ((ident[0], ident[1])
                == (image_st.st_dev, image_st.st_ino))
    try:
        live = read_loop_backing(loop)
    except AdmissionError:
        return False
    return sysfs_backing_matches(live, image, image_st.st_dev,
                                 image_st.st_ino)


def adopt_loop(manifest, image, loop, image_st):
    manifest["evidence"]["ext4_loop"] = loop
    manifest["evidence"]["ext4_loop_backing"] = {
        "path": image,
        "dev": image_st.st_dev,
        "ino": image_st.st_ino,
    }
    drop_pending_acquisition(manifest, "loop", image)
    _persist_now(manifest)


def scan_loop_by_backing(dev, ino):
    """Every /dev/loopN whose live backing is (dev, ino), plus whether
    the scan assessed every candidate.

    S23-round3: returns (matches, incomplete). Kernel backing
    identity decides whenever the device node is readable — a
    deleted backing still identifies its true inode, so an
    attached-but-unlinked image is found, not skipped. A candidate
    the scan cannot assess (unreadable kernel status plus an
    unstatable pathname — ENOENT after an unlink, EACCES) marks
    the scan incomplete instead of silently skipping: callers
    retain custody on incomplete scans, and only a complete empty
    scan proves absence.

    S23-round4: a missing device node is unassessable, never
    detached — removing /dev/loopN leaves the kernel loop (and
    its sysfs backing) live, so a sysfs-live candidate whose
    node cannot be opened marks the scan incomplete (or adopts
    through the pathname fallback when the backing stats to
    the query identity).
    """
    matches = []
    incomplete = False
    try:
        names = os.listdir("/sys/block")
    except OSError as exc:
        raise AdmissionError(f"loop scan unreadable: {exc}")
    for name in sorted(names):
        if not name.startswith("loop"):
            continue
        loop = f"/dev/{name}"
        try:
            live = read_loop_backing(loop)
        except AdmissionError:
            raise
        if live is None:
            continue
        try:
            ident = read_loop_backing_id(loop)
        except LoopIdUnavailable:
            ident = "unavailable"
        if ident is None:
            continue
        if ident != "unavailable":
            if (ident[0], ident[1]) == (dev, ino):
                matches.append(loop)
            continue
        if live.endswith(" (deleted)"):
            # Unlinked backing, unassessable without kernel status:
            # the loop may still hold our image.
            incomplete = True
            continue
        try:
            st = os.stat(live)
        except OSError:
            incomplete = True
            continue
        if (st.st_dev, st.st_ino) == (dev, ino):
            matches.append(loop)
    return (matches, incomplete)


def reconcile_loop_attach(manifest, image, dev, ino):
    """Adopt, clear, or retain a loop attach of uncertain outcome.

    Returns the adopted loop name, or None when no effect took
    place (pending dropped) or the outcome stays uncertain
    (pending retained). (S23)

    S23-round3: only a COMPLETE scan adopts or clears. An
    incomplete scan retains pending custody even with matches in
    hand — another loop may hold the same image, and a dropped
    record would strand a live attachment with no recovery path.
    """
    try:
        matches, incomplete = scan_loop_by_backing(dev, ino)
    except AdmissionError:
        return None
    if incomplete:
        return None
    if len(matches) == 1:
        manifest["evidence"]["ext4_loop"] = matches[0]
        manifest["evidence"]["ext4_loop_backing"] = {
            "path": image, "dev": dev, "ino": ino,
        }
        drop_pending_acquisition(manifest, "loop", image)
        _persist_now(manifest)
        return matches[0]
    if not matches:
        drop_pending_acquisition(manifest, "loop", image)
        _persist_now(manifest)
        return None
    return None


def mount_fingerprint_matches(row, fingerprint):
    # S15-round3: the mount-fs helper reports the mount ID it
    # post-verified; when the caller carries it, the row must
    # be that mount — not merely the same source/type at the
    # target. (Uncertain paths omit it: no report exists.)
    if (fingerprint.get("mnt_id") is not None
            and row["mnt_id"] != fingerprint["mnt_id"]):
        return False
    if row["fstype"] != fingerprint.get("fstype"):
        return False
    if row["source"] != fingerprint.get("source"):
        return False
    for want in fingerprint.get("expect_super", []):
        if want not in row["super"]:
            return False
    return True


def _loop_fd_backing_verified(fd, live, backing):
    """loop_backing_verified against a retained device fd.

    S71-round6: identical semantics to
    [`loop_backing_verified`], but the kernel identity comes
    from the ALREADY-OPEN descriptor instead of a second
    open-by-name — a node swap between the two opens cannot
    split the proofs across different devices.
    """
    if live is None:
        return False
    if not isinstance(backing, dict) or not backing.get("path"):
        return False
    try:
        ident = _loop_get_status_on(fd)
    except LoopIdUnavailable:
        ident = None
    if ident is not None:
        return ((ident[0], ident[1]) == (backing.get("dev"),
                                        backing.get("ino")))
    return sysfs_backing_matches(live, backing["path"],
                                 backing.get("dev"),
                                 backing.get("ino"))


def _loop_fd_still_ours(fd, loop, backing):
    try:
        live = read_loop_backing(loop)
    except AdmissionError:
        return False
    if live is None:
        return False
    return _loop_fd_backing_verified(fd, live, backing)


def loop_single_fd_proof(target, loop, row, backing):
    """Backing validation + mount correspondence on ONE loop FD.

    S71-round6: opens the loop node once and runs both the
    backing-identity proof and the mount-correspondence proof
    against that retained descriptor. A /dev/loopN node
    substitution between two opens can no longer validate the
    backing on our device while matching correspondence on a
    foreign one — both proofs observe the same kernel object.
    Returns False when the node cannot be opened (gone is not
    proven here; callers treat False as unproven custody).
    """
    try:
        fd = os.open(loop, os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        if not _loop_fd_still_ours(fd, loop, backing):
            return False
        return _mount_matches_loop(
            target, loop, row, loop_fd=fd)
    finally:
        os.close(fd)


def _mount_matches_loop(target, loop, row, loop_fd=None):
    """True when the SELECTED row's filesystem sits on `loop`. (S71)

    Connects the mount row to the retained loop source: the
    mounted filesystem's device ID must equal the loop node's
    own device ID. A foreign loop occupying our target while
    our loop stays correctly bound (loop A ours, loop B
    mounted) mismatches and retains uncertainty — shape plus a
    separately bound loop never adopts.

    S71-round5: every pathname stat is replaced by a held
    descriptor. A device-node rename (or bind over /dev/loopN)
    between a validate-stat and a mount-stat defeats pathname
    evidence while the row spelling stays exact; descriptors
    cannot be swapped under us. The target side opens O_PATH
    and must carry the SELECTED row's mount ID (a swapped-in
    stranger fails even on the same node); the loop side uses
    the caller's retained fd when given (helper post-verify:
    the same description mount(2) sourced, never re-resolved)
    or a fresh O_PATH open otherwise (post-hoc adoption: a
    node swap after this open cannot redirect the fstat).
    Live kernel evidence at decision time (not the table
    snapshot's major:minor, which the parser does not retain);
    anything unreadable, unstatable, or mismatched refuses.
    """
    try:
        target_fd = os.open(target, os.O_PATH | os.O_NOFOLLOW
                            | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        try:
            mounted = os.fstat(target_fd).st_dev
        except OSError:
            return False
        try:
            live_mnt = _mnt_id_of(target_fd)
        except OSError:
            return False
        if live_mnt != row.get("mnt_id"):
            return False
        if loop_fd is not None:
            try:
                node = os.fstat(loop_fd)
            except OSError:
                return False
        else:
            try:
                node_fd = os.open(loop, os.O_PATH | os.O_NOFOLLOW
                                  | os.O_CLOEXEC)
            except OSError:
                return False
            try:
                node = os.fstat(node_fd)
            except OSError:
                return False
            finally:
                try:
                    os.close(node_fd)
                except OSError:
                    pass
    finally:
        try:
            os.close(target_fd)
        except OSError:
            pass
    if not stat.S_ISBLK(node.st_mode):
        return False
    return mounted == node.st_rdev


# S81-round4: single spelling of the overlay mount canary,
# shared by the controller (plant + uncertain-path adoption)
# and the helper (post-mount binding). A skew between the two
# sides would fail every overlay mount.
MOUNT_CANARY_NAME = ".tt04-mount-canary"

# S81-round6: pin-probe file prefix. The probe name carries a
# fresh random suffix per attempt (unpredictable: an attacker
# cannot pre-place it), and the probe content is generated in
# helper memory post-pin — never on disk before the pin, so a
# copied pre-mount token cannot mint a probe-passing clone.
MOUNT_PROBE_PREFIX = ".tt04-pin-probe-"

# S17-round4: advisory inter-helper lock for mount-table
# mutations. Every mount-fs create and every retire-mount
# detach holds LOCK_EX on this run-root file across its
# validate→effect→prove section, so two concurrent helpers
# can never stack at, move, or detach the same mountpoint
# under each other.
MOUNT_EXCLOCK_NAME = ".tt04-mount-lock"


def _mount_exclock_acquire(run_root):
    """Take the run-root mount-mutation lock. (S17-round4)

    Serializes this tool's own mount-table mutations: without
    it, a concurrent helper can stack a foreign mount at our
    target (or move ours away) after our validation, and our
    umount detaches the foreign top while the post-effect
    table read still shows ours as gone — a foreign detach
    misreported as our discharge. The lock is advisory among
    our own helpers only (a privileged third party racing
    mount(2)/umount(2) directly is out of scope); flock
    releases on crash, and sections are one helper call.
    Raises _HelperFail when the lock cannot be taken.
    """
    path = os.path.join(run_root, MOUNT_EXCLOCK_NAME)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        raise _HelperFail(f"mount lock unavailable: {exc}")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        raise _HelperFail(f"mount lock unavailable: {exc}")
    return fd


def _mount_exclock_release(fd):
    """Release a lock from _mount_exclock_acquire; never raises."""
    try:
        os.close(fd)  # closing releases the flock
    except OSError:
        pass


def _read_capped(fd, limit):
    """Read all bytes from fd `fd`; None when over `limit`/on error.

    Never partial content: oversize and I/O errors yield
    None. The fd stays open (caller owns it).
    """
    chunks = []
    total = 0
    while True:
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            return None
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            return None
    return b"".join(chunks)


def _read_bounded_nofollow(path, limit):
    """Read a file O_NOFOLLOW up to `limit` bytes; None on refusal.

    Symlinks, FIFOs (short reads still bounded), I/O errors and
    oversize all yield None — never partial content.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        return _read_capped(fd, limit)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _read_upper_canary(upper_fd):
    """Expected overlay token from the held upper layer. (S81-round5)

    The binding content comes from retained authority (the
    verified upper dir fd), never from helper argv: /proc
    cmdline is world-readable while the token file is 0600
    (S81-round6), so an argv token hands every local observer
    the content needed for a same-token replacement. Read
    pre-mount so the
    expected value is pinned before the interference window
    (a post-mount read could sample an attacker's rewrite).
    Raises _HelperFail when missing, unreadable, empty or
    non-ascii — pre-effect, mount never runs.
    """
    try:
        fd = os.open(MOUNT_CANARY_NAME,
                     os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=upper_fd)
    except OSError as exc:
        raise _HelperFail(
            f"overlay upper canary unreadable ({exc}); refusing")
    try:
        data = _read_capped(fd, 1024)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if data is None:
        raise _HelperFail(
            "overlay upper canary unreadable; refusing")
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise _HelperFail(
            "overlay upper canary not ascii; refusing")
    if not text:
        raise _HelperFail(
            "overlay upper canary empty; refusing")
    return text


def _canary_matches(target, name, content, run_root=None,
                    expect_mnt_id=None):
    """True when the pre-mount canary shows through `target`. (S15)

    Guards uncertain-path overlay adoption: super options no
    longer spell the layer paths (fd-bound layers record as
    /dev/fd/N), so a random canary written to upper before the
    effect proves the live mount binds our upper. Symlinks,
    FIFOs, oversized or wrong content all refuse.

    S81-round5: the read binds to the SELECTED row's mount ID
    (`expect_mnt_id`, required) — row selection and content
    proof were separate pathname observations, so a swapped-in
    same-token stranger passed both. The opened directory
    must carry the expected ID before the canary file is read
    through it (openat); the held dir fd then pins that mount
    for the read itself.

    S17-round5: under confinement the read routes through the
    keeper ns (the host sees the covered dir, never the mount);
    the helper reports bounded bytes as hex (argv carries only
    public paths — never the secret content). `run_root` is
    required for the routed read (helper-side containment);
    without it a confined read refuses.
    """
    if expect_mnt_id is None:
        return False
    try:
        want = content.encode("ascii")
    except (UnicodeError, AttributeError):
        return False
    ns = _ns_active()
    # S99-round6: inside processes read locally (the ns view
    # is their own); only outsiders re-exec the read.
    if ns is not None and not _inside_keeper_ns():
        if run_root is None:
            return False
        helper = os.path.abspath(__file__)
        rc, out, _ = run_sudo(
            [sys.executable, helper, "ns-canary",
             "--run-root", run_root,
             "--target", target, "--name", name,
             "--expect-mnt-id", str(expect_mnt_id)],
            timeout=60)
        if rc != 0:
            return False
        seen = out.strip()
        return len(seen) <= 2048 and seen == want.hex()
    try:
        dir_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY
                         | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        try:
            live_mnt = _mnt_id_of(dir_fd)
        except OSError:
            return False
        if live_mnt != expect_mnt_id:
            return False
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW
                         | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=dir_fd)
        except OSError:
            return False
        try:
            data = _read_capped(fd, 1024)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass
    if data is None:
        return False
    return data == want


def ns_canary_command(args):
    """Privileged-internal: bounded nofollow read as hex. (S17-round5)

    Never invoked by hand: _canary_matches re-execs this file
    under sudo+nsenter so the canary read sees the keeper-ns
    mount instead of the host's covered dir. Prints the file's
    bytes (at most 1024) as lowercase hex, or FAILED (exit 1).
    The caller (which holds the expected content) compares —
    argv never carries the secret.

    S81-round5: the read binds to --expect-mnt-id (the
    caller's selected row) — a swapped-in same-name stranger
    refuses before any byte is reported.
    """
    run_root = check_run_root(args.run_root)
    if run_root is None:
        print(f"FAILED: foreign run-root: {args.run_root[:80]!r}")
        return 1
    target = args.target or ""
    name = args.name or ""
    want_mnt = args.expect_mnt_id or ""
    if (not target or not name or len(target) > MAX_PATH
            or "/" in name or name in (".", "..")
            or not contained(target, run_root)
            or not want_mnt.isdigit()):
        print("FAILED: bad ns-canary argv")
        return 1
    try:
        dir_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY
                         | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        print(f"FAILED: target not openable: {exc}")
        return 1
    try:
        try:
            live_mnt = _mnt_id_of(dir_fd)
        except OSError as exc:
            print(f"FAILED: identity unreadable: {exc}")
            return 1
        if live_mnt != int(want_mnt):
            print(f"FAILED: mount mismatch (live={live_mnt} "
                  f"expected={want_mnt})")
            return 1
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW
                         | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=dir_fd)
        except OSError:
            print("FAILED: unreadable")
            return 1
        try:
            data = _read_capped(fd, 1024)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass
    if data is None:
        print("FAILED: unreadable")
        return 1
    print(data.hex())
    return 0


def reconcile_mount_effect(manifest, run_root, role, target, fingerprint,
                           loop=None, loop_backing=None,
                           canary=None, failure=None):
    """Adopt, clear, or retain a mount of uncertain outcome. (S23)

    Returns the adopted row, or None when the mount is absent
    (pending dropped) or the outcome stays uncertain (pending
    retained: stacked or foreign occupants are never adopted and
    never removed here).

    S15-round3: uncertain paths carry no helper report, so
    adoption additionally requires the ext4 loop to still bind
    our image (`loop`/`loop_backing`) or the overlay pre-mount
    canary to show through (`canary` as (name, content)). A
    /dev/fd/N row source matches a recorded loop-device source
    (the kernel echoes fd-bound operands literally); the loop
    binding check below is what makes that adoption sound.

    S74: `failure` is the mount_fs_via_helper report. A moved
    or otherwise post-effect-uncertain outcome keeps pending
    custody with the reported recovery identity (mount ID,
    observed mountpoint) — pending is never discharged from
    target absence when the effect may have fired. Only a
    refused-class failure (no effect possible) reaches the
    adopt-or-drop logic below.
    """
    if failure is not None:
        kind, mnt_id, observed = _classify_mount_failure(failure)
        if kind in ("moved", "uncertain"):
            kept = dict(fingerprint)
            if mnt_id is not None:
                kept["mnt_id"] = mnt_id
            if kind == "moved":
                where = (f"observed {observed} " if observed
                         is not None else "location unknown ")
                detail = (f"target moved during mount "
                          f"({where}mnt={mnt_id}); custody kept "
                          f"pending; manual retirement required")
            else:
                detail = ("mount outcome uncertain after "
                          "effect; custody kept pending")
            _refresh_mount_custody(manifest, role, target, kept,
                                   detail,
                                   observed_target=observed)
            return None
    try:
        table = read_mount_table()
    except AdmissionError:
        return None
    rows = find_mounts(table, target)
    if not rows:
        # S74-round5: no absence-based discharge while a known
        # mount ID is still live anywhere — a move-away keeps
        # it live elsewhere.
        known = (fingerprint or {}).get("mnt_id")
        if known is not None:
            live = [row for row in table
                    if row.get("mnt_id") == known]
            if live:
                kept = dict(fingerprint)
                _refresh_mount_custody(
                    manifest, role, target, kept,
                    f"mount {target} moved (mnt={known} live "
                    f"at {live[0]['target']}); custody kept "
                    f"pending",
                    observed_target=live[0]["target"])
                return None
        drop_pending_acquisition(manifest, "mount", target)
        _persist_now(manifest)
        return None
    if len(rows) != 1:
        return None
    if mount_fingerprint_matches(rows[0], fingerprint):
        adopt_fp = fingerprint
    elif (loop is not None and loop_backing is not None
            and _fd_spelling_loop_shape(rows[0], fingerprint)):
        # The kernel echoes fd-bound operands literally: adopt
        # under the OBSERVED spelling (the loop binding and
        # mount correspondence gates below are what make this
        # sound — and they now run for the exact spelling too).
        adopt_fp = dict(fingerprint, source=rows[0]["source"])
    else:
        return None
    if loop is not None and not loop_single_fd_proof(
            target, loop, rows[0], loop_backing):
        # S71-round5: EVERY loop-backed adoption proves
        # correspondence — exact spellings included. A
        # device-node rename defeats the row spelling and the
        # current-binding check together (both read the same
        # mutable name); only the descriptor-bound mount-ID +
        # device proof sees through it.
        # S71-round6: backing validation and correspondence
        # share ONE retained loop FD — a node substitution
        # between two opens can no longer split them.
        return None
    if canary is not None and not _canary_matches(
            target, canary[0], canary[1], run_root,
            expect_mnt_id=rows[0].get("mnt_id")):
        return None
    record_mount(manifest, run_root, role, target,
                 adopt_fp.get("expect_super", []),
                 expected=adopt_fp)
    drop_pending_acquisition(manifest, "mount", target)
    _persist_now(manifest)
    return rows[0]


def _fd_spelling_loop_shape(row, fingerprint):
    """Shape-only: fd-spelling row for a recorded loop mount. (S15)

    True when the row's fstype matches, the recorded source is
    a loop device, and the row source is an fd spelling. Never
    sufficient alone — callers must also run the single-FD
    backing + correspondence proof (see loop_single_fd_proof).
    """
    return (row["fstype"] == fingerprint.get("fstype")
            and str(fingerprint.get("source", "")).startswith(
                "/dev/loop")
            and str(row.get("source", "")).startswith("/dev/fd/"))


def mount_pending(manifest, target):
    return any(e.get("kind") == "mount" and e.get("key") == target
               for e in manifest.get("pending_acquisitions", []))


def _refresh_mount_custody(manifest, role, target, fingerprint,
                           detail, observed_target=None):
    """Refresh a mount pending record with full evidence. (S62-round4)

    The replacement carries the fingerprint's mount ID (known
    from the helper report at every rollback site) plus the
    prior record's binding evidence (overlay canary, ext4 loop
    backing) — recovery keeps every identity the acquisition
    proved. Single atomic persist via refresh_pending_acquisition.
    S74: `observed_target` records a moved mount's observed
    mountpoint for ID-keyed recovery.
    """
    old = {}
    for entry in manifest.get("pending_acquisitions", []):
        if entry.get("kind") == "mount" and entry.get("key") == target:
            old = entry
            break
    entry = {"kind": "mount", "key": target, "role": role,
             "target": target,
             "fstype": fingerprint.get("fstype"),
             "source": fingerprint.get("source"),
             "expect_super": fingerprint.get("expect_super", [])}
    if fingerprint.get("mnt_id") is not None:
        entry["mnt_id"] = fingerprint["mnt_id"]
    for key in ("canary", "loop_backing"):
        if key in old:
            entry[key] = old[key]
    if observed_target is not None:
        entry["observed_target"] = observed_target
    entry["detail"] = detail[:256]
    refresh_pending_acquisition(manifest, "mount", target, entry)


def rollback_owned_mount(manifest, run_root, role, target, fingerprint):
    """Undo a just-created mount only when it is provably ours.

    S16: the privileged retire helper re-validates the live mount
    against our fingerprint in-process; stacked, foreign, or
    re-sourced occupants make it refuse without effect, and the
    mount stays in pending custody. Returns a note for the cell.
    """
    try:
        table = read_mount_table()
    except AdmissionError as exc:
        # S62: replace semantics — pending custody is still held
        # (admission-first ordering), so refresh the record in
        # place instead of duplicating it.
        _refresh_mount_custody(
            manifest, role, target, fingerprint,
            f"rollback table unreadable: {exc}")
        return "rollback table unreadable; custody kept pending"
    if not find_mounts(table, target):
        # S74-round5: target absence is not a discharge when the
        # helper-reported mount ID is still live elsewhere (the
        # role directory may have been renamed after the
        # report) — refresh custody, never drop.
        known = (fingerprint or {}).get("mnt_id")
        if known is not None:
            live = [row for row in table
                    if row.get("mnt_id") == known]
            if live:
                _refresh_mount_custody(
                    manifest, role, target, fingerprint,
                    f"mount {target} moved (mnt={known} live "
                    f"at {live[0]['target']}); custody kept "
                    f"pending",
                    observed_target=live[0]["target"])
                return ("mount moved after create; custody kept "
                        "pending")
        drop_pending_acquisition(manifest, "mount", target)
        _persist_now(manifest)
        return "mount already absent; nothing rolled back"
    failure = retire_mount_via_helper(run_root, target, fingerprint)
    if failure is None:
        drop_pending_acquisition(manifest, "mount", target)
        _persist_now(manifest)
        return "owned mount rolled back"
    # S62: replace, not duplicate — the pre-admission pending
    # record is still held; refresh it with the refusal detail.
    _refresh_mount_custody(manifest, role, target, fingerprint,
                           failure)
    return f"rollback refused ({failure}); custody kept pending"


def detach_verified_loop(manifest, run_root, loop, backing):
    """Detach a loop only when its live backing is ours. (S16)

    On any refusal the loop stays in pending custody. Returns
    None on success (or when already detached), else a note.
    """
    failure = cleanup_loop_device(loop, backing, run_root)
    if failure is None:
        return None
    record_pending_acquisition(manifest, {
        "kind": "loop", "key": (backing or {}).get("path", loop),
        "loop": loop, "backing": backing,
        "detail": failure[:256],
    })
    return failure


def provision_ext4(manifest, run_root):
    cell = {"status": "skipped", "needs_privilege": True, "reason": ""}
    manifest["cells"]["FS01"] = cell
    if shutil.which("mkfs.ext4") is None:
        cell["reason"] = "missing mkfs.ext4 tool"
        return
    auth = _require_guard()
    img_fd = None
    try:
        auth.mkdir("ext4")
        img_fd, image = auth.open_new("ext4/fs01.img")
        try:
            os.ftruncate(img_fd, 64 << 20)
        except OSError as exc:
            cell["reason"] = f"ext4 image not truncatable: {exc}"
            return
        # S15-round3: the format runs inside the privileged
        # helper, which re-verifies the image identity itself and
        # formats via /dev/fd/N — the caller's pathname never
        # reaches a privileged resolver.
        img_st = os.fstat(img_fd)
        failure = make_ext4_via_helper(
            run_root, auth, image, img_st.st_dev, img_st.st_ino)
        if failure is not None:
            cell["reason"] = failure
            return
        # S18: the image descriptor stays open across attachment;
        # the recorded backing identity is this open file, and the
        # kernel's live association must match it before custody.
        image_st = os.fstat(img_fd)
        record_pending_acquisition(manifest, {
            "kind": "loop", "key": image,
            "image": image, "dev": image_st.st_dev,
            "ino": image_st.st_ino,
        })
        # S15-round3: the attach runs inside the privileged
        # helper (native LOOP_CONFIGURE on a verified fd); the
        # caller still re-verifies the live association before
        # adoption.
        loop, failure = attach_loop_via_helper(
            run_root, auth, image, image_st.st_dev,
            image_st.st_ino)
        if failure is None:
            if verify_loop_backing(loop, image, image_st):
                adopt_loop(manifest, image, loop, image_st)
            else:
                cell["reason"] = (
                    "losetup association not ours: kernel backing "
                    "identity differs from the held image; "
                    "acquisition kept pending")
                return
        else:
            # S23: a timeout (or any failed response) may still
            # have attached the image; reconcile through the
            # kernel's own backing identity, never the lost reply.
            loop = reconcile_loop_attach(
                manifest, image, image_st.st_dev, image_st.st_ino)
            if loop is None:
                if any(e.get("kind") == "loop"
                       and e.get("key") == image
                       for e in manifest.get(
                               "pending_acquisitions", [])):
                    cell["reason"] = (
                        "losetup outcome uncertain and backing "
                        "identity matches several loops; "
                        "acquisition kept pending")
                else:
                    cell["reason"] = failure
                return
        backing = manifest["evidence"]["ext4_loop_backing"]
        mnt = auth.mkdir("ext4/mnt", exist_ok=True)
        # S15-round3: creation-time observations for the mount-fs
        # helper, which re-verifies each identity itself and
        # mounts on /dev/fd/N — no caller pathname reaches a
        # privileged resolver. Ownership is folded into the
        # helper (fchown on a mount-correspondent fd).
        mnt_st = os.stat(mnt)
        record_pending_acquisition(manifest, {
            "kind": "mount", "key": mnt, "role": "ext4-fs01",
            "target": mnt, "fstype": "ext4", "source": loop,
            "expect_super": [],
            # S15-round3: proves an fd-spelling occupant is
            # ours when the helper report was lost (timeout).
            "loop_backing": dict(backing),
        })
        reported, failure = mount_fs_via_helper(
            run_root, auth, mnt, mnt_st.st_dev, mnt_st.st_ino,
            "ext4", loop=loop,
            backing=(backing["dev"], backing["ino"]),
            own=(os.geteuid(), os.getegid()))
        if failure is None:
            # S62: admission commits before pending custody is
            # dropped, and the sole row must match the retained
            # acquisition identity — the helper's reported mount
            # ID and super spelling join the fingerprint, so a
            # foreign replacement after a successful create is
            # refused, never adopted.
            expected = {"fstype": "ext4",
                        "source": reported[1],
                        "mnt_id": reported[0],
                        "expect_super": [reported[2]]}
            try:
                record_mount(manifest, run_root, "ext4-fs01", mnt,
                             expect_super=[reported[2]],
                             expected=expected)
            except AdmissionError as exc:
                # S16: admission refused (stacked/foreign) — roll
                # back only what is provably ours; the helper
                # refuses anything else and custody stays pending.
                note = rollback_owned_mount(
                    manifest, run_root, "ext4-fs01", mnt,
                    expected)
                detach_verified_loop(manifest, run_root, loop, backing)
                cell["reason"] = (
                    f"ext4 mount not admitted ({exc}); {note}")
                return
            drop_pending_acquisition(manifest, "mount", mnt)
        else:
            adopted = reconcile_mount_effect(
                manifest, run_root, "ext4-fs01", mnt, {
                    "fstype": "ext4", "source": loop,
                    "expect_super": [],
                }, loop=loop, loop_backing=backing,
                failure=failure)
            if adopted is None:
                if mount_pending(manifest, mnt):
                    detach_verified_loop(
                        manifest, run_root, loop, backing)
                    cell["reason"] = (
                        "ext4 mount outcome uncertain "
                        f"({failure[:160]}); custody kept "
                        "pending")
                else:
                    detach_verified_loop(
                        manifest, run_root, loop, backing)
                    cell["reason"] = failure
                return
        auth.write_bytes("ext4/mnt/a.bin", pattern_bytes(21, 8192))
        auth.link("ext4/mnt/a.bin", "ext4/mnt/alias.bin")
        auth.write_bytes("ext4/mnt/b.bin", pattern_bytes(22, 8192))
        record_file(manifest, "ext4-a", auth.abspath("ext4/mnt/a.bin"))
        record_file(manifest, "ext4-alias",
                     auth.abspath("ext4/mnt/alias.bin"))
        record_file(manifest, "ext4-b", auth.abspath("ext4/mnt/b.bin"))
        cell.update(status="provisioned",
                    detail=f"loop {loop} mounted; hardlink alias recorded")
        cell.pop("reason", None)
    except OSError as exc:
        cell["reason"] = f"ext4 provisioning I/O failed: {exc}"
    finally:
        if img_fd is not None:
            try:
                os.close(img_fd)
            except OSError:
                pass


def mount_overlay(manifest, run_root, role, opts, cell_name, lower_base=None):
    """Mount one overlay stack.

    ``lower_base`` overrides the lowerdir parent (FS05 puts its lower
    on tmpfs so layers span filesystems and xino=on is effective; the
    kernel ignores xino=on for same-fs stacks). Auxiliary layer roots
    are recorded in the manifest and retired by cleanup.
    """
    cell = manifest["cells"][cell_name]
    auth = _require_guard()
    base = auth.abspath(role)
    lower_parent = lower_base if lower_base else base
    lower_rel = (None if lower_base else f"{role}/lower")
    try:
        for sub in ("upper", "work", "merged"):
            auth.mkdirs(f"{role}/{sub}")
        if lower_rel is not None:
            auth.mkdirs(lower_rel)
            auth.write_bytes(f"{lower_rel}/shared.txt",
                             b"lower-original\n")
            auth.write_bytes(f"{lower_rel}/lower-only.txt",
                             b"lower-only\n")
        else:
            # FS05 lower lives on the tmpfs aux root (outside the
            # run-root authority); plain writes, identity-bound at
            # the aux record.
            aux_lower = Path(lower_parent) / "lower"
            # S13: the aux tree is deletion-gated (exclusive), so
            # its mode is pinned at creation.
            os.makedirs(aux_lower, mode=0o755, exist_ok=True)
            (aux_lower / "shared.txt").write_bytes(b"lower-original\n")
            (aux_lower / "lower-only.txt").write_bytes(b"lower-only\n")
        lower = os.path.join(lower_parent, "lower")
        upper = os.path.join(base, "upper")
        work = os.path.join(base, "work")
        merged = os.path.join(base, "merged")
        # S15-round3: creation-time observations for the mount-fs
        # helper, which re-verifies each identity itself and
        # mounts on /dev/fd/N — no caller pathname reaches a
        # privileged resolver. The pre-mount canary binds
        # uncertain-path adoption to our upper.
        canary = secrets.token_hex(16)
        # S81-round6: the token file is 0600 (O_EXCL create —
        # umask can only remove bits from 0600, never add) —
        # a world-readable token lets any local user mint a
        # copied-token pre-pin clone.
        auth.write_bytes(f"{role}/upper/{MOUNT_CANARY_NAME}",
                         canary.encode("ascii"), mode=0o600)
        layer_ids = {}
        for name, path in (("lower", lower), ("upper", upper),
                           ("work", work)):
            st = os.stat(path)
            layer_ids[name] = (path, st.st_dev, st.st_ino)
        merged_st = os.stat(merged)
        aux = None
        if lower_base is not None:
            ast = os.stat(lower_base)
            aux = (lower_base, ast.st_dev, ast.st_ino)
        record_pending_acquisition(manifest, {
            "kind": "mount", "key": merged, "role": role,
            "target": merged, "fstype": "overlay",
            "source": "overlay", "expect_super": [],
            "canary": canary,
        })
        reported, failure = mount_fs_via_helper(
            run_root, auth, merged, merged_st.st_dev,
            merged_st.st_ino, "overlay",
            layers=[("lower", *layer_ids["lower"]),
                    ("upper", *layer_ids["upper"]),
                    ("work", *layer_ids["work"])],
            extra_opts=opts, aux=aux)
        if failure is None:
            # S62: admission commits before pending custody is
            # dropped, and the sole row must match the retained
            # acquisition fingerprint — the helper's reported
            # mount ID and super spelling join it, so a foreign
            # replacement after a successful create is refused,
            # never adopted.
            expected = {"fstype": "overlay",
                        "source": reported[1],
                        "mnt_id": reported[0],
                        "expect_super": [reported[2]]}
            try:
                record_mount(manifest, run_root, role, merged,
                             expect_super=[reported[2]],
                             expected=expected)
            except AdmissionError as exc:
                # S16: roll back only the mount we can prove is
                # ours; anything else stays pending, never unmounted.
                note = rollback_owned_mount(
                    manifest, run_root, role, merged, expected)
                cell.update(status="unsupported",
                            reason=f"overlay mount not admitted ({exc}); "
                                   f"{note}")
                return False
            drop_pending_acquisition(manifest, "mount", merged)
        else:
            adopted = reconcile_mount_effect(
                manifest, run_root, role, merged, {
                    "fstype": "overlay", "source": "overlay",
                    "expect_super": [],
                }, canary=(MOUNT_CANARY_NAME, canary),
                failure=failure)
            if adopted is None:
                if mount_pending(manifest, merged):
                    cell.update(status="unsupported", reason=(
                        f"overlay mount outcome uncertain "
                        f"({role}: {failure[:160]}); "
                        f"custody kept pending"))
                else:
                    cell.update(status="unsupported", reason=(
                        f"overlay mount refused ({role}{opts or ''}): "
                        f"{failure}"))
                    manifest["evidence"][f"{role}_refusal"] = failure
                return False
        for entry in manifest["mounts"]:
            if entry["target"] == merged:
                entry["options"] = opts or "(defaults)"
        auth.write_bytes(f"{role}/upper/upper-only.txt", b"upper-only\n")
        record_file(manifest, f"{role}-merged-shared",
                    os.path.join(merged, "shared.txt"))
        manifest["evidence"][f"{role}_layout"] = {
            "lower": lower, "upper": upper,
            "work": work, "merged": merged,
        }
        cell.update(status="provisioned", detail=f"{role}{opts or ''} mounted")
        cell.pop("reason", None)
        return True
    except OSError as exc:
        cell.update(status="unsupported", reason=f"overlay I/O failed: {exc}")
        return False


def provision_overlays(manifest, run_root):
    for name in ("FS04", "FS05", "FS06", "FS07"):
        manifest["cells"][name] = {
            "status": "skipped", "needs_privilege": True, "reason": ""}
    if "overlay" not in (read_text_capped("/proc/filesystems", 65536) or ""):
        for name in ("FS04", "FS05", "FS06", "FS07"):
            manifest["cells"][name]["reason"] = \
                "overlay missing from /proc/filesystems"
        return
    ok_off = mount_overlay(
        manifest, run_root, "ov-xino-off", ",xino=off,metacopy=off", "FS04")
    manifest["cells"]["FS06"] = {
        "status": "provisioned" if ok_off else "skipped",
        "needs_privilege": True,
        **({"detail": "copy-up trigger runs live in the cell on "
                       "ov-xino-off/merged/shared.txt"}
           if ok_off else
           {"reason": "FS04 mount unavailable; copy-up has no live mount"}),
    }
    # FS05 lower on tmpfs: xino=on is ignored for same-fs stacks.
    aux = None
    try:
        aux = tempfile.mkdtemp(prefix="tt04-", dir="/dev/shm")
        aux_st = os.stat(aux)
        # R20: bind the aux identity at acquisition; cleanup
        # refuses a replacement at the recorded name.
        manifest.setdefault("aux_roots", []).append({
            "path": aux, "dev": aux_st.st_dev, "ino": aux_st.st_ino,
        })
        _persist_now(manifest)
    except OSError as exc:
        manifest["cells"]["FS05"]["reason"] = (
            f"tmpfs aux root unavailable: {exc}")
        aux = None
    if aux is not None:
        if mount_overlay(manifest, run_root, "ov-xino-on",
                         ",xino=on,metacopy=off", "FS05",
                         lower_base=aux):
            verify_xino_effective(manifest, run_root, aux)
    metacopy_ok = mount_overlay(
        manifest, run_root, "ov-metacopy", ",metacopy=on", "FS07")
    if metacopy_ok:
        manifest["cells"]["FS07"]["detail"] = \
            "metacopy=on profile mounted; transition verified live"


def verify_xino_effective(manifest, run_root, aux):
    """Confirm xino=on composes inodes; else degrade FS05 honestly."""
    cell = manifest["cells"]["FS05"]
    auth = _require_guard()
    try:
        lower_ino = os.stat(os.path.join(aux, "lower", "shared.txt")).st_ino
        merged_ino = auth.stat("ov-xino-on/merged/shared.txt").st_ino
    except RootReplacedError:
        raise
    except (OSError, AdmissionError) as exc:
        cell.update(status="unsupported",
                    reason=f"xino effectiveness unreadable: {exc}")
        return
    manifest["evidence"]["xino_on_inos"] = {
        "lower": lower_ino, "merged": merged_ino}
    if lower_ino == merged_ino:
        cell.update(status="unsupported", reason=(
            "xino=on ignored by kernel: merged ino == lower ino across "
            "filesystems; mount retained for the refusal branch"))
    else:
        cell["detail"] = (cell.get("detail", "")
                          + f"; composed ino {merged_ino} != lower {lower_ino}")


SLEEPER_PY = r"""
import mmap, os, sys, time
path, report, uid, gid = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
fd = os.open(path, os.O_RDONLY)
size = os.fstat(fd).st_size
mm = mmap.mmap(fd, 4096, access=mmap.ACCESS_READ)
addrs = []
for line in open("/proc/self/maps"):
    fields = line.split()
    if len(fields) >= 6 and fields[5] == path:
        addrs.append(fields[0])
with open(report, "w") as handle:
    handle.write(f"pid={os.getpid()}\nrange={addrs[0] if addrs else 'none'}\n")
    handle.write(f"size={size}\n")
# Drop to the observer uid: namespace setup needed root, but the
# sleeper itself must stay observable (exe/root/maps) unprivileged.
# setuid clears dumpability, so re-enable it explicitly afterwards.
import ctypes as _ctypes
os.setgid(int(gid))
os.setuid(int(uid))
_libc = _ctypes.CDLL("libc.so.6", use_errno=True)
if _libc.prctl(4, 1) != 0:
    raise OSError(_ctypes.get_errno(), "prctl PR_SET_DUMPABLE failed")
sys.stdout.write("ready\n")
sys.stdout.flush()
# Persist until cleanup retires this run; 600s naps ended mid-suite.
while True:
    time.sleep(600)
"""


def child_pids_with_errors(ppid):
    """(children of `ppid`, unobservable-entry count). (S21)

    A vanished entry (FileNotFoundError) is a transient exit and
    stays silent; denial, I/O failure, or malformed content counts
    as unknown — the caller cannot prove the child list complete.
    """
    found = []
    unknown = 0
    try:
        entries = os.listdir("/proc")
    except OSError:
        return [], 1
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "r") as handle:
                after = handle.read().rsplit(")", 1)[1].split()
            if int(after[1]) == ppid:
                found.append(int(entry))
        except FileNotFoundError:
            continue
        except (OSError, ValueError, IndexError):
            unknown += 1
    return sorted(found), unknown


def child_pids(ppid):
    found, _ = child_pids_with_errors(ppid)
    return found


def pin_proc(pid):
    """Hold a pidfd for `pid`. (S22)

    The returned fd addresses the task, not the number:
    signals must go through pidfd_send_signal on this fd (see
    signal_owned), never os.kill — the kernel MAY recycle the
    numeric pid after exit+reap while the fd is held, and only
    the descriptor-bound signal fails closed (ESRCH) instead
    of redirecting at whoever reused the number. Raises
    ProcAbsent when the pid is provably gone, ProcUnknown when
    it cannot be pinned.
    """
    if not hasattr(os, "pidfd_open"):
        raise ProcUnknown(f"proc {pid} unpinnable: no pidfd_open")
    try:
        return os.pidfd_open(pid, 0)
    except ProcessLookupError:
        raise ProcAbsent(f"proc {pid} absent")
    except PermissionError as exc:
        raise ProcUnknown(f"proc {pid} unpinnable: {exc}")
    except OSError as exc:
        if exc.errno in (errno.ESRCH, errno.ENOENT):
            raise ProcAbsent(f"proc {pid} absent")
        raise ProcUnknown(f"proc {pid} unpinnable: {exc}")


# Linux pidfd_send_signal number (asm-generic, synced to x86,
# x86-64, arm64 and riscv; the kernel guarantees these). Used
# only when the libc wrapper is absent.
_PIDFD_SEND_SIGNAL_NR = 424


def _pidfd_send_signal(pin_fd, signum):
    """Signal the task pinned by `pin_fd`; None ok else errno. (S22)

    pidfd_send_signal addresses the pinned task, never the
    numeric pid: exit+reap+reuse between observation and
    signal yields ESRCH instead of a redirected signal.
    Prefers the libc wrapper; falls back to the raw syscall
    number when the wrapper is absent (glibc < 2.32).
    """
    libc = _libc_handle()
    try:
        send = libc.pidfd_send_signal
    except AttributeError:
        send = None
    if send is not None:
        send.argtypes = [ctypes.c_int, ctypes.c_int,
                         ctypes.c_void_p, ctypes.c_uint]
        send.restype = ctypes.c_int
        if send(pin_fd, signum, None, 0) == 0:
            return None
        return ctypes.get_errno()
    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_long,
                             ctypes.c_long, ctypes.c_long,
                             ctypes.c_long]
    libc.syscall.restype = ctypes.c_long
    if libc.syscall(_PIDFD_SEND_SIGNAL_NR, pin_fd, signum,
                    0, 0) == 0:
        return None
    return ctypes.get_errno()


def stat_state_start(pid):
    """(state, starttime) for `pid`; never returns None. (S21)

    Raises ProcAbsent on proven absence, ProcUnknown on denial,
    I/O failure, or malformed content.
    """
    try:
        with open(f"/proc/{pid}/stat", "r") as handle:
            after = handle.read().rsplit(")", 1)[1].split()
        return (after[0], int(after[19]))
    except FileNotFoundError:
        raise ProcAbsent(f"proc {pid} absent")
    except (OSError, ValueError, IndexError) as exc:
        raise ProcUnknown(f"proc {pid} stat unreadable: {exc}")


def resolve_leaf(root_pid, timeout=15):
    """Follow the single-child wrapper chain to the childless sleeper.

    sudo/unshare/sh wrappers may exec (collapsing the chain) or fork;
    the leaf must persist across three consecutive samples so a
    transient mid-exec process is never recorded.
    """
    import time as _time
    deadline = _time.time() + timeout
    stable = None
    stable_hits = 0
    saw_unknown = False
    while True:
        pid = root_pid
        unknown = 0
        for _ in range(8):
            kids, missed = child_pids_with_errors(pid)
            unknown += missed
            kids = [k for k in kids if k != os.getpid()]
            if len(kids) != 1:
                break
            pid = kids[0]
        leaf_kids, missed = child_pids_with_errors(pid)
        unknown += missed
        if unknown:
            # S21: an unobservable descendant means the chain is
            # not proven single-child — never record through it.
            saw_unknown = True
            stable, stable_hits = None, 0
        elif pid != root_pid and not leaf_kids:
            if pid == stable:
                stable_hits += 1
                if stable_hits >= 3:
                    return pid
            else:
                stable, stable_hits = pid, 1
        else:
            stable, stable_hits = None, 0
        if _time.time() >= deadline:
            raise AdmissionError(
                f"no stable sleeper leaf under wrapper pid {root_pid}"
                + (" (unobservable descendants)"
                   if saw_unknown else ""))
        _time.sleep(0.1)


def write_sleeper(auth):
    return auth.write_bytes("ns/map_sleeper.py",
                            SLEEPER_PY.encode("utf-8"))


def readline_bounded(stream, timeout, max_bytes):
    """One readiness line, bounded in time and length. (S24)

    A wrapper that stays alive without completing a line (or
    floods output) must strand neither the create nor custody:
    the deadline caps the wait and max_bytes caps the read.
    """
    import time as _time
    sel = selectors.DefaultSelector()
    try:
        sel.register(stream, selectors.EVENT_READ)
    except (OSError, ValueError) as exc:
        raise AdmissionError(f"readiness stream not pollable: {exc}")
    try:
        deadline = _time.time() + timeout
        data = bytearray()
        fileno = stream.fileno()
        while True:
            remaining = deadline - _time.time()
            if remaining <= 0:
                raise AdmissionError(
                    f"readiness line not completed in {timeout}s")
            events = sel.select(timeout=remaining)
            if not events:
                raise AdmissionError(
                    f"readiness line not completed in {timeout}s")
            try:
                chunk = os.read(fileno, min(4096, max_bytes + 1 - len(data)))
            except OSError as exc:
                raise AdmissionError(f"readiness read failed: {exc}")
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                raise AdmissionError(
                    f"readiness line exceeds {max_bytes} bytes")
            if b"\n" in chunk:
                break
        return bytes(data)
    finally:
        sel.close()


def spawn_sleeper(helper, target_file, report, wrapper, manifest=None,
                  role="sleeper-wrapper", leaf_role=None,
                  ready_timeout=READY_TIMEOUT,
                  ready_max_bytes=READY_MAX_BYTES):
    """Start an owned mapping sleeper; returns (wrapper_pid, sleeper_pid).

    ``wrapper`` prefixes the argv (sudo/ns setup); the sleeper is the
    stable childless leaf under the spawned wrapper PID.

    S24: wrapper custody is armed immediately after Popen (a
    pending record persisted when a manifest is given) and the
    readiness line is a bounded poll. Every failure path kills
    the whole tree, checks the kill result, and — when the tree
    cannot be proven gone — persists the unresolved wrapper
    before raising.

    S21-round3: the pending-to-admitted handoff is transactional.
    The wrapper pending stays armed across the return, and the
    leaf pending is armed here too (``leaf_role`` names it, and is
    required whenever a manifest is given): the caller admits
    both ends and only then drops both pendings. A record_proc
    failure in between keeps both pendings, so no live process
    loses custody.
    """
    target_file = os.path.realpath(target_file)
    guard_verify()
    log = open(report + ".log", "wb")
    try:
        child = subprocess.Popen(
            [*wrapper, sys.executable, str(helper),
             str(target_file), report,
             str(os.geteuid()), str(os.getegid())],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=log, close_fds=True,
        )
    except OSError:
        log.close()
        raise
    # The child holds its own copy; ours would leak one fd per spawn.
    log.close()
    if manifest is not None:
        try:
            _, start = stat_state_start(child.pid)
        except (ProcAbsent, ProcUnknown):
            start = None
        record_pending_proc(
            manifest, role, child.pid, start,
            "sleeper wrapper armed before readiness")

    def fail(message):
        # R21: kill the whole tree, not just the wrapper — a
        # half-spawned leaf would otherwise run on unrecorded.
        # S21: the kill result is checked, never ignored; the
        # armed record refreshes in place on failure (never a
        # drop-then-record window) and drops only when the
        # tree is proven gone. (S21-round4.)
        gone = kill_tree(role, child.pid)
        try:
            child.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if manifest is not None:
            if not gone:
                refresh_pending_proc(
                    manifest, role, child.pid, None,
                    f"sleeper tree not proven gone: {message}")
            else:
                drop_pending_proc(manifest, role, child.pid)
        raise AdmissionError(message)

    try:
        line = readline_bounded(child.stdout, ready_timeout,
                                ready_max_bytes)
    except AdmissionError as exc:
        line = None
        ready_error = exc
    finally:
        try:
            child.stdout.close()
        except OSError:
            pass
    if line is None or line.strip() != b"ready":
        detail = "" if line is None else f" (got {line[:40]!r})"
        fail(f"sleeper for {target_file} never became ready{detail}"
             + (f": {ready_error}" if line is None else ""))
    try:
        sleeper = resolve_leaf(child.pid)
    except (OSError, AdmissionError) as exc:
        # R21: ready but no stable leaf to record — guard the
        # sleeper by killing the tree before refusing.
        fail(f"sleeper for {target_file} has no stable leaf: {exc}")
    if manifest is not None:
        # S21-round3: arm the leaf pending before returning; the
        # wrapper pending (armed above) stays too. The caller drops
        # both only after admitting both ends.
        if leaf_role is None:
            raise AdmissionError(
                "spawn_sleeper with a manifest requires leaf_role")
        try:
            _, leaf_start = stat_state_start(sleeper)
        except (ProcAbsent, ProcUnknown):
            leaf_start = None
        record_pending_proc(
            manifest, leaf_role, sleeper, leaf_start,
            "sleeper leaf armed before admission")
    guard_verify()
    return (child.pid, sleeper)


def bind_view_wrapper(alt, view):
    """Argv prefix mounting the foreign-view bind before the sleeper.

    R22: paths travel as positional parameters ($1/$2), never
    interpolated into the shell program — a run-root bearing
    spaces, semicolons or comment markers stays inert data.
    ``spawn_sleeper`` appends the interpreter argv after these, so
    the script shifts the two paths off and execs the rest.
    """
    return ["sudo", "-n", "unshare", "-m", "--propagation", "private",
            "sh", "-c",
            'mount --bind "$1" "$2" && shift 2 && exec "$@"',
            "tt04-view", str(alt), str(view)]


def provision_sleepers(manifest, run_root):
    cell = {"status": "skipped", "needs_privilege": True, "reason": ""}
    manifest["cells"]["FS08"] = cell
    auth = _require_guard()
    try:
        auth.mkdir("ns")
        auth.mkdir("ns/view")
        auth.mkdir("ns/alt")
        auth.write_bytes(
            "ns/view/data.txt",
            b"observer-view-bytes\n" + pattern_bytes(41, 8172))
        auth.write_bytes(
            "ns/alt/data.txt",
            b"foreign-view-bytes\n" + pattern_bytes(42, 8173))
        auth.write_bytes("ns/mapped.bin", pattern_bytes(31, 8192))
        helper = write_sleeper(auth)
        view = auth.abspath("ns/view")
        alt = auth.abspath("ns/alt")
        mapped = auth.abspath("ns/mapped.bin")
        # Foreign mount view: the sleeper overmounts view/ with alt/ in a
        # private mount namespace, then maps view/data.txt (foreign bytes)
        # plus the shared mapped.bin for the aligned control.
        mnt_wrap, mnt_sleep = spawn_sleeper(
            helper, os.path.join(view, "data.txt"),
            auth.abspath("ns/mnt.report"),
            bind_view_wrapper(alt, view), manifest,
            role="mnt-sleeper-wrapper", leaf_role="mnt-sleeper")
        record_proc(manifest, "mnt-sleeper-wrapper", mnt_wrap)
        record_proc(manifest, "mnt-sleeper", mnt_sleep)
        # S21-round3: transactional handoff — both pendings drop
        # only after both ends admit; an admission failure above
        # keeps both for cleanup retry.
        drop_pending_proc(manifest, "mnt-sleeper-wrapper", mnt_wrap)
        drop_pending_proc(manifest, "mnt-sleeper", mnt_sleep)
        time_wait_report(auth.abspath("ns/mnt.report"))
        pid_wrap, pid_sleep = spawn_sleeper(
            helper, mapped, auth.abspath("ns/pid.report"),
            ["sudo", "-n", "unshare", "-p", "-f", "--mount-proc"],
            manifest, role="pidns-sleeper-wrapper",
            leaf_role="pidns-sleeper")
        record_proc(manifest, "pidns-sleeper-wrapper", pid_wrap)
        record_proc(manifest, "pidns-sleeper", pid_sleep)
        drop_pending_proc(manifest, "pidns-sleeper-wrapper", pid_wrap)
        drop_pending_proc(manifest, "pidns-sleeper", pid_sleep)
        time_wait_report(auth.abspath("ns/pid.report"))
        # Pure pidns sleeper: --mount-proc implies a fresh mount
        # namespace, so a second sleeper without it isolates the pidns
        # boundary from mount-domain isolation.
        pure_wrap, pure_sleep = spawn_sleeper(
            helper, mapped, auth.abspath("ns/pure.report"),
            ["sudo", "-n", "unshare", "-p", "-f"],
            manifest, role="pure-pidns-wrapper",
            leaf_role="pure-pidns-sleeper")
        record_proc(manifest, "pure-pidns-wrapper", pure_wrap)
        record_proc(manifest, "pure-pidns-sleeper", pure_sleep)
        drop_pending_proc(manifest, "pure-pidns-wrapper", pure_wrap)
        drop_pending_proc(manifest, "pure-pidns-sleeper", pure_sleep)
        time_wait_report(auth.abspath("ns/pure.report"))
        nested = try_nested_pidns(manifest, auth, helper)
        provision_churn(manifest, run_root)
        provision_chroot(manifest, auth)
        manifest["evidence"]["ns_reports"] = {
            "mnt": auth.abspath("ns/mnt.report"),
            "pid": auth.abspath("ns/pid.report"),
            "pure": auth.abspath("ns/pure.report"),
        }
        cell.update(status="provisioned", detail=(
            "foreign-mount + pidns sleepers alive"
            + (" + nested pidns" if nested else "")))
        cell.pop("reason", None)
    except RootReplacedError:
        raise
    except (OSError, AdmissionError) as exc:
        cell["reason"] = f"sleeper provisioning failed: {exc}"


def time_wait_report(report, timeout=15):
    try:
        return poll_text_contains(report, "range=", timeout)
    except AdmissionError:
        raise AdmissionError(f"sleeper report never completed: {report}")


def try_nested_pidns(manifest, auth, helper):
    wrap = sleep = None
    try:
        wrap, sleep = spawn_sleeper(
            helper, auth.abspath("ns/mapped.bin"),
            auth.abspath("ns/nested.report"),
            ["sudo", "-n", "unshare", "-p", "-f", "--mount-proc",
             "unshare", "-p", "-f", "--mount-proc"],
            manifest, role="nested-pidns-sleeper-wrapper",
            leaf_role="nested-pidns-sleeper")
    except (OSError, AdmissionError):
        manifest["evidence"]["nested_pidns"] = "unsupported: nested unshare refused"
        return False
    try:
        ident = proc_identity(sleep)
    except AdmissionError as exc:
        # S21: never blindly signal an unobservable pid; persist
        # custody and let cleanup report/retry it. Each end
        # retires independently: an identity-change refusal
        # proves whoever was there gone-or-foreign, so the
        # other end still retires. Each spawn pending stays
        # armed across its retirement (which refreshes in
        # place on failure) and drops only on proven gone —
        # never dropped before its replacement commits.
        # (S21-round3, S21-round4.)
        for rrole, rpid in (("nested-pidns-sleeper", sleep),
                            ("nested-pidns-sleeper-wrapper", wrap)):
            try:
                gone = retire_fresh_proc(rrole, rpid, manifest)
            except ProcIdentityChanged:
                # Identity changed under the pin: the spawned
                # process is proven gone (a new occupant is a
                # stranger that was never signalled). Drop the
                # stale record. (S21-round5: ONLY this typed
                # outcome drops — a persistence/publication
                # AdmissionError from the retirement's refresh
                # propagates with custody retained.)
                drop_pending_proc(manifest, rrole, rpid)
                continue
            if gone:
                drop_pending_proc(manifest, rrole, rpid)
        manifest["evidence"]["nested_pidns"] = (
            f"unsupported: identity unreadable ({exc})")
        return False
    if len(ident["nspid"]) < 3:
        # S21-round4: custody transfers from the spawn pendings
        # to the tree kill — both records stay armed across the
        # kill and drop only when the tree is proven gone;
        # otherwise each refreshes in place with the failure.
        # S104-round6: the established spawn identities ride
        # along, so a recycled wrapper number is never
        # signalled and a reparented leaf still reconciles.
        armed = {}
        for rrole, rpid in (
                ("nested-pidns-sleeper-wrapper", wrap),
                ("nested-pidns-sleeper", sleep)):
            for entry in manifest.get("pending_procs", []):
                if (entry.get("role") == rrole
                        and entry.get("pid") == rpid):
                    armed[rpid] = entry.get("starttime")
                    break
        if not kill_tree("nested-pidns", wrap, armed=armed):
            try:
                _, wrap_start = stat_state_start(wrap)
            except (ProcAbsent, ProcUnknown):
                wrap_start = None
            refresh_pending_proc(
                manifest, "nested-pidns-sleeper-wrapper", wrap,
                wrap_start, "unsupported tree not proven gone")
            # S21-round3: the unproven member may be the leaf —
            # pend it too, so every unresolved process keeps a
            # record.
            try:
                _, sleep_start = stat_state_start(sleep)
            except (ProcAbsent, ProcUnknown):
                sleep_start = None
            refresh_pending_proc(
                manifest, "nested-pidns-sleeper", sleep,
                sleep_start, "unsupported tree not proven gone")
        else:
            drop_pending_proc(
                manifest, "nested-pidns-sleeper-wrapper", wrap)
            drop_pending_proc(manifest, "nested-pidns-sleeper",
                              sleep)
        manifest["evidence"]["nested_pidns"] = (
            f"unsupported: NSpid depth {len(ident['nspid'])} < 3")
        return False
    record_proc(manifest, "nested-pidns-sleeper-wrapper", wrap)
    record_proc(manifest, "nested-pidns-sleeper", sleep)
    # S21-round3: transactional handoff (see provision_sleepers).
    drop_pending_proc(manifest, "nested-pidns-sleeper-wrapper", wrap)
    drop_pending_proc(manifest, "nested-pidns-sleeper", sleep)
    time_wait_report(auth.abspath("ns/nested.report"))
    manifest["evidence"]["nested_pidns"] = "provisioned"
    return True


def signal_owned(pid, signum, pin_fd, expected_start):
    """Signal an owned PID through its pidfd pin. (S21/S22)

    `pin_fd` must be an open pidfd for `pid`: it is fstat'ed,
    the live starttime is re-verified against `expected_start`,
    and only then is the signal sent with pidfd_send_signal —
    which addresses the pinned task, never the numeric pid, so
    exit+reap+reuse between the observation and the signal
    yields ESRCH (gone) instead of a redirected signal. The
    EPERM escalation re-pins and re-verifies inside the
    privileged helper (same guarantee — the pin is opened,
    verified, and used inside that one process). Returns True
    when a signal was sent, False when the process was already
    gone. Raises AdmissionError on identity change, ProcUnknown
    when the pid cannot be observed.
    """
    if pin_fd is None:
        raise AdmissionError(
            f"refusing to signal pid {pid}: no retained pidfd")
    try:
        os.fstat(pin_fd)
    except OSError:
        raise ProcUnknown(
            f"refusing to signal pid {pid}: pidfd not held")
    try:
        state, start = stat_state_start(pid)
    except ProcAbsent:
        return False
    if state == "Z":
        return False
    if start != expected_start:
        raise AdmissionError(
            f"refusing to signal pid {pid}: starttime changed "
            f"(live={start} expected={expected_start})")
    err = _pidfd_send_signal(pin_fd, signum)
    if err is None:
        return True
    if err in (errno.ESRCH, errno.ENOENT):
        return False
    if err not in (errno.EPERM, errno.EACCES):
        raise ProcUnknown(
            f"signal to pid {pid} failed: {os.strerror(err)}")
    # Root-spawned sleepers cannot be signalled by the observer
    # uid; the privileged helper re-pins the pid, re-verifies
    # the expected starttime, and signals through its own held
    # pidfd — no numeric kill at any stage.
    return _signal_via_helper(pid, expected_start, signum)


def _signal_via_helper(pid, expected_start, signum):
    """Escalated pidfd-bound signal; True sent, False gone. (S22)

    The helper opens its own pidfd for `pid`, verifies the
    expected starttime, and signals through the held
    descriptor — reuse between this caller's observation and
    the privileged effect cannot redirect the signal (the
    verification or the descriptor-bound signal fails
    closed). Identity change raises AdmissionError; anything
    else unobservable raises ProcUnknown.
    """
    helper = os.path.abspath(__file__)
    rc, out, err = run_sudo(
        [sys.executable, helper, "signal-proc",
         "--pid", str(pid), "--starttime", str(expected_start),
         "--signum", str(signum)],
        timeout=120)
    if rc == 0 and out.startswith("signalled "):
        return True
    if rc == 0 and out.startswith("proc-gone "):
        return False
    if "identity changed" in (out or ""):
        raise AdmissionError(
            f"refusing to signal pid {pid}: {tail(out or err)}")
    raise ProcUnknown(
        f"signal to pid {pid} failed: {tail(out or err)}")


def signal_proc_command(args):
    """Privileged-internal: signal one verified pid via pidfd. (S22)

    Never invoked by hand: signal_owned re-execs this file
    under sudo when the observer uid gets EPERM, so the
    privileged signal re-pins the pid itself, re-verifies the
    expected starttime, and signals through the held pidfd —
    the pin is opened, verified, and used inside this one
    process, so pid reuse between the caller's observation and
    the effect cannot redirect the signal. Prints `signalled
    <pid>` or `proc-gone <pid>` (exit 0); `FAILED: <reason>`
    exit 1 (unobservable, or identity changed — the caller
    tells them apart by the marker).
    """
    try:
        pid = int(args.pid)
        starttime = int(args.starttime)
        signum = int(args.signum)
    except (TypeError, ValueError):
        print("FAILED: bad signal-proc argv")
        return 1
    if pid <= 0 or signum <= 0 or signum > 64 or starttime < 0:
        print("FAILED: bad signal-proc argv")
        return 1
    try:
        pin = pin_proc(pid)
    except ProcAbsent:
        print(f"proc-gone {pid}")
        return 0
    except ProcUnknown as exc:
        print(f"FAILED: {exc}")
        return 1
    try:
        try:
            state, start = stat_state_start(pid)
        except ProcAbsent:
            print(f"proc-gone {pid}")
            return 0
        except ProcUnknown as exc:
            print(f"FAILED: {exc}")
            return 1
        if state == "Z":
            print(f"proc-gone {pid}")
            return 0
        if start != starttime:
            print(f"FAILED: identity changed (live={start} "
                  f"expected={starttime})")
            return 1
        err = _pidfd_send_signal(pin, signum)
    finally:
        try:
            os.close(pin)
        except OSError:
            pass
    if err is None:
        print(f"signalled {pid}")
        return 0
    if err in (errno.ESRCH, errno.ENOENT):
        print(f"proc-gone {pid}")
        return 0
    print(f"FAILED: signal failed: {os.strerror(err)}")
    return 1


def kill_tree(role, root_pid, timeout=10, armed=None):
    """SIGTERM then SIGKILL a wrapper and every descendant (R21).

    Used when a spawn produced live processes but no stable leaf
    to record: killing the wrapper alone would orphan the leaf.
    Every pid is signalled through its pidfd pin
    (pidfd_send_signal, never a numeric kill), so pid reuse
    between observation and signal cannot redirect the kill
    (S22). Returns True only when the whole tree is proven
    gone; unobservable members or survivors yield False, never
    a silent True (S21).

    S104-round6: `armed` maps established pids to their armed
    starttimes (None when never observed). A member whose
    live starttime differs from its armed value is a recycled
    number: the ORIGINAL is proven gone (a new occupant is a
    stranger that was never signalled) and the stranger is
    never pinned, signalled, or descended into. Armed members
    seed the walk independently, so a known leaf is
    reconciled even when the wrapper is absent and it has
    reparented away. Callers retiring just-spawned children
    through a retained Popen handle (unreaped — the number
    cannot recycle) pass no armed map; callers retiring by
    recorded number must.
    """
    import signal as _signal
    import time as _time
    armed = dict(armed or {})
    pins = {}
    snap = {}
    # Armed members proven gone without signalling: absent at
    # observation, or holding a stranger (starttime mismatch).
    resolved = set()
    unknown = 0
    stack = [root_pid] + [pid for pid in armed
                          if pid != root_pid]
    seen = set()
    try:
        while stack:
            pid = stack.pop()
            if pid in seen:
                continue
            seen.add(pid)
            expect = armed.get(pid)
            try:
                pin = pin_proc(pid)
            except ProcAbsent:
                if pid in armed:
                    resolved.add(pid)
                continue
            except ProcUnknown:
                unknown += 1
                continue
            try:
                state, start = stat_state_start(pid)
            except ProcAbsent:
                os.close(pin)
                if pid in armed:
                    resolved.add(pid)
                continue
            except ProcUnknown:
                os.close(pin)
                unknown += 1
                continue
            if state == "Z":
                # Zombie: already dead; reaping is its parent's job.
                os.close(pin)
                if pid in armed:
                    resolved.add(pid)
                continue
            if expect is not None and start != expect:
                # Recycled number: the original is proven gone;
                # the stranger is never signalled or descended.
                os.close(pin)
                resolved.add(pid)
                continue
            pins[pid] = pin
            snap[pid] = start
            kids, missed = child_pids_with_errors(pid)
            unknown += missed
            stack.extend(kids)

        def still(pid):
            try:
                state, start = stat_state_start(pid)
            except ProcAbsent:
                return False
            except ProcUnknown:
                return True
            return state != "Z" and start == snap[pid]

        for signum in (_signal.SIGTERM, _signal.SIGKILL):
            for pid, pin in pins.items():
                try:
                    state, start = stat_state_start(pid)
                except ProcAbsent:
                    continue
                except ProcUnknown:
                    unknown += 1
                    continue
                if state == "Z" or start != snap[pid]:
                    continue
                try:
                    signal_owned(pid, signum, pin, snap[pid])
                except ProcUnknown:
                    unknown += 1
                except AdmissionError:
                    unknown += 1
            deadline = _time.time() + timeout
            while _time.time() < deadline:
                if not any(still(pid) for pid in snap):
                    break
                _time.sleep(0.05)
        # S104-round6: every armed member seeded above is now
        # either pinned in snap (governed by still()), proven
        # gone in resolved (absent, zombie, or recycled number
        # holding a stranger), or counted in unknown — so the
        # tree-gone plus unknown-free verdict below also
        # reconciles every recorded member with no extra clause.
        return not any(still(pid) for pid in snap) and unknown == 0
    finally:
        for pin in pins.values():
            try:
                os.close(pin)
            except OSError:
                pass


def kill_owned(role, pid, starttime, timeout=10):
    """SIGTERM then SIGKILL an owned PID bound to a pidfd pin.

    S21/S22: returns True only when the pid is proven gone;
    survivors yield False; identity change raises
    ProcIdentityChanged; unobservable state raises ProcUnknown. A
    starttime is required: callers that never observed one must
    use retire_fresh_proc, never a blind numeric kill.
    """
    import signal as _signal
    import time as _time
    if starttime is None:
        raise AdmissionError(
            f"refusing to kill pid {pid} ({role}) without identity")
    try:
        pin = pin_proc(pid)
    except ProcAbsent:
        return True
    try:
        try:
            state, start = stat_state_start(pid)
        except ProcAbsent:
            return True
        if state == "Z":
            return True
        if start != starttime:
            raise ProcIdentityChanged(
                f"refusing to kill pid {pid} ({role}): starttime changed")
        signal_owned(pid, _signal.SIGTERM, pin, starttime)
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            try:
                state, _ = stat_state_start(pid)
            except ProcAbsent:
                return True
            if state == "Z":
                return True
            _time.sleep(0.05)
        try:
            state, start = stat_state_start(pid)
        except ProcAbsent:
            return True
        if state == "Z":
            return True
        if start != starttime:
            raise ProcIdentityChanged(
                f"refusing to SIGKILL pid {pid} ({role}): "
                f"starttime changed")
        signal_owned(pid, _signal.SIGKILL, pin, starttime)
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            try:
                state, _ = stat_state_start(pid)
            except ProcAbsent:
                return True
            if state == "Z":
                return True
            _time.sleep(0.05)
        return False
    finally:
        try:
            os.close(pin)
        except OSError:
            pass


def retire_fresh_proc(role, pid, manifest=None, timeout=10):
    """Retire a just-spawned pid whose identity was never recorded.

    S21: pins the pid, observes its starttime under the pin, and
    kills only that identity. When the pid is unobservable the
    process is NOT blindly signalled: its custody is persisted as
    pending (when a manifest is given) and False is returned.
    Returns True only when the pid is proven gone.

    S21-round3: a False (survivor) result persists custody too —
    every unsuccessful retirement keeps a pending record,
    including plain survival.

    S21-round4: custody persists by refresh (replace in memory,
    persist once), so a pre-existing spawn pending is never
    dropped before its replacement commits — callers keep the
    spawn record armed across the call and drop only on a
    proven-gone True.

    S91-round5: when the manifest already arms a starttime for
    this (role, pid) and the fresh observation disagrees, the
    occupant is a recycled stranger — no signal is sent, the
    armed identity is preserved, and False is returned.
    """
    try:
        pin = pin_proc(pid)
    except ProcAbsent:
        return True
    except ProcUnknown as exc:
        if manifest is not None:
            refresh_pending_proc(manifest, role, pid, None, str(exc))
        return False
    try:
        try:
            state, start = stat_state_start(pid)
        except ProcAbsent:
            return True
        except ProcUnknown as exc:
            if manifest is not None:
                refresh_pending_proc(manifest, role, pid, None, str(exc))
            return False
        if state == "Z":
            return True
    finally:
        try:
            os.close(pin)
        except OSError:
            pass
    if manifest is not None:
        # S91-round5: the number may have been recycled under
        # an armed spawn record — a just-observed starttime
        # that disagrees with the armed one is a stranger that
        # must never be signalled. Fresh identity is killed
        # only when none was previously established.
        armed = None
        for entry in manifest.get("pending_procs", []):
            if (entry.get("role") == role
                    and entry.get("pid") == pid):
                armed = entry.get("starttime")
                break
        if armed is not None and armed != start:
            refresh_pending_proc(
                manifest, role, pid, start,
                "recycled occupant refused signal")
            return False
    try:
        gone = kill_owned(role, pid, start, timeout)
    except ProcUnknown as exc:
        if manifest is not None:
            refresh_pending_proc(manifest, role, pid, start, str(exc))
        return False
    if not gone and manifest is not None:
        # S21-round3: the survivor keeps a pending record with the
        # observed identity, so cleanup retries it by name.
        refresh_pending_proc(
            manifest, role, pid, start,
            "retirement did not prove the process gone")
    return gone


CHURN_DRIVER_PY = r"""
import ctypes, os, subprocess, sys
root, fifo, ack = sys.argv[1], sys.argv[2], sys.argv[3]
bind_dev, bind_ino = int(sys.argv[4]), int(sys.argv[5])
point = os.path.join(root, "churn", "point")
payload_a = os.path.join(root, "churn", "payload-a")
payload_b = os.path.join(root, "churn", "payload-b")
# S13: churn dirs are deletion-gated (exclusive); pin the mode.
os.makedirs(os.path.dirname(point), mode=0o755, exist_ok=True)
ledger = open(os.path.join(root, "churn", "ledger.log"), "a", buffering=1)
try:
    _libc = ctypes.CDLL("libc.so.6", use_errno=True)
except OSError:
    from ctypes.util import find_library as _find
    _libc = ctypes.CDLL(_find("c"), use_errno=True)
def run(argv):
    proc = subprocess.run(argv, capture_output=True, text=True)
    ledger.write(f"run={' '.join(argv)} rc={proc.returncode} "
                 f"err={proc.stderr.strip()[-200:]}\n")
    return proc.returncode
def unescape_mnt(field):
    # Same octal grammar as the host unescape_mountinfo; unknown
    # escapes refuse (return None) so undecodable rows never
    # compare equal to our target.
    out = []
    i = 0
    while i < len(field):
        char = field[i]
        if char != "\\":
            out.append(char)
            i += 1
            continue
        esc = field[i + 1:i + 4]
        if esc == "040":
            out.append(" ")
        elif esc == "011":
            out.append("\t")
        elif esc == "012":
            out.append("\n")
        elif esc == "134":
            out.append("\\")
        else:
            return None
        i += 4
    return "".join(out)
def read_table_text():
    # TT04_MOUNTINFO overrides the table path for tests only.
    table_path = os.environ.get("TT04_MOUNTINFO", "/proc/self/mountinfo")
    with open(table_path, "rb") as handle:
        return os.fsdecode(handle.read())
def rows_at(text, target):
    # S19: real mountinfo semantics — compare the UNESCAPED
    # target, and keep root/source/fstype/mnt_id for identity.
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" - ")
        if len(parts) != 2:
            continue
        pre, post = parts[0].split(), parts[1].split()
        if len(pre) < 6 or len(post) != 3:
            continue
        try:
            mnt_id = int(pre[0])
        except ValueError:
            continue
        tgt = unescape_mnt(pre[4])
        if tgt is None or tgt != target:
            continue
        root = unescape_mnt(pre[3])
        source = unescape_mnt(post[1])
        if root is None or source is None:
            continue
        found.append({"mnt_id": mnt_id, "root": root,
                      "target": tgt, "fstype": post[0],
                      "source": source, "super": post[2]})
    return found
def target_is_payload(target, payload, dev, ino):
    # S19: the retained object proof — the live object AT the
    # point must be our payload object. A bind mount covers the
    # point with the payload inode; anything else (underlying
    # file, foreign bind) differs.
    try:
        shown = os.stat(target)
        want = os.stat(payload)
    except OSError:
        return False
    return ((shown.st_dev, shown.st_ino)
            == (want.st_dev, want.st_ino)
            == (dev, ino))
def owned_bind_only(target, payload, dev, ino):
    # R18/S19: exactly one mount at the target, a real bind row
    # (the filesystem source, never the payload pathname), and
    # the live object at the target is our payload object.
    try:
        rows = rows_at(read_table_text(), target)
    except OSError:
        return False
    if len(rows) != 1:
        return False
    if rows[0]["source"] == payload:
        return False
    return target_is_payload(target, payload, dev, ino)
def detach(target):
    # In-process umount2: validation and effect share this
    # privileged process with no subprocess gap between them.
    path = os.fsencode(target)
    return _libc.umount2(path, 0)
def current_row(target):
    try:
        rows = rows_at(read_table_text(), target)
    except OSError:
        return None
    if len(rows) != 1:
        return None
    return rows[0]
expected = None
ledger.write("driver-ready\n")
# Self-held RDWR descriptor: writers come and go per command, and
# without it the first writer close delivers EOF and ends the loop.
hold = os.open(fifo, os.O_RDWR)
with open(fifo, "r") as commands:
    for line in commands:
        cmd = line.strip()
        ledger.write(f"cmd={cmd}\n")
        if cmd == "bind-b":
            rc = run(["mount", "--bind", payload_b, point])
            if rc == 0:
                row = current_row(point)
                if (row is not None
                        and target_is_payload(point, payload_b,
                                              bind_dev, bind_ino)):
                    expected = row
                    open(ack, "w").write(
                        f"bind-b rc=0 mnt={row['mnt_id']}\n")
                else:
                    expected = None
                    ledger.write("bind-b: occupant not ours; "
                                 "retained as foreign\n")
                    open(ack, "w").write("bind-b rc=1\n")
            else:
                expected = None
                open(ack, "w").write(f"bind-b rc={rc}\n")
        elif cmd == "restore":
            row = current_row(point)
            if (expected is not None and row is not None
                    and row == expected
                    and owned_bind_only(point, payload_b,
                                        bind_dev, bind_ino)):
                rc = detach(point)
                if rc == 0:
                    after = current_row(point)
                    if after is None:
                        expected = None
                        open(ack, "w").write("restore rc=0\n")
                    else:
                        ledger.write("restore: still mounted after "
                                     "detach; retained\n")
                        open(ack, "w").write("restore rc=1\n")
                else:
                    ledger.write(f"restore: detach failed rc={rc}\n")
                    open(ack, "w").write(f"restore rc={rc}\n")
            else:
                ledger.write("restore-refused: foreign occupant\n")
                rc = 77
                open(ack, "w").write("restore rc=77\n")
        elif cmd == "quit":
            open(ack, "w").write("quit rc=0\n")
            break
        else:
            open(ack, "w").write(f"unknown rc=99 cmd={cmd[:32]}\n")
ledger.write("driver-exit\n")
"""


def provision_churn(manifest, run_root):
    auth = _require_guard()
    auth.mkdirs("churn")
    auth.write_bytes("churn/payload-a", b"churn-payload-a\n")
    auth.write_bytes("churn/payload-b", b"churn-payload-b\n")
    auth.write_bytes("churn/point", b"churn-payload-a\n")
    driver = auth.write_bytes("churn/driver.py",
                              CHURN_DRIVER_PY.encode("utf-8"))
    fifo = auth.mkfifo("churn/cmd.fifo")
    ack = auth.abspath("churn/ack.txt")
    ledger = auth.abspath("churn/ledger.log")
    point = auth.abspath("churn/point")
    payload = auth.abspath("churn/payload-b")
    payload_st = auth.stat("churn/payload-b")
    auth.verify()
    log = open(auth.abspath("churn/driver.log"), "wb")
    try:
        child = subprocess.Popen(
            ["sudo", "-n", sys.executable, driver,
             run_root, fifo, ack,
             str(payload_st.st_dev), str(payload_st.st_ino)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            close_fds=True)
    except OSError as exc:
        log.close()
        raise AdmissionError(f"churn driver spawn failed: {exc}")
    # The driver holds its own copies; ours would leak one fd per run.
    log.close()
    try:
        poll_text_contains(ledger, "driver-ready", 15)
    except AdmissionError:
        # S21: an unreadable ledger is not a dead driver — kill
        # the whole tree and check the result before refusing.
        gone = kill_tree("churn-driver", child.pid)
        try:
            child.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if not gone:
            record_pending_proc(
                manifest, "churn-driver", child.pid, None,
                "driver never ready and tree not proven gone")
        raise AdmissionError("churn driver never became ready")
    record_proc(manifest, "churn-driver", child.pid)
    manifest["evidence"]["churn"] = {
        "fifo": fifo, "ack": ack,
        "ledger": ledger, "point": point,
        # R18/S19: the only mount this point may ever host is our
        # own payload-b bind; teardown refuses anything else. The
        # bind object identity (not the mountinfo source, which is
        # the filesystem source) is the ownership proof.
        "bind_source": payload,
        "bind_source_dev": payload_st.st_dev,
        "bind_source_ino": payload_st.st_ino,
    }


def is_static_elf(path):
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
        if head != b"\x7fELF":
            return False
        proc = subprocess.run(
            ["file", "-b", path], capture_output=True,
            text=True, timeout=30)
        return "statically linked" in (proc.stdout or "")
    except (OSError, subprocess.TimeoutExpired):
        return False


def provision_chroot(manifest, auth):
    """Replaced-root sleeper: static busybox sleeping inside a chroot.

    Runs as the observer uid (--userspec) so /proc/PID/root stays
    readable unprivileged; readiness IS the replaced-root proof.
    """
    payload = None
    for candidate in ("/bin/busybox.static", "/bin/busybox",
                      "/usr/bin/busybox.static", "/usr/bin/busybox"):
        if is_static_elf(candidate):
            payload = candidate
            break
    if payload is None:
        manifest["evidence"]["chroot"] = (
            "unsupported: no statically linked chroot payload found")
        return
    try:
        auth.mkdirs("ns/chroot/bin")
        auth.copy_from(payload, "ns/chroot/bin/busybox")
        root = auth.abspath("ns/chroot")
        auth.verify()
        child = subprocess.Popen(
            ["sudo", "-n", "chroot",
             f"--userspec={os.geteuid()}:{os.getegid()}",
             root, "/bin/busybox", "sleep", "86400"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True)
    except RootReplacedError:
        raise
    except (OSError, AdmissionError) as exc:
        manifest["evidence"]["chroot"] = (
            f"unsupported: chroot spawn failed: {exc}")
        return
    import time as _time
    try:
        sleeper = resolve_leaf(child.pid)
    except (OSError, AdmissionError):
        # R21: spawned but no stable leaf to record — kill the
        # tree so no unrecorded sleeper survives. S21: the kill
        # result is checked and unresolved custody persists.
        gone = kill_tree("chroot-wrapper", child.pid)
        try:
            child.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if gone:
            note = "wrapper tree killed"
        else:
            record_pending_proc(
                manifest, "chroot-wrapper", child.pid, None,
                "chroot leaf never stabilized; tree not proven gone")
            note = "wrapper tree NOT proven gone; custody pending"
        manifest["evidence"]["chroot"] = (
            f"unsupported: chroot leaf never stabilized; {note}")
        return
    try:
        deadline = _time.time() + 15
        seen = None
        while _time.time() < deadline:
            try:
                seen = os.readlink(f"/proc/{sleeper}/root")
            except OSError:
                seen = None
            if seen == os.path.realpath(root):
                break
            _time.sleep(0.05)
        if seen != os.path.realpath(root):
            # S21: retire by observed identity, never blind; on
            # failure the pending record keeps custody.
            if not retire_fresh_proc("chroot-sleeper", sleeper,
                                     manifest):
                record_pending_proc(
                    manifest, "chroot-wrapper", child.pid, None,
                    "root link never showed chroot; tree unresolved")
            manifest["evidence"]["chroot"] = (
                f"unsupported: root link never showed chroot (saw {seen!r})")
            return
        record_proc(manifest, "chroot-wrapper", child.pid)
        record_proc(manifest, "chroot-sleeper", sleeper)
        manifest["evidence"]["chroot"] = {
            "root": os.path.realpath(root), "payload": payload,
            "sleeper": sleeper,
        }
    except (OSError, AdmissionError) as exc:
        manifest["evidence"]["chroot"] = (
            f"unsupported: chroot fixture failed: {exc}")


def fresh_manifest(run_root, privileged, mount_ns=None):
    """New manifest; mount_ns binds the keeper identity. (S100)

    `mount_ns` defaults from the current binding: the ensured
    keeper's {"pid","nsid","starttime"} dict, else False (no
    mounts possible unensured). Pass explicitly to pin a
    binding (tests) — never to forge one.
    """
    if mount_ns is None:
        if (_MOUNT_NS is not None and _MOUNT_NS != "direct"
                and _MOUNT_NS_IDENTITY is not None):
            pid, nsid, starttime, _canary = _MOUNT_NS_IDENTITY
            mount_ns = {"pid": pid, "nsid": nsid,
                        "starttime": starttime}
        else:
            mount_ns = False
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    run_id = f"tt04-{os.getpid()}-{stamp.replace(':', '').replace('+', '')}"
    cells = {}
    for cell in CELLS:
        if cell["needs_privilege"] and not privileged:
            cells[cell["name"]] = {
                "status": "skipped", "needs_privilege": True,
                "reason": ("missing --privileged grant: rerun create "
                           "--privileged with working sudo -n"),
            }
    return {
        "schema": SCHEMA_MANIFEST, "run_id": run_id,
        "run_root": run_root, "created_utc": stamp,
        "euid": os.geteuid(), "privilege_granted": privileged,
        # S17-round5: ns-native manifest (mounts confined to the
        # keeper ns; absence of this key means pre-ns/host).
        # S100-round6: the key carries the bound keeper
        # identity {"pid","nsid","starttime"} (False when no
        # keeper is bound); True survives only on manifests
        # written by round-5 code (adopt-current).
        "mount_ns": mount_ns,
        "kernel": host_capabilities(), "cells": cells,
        "mounts": [], "procs": [], "files": [], "evidence": {},
        "aux_roots": [],
        # S21/S24: processes whose retirement is not proven.
        "pending_procs": [],
        # S16/S23: kernel acquisitions of uncertain outcome.
        "pending_acquisitions": [],
        # F09: lifecycle of the recovery record itself. "creating"
        # until the final save flips it to "complete"; a failure
        # mid-create persists "failed" with the error and partial
        # custody instead of leaving live resources unrecorded.
        "status": "creating",
        # F08: run-root (dev, ino) bound right after mkdir; cleanup
        # refuses to destroy a replacement with a different identity.
        "run_root_identity": {},
    }


def create_command(args):
    global _PERSIST, _ROOT_GUARD
    run_root = check_run_root(args.run_root)
    if run_root is None:
        return fail2(f"foreign run-root: {args.run_root[:80]!r}")
    if os.path.exists(args.manifest):
        return fail2(f"already provisioned: {args.manifest} exists; "
                     "run cleanup first")
    if args.privileged:
        refusal = _refuse_without_sudo_grant()
        if refusal is not None:
            return fail2(refusal)
    manifest = fresh_manifest(run_root, args.privileged)
    try:
        # S13: the run root is deletion-gated (exclusive), so its
        # mode is pinned at creation, atomically with the mkdir.
        os.makedirs(run_root, mode=0o755, exist_ok=False)
    except FileExistsError:
        return fail2(f"already provisioned: run-root {run_root} exists; "
                     "run cleanup first")
    except OSError as exc:
        return fail2(f"run-root not creatable: {exc}")
    # F08/S15: hold the anchor from creation on; the recorded
    # identity is the held descriptor's, and every fixture write
    # below goes through it.
    try:
        guard = RootAuthority(run_root)
    except RootAuthorityError as exc:
        return fail2(f"run-root not statable: {exc}")
    manifest["run_root_identity"] = {
        "dev": guard.dev, "ino": guard.ino,
    }
    # F09: exclusive durable recovery record before any acquisition.
    # A missing manifest parent (or a lost creation race) now fails
    # here — before mounts, procs and files exist — instead of after
    # effects occurred. The just-created empty anchor is removed with
    # rmdir (which only removes empty dirs) on this narrow path.
    try:
        fd = os.open(args.manifest,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        guard.close()
        try:
            os.rmdir(run_root)
        except OSError:
            pass
        return fail2(f"already provisioned: {args.manifest} exists; "
                     "run cleanup first")
    except OSError as exc:
        guard.close()
        try:
            os.rmdir(run_root)
        except OSError:
            pass
        return fail2(f"manifest not creatable: {exc}")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    _PERSIST = args.manifest
    _ROOT_GUARD = guard
    try:
        create_unprivileged(manifest, run_root)
        guard.verify()
        save_manifest(manifest, args.manifest)
        if args.privileged:
            provision_ext4(manifest, run_root)
            guard.verify()
            save_manifest(manifest, args.manifest)
            provision_overlays(manifest, run_root)
            guard.verify()
            save_manifest(manifest, args.manifest)
            provision_sleepers(manifest, run_root)
            guard.verify()
            save_manifest(manifest, args.manifest)
    except AdmissionError as exc:
        # F09: preserve partial custody on failure instead of leaving
        # live resources unrecorded; cleanup can retire them.
        manifest["status"] = "failed"
        manifest["error"] = str(exc)
        try:
            save_manifest(manifest, args.manifest)
        except (OSError, AdmissionError):
            pass
        return fail2(f"provisioning refused: {exc}")
    except (OSError, subprocess.TimeoutExpired) as exc:
        manifest["status"] = "failed"
        manifest["error"] = f"I/O failure: {exc}"
        try:
            save_manifest(manifest, args.manifest)
        except (OSError, AdmissionError):
            pass
        print(f"create: FAILED {exc}")
        return 1
    finally:
        _PERSIST = None
        _ROOT_GUARD = None
        guard.close()
    manifest["status"] = "complete"
    save_manifest(manifest, args.manifest)
    provisioned = sum(1 for c in manifest["cells"].values()
                      if c.get("status") == "provisioned")
    print(f"created {run_root}: {provisioned} cells provisioned, "
          f"{len(manifest['mounts'])} mounts, {len(manifest['procs'])} procs")
    return 0


def load_manifest(path, run_root):
    try:
        raw, _ = read_regular_capped(path, MAX_FILE_BYTES)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, AdmissionError) as exc:
        raise AdmissionError(f"manifest unreadable: {exc}")
    if data.get("schema") != SCHEMA_MANIFEST:
        raise AdmissionError("manifest schema mismatch")
    if data.get("run_root") != run_root:
        raise AdmissionError(
            f"run-root mismatch: manifest={data.get('run_root')} "
            f"arg={run_root}")
    return data


def admit_file(record, run_root):
    path = record.get("path", "")
    if not path or len(path) > MAX_PATH or not contained(path, run_root):
        raise AdmissionError(f"foreign file path: {path[:80]!r}")
    try:
        data, st = read_regular_capped(path, MAX_FILE_BYTES)
    except AdmissionError as exc:
        raise AdmissionError(
            f"file {record.get('role')} unreadable: {exc}")
    if (st.st_dev != record.get("dev") or st.st_ino != record.get("ino")
            or len(data) != record.get("size")):
        raise AdmissionError(
            f"file {record.get('role')} identity changed: "
            f"live=({st.st_dev},{st.st_ino},{st.st_size})")
    if hashlib.sha256(data).hexdigest() != record.get("sha256"):
        raise AdmissionError(
            f"file {record.get('role')} content changed")


def admit_proc(record):
    ident = proc_identity(record.get("pid", -1))
    if ident["starttime"] != record.get("starttime"):
        raise AdmissionError(
            f"proc {record.get('role')} identity changed "
            f"(pid {record.get('pid')} reused or exited)")
    return ident


def inspect_command(args):
    run_root = check_run_root(args.run_root)
    if run_root is None:
        return fail2(f"foreign run-root: {args.run_root[:80]!r}")
    try:
        manifest = load_manifest(args.manifest, run_root)
        # S100-round6: ns-identity mismatch/unavailability
        # refuses here (never a host-table fallback).
        _apply_manifest_ns_mode(manifest)
    except AdmissionError as exc:
        print(f"inspect: REFUSED {exc}")
        return 1
    try:
        # S15: the root identity gates every other admission — a
        # manifest mixing the original root identity with a
        # replacement's file records must refuse here.
        if not admit_run_root_identity(manifest, run_root):
            raise AdmissionError("run-root retired; nothing to admit")
        if manifest.get("pending_procs"):
            raise AdmissionError(
                f"{len(manifest['pending_procs'])} unretired "
                f"process(es) in custody")
        if manifest.get("pending_acquisitions"):
            raise AdmissionError(
                f"{len(manifest['pending_acquisitions'])} uncertain "
                f"acquisition(s) in custody")
        table = read_mount_table()
        for entry in manifest["mounts"]:
            admit_mount(entry, table, run_root)
        for entry in manifest["procs"]:
            admit_proc(entry)
        for entry in manifest["files"]:
            admit_file(entry, run_root)
        for aux in manifest.get("aux_roots", []):
            if not isinstance(aux, dict):
                raise AdmissionError(
                    f"aux root record malformed: {str(aux)[:60]!r}")
            norm = os.path.normpath(aux.get("path", ""))
            if not norm.startswith("/dev/shm/tt04-") or ".." in norm:
                raise AdmissionError(
                    f"foreign aux root: {aux.get('path', '')[:60]!r}")
            try:
                lst = os.lstat(norm)
            except OSError as exc:
                raise AdmissionError(
                    f"aux root missing: {norm[:60]!r} ({exc})")
            if stat.S_ISLNK(lst.st_mode):
                raise AdmissionError(
                    f"aux root replaced by symlink: {norm[:60]!r}")
            if ((lst.st_dev, lst.st_ino)
                    != (aux.get("dev"), aux.get("ino"))):
                raise AdmissionError(
                    f"aux root identity changed: {norm[:60]!r}")
        for name, cell in manifest["cells"].items():
            if cell.get("status") not in (
                    "provisioned", "skipped", "unsupported"):
                raise AdmissionError(f"cell {name} has invalid status")
            if cell.get("status") != "provisioned" and not cell.get("reason"):
                raise AdmissionError(f"cell {name} lacks a skip reason")
    except AdmissionError as exc:
        print(f"inspect: REFUSED {exc}")
        return 1
    print(f"inspect: admitted {len(manifest['mounts'])} mounts, "
          f"{len(manifest['procs'])} procs, {len(manifest['files'])} files")
    return 0


def admit_run_root_identity(manifest, run_root):
    """F08: verify the live run-root is the recorded one.

    Returns True when present and admitted, False when already gone
    (the idempotent retired path). Raises on a replacement: a
    different (dev, ino) — including a symlink swapped in for the
    recorded directory — must never be destroyed by a repeated
    cleanup. Manifests predating the identity record fail closed.
    R42: only proven absence (ENOENT) reads as retired; denial or
    I/O failure raises, so residue behind an unreadable parent
    never reports success.
    """
    try:
        st = os.stat(run_root)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AdmissionError(
            f"run-root not provably absent at {run_root}: {exc}")
    rec = manifest.get("run_root_identity") or {}
    if (st.st_dev, st.st_ino) != (rec.get("dev"), rec.get("ino")):
        raise AdmissionError(
            f"run-root identity changed at {run_root}: "
            f"live=({st.st_dev},{st.st_ino}) "
            f"manifest=({rec.get('dev')},{rec.get('ino')}); "
            f"replacement refused")
    return True


def _libc_handle():
    try:
        return ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        from ctypes.util import find_library
        found = find_library("c")
        if not found:
            raise AdmissionError("no C library for umount2")
        return ctypes.CDLL(found, use_errno=True)


def _umount2(target):
    """In-process umount2; returns None on success, else errno."""
    libc = _libc_handle()
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.umount2.restype = ctypes.c_int
    rc = libc.umount2(os.fsencode(target), 0)
    if rc == 0:
        return None
    return ctypes.get_errno()


_MS_MOVE = 8192


def _mount_move(source, target):
    """In-process MS_MOVE; returns None on success, else errno.

    (S17-round5: the move half of move-verify-detach.)
    """
    libc = _libc_handle()
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_char_p, ctypes.c_ulong,
                           ctypes.c_char_p]
    libc.mount.restype = ctypes.c_int
    rc = libc.mount(os.fsencode(source), os.fsencode(target),
                    None, _MS_MOVE, None)
    if rc == 0:
        return None
    return ctypes.get_errno()


def _retire_stage_dir(run_root):
    """Exclusively create a private retire-staging dir. (S17-round5)

    Random suffix (unpredictable to racers); 0700. Returns the
    path. Raises AdmissionError when it cannot be created.
    """
    for _ in range(8):
        path = os.path.join(
            run_root, f".tt04-retire-{secrets.token_hex(8)}")
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            continue
        except OSError as exc:
            raise AdmissionError(
                f"retire staging not creatable: {exc}")
        return path
    raise AdmissionError(
        "retire staging not creatable: collisions")


def _loop_get_status_on(fd):
    """(dev, ino) of the backing bound to held loop fd `fd`.

    S17-round3: LOOP_GET_STATUS64 addressed to an already-open
    device description — no pathname resolution, so a
    device-node swap between validation and effect cannot
    redirect the read. Returns None only when provably
    detached (ENXIO); raises LoopIdUnavailable when the status
    cannot be read — unknown, never detached.
    """
    buf = bytearray(LOOP_INFO64_SIZE)
    try:
        fcntl.ioctl(fd, LOOP_GET_STATUS64, buf, True)
    except OSError as exc:
        if exc.errno == errno.ENXIO:
            return None
        raise LoopIdUnavailable(f"loop status unreadable: {exc}")
    dev, ino = struct.unpack_from("<QQ", buf)
    return (dev, ino)


def _loop_clr_fd_on(fd):
    """In-process LOOP_CLR_FD on held loop fd `fd`.

    S17-round3: the detach addresses the same open device
    description the final validation read — no re-open, no
    re-resolution. Returns None on success, else errno.
    """
    try:
        fcntl.ioctl(fd, LOOP_CLR_FD)
    except OSError as exc:
        return exc.errno or errno.EIO
    return None


def retire_mount_now(target, expected, run_root):
    """Validate and detach one mount in this process. (S17)

    `expected` carries target/fstype/source/expect_super and,
    when recorded, mnt_id/root. The target directory's mount
    ID is snapshotted at open (the descriptor is closed before
    the effect — any open fd on the mount, O_PATH included,
    pins umount EBUSY, verified live); every table observation
    must agree with that snapshot (a replica replacement the
    record alone would admit refuses); the validated mount is
    moved to private staging, re-verified there by mount ID,
    and detached at staging (never at the shared target name);
    and the post-proof scans the WHOLE table for our mount ID
    — a move-away keeps it live elsewhere, so target-scoped
    "clear" never stands for discharged. Returns None on
    success (or when already absent), else a failure string;
    anything uncertain is retained, never detached.

    S17-round3: the kernel offers no fd-bound detach —
    umount2 on a /proc/self/fd path resolves to the TOP mount
    at that location exactly like the pathname (verified
    live) — so the effect stays pathname-addressed and the
    binding is established by the snapshot correspondence
    before it and the mount-ID proof after it. Residuals: a
    party privileged enough to stack at the target between
    the final observation and the detach (one in-process step,
    no rendezvous) can have its own top mount detached while
    ours stays live — detected by the post-proof, custody
    retained; and a move-away landing before the first
    observation is invisible to rollback-style records (no
    recorded ID to scan for). Both interposers can detach
    mounts directly, so the confusion grants nothing beyond
    their existing privilege.

    S17-round4: stacking by OUR OWN concurrent helpers is now
    excluded by the run-root mount-mutation lock
    (MOUNT_EXCLOCK_NAME), held across the whole helper call in
    both mount-fs and retire-mount — and a foreign row
    appearing at the target across the detach raises the
    occupant-changed alarm above instead of reporting
    discharged. What remains is a privileged third party
    racing mount(2)/umount(2) directly inside the microsecond
    effect window: still detected when our row survives or a
    foreign row persists at the target, still unobservable
    when the foreign top appears and vanishes between the two
    table reads. That last sliver is inherent to any
    table-diff post-proof and grants nothing beyond root's
    existing mount privilege.

    S17-round5: move-verify-detach closes that sliver for the
    detach itself. The effect at the shared name is now only
    MS_MOVE (reversible): whatever the target resolves to at
    effect time is moved to unpredictable private staging and
    re-verified by mount ID before any detach. A swapped-in
    foreign mount is moved back and reported loudly; an empty
    or stacked staging is left untouched and loud; only the
    snapshot-proven occupant is ever detached, and only at
    staging. What remains is a privileged party that reads our
    random staging path out of the mount table and swaps the
    staging occupant inside the move-to-verify window — still
    detected (any surprise is loud, never None), still never a
    silent foreign detach.

    S17-round6: the round-5 closure claim was overbroad and is
    corrected here — the staging verify-then-detach step has
    the same shape of window the target step had (narrower:
    random path, private namespace, lock-held helpers), and a
    privileged in-namespace party racing that final step can
    detach ours, plant B at staging, and have our umount
    detach B with an empty final table. No observation closes
    it (any read splits from the effect) and no fd-bound
    detach exists to give effect authority: umount2 on a
    /proc/self/fd path detaches the TOP mount at the fd
    dentry's location (stack probe: the stacker went, ours
    survived), and any open fd on the mount — O_PATH included
    — pins a same-mount umount EBUSY, so the hold cannot span
    the effect (all re-verified live on 7.0.0-38). After the
    fact "we detached ours" and "we detached B after the
    attacker detached ours" are identical in every kernel
    observable, so even detection is impossible for that one
    input — it is graded as an explicit residual (pinned by
    test_retire_mount_detach_replace_residual_pinned, which
    fails-good if the mechanism ever distinguishes it).
    Everything else the window admits is loud: a stack or a
    move-away leaves our ID live (post-proof, custody
    retained), and a surviving staging occupant (busy-pinned
    B) now raises the staging-occupant alarm instead of the
    previous silent None. The admitted actors are our helpers
    (lock-excluded), unprivileged parties (cannot mount), and
    privileged parties that do not race the final in-process
    step; a privileged party racing it is outside the
    contract. It can always cause loud failure; only a full
    detach+replace with a quiescent plant reaches the pinned
    residual (silent None, plant detached). The plant can be
    any mount the attacker moves to staging, so the residual
    is a genuine confused-deputy harm — bounded only by the
    attacker's pre-existing privilege (a party able to detach
    our mount and plant at our random staging path can detach
    any mount directly) and the race itself (one in-process
    step, no rendezvous, random path under a private
    namespace).
    """
    if not target or not contained(target, run_root):
        return f"foreign mount target refused: {target[:60]!r}"
    record = {"target": target,
              "mnt_id": expected.get("mnt_id"),
              "fstype": expected.get("fstype"),
              "source": expected.get("source"),
              "expect_super": expected.get("expect_super", [])}
    if expected.get("root") is not None:
        record["root"] = expected["root"]
    try:
        probe = os.open(target, os.O_RDONLY | os.O_DIRECTORY
                        | os.O_NOFOLLOW)
    except FileNotFoundError:
        try:
            table = read_mount_table()
        except AdmissionError as exc:
            return f"mount table unreadable: {exc}"
        if find_mounts(table, target):
            return (f"mount {target} path vanished but mount "
                    f"live; refusing")
        # S17-round4: the path vanished (renamed away) — a
        # recorded mount ID that is still live anywhere in the
        # table is a moved mount, not a discharge.
        if record.get("mnt_id") is not None:
            live = [row for row in table
                    if row.get("mnt_id") == record["mnt_id"]]
            if live:
                return (f"mount {target} moved (mnt="
                        f"{record['mnt_id']} live at "
                        f"{live[0]['target']}); manual "
                        f"retirement required")
        return None
    except OSError as exc:
        return (f"mount {target} target not openable ({exc}); "
                f"refusing")
    try:
        try:
            snap_mnt = _mnt_id_of(probe)
        except OSError as exc:
            return (f"mount {target} descriptor identity "
                    f"unreadable ({exc}); refusing")
    finally:
        try:
            os.close(probe)
        except OSError:
            pass
    try:
        table = read_mount_table()
    except AdmissionError as exc:
        return f"mount table unreadable: {exc}"
    if not find_mounts(table, target):
        if record.get("mnt_id") is not None:
            gone = [entry for entry in table
                    if entry["mnt_id"] == record["mnt_id"]]
            if gone:
                return (f"mount {target} still live at "
                        f"{gone[0]['target']}; custody retained")
        return None
    try:
        row = admit_mount(record, table, run_root)
    except AdmissionError as exc:
        return (f"mount {target} replacement refused ({exc}); "
                f"left in place")
    if row["mnt_id"] != snap_mnt:
        return (f"mount {target} identity changed between "
                f"open and validation (table={row['mnt_id']} "
                f"snapshot={snap_mnt}); refusing")
    try:
        effect_table = read_mount_table()
    except AdmissionError as exc:
        return f"mount table unreadable before effect: {exc}"
    try:
        row = admit_mount(record, effect_table, run_root)
    except AdmissionError as exc:
        return (f"mount {target} changed between validation "
                f"and effect ({exc}); refusing")
    if row["mnt_id"] != snap_mnt:
        return (f"mount {target} changed between validation "
                f"and effect (table={row['mnt_id']} "
                f"snapshot={snap_mnt}); refusing")
    # S17-round5: move-verify-detach — the detach never
    # addresses the shared target name. The validated top
    # mount is moved to a private staging path first; only a
    # staging occupant whose mount ID equals the snapshot is
    # detached. A racer swapping the target between the final
    # validation and the move only diverts a REVERSIBLE move
    # (detected below, moved back, reported loudly) — never an
    # irreversible foreign detach misreported as our discharge.
    try:
        staging = _retire_stage_dir(run_root)
    except AdmissionError as exc:
        return f"mount {target} retire staging unavailable: {exc}"
    try:
        move_err = _mount_move(target, staging)
        if move_err is not None:
            return (f"mount {target} not moved to staging "
                    f"({os.strerror(move_err)}); refusing")
        try:
            stage_table = read_mount_table()
        except AdmissionError as exc:
            back_err = _mount_move(staging, target)
            if back_err is not None:
                return (f"mount {target} staging unverifiable "
                        f"({exc}); move-back failed "
                        f"({os.strerror(back_err)}); left at "
                        f"{staging}; manual recovery required")
            return (f"mount {target} staging unverifiable "
                    f"({exc}); moved back; custody retained")
        staged = find_mounts(stage_table, staging)
        if len(staged) != 1:
            count = "empty" if not staged else (
                f"{len(staged)} stacked")
            return (f"mount {target} staging {count} after "
                    f"move (expected sole mnt={snap_mnt}); "
                    f"left untouched; refusing detach; custody "
                    f"retained")
        if staged[0]["mnt_id"] != snap_mnt:
            back_err = _mount_move(staging, target)
            if back_err is not None:
                return (f"mount {target} staging holds foreign "
                        f"mnt={staged[0]['mnt_id']} (expected "
                        f"{snap_mnt}); move-back failed "
                        f"({os.strerror(back_err)}); left at "
                        f"{staging}; manual recovery required")
            return (f"mount {target} staging holds foreign "
                    f"mnt={staged[0]['mnt_id']} (expected "
                    f"{snap_mnt}); moved back; refusing detach; "
                    f"custody retained")
        umount_err = _umount2(staging)
    finally:
        try:
            os.rmdir(staging)
        except OSError:
            pass
    # The umount result is advisory: the post-proof decides.
    # Our mount ID must be gone from the WHOLE table — a
    # move-away is still ours, still live.
    try:
        after = read_mount_table()
    except AdmissionError as exc:
        return f"mount table unreadable after effect: {exc}"
    live = [entry for entry in after
            if entry["mnt_id"] == snap_mnt]
    if live:
        where = live[0]["target"]
        detail = f" at {where}" if where != target else ""
        note = (f" (umount: {os.strerror(umount_err)})"
                if umount_err else "")
        return (f"mount {target} still live after detach"
                f"{detail}{note}; custody retained")
    # S17-round4: interposition alarm — our row is gone, but a
    # foreign row sits at our target that was not there before
    # the effect. Either a racer stacked at our mountpoint
    # after we detached ours (benign but loud), or ours was
    # unmounted concurrently and our umount detached the
    # foreign top. Either way the occupant is not provably
    # ours: retain custody.
    before_here = {row.get("mnt_id") for row in effect_table
                   if row.get("target") == target}
    for row in find_mounts(after, target):
        if row.get("mnt_id") not in before_here:
            return (f"mount {target} occupant changed "
                    f"across detach (foreign mnt="
                    f"{row.get('mnt_id')} appeared, ours "
                    f"discharged); interposed mutation "
                    f"suspected; custody retained")
    # S17-round6: staging-occupant alarm — our ID is gone but
    # staging still hosts a mount (a detach+replace whose
    # foreign occupant survived our detach, e.g. busy-pinned
    # by the interposer so the umount EBUSY'd). Previously
    # this returned None (silent stranding); the occupant is
    # not provably ours, so it is loud, named and stranded —
    # never detached, never silent.
    for row in find_mounts(after, staging):
        return (f"mount {target} staging still occupied "
                f"after detach (foreign mnt="
                f"{row.get('mnt_id')} at {staging}, ours "
                f"discharged); interposed mutation "
                f"suspected; foreign mount left in place; "
                f"manual recovery required")
    return None


def retire_mount_via_helper(run_root, target, fingerprint):
    """Ownership-bound detach through the privileged helper.

    The helper re-validates in-process (see retire_mount_now),
    so this caller's observations going stale cannot redirect
    the detach onto a foreign mount. (S16/S17)
    """
    helper = os.path.abspath(__file__)
    argv = [sys.executable, helper, "retire-mount",
           "--run-root", run_root, "--target", target,
           "--fstype", str(fingerprint.get("fstype", "")),
           "--source", str(fingerprint.get("source", ""))]
    if fingerprint.get("mnt_id") is not None:
        argv += ["--mnt-id", str(fingerprint["mnt_id"])]
    if fingerprint.get("root") is not None:
        argv += ["--mount-root", str(fingerprint["root"])]
    for want in fingerprint.get("expect_super", []):
        argv += ["--expect-super", str(want)]
    rc, out, err = run_sudo(argv, timeout=120)
    if rc == 0 and out.startswith("retired-mount "):
        return None
    return f"mount {target} retire refused: rc={rc} {tail(out or err)}"


def loop_backing_verified(loop, live, backing):
    """True when the loop's live backing is the recorded one.

    S18-round3: takes the loop device plus the already-read sysfs
    value (one sysfs read per validation step, as before). Kernel
    backing identity governs whenever the device node reports a
    binding — the held (dev, ino) decides, so a deleted/restored
    swap cannot spoof it. A detached-at-ioctl device and an
    unreadable node both fall through to the already-read sysfs
    value (deleted backings refuse as unprovable): the surrounding
    validate/effect/post-effect reads converge genuine detachment
    to success exactly as before, while a rebound loop fails the
    string match.
    """
    if live is None:
        return False
    if not isinstance(backing, dict) or not backing.get("path"):
        return False
    try:
        ident = read_loop_backing_id(loop)
    except LoopIdUnavailable:
        ident = None
    if ident is not None:
        return ((ident[0], ident[1]) == (backing.get("dev"),
                                        backing.get("ino")))
    return sysfs_backing_matches(live, backing["path"],
                                 backing.get("dev"),
                                 backing.get("ino"))


def retire_loop_now(loop, backing, run_root):
    """Validate and detach one loop device in this process. (S17)

    S17-round3: the final kernel-identity validation, the
    LOOP_CLR_FD effect, and the post-proof all address ONE
    held device fd — no pathname re-resolution between
    validation and effect, so a device-node swap at the final
    boundary cannot redirect the detach onto a foreign
    association. Returns None on success (or when already
    detached), else a failure string. A device whose live
    backing differs from the record is a reused name:
    refused, never detached.

    Residual: a party privileged enough to re-associate the
    device between the final GET and the CLR (adjacent ioctls,
    no rendezvous) could substitute the cleared association —
    but that party can detach loop devices directly, so the
    confusion grants nothing beyond its existing privilege.
    """
    if not loop or not str(loop).startswith("/dev/loop"):
        return f"foreign loop device refused: {str(loop)[:60]!r}"
    if not isinstance(backing, dict) or not backing.get("path"):
        return (f"loop {loop} has no recorded backing; refusing detach")
    if not contained(os.path.normpath(backing["path"]), run_root):
        return (f"loop {loop} backing outside run-root; refusing detach")
    try:
        live = read_loop_backing(loop)
    except AdmissionError as exc:
        return str(exc)
    if live is None:
        return None
    if not sysfs_backing_matches(live, backing["path"],
                                 backing.get("dev"),
                                 backing.get("ino")):
        return (f"loop {loop} backing changed "
                f"(live={live[:60]!r}); refusing detach")
    try:
        fd = os.open(loop, os.O_RDWR | os.O_NONBLOCK
                     | os.O_CLOEXEC)
    except OSError as exc:
        return (f"loop {loop} device not openable ({exc}); "
                f"refusing detach")
    try:
        try:
            ident = _loop_get_status_on(fd)
        except LoopIdUnavailable as exc:
            return (f"loop {loop} status unreadable ({exc}); "
                    f"refusing detach")
        if ident is None:
            return None
        if ((ident[0], ident[1]) != (backing.get("dev"),
                                    backing.get("ino"))):
            return (f"loop {loop} backing changed between "
                    f"validation and effect; refusing detach")
        clr_err = _loop_clr_fd_on(fd)
        # The CLR result is advisory: the post-proof on the
        # same fd decides. (ENXIO from the CLR — a cooperative
        # detach winning the race — converges to success when
        # the binding is provably gone.)
        try:
            after = _loop_get_status_on(fd)
        except LoopIdUnavailable as exc:
            return (f"loop {loop} status unreadable after detach "
                    f"({exc}); custody retained")
        if after is None:
            return None
        if ((after[0], after[1]) == (backing.get("dev"),
                                    backing.get("ino"))):
            note = (f" (detach: {os.strerror(clr_err)})"
                    if clr_err else "")
            return (f"loop {loop} still attached after detach"
                    f"{note}; custody retained")
        # Detached and already rebound by another party: our
        # obligation is discharged; the new association is not
        # ours to touch.
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def retire_loop_via_helper(run_root, loop, backing):
    helper = os.path.abspath(__file__)
    rc, out, err = run_sudo(
        [sys.executable, helper, "retire-loop",
         "--run-root", run_root, "--loop", loop,
         "--backing-path", str(backing.get("path", "")),
         "--backing-dev", str(backing.get("dev", -1)),
         "--backing-ino", str(backing.get("ino", -1))],
        timeout=120)
    if rc == 0 and out.startswith("retired-loop "):
        return None
    return f"losetup -d {loop} refused: rc={rc} {tail(out or err)}"


def target_is_payload(target, payload, dev, ino):
    """True when the live object at `target` is the payload object."""
    try:
        shown = os.stat(target)
        want = os.stat(payload)
    except OSError:
        return False
    return ((shown.st_dev, shown.st_ino)
            == (want.st_dev, want.st_ino)
            == (dev, ino))


def owned_bind_only(target, payload, dev, ino, table):
    """True when `target` hosts exactly our payload bind. (S19)

    Host-side twin of the driver's gate: one row at the target,
    a real bind row (the filesystem source, never the payload
    pathname — a row sourcing the payload file is fabricated),
    and the live object at the target is our payload object.
    """
    rows = find_mounts(table, target)
    if len(rows) != 1:
        return False
    if rows[0]["source"] == os.path.normpath(payload):
        return False
    return target_is_payload(target, payload, dev, ino)


def cleanup_one_mount(entry, run_root):
    """Unmount one recorded mount. Returns None on success (or when
    already gone), else a failure string. A live mount whose identity
    differs from the record is a replacement: it is refused and left
    in place, never unmounted. (F08)

    S17: the table is read fresh for every decision (never a
    shared snapshot), and the effect runs through the privileged
    helper, which re-validates in-process before detaching.
    """
    target = entry.get("target", "")
    if not target or not contained(target, run_root):
        return f"foreign mount target refused: {target[:60]!r}"
    try:
        table = read_mount_table()
    except AdmissionError as exc:
        return f"mount table unreadable: {exc}"
    if not find_mounts(table, target):
        # S17-round4: nothing at the recorded target — but a
        # recorded mount ID that is still live anywhere (a
        # move-away, including outside the run root) is a
        # moved mount, not a discharge.
        if entry.get("mnt_id") is not None:
            live = [row for row in table
                    if row.get("mnt_id") == entry["mnt_id"]]
            if live:
                return (f"mount {target} moved (mnt="
                        f"{entry['mnt_id']} live at "
                        f"{live[0]['target']}); manual "
                        f"retirement required")
        return None
    try:
        admit_mount(entry, table, run_root)
    except AdmissionError as exc:
        return f"mount {target} replacement refused ({exc}); left in place"
    fingerprint = {
        "mnt_id": entry.get("mnt_id"),
        "fstype": entry.get("fstype"),
        "source": entry.get("source"),
        "expect_super": entry.get("expect_super", []),
    }
    if entry.get("root") is not None:
        fingerprint["root"] = entry["root"]
    return retire_mount_via_helper(run_root, target, fingerprint)


def read_loop_backing(loop):
    """Live backing file of a /dev/loopN device, or None when the
    device is gone (already detached). Only proven absence (ENOENT)
    reads as detached; any other read failure raises, so a denial
    or I/O error never masquerades as a retired loop. (R42)"""
    name = os.path.basename(str(loop))
    try:
        with open(f"/sys/block/{name}/loop/backing_file", "rb") as handle:
            # S26: backing_file is a pathname; decode byte-preserving
            # so a non-UTF-8 image path compares identical.
            return os.fsdecode(handle.read()).strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AdmissionError(
            f"loop {loop} backing unreadable (not provably detached): "
            f"{exc}")


def read_loop_backing_id(loop):
    """(dev, ino) of the loop's kernel-held backing file.

    S18/S23: LOOP_GET_STATUS64 on a retained O_RDONLY device
    descriptor — kernel object identity with no pathname
    resolution, so a deleted backing still reports its true inode
    and a restored impostor at the old name cannot spoof it.
    Returns None only when provably detached (ENXIO on the held
    fd); raises LoopIdUnavailable when the status cannot be
    read (EACCES on the node, I/O errors) — unknown, never
    detached.

    S23-round4: a missing device node raises too — removing
    /dev/loopN does not detach the kernel loop, whose sysfs
    backing may still be live. Callers treat this as
    unassessable (incomplete scans, refused detaches), never
    as a detached verdict.
    """
    try:
        fd = os.open(loop, os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_CLOEXEC)
    except FileNotFoundError:
        raise LoopIdUnavailable(
            f"loop {loop} device node missing: unknown, never "
            f"detached")
    except OSError as exc:
        raise LoopIdUnavailable(
            f"loop {loop} not openable: {exc}")
    try:
        return _loop_get_status_on(fd)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def sysfs_backing_matches(live, path, dev, ino):
    """Pathname fallback for loop backing identity. (S18)

    Sound for every STABLE state: a " (deleted)" backing is
    unprovable via pathname — the live name may hold a restored
    impostor (the deleted-B/restored-A counterexample) — and
    refuses outright. A live name must spell the expected path
    and stat to the expected identity. Residual: a transient
    rename winning the sysfs-read/stat race inside one call;
    callers prefer read_loop_backing_id (kernel identity, no
    race) whenever the device node is readable.
    """
    if live is None:
        return False
    if live.endswith(" (deleted)"):
        return False
    if os.path.normpath(live) != os.path.normpath(path):
        return False
    try:
        st = os.stat(live)
    except OSError:
        return False
    return (st.st_dev, st.st_ino) == (dev, ino)


def cleanup_loop_device(loop, backing, run_root):
    """Detach one recorded loop device. Returns None on success (or
    when already detached), else a failure string. A device whose
    live backing differs from the recorded image is a reused name:
    it is refused, never detached. Identity is the backing
    (dev, ino) binding, not the pathname spelling: same-path
    different-inode reuse refuses. (F08, R19)

    S17: pre-validated here against a fresh read, then detached
    through the privileged helper, which re-validates in-process.
    """
    if not loop or not str(loop).startswith("/dev/loop"):
        return None
    try:
        live = read_loop_backing(loop)
    except AdmissionError as exc:
        return str(exc)
    if live is None:
        return None
    if not isinstance(backing, dict) or not backing.get("path"):
        return (f"loop {loop} has no recorded backing; refusing detach "
                f"(live={live[:60]!r})")
    # S18-round3: kernel backing identity governs (no pathname
    # resolution). A detached-at-ioctl device is already gone. The
    # already-read sysfs value is the fallback with the original
    # sub-case reports — except a " (deleted)" backing, which is
    # unprovable via pathname (the live name may hold a restored
    # impostor) and refuses outright instead of stripping.
    try:
        ident = read_loop_backing_id(loop)
    except LoopIdUnavailable:
        ident = "unavailable"
    if ident is None:
        return None
    if ident != "unavailable":
        if ((ident[0], ident[1]) != (backing.get("dev"),
                                    backing.get("ino"))):
            return (f"loop {loop} backing identity changed "
                    f"(live=({ident[0]},{ident[1]})); refusing detach")
    else:
        if live.endswith(" (deleted)"):
            return (f"loop {loop} backing deleted from under record "
                    f"(live={live[:60]!r}); refusing detach")
        if os.path.normpath(live) != os.path.normpath(backing["path"]):
            return (f"loop {loop} backing changed (live={live[:60]!r}); "
                    f"refusing detach")
        try:
            st = os.stat(live)
        except OSError as exc:
            return (f"loop {loop} backing unverifiable ({exc}); "
                    f"refusing detach")
        if (st.st_dev, st.st_ino) != (backing.get("dev"),
                                      backing.get("ino")):
            return (f"loop {loop} backing identity changed "
                    f"(live=({st.st_dev},{st.st_ino})); refusing detach")
    return retire_loop_via_helper(run_root, loop, backing)


def cleanup_churn_point(churn, run_root):
    """Retire the driver-managed churn bind point. Returns None when
    nothing is mounted (or no churn was recorded), else a failure
    string. The live mount must be exactly our recorded payload-b
    bind: stacked, foreign, or re-sourced mounts are refused and
    left in place, never unmounted. (R18)

    S19: ownership is the bind OBJECT identity — the live object
    at the point must be our payload object — not the mountinfo
    source, which for a real bind names the filesystem. The
    detach runs through the privileged helper.
    """
    churn = churn or {}
    point = churn.get("point", "")
    if not point or not contained(point, run_root):
        return None
    payload = churn.get("bind_source", "")
    if not payload:
        return (f"churn point {point} has no recorded bind source; "
                f"refusing umount, left in place")
    try:
        table = read_mount_table()
    except AdmissionError as exc:
        # F08: an unreadable table must not silently skip this
        # umount (the point would stay mounted under the retire).
        return f"churn point table unreadable: {exc}"
    rows = find_mounts(table, point)
    if not rows:
        return None
    if len(rows) > 1:
        return (f"churn point {point} has stacked mounts; "
                f"refusing umount, left in place")
    row = rows[0]
    if row["source"] == os.path.normpath(payload):
        return (f"churn point {point} hosts fabricated mount "
                f"(source names the payload file); refusing umount, "
                f"left in place")
    if not target_is_payload(point, payload,
                             churn.get("bind_source_dev"),
                             churn.get("bind_source_ino")):
        return (f"churn point {point} bind object identity changed; "
                f"refusing umount, left in place")
    return retire_mount_via_helper(run_root, point, {
        "mnt_id": row["mnt_id"], "fstype": row["fstype"],
        "source": row["source"], "root": row["root"],
        "expect_super": [],
    })


def _require_exclusive_dir(fd, what):
    """Prove open directory fd `fd` mutation-exclusive to trusted owners.

    S13: owned by a trusted remover with no group/other write
    bit. Raises OSError otherwise: in a shared directory
    another UID could rename a held entry away and plant a
    replacement between the hold and the unlink, and the
    post-unlink proof would only detect the foreign deletion
    after it happened. A foreign owner raises EACCES (a
    permission failure the caller may retry privileged); a
    loose mode is a hard refusal (privilege cannot close a
    swappable window).

    S75: the trusted set is the S76 controller identity — us,
    root, or the sudo-invoking owner — so the exclusion policy
    survives the caller-to-root cleanup transition: the
    privileged remover accepts the controller's exclusive
    directories instead of rejecting the normal user's tree.
    Capability still rests with the kernel (an unprivileged
    caller admitted past the gate fails its unlinks with
    EACCES and escalates as before).
    """
    st = os.fstat(fd)
    allowed = _trusted_parent_owners()
    if st.st_uid not in allowed:
        raise OSError(
            errno.EACCES,
            f"{what} owned by uid {st.st_uid}, not a trusted "
            f"remover owner {sorted(allowed)}: privileged "
            f"removal may proceed")
    if st.st_mode & 0o022:
        raise OSError(
            f"{what} not exclusive "
            f"(mode={oct(st.st_mode & 0o7777)}): "
            f"refusing removal through a swappable directory")


def _removal_excluded(parent_fd, root_fd):
    """Exclusion verdict for unlinking a held root ("" when excluded).

    S13: an exclusive parent excludes foreign swappers outright;
    otherwise a sticky parent holding a trusted entry excludes
    them (sticky rename needs entry or parent ownership, and
    both ends are trusted). Anything else is an unsupported
    shared directory and the unlink must refuse. A
    foreign-owned entry yields a "denied: " verdict (privileged
    removal may proceed); a swappable window yields a hard
    refusal (no privilege level makes deleting through it
    safe).

    S13-round4: the sticky exception additionally requires a
    trusted parent owner. A sticky directory's foreign owner
    bypasses the sticky bit and may replace our entry despite
    it, so the final rmdir would delete the replacement while
    the post-unlink proof only detects it afterwards.

    S75: the owner comparisons use the S76 controller identity
    (us, root, or the sudo-invoking owner), so the verdict
    survives the caller-to-root cleanup transition: the
    privileged remover accepts the controller's exclusive
    parent and entry instead of rejecting the normal user's
    tree. Only genuinely foreign owners yield "denied:" (or a
    hard refusal past a swappable window).
    """
    pst = os.fstat(parent_fd)
    euid = os.geteuid()
    allowed = _trusted_parent_owners()
    if pst.st_uid in allowed and not pst.st_mode & 0o022:
        return ""
    rst = os.fstat(root_fd)
    # Sticky rename needs entry or parent ownership: both ends
    # trusted (either may be the sudo-invoking controller for
    # a privileged remover) excludes every foreign swapper.
    if (pst.st_mode & stat.S_ISVTX and rst.st_uid in allowed
            and pst.st_uid in allowed):
        return ""
    if rst.st_uid not in allowed:
        return (f"denied: entry owned by uid {rst.st_uid}, not a "
                f"trusted remover owner {sorted(allowed)}: "
                f"privileged removal may proceed")
    return (
        f"removal not excluded (parent uid={pst.st_uid} "
        f"mode={oct(pst.st_mode & 0o7777)}): refusing unlink "
        f"through a swappable directory")


def _mnt_id_of(fd):
    """Mount ID of an open descriptor via /proc/self/fdinfo. (S27)

    S27-round3: descriptor-bound mount identity for the traversal
    guard — works on O_PATH holds (verified: fdinfo carries
    mnt_id for them) as well as plain opens. Raises OSError when
    the identity cannot be established; callers treat that as a
    boundary (refuse), never as same-mount.
    """
    try:
        with open(f"/proc/self/fdinfo/{fd}", "r") as handle:
            for line in handle:
                if line.startswith("mnt_id:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError) as exc:
        raise OSError(
            f"mount identity unreadable for fd {fd}: {exc}")
    raise OSError(f"mount identity missing for fd {fd}")


def fd_clear_dir(fd, rel="", mounts=frozenset(), root_dev=None,
                 root_mnt=None):
    """Recursively remove every entry under open dir fd `fd`
    (fd-relative; never resolves a path). (R15)

    S13: one O_PATH hold per entry (follows nothing; holds files,
    dirs, symlinks and fifos without opening their data, so no
    fifo blocks the walk). Directories reopen through the hold
    with "." — no second name lookup, so renaming the entry
    itself mid-walk cannot redirect the recursion. Every unlink
    proves against the held inode afterwards: a swapped-in
    replacement takes the deletion while OUR inode stays linked,
    and the proof raises instead of reporting success over it.
    Multi-linked entries (hardlinks — never created by this
    tool, so always foreign evidence) refuse the same way: the
    inode would survive the unlink, and "removed" would be a
    lie. Mirrors scopebase_linux::conformance's walk.

    S27: mount-boundary refusal during the walk. `rel` tracks the
    logical path under the tree root and `mounts` holds the live
    mount targets below it (relative): descending into a mounted
    directory refuses instead of clearing foreign content. A
    device change against `root_dev` is an independent backstop
    for cross-filesystem mounts; the target set additionally
    covers same-filesystem binds, which share the device.

    S13-round3: mutation exclusion before deletion. Each
    traversed directory proves exclusive before any entry inside
    it is unlinked; recursion carries the gate to every level. A
    mounted directory is foreign content whatever its mode, so
    the mount-boundary check precedes the gate.

    S27-round3: descriptor-bound mount check on every child
    directory. The target snapshot cannot see a bind mounted
    after it, and a same-filesystem bind shares the device — but
    never the mount ID. The root's mount ID is read once from
    its held fd; each child hold must carry the same ID before
    descent, or the walk refuses instead of clearing foreign
    content.
    """
    if rel in mounts:
        raise OSError(
            f"mount boundary at {rel or '.'!r}: refusing traversal")
    _require_exclusive_dir(fd, f"tree directory {rel or '.'!r}")
    if root_dev is None:
        root_dev = os.fstat(fd).st_dev
    if root_mnt is None:
        root_mnt = _mnt_id_of(fd)
    for name in os.listdir(fd):
        child_rel = f"{rel}/{name}" if rel else name
        if child_rel in mounts:
            # A mount AT this name (mounted file, or a directory
            # about to be descended into): never unlink through it.
            raise OSError(
                f"mount boundary at {child_rel!r}: refusing traversal")
        try:
            held = os.open(
                name, os.O_PATH | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            # Already gone (a cooperative sibling retired it):
            # converge rather than fail the whole removal.
            continue
        try:
            st = os.fstat(held)
            if stat.S_ISDIR(st.st_mode):
                # S27-round3: mount identity on the held
                # descriptor, before the device backstop and
                # before descent — a post-snapshot same-fs bind
                # shares the device but never this ID.
                if _mnt_id_of(held) != root_mnt:
                    raise OSError(
                        f"mount boundary at {name!r} (mount id "
                        f"differs from tree): refusing traversal")
                if st.st_dev != root_dev:
                    raise OSError(
                        f"mount boundary at {name!r} (device "
                        f"{st.st_dev} != tree {root_dev}): refusing")
                child = os.open(
                    ".", os.O_RDONLY | os.O_DIRECTORY,
                    dir_fd=held)
                try:
                    fd_clear_dir(child, child_rel, mounts, root_dev,
                                 root_mnt)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=fd)
            else:
                # Plain unlink never follows a link, whatever the
                # entry changed into — dangling symlink, fifo,
                # socket alike.
                os.unlink(name, dir_fd=fd)
            if os.fstat(held).st_nlink != 0:
                raise OSError(
                    f"replaced during removal: entry {name!r} "
                    f"still linked; refusing")
        finally:
            os.close(held)


def mount_targets_under(tree_path):
    """Live mount targets at/under `tree_path`, relative. (S27)

    Returns a frozenset of slash-separated relative paths (""
    for a mount AT the tree root itself). Raises AdmissionError
    when the table is unreadable: an unguardable walk refuses.
    """
    table = read_mount_table()
    base = os.path.normpath(tree_path)
    found = set()
    for row in table:
        target = os.path.normpath(row["target"])
        if target == base:
            found.add("")
        elif target.startswith(base + os.sep):
            found.add(target[len(base) + 1:])
    return frozenset(found)


def remove_pinned_tree(parent_fd, name, expected, tree_path=None):
    """Remove directory `name` under pinned `parent_fd`. (R15, R16)

    The root is opened through the parent fd, verified against the
    recorded (dev, ino), cleared through the held fd, and its name
    unlinked through the pinned parent — with a final link-count
    check on the held fd proving OUR directory lost its name.
    Returns None on success (or when already gone), else a failure
    string; permission failures carry a "denied: " prefix so the
    caller can retry privileged, while replacements refuse.

    S14 note: unlike FixtureRoot/cleanup_run, this tool pins
    foreign-owned sticky parents (/dev/shm tt04 roots) by design.
    S13-round3: the exclusion gate applies in sticky-aware form —
    an exclusive parent, or a sticky parent holding a trusted
    entry; anything else refuses before unlinking. Recorded
    (dev, ino) identity checks plus the per-entry proof in
    fd_clear_dir stay as backstops.
    S13-round4: the sticky exception needs a trusted parent owner
    as well (root-owned /dev/shm stays admitted) — see
    ``_removal_excluded``.
    S75: both ends use the S76 controller identity, so the
    verdict survives the caller-to-root transition — see
    ``_removal_excluded``.

    S27: when `tree_path` (the absolute path of this tree) is
    given, the live mount targets below it are computed fresh and
    the walk refuses to traverse any of them.
    """
    try:
        root_fd = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return f"denied: pinned open failed: {exc}"
        return f"pinned open failed: {exc}"
    try:
        st = os.fstat(root_fd)
        if (st.st_dev, st.st_ino) != expected:
            return (f"identity changed: live=({st.st_dev},{st.st_ino}) "
                    f"expected={expected}; replacement refused")
        # S13-round3: fail fast on an unexcluded parent before
        # clearing anything; re-verified tightly before the unlink
        # below.
        excluded = _removal_excluded(parent_fd, root_fd)
        if excluded:
            return excluded
        mounts = frozenset()
        if tree_path is not None:
            try:
                mounts = mount_targets_under(tree_path)
            except AdmissionError as exc:
                return f"clear failed: {exc}"
            if "" in mounts:
                return ("clear failed: mount boundary at tree root: "
                        "refusing traversal")
        try:
            fd_clear_dir(root_fd, "", mounts)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                return f"denied: clear failed: {exc}"
            return f"clear failed: {exc}"
        # Re-verify the name still addresses our inode before unlink.
        try:
            live = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd)
        except OSError as exc:
            return f"pre-unlink verify failed: {exc}"
        try:
            got = os.fstat(live)
        finally:
            os.close(live)
        if (got.st_dev, got.st_ino) != expected:
            return (f"identity changed before unlink: "
                    f"live=({got.st_dev},{got.st_ino}); "
                    f"replacement refused")
        # S13-round3: tight window — exclusion re-verified
        # immediately before the unlink.
        excluded = _removal_excluded(parent_fd, root_fd)
        if excluded:
            return excluded
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                return f"denied: unlink failed: {exc}"
            return f"unlink failed: {exc}"
        if os.fstat(root_fd).st_nlink != 0:
            return ("replaced during unlink: our directory still "
                    "linked; refusing (original cleared, name kept)")
    finally:
        os.close(root_fd)
    return None


def cleanup_aux_root(aux):
    """Retire one recorded auxiliary root. None on success (or
    already gone), else a failure string. Identity-bound: a
    replacement at the recorded name is refused, never deleted;
    removal is fd-relative under the pinned parent. (R20)"""
    if not isinstance(aux, dict):
        return f"aux root record malformed: {str(aux)[:60]!r}"
    norm = os.path.normpath(aux.get("path", ""))
    if (not norm.startswith("/dev/shm/tt04-") or "/" in
            norm[len("/dev/shm/tt04-"):] or ".." in norm):
        return f"foreign aux root refused: {aux.get('path', '')[:60]!r}"
    try:
        lst = os.lstat(norm)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"aux root {norm} unverifiable: {exc}"
    if stat.S_ISLNK(lst.st_mode):
        return f"aux root {norm} replaced by symlink; refused"
    expected = (aux.get("dev"), aux.get("ino"))
    if (lst.st_dev, lst.st_ino) != expected:
        return (f"aux root {norm} identity changed; "
                f"replacement refused")
    # S27: a mount at or under the aux root refuses the removal
    # before traversal; the walk itself re-checks live targets.
    try:
        guarded = mount_targets_under(norm)
    except AdmissionError as exc:
        return f"aux root {norm} table unreadable: {exc}"
    if guarded:
        return (f"aux root {norm} hosts mounts "
                f"({sorted(guarded)[:4]!r}); refusing traversal")
    parent = os.path.dirname(norm)
    name = os.path.basename(norm)
    try:
        parent_fd = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        return f"aux root parent not openable: {exc}"
    try:
        failure = remove_pinned_tree(parent_fd, name, expected, norm)
    finally:
        os.close(parent_fd)
    if failure is not None:
        # Aux roots are caller-owned tmpfs dirs; a denial is
        # reported, never silently escalated to sudo.
        return f"aux root {norm}: {failure}"
    return None


def _path_present(path):
    """True/False for proven presence/absence; denial raises. (S20)"""
    try:
        os.stat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AdmissionError(f"{path} not provably present/absent: {exc}")


def _reset_ack(ack):
    try:
        fd = os.open(ack,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                     | os.O_NONBLOCK, 0o644)
    except OSError:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def cleanup_pending_procs(manifest):
    """Retry/verify unretired processes; returns failure strings."""
    failures = []
    for entry in manifest.get("pending_procs", []):
        role = entry.get("role", "?")
        pid = entry.get("pid", -1)
        start = entry.get("starttime")
        try:
            state, cur = stat_state_start(pid)
        except ProcAbsent:
            continue
        except ProcUnknown as exc:
            failures.append(f"pending proc {role}: {exc}")
            continue
        if state == "Z":
            continue
        if start is not None and cur != start:
            # Ours exited; the pid number is someone else's now.
            continue
        if start is None:
            failures.append(
                f"pending proc {role} (pid {pid}): live but never "
                f"identified; manual retirement required")
            continue
        try:
            if not kill_owned(role, pid, start):
                failures.append(f"pending proc {role} survives")
        except AdmissionError as exc:
            failures.append(str(exc))
    return failures


def _moved_mount_report(entry, fingerprint, row, target, run_root=None):
    """Manual-recovery report for an ID-found moved mount. (S74)

    The pending record carries a mount ID the helper verified
    (moved report) or a refresh preserved (rollback refusal);
    the table still shows that ID, but at another mountpoint.
    The binding gates are re-checked live at the new location:
    a proven-ours occupant reports manual retirement with the
    live location; anything else is left in place, never
    unmounted.
    """
    loc = row["target"]
    checks = []
    if entry.get("canary") is not None:
        checks.append(_canary_matches(loc, MOUNT_CANARY_NAME,
                                      entry["canary"], run_root,
                                      expect_mnt_id=row.get(
                                          "mnt_id")))
    if entry.get("loop_backing") is not None:
        source = fingerprint.get("source") or ""
        # S71-round6: one retained FD across both proofs.
        checks.append(loop_single_fd_proof(
            loc, source, row, entry["loop_backing"]))
    if checks and all(checks):
        return (f"pending mount {target}: moved (mnt="
                f"{entry['mnt_id']} live at {loc}); manual "
                f"retirement required")
    if not checks:
        return (f"pending mount {target}: mount-ID "
                f"{entry['mnt_id']} live at {loc} without "
                f"binding evidence; verify the occupant before "
                f"retiring; manual retirement required")
    return (f"pending mount {target}: mount-ID {entry['mnt_id']} "
            f"live at {loc} but occupant not provably ours; "
            f"left in place")


def cleanup_pending_acquisitions(manifest, run_root):
    """Reconcile uncertain acquisitions; returns failure strings."""
    failures = []
    for entry in manifest.get("pending_acquisitions", []):
        kind = entry.get("kind")
        if kind == "loop":
            if isinstance(entry.get("backing"), dict):
                backing = entry["backing"]
            else:
                backing = {"path": entry.get("image"),
                           "dev": entry.get("dev"),
                           "ino": entry.get("ino")}
            if not backing.get("path"):
                failures.append("pending loop without identity; "
                                "manual retirement required")
                continue
            try:
                matches, incomplete = scan_loop_by_backing(
                    backing.get("dev"), backing.get("ino"))
            except AdmissionError as exc:
                failures.append(f"pending loop: {exc}")
                continue
            if incomplete:
                failures.append(
                    f"pending loop {backing['path']}: backing scan "
                    f"incomplete; manual retirement required")
                continue
            if not matches:
                continue
            if len(matches) > 1:
                failures.append(
                    f"pending loop {backing['path']}: backing "
                    f"identity matches {len(matches)} loops; "
                    f"manual retirement required")
                continue
            failure = cleanup_loop_device(matches[0], backing, run_root)
            if failure is not None:
                failures.append(failure)
        elif kind == "mount":
            target = entry.get("target", "")
            fingerprint = {
                "fstype": entry.get("fstype"),
                "source": entry.get("source"),
                "expect_super": entry.get("expect_super", []),
            }
            try:
                table = read_mount_table()
            except AdmissionError as exc:
                failures.append(f"pending mount {target}: {exc}")
                continue
            if entry.get("mnt_id") is not None:
                # S74: ID-keyed recovery — a moved mount (or a
                # mount that moved after a pending refresh
                # preserved its ID) is found wherever it sits.
                # At the recorded target the normal path below
                # runs (adopt-or-report); elsewhere the binding
                # gates are re-checked and retirement is manual.
                live = [row for row in table
                        if row.get("mnt_id") == entry["mnt_id"]]
                if live and live[0]["target"] != target:
                    failures.append(_moved_mount_report(
                        entry, fingerprint, live[0], target,
                        run_root))
                    continue
            rows = find_mounts(table, target)
            if not rows:
                if entry.get("mnt_id") is None:
                    # S74-round6: ID-less and nothing at the
                    # target — the effect may still have fired
                    # (pre-pin move the helper could not
                    # recover, confinement-blind table):
                    # absence at the name proves nothing, so
                    # custody is retained LOUDLY, never
                    # silently continued past. (An entry whose
                    # known ID is absent table-wide is proven
                    # discharged and still continues quietly.)
                    failures.append(
                        f"pending mount {target}: target empty "
                        f"but mount outcome uncertain; cannot "
                        f"prove absence; custody kept pending")
                continue
            known = entry.get("mnt_id")
            if (known is not None and len(rows) == 1
                    and rows[0].get("mnt_id") != known):
                # S72-round5: the recorded mount ID is gone from
                # the whole table (the search above found it
                # nowhere) but a same-fingerprint occupant sits
                # at the target — a replacement, never ours to
                # unmount, however well it matches. The known ID
                # is preserved (the record is untouched), not
                # silently swapped for the stranger's.
                failures.append(
                    f"pending mount {target}: recorded mount-ID "
                    f"{known} absent but occupant has ID "
                    f"{rows[0].get('mnt_id')}; replacement "
                    f"refused, left in place; manual "
                    f"verification required")
                continue
            adoptable = (
                len(rows) == 1
                and mount_fingerprint_matches(rows[0], fingerprint))
            if not adoptable and (
                    len(rows) == 1
                    and entry.get("loop_backing") is not None
                    and _fd_spelling_loop_shape(
                        rows[0], fingerprint)):
                # S15-round3: the helper mounted on an fd-bound
                # source but its report was lost (timeout) — the
                # kernel's literal /dev/fd/N spelling plus the
                # gates below proves the occupant is ours.
                adoptable = True
            if adoptable and entry.get("loop_backing") is not None:
                # S71-round5: EVERY loop-backed recovery
                # adoption proves the retained binding AND the
                # descriptor-bound correspondence — exact and
                # fd spellings alike. (The exact arm previously
                # checked neither: a node-spelling swap adopted
                # a foreign occupant outright.)
                src = fingerprint.get("source")
                if not (isinstance(src, str)
                        and src.startswith("/dev/loop")):
                    adoptable = False
                elif not loop_single_fd_proof(
                        target, src, rows[0],
                        entry["loop_backing"]):
                    # S71-round6: one retained FD across both
                    # proofs — no split opens to substitute
                    # between.
                    adoptable = False
            if adoptable and entry.get("canary") is not None:
                # S72-round4: the pending entry carries the
                # acquisition canary — the current occupant must
                # show it through, or a foreign same-type overlay
                # at our target is adopted and unmounted.
                if not _canary_matches(target, MOUNT_CANARY_NAME,
                                       entry["canary"], run_root,
                                       expect_mnt_id=rows[0].get(
                                           "mnt_id")):
                    adoptable = False
            if adoptable:
                failure = cleanup_one_mount({
                    "target": target, "mnt_id": rows[0]["mnt_id"],
                    "fstype": rows[0]["fstype"],
                    "source": rows[0]["source"],
                    "root": rows[0]["root"],
                    "expect_super": fingerprint["expect_super"],
                }, run_root)
                if failure is not None:
                    failures.append(failure)
            else:
                failures.append(
                    f"pending mount {target}: occupant not provably "
                    f"ours; left in place")
        else:
            failures.append(
                f"unknown pending acquisition kind: {kind!r}")
    return failures


def cleanup_command(args):
    run_root = check_run_root(args.run_root)
    if run_root is None:
        return fail2(f"foreign run-root: {args.run_root[:80]!r}")
    # S20: proven absence vs denial at command entry. exists()
    # suppresses EACCES, so both paths use explicit stat: denial
    # on either is a failure, never "nothing provisioned".
    try:
        manifest_present = _path_present(args.manifest)
    except AdmissionError as exc:
        print(f"cleanup: FAILED\n  - manifest {exc}")
        return 1
    if not manifest_present:
        # F09: a missing manifest with live residue is a refusal,
        # never a false success.
        try:
            root_present = _path_present(run_root)
        except AdmissionError as exc:
            print(f"cleanup: FAILED\n  - run-root {exc}")
            return 1
        if root_present:
            print("cleanup: FAILED\n  - run-root residue without "
                  "manifest: refusing automatic cleanup; remove "
                  "manually or reprovision")
            return 1
        print("cleanup: nothing provisioned (no manifest)")
        return 0
    try:
        manifest = load_manifest(args.manifest, run_root)
        # S100-round6: ns-identity mismatch/unavailability
        # refuses here (never a host-table fallback).
        _apply_manifest_ns_mode(manifest)
    except AdmissionError as exc:
        # A manifest naming a foreign root is a usage refusal, never a
        # recursive delete of unknown state. (S100-round6: match
        # the load errors precisely — a keeper-ns mismatch is a
        # custody refusal (rc 1), not a foreign root (rc 2).)
        if ("run-root mismatch" in str(exc)
                or "schema mismatch" in str(exc)):
            return fail2(f"foreign run-root: {exc}")
        print(f"cleanup: REFUSED {exc}")
        return 1
    try:
        # Raises on a replacement directory; a missing root flows
        # through the no-op paths below to the idempotent retired
        # report (aux roots outside it are still retired).
        admit_run_root_identity(manifest, run_root)
    except AdmissionError as exc:
        print(f"cleanup: REFUSED {exc}")
        return 1
    failures = []
    # Ask a live churn driver to restore its bind point before it dies.
    churn = manifest.get("evidence", {}).get("churn") or {}
    fifo, ack, point = (churn.get("fifo"), churn.get("ack"),
                        churn.get("point"))
    if (fifo and ack and point and contained(fifo, run_root)
            and contained(ack, run_root)):
        try:
            fifo_present = _path_present(fifo)
        except AdmissionError as exc:
            failures.append(f"churn fifo unverifiable: {exc}")
            fifo_present = False
        if fifo_present:
            def driver_cmd(cmd):
                try:
                    fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                except OSError:
                    return False
                try:
                    os.write(fd, (cmd + "\n").encode())
                except OSError:
                    return False
                finally:
                    os.close(fd)
                try:
                    poll_text_contains(ack, f"{cmd} rc=", 10)
                    return True
                except AdmissionError:
                    return False

            _reset_ack(ack)
            driver_cmd("restore")
            _reset_ack(ack)
            driver_cmd("quit")
    # Sleepers and drivers (identity-checked), wrappers last.
    for entry in manifest["procs"]:
        try:
            if not kill_owned(entry.get("role", "?"),
                              entry.get("pid", -1),
                              entry.get("starttime")):
                failures.append(f"proc {entry.get('role')} survives")
        except AdmissionError as exc:
            failures.append(str(exc))
    failures.extend(cleanup_pending_procs(manifest))
    # S17: every mount decision reads the table fresh; no shared
    # snapshot spans validation and effect.
    for entry in reversed(manifest["mounts"]):
        failure = cleanup_one_mount(entry, run_root)
        if failure is not None:
            failures.append(failure)
    failure = cleanup_loop_device(manifest["evidence"].get("ext4_loop"),
                                  manifest["evidence"].get("ext4_loop_backing"),
                                  run_root)
    if failure is not None:
        failures.append(failure)
    failures.extend(cleanup_pending_acquisitions(manifest, run_root))
    for sv in manifest["evidence"].get("btrfs_subvolumes", []):
        path = os.path.join(run_root, "btrfs", sv)
        # F08-adjacent: a bare ".." has no "/" yet escapes the btrfs
        # dir, so dot segments are refused explicitly.
        if not contained(path, run_root) or "/" in sv or sv in (".", ".."):
            failures.append(f"foreign subvolume refused: {sv[:40]!r}")
            continue
        try:
            if not _path_present(path):
                continue
        except AdmissionError as exc:
            failures.append(f"subvolume {sv} unverifiable: {exc}")
            continue
        try:
            proc = subprocess.run(
                ["btrfs", "subvolume", "delete", path],
                capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            # R21: a hung unprivileged delete falls through to the
            # sudo attempt (which caps at 120s) instead of escaping
            # as a traceback with the subvolume unrecorded.
            proc = None
        if proc is None or proc.returncode != 0:
            rc, _, err = run_sudo(["btrfs", "subvolume", "delete", path])
            if rc != 0:
                failures.append(f"subvolume delete {sv} refused: {tail(err)}")
    # The churn bind point is driver-managed, not a recorded mount:
    # retire it only when it still hosts our own bind (R18).
    failure = cleanup_churn_point(churn, run_root)
    if failure is not None:
        failures.append(failure)
    # Never remove a run-root that still hosts a recorded live mount,
    # or any other mount at or under it. F08: no exemptions — an
    # unexpected mount AT the run-root itself, or a lingering churn
    # point, refuses cleanup rather than being removed through. (A
    # cleanly unmounted point is simply absent from the table, so the
    # old `target != point` carve-out only ever hid failures.)
    try:
        table = read_mount_table()
    except AdmissionError as exc:
        failures.append(f"mount table unreadable before retire: {exc}")
        table = []
    for entry in manifest["mounts"]:
        if find_mounts(table, entry.get("target", "")):
            failures.append(f"mount still live: {entry.get('target')}")
    recorded = {e.get("target") for e in manifest["mounts"]}
    # S74: moved-but-custodied mounts are known by their
    # observed location — not unrecorded strays.
    for pending in manifest.get("pending_acquisitions", []):
        if pending.get("kind") == "mount" and pending.get(
                "observed_target"):
            recorded.add(pending["observed_target"])
    for row in table:
        target = row["target"]
        if contained(target, run_root) and target not in recorded:
            failures.append(f"unrecorded mount under run-root: {target}")
    if failures:
        print("cleanup: FAILED")
        for item in failures:
            print(f"  - {item}")
        return 1
    for aux in manifest.get("aux_roots", []):
        failure = cleanup_aux_root(aux)
        if failure is not None:
            failures.append(failure)
    if failures:
        print("cleanup: FAILED")
        for item in failures:
            print(f"  - {item}")
        return 1
    return _retire_pinned_root(manifest, run_root)


def _retire_pinned_root(manifest, run_root):
    """Destroy the admitted run-root; return the cleanup exit code.

    R15/R16: removal is descriptor-relative end to end. The parent
    is pinned once, the root is opened through it, verified against
    the recorded (dev, ino), cleared through the held fd, and its
    name unlinked through the pinned parent — with a final
    link-count check proving OUR directory lost its name. The
    privileged path re-execs this same file under sudo with the
    recorded identity as argv (no shell, no chmod/chown/rm
    fallbacks), so verification and destruction share one process
    and no caller-side check-then-use gap remains.
    """
    # F08: re-verify immediately before destruction: the root may
    # have been replaced after the entry gate. R42: denial raises
    # (REFUSED); only proven absence retires idempotently.
    try:
        if not admit_run_root_identity(manifest, run_root):
            print(f"cleanup: already retired {run_root}")
            return 0
    except AdmissionError as exc:
        print(f"cleanup: REFUSED {exc}")
        return 1
    rec = manifest.get("run_root_identity") or {}
    expected = (rec.get("dev"), rec.get("ino"))
    parent = os.path.dirname(run_root)
    name = os.path.basename(run_root)
    try:
        parent_fd = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        print(f"cleanup: FAILED\n  - run-root parent not openable: {exc}")
        return 1
    try:
        failure = remove_pinned_tree(parent_fd, name, expected, run_root)
    finally:
        os.close(parent_fd)
    if failure is None:
        print(f"cleanup: retired {run_root}")
        return 0
    if failure.startswith("denied: "):
        # Root-owned entries (overlay workdirs) defeat the
        # unprivileged pass; one privileged fd-bound removal.
        failure = _retire_via_sudo(parent, name, expected)
        if failure is None:
            print(f"cleanup: retired {run_root} via sudo "
                  f"(unprivileged pass denied)")
            return 0
    print(f"cleanup: FAILED\n  - run-root not removed: {failure}")
    return 1


def _retire_via_sudo(parent, name, expected):
    """One privileged fd-bound removal via this same file (R16).

    The helper re-verifies the recorded identity itself, in the
    same process that destroys, so no caller-side validation can
    go stale. Returns None on success, else a failure string.
    """
    dev, ino = expected
    helper = os.path.abspath(__file__)
    rc, out, err = run_sudo(
        [sys.executable, helper, "retire-helper",
         "--parent", parent, "--name", name,
         "--dev", str(dev), "--ino", str(ino)],
        timeout=300)
    if rc == 0 and out.startswith("retired "):
        return None
    return f"sudo retire refused: rc={rc} {tail(out or err)}"


def retire_helper_command(args):
    """Privileged-internal: fd-bound removal of one admitted dir.

    Never invoked by hand: cleanup re-execs this file under sudo
    so the privileged removal verifies identity itself, in the
    same process that destroys. Prints `retired <name>` or
    `FAILED: <reason>`; exit 0/1.
    """
    name = args.name
    if (not name or "/" in name or name in (".", "..")
            or "\x00" in name or len(name) > 255):
        print(f"FAILED: bad helper name: {name[:60]!r}")
        return 1
    if not os.path.isabs(args.parent):
        print(f"FAILED: helper parent not absolute: {args.parent[:80]!r}")
        return 1
    try:
        parent_fd = os.open(
            args.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        print(f"FAILED: helper parent not openable: {exc}")
        return 1
    try:
        failure = remove_pinned_tree(
            parent_fd, name, (args.dev, args.ino),
            os.path.join(args.parent, name))
    finally:
        os.close(parent_fd)
    if failure is not None:
        print(f"FAILED: {failure}")
        return 1
    print(f"retired {name}")
    return 0


def retire_mount_command(args):
    """Privileged-internal: validate and detach one mount. (S17)

    Never invoked by hand: cleanup/rollback re-exec this file
    under sudo so validation, effect, and post-effect proof share
    one privileged process. Prints `retired-mount <target>` or
    `FAILED: <reason>`; exit 0/1.
    """
    run_root = check_run_root(args.run_root)
    if run_root is None:
        print(f"FAILED: foreign run-root: {args.run_root[:80]!r}")
        return 1
    expected = {
        "mnt_id": args.mnt_id,
        "fstype": args.fstype,
        "source": args.source,
        "expect_super": args.expect_super or [],
    }
    if args.mount_root is not None:
        expected["root"] = args.mount_root
    # S17-round4: serialize against concurrent mount-fs creates
    # (and fellow detaches) across validate→effect→prove.
    lock_fd = _mount_exclock_acquire(run_root)
    try:
        failure = retire_mount_now(args.target, expected, run_root)
    finally:
        _mount_exclock_release(lock_fd)
    if failure is not None:
        print(f"FAILED: {failure}")
        return 1
    print(f"retired-mount {args.target}")
    return 0


def retire_loop_command(args):
    """Privileged-internal: validate and detach one loop. (S17)

    Same single-process discipline as retire-mount, via
    LOOP_CLR_FD. Prints `retired-loop <loop>` or `FAILED:
    <reason>`; exit 0/1.
    """
    run_root = check_run_root(args.run_root)
    if run_root is None:
        print(f"FAILED: foreign run-root: {args.run_root[:80]!r}")
        return 1
    failure = retire_loop_now(args.loop, {
        "path": args.backing_path,
        "dev": args.backing_dev,
        "ino": args.backing_ino,
    }, run_root)
    if failure is not None:
        print(f"FAILED: {failure}")
        return 1
    print(f"retired-loop {args.loop}")
    return 0


class _HelperFail(Exception):
    """Privileged-create-helper refusal; the command prints FAILED."""


class _HelperUncertain(_HelperFail):
    """mount(2) returned 0 but post-verification is inconclusive.

    S74: the effect fired, so the caller must keep pending
    custody — never discharge from target absence. The command
    prints FAILED-UNCERTAIN.
    """


class _HelperMoved(_HelperFail):
    """The verified occupant sits at a moved target. (S74)

    mount(2) returned 0 on the held target FD, the post-effect
    row passed every binding gate, but its mountpoint is no
    longer the verified name — the target was renamed around
    the effect. Carries the acquired mount ID and the observed
    mountpoint so the caller retains ID-keyed recovery
    custody. The command prints FAILED-MOVED.
    """

    def __init__(self, mnt_id, observed, reason):
        super().__init__(reason)
        self.mnt_id = mnt_id
        self.observed = observed


def _bind_helper_root(run_root_arg, dev, ino):
    """Re-establish the caller's run-root authority in this process.

    S15-round3: create helpers (make-ext4, attach-loop, mount-fs)
    take no caller-side validation on trust — they bind the
    run-root themselves and require its live identity to equal
    the (dev, ino) the caller recorded from its held guard. The
    argv pathname is a hint; the (dev, ino) equality is the
    barrier between the caller's last verification and the
    privileged effect. Returns (run_root, guard); the caller
    closes the guard. Raises _HelperFail on any mismatch.
    """
    run_root = check_run_root(run_root_arg)
    if run_root is None:
        raise _HelperFail(
            f"foreign run-root: {str(run_root_arg)[:80]!r}")
    try:
        guard = RootAuthority(run_root)
    except RootAuthorityError as exc:
        raise _HelperFail(str(exc))
    if (guard.dev, guard.ino) != (dev, ino):
        guard.close()
        raise _HelperFail(
            f"run-root identity mismatch: live=({guard.dev},"
            f"{guard.ino}) expected=({dev},{ino}); refusing")
    return (run_root, guard)


def _open_verified_operand(run_root, path, dev, ino, kind):
    """Open an absolute operand with no following, verifying identity.

    S15-round3: `kind` is "regular" or "dir". The operand must be
    contained in `run_root` (callers pass aux roots separately
    where layers legitimately live outside), must open with
    O_NOFOLLOW, and must fstat to the expected (dev, ino) with
    the expected kind. Anything else raises _HelperFail.
    Returns the open fd; the caller closes it.
    """
    if not path or not os.path.isabs(path):
        raise _HelperFail(f"operand not absolute: {str(path)[:80]!r}")
    if not contained(os.path.normpath(path), run_root):
        raise _HelperFail(
            f"operand outside run-root: {str(path)[:80]!r}")
    flags = os.O_NOFOLLOW | os.O_CLOEXEC
    if kind == "dir":
        flags |= os.O_RDONLY | os.O_DIRECTORY
    else:
        flags |= os.O_RDWR
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _HelperFail(
            f"operand not openable: {str(path)[:80]!r}: {exc}")
    try:
        st = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise _HelperFail(
            f"operand not statable: {str(path)[:80]!r}: {exc}")
    good = (stat.S_ISDIR(st.st_mode) if kind == "dir"
            else stat.S_ISREG(st.st_mode))
    if (st.st_dev, st.st_ino) != (dev, ino) or not good:
        os.close(fd)
        raise _HelperFail(
            f"operand identity mismatch: {str(path)[:80]!r} "
            f"live=({st.st_dev},{st.st_ino}) "
            f"expected=({dev},{ino}); refusing")
    return fd


def make_ext4_command(args):
    """Privileged-internal: mkfs.ext4 on a verified image file. (S15)

    Never invoked by hand: provision_ext4 re-execs this file
    under sudo so the privileged format verifies its operand
    itself, in the same process that formats, operating on
    /dev/fd/N — no pathname resolution between verification
    and effect. Prints `made-ext4 <image>` or `FAILED:
    <reason>`; exit 0/1.
    """
    try:
        run_root, guard = _bind_helper_root(
            args.run_root, args.root_dev, args.root_ino)
        try:
            fd = _open_verified_operand(
                run_root, args.image, args.dev, args.ino,
                "regular")
            try:
                mkfs = shutil.which("mkfs.ext4")
                if mkfs is None:
                    raise _HelperFail("missing mkfs.ext4 tool")
                try:
                    proc = subprocess.run(
                        [mkfs, "-q", "-F", f"/dev/fd/{fd}"],
                        capture_output=True, text=True,
                        timeout=300, pass_fds=[fd])
                except subprocess.TimeoutExpired:
                    raise _HelperFail("mkfs.ext4 timed out")
                except OSError as exc:
                    raise _HelperFail(
                        f"mkfs.ext4 exec failed: {exc}")
                if proc.returncode != 0:
                    raise _HelperFail(
                        f"mkfs.ext4 refused: {tail(proc.stderr)}")
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass
        finally:
            guard.close()
    except _HelperFail as exc:
        print(f"FAILED: {exc}")
        return 1
    print(f"made-ext4 {args.image}")
    return 0


def make_ext4_via_helper(run_root, guard, image, dev, ino):
    """Format one verified image through the privileged helper.

    Returns None on success, else a failure string. The helper
    re-verifies the run-root and image identities in-process,
    so caller observations going stale cannot redirect the
    format. (S15)
    """
    helper = os.path.abspath(__file__)
    rc, out, err = run_sudo(
        [sys.executable, helper, "make-ext4",
         "--run-root", run_root,
         "--root-dev", str(guard.dev),
         "--root-ino", str(guard.ino),
         "--image", image,
         "--dev", str(dev), "--ino", str(ino)],
        timeout=330)
    if rc == 0 and out.startswith("made-ext4 "):
        return None
    return f"mkfs.ext4 refused: rc={rc} {tail(out or err)}"


def attach_loop_command(args):
    """Privileged-internal: bind a loop device to a verified image. (S15)

    Never invoked by hand: provision_ext4 re-execs this file
    under sudo so the privileged attach opens the image itself,
    verifies the caller's (dev, ino), and configures a free
    loop device natively (LOOP_CONFIGURE on the held fd) — the
    caller's pathname never reaches a privileged resolver, and
    no external losetup binary resolves operands. The live
    association is verified (LOOP_GET_STATUS64) before the
    report. Prints `attached-loop /dev/loopN` or `FAILED:
    <reason>`; exit 0/1.
    """
    try:
        run_root, guard = _bind_helper_root(
            args.run_root, args.root_dev, args.root_ino)
        try:
            img_fd = _open_verified_operand(
                run_root, args.image, args.dev, args.ino,
                "regular")
            try:
                loop = _configure_free_loop(
                    img_fd, args.dev, args.ino)
            finally:
                try:
                    os.close(img_fd)
                except OSError:
                    pass
        finally:
            guard.close()
    except _HelperFail as exc:
        print(f"FAILED: {exc}")
        return 1
    print(f"attached-loop {loop}")
    return 0


def _configure_free_loop(img_fd, expect_dev, expect_ino):
    """Bind a free /dev/loopN to held image fd `img_fd`. (S15)

    Returns the bound device path. The configured device fd is
    retained through the post-verify read — no pathname
    re-resolution between configure and validation, so a
    device-node swap cannot forge a mismatch.

    S73: the post-verify never clears. A mismatch means the
    device was rebound after our configure (the live
    association is foreign now) or the expectation was stale
    (the live association is still ours — the caller's
    reconcile adopts it); an unreadable status means ownership
    is unestablished. Rollback may retire only an association
    whose ownership remains established, so both refuse and
    leave the device in place for reconcile — never a
    reopen-by-name CLR of a foreign or unverified association.
    Raises _HelperFail when no free device exists, the
    configure fails, or the post-verify refuses.
    """
    try:
        ctl = os.open("/dev/loop-control",
                      os.O_RDWR | os.O_CLOEXEC)
    except OSError as exc:
        raise _HelperFail(f"loop-control not openable: {exc}")
    try:
        try:
            num = fcntl.ioctl(ctl, LOOP_CTL_GET_FREE)
        except OSError as exc:
            raise _HelperFail(f"no free loop device: {exc}")
    finally:
        try:
            os.close(ctl)
        except OSError:
            pass
    loop = f"/dev/loop{num}"
    try:
        loop_fd = os.open(loop, os.O_RDWR | os.O_CLOEXEC)
    except OSError as exc:
        raise _HelperFail(f"loop {loop} not openable: {exc}")
    try:
        config = (struct.pack("<II", img_fd, 0) + bytes(232)
                  + bytes(64))
        try:
            fcntl.ioctl(loop_fd, LOOP_CONFIGURE, config)
        except OSError as exc:
            raise _HelperFail(
                f"loop {loop} configure failed: {exc}")
        try:
            ident = _loop_get_status_on(loop_fd)
        except LoopIdUnavailable as exc:
            raise _HelperFail(
                f"loop {loop} association unverifiable ({exc}); "
                f"left in place for reconcile")
        if ident is None:
            raise _HelperFail(
                f"loop {loop} detached after configure; left "
                f"for reconcile")
        if ident != (expect_dev, expect_ino):
            raise _HelperFail(
                f"loop {loop} association mismatch: live={ident} "
                f"expected=({expect_dev},{expect_ino}); left in "
                f"place (foreign or rebound, never cleared)")
    finally:
        try:
            os.close(loop_fd)
        except OSError:
            pass
    return loop


def attach_loop_via_helper(run_root, guard, image, dev, ino):
    """Attach a loop to one verified image through the helper.

    Returns (loop, None) on success, else (None, failure).
    The helper verifies the image identity in-process and
    reports the bound device; the caller still re-verifies the
    live association before adoption. (S15)
    """
    helper = os.path.abspath(__file__)
    rc, out, err = run_sudo(
        [sys.executable, helper, "attach-loop",
         "--run-root", run_root,
         "--root-dev", str(guard.dev),
         "--root-ino", str(guard.ino),
         "--image", image,
         "--dev", str(dev), "--ino", str(ino)],
        timeout=120)
    if rc == 0 and out.startswith("attached-loop /dev/loop"):
        candidate = out.split()[1] if len(out.split()) > 1 else ""
        if candidate.startswith("/dev/loop"):
            return (candidate, None)
    return (None,
            f"losetup refused: rc={rc} {tail(out or err)}")


def _mount2(source, target, fstype, flags, data):
    """In-process mount(2); returns None on success, else errno. (S15)"""
    libc = _libc_handle()
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_char_p, ctypes.c_ulong,
                           ctypes.c_char_p]
    libc.mount.restype = ctypes.c_int
    rc = libc.mount(os.fsencode(source), os.fsencode(target),
                    os.fsencode(fstype), flags,
                    None if data is None else os.fsencode(data))
    if rc == 0:
        return None
    return ctypes.get_errno()


def _parse_layer_spec(spec):
    """Parse one NAME=ABS_PATH:DEV:INO layer spec. (S15)

    Raises _HelperFail on any malformed spec.
    """
    try:
        name, rest = spec.split("=", 1)
        path, dev, ino = rest.rsplit(":", 2)
        dev = int(dev)
        ino = int(ino)
    except (ValueError, AttributeError):
        raise _HelperFail(f"malformed layer spec: {spec[:80]!r}")
    if name not in ("lower", "upper", "work"):
        raise _HelperFail(f"bad layer name: {name[:20]!r}")
    if not path or not os.path.isabs(path):
        raise _HelperFail(f"layer path not absolute: {spec[:80]!r}")
    return (name, path, dev, ino)


def mount_fs_command(args):
    """Privileged-internal: mount one verified filesystem. (S15)

    Never invoked by hand: provision_ext4/mount_overlay re-exec
    this file under sudo so the privileged mount opens every
    operand itself (target dir, loop device, overlay layers),
    verifies each (dev, ino) against the caller's creation-time
    observation, and calls mount(2) on /dev/fd/N operands — no
    pathname resolution between verification and effect. The
    live row is post-verified (row selection plus acquisition
    binding: loop-device correspondence for ext4, upper-canary
    content for overlay) and reported; with --own-uid/gid
    the fresh root is fchown'd through a mount-ID-correspondent
    fd (no pathname chown), only after the binding passes.
    Prints `mounted <target> mnt=<id> source=<src> super=<opts>`
    or `FAILED: <reason>`; exit 0/1.

    S74: post-effect failures carry their own taxonomy so the
    caller never discharges custody it still holds. `FAILED-
    UNCERTAIN: <reason>` means mount(2) returned 0 but the
    occupant could not be proven (missing, ambiguous, or
    binding-refused row) — keep pending. `FAILED-MOVED:
    mnt=<id> observed=<esc-target> <reason>` means the
    occupant passed every gate at a renamed mountpoint — keep
    pending with the reported mount ID for recovery.
    """
    try:
        run_root, guard = _bind_helper_root(
            args.run_root, args.root_dev, args.root_ino)
        # S17-round4: serialize against concurrent retire-mount
        # detaches (and vice versa); _HelperFail maps to FAILED.
        lock_fd = _mount_exclock_acquire(run_root)
        try:
            target_fd = _open_verified_operand(
                run_root, args.target, args.target_dev,
                args.target_ino, "dir")
            try:
                if args.fstype == "ext4":
                    row, pin_fd = _mount_ext4_now(
                        args, run_root, target_fd)
                elif args.fstype == "overlay":
                    row, pin_fd = _mount_overlay_now(
                        args, run_root, target_fd)
                else:
                    raise _HelperFail(
                        f"unsupported fstype: "
                        f"{str(args.fstype)[:20]!r}")
            finally:
                try:
                    os.close(target_fd)
                except OSError:
                    pass
            # S81-round5: the pin transfers from post-verify —
            # it stays held through the chown (a swap there
            # still needs a lazy detach, which the pin
            # survives) and closes before the report.
            try:
                if args.own_uid is not None:
                    _own_fresh_root(args, run_root, pin_fd)
            finally:
                try:
                    os.close(pin_fd)
                except OSError:
                    pass
        finally:
            _mount_exclock_release(lock_fd)
            guard.close()
    except _HelperMoved as exc:
        # S74: structured moved report — the escaped observed
        # target stays single-line (S77 codec); both fields are
        # capped so the line survives the caller's error tail.
        observed = _escape_report_field(str(exc.observed))[:150]
        print(f"FAILED-MOVED: mnt={exc.mnt_id} observed={observed} "
              f"{str(exc)[:120]}")
        return 1
    except _HelperUncertain as exc:
        print(f"FAILED-UNCERTAIN: {exc}")
        return 1
    except _HelperFail as exc:
        print(f"FAILED: {exc}")
        return 1
    print(_format_mounted_line(
        args.target, row["mnt_id"],
        row["source"], row["super"]))
    return 0


def _mount_ext4_now(args, run_root, target_fd):
    """mount(2) one ext4 loop fs on held fds; (row, pin_fd).

    S15-round4: the loop device is opened once — its kernel
    backing is validated through that same held descriptor
    (LOOP_GET_STATUS64, no pathname re-resolution) and the
    mount sources /dev/fd/N of it. A device-node substitution
    between a validate-open and a separate mount-open cannot
    redirect the filesystem source: there is no second open.

    S81-round5: the loop fd stays open through post-verify —
    the binding re-reads the RETAINED description (device +
    backing), never the spelling, so a node substitution
    between validation and verification cannot redirect the
    proof either.
    """
    if not args.loop or not args.loop.startswith("/dev/loop"):
        raise _HelperFail(
            f"foreign loop device: {str(args.loop)[:40]!r}")
    try:
        loop_fd = os.open(args.loop,
                          os.O_RDWR | os.O_NOFOLLOW
                          | os.O_CLOEXEC)
    except FileNotFoundError:
        raise _HelperFail(
            f"loop {args.loop} not bound; refusing mount")
    except OSError as exc:
        raise _HelperFail(f"loop {args.loop} not openable: {exc}")
    try:
        try:
            ident = _loop_get_status_on(loop_fd)
        except LoopIdUnavailable as exc:
            raise _HelperFail(
                f"loop {args.loop} backing unverifiable ({exc}); "
                f"refusing mount")
        if ident is None:
            raise _HelperFail(
                f"loop {args.loop} not bound; refusing mount")
        if ident != (args.backing_dev, args.backing_ino):
            raise _HelperFail(
                f"loop {args.loop} backing not ours "
                f"(live={ident}); refusing mount")
        try:
            # S74: pre-effect snapshot for diff selection — a
            # target renamed around the effect is still found at
            # its observed mountpoint. Unreadable here is a plain
            # refusal: mount(2) never runs.
            pre = _snapshot_mount_rows()
        except AdmissionError as exc:
            raise _HelperFail(
                f"mount table unreadable before mount: {exc}")
        err = _mount2(f"/dev/fd/{loop_fd}",
                      f"/dev/fd/{target_fd}", "ext4",
                      MS_RELATIME, None)
        if err is not None:
            raise _HelperFail(
                f"mount {args.target} failed: {os.strerror(err)}")
        return _post_verify_mount(
            args.target, "ext4", args.loop, loop=args.loop,
            loop_fd=loop_fd,
            backing=(args.backing_dev, args.backing_ino),
            pre=pre)
    finally:
        try:
            os.close(loop_fd)
        except OSError:
            pass


def _mount_overlay_now(args, run_root, target_fd):
    """mount(2) one overlay stack on held fds; (row, pin_fd)."""
    specs = args.layer or []
    if len(specs) != 3:
        raise _HelperFail(
            f"overlay needs 3 layers, got {len(specs)}")
    aux_root = None
    if args.aux_root is not None:
        aux_root = _verify_aux_root(args)
    layers = {}
    for spec in specs:
        name, path, dev, ino = _parse_layer_spec(spec)
        if name in layers:
            raise _HelperFail(f"duplicate layer: {name}")
        under_run = contained(os.path.normpath(path), run_root)
        under_aux = (aux_root is not None and contained(
            os.path.normpath(path), aux_root))
        if not (under_run or under_aux):
            raise _HelperFail(
                f"layer {name} outside run-root and aux-root: "
                f"{path[:80]!r}")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY
                         | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise _HelperFail(
                f"layer {name} not openable: {exc}")
        try:
            st = os.fstat(fd)
        except OSError as exc:
            os.close(fd)
            raise _HelperFail(
                f"layer {name} not statable: {exc}")
        if ((st.st_dev, st.st_ino) != (dev, ino)
                or not stat.S_ISDIR(st.st_mode)):
            os.close(fd)
            raise _HelperFail(
                f"layer {name} identity mismatch: "
                f"live=({st.st_dev},{st.st_ino}) "
                f"expected=({dev},{ino}); refusing")
        layers[name] = fd
    try:
        # S81-round5: overlay post-mount binding is mandatory
        # — the expected token pins from the HELD upper fd
        # before any effect (never from argv: cmdline is
        # world-readable).
        # S81-round6: the token FILE is 0600 (the round-5
        # "upper is 0700" premise was wrong — layer dirs are
        # 0755; only the file mode keeps the token from other
        # users, and only the pin probe below keeps a copied
        # token from minting a pre-pin clone).
        expected = _read_upper_canary(layers["upper"])
        extra = args.extra_opts or ""
        if extra and not _OVERLAY_EXTRA_RE.fullmatch(extra):
            raise _HelperFail(
                f"bad overlay extra opts: {extra[:60]!r}")
        data = (f"lowerdir=/dev/fd/{layers['lower']},"
                f"upperdir=/dev/fd/{layers['upper']},"
                f"workdir=/dev/fd/{layers['work']}{extra}")
        # S74: pre-effect snapshot for diff selection (see the
        # ext4 path); unreadable here refuses before mount(2).
        try:
            pre = _snapshot_mount_rows()
        except AdmissionError as exc:
            raise _HelperFail(
                f"mount table unreadable before mount: {exc}")
        err = _mount2("overlay", f"/dev/fd/{target_fd}",
                      "overlay", MS_RELATIME, data)
    finally:
        # S81-round6: the upper fd stays open through
        # post-verify — the pin probe reads OUR upper
        # through this held verified description (no
        # pathname re-resolution on the upper side).
        for name, fd in layers.items():
            if name == "upper":
                continue
            try:
                os.close(fd)
            except OSError:
                pass
    if err is not None:
        try:
            os.close(layers["upper"])
        except OSError:
            pass
        raise _HelperFail(
            f"mount {args.target} failed: {os.strerror(err)}")
    try:
        return _post_verify_mount(
            args.target, "overlay", "overlay",
            canary=expected, pre=pre,
            upper_fd=layers["upper"])
    finally:
        try:
            os.close(layers["upper"])
        except OSError:
            pass


def _verify_aux_root(args):
    """Verify a declared aux root's identity; return its path."""
    aux = check_run_root(args.aux_root)
    if aux is None:
        raise _HelperFail(
            f"foreign aux-root: {str(args.aux_root)[:80]!r}")
    try:
        fd = os.open(aux, os.O_RDONLY | os.O_DIRECTORY
                     | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise _HelperFail(f"aux-root not openable: {exc}")
    try:
        st = os.fstat(fd)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if (st.st_dev, st.st_ino) != (args.aux_dev, args.aux_ino):
        raise _HelperFail(
            f"aux-root identity mismatch: live=({st.st_dev},"
            f"{st.st_ino}); refusing")
    return aux


def _snapshot_mount_rows():
    """Pre-effect mount-table snapshot as row tuples. (S74)

    The post-verify diff selects our effect by table
    difference, so a target renamed around mount(2) is still
    found at its observed mountpoint.
    """
    return frozenset(
        (row["mnt_id"], row["target"], row["fstype"],
         row["source"], row["super"], row["root"])
        for row in read_mount_table())


def _pin_fresh_mount(target):
    """Open+identify the just-mounted target; (fd, mnt_id). (S81-round5)

    The held fd pins OUR vfsmount: a regular umount goes
    EBUSY while it is open (verified live, both O_PATH and
    O_RDONLY), so a replacement inside the post-mount window
    needs a lazy detach — which keeps our mount (and its ID)
    alive, so the post-verify cross-check (pinned ID versus
    the live row's ID) cannot be fooled by ID recycling
    (verified live: a detached-but-held mount keeps its ID
    and the next mount takes a fresh one). Uses O_RDONLY:
    fchown and openat need more than O_PATH (EBADF, verified
    live). Ownership transfers to the caller, which closes
    after the report. Raises _HelperUncertain when the fresh
    mount cannot be pinned (post-effect by construction —
    mount(2) already returned 0).
    """
    try:
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY
                     | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise _HelperUncertain(
            f"fresh mount at {target} not pinnable ({exc}); "
            f"left in place")
    try:
        mid = _mnt_id_of(fd)
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        raise _HelperUncertain(
            f"fresh mount identity unreadable ({exc}); refusing")
    return (fd, mid)


def _verify_mount_row(row, at, fstype, source, loop=None,
                      canary=None, loop_fd=None, backing=None):
    """Refusal reason for a candidate post-effect row, or None. (S74)

    The row gates shared by the pathname and table-diff
    selection paths: expected fstype/source (a /dev/fd/N
    spelling matches a device source — the kernel records
    fd-bound operands literally) plus the acquisition
    binding (loop-device correspondence for ext4, upper
    canary for overlay), checked live at `at`. A passing row
    is proven ours independently of any pathname.

    S81-round5: the ext4 binding reads the RETAINED loop
    description (`loop_fd`, still open from the mount — never
    re-resolved) for both the device correspondence and the
    backing recheck, so a device-node substitution between
    validation and verification cannot redirect the proof;
    the canary read binds to the row's mount ID.
    """
    if row["fstype"] != fstype:
        return (f"mount {at} occupant not ours "
                f"({row['fstype']},{row['source']}); left in place")
    if row["source"] != source and not (
            source.startswith("/dev/")
            and row["source"].startswith("/dev/fd/")):
        return (f"mount {at} occupant not ours "
                f"({row['fstype']},{row['source']}); left in place")
    if loop is not None and not _mount_matches_loop(
            at, loop, row, loop_fd):
        return f"mount {at} occupant not on {loop}; left in place"
    if backing is not None:
        try:
            ident = (_loop_get_status_on(loop_fd)
                     if loop_fd is not None else None)
        except (AdmissionError, OSError):
            ident = None
        if ident != backing:
            return (f"mount {at} loop backing changed; "
                    f"left in place")
    if canary is not None and not _canary_matches(
            at, MOUNT_CANARY_NAME, canary,
            expect_mnt_id=row.get("mnt_id")):
        return f"mount {at} canary mismatch; left in place"
    return None


def _recover_unpinned_mount(target, fstype, source, loop,
                            canary, loop_fd, backing, pre,
                            pin_exc):
    """ID-keyed recovery when the pin open fails. (S74-round6)

    The fresh mount's pathname vanished before the pin (the
    target's parent renamed around the effect, possibly out
    of the run root) — mounting through the held operand
    still succeeded. Instead of going ID-less (which the
    pending path then silently continues past and the final
    sweep cannot see outside the run root), recover by table
    difference: added rows passing every binding gate are
    ours wherever they sit. Returns the exception to raise:
    _HelperMoved on a unique match (downstream keeps ID-keyed
    recovery custody and reports manual retirement loudly),
    _HelperUncertain when nothing matches (the original pin
    failure) or the match is ambiguous. With no pre snapshot
    the whole table is gated (bounded scan); a truncated scan
    stays uncertain, never a false recovery.
    """
    try:
        table = read_mount_table()
    except AdmissionError:
        return pin_exc
    ours = []
    truncated = False
    for index, added in enumerate(table):
        if index >= 2048:
            truncated = True
            break
        if pre is not None and (
                added["mnt_id"], added["target"],
                added["fstype"], added["source"],
                added["super"], added["root"]) in pre:
            continue
        if _verify_mount_row(
                added, added["target"], fstype, source,
                loop, canary, loop_fd, backing) is None:
            ours.append(added)
    if len(ours) == 1 and not truncated:
        row = ours[0]
        if len(find_mounts(table, row["target"])) != 1:
            return _HelperUncertain(
                f"ambiguous stacked mount at {row['target']} "
                f"after create; left in place")
        return _HelperMoved(
            row["mnt_id"], row["target"],
            f"target moved during mount (mountpoint now "
            f"{row['target'][:80]!r}); pin failed "
            f"({pin_exc}), recovered by table difference")
    if truncated:
        return _HelperUncertain(
            f"mount {target} pin failed ({pin_exc}); recovery "
            f"scan truncated; left in place")
    if len(ours) > 1:
        return _HelperUncertain(
            f"ambiguous moved mount after pin failure "
            f"({len(ours)} gate-passing rows); left in place")
    return pin_exc


def _pin_probe_upper(pin_fd, upper_fd):
    """Challenge-response binding the pin to OUR upper. (S81)

    Writes a fresh random probe through the pin fd (into the
    pinned mount's upper layer, wherever that is) and demands
    the same bytes from the HELD verified upper dir fd. A
    pre-pin replacement carrying the copied pre-mount token
    shows the right canary but drains to the attacker's upper
    — our upper lacks the probe, so the clone refuses before
    any chown or report. Both reads are O_NOFOLLOW and
    descriptor-bound (no pathname re-resolution); the probe
    name is unpredictable per attempt (no pre-placement) and
    O_EXCL-created 0600; anything unreadable, missing or
    mismatched refuses. Returns None when bound, else the
    refusal reason. Residual: an attacker who copies the
    probe content into our upper inside the write-to-read
    microsecond window, or who mounts our own upperdir as
    their clone's upper — both still need the un-synchronizable
    pre-pin race first.
    """
    name = MOUNT_PROBE_PREFIX + secrets.token_hex(8)
    value = secrets.token_hex(16).encode("ascii")
    try:
        out = os.open(name,
                      os.O_WRONLY | os.O_CREAT | os.O_EXCL
                      | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                      dir_fd=pin_fd)
    except OSError as exc:
        return f"pin probe not writable ({exc}); left in place"
    try:
        try:
            view = memoryview(value)
            while view:
                done = os.write(out, view)
                view = view[done:]
            os.fsync(out)
        finally:
            try:
                os.close(out)
            except OSError:
                pass
    except OSError as exc:
        return f"pin probe not writable ({exc}); left in place"
    try:
        back = os.open(name,
                       os.O_RDONLY | os.O_NOFOLLOW
                       | os.O_NONBLOCK | os.O_CLOEXEC,
                       dir_fd=pin_fd)
    except OSError as exc:
        return f"pin probe not readable ({exc}); left in place"
    try:
        seen_pin = _read_capped(back, 256)
    finally:
        try:
            os.close(back)
        except OSError:
            pass
    if seen_pin != value:
        return "pin probe mismatch in pinned mount; left in place"
    try:
        ours = os.open(name,
                       os.O_RDONLY | os.O_NOFOLLOW
                       | os.O_NONBLOCK | os.O_CLOEXEC,
                       dir_fd=upper_fd)
    except OSError:
        return ("pin probe absent from our upper (pinned mount "
                "does not drain there); left in place")
    try:
        seen_upper = _read_capped(ours, 256)
    finally:
        try:
            os.close(ours)
        except OSError:
            pass
    if seen_upper != value:
        return ("pin probe mismatch in our upper; "
                "left in place")
    return None


def _post_verify_mount(target, fstype, source, loop=None,
                       canary=None, pre=None, loop_fd=None,
                       backing=None, upper_fd=None):
    """The live row + pin fd for a just-created mount. (S15)

    Exactly one row at the target, with the expected fstype
    and source; anything else (absent, stacked, foreign) is a
    FAILED mount, never reported as success. A /dev/fd/N
    source spelling matches a device source: the kernel
    records our fd-bound operand literally, and the row
    appeared synchronously with our mount(2) (mount ran only
    after every operand verified, and failure returns before
    this read). No rollback detach here: an unverified
    occupant is never unmounted — the caller keeps pending
    custody. Returns (row, pin_fd); the pin stays open for
    the caller (chown + report) and is closed here on every
    raise.

    S81-round5: the target is pinned BEFORE the post-mount
    window opens, and the pin decides. A regular umount goes
    EBUSY while the pin is held, so a replacement needs a
    lazy detach — which keeps our mount (and ID) alive, so
    the cross-check (pinned ID versus the live row's ID)
    refuses any stranger deterministically, independent of
    replayable content: a copied-token replacement still
    carries a fresh ID. Diff selection narrows added rows to
    our pinned ID first (a parallel job's mount in the same
    window is ignored, not ambiguous); the gates then confirm
    the selected row as before. Residual: a swap landing
    between mount(2) and the pin-open (microseconds, no
    synchronizable hook — blind preemption luck) with a
    perfect clone is accepted; everything else refuses.

    S81-round6: the pin probe supersedes that residual for
    overlay mounts given the held upper fd (`upper_fd`): a
    fresh random challenge written through the pin must show
    in OUR upper, so a copied-token pre-pin clone (the only
    perfect clone the round-5 window admitted) refuses before
    any chown or report. What remains needs the same blind
    pre-pin race PLUS a probe-copy microsecond win or our own
    upperdir as the clone's upper.

    S74-round4: every raise below is post-effect (mount(2)
    returned 0), so failures are _HelperUncertain — the
    caller must keep pending custody — never plain
    pre-effect refusals. When `pre` (a _snapshot_mount_rows
    set taken immediately before the effect) is given, the
    occupant is additionally selected by table difference:
    the added row carrying our pinned ID is ours wherever it
    sits; at a renamed mountpoint that is a _HelperMoved
    report (mount ID plus observed target for ID-keyed
    recovery) instead of a false failure. With no
    diff-selected occupant the pathname proof below runs
    unchanged (a same-name replacement fails the cross-check
    with the established reasons).

    S74-round6: a pin-open failure (the target renamed before
    the pin, possibly out of the run root) no longer goes
    ID-less — _recover_unpinned_mount gates the added rows
    and reports _HelperMoved on a unique match, so pending
    custody keeps the mount ID and the observed target
    instead of an unrecoverable pathname. Unmatched or
    ambiguous recovery re-raises uncertainty (loud-retained
    downstream, never silently discharged).
    """
    _test_pre_pin_delay()
    try:
        pin_fd, pin_mnt = _pin_fresh_mount(target)
    except _HelperUncertain as pin_exc:
        raise _recover_unpinned_mount(
            target, fstype, source, loop, canary, loop_fd,
            backing, pre, pin_exc)
    try:
        _test_post_mount_delay()
        try:
            table = read_mount_table()
        except AdmissionError as exc:
            raise _HelperUncertain(
                f"mount table unreadable after mount: {exc}")
        row = None
        if pre is not None:
            ours = [
                added for added in table
                if (added["mnt_id"], added["target"],
                    added["fstype"], added["source"],
                    added["super"], added["root"]) not in pre
                and added["mnt_id"] == pin_mnt
                and _verify_mount_row(
                    added, added["target"], fstype, source,
                    loop, canary, loop_fd, backing) is None]
            if len(ours) > 1:
                raise _HelperUncertain(
                    f"duplicate mount ID {pin_mnt} after "
                    f"create; left in place")
            if len(ours) == 1:
                row = ours[0]
                if len(find_mounts(table, row["target"])) != 1:
                    raise _HelperUncertain(
                        f"ambiguous stacked mount at "
                        f"{row['target']} after create")
                if row["target"] != target:
                    raise _HelperMoved(
                        row["mnt_id"], row["target"],
                        f"target moved during mount (mountpoint now "
                        f"{row['target'][:80]!r})")
        if row is None:
            rows = find_mounts(table, target)
            if not rows:
                raise _HelperUncertain(
                    f"mount {target} missing after create")
            if len(rows) > 1:
                raise _HelperUncertain(
                    f"ambiguous stacked mount at {target} "
                    f"after create")
            refusal = _verify_mount_row(
                rows[0], target, fstype, source,
                loop, canary, loop_fd, backing)
            if refusal is not None:
                raise _HelperUncertain(refusal)
            row = rows[0]
        if row["mnt_id"] != pin_mnt:
            raise _HelperUncertain(
                f"mount at {target} changed during effect "
                f"(pinned mnt={pin_mnt}, live "
                f"mnt={row['mnt_id']}); left in place")
        if upper_fd is not None:
            refusal = _pin_probe_upper(pin_fd, upper_fd)
            if refusal is not None:
                raise _HelperUncertain(
                    f"mount {target} {refusal}")
        return (row, pin_fd)
    except BaseException:
        try:
            os.close(pin_fd)
        except OSError:
            pass
        raise


def _test_post_mount_delay():
    """Test-only post-mount pause for replacement tests. (S81)

    Reads S81_HELPER_POST_MOUNT_DELAY_MS (bounded, garbage
    means none) and sleeps before the first post-read, so the
    live suite can plant a foreign replacement inside the
    window deterministically. Production `run_sudo` passes no
    environment (plain `sudo -n` with env_reset), so this
    never fires outside `sudo env ...` test invocations.
    """
    try:
        delay_ms = int(os.environ.get(
            "S81_HELPER_POST_MOUNT_DELAY_MS", "0"))
    except ValueError:
        return
    delay_ms = max(0, min(delay_ms, 30_000))
    if delay_ms:
        time.sleep(delay_ms / 1000.0)


def _test_pre_pin_delay():
    """Test-only pre-pin pause for move-recovery tests. (S74)

    Reads S74_PRE_PIN_DELAY_MS (bounded, garbage means none)
    and sleeps after mount(2) but before the pin open, so the
    live suite can rename the target's parent (moving the
    fresh mount outside the run root) deterministically
    before pin acquisition. Same production silence as the
    post-mount delay (no env through `run_sudo`).
    """
    try:
        delay_ms = int(os.environ.get(
            "S74_PRE_PIN_DELAY_MS", "0"))
    except ValueError:
        return
    delay_ms = max(0, min(delay_ms, 30_000))
    if delay_ms:
        time.sleep(delay_ms / 1000.0)


def _own_fresh_root(args, run_root, pin_fd):
    """fchown the fresh mount root to --own-uid/gid. (S15)

    The chown addresses the post-verify PIN fd — the same
    held description the cross-check proved is the selected
    row's mount — never a fresh pathname open (which would
    re-resolve the mutable target and re-compare against an
    already-selected row, both sides wrong after a swap).

    S74-round5: every failure here raises _HelperUncertain,
    never plain _HelperFail — the mount fired and verified
    before this stage, so the outcome is post-effect by
    construction and the caller must keep pending custody
    (a plain FAILED would normalize as a pre-effect refusal
    and discharge a live mount).
    """
    if args.own_gid is None:
        raise _HelperUncertain("own-gid required with own-uid")
    if not contained(os.path.normpath(args.target), run_root):
        raise _HelperUncertain(
            f"own target outside run-root: "
            f"{str(args.target)[:80]!r}")
    try:
        os.fchown(pin_fd, args.own_uid, args.own_gid)
    except OSError as exc:
        raise _HelperUncertain(f"fresh root chown failed: {exc}")


def mount_fs_via_helper(run_root, guard, target, target_dev,
                        target_ino, fstype, loop=None,
                        backing=None, layers=(), extra_opts="",
                        aux=None, own=None):
    """Mount one verified filesystem through the helper. (S15)

    `backing` is (dev, ino) for ext4; `layers` is a list of
    (name, path, dev, ino); `aux` is (path, dev, ino) or None;
    `own` is (uid, gid) or None. The overlay post-mount
    binding token is NOT passed (S81-round5: argv is
    world-readable) — the controller plants the file in upper
    and the helper reads the expectation from its held upper
    fd. Returns ((mnt_id, source, super), None) on success —
    the helper's post-verified observation, which joins the
    adoption fingerprint — else (None, failure).
    """
    helper = os.path.abspath(__file__)
    argv = [sys.executable, helper, "mount-fs",
           "--run-root", run_root,
           "--root-dev", str(guard.dev),
           "--root-ino", str(guard.ino),
           "--target", target,
           "--target-dev", str(target_dev),
           "--target-ino", str(target_ino),
           "--fstype", fstype]
    if fstype == "ext4":
        argv += ["--loop", loop,
                "--backing-dev", str(backing[0]),
                "--backing-ino", str(backing[1])]
    else:
        for name, path, dev, ino in layers:
            argv += ["--layer", f"{name}={path}:{dev}:{ino}"]
        if extra_opts:
            argv += ["--extra-opts", extra_opts]
    if aux is not None:
        argv += ["--aux-root", aux[0],
                "--aux-dev", str(aux[1]),
                "--aux-ino", str(aux[2])]
    if own is not None:
        argv += ["--own-uid", str(own[0]),
                "--own-gid", str(own[1])]
    rc, out, err = run_sudo(argv, timeout=120)
    if rc == 0 and out.startswith("mounted "):
        parsed = _parse_mounted_line(out, target)
        if parsed is not None:
            return (parsed, None)
        # rc==0 means the helper verified the occupant at the
        # requested target — reconcile may still adopt it, so
        # this stays a reconcilable (refused-class) report.
        return (None, f"mount {target} report unparseable: "
                      f"{tail(out or err)}")
    return (None, _normalize_mount_failure(target, rc, out, err))


def _parse_moved_report(text):
    """(mnt_id, observed) from a FAILED-MOVED helper line, or None.

    S74: `observed` is None when the escaped target does not
    decode (truncated mid-escape): the mount ID still
    identifies the effect for recovery.
    """
    match = re.search(
        r"FAILED-MOVED:\s+mnt=(\d+)\s+observed=(\S+)", text or "")
    if match is None:
        return None
    try:
        mnt_id = int(match.group(1))
    except ValueError:
        return None
    return (mnt_id, _unescape_report_field(match.group(2)))


def _normalize_mount_failure(target, rc, out, err):
    """Classify a failed mount-fs invocation. (S74)

    Post-effect outcomes (a moved occupant, an inconclusive
    post-read, a timeout, a helper crash) keep pending
    custody; only pre-effect refusals (plain FAILED, sudo
    exec failure) may reconcile-drop on target absence. The
    normalized strings are the _classify_mount_failure
    contract; the refused shape is unchanged.
    """
    text = f"{out or ''}\n{err or ''}"
    moved = _parse_moved_report(text)
    if moved is not None:
        mnt_id, observed = moved
        if observed is None:
            # The ID survived but the location did not decode:
            # deliberately not the parseable moved shape, so
            # classification degrades to uncertain-with-ID.
            return (f"mount {str(target)[:100]} moved during "
                    f"create (mnt={mnt_id} observed-unknown): "
                    f"{tail(text)[:200]}")
        seen = _escape_report_field(observed)[:150]
        return (f"mount {str(target)[:100]} moved during create "
                f"(mnt={mnt_id} observed={seen}): "
                f"{tail(text)[:200]}")
    if ("FAILED-UNCERTAIN:" in text or rc in (0, 124)
            or (rc == 1 and "FAILED" not in text)
            or rc not in (0, 1, 124, 127)):
        return (f"mount {str(target)[:100]} effect uncertain "
                f"after create: {tail(text)[:200]}")
    # rc==127 (sudo never ran the helper), or rc==1 with a
    # plain pre-effect FAILED report: no effect is possible.
    return (f"mount {target} refused: rc={rc} {tail(out or err)}")


def _classify_mount_failure(failure):
    """(kind, mnt_id, observed) for a mount failure string. (S74)

    `failure` is a mount_fs_via_helper report: "moved" (the
    target was renamed around the effect — ID-keyed recovery
    custody), "uncertain" (the effect may have fired: timeout,
    crash, or an inconclusive helper post-read — never
    discharge), or "refused" (no effect possible: pre-effect
    refusal, sudo exec failure, or an rc==0 report the helper
    had verified and reconcile may adopt). Unparseable moved
    reports degrade to uncertain, keeping the mount ID when
    it survived.
    """
    text = failure or ""
    if "moved during create" in text:
        match = re.search(
            r"moved during create \(mnt=(\d+) observed=(\S+)\)",
            text)
        if match is not None:
            observed = _unescape_report_field(match.group(2))
            if observed is not None:
                return ("moved", int(match.group(1)), observed)
            return ("uncertain", int(match.group(1)), None)
        orphan = re.search(r"moved during create \(mnt=(\d+)",
                           text)
        if orphan is not None:
            return ("uncertain", int(orphan.group(1)), None)
        return ("uncertain", None, None)
    if "effect uncertain after create" in text:
        return ("uncertain", None, None)
    return ("refused", None, None)


_REPORT_ESCAPES = {
    "\\": "\\134",
    " ": "\\040",
    "\t": "\\011",
    "\n": "\\012",
    "\v": "\\013",
    "\f": "\\014",
    "\r": "\\015",
}

_REPORT_UNESCAPES = {v[1:]: k for k, v in _REPORT_ESCAPES.items()}


def _escape_report_field(text):
    """Escape one helper-report field. (S77)

    Kernel-mountinfo-style octal escapes for the framing
    separators (backslash, space, every ASCII line/field
    separator): an admitted LF-containing pathname survives
    the single-line success report instead of splitting it.
    """
    return "".join(_REPORT_ESCAPES.get(char, char) for char in text)


def _unescape_report_field(text):
    """Decode one helper-report field, or None. (S77)

    Unknown escapes refuse (mirroring `unescape_mountinfo`):
    a report we cannot decode exactly is unparseable, never
    guessed at.
    """
    out = []
    i = 0
    while i < len(text):
        char = text[i]
        if char != "\\":
            out.append(char)
            i += 1
            continue
        esc = text[i + 1:i + 4]
        if len(esc) != 3 or esc not in _REPORT_UNESCAPES:
            return None
        out.append(_REPORT_UNESCAPES[esc])
        i += 4
    return "".join(out)


def _format_mounted_line(target, mnt_id, source, super_opts):
    """Format the helper success report with escaped fields. (S77)"""
    return (f"mounted {_escape_report_field(target)} "
            f"mnt={mnt_id} "
            f"source={_escape_report_field(source)} "
            f"super={_escape_report_field(super_opts)}")


def _parse_mounted_line(out, target):
    """Parse `mounted <target> mnt=<id> source=<src> super=<opts>`. (S15)

    Returns (mnt_id, source, super) when the line is
    well-formed AND names the requested target, else None.
    Right-anchored field search, so targets containing spaces
    or field-like spellings still parse exactly.
    S77-round4: the whole response parses as one frame (no
    `splitlines` truncation — an escaped target never carries
    a raw line separator, and a raw one refuses); fields
    unescape after the split, unknown escapes refuse.
    """
    body = out[:-1] if out.endswith("\n") else out
    if "\n" in body or "\r" in body:
        return None
    if not body.startswith("mounted "):
        return None
    rest = body[len("mounted "):]
    mnt_at = rest.rfind(" mnt=")
    source_at = rest.rfind(" source=")
    super_at = rest.rfind(" super=")
    if (mnt_at < 0 or source_at < 0 or super_at < 0
            or not mnt_at < source_at < super_at):
        return None
    raw_target = rest[:mnt_at]
    raw_source = rest[source_at + len(" source="):super_at]
    raw_super = rest[super_at + len(" super="):]
    for field in (raw_source, raw_super):
        if not field or " " in field or "\t" in field:
            return None
    try:
        mnt_id = int(rest[mnt_at + len(" mnt="):source_at])
    except ValueError:
        return None
    decoded_target = _unescape_report_field(raw_target)
    decoded_source = _unescape_report_field(raw_source)
    decoded_super = _unescape_report_field(raw_super)
    if (decoded_target is None or decoded_source is None
            or decoded_super is None):
        return None
    if decoded_target != target:
        return None
    return (mnt_id, decoded_source, decoded_super)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="provision_fs.py")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "create", "inspect", "cleanup"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--manifest", required=True)
        cmd.add_argument("--run-root", required=True)
        if name == "create":
            cmd.add_argument("--privileged", action="store_true")
    helper_cmd = sub.add_parser(
        "retire-helper",
        help="privileged-internal fd-bound removal (invoked via sudo "
             "by cleanup, never by hand)")
    helper_cmd.add_argument("--parent", required=True)
    helper_cmd.add_argument("--name", required=True)
    helper_cmd.add_argument("--dev", required=True, type=int)
    helper_cmd.add_argument("--ino", required=True, type=int)
    mount_cmd = sub.add_parser(
        "retire-mount",
        help="privileged-internal mount detach (invoked via sudo "
             "by cleanup/rollback, never by hand)")
    mount_cmd.add_argument("--run-root", required=True)
    mount_cmd.add_argument("--target", required=True)
    mount_cmd.add_argument("--mnt-id", required=False, type=int,
                           default=None)
    mount_cmd.add_argument("--fstype", required=True)
    mount_cmd.add_argument("--source", required=True)
    mount_cmd.add_argument("--mount-root", required=False, default=None)
    mount_cmd.add_argument("--expect-super", action="append", default=[])
    loop_cmd = sub.add_parser(
        "retire-loop",
        help="privileged-internal loop detach (invoked via sudo "
             "by cleanup/rollback, never by hand)")
    loop_cmd.add_argument("--run-root", required=True)
    loop_cmd.add_argument("--loop", required=True)
    loop_cmd.add_argument("--backing-path", required=True)
    loop_cmd.add_argument("--backing-dev", required=True, type=int)
    loop_cmd.add_argument("--backing-ino", required=True, type=int)
    sig_cmd = sub.add_parser(
        "signal-proc",
        help="privileged-internal pidfd-bound signal (invoked "
             "via sudo by signal_owned on EPERM, never by hand)")
    sig_cmd.add_argument("--pid", required=True)
    sig_cmd.add_argument("--starttime", required=True)
    sig_cmd.add_argument("--signum", required=True)
    nsc_cmd = sub.add_parser(
        "ns-canary",
        help="privileged-internal bounded canary read (invoked "
             "via sudo+nsenter by _canary_matches, never by hand)")
    nsc_cmd.add_argument("--run-root", required=True)
    nsc_cmd.add_argument("--target", required=True)
    nsc_cmd.add_argument("--name", required=True)
    nsc_cmd.add_argument("--expect-mnt-id", required=True)
    make_cmd = sub.add_parser(
        "make-ext4",
        help="privileged-internal verified mkfs (invoked via sudo "
             "by provision_ext4, never by hand)")
    make_cmd.add_argument("--run-root", required=True)
    make_cmd.add_argument("--root-dev", required=True, type=int)
    make_cmd.add_argument("--root-ino", required=True, type=int)
    make_cmd.add_argument("--image", required=True)
    make_cmd.add_argument("--dev", required=True, type=int)
    make_cmd.add_argument("--ino", required=True, type=int)
    attach_cmd = sub.add_parser(
        "attach-loop",
        help="privileged-internal verified loop attach (invoked "
             "via sudo by provision_ext4, never by hand)")
    attach_cmd.add_argument("--run-root", required=True)
    attach_cmd.add_argument("--root-dev", required=True, type=int)
    attach_cmd.add_argument("--root-ino", required=True, type=int)
    attach_cmd.add_argument("--image", required=True)
    attach_cmd.add_argument("--dev", required=True, type=int)
    attach_cmd.add_argument("--ino", required=True, type=int)
    mount_cmd = sub.add_parser(
        "mount-fs",
        help="privileged-internal verified mount (invoked via "
             "sudo by provision_ext4/mount_overlay, never by "
             "hand)")
    mount_cmd.add_argument("--run-root", required=True)
    mount_cmd.add_argument("--root-dev", required=True, type=int)
    mount_cmd.add_argument("--root-ino", required=True, type=int)
    mount_cmd.add_argument("--target", required=True)
    mount_cmd.add_argument("--target-dev", required=True, type=int)
    mount_cmd.add_argument("--target-ino", required=True, type=int)
    mount_cmd.add_argument("--fstype", required=True)
    mount_cmd.add_argument("--loop", required=False, default=None)
    mount_cmd.add_argument("--backing-dev", required=False, type=int,
                           default=None)
    mount_cmd.add_argument("--backing-ino", required=False, type=int,
                           default=None)
    mount_cmd.add_argument("--layer", action="append", default=[])
    mount_cmd.add_argument("--extra-opts", required=False,
                           default="")
    mount_cmd.add_argument("--aux-root", required=False,
                           default=None)
    mount_cmd.add_argument("--aux-dev", required=False, type=int,
                           default=None)
    mount_cmd.add_argument("--aux-ino", required=False, type=int,
                           default=None)
    mount_cmd.add_argument("--own-uid", required=False, type=int,
                           default=None)
    mount_cmd.add_argument("--own-gid", required=False, type=int,
                           default=None)
    # S81-round5: no --canary — the expected overlay token is
    # read from the held upper fd pre-mount (argv is
    # world-readable; the token file is 0600).
    args = parser.parse_args(argv)
    if args.command == "plan":
        return plan_command(args)
    if args.command == "create":
        return _main_create(args)
    if args.command in ("inspect", "cleanup"):
        return _main_inspect_cleanup(args)
    if args.command == "retire-helper":
        return retire_helper_command(args)
    if args.command == "retire-mount":
        return retire_mount_command(args)
    if args.command == "retire-loop":
        return retire_loop_command(args)
    if args.command == "make-ext4":
        return make_ext4_command(args)
    if args.command == "attach-loop":
        return attach_loop_command(args)
    if args.command == "mount-fs":
        return mount_fs_command(args)
    if args.command == "signal-proc":
        return signal_proc_command(args)
    if args.command == "ns-canary":
        return ns_canary_command(args)
    raise AssertionError(f"unhandled command: {args.command}")


def _enter_keeper_ns(command):
    """Re-exec inside the bound ns unless already there. (S99)

    Returns None on success (either already inside, or
    replaced by the re-exec — execvp never returns). Returns
    the command's loud failure code when the entry cannot be
    made (never runs the command outside its namespace).
    """
    if _inside_keeper_ns():
        return None
    try:
        _reexec_inside_ns()
    except (OSError, AdmissionError) as exc:
        print(f"{command}: cannot enter keeper ns: {exc}",
              file=sys.stderr)
        return 1
    return None


def _refuse_without_sudo_grant():
    """fail2 message unless sudo -n works, else None. (S102)

    Shared by main (before any keeper setup) and
    create_command (authoritative, post-entry): a missing
    sudo tool or grant reports as a usage/grant refusal (rc
    2), never as keeper trouble (rc 1).
    """
    if shutil.which("sudo") is None:
        return "missing sudo tool for --privileged create"
    rc, _, err = run_sudo(["true"], timeout=30)
    if rc != 0:
        return (f"missing sudo -n grant for --privileged "
                f"create: {tail(err)}")
    return None


def _main_create(args):
    """Grant-first create entry: validate, then ensure. (S102)

    Usage refusals (foreign run-root, already provisioned,
    missing sudo grant) and unprivileged creates never touch
    keeper infrastructure — no root sleepers, no canary
    mounts, no pidfile. Only a validated --privileged create
    ensures (spawning when needed), re-execs inside, and
    provisions; an ensure failure fails the command (S101:
    never a warn-and-continue onto the host table).
    """
    run_root = check_run_root(args.run_root)
    if run_root is None:
        return fail2(f"foreign run-root: {args.run_root[:80]!r}")
    if os.path.exists(args.manifest):
        return fail2(f"already provisioned: {args.manifest} exists; "
                     "run cleanup first")
    if os.path.exists(run_root):
        return fail2(f"already provisioned: run-root {run_root} exists; "
                     "run cleanup first")
    if not args.privileged:
        return create_command(args)
    refusal = _refuse_without_sudo_grant()
    if refusal is not None:
        return fail2(refusal)
    try:
        ensure_mount_ns()
    except AdmissionError as exc:
        print(f"create: keeper ns unavailable: {exc}",
              file=sys.stderr)
        return 1
    failed = _enter_keeper_ns("create")
    if failed is not None:
        return failed
    return create_command(args)


def _main_inspect_cleanup(args):
    """Bind-only inspect/cleanup entry. (S101/S102)

    Validates the run-root, then routes on the manifest:
    legacy manifests run direct (host); ns-native manifests
    bind the RECORDED keeper (never spawn) and re-exec
    inside; an unreadable manifest binds opportunistically
    (residue scans then see the ns table) or runs unensured
    when no keeper was ever recorded. Anything else —
    recorded-but-unverifiable keeper, identity mismatch,
    unresolved keeper evidence — refuses upfront (rc 1):
    mount custody is unavailable or unresolved, never
    host-fallen-back.
    """
    command = args.command
    run_root = check_run_root(args.run_root)
    if run_root is None:
        return fail2(f"foreign run-root: {args.run_root[:80]!r}")
    try:
        manifest = load_manifest(args.manifest, run_root)
    except AdmissionError:
        return _main_unmanifested(args, command)
    mode = manifest.get("mount_ns")
    if not mode:
        return (inspect_command(args)
                if command == "inspect" else cleanup_command(args))
    try:
        bind_mount_ns(
            expected=mode if isinstance(mode, dict) else None)
    except AdmissionError as exc:
        print(f"{command}: {exc}", file=sys.stderr)
        return 1
    failed = _enter_keeper_ns(command)
    if failed is not None:
        return failed
    return (inspect_command(args)
            if command == "inspect" else cleanup_command(args))


def _main_unmanifested(args, command):
    """Entry when the manifest cannot be loaded. (S101)

    The command owns the refusal (F09 residue scan); this
    only positions the namespace view: bind when a keeper is
    recorded (scans then see the ns table), run unensured
    when none ever was (host scan, helpers refuse). A
    recorded-but-unverifiable keeper, or leftover unresolved
    keeper evidence, refuses — residue in an unreachable
    namespace must never read as a clean host.
    """
    try:
        bind_mount_ns()
    except AdmissionError as exc:
        text = str(exc)
        if "no keeper recorded" in text:
            pidfile, _candir = _keeper_paths()
            if os.path.exists(f"{pidfile}.unresolved"):
                print(f"{command}: unresolved keeper evidence at "
                      f"{pidfile}.unresolved; refusing",
                      file=sys.stderr)
                return 1
        else:
            print(f"{command}: {exc}", file=sys.stderr)
            return 1
    else:
        failed = _enter_keeper_ns(command)
        if failed is not None:
            return failed
    return (inspect_command(args)
            if command == "inspect" else cleanup_command(args))


if __name__ == "__main__":
    sys.exit(main())




