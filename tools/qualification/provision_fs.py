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
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
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
# LOOP_CLR_FD ioctl number (linux/loop.h), stable across arches.
LOOP_CLR_FD = 0x4C81

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


class ProcAbsent(AdmissionError):
    """The process is provably gone (ESRCH/ENOENT)."""


class ProcUnknown(AdmissionError):
    """The process state is unobservable (denial/I/O/malformed).

    S21: unknowns are retained custody, never treated as absent.
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


def run_sudo(argv, timeout=120):
    # S15: while a create holds the run-root authority, every
    # privileged effect is bracketed by re-verification of the held
    # root, so a swapped root fails the create loudly instead of
    # collecting effects into a replacement.
    guard = _ROOT_GUARD
    if guard is not None:
        guard.verify()
    try:
        proc = subprocess.run(
            ["sudo", "-n", *argv], capture_output=True,
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


class RootAuthority:
    """A held run-root directory plus its recorded identity."""

    def __init__(self, path):
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
        if not stat.S_ISDIR(pst.st_mode):
            raise AdmissionError(
                f"manifest parent not a directory: {parent[:80]!r}")
        if ((pst.st_mode & stat.S_IWOTH)
                and not (pst.st_mode & stat.S_ISVTX)):
            raise AdmissionError(
                f"manifest parent is shared and unprotected: "
                f"{parent[:80]!r} (mode {oct(pst.st_mode & 0o7777)}); "
                f"use a private directory")
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


def record_mount(manifest, run_root, role, target, expect_super=()):
    table = read_mount_table()
    rows = find_mounts(table, target)
    if not rows:
        raise AdmissionError(f"mount missing after create: {target}")
    if len(rows) > 1:
        raise AdmissionError(
            f"ambiguous stacked mount at {target}: refusing record")
    row = rows[0]
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

    S18: compares the (dev, ino) of the backing path the kernel
    reports for `loop` against the fstat of the held image
    descriptor — never a bare pathname stat taken after the
    attach reply. Any mismatch, missing association, or
    unreadable backing refuses.
    """
    if not loop or not str(loop).startswith("/dev/loop"):
        return False
    try:
        live = read_loop_backing(loop)
    except AdmissionError:
        return False
    if live is None:
        return False
    try:
        st = os.stat(strip_deleted_suffix(live))
    except OSError:
        return False
    return ((st.st_dev, st.st_ino) == (image_st.st_dev, image_st.st_ino)
            and os.path.normpath(strip_deleted_suffix(live))
            == os.path.normpath(image))


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
    """Every /dev/loopN whose live backing is (dev, ino). (S23)

    Deleted backings ("path (deleted)") never match a live
    image: their pathnames no longer stat.
    """
    matches = []
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
            st = os.stat(strip_deleted_suffix(live))
        except OSError:
            continue
        if (st.st_dev, st.st_ino) == (dev, ino):
            matches.append(loop)
    return matches


def reconcile_loop_attach(manifest, image, dev, ino):
    """Adopt, clear, or retain a loop attach of uncertain outcome.

    Returns the adopted loop name, or None when no effect took
    place (pending dropped) or the outcome stays uncertain
    (pending retained). (S23)
    """
    try:
        matches = scan_loop_by_backing(dev, ino)
    except AdmissionError:
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
    if row["fstype"] != fingerprint.get("fstype"):
        return False
    if row["source"] != fingerprint.get("source"):
        return False
    for want in fingerprint.get("expect_super", []):
        if want not in row["super"]:
            return False
    return True


def reconcile_mount_effect(manifest, run_root, role, target, fingerprint):
    """Adopt, clear, or retain a mount of uncertain outcome. (S23)

    Returns the adopted row, or None when the mount is absent
    (pending dropped) or the outcome stays uncertain (pending
    retained: stacked or foreign occupants are never adopted and
    never removed here).
    """
    try:
        table = read_mount_table()
    except AdmissionError:
        return None
    rows = find_mounts(table, target)
    if not rows:
        drop_pending_acquisition(manifest, "mount", target)
        _persist_now(manifest)
        return None
    if len(rows) == 1 and mount_fingerprint_matches(rows[0], fingerprint):
        record_mount(manifest, run_root, role, target,
                     fingerprint.get("expect_super", []))
        drop_pending_acquisition(manifest, "mount", target)
        _persist_now(manifest)
        return rows[0]
    return None


def mount_pending(manifest, target):
    return any(e.get("kind") == "mount" and e.get("key") == target
               for e in manifest.get("pending_acquisitions", []))


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
        record_pending_acquisition(manifest, {
            "kind": "mount", "key": target, "role": role,
            "target": target, "fstype": fingerprint.get("fstype"),
            "source": fingerprint.get("source"),
            "expect_super": fingerprint.get("expect_super", []),
            "detail": f"rollback table unreadable: {exc}",
        })
        return "rollback table unreadable; custody kept pending"
    if not find_mounts(table, target):
        drop_pending_acquisition(manifest, "mount", target)
        _persist_now(manifest)
        return "mount already absent; nothing rolled back"
    failure = retire_mount_via_helper(run_root, target, fingerprint)
    if failure is None:
        drop_pending_acquisition(manifest, "mount", target)
        _persist_now(manifest)
        return "owned mount rolled back"
    record_pending_acquisition(manifest, {
        "kind": "mount", "key": target, "role": role,
        "target": target, "fstype": fingerprint.get("fstype"),
        "source": fingerprint.get("source"),
        "expect_super": fingerprint.get("expect_super", []),
        "detail": failure[:256],
    })
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
        rc, _, err = run_sudo(["mkfs.ext4", "-q", "-F", image])
        if rc != 0:
            cell["reason"] = f"mkfs.ext4 refused: {tail(err)}"
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
        rc, out, err = run_sudo(
            ["losetup", "--find", "--show", image])
        loop = None
        if rc == 0 and out.strip():
            candidate = out.strip().split()[0]
            if verify_loop_backing(candidate, image, image_st):
                loop = candidate
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
                    cell["reason"] = f"losetup refused: {tail(err)}"
                return
        backing = manifest["evidence"]["ext4_loop_backing"]
        mnt = auth.mkdir("ext4/mnt", exist_ok=True)
        record_pending_acquisition(manifest, {
            "kind": "mount", "key": mnt, "role": "ext4-fs01",
            "target": mnt, "fstype": "ext4", "source": loop,
            "expect_super": [],
        })
        rc, _, err = run_sudo(["mount", "-t", "ext4", loop, mnt])
        if rc == 0:
            drop_pending_acquisition(manifest, "mount", mnt)
            try:
                record_mount(manifest, run_root, "ext4-fs01", mnt)
            except AdmissionError as exc:
                # S16: admission refused (stacked/foreign) — roll
                # back only what is provably ours; the helper
                # refuses anything else and custody stays pending.
                note = rollback_owned_mount(
                    manifest, run_root, "ext4-fs01", mnt, {
                        "fstype": "ext4", "source": loop,
                        "expect_super": [],
                    })
                detach_verified_loop(manifest, run_root, loop, backing)
                cell["reason"] = (
                    f"ext4 mount not admitted ({exc}); {note}")
                return
        else:
            adopted = reconcile_mount_effect(
                manifest, run_root, "ext4-fs01", mnt, {
                    "fstype": "ext4", "source": loop,
                    "expect_super": [],
                })
            if adopted is None:
                if mount_pending(manifest, mnt):
                    detach_verified_loop(
                        manifest, run_root, loop, backing)
                    cell["reason"] = (
                        "ext4 mount outcome uncertain; custody kept "
                        "pending")
                else:
                    detach_verified_loop(
                        manifest, run_root, loop, backing)
                    cell["reason"] = f"ext4 mount refused: {tail(err)}"
                return
        rc, _, err = run_sudo(
            ["chown", f"{os.geteuid()}:{os.getegid()}", mnt])
        if rc != 0:
            cell["reason"] = f"ext4 chown refused: {tail(err)}"
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
            aux_lower.mkdir(parents=True, exist_ok=True)
            (aux_lower / "shared.txt").write_bytes(b"lower-original\n")
            (aux_lower / "lower-only.txt").write_bytes(b"lower-only\n")
        lower = os.path.join(lower_parent, "lower")
        upper = os.path.join(base, "upper")
        work = os.path.join(base, "work")
        merged = os.path.join(base, "merged")
        optline = (f"lowerdir={lower},upperdir={upper},"
                   f"workdir={work}{opts}")
        fingerprint = {
            "fstype": "overlay", "source": "overlay",
            "expect_super": [f"lowerdir={lower}",
                             f"upperdir={upper}",
                             f"workdir={work}"],
        }
        record_pending_acquisition(manifest, {
            "kind": "mount", "key": merged, "role": role,
            "target": merged, **fingerprint,
        })
        rc, _, err = run_sudo([
            "mount", "-t", "overlay", "overlay",
            "-o", optline, merged])
        if rc == 0:
            drop_pending_acquisition(manifest, "mount", merged)
            try:
                record_mount(manifest, run_root, role, merged,
                             expect_super=fingerprint["expect_super"])
            except AdmissionError as exc:
                # S16: roll back only the mount we can prove is
                # ours; anything else stays pending, never unmounted.
                note = rollback_owned_mount(
                    manifest, run_root, role, merged, fingerprint)
                cell.update(status="unsupported",
                            reason=f"overlay mount not admitted ({exc}); "
                                   f"{note}")
                return False
        else:
            adopted = reconcile_mount_effect(
                manifest, run_root, role, merged, fingerprint)
            if adopted is None:
                if mount_pending(manifest, merged):
                    cell.update(status="unsupported", reason=(
                        f"overlay mount outcome uncertain ({role}); "
                        f"custody kept pending"))
                else:
                    cell.update(status="unsupported", reason=(
                        f"overlay mount refused ({role}{opts or ''}): "
                        f"{tail(err)}"))
                    manifest["evidence"][f"{role}_refusal"] = tail(err)
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
    """Hold a pidfd for `pid`, pinning it against reuse. (S22)

    The returned fd must stay open from observation through the
    signal: while it is held the kernel cannot recycle the pid,
    so even a numeric kill (including the sudo path) cannot be
    redirected at a reused process. Raises ProcAbsent when the
    pid is provably gone, ProcUnknown when it cannot be pinned.
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
                  role="sleeper-wrapper", ready_timeout=READY_TIMEOUT,
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
    armed = False
    if manifest is not None:
        try:
            _, start = stat_state_start(child.pid)
        except (ProcAbsent, ProcUnknown):
            start = None
        record_pending_proc(
            manifest, role, child.pid, start,
            "sleeper wrapper armed before readiness")
        armed = True

    def fail(message):
        # R21: kill the whole tree, not just the wrapper — a
        # half-spawned leaf would otherwise run on unrecorded.
        # S21: the kill result is checked, never ignored.
        gone = kill_tree(role, child.pid)
        try:
            child.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if manifest is not None:
            drop_pending_proc(manifest, role, child.pid)
            if not gone:
                record_pending_proc(
                    manifest, role, child.pid, None,
                    f"sleeper tree not proven gone: {message}")
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
    if manifest is not None and armed:
        drop_pending_proc(manifest, role, child.pid)
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
            role="mnt-sleeper-wrapper")
        record_proc(manifest, "mnt-sleeper-wrapper", mnt_wrap)
        record_proc(manifest, "mnt-sleeper", mnt_sleep)
        time_wait_report(auth.abspath("ns/mnt.report"))
        pid_wrap, pid_sleep = spawn_sleeper(
            helper, mapped, auth.abspath("ns/pid.report"),
            ["sudo", "-n", "unshare", "-p", "-f", "--mount-proc"],
            manifest, role="pidns-sleeper-wrapper")
        record_proc(manifest, "pidns-sleeper-wrapper", pid_wrap)
        record_proc(manifest, "pidns-sleeper", pid_sleep)
        time_wait_report(auth.abspath("ns/pid.report"))
        # Pure pidns sleeper: --mount-proc implies a fresh mount
        # namespace, so a second sleeper without it isolates the pidns
        # boundary from mount-domain isolation.
        pure_wrap, pure_sleep = spawn_sleeper(
            helper, mapped, auth.abspath("ns/pure.report"),
            ["sudo", "-n", "unshare", "-p", "-f"],
            manifest, role="pure-pidns-wrapper")
        record_proc(manifest, "pure-pidns-wrapper", pure_wrap)
        record_proc(manifest, "pure-pidns-sleeper", pure_sleep)
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
            manifest, role="nested-pidns-sleeper-wrapper")
    except (OSError, AdmissionError):
        manifest["evidence"]["nested_pidns"] = "unsupported: nested unshare refused"
        return False
    try:
        ident = proc_identity(sleep)
    except AdmissionError as exc:
        # S21: never blindly signal an unobservable pid; persist
        # custody and let cleanup report/retry it.
        retire_fresh_proc("nested-pidns-sleeper", sleep, manifest)
        retire_fresh_proc("nested-pidns-sleeper-wrapper", wrap, manifest)
        manifest["evidence"]["nested_pidns"] = (
            f"unsupported: identity unreadable ({exc})")
        return False
    if len(ident["nspid"]) < 3:
        if not kill_tree("nested-pidns", wrap):
            try:
                _, wrap_start = stat_state_start(wrap)
            except (ProcAbsent, ProcUnknown):
                wrap_start = None
            record_pending_proc(
                manifest, "nested-pidns-sleeper-wrapper", wrap,
                wrap_start, "unsupported tree not proven gone")
        manifest["evidence"]["nested_pidns"] = (
            f"unsupported: NSpid depth {len(ident['nspid'])} < 3")
        return False
    record_proc(manifest, "nested-pidns-sleeper-wrapper", wrap)
    record_proc(manifest, "nested-pidns-sleeper", sleep)
    time_wait_report(auth.abspath("ns/nested.report"))
    manifest["evidence"]["nested_pidns"] = "provisioned"
    return True


def signal_owned(pid, signum, pin_fd, expected_start):
    """Signal an owned PID while its pidfd pin is held. (S21/S22)

    `pin_fd` must be an open pidfd for `pid`: it is fstat'ed, the
    live starttime is re-verified against `expected_start` under
    the pin, and only then is the signal sent. The pin stays open
    across the sudo escalation too, so a reused pid can never
    receive the signal. Returns True when a signal was sent,
    False when the process was already gone. Raises
    AdmissionError on identity change, ProcUnknown when the pid
    cannot be observed.
    """
    import signal as _signal
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
    try:
        os.kill(pid, signum)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    except OSError as exc:
        if exc.errno in (errno.ESRCH, errno.ENOENT):
            return False
        if exc.errno not in (errno.EPERM, errno.EACCES):
            raise ProcUnknown(
                f"signal to pid {pid} failed: {exc}")
    # Root-spawned sleepers cannot be signalled by the observer
    # uid; the pin stays open across this escalation, so the
    # numeric sudo kill cannot be redirected at a reused pid.
    name = _signal.Signals(signum).name
    run_sudo(["kill", f"-{name}", str(pid)])
    return True


def kill_tree(role, root_pid, timeout=10):
    """SIGTERM then SIGKILL a wrapper and every descendant (R21).

    Used when a spawn produced live processes but no stable leaf
    to record: killing the wrapper alone would orphan the leaf.
    Every pid is pinned with a pidfd before observation and the
    pins stay open through every signal, so pid reuse cannot
    redirect the kill (S22). Returns True only when the whole
    tree is proven gone; unobservable members or survivors yield
    False, never a silent True (S21).
    """
    import signal as _signal
    import time as _time
    pins = {}
    snap = {}
    unknown = 0
    stack = [root_pid]
    seen = set()
    try:
        while stack:
            pid = stack.pop()
            if pid in seen:
                continue
            seen.add(pid)
            try:
                pin = pin_proc(pid)
            except ProcAbsent:
                continue
            except ProcUnknown:
                unknown += 1
                continue
            try:
                state, start = stat_state_start(pid)
            except ProcAbsent:
                os.close(pin)
                continue
            except ProcUnknown:
                os.close(pin)
                unknown += 1
                continue
            if state == "Z":
                # Zombie: already dead; reaping is its parent's job.
                os.close(pin)
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
    AdmissionError; unobservable state raises ProcUnknown. A
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
            raise AdmissionError(
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
            raise AdmissionError(
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
    """
    try:
        pin = pin_proc(pid)
    except ProcAbsent:
        return True
    except ProcUnknown as exc:
        if manifest is not None:
            record_pending_proc(manifest, role, pid, None, str(exc))
        return False
    try:
        try:
            state, start = stat_state_start(pid)
        except ProcAbsent:
            return True
        except ProcUnknown as exc:
            if manifest is not None:
                record_pending_proc(manifest, role, pid, None, str(exc))
            return False
        if state == "Z":
            return True
    finally:
        try:
            os.close(pin)
        except OSError:
            pass
    try:
        return kill_owned(role, pid, start, timeout)
    except ProcUnknown as exc:
        if manifest is not None:
            record_pending_proc(manifest, role, pid, start, str(exc))
        return False


CHURN_DRIVER_PY = r"""
import ctypes, os, subprocess, sys
root, fifo, ack = sys.argv[1], sys.argv[2], sys.argv[3]
bind_dev, bind_ino = int(sys.argv[4]), int(sys.argv[5])
point = os.path.join(root, "churn", "point")
payload_a = os.path.join(root, "churn", "payload-a")
payload_b = os.path.join(root, "churn", "payload-b")
os.makedirs(os.path.dirname(point), exist_ok=True)
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


def fresh_manifest(run_root, privileged):
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
        if shutil.which("sudo") is None:
            return fail2("missing sudo tool for --privileged create")
        rc, _, err = run_sudo(["true"], timeout=30)
        if rc != 0:
            return fail2(f"missing sudo -n grant for --privileged "
                         f"create: {tail(err)}")
    manifest = fresh_manifest(run_root, args.privileged)
    try:
        Path(run_root).mkdir(parents=True, exist_ok=False)
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


def _loop_clr_fd(loop):
    """In-process LOOP_CLR_FD; returns None on success, else errno."""
    try:
        fd = os.open(loop, os.O_RDWR | os.O_NONBLOCK)
    except OSError as exc:
        return exc.errno or errno.EIO
    try:
        try:
            fcntl.ioctl(fd, LOOP_CLR_FD)
        except OSError as exc:
            return exc.errno or errno.EIO
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return None


def retire_mount_now(target, expected, run_root):
    """Validate and detach one mount in this process. (S17)

    `expected` carries target/fstype/source/expect_super and,
    when recorded, mnt_id/root. The live table is read for
    validation, read AGAIN immediately before the effect (a
    substitution between the two refuses), the detach runs
    in-process via umount2, and a post-effect read proves the
    target clear. Returns None on success (or when already
    absent), else a failure string; anything uncertain is
    retained, never detached.
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
        table = read_mount_table()
    except AdmissionError as exc:
        return f"mount table unreadable: {exc}"
    if not find_mounts(table, target):
        return None
    try:
        admit_mount(record, table, run_root)
    except AdmissionError as exc:
        return f"mount {target} replacement refused ({exc}); left in place"
    try:
        effect_table = read_mount_table()
    except AdmissionError as exc:
        return f"mount table unreadable before effect: {exc}"
    try:
        admit_mount(record, effect_table, run_root)
    except AdmissionError as exc:
        return (f"mount {target} changed between validation and "
                f"effect ({exc}); refusing")
    err = _umount2(target)
    if err is not None:
        if err in (errno.ENOENT, errno.ENXIO, errno.EINVAL):
            # Lost a race with a cooperative unmount: verify.
            pass
        else:
            return (f"umount {target} refused: "
                    f"{os.strerror(err)}")
    try:
        after = read_mount_table()
    except AdmissionError as exc:
        return f"mount table unreadable after effect: {exc}"
    if find_mounts(after, target):
        return (f"mount {target} still live after detach; "
                f"custody retained")
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


def loop_backing_verified(live, backing):
    """True when a just-read backing value is the recorded one.

    Takes the already-read sysfs value so each validation step
    reads exactly once.
    """
    if live is None:
        return False
    if not isinstance(backing, dict) or not backing.get("path"):
        return False
    live_path = strip_deleted_suffix(live)
    if os.path.normpath(live_path) != os.path.normpath(backing["path"]):
        return False
    try:
        st = os.stat(live_path)
    except OSError:
        return False
    return (st.st_dev, st.st_ino) == (backing.get("dev"),
                                      backing.get("ino"))


def retire_loop_now(loop, backing, run_root):
    """Validate and detach one loop device in this process. (S17)

    Same validation/effect/post-effect discipline as
    retire_mount_now, with the detach via LOOP_CLR_FD. Returns
    None on success (or when already detached), else a failure
    string. A device whose live backing differs from the record
    is a reused name: refused, never detached.
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
    if not loop_backing_verified(live, backing):
        return (f"loop {loop} backing changed "
                f"(live={live[:60]!r}); refusing detach")
    try:
        effect = read_loop_backing(loop)
    except AdmissionError as exc:
        return str(exc)
    if effect is None:
        return None
    if not loop_backing_verified(effect, backing):
        return (f"loop {loop} backing changed between validation "
                f"and effect; refusing detach")
    err = _loop_clr_fd(loop)
    if err is not None and err != errno.ENXIO:
        return f"loop {loop} detach refused: {os.strerror(err)}"
    try:
        after = read_loop_backing(loop)
    except AdmissionError as exc:
        return str(exc)
    if after is None:
        return None
    if loop_backing_verified(after, backing):
        return (f"loop {loop} still attached after detach; "
                f"custody retained")
    # Detached and already reused by another party: our
    # obligation is discharged; the new association is not ours
    # to touch.
    return None


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
    live_path = strip_deleted_suffix(live)
    if os.path.normpath(live_path) != os.path.normpath(backing["path"]):
        return (f"loop {loop} backing changed (live={live[:60]!r}); "
                f"refusing detach")
    try:
        st = os.stat(live_path)
    except OSError as exc:
        return (f"loop {loop} backing unverifiable ({exc}); "
                f"refusing detach")
    if (st.st_dev, st.st_ino) != (backing.get("dev"), backing.get("ino")):
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


def fd_clear_dir(fd, rel="", mounts=frozenset(), root_dev=None):
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
    """
    if root_dev is None:
        root_dev = os.fstat(fd).st_dev
    if rel in mounts:
        raise OSError(
            f"mount boundary at {rel or '.'!r}: refusing traversal")
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
                if st.st_dev != root_dev:
                    raise OSError(
                        f"mount boundary at {name!r} (device "
                        f"{st.st_dev} != tree {root_dev}): refusing")
                child = os.open(
                    ".", os.O_RDONLY | os.O_DIRECTORY,
                    dir_fd=held)
                try:
                    fd_clear_dir(child, child_rel, mounts, root_dev)
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
    foreign-owned sticky parents (/dev/shm tt04 roots) by design,
    so the exclusive-parent gate does not apply here; recorded
    (dev, ino) identity checks are its mechanism. The S13
    per-entry proof in fd_clear_dir applies regardless of parent
    shape.

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
                matches = scan_loop_by_backing(
                    backing.get("dev"), backing.get("ino"))
            except AdmissionError as exc:
                failures.append(f"pending loop: {exc}")
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
            rows = find_mounts(table, target)
            if not rows:
                continue
            if (len(rows) == 1
                    and mount_fingerprint_matches(rows[0], fingerprint)):
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
    except AdmissionError as exc:
        # A manifest naming a foreign root is a usage refusal, never a
        # recursive delete of unknown state.
        if "mismatch" in str(exc) or "schema" in str(exc):
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
    failure = retire_mount_now(args.target, expected, run_root)
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
    args = parser.parse_args(argv)
    if args.command == "plan":
        return plan_command(args)
    if args.command == "create":
        return create_command(args)
    if args.command == "inspect":
        return inspect_command(args)
    if args.command == "retire-helper":
        return retire_helper_command(args)
    if args.command == "retire-mount":
        return retire_mount_command(args)
    if args.command == "retire-loop":
        return retire_loop_command(args)
    return cleanup_command(args)


if __name__ == "__main__":
    sys.exit(main())




