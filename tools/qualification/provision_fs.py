# SPDX-License-Identifier: Apache-2.0
"""TT04 real filesystem provisioner: plan|create|inspect|cleanup.

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
import datetime
import hashlib
import json
import os
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


def fail2(message):
    print(f"provision_fs: {message}", file=sys.stderr)
    return 2


def tail(text):
    text = (text or "")[-ERR_TAIL:]
    return text.strip().replace("\n", " | ")


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
    return {
        "mnt_id": mnt_id,
        "target": pre[4],
        "fstype": post[0],
        "source": post[1],
        "super": post[2],
    }


def read_mount_table():
    rows = []
    with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as handle:
        for line in handle.read().splitlines():
            line = line.strip()
            if line:
                rows.append(parse_mountinfo_row(line))
    return rows


def find_mount(table, target):
    for row in table:
        if row["target"] == target:
            return row
    return None


def admit_mount(record, table, run_root):
    target = record.get("target", "")
    if not target or len(target) > MAX_PATH or not contained(target, run_root):
        raise AdmissionError(f"foreign mount target: {target[:80]!r}")
    row = find_mount(table, target)
    if row is None:
        raise AdmissionError(f"mount not present: {target}")
    if row["mnt_id"] != record.get("mnt_id"):
        raise AdmissionError(
            f"mnt_id changed for {target}: live={row['mnt_id']} "
            f"manifest={record.get('mnt_id')}"
        )
    if row["fstype"] != record.get("fstype"):
        raise AdmissionError(f"fstype changed for {target}")
    if row["source"] != record.get("source"):
        raise AdmissionError(f"source changed for {target}")
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
        except OSError:
            caps["sudo_n"] = False
    if shutil.which("btrfs") is not None:
        try:
            proc = subprocess.run(
                ["btrfs", "--version"], capture_output=True,
                text=True, timeout=30,
            )
            caps["btrfs_version"] = (proc.stdout or proc.stderr or "").strip()[:80]
        except OSError:
            pass
    clone = read_text_capped("/proc/sys/kernel/unprivileged_userns_clone", 64)
    if clone is not None:
        caps["unprivileged_userns_clone"] = clone.strip()[:16]
    return caps


def proc_identity(pid):
    """Owned-process identity: starttime (last-paren field 22), exe, NSpid.

    stat/status are world-readable; the exe link of a root-spawned
    sleeper is EACCES to the observer and stays a recorded unknown.
    """
    try:
        stat = read_text_capped(f"/proc/{pid}/stat")
        status = read_text_capped(f"/proc/{pid}/status", 65536)
    except OSError as exc:
        raise AdmissionError(f"proc {pid} unreadable: {exc}")
    if not stat or not status:
        raise AdmissionError(f"proc {pid} has empty stat/status")
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = None
    try:
        after = stat.rsplit(")", 1)[1].split()
        starttime = int(after[19])
    except (IndexError, ValueError):
        raise AdmissionError(f"proc {pid} stat unparseable")
    nspid = None
    for line in status.splitlines():
        if line.startswith("NSpid:"):
            nspid = line.split(":", 1)[1].split()
            break
    if nspid is None:
        raise AdmissionError(f"proc {pid} lacks NSpid")
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
    try:
        proc = subprocess.run(
            ["sudo", "-n", *argv], capture_output=True,
            text=True, timeout=timeout,
        )
    except OSError as exc:
        return (127, "", f"sudo exec failed: {exc}")
    return (proc.returncode, proc.stdout or "", proc.stderr or "")


# F09: incremental recovery persistence. create_command sets _PERSIST to
# the manifest path once the exclusive recovery record exists; every
# acquisition record below then persists immediately, so a later
# failure (or crash between steps) keeps custody of what is live.
# Single-threaded CLI: no locking needed.
_PERSIST = None


def save_manifest(manifest, path):
    """Atomically replace the manifest (tmp write, fsync, rename)."""
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _persist_now(manifest):
    if _PERSIST is not None:
        save_manifest(manifest, _PERSIST)


def record_mount(manifest, run_root, role, target, expect_super=()):
    table = read_mount_table()
    row = find_mount(table, target)
    if row is None:
        raise AdmissionError(f"mount missing after create: {target}")
    if len(manifest["mounts"]) >= MAX_MOUNTS:
        raise AdmissionError("mount cap exceeded")
    manifest["mounts"].append({
        "role": role, "source": row["source"], "target": row["target"],
        "fstype": row["fstype"], "options": "",
        "actual_super": row["super"][:512], "mnt_id": row["mnt_id"],
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


def record_file(manifest, role, path):
    if len(manifest["files"]) >= MAX_FILES:
        raise AdmissionError("file cap exceeded")
    data = Path(path).read_bytes()
    if len(data) > MAX_FILE_BYTES:
        raise AdmissionError(f"file too large to record: {path}")
    st = os.stat(path)
    manifest["files"].append({
        "role": role, "path": path, "dev": st.st_dev,
        "ino": st.st_ino, "size": st.st_size,
        "sha256": hashlib.sha256(data).hexdigest(),
    })
    _persist_now(manifest)


def pattern_bytes(seed, size):
    return bytes(((i * 31 + seed) % 251 + 1) for i in range(size))


def create_unprivileged(manifest, run_root):
    root = Path(run_root)
    plain = root / "plain"
    plain.mkdir(parents=True, exist_ok=False)
    (plain / "a.bin").write_bytes(pattern_bytes(1, 8192))
    (plain / "b.bin").write_bytes(pattern_bytes(2, 8192))
    record_file(manifest, "plain-a", str(plain / "a.bin"))
    record_file(manifest, "plain-b", str(plain / "b.bin"))
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
    base = Path(run_root) / "btrfs"
    try:
        base.mkdir(parents=True, exist_ok=False)
        proc = subprocess.run(
            ["btrfs", "subvolume", "create", str(base / "svA")],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            skip(f"btrfs subvolume create refused: {tail(proc.stderr)}")
            return
        for name in ("svB",):
            proc = subprocess.run(
                ["btrfs", "subvolume", "create", str(base / name)],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode != 0:
                skip(f"btrfs subvolume create refused: {tail(proc.stderr)}")
                return
        for sv, seed in (("svA", 11), ("svB", 12)):
            (base / sv / "f").write_bytes(pattern_bytes(seed, 8192))
        proc = subprocess.run(
            ["btrfs", "subvolume", "snapshot",
             str(base / "svA"), str(base / "snapA")],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            skip(f"btrfs snapshot refused: {tail(proc.stderr)}")
            return
        manifest["evidence"]["btrfs_subvolumes"] = ["svA", "svB", "snapA"]
        record_file(manifest, "btrfs-svA-f", str(base / "svA" / "f"))
        record_file(manifest, "btrfs-svB-f", str(base / "svB" / "f"))
        record_file(manifest, "btrfs-snapA-f", str(base / "snapA" / "f"))
        manifest["cells"]["FS02"] = {
            "status": "provisioned", "needs_privilege": False,
            "detail": "svA/svB/snapA with two-page files; "
                      "collision is verified live by the cell oracle",
        }
        manifest["cells"]["FS03"] = {
            "status": "provisioned", "needs_privilege": False,
            "detail": "snapshot-pinned svA-f/snapA-f collision pair",
        }
    except OSError as exc:
        skip(f"btrfs provisioning I/O failed: {exc}")


def provision_ext4(manifest, run_root):
    cell = {"status": "skipped", "needs_privilege": True, "reason": ""}
    manifest["cells"]["FS01"] = cell
    if shutil.which("mkfs.ext4") is None:
        cell["reason"] = "missing mkfs.ext4 tool"
        return
    try:
        base = Path(run_root) / "ext4"
        base.mkdir(parents=True, exist_ok=False)
        image = base / "fs01.img"
        with open(image, "wb") as handle:
            handle.truncate(64 << 20)
        rc, _, err = run_sudo(["mkfs.ext4", "-q", "-F", str(image)])
        if rc != 0:
            cell["reason"] = f"mkfs.ext4 refused: {tail(err)}"
            return
        rc, out, err = run_sudo(
            ["losetup", "--find", "--show", str(image)])
        if rc != 0:
            cell["reason"] = f"losetup refused: {tail(err)}"
            return
        loop = out.strip().split()[0]
        manifest["evidence"]["ext4_loop"] = loop
        # F08: the backing image identity, so cleanup detaches only
        # the loop it attached (never a reused /dev/loopN name).
        manifest["evidence"]["ext4_loop_backing"] = str(image)
        mnt = base / "mnt"
        mnt.mkdir(exist_ok=True)
        rc, _, err = run_sudo(["mount", "-t", "ext4", loop, str(mnt)])
        if rc != 0:
            run_sudo(["losetup", "-d", loop])
            cell["reason"] = f"ext4 mount refused: {tail(err)}"
            return
        try:
            record_mount(manifest, run_root, "ext4-fs01", str(mnt))
        except AdmissionError as exc:
            run_sudo(["umount", str(mnt)])
            run_sudo(["losetup", "-d", loop])
            cell["reason"] = f"ext4 mount not admitted: {exc}"
            return
        rc, _, err = run_sudo(
            ["chown", f"{os.geteuid()}:{os.getegid()}", str(mnt)])
        if rc != 0:
            cell["reason"] = f"ext4 chown refused: {tail(err)}"
            return
        (mnt / "a.bin").write_bytes(pattern_bytes(21, 8192))
        os.link(mnt / "a.bin", mnt / "alias.bin")
        (mnt / "b.bin").write_bytes(pattern_bytes(22, 8192))
        record_file(manifest, "ext4-a", str(mnt / "a.bin"))
        record_file(manifest, "ext4-alias", str(mnt / "alias.bin"))
        record_file(manifest, "ext4-b", str(mnt / "b.bin"))
        cell.update(status="provisioned",
                    detail=f"loop {loop} mounted; hardlink alias recorded")
        cell.pop("reason", None)
    except OSError as exc:
        cell["reason"] = f"ext4 provisioning I/O failed: {exc}"


def mount_overlay(manifest, run_root, role, opts, cell_name, lower_base=None):
    """Mount one overlay stack.

    ``lower_base`` overrides the lowerdir parent (FS05 puts its lower
    on tmpfs so layers span filesystems and xino=on is effective; the
    kernel ignores xino=on for same-fs stacks). Auxiliary layer roots
    are recorded in the manifest and retired by cleanup.
    """
    cell = manifest["cells"][cell_name]
    base = Path(run_root) / role
    lower_parent = Path(lower_base) if lower_base else base
    try:
        for sub in ("upper", "work", "merged"):
            (base / sub).mkdir(parents=True, exist_ok=True)
        (lower_parent / "lower").mkdir(parents=True, exist_ok=True)
        (lower_parent / "lower" / "shared.txt").write_bytes(b"lower-original\n")
        (lower_parent / "lower" / "lower-only.txt").write_bytes(b"lower-only\n")
        optline = (
            f"lowerdir={lower_parent / 'lower'},upperdir={base / 'upper'},"
            f"workdir={base / 'work'}{opts}"
        )
        rc, _, err = run_sudo([
            "mount", "-t", "overlay", "overlay",
            "-o", optline, str(base / "merged")])
        if rc != 0:
            cell.update(status="unsupported", reason=(
                f"overlay mount refused ({role}{opts or ''}): {tail(err)}"))
            manifest["evidence"][f"{role}_refusal"] = tail(err)
            return False
        try:
            record_mount(manifest, run_root, role, str(base / "merged"),
                         expect_super=[f"lowerdir={lower_parent / 'lower'}",
                                       f"upperdir={base / 'upper'}",
                                       f"workdir={base / 'work'}"])
        except AdmissionError as exc:
            run_sudo(["umount", str(base / "merged")])
            cell.update(status="unsupported",
                        reason=f"overlay mount not admitted: {exc}")
            return False
        for entry in manifest["mounts"]:
            if entry["target"] == str(base / "merged"):
                entry["options"] = opts or "(defaults)"
        (base / "upper" / "upper-only.txt").write_bytes(b"upper-only\n")
        record_file(manifest, f"{role}-merged-shared",
                    str(base / "merged" / "shared.txt"))
        manifest["evidence"][f"{role}_layout"] = {
            "lower": str(lower_parent / "lower"),
            "upper": str(base / "upper"),
            "work": str(base / "work"), "merged": str(base / "merged"),
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
        manifest.setdefault("aux_roots", []).append(aux)
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
    try:
        lower_ino = os.stat(os.path.join(aux, "lower", "shared.txt")).st_ino
        merged_ino = os.stat(os.path.join(
            run_root, "ov-xino-on", "merged", "shared.txt")).st_ino
    except OSError as exc:
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


def child_pids(ppid):
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "r") as handle:
                after = handle.read().rsplit(")", 1)[1].split()
            if int(after[1]) == ppid:
                found.append(int(entry))
        except (OSError, ValueError, IndexError):
            continue
    return sorted(found)


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
    while True:
        pid = root_pid
        for _ in range(8):
            kids = [k for k in child_pids(pid) if k != os.getpid()]
            if len(kids) != 1:
                break
            pid = kids[0]
        if pid != root_pid and not child_pids(pid):
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
                f"no stable sleeper leaf under wrapper pid {root_pid}")
        _time.sleep(0.1)


def write_sleeper(base):
    helper = base / "map_sleeper.py"
    helper.write_text(SLEEPER_PY)
    return helper


def spawn_sleeper(helper, target_file, report, wrapper):
    """Start an owned mapping sleeper; returns (wrapper_pid, sleeper_pid).

    ``wrapper`` prefixes the argv (sudo/ns setup); the sleeper is the
    stable childless leaf under the spawned wrapper PID.
    """
    target_file = os.path.realpath(target_file)
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
    try:
        line = child.stdout.readline()
    except OSError:
        line = b""
    child.stdout.close()
    if line.strip() != b"ready":
        child.kill()
        child.wait()
        raise AdmissionError(
            f"sleeper for {target_file} never became ready")
    sleeper = resolve_leaf(child.pid)
    return (child.pid, sleeper)


def provision_sleepers(manifest, run_root):
    cell = {"status": "skipped", "needs_privilege": True, "reason": ""}
    manifest["cells"]["FS08"] = cell
    base = Path(run_root) / "ns"
    try:
        base.mkdir(parents=True, exist_ok=False)
        view = base / "view"
        alt = base / "alt"
        view.mkdir()
        alt.mkdir()
        (view / "data.txt").write_bytes(
            b"observer-view-bytes\n" + pattern_bytes(41, 8172))
        (alt / "data.txt").write_bytes(
            b"foreign-view-bytes\n" + pattern_bytes(42, 8173))
        (base / "mapped.bin").write_bytes(pattern_bytes(31, 8192))
        helper = write_sleeper(base)
        # Foreign mount view: the sleeper overmounts view/ with alt/ in a
        # private mount namespace, then maps view/data.txt (foreign bytes)
        # plus the shared mapped.bin for the aligned control.
        mnt_wrap, mnt_sleep = spawn_sleeper(
            helper, base / "view" / "data.txt",
            str(base / "mnt.report"),
            ["sudo", "-n", "unshare", "-m", "--propagation", "private",
             "sh", "-c",
             f"mount --bind {alt} {view} && exec \"$@\"",
             "tt04-view"])
        record_proc(manifest, "mnt-sleeper-wrapper", mnt_wrap)
        record_proc(manifest, "mnt-sleeper", mnt_sleep)
        time_wait_report(base / "mnt.report")
        pid_wrap, pid_sleep = spawn_sleeper(
            helper, base / "mapped.bin", str(base / "pid.report"),
            ["sudo", "-n", "unshare", "-p", "-f", "--mount-proc"])
        record_proc(manifest, "pidns-sleeper-wrapper", pid_wrap)
        record_proc(manifest, "pidns-sleeper", pid_sleep)
        time_wait_report(base / "pid.report")
        # Pure pidns sleeper: --mount-proc implies a fresh mount
        # namespace, so a second sleeper without it isolates the pidns
        # boundary from mount-domain isolation.
        pure_wrap, pure_sleep = spawn_sleeper(
            helper, base / "mapped.bin", str(base / "pure.report"),
            ["sudo", "-n", "unshare", "-p", "-f"])
        record_proc(manifest, "pure-pidns-wrapper", pure_wrap)
        record_proc(manifest, "pure-pidns-sleeper", pure_sleep)
        time_wait_report(base / "pure.report")
        nested = try_nested_pidns(manifest, base, helper)
        provision_churn(manifest, run_root, base)
        provision_chroot(manifest, base)
        manifest["evidence"]["ns_reports"] = {
            "mnt": str(base / "mnt.report"),
            "pid": str(base / "pid.report"),
            "pure": str(base / "pure.report"),
        }
        cell.update(status="provisioned", detail=(
            "foreign-mount + pidns sleepers alive"
            + (" + nested pidns" if nested else "")))
        cell.pop("reason", None)
    except (OSError, AdmissionError) as exc:
        cell["reason"] = f"sleeper provisioning failed: {exc}"


def time_wait_report(report, timeout=15):
    import time as _time
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        try:
            text = Path(report).read_text()
        except OSError:
            text = ""
        if "range=" in text:
            return text
        _time.sleep(0.05)
    raise AdmissionError(f"sleeper report never completed: {report}")


def try_nested_pidns(manifest, base, helper):
    wrap = sleep = None
    try:
        wrap, sleep = spawn_sleeper(
            helper, base / "mapped.bin", str(base / "nested.report"),
            ["sudo", "-n", "unshare", "-p", "-f", "--mount-proc",
             "unshare", "-p", "-f", "--mount-proc"])
    except (OSError, AdmissionError):
        manifest["evidence"]["nested_pidns"] = "unsupported: nested unshare refused"
        return False
    try:
        ident = proc_identity(sleep)
    except AdmissionError:
        kill_owned("nested-pidns-sleeper", sleep, None)
        manifest["evidence"]["nested_pidns"] = "unsupported: identity unreadable"
        return False
    if len(ident["nspid"]) < 3:
        kill_owned("nested-pidns-sleeper", sleep, ident["starttime"])
        manifest["evidence"]["nested_pidns"] = (
            f"unsupported: NSpid depth {len(ident['nspid'])} < 3")
        return False
    record_proc(manifest, "nested-pidns-sleeper-wrapper", wrap)
    record_proc(manifest, "nested-pidns-sleeper", sleep)
    time_wait_report(base / "nested.report")
    manifest["evidence"]["nested_pidns"] = "provisioned"
    return True


def signal_owned(pid, signum):
    """Signal an owned PID, escalating to sudo when EPERM-denied.

    Root-spawned sleepers cannot be signalled by the observer uid;
    escalation happens only after the caller's starttime check.
    """
    import errno as _errno
    import signal as _signal
    try:
        os.kill(pid, signum)
        return
    except OSError as exc:
        if exc.errno not in (_errno.EPERM, _errno.EACCES):
            return
    name = _signal.Signals(signum).name
    run_sudo(["kill", f"-{name}", str(pid)])


def kill_owned(role, pid, starttime, timeout=10):
    """SIGTERM then SIGKILL an owned PID after a starttime identity check."""
    import signal as _signal
    import time as _time
    try:
        ident = proc_identity(pid)
    except AdmissionError:
        return True
    if starttime is not None and ident["starttime"] != starttime:
        raise AdmissionError(
            f"refusing to kill pid {pid} ({role}): starttime changed")
    signal_owned(pid, _signal.SIGTERM)
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        try:
            proc_identity(pid)
        except AdmissionError:
            return True
        _time.sleep(0.05)
    try:
        cur = proc_identity(pid)
    except AdmissionError:
        return True
    if starttime is not None and cur["starttime"] != starttime:
        raise AdmissionError(
            f"refusing to SIGKILL pid {pid} ({role}): starttime changed")
    signal_owned(pid, _signal.SIGKILL)
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        try:
            proc_identity(pid)
        except AdmissionError:
            return True
        _time.sleep(0.05)
    return False


CHURN_DRIVER_PY = r"""
import os, subprocess, sys
root, fifo, ack = sys.argv[1], sys.argv[2], sys.argv[3]
point = os.path.join(root, "churn", "point")
payload_a = os.path.join(root, "churn", "payload-a")
payload_b = os.path.join(root, "churn", "payload-b")
os.makedirs(os.path.dirname(point), exist_ok=True)
ledger = open(os.path.join(root, "churn", "ledger.log"), "a", buffering=1)
def run(argv):
    proc = subprocess.run(argv, capture_output=True, text=True)
    ledger.write(f"run={' '.join(argv)} rc={proc.returncode} "
                 f"err={proc.stderr.strip()[-200:]}\n")
    return proc.returncode
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
            open(ack, "w").write(f"bind-b rc={rc}\n")
        elif cmd == "restore":
            rc = run(["umount", point])
            open(ack, "w").write(f"restore rc={rc}\n")
        elif cmd == "quit":
            open(ack, "w").write("quit rc=0\n")
            break
        else:
            open(ack, "w").write(f"unknown rc=99 cmd={cmd[:32]}\n")
ledger.write("driver-exit\n")
"""


def provision_churn(manifest, run_root, base):
    churn = Path(run_root) / "churn"
    churn.mkdir(parents=True, exist_ok=True)
    (churn / "payload-a").write_bytes(b"churn-payload-a\n")
    (churn / "payload-b").write_bytes(b"churn-payload-b\n")
    point = churn / "point"
    point.write_bytes(b"churn-payload-a\n")
    driver = churn / "driver.py"
    driver.write_text(CHURN_DRIVER_PY)
    fifo = churn / "cmd.fifo"
    ack = churn / "ack.txt"
    try:
        if fifo.exists():
            fifo.unlink()
        os.mkfifo(fifo)
    except OSError as exc:
        raise AdmissionError(f"churn fifo failed: {exc}")
    log = open(churn / "driver.log", "wb")
    try:
        child = subprocess.Popen(
            ["sudo", "-n", sys.executable, str(driver),
             str(run_root), str(fifo), str(ack)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            close_fds=True)
    except OSError as exc:
        log.close()
        raise AdmissionError(f"churn driver spawn failed: {exc}")
    import time as _time
    deadline = _time.time() + 15
    ready = False
    ledger = churn / "ledger.log"
    while _time.time() < deadline:
        try:
            if "driver-ready" in ledger.read_text():
                ready = True
                break
        except OSError:
            pass
        _time.sleep(0.05)
    if not ready:
        child.kill()
        child.wait()
        raise AdmissionError("churn driver never became ready")
    record_proc(manifest, "churn-driver", child.pid)
    manifest["evidence"]["churn"] = {
        "fifo": str(fifo), "ack": str(ack),
        "ledger": str(ledger), "point": str(point),
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
    except OSError:
        return False


def provision_chroot(manifest, base):
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
    root = base / "chroot"
    try:
        (root / "bin").mkdir(parents=True, exist_ok=False)
        shutil.copy(payload, root / "bin" / "busybox")
        child = subprocess.Popen(
            ["sudo", "-n", "chroot",
             f"--userspec={os.geteuid()}:{os.getegid()}",
             str(root), "/bin/busybox", "sleep", "86400"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True)
    except OSError as exc:
        manifest["evidence"]["chroot"] = (
            f"unsupported: chroot spawn failed: {exc}")
        return
    import time as _time
    try:
        sleeper = resolve_leaf(child.pid)
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
            kill_owned("chroot-sleeper", sleeper, None)
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
    global _PERSIST
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
    try:
        root_st = os.stat(run_root)
    except OSError as exc:
        return fail2(f"run-root not statable: {exc}")
    # F08: bind the anchor identity before anything else is acquired.
    manifest["run_root_identity"] = {
        "dev": root_st.st_dev, "ino": root_st.st_ino,
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
        try:
            os.rmdir(run_root)
        except OSError:
            pass
        return fail2(f"already provisioned: {args.manifest} exists; "
                     "run cleanup first")
    except OSError as exc:
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
    try:
        create_unprivileged(manifest, run_root)
        save_manifest(manifest, args.manifest)
        if args.privileged:
            provision_ext4(manifest, run_root)
            save_manifest(manifest, args.manifest)
            provision_overlays(manifest, run_root)
            save_manifest(manifest, args.manifest)
            provision_sleepers(manifest, run_root)
            save_manifest(manifest, args.manifest)
    except AdmissionError as exc:
        # F09: preserve partial custody on failure instead of leaving
        # live resources unrecorded; cleanup can retire them.
        manifest["status"] = "failed"
        manifest["error"] = str(exc)
        try:
            save_manifest(manifest, args.manifest)
        except OSError:
            pass
        return fail2(f"provisioning refused: {exc}")
    except OSError as exc:
        manifest["status"] = "failed"
        manifest["error"] = f"I/O failure: {exc}"
        try:
            save_manifest(manifest, args.manifest)
        except OSError:
            pass
        print(f"create: FAILED {exc}")
        return 1
    finally:
        _PERSIST = None
    manifest["status"] = "complete"
    save_manifest(manifest, args.manifest)
    provisioned = sum(1 for c in manifest["cells"].values()
                      if c.get("status") == "provisioned")
    print(f"created {run_root}: {provisioned} cells provisioned, "
          f"{len(manifest['mounts'])} mounts, {len(manifest['procs'])} procs")
    return 0


def load_manifest(path, run_root):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
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
        data = Path(path).read_bytes()
        st = os.stat(path)
    except OSError as exc:
        raise AdmissionError(
            f"file {record.get('role')} unreadable: {exc}")
    if len(data) > MAX_FILE_BYTES:
        raise AdmissionError(f"file {record.get('role')} exceeds cap")
    if (st.st_dev != record.get("dev") or st.st_ino != record.get("ino")
            or st.st_size != record.get("size")):
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
        table = read_mount_table()
        for entry in manifest["mounts"]:
            admit_mount(entry, table, run_root)
        for entry in manifest["procs"]:
            admit_proc(entry)
        for entry in manifest["files"]:
            admit_file(entry, run_root)
        for aux in manifest.get("aux_roots", []):
            norm = os.path.normpath(aux)
            if not norm.startswith("/dev/shm/tt04-") or ".." in norm:
                raise AdmissionError(f"foreign aux root: {aux[:60]!r}")
            if not os.path.isdir(norm):
                raise AdmissionError(f"aux root missing: {norm[:60]!r}")
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
    """
    try:
        st = os.stat(run_root)
    except OSError:
        return False
    rec = manifest.get("run_root_identity") or {}
    if (st.st_dev, st.st_ino) != (rec.get("dev"), rec.get("ino")):
        raise AdmissionError(
            f"run-root identity changed at {run_root}: "
            f"live=({st.st_dev},{st.st_ino}) "
            f"manifest=({rec.get('dev')},{rec.get('ino')}); "
            f"replacement refused")
    return True


def cleanup_one_mount(entry, table, run_root):
    """Unmount one recorded mount. Returns None on success (or when
    already gone), else a failure string. A live mount whose identity
    differs from the record is a replacement: it is refused and left
    in place, never unmounted. (F08)"""
    target = entry.get("target", "")
    if not target or not contained(target, run_root):
        return f"foreign mount target refused: {target[:60]!r}"
    if find_mount(table, target) is None:
        return None
    try:
        admit_mount(entry, table, run_root)
    except AdmissionError as exc:
        return f"mount {target} replacement refused ({exc}); left in place"
    rc, _, err = run_sudo(["umount", target])
    if rc != 0:
        return f"umount {target} refused: {tail(err)}"
    return None


def read_loop_backing(loop):
    """Live backing file of a /dev/loopN device, or None when the
    device is gone (already detached)."""
    name = os.path.basename(str(loop))
    try:
        with open(f"/sys/block/{name}/loop/backing_file",
                  "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return None


def cleanup_loop_device(loop, backing):
    """Detach one recorded loop device. Returns None on success (or
    when already detached), else a failure string. A device whose
    live backing differs from the recorded image is a reused name:
    it is refused, never detached. (F08)"""
    if not loop or not str(loop).startswith("/dev/loop"):
        return None
    live = read_loop_backing(loop)
    if live is None:
        return None
    if not backing:
        return (f"loop {loop} has no recorded backing; refusing detach "
                f"(live={live[:60]!r})")
    if live != backing:
        return (f"loop {loop} backing changed (live={live[:60]!r}); "
                f"refusing detach")
    rc, _, err = run_sudo(["losetup", "-d", loop])
    if rc != 0 and "No such device" not in tail(err):
        return f"losetup -d {loop} refused: {tail(err)}"
    return None


def cleanup_command(args):
    run_root = check_run_root(args.run_root)
    if run_root is None:
        return fail2(f"foreign run-root: {args.run_root[:80]!r}")
    if not os.path.exists(args.manifest):
        # F09: a missing manifest with live residue is a refusal,
        # never a false success.
        if os.path.exists(run_root):
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
            and contained(ack, run_root) and os.path.exists(fifo)):
        import time as _time

        def driver_cmd(cmd):
            try:
                fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:
                return False
            try:
                os.write(fd, (cmd + "\n").encode())
            finally:
                os.close(fd)
            deadline = _time.time() + 10
            while _time.time() < deadline:
                try:
                    if Path(ack).read_text().startswith(f"{cmd} rc="):
                        return True
                except OSError:
                    pass
                _time.sleep(0.05)
            return False

        try:
            Path(ack).write_text("")
            driver_cmd("restore")
            Path(ack).write_text("")
            driver_cmd("quit")
        except OSError:
            pass
    # Sleepers and drivers (identity-checked), wrappers last.
    for entry in manifest["procs"]:
        try:
            if not kill_owned(entry.get("role", "?"),
                              entry.get("pid", -1),
                              entry.get("starttime")):
                failures.append(f"proc {entry.get('role')} survives")
        except AdmissionError as exc:
            failures.append(str(exc))
    try:
        table = read_mount_table()
    except AdmissionError as exc:
        failures.append(f"mount table unreadable: {exc}")
        table = []
    for entry in reversed(manifest["mounts"]):
        failure = cleanup_one_mount(entry, table, run_root)
        if failure is not None:
            failures.append(failure)
    failure = cleanup_loop_device(manifest["evidence"].get("ext4_loop"),
                                  manifest["evidence"].get("ext4_loop_backing"))
    if failure is not None:
        failures.append(failure)
    for sv in manifest["evidence"].get("btrfs_subvolumes", []):
        path = os.path.join(run_root, "btrfs", sv)
        # F08-adjacent: a bare ".." has no "/" yet escapes the btrfs
        # dir, so dot segments are refused explicitly.
        if not contained(path, run_root) or "/" in sv or sv in (".", ".."):
            failures.append(f"foreign subvolume refused: {sv[:40]!r}")
            continue
        if not os.path.exists(path):
            continue
        proc = subprocess.run(
            ["btrfs", "subvolume", "delete", path],
            capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            rc, _, err = run_sudo(["btrfs", "subvolume", "delete", path])
            if rc != 0:
                failures.append(f"subvolume delete {sv} refused: {tail(err)}")
    # The churn bind point is driver-managed, not a recorded mount:
    # unmount it explicitly (it is always inside the owned run-root).
    if point and contained(point, run_root):
        try:
            live = read_mount_table()
        except AdmissionError as exc:
            # F08: an unreadable table must not silently skip this
            # umount (the point would stay mounted under the rmtree).
            failures.append(f"churn point table unreadable: {exc}")
            live = []
        if find_mount(live, point) is not None:
            rc, _, err = run_sudo(["umount", point])
            if rc != 0:
                failures.append(
                    f"churn point umount refused: {tail(err)}")
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
        if find_mount(table, entry.get("target", "")) is not None:
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
        norm = os.path.normpath(aux)
        if (not norm.startswith("/dev/shm/tt04-") or "/" in
                norm[len("/dev/shm/tt04-"):] or ".." in norm):
            failures.append(f"foreign aux root refused: {aux[:60]!r}")
            continue
        if os.path.exists(norm):
            try:
                shutil.rmtree(norm, ignore_errors=False)
            except OSError as exc:
                failures.append(f"aux root {norm} not removed: {exc}")
    if failures:
        print("cleanup: FAILED")
        for item in failures:
            print(f"  - {item}")
        return 1
    # F08: re-verify immediately before destruction: the root may
    # have been replaced after the entry gate.
    try:
        if not admit_run_root_identity(manifest, run_root):
            print(f"cleanup: already retired {run_root}")
            return 0
    except AdmissionError as exc:
        print(f"cleanup: REFUSED {exc}")
        return 1
    # Pin the verified directory: the unprivileged retire below
    # resolves through this fd, immune to path swaps entirely.
    try:
        root_fd = os.open(
            run_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        if not os.path.exists(run_root):
            print(f"cleanup: already retired {run_root}")
            return 0
        print(f"cleanup: FAILED\n  - run-root not openable: {exc}")
        return 1
    try:
        retire_rc = _retire_pinned_root(
            manifest, run_root, f"/proc/self/fd/{root_fd}")
    finally:
        os.close(root_fd)
    return retire_rc


def _live_root_ok(manifest, run_root):
    """Re-verify the live root is the recorded directory (not a
    symlink, not a replacement). True/False; False only when already
    gone. Raises on replacement. Used immediately before each
    path-based privileged fallback, which cannot cross the sudo
    boundary on a pinned fd. (F08)"""
    try:
        lst = os.lstat(run_root)
    except OSError:
        return False
    if stat.S_ISLNK(lst.st_mode):
        raise AdmissionError(
            f"run-root replaced by symlink at {run_root}; refused")
    try:
        st = os.stat(run_root)
    except OSError:
        return False
    rec = manifest.get("run_root_identity") or {}
    if (st.st_dev, st.st_ino) != (rec.get("dev"), rec.get("ino")):
        raise AdmissionError(
            f"run-root identity changed at {run_root}: "
            f"live=({st.st_dev},{st.st_ino}) "
            f"manifest=({rec.get('dev')},{rec.get('ino')}); "
            f"replacement refused")
    return True


def _retire_pinned_root(manifest, run_root, fd_path):
    # Overlay workdirs contain root-owned restricted entries; reclaim
    # ownership of the owned run-root, then retry, then remove via sudo
    # as a last resort. All mounts are already verified gone and the
    # root is containment-checked.
    first_error = ""
    try:
        shutil.rmtree(fd_path, ignore_errors=False)
    except OSError as exc:
        first_error = str(exc)
        try:
            if not _live_root_ok(manifest, run_root):
                print(f"cleanup: retired {run_root}")
                return 0
        except AdmissionError as refuse:
            print(f"cleanup: REFUSED {refuse}")
            return 1
        run_sudo(["chmod", "-R", "u+rwX", run_root])
        try:
            if not _live_root_ok(manifest, run_root):
                print(f"cleanup: retired {run_root}")
                return 0
        except AdmissionError as refuse:
            print(f"cleanup: REFUSED {refuse}")
            return 1
        rc, _, err = run_sudo(
            ["chown", "-R", f"{os.geteuid()}:{os.getegid()}", run_root])
        if rc == 0:
            try:
                shutil.rmtree(fd_path, ignore_errors=False)
            except OSError as exc2:
                first_error = f"{first_error}; retry: {exc2}"
        else:
            first_error = f"{first_error}; chown refused: {tail(err)}"
        try:
            if not _live_root_ok(manifest, run_root):
                print(f"cleanup: retired {run_root}")
                return 0
        except AdmissionError as refuse:
            print(f"cleanup: REFUSED {refuse}")
            return 1
        if os.path.exists(run_root):
            rc2, _, err2 = run_sudo(["rm", "-rf", run_root])
            if rc2 != 0 or os.path.exists(run_root):
                print(f"cleanup: FAILED\n  - run-root not removed: "
                      f"{first_error}; sudo rm rc={rc2} {tail(err2)}")
                return 1
            print(f"cleanup: retired {run_root} via sudo rm "
                  f"(first error: {first_error})")
            return 0
    if os.path.exists(run_root):
        print(f"cleanup: FAILED\n  - run-root survives: {first_error}")
        return 1
    print(f"cleanup: retired {run_root}")
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
    args = parser.parse_args(argv)
    if args.command == "plan":
        return plan_command(args)
    if args.command == "create":
        return create_command(args)
    if args.command == "inspect":
        return inspect_command(args)
    return cleanup_command(args)


if __name__ == "__main__":
    sys.exit(main())




