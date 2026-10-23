#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT05 unprivileged cell workloads: object identity and capability probes.

Subcommands (argv-declared by the kernel-cell environment, executed by
run_guest only after lease plus capability gating):

- identity --object PATH --expect-sha256 HEX --expect-kind rel|exec
  --result PATH: re-hash staged bytes and re-check ELF/machine/type
  identity. This is the live "loaded bytes match admitted object" leg.
- capabilities --result PATH: record read-only host capability evidence
  (kernel release, euid, bpffs/kvm/sysctl/tool probes) for skip
  diagnosis. A measurement, never a gate: gates live in run_guest
  requirements.

Both write the workload result envelope {setup_ok, assertion, detail}
plus evidence extras. NEW narrow workload: no donor ships an offline
object-identity/capability probe pair; ELF parsing is shared with
admit_object (no second implementation).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import kernel_common as kc  # noqa: E402
from admit_object import EM_BPF, ET_EXEC, ET_REL, read_elf_identity  # noqa: E402


def _write_result(path, setup_ok, assertion, detail, **extra):
    doc = {"setup_ok": setup_ok, "assertion": assertion, "detail": detail}
    doc.update(extra)
    kc.write_json_atomic(path, doc)


def cmd_identity(args):
    try:
        actual = kc.digest_file(args.object)
    except kc.KernelError as error:
        _write_result(args.result, True, "fail", f"hash failed: {error}")
        return 0
    if actual != args.expect_sha256:
        _write_result(args.result, True, "fail",
                      f"staged sha256 {actual} != admitted {args.expect_sha256}",
                      staged_sha256=actual)
        return 0
    try:
        ident = read_elf_identity(args.object)
    except kc.KernelError as error:
        _write_result(args.result, True, "fail", f"ELF identity failed: {error}")
        return 0
    if ident["machine"] != EM_BPF:
        _write_result(args.result, True, "fail",
                      f"e_machine {ident['machine']} is not EM_BPF")
        return 0
    want = ET_REL if args.expect_kind == "rel" else ET_EXEC
    if ident["etype"] != want:
        _write_result(args.result, True, "fail",
                      f"ELF type {ident['etype']} contradicts kind {args.expect_kind}")
        return 0
    _write_result(args.result, True, "pass", "staged bytes match the admission",
                  staged_sha256=actual, machine=ident["machine"],
                  etype=ident["etype"], license_observed=ident["license"])
    return 0


def _probe(name, ok, evidence):
    return {"requirement": name, "ok": bool(ok), "evidence": str(evidence)[:256]}


def cmd_capabilities(args):
    probes = []
    probes.append(_probe("root-euid", os.geteuid() == 0, f"euid={os.geteuid()}"))
    bpffs = os.path.exists("/sys/fs/bpf")
    bpffs_w = os.access("/sys/fs/bpf", os.W_OK | os.X_OK)
    probes.append(_probe("bpffs-writable", bpffs_w, f"exists={bpffs} writable={bpffs_w}"))
    try:
        with open("/proc/sys/kernel/unprivileged_bpf_disabled") as stream:
            toggle = stream.read().strip()
        probes.append(_probe("bpf-unprivileged-allowed", toggle == "0",
                             f"unprivileged_bpf_disabled={toggle}"))
    except OSError as error:
        probes.append(_probe("bpf-unprivileged-allowed", False, f"sysctl unreadable: {error}"))
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    probes.append(_probe("kvm-rw", kvm, f"/dev/kvm rw={kvm}"))
    for tool in ("qemu-system-x86_64", "vng", "docker", "python3"):
        found = shutil.which(tool)
        probes.append(_probe(f"tool:{tool}", found is not None, found or "absent"))
    _write_result(args.result, True, "pass",
                  f"{sum(p['ok'] for p in probes)}/{len(probes)} probes true",
                  kernel_release=platform.uname().release,
                  machine=platform.uname().machine,
                  probes=probes)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="TT05 unprivileged cell workloads.")
    sub = parser.add_subparsers(dest="command", required=True)
    ident = sub.add_parser("identity")
    ident.add_argument("--object", required=True)
    ident.add_argument("--expect-sha256", required=True)
    ident.add_argument("--expect-kind", required=True, choices=("rel", "exec"))
    ident.add_argument("--result", required=True)
    caps = sub.add_parser("capabilities")
    caps.add_argument("--result", required=True)
    args = parser.parse_args(argv)
    if args.command == "identity":
        return cmd_identity(args)
    return cmd_capabilities(args)


if __name__ == "__main__":
    sys.exit(main())
