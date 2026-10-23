# SPDX-License-Identifier: Apache-2.0
"""TT05 test scaffolding: deterministic ELF/manifest/profile/environment builders.

No test subject is imported here; each test module loads its subject via
importlib from tools/qualification so TDD RED shows as ModuleNotFoundError.
"""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


EM_BPF = 247
ET_REL = 1
ET_EXEC = 2


def build_elf(kind=ET_REL, machine=EM_BPF, license_text=b"GPL", mutate=None):
    """Minimal deterministic ELF64 relocatable with a license section.

    mutate: None | 'bad-magic' | 'et-exec' | 'x86-machine' | 'no-license'
      | 'truncated' | 'be-data'. Kind/machine/license_text apply first.
    """
    if mutate == "et-exec":
        kind = ET_EXEC
    if mutate == "x86-machine":
        machine = 62
    data_enc = 2 if mutate == "be-data" else 1
    endian = ">" if data_enc == 2 else "<"
    have_license = mutate != "no-license"
    shstr = b"\x00license\x00.text\x00"
    content = (license_text if license_text.endswith(b"\x00") else license_text + b"\x00")
    ehsize = 64
    shoff = 64
    shnum = 3
    shstr_off = shoff + shnum * 64
    lic_off = shstr_off + len(shstr)
    ehdr = struct.pack(
        endian + "16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, data_enc, 1, 0, 0]) + b"\x00" * 7,
        kind, machine, 1, 0, 0, shoff, 0, ehsize, 0, 0, 64, shnum, 2,
    )
    null_sh = struct.pack(endian + "IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    if have_license:
        lic_sh = struct.pack(endian + "IIQQQQIIQQ", 1, 1, 0, 0, lic_off, len(content), 0, 0, 1, 0)
    else:
        lic_sh = struct.pack(endian + "IIQQQQIIQQ", 9, 1, 0, 0, lic_off, 0, 0, 0, 1, 0)
    # Section names are cosmetic for parsing; the license lookup matches
    # the exact string "license" in the string table.
    str_sh = struct.pack(endian + "IIQQQQIIQQ", 9, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    blob = ehdr + null_sh + lic_sh + str_sh + shstr + (content if have_license else b"")
    if mutate == "bad-magic":
        blob = b"\x7fELX" + blob[4:]
    if mutate == "truncated":
        blob = blob[:100]
    return blob


def manifest_bytes(entries):
    return (json.dumps(
        {"schema_version": 1, "kind": "tc03_final_object_manifest", "objects": entries},
        sort_keys=True,
    ) + "\n").encode()


def object_entry(object_path, sha_hex=None, **overrides):
    entry = {
        "id": "tt05-demo-object",
        "kind": "rel",
        "path": str(object_path),
        "sha256": sha_hex or hashlib.sha256(Path(object_path).read_bytes()).hexdigest(),
        "producer_name": "tt05-test-producer",
        "producer_version": "0.0.0-test",
        "artifact": "tt05-demo-artifact",
        "profile": "tt05-test-v1",
        "isa_profile": "bpfel-v4",
        "isa_version": "21.1.8",
        "license_declared": "GPL",
    }
    entry.update(overrides)
    return entry


def profile_bytes(**overrides):
    doc = {
        "schema_version": 1,
        "kind": "tc03_isa_profile",
        "name": "bpfel-v4",
        "version": "21.1.8",
        "cpu": "v4",
        "features_enabled": [],
        "allowed_families": ["base", "jump32"],
        "required_families": ["base"],
        "admitted_licenses": ["GPL"],
        "requires_license": True,
    }
    doc.update(overrides)
    return (json.dumps(doc, sort_keys=True) + "\n").encode()


def env_bytes(cells):
    return (json.dumps(
        {
            "schema_version": 1,
            "kind": "scopebase_kernel_cells_v1",
            "doc": "docs/testing/kernel-cells.md",
            "cells": cells,
        },
        sort_keys=True,
    ) + "\n").encode()


def cell(name, kind="host-unprivileged", requirements=(), excluded_targets=(),
         needs_reproducer=False, workload=None, release_probes=()):
    return {
        "name": name,
        "kind": kind,
        "description": f"test cell {name}",
        "requirements": list(requirements),
        "excluded_targets": list(excluded_targets),
        "needs_reproducer": needs_reproducer,
        "workload": workload,
        "release_probes": list(release_probes),
    }


def workload(argv, timeout_secs=60, result="result.json"):
    return {"argv": list(argv), "timeout_secs": timeout_secs, "result": result}


PASS_RESULT = {"setup_ok": True, "assertion": "pass", "detail": "stub-ok"}
FAIL_RESULT = {"setup_ok": True, "assertion": "fail", "detail": "stub-invariant-violated"}
