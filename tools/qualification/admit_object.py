#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT05 exact object admission: bind presented bytes to one TC03 entry.

admit_object(manifest_path, object_path, profile_path) -> Admission.
Consumes TC03 final-object manifests and ISA profiles without rewriting
them; every binding below mirrors the testkit check_object contract:

- strict documents (UTF-8, duplicate-field and unknown-field refusal,
  bounded strings, lowercase hex64 digests, identifier rules)
- exactly one manifest entry whose sha256 equals the presented bytes
  (zero matches refuse uninventoried-object, two refuse ambiguous-object)
- ELF64 + EM_BPF bytes whose ET_REL/ET_EXEC type matches the entry kind
- entry isa_profile/isa_version equal the profile name/version
- license gate: a declared token absent from or differing from the
  object refuses, as does a required-but-missing or unlisted license

Admission records the final object digest. It carries no build fields
and run_guest has no build path, so a guest cannot rebuild the object
implicitly. Contract (cpu/features) drift and decoded-family checks stay
with the TC01/TC03 Rust check_object; this tool takes no contract input.

Donor slices (all user-owned; Grant: OWNER-2026-10-23):
- K4 ADAPT: kryprobe-ws w001 @ d153f3aaf9a3931337b47c9e1b046c692da55083,
  `kryprobe/scripts/sudo_lane.py` lines 506-547 (payload/file bijection,
  symlink and traversal refusal, staged-artifact drift refusal).

Exit codes: 0 admitted, 1 refused (exact reason on stderr, no output
file), 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernel_common as kc  # noqa: E402

MANIFEST_FIELDS = ("schema_version", "kind", "objects")
ENTRY_FIELDS = ("id", "kind", "path", "sha256", "producer_name",
                "producer_version", "artifact", "profile", "isa_profile",
                "isa_version", "license_declared")
PROFILE_FIELDS = ("schema_version", "kind", "name", "version", "cpu",
                  "features_enabled", "allowed_families", "required_families",
                  "admitted_licenses", "requires_license")
KNOWN_CPUS = ("generic", "v3", "v4")
KNOWN_FAMILIES = ("base", "alu32", "jump32", "ext-jumps", "signed-load-move",
                  "byte-swap", "signed-div", "long-jump", "imm-store",
                  "acqrel", "indirect-jumps")
V4_ONLY_FEATURES = ("acqrel", "indirect-jumps")
EM_BPF = 247
ET_REL, ET_EXEC = 1, 2
MAX_SECTIONS = 4096
MAX_LICENSE_BYTES = 4096


def _version(doc, what):
    if doc.get("schema_version") != 1:
        kc.refuse("invalid-version", f"{what} schema_version must be exactly 1")


def parse_manifest(path):
    doc, sha = kc.load_json(path)
    if not isinstance(doc, dict):
        kc.refuse("invalid-json", "manifest must be an object")
    kc.check_no_unknown(doc, MANIFEST_FIELDS, "manifest")
    _version(doc, "manifest")
    if doc.get("kind") != "tc03_final_object_manifest":
        kc.refuse("invalid-kind", "manifest kind must be tc03_final_object_manifest")
    objects = doc.get("objects")
    if not isinstance(objects, list) or not objects:
        kc.refuse("invalid-input", "manifest objects must be a nonempty list")
    if len(objects) > 4096:
        kc.refuse("too-large", "manifest objects exceed 4096 entries")
    entries = []
    seen = set()
    for index, entry in enumerate(objects):
        what = f"manifest objects[{index}]"
        if not isinstance(entry, dict):
            kc.refuse("invalid-json", f"{what} must be an object")
        kc.check_no_unknown(entry, ENTRY_FIELDS, what)
        ident = kc.req_str(entry, "id", what, 96)
        kc.check_label(ident, "id", what, 96)
        if ident in seen:
            kc.refuse("invalid-input", f"duplicate object id {ident!r}")
        seen.add(ident)
        kind = kc.req_str(entry, "kind", what, 16)
        if kind not in ("rel", "exec"):
            kc.refuse("invalid-input", f"{what} kind must be rel or exec")
        entry_path = kc.req_str(entry, "path", what, 512)
        sha256 = kc.check_sha(kc.req_str(entry, "sha256", what, 64), "sha256", what)
        producer_name = kc.req_str(entry, "producer_name", what, 128)
        producer_version = kc.req_str(entry, "producer_version", what, 128)
        artifact = kc.req_str(entry, "artifact", what, 96)
        kc.check_label(artifact, "artifact", what, 96)
        profile = kc.req_str(entry, "profile", what, 64)
        kc.check_label(profile, "profile", what, 64)
        isa_profile = kc.req_str(entry, "isa_profile", what, 96)
        kc.check_label(isa_profile, "isa_profile", what, 96)
        isa_version = kc.req_str(entry, "isa_version", what, 64)
        declared = entry.get("license_declared")
        if declared is not None:
            if not isinstance(declared, str) or not declared \
                    or len(declared.encode()) > 128:
                kc.refuse("invalid-input", f"{what} license_declared bounded nonempty")
        entries.append({
            "id": ident, "kind": kind, "path": entry_path, "sha256": sha256,
            "producer_name": producer_name, "producer_version": producer_version,
            "artifact": artifact, "profile": profile,
            "isa_profile": isa_profile, "isa_version": isa_version,
            "license_declared": declared,
        })
    return entries, sha


def parse_profile(path):
    doc, sha = kc.load_json(path)
    if not isinstance(doc, dict):
        kc.refuse("invalid-json", "profile must be an object")
    kc.check_no_unknown(doc, PROFILE_FIELDS, "profile")
    _version(doc, "profile")
    if doc.get("kind") != "tc03_isa_profile":
        kc.refuse("invalid-kind", "profile kind must be tc03_isa_profile")
    name = kc.req_str(doc, "name", "profile", 96)
    kc.check_label(name, "name", "profile", 96)
    version = kc.req_str(doc, "version", "profile", 64)
    if not all(0x21 <= ord(ch) <= 0x7E for ch in version):
        kc.refuse("invalid-input", "profile version must be visible ASCII")
    cpu = doc.get("cpu")
    if cpu is not None and cpu not in KNOWN_CPUS:
        kc.refuse("invalid-input", "profile cpu must be generic, v3, v4 or null")
    features = doc.get("features_enabled")
    if not isinstance(features, list) or len(set(features)) != len(features):
        kc.refuse("invalid-input", "features_enabled must be a duplicate-free list")
    for feature in features:
        if not isinstance(feature, str):
            kc.refuse("invalid-input", "features_enabled entries must be strings")
        kc.check_label(feature, "features_enabled", "profile", 96)
    if cpu in (None, "generic") and features:
        kc.refuse("profile-incompatible", "enabled features without a v3/v4 cpu pin")
    if cpu == "v3" and any(f in V4_ONLY_FEATURES for f in features):
        kc.refuse("profile-incompatible", "v4-only feature on v3")
    for field in ("allowed_families", "required_families"):
        families = doc.get(field)
        if not isinstance(families, list) or len(set(families)) != len(families):
            kc.refuse("invalid-input", f"{field} must be a duplicate-free list")
        for family in families:
            if family not in KNOWN_FAMILIES:
                kc.refuse("invalid-input", f"{field} has unknown family {family!r}")
    if any(f not in doc["allowed_families"] for f in doc["required_families"]):
        kc.refuse("profile-incompatible", "required family outside allowed set")
    licenses = doc.get("admitted_licenses")
    if not isinstance(licenses, list) or len(set(licenses)) != len(licenses):
        kc.refuse("invalid-input", "admitted_licenses must be a duplicate-free list")
    for token in licenses:
        if not isinstance(token, str) or not token or len(token.encode()) > 128 \
                or not all(0x20 <= ord(ch) <= 0x7E for ch in token):
            kc.refuse("invalid-input", "admitted_licenses entries are bounded printables")
    requires = doc.get("requires_license")
    if type(requires) is not bool:
        kc.refuse("invalid-json", "requires_license must be a boolean")
    if requires and not licenses:
        kc.refuse("profile-incompatible", "requires_license with empty admitted list")
    return {"name": name, "version": version, "cpu": cpu,
            "admitted_licenses": licenses, "requires_license": requires}, sha


def _c_string(table, offset, bound):
    end = table.find(b"\x00", offset)
    if end < 0 or end - offset > bound:
        kc.refuse("object-not-elf", "ELF string runs past its table bound")
    try:
        return table[offset:end].decode("ascii")
    except UnicodeError:
        kc.refuse("object-not-elf", "ELF string is not ASCII")


def read_elf_identity(path):
    """Minimal bounded ELF64 identity: endianness, machine, type, license.

    Reads only the ELF header plus section headers/string table; refuses
    truncated, over-large-section-count and ambiguous-license objects.
    """
    raw = Path(path).read_bytes()
    if len(raw) > kc.MAX_OBJECT_BYTES:
        kc.refuse("object-too-large", f"{path} exceeds {kc.MAX_OBJECT_BYTES} bytes")
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        kc.refuse("object-not-elf", f"{path} lacks the ELF magic")
    if raw[4] != 2:
        kc.refuse("object-not-elf", f"{path} is not ELF64")
    endian = "<" if raw[5] == 1 else (">" if raw[5] == 2 else None)
    if endian is None:
        kc.refuse("object-not-elf", f"{path} has unknown ELF data encoding")
    etype, machine = struct.unpack_from(endian + "HH", raw, 16)
    (e_shoff,) = struct.unpack_from(endian + "Q", raw, 40)
    _, _, _, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
        endian + "HHHHHH", raw, 52)
    if e_shentsize != 64 or e_shnum > MAX_SECTIONS or e_shstrndx >= e_shnum:
        kc.refuse("object-not-elf", f"{path} has implausible section headers")
    end = e_shoff + e_shentsize * e_shnum
    if end > len(raw):
        kc.refuse("object-not-elf", f"{path} section headers run past EOF")
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        name, stype, _, _, sh_off, sh_size = struct.unpack_from(
            endian + "IIQQQQ", raw, off)[:6]
        if sh_off + sh_size > len(raw) or sh_size > kc.MAX_OBJECT_BYTES:
            kc.refuse("object-not-elf", f"{path} section {index} runs past EOF")
        sections.append((name, stype, sh_off, sh_size))
    str_name, str_type, str_off, str_size = sections[e_shstrndx]
    if str_size > MAX_LICENSE_BYTES * 256:
        kc.refuse("object-not-elf", f"{path} string table implausibly large")
    strtab = raw[str_off:str_off + str_size]
    names = [(_c_string(strtab, name, str_size) if name < str_size else None)
             for name, _, _, _ in sections]
    license_hits = [sections[i] for i, nm in enumerate(names) if nm == "license"]
    if len(license_hits) > 1:
        kc.refuse("object-ambiguous-license", f"{path} has several license sections")
    observed = None
    if license_hits:
        _, _, content_off, content_size = license_hits[0]
        if content_size > MAX_LICENSE_BYTES or content_size == 0:
            kc.refuse("object-not-elf", f"{path} license section size implausible")
        content = raw[content_off:content_off + content_size].split(b"\x00")[0]
        try:
            observed = content.decode("ascii")
        except UnicodeError:
            kc.refuse("object-not-elf", f"{path} license bytes are not ASCII")
        if not observed or len(observed) > 128 \
                or not all(0x20 <= ord(ch) <= 0x7E for ch in observed):
            kc.refuse("object-not-elf", f"{path} license is not a bounded token")
    return {"machine": machine, "etype": etype, "license": observed}


def admit_object(manifest_path, object_path, profile_path):
    """Bind presented object bytes to exactly one manifest entry."""
    obj = Path(object_path)
    if obj.is_symlink():
        kc.refuse("object-symlink", f"{object_path} is a symlink; stage a real file")
    if not obj.is_file():
        kc.refuse("object-missing", f"{object_path} is not a regular file")
    entries, manifest_sha = parse_manifest(manifest_path)
    profile, profile_sha = parse_profile(profile_path)
    actual_sha = kc.digest_file(object_path)
    matches = [entry for entry in entries if entry["sha256"] == actual_sha]
    if not matches:
        kc.refuse("uninventoried-object",
                   f"{object_path} sha256 {actual_sha} matches no manifest entry")
    if len(matches) > 1:
        kc.refuse("ambiguous-object",
                   f"sha256 {actual_sha} matches several manifest entries")
    entry = matches[0]
    ident = read_elf_identity(object_path)
    if ident["machine"] != EM_BPF:
        kc.refuse("object-not-bpf",
                   f"{object_path} e_machine {ident['machine']} is not EM_BPF")
    want = ET_REL if entry["kind"] == "rel" else ET_EXEC
    if ident["etype"] != want:
        kc.refuse("kind-contradicts-object",
                   f"manifest kind {entry['kind']} contradicts ELF type {ident['etype']}")
    if entry["isa_profile"] != profile["name"] \
            or entry["isa_version"] != profile["version"]:
        kc.refuse("profile-mismatch",
                   f"entry names {entry['isa_profile']} {entry['isa_version']}; "
                   f"profile is {profile['name']} {profile['version']}")
    declared, observed = entry["license_declared"], ident["license"]
    if declared is not None and observed is None:
        kc.refuse("license-missing-from-object",
                   f"manifest declares {declared!r} but the object has no license")
    if declared is not None and observed is not None and declared != observed:
        kc.refuse("license-differs-from-object",
                   f"manifest declares {declared!r}; object carries {observed!r}")
    if profile["requires_license"] and observed is None:
        kc.refuse("license-required",
                   "profile requires a license but the object has none")
    if observed is not None and profile["admitted_licenses"] \
            and observed not in profile["admitted_licenses"]:
        kc.refuse("license-unlisted",
                   f"object license {observed!r} is outside the admitted list")
    return {
        "schema": kc.SCHEMA_ADMISSION,
        "status": "admitted",
        "tool": f"admit_object {kc.TOOL_VERSION}",
        "admitted_utc": kc.utcnow(),
        "manifest_sha256": manifest_sha,
        "profile_sha256": profile_sha,
        "object": {
            "id": entry["id"], "kind": entry["kind"], "path": entry["path"],
            "sha256": actual_sha, "producer_name": entry["producer_name"],
            "producer_version": entry["producer_version"],
            "artifact": entry["artifact"], "profile": entry["profile"],
            "isa_profile": entry["isa_profile"], "isa_version": entry["isa_version"],
            "license_declared": declared, "license_observed": observed,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Admit one object against TC03 docs.")
    parser.add_argument("manifest_path")
    parser.add_argument("object_path")
    parser.add_argument("profile_path")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        admission = admit_object(args.manifest_path, args.object_path, args.profile_path)
    except kc.KernelError as error:
        print(f"admit_object: REFUSED {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError) as error:
        print(f"admit_object: usage error: {error}", file=sys.stderr)
        return 2
    kc.write_json_atomic(args.output, admission)
    print(f"admit_object: admitted {admission['object']['id']} "
          f"{admission['object']['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
