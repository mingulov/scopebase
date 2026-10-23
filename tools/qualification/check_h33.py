#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT10 H33 executable license-boundary checks (CI cell gates).

Three subcommands, one per executable H33 cell:

  source-closure        H33.source-closure (T0): workspace manifests declare
                        SPDX options, every option's text is present beside its
                        manifest with its canonical marker, third-party notice
                        records select only offered options, and no non-own
                        source grant or runtime-license carrier crosses the
                        tree without a closure record.
  final-object-license  H33.final-object-license (T2): the bound emitted
                        object decodes (independent ELF parse) to the declared
                        runtime license bytes, and the source grant stays a
                        separate record from the runtime token.
  installed-notices     H33.installed-notices (T5): the shippable delivery
                        bundle carries a byte-matching notice text for every
                        selected option of every entry, and no unattributed
                        byte ships in the bundle.

Exit 0 prints one PASS line. Exit 1 prints FAIL <rule> lines. Exit 64 is a
usage error. Stdlib only; every read is bounded.

PORT/ADAPT (user-owned donor p11scope, .worktrees/v040-integration,
commit 2c2713e66292b0d2688508a25f79e813ae823d81, verified against the
2026-10-18 frozen snapshot):
  - grant/runtime separation rule adapted from the donor pair
    crates/ebpf/native/image_identity.c:1 (SPDX header) + :161 (runtime
    `char LICENSE[] SEC("license") = "GPL";`), with the twin in
    crates/ebpf/native/vma_identity.c:1 + :317;
  - target-input option-declaration pattern from crates/ebpf/Cargo.toml:5
    (`license = "GPL-2.0-only"`);
  - refusal-layering lesson quoted from crates/ebpf/src/main.rs:750-759:

    /// Laid out by hand, with the tail padding named.
    /// This struct is copied whole onto the BPF stack. Under `repr(Rust)` the
    /// compiler ordered it with five trailing padding bytes that nothing wrote,
    /// and LLVM widened the copy to 8-byte loads that span them. Verifiers before
    /// ~6.5 refuse to read a stack byte that is neither MISC nor ZERO, so the copy
    /// was rejected with `invalid read from stack off -72+3 size 8` and
    /// `BPF_PROG_LOAD` returned EACCES -- on 5.15 and 6.2, while 6.5 and newer
    /// accepted the very same object. Naming the padding and initialising it makes
    /// the whole 32 bytes written, which every verifier accepts.

    A bare errno (or a bare license token) never identifies the refusing
    layer. Hence every rule below names its own layer: decode failures are
    decode failures (O2), a missing section is not a mismatched byte (O3),
    and a runtime token is never accepted as a source grant (O4/S4).

Checker logic itself is NEW: no donor license checker exists (H33 is a
ScopeBase-planned family). tools/qualification/h33_oracle.py re-derives the
same verdicts through independent minimal code; agreement is asserted by
tools/qualification/tests/test_h33.py (single-author cross-check, not
independent authorship).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

MAX_BYTES = 8 << 20
MAX_SCAN_FILES = 65536
HEADER_LINES = 5

KNOWN_ATOMS = frozenset(
    {
        "Apache-2.0",
        "MIT",
        "Unlicense",
        "Unicode-3.0",
        "GPL-2.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "Apache-2.0 WITH LLVM-exception",
    }
)
# Canonical marker needles per option that needs a shipped text. These are
# functional detection needles (shortest stable phrases), not reproduced
# content; the vendored texts themselves are byte-exact upstream notices.
MARKERS = {
    "Apache-2.0": (b"Apache License", b"Version 2.0"),
    "MIT": (
        b"Permission is hereby granted, free of charge",
        b'THE SOFTWARE IS PROVIDED "AS IS"',
    ),
    "Unicode-3.0": (b"UNICODE LICENSE V3",),
}
# Crate-root text file per option for the source-closure gate.
OPTION_TEXTS = {
    "Apache-2.0": "LICENSE-APACHE",
    "MIT": "LICENSE-MIT",
    "Unicode-3.0": "LICENSE-UNICODE",
}
# Filename needles mapping a bundle text back to its option.
TEXT_OPTION_BY_NAME = (
    ("LICENSE-APACHE", "Apache-2.0"),
    ("LICENSE-MIT", "MIT"),
    ("LICENSE-UNICODE", "Unicode-3.0"),
)
KNOWN_RUNTIME_TOKENS = frozenset({"GPL"})
SPDX_RE = re.compile(
    rb"SPDX-License-Identifier:\s*([A-Za-z0-9_.+:~-]+(?:\s+WITH\s+[A-Za-z0-9_.-]+)?)"
)
CARRIER_NEEDLES = (b'SEC("license")', b'section "license"')
GRANT_EXTENSIONS = {".rs", ".py", ".c", ".h", ".ll", ".sh"}
CARRIER_EXTENSIONS = {".c", ".h", ".ll"}
SKIP_DIRS = {"target", ".git", ".scopebase", "__pycache__"}
# Attributed upstream notice texts: expected third-party bytes, covered by the
# installed-notices gate instead of the source scan.
SKIP_PREFIXES = ("crates/scopebase-conformance/delivery/notices/",)


class Fail(Exception):
    def __init__(self, rule, location, detail):
        super().__init__(f"FAIL {rule} {location}: {detail}")
        self.rule = rule


def read_bounded(path, rule, location):
    try:
        with open(path, "rb") as stream:
            data = stream.read(MAX_BYTES + 1)
    except OSError as exc:
        raise Fail(rule, location, f"unreadable: {exc.strerror or exc}")
    if len(data) > MAX_BYTES:
        raise Fail(rule, location, f"exceeds {MAX_BYTES} byte bound")
    return data


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def tokenize_expression(text):
    tokens = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        if text[pos] in "()":
            tokens.append(text[pos])
            pos += 1
            continue
        match = re.match(r"[A-Za-z0-9_.+:-]+", text[pos:])
        if not match:
            return None
        word = match.group(0)
        pos += len(word)
        if word in ("AND", "OR", "WITH"):
            tokens.append(word)
            continue
        atom = word
        saved = pos
        while True:
            gap = re.match(r"\s+", text[pos:])
            nxt = pos + (len(gap.group(0)) if gap else 0)
            with_match = re.match(r"WITH\b", text[nxt:])
            if not with_match:
                break
            pos = nxt + 4
            gap2 = re.match(r"\s+", text[pos:])
            pos += len(gap2.group(0)) if gap2 else 0
            exc = re.match(r"[A-Za-z0-9_.-]+", text[pos:])
            if not exc:
                pos = saved
                break
            atom += " WITH " + exc.group(0)
            pos += len(exc.group(0))
            saved = pos
        tokens.append(("atom", atom))
    return tokens


def parse_alternatives(text):
    """Parse an SPDX option expression into a list of frozenset alternatives."""
    tokens = tokenize_expression(text)
    if not tokens:
        return None

    def parse_or(idx):
        first, idx = parse_and(idx)
        if first is None:
            return None, idx
        alts = [first]
        while idx < len(tokens) and tokens[idx] == "OR":
            nxt, idx = parse_and(idx + 1)
            if nxt is None:
                return None, idx
            alts.append(nxt)
        merged = []
        for alt in alts:
            merged.extend(alt)
        return merged, idx

    def parse_and(idx):
        first, idx = parse_unary(idx)
        if first is None:
            return None, idx
        while idx < len(tokens) and tokens[idx] == "AND":
            nxt, idx = parse_unary(idx + 1)
            if nxt is None:
                return None, idx
            first = [a | b for a in first for b in nxt]
        return first, idx

    def parse_unary(idx):
        if idx < len(tokens) and tokens[idx] == "(":
            inner, idx = parse_or(idx + 1)
            if inner is None or idx >= len(tokens) or tokens[idx] != ")":
                return None, idx
            return inner, idx + 1
        if idx < len(tokens) and isinstance(tokens[idx], tuple):
            return [frozenset([tokens[idx][1]])], idx + 1
        return None, idx

    alts, idx = parse_or(0)
    if alts is None or idx != len(tokens):
        return None
    return alts


def selected_atoms(text):
    alts = parse_alternatives(text)
    if alts is None or len(alts) != 1:
        return None
    return alts[0]


def check_offered(expression, selected):
    """True iff the selected option set is one alternative of the expression."""
    alts = parse_alternatives(expression)
    want = selected_atoms(selected)
    if alts is None or want is None:
        return False
    if any(atom not in KNOWN_ATOMS for alt in alts for atom in alt):
        return False
    if any(atom not in KNOWN_ATOMS for atom in want):
        return False
    return want in alts


def header_grant(data):
    for line in data.splitlines()[:HEADER_LINES]:
        match = SPDX_RE.search(line)
        if match:
            return match.group(1).decode("ascii")
    return None


def parse_cargo_license(data, rule, location):
    """Return (license_value or None, problem or None) for a Cargo manifest."""
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return None, "manifest is not UTF-8"
    table = None
    seen_package = False
    value = None
    inherited = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            match = re.fullmatch(r"\[([A-Za-z0-9_.-]+)\]", line)
            table = match.group(1) if match else None
            if table == "package":
                seen_package = True
            continue
        if table != "package":
            continue
        match = re.fullmatch(r'license\s*=\s*"([^"]+)"', line) or re.fullmatch(
            r"license\s*=\s*'([^']+)'", line
        )
        if match:
            if value is not None:
                return None, "duplicate license declaration"
            value = match.group(1)
            continue
        if re.fullmatch(r"license\.workspace\s*=\s*true", line):
            inherited = True
    if not seen_package:
        return None, "no [package] table"
    if value is None:
        if inherited:
            return None, "license.workspace inheritance is not resolved"
        return None, "missing license declaration"
    return value, None


def load_json(data, rule, location):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Fail(rule, location, f"invalid JSON: {exc}")


def notices_entries(data, rule, location):
    text = data.decode("utf-8", errors="strict") if isinstance(data, bytes) else data
    start = text.find("```json")
    if start < 0:
        raise Fail(rule, location, "no ```json notices block")
    start += len("```json")
    end = text.find("```", start)
    if end < 0:
        raise Fail(rule, location, "unterminated ```json notices block")
    try:
        entries = json.loads(text[start:end])
    except ValueError as exc:
        raise Fail(rule, location, f"notices JSON invalid: {exc}")
    if not isinstance(entries, list):
        raise Fail(rule, location, "notices JSON is not a list")
    return entries


def check_notices_entries(entries, rule_shape, rule_offered, location):
    failures = []
    for idx, entry in enumerate(entries):
        where = f"{location} entry {idx}"
        if not isinstance(entry, dict):
            failures.append(Fail(rule_shape, where, "entry is not an object"))
            continue
        missing = [
            field
            for field in (
                "name",
                "version",
                "source",
                "license_expression",
                "selected_option",
                "files",
                "bundled",
            )
            if field not in entry
        ]
        if missing:
            failures.append(
                Fail(rule_shape, where, f"missing {','.join(missing)}")
            )
            continue
        expression = entry["license_expression"]
        selected = entry["selected_option"]
        if not isinstance(expression, str) or not isinstance(selected, str):
            failures.append(Fail(rule_shape, where, "expression must be text"))
            continue
        if parse_alternatives(expression) is None or selected_atoms(selected) is None:
            failures.append(Fail(rule_shape, where, "option expression unparsable"))
            continue
        if not check_offered(expression, selected):
            failures.append(
                Fail(
                    rule_offered,
                    where,
                    f"{selected!r} is not offered by {expression!r}",
                )
            )
        files = entry["files"]
        if not isinstance(files, list):
            failures.append(Fail(rule_shape, where, "files is not a list"))
            continue
        for finfo in files:
            if (
                not isinstance(finfo, dict)
                or not isinstance(finfo.get("path"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", finfo.get("sha256", ""))
            ):
                failures.append(Fail(rule_shape, where, "notice pin malformed"))
    return failures


def iter_scan_files(root):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if rel.startswith(SKIP_PREFIXES):
                continue
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            count += 1
            if count > MAX_SCAN_FILES:
                raise Fail(
                    "S4-scan-cap", ".", f"exceeds {MAX_SCAN_FILES} file bound"
                )
            yield rel, full


def cmd_source_closure(root, closure_arg):
    failures = []
    checks = 0
    manifest_path = (
        closure_arg
        if os.path.isabs(closure_arg)
        else os.path.join(root, closure_arg)
    )
    doc = load_json(
        read_bounded(manifest_path, "S4-closure-pin", closure_arg), "S4-closure-pin",
        closure_arg,
    )
    if (
        not isinstance(doc, dict)
        or doc.get("schema_version") != 1
        or doc.get("kind") != "h33-source-closure-v1"
        or not isinstance(doc.get("own_grant"), str)
        or not isinstance(doc.get("third_party_inputs"), list)
        or not isinstance(doc.get("runtime_carriers"), list)
    ):
        raise Fail("S4-closure-pin", closure_arg, "closure manifest malformed")
    own = doc["own_grant"]
    if own not in KNOWN_ATOMS:
        raise Fail("S4-closure-pin", closure_arg, f"unknown own grant {own!r}")
    checks += 1
    listed_inputs = {}
    for item in doc["third_party_inputs"]:
        checks += 1
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
            or not isinstance(item.get("grant"), str)
            or item.get("grant") not in KNOWN_ATOMS
        ):
            failures.append(Fail("S4-closure-pin", closure_arg, "input record malformed"))
            continue
        target = os.path.join(root, item["path"])
        if not os.path.isfile(target) or os.path.islink(target):
            failures.append(
                Fail("S4-closure-pin", item["path"], "listed input missing")
            )
            continue
        data = read_bounded(target, "S4-closure-pin", item["path"])
        if sha256_of(data) != item["sha256"]:
            failures.append(
                Fail("S4-closure-pin", item["path"], "listed input bytes drifted")
            )
            continue
        if header_grant(data) != item["grant"]:
            failures.append(
                Fail("S4-closure-pin", item["path"], "listed grant drifted")
            )
            continue
        listed_inputs[item["path"]] = item["grant"]
    listed_carriers = set()
    for item in doc["runtime_carriers"]:
        checks += 1
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
        ):
            failures.append(Fail("S4-closure-pin", closure_arg, "carrier record malformed"))
            continue
        target = os.path.join(root, item["path"])
        if not os.path.isfile(target) or os.path.islink(target):
            failures.append(
                Fail("S4-closure-pin", item["path"], "listed carrier missing")
            )
            continue
        data = read_bounded(target, "S4-closure-pin", item["path"])
        if sha256_of(data) != item["sha256"]:
            failures.append(
                Fail("S4-closure-pin", item["path"], "listed carrier bytes drifted")
            )
            continue
        listed_carriers.add(item["path"])
    crates_dir = os.path.join(root, "crates")
    manifests = []
    if os.path.isfile(os.path.join(root, "Cargo.toml")):
        manifests.append("Cargo.toml")
    if os.path.isdir(crates_dir):
        for member in sorted(os.listdir(crates_dir)):
            candidate = os.path.join(crates_dir, member, "Cargo.toml")
            if os.path.isfile(candidate):
                manifests.append(f"crates/{member}/Cargo.toml")
    if not manifests:
        failures.append(Fail("S1-manifest", ".", "no crate manifests found"))
    for rel in manifests:
        checks += 1
        data = read_bounded(os.path.join(root, rel), "S1-manifest", rel)
        value, problem = parse_cargo_license(data, "S1-manifest", rel)
        if problem is not None:
            if rel == "Cargo.toml" and problem == "no [package] table":
                continue
            failures.append(Fail("S1-manifest", rel, problem))
            continue
        alts = parse_alternatives(value)
        atoms = {atom for alt in (alts or []) for atom in alt}
        if alts is None or not atoms <= KNOWN_ATOMS:
            failures.append(Fail("S1-expression", rel, f"unknown option in {value!r}"))
            continue
        checks += 1
        crate_dir = os.path.dirname(os.path.join(root, rel))
        crate_rel = os.path.dirname(rel)
        for atom in sorted(atoms):
            text_name = OPTION_TEXTS.get(atom)
            if text_name is None:
                failures.append(
                    Fail("S2-missing-text", crate_rel or ".",
                         f"no canonical text mapped for {atom}")
                )
                continue
            text_path = os.path.join(crate_dir, text_name)
            text_rel = f"{crate_rel}/{text_name}" if crate_rel else text_name
            if not os.path.isfile(text_path) or os.path.islink(text_path):
                failures.append(
                    Fail("S2-missing-text", text_rel, f"{atom} text absent")
                )
                continue
            text = read_bounded(text_path, "S2-marker", text_rel)
            if not all(marker in text for marker in MARKERS[atom]):
                failures.append(
                    Fail("S2-marker", text_rel, f"{atom} marker absent")
                )
                continue
            checks += 1
        notices_rel = f"{crate_rel}/THIRD-PARTY-NOTICES.md" if crate_rel else None
        if notices_rel and os.path.isfile(os.path.join(root, notices_rel)):
            checks += 1
            data = read_bounded(
                os.path.join(root, notices_rel), "S3-shape", notices_rel
            )
            try:
                entries = notices_entries(data, "S3-shape", notices_rel)
            except Fail as fail:
                failures.append(fail)
                continue
            failures.extend(
                check_notices_entries(entries, "S3-shape", "S3-not-offered", notices_rel)
            )
            checks += 1
    for rel, full in iter_scan_files(root):
        suffix = os.path.splitext(rel)[1]
        if suffix not in GRANT_EXTENSIONS and suffix not in CARRIER_EXTENSIONS:
            continue
        data = read_bounded(full, "S4-unknown-grant", rel)
        checks += 1
        if suffix in GRANT_EXTENSIONS:
            grant = header_grant(data)
            if grant is not None:
                if grant not in KNOWN_ATOMS:
                    failures.append(
                        Fail("S4-unknown-grant", rel, f"unknown grant {grant!r}")
                    )
                elif grant != own and rel not in listed_inputs:
                    failures.append(
                        Fail(
                            "S4-smuggled-grant", rel,
                            f"{grant} crosses without a closure record",
                        )
                    )
        if suffix in CARRIER_EXTENSIONS and any(
            needle in data for needle in CARRIER_NEEDLES
        ):
            if rel not in listed_carriers:
                failures.append(
                    Fail(
                        "S4-unlisted-runtime", rel,
                        "runtime license pattern without a carrier record",
                    )
                )
    return failures, checks


def decode_license_section(data):
    """Return (ok, payload): payload is the license bytes or a failure detail."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return False, "bad ELF magic"
    elf_class = data[4]
    elf_data = data[5]
    if elf_class not in (1, 2) or elf_data not in (1, 2):
        return False, f"unsupported class={elf_class} data={elf_data}"
    order = "<" if elf_data == 1 else ">"
    try:
        if elf_class == 2:
            fields = struct.unpack_from(order + "QQQIHHHHHH", data, 0x18)
            shoff, shentsize, shnum, shstrndx = fields[2], fields[7], fields[8], fields[9]
            sh_fmt, sh_size = order + "IIQQQQIIQQ", 64
        else:
            fields = struct.unpack_from(order + "IIIIHHHHHH", data, 0x18)
            shoff, shentsize, shnum, shstrndx = fields[2], fields[7], fields[8], fields[9]
            sh_fmt, sh_size = order + "IIIIIIIIII", 40
    except struct.error:
        return False, "truncated ELF header"
    if shentsize < sh_size or shnum == 0:
        return False, "no section headers"
    if shoff + shentsize * shnum > len(data):
        return False, "truncated section headers"
    if shstrndx >= shnum:
        return False, "bad shstrndx"
    headers = []
    for idx in range(shnum):
        try:
            fields = struct.unpack_from(sh_fmt, data, shoff + idx * shentsize)
        except struct.error:
            return False, "truncated section header"
        headers.append(fields)
    strtab = headers[shstrndx]
    str_off, str_size = (strtab[4], strtab[5]) if elf_class == 2 else (strtab[4], strtab[5])
    if str_off + str_size > len(data):
        return False, "truncated section names"
    names = data[str_off : str_off + str_size]
    found = []
    for fields in headers:
        name_off = fields[0]
        sec_off, sec_size = fields[4], fields[5]
        if name_off >= len(names):
            return False, "bad section name offset"
        end = names.find(b"\x00", name_off)
        if end < 0:
            return False, "unterminated section name"
        if names[name_off:end] == b"license":
            if sec_off + sec_size > len(data):
                return False, "truncated license section"
            found.append(data[sec_off : sec_off + sec_size])
    if len(found) > 1:
        return False, "duplicate license sections"
    if not found:
        return False, "missing"
    return True, bytes(found[0])


def cmd_final_object(root, manifest_arg):
    failures = []
    checks = 0
    manifest_path = (
        manifest_arg if os.path.isabs(manifest_arg) else os.path.join(root, manifest_arg)
    )
    doc = load_json(
        read_bounded(manifest_path, "O1-pin", manifest_arg), "O1-pin", manifest_arg
    )
    if (
        not isinstance(doc, dict)
        or doc.get("schema_version") != 1
        or doc.get("kind") != "h33-object-license-v1"
        or not isinstance(doc.get("objects"), list)
        or not doc["objects"]
    ):
        raise Fail("O1-pin", manifest_arg, "object manifest malformed")
    checks += 1
    for item in doc["objects"]:
        where = item.get("path", manifest_arg) if isinstance(item, dict) else manifest_arg
        checks += 1
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
            or not isinstance(item.get("source"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item.get("source_sha256", ""))
            or not isinstance(item.get("source_grant"), str)
            or not isinstance(item.get("offered_options"), list)
            or not item["offered_options"]
            or not isinstance(item.get("runtime_declaration"), str)
            or not isinstance(item.get("emitter_id"), str)
            or not isinstance(item.get("emitter_record"), str)
            or not isinstance(item.get("donor_pattern"), dict)
        ):
            failures.append(Fail("O1-pin", where, "object record malformed"))
            continue
        pattern = item["donor_pattern"]
        anchors = pattern.get("anchors")
        if (
            not isinstance(pattern.get("commit"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", pattern["commit"])
            or not isinstance(anchors, list)
            or not anchors
            or any(
                not isinstance(a, dict)
                or not isinstance(a.get("path"), str)
                or not isinstance(a.get("header_line"), int)
                or a["header_line"] < 1
                or not isinstance(a.get("runtime_line"), int)
                or a["runtime_line"] < 1
                or not a.get("header")
                or not a.get("runtime")
                or not re.fullmatch(r"[0-9a-f]{64}", a.get("sha256", ""))
                for a in anchors
            )
        ):
            failures.append(Fail("O1-pin", where, "donor pattern record malformed"))
            continue
        target = os.path.join(root, item["path"])
        if not os.path.isfile(target) or os.path.islink(target):
            failures.append(Fail("O1-pin", where, "bound object missing"))
            continue
        data = read_bounded(target, "O1-pin", where)
        if sha256_of(data) != item["sha256"]:
            failures.append(Fail("O1-pin", where, "bound object bytes drifted"))
            continue
        checks += 1
        source = os.path.join(root, item["source"])
        if not os.path.isfile(source) or os.path.islink(source):
            failures.append(Fail("O1-pin", where, "recorded source missing"))
            continue
        if sha256_of(read_bounded(source, "O1-pin", where)) != item["source_sha256"]:
            failures.append(Fail("O1-pin", where, "recorded source bytes drifted"))
            continue
        checks += 1
        ok, payload = decode_license_section(data)
        if not ok:
            if payload == "missing":
                failures.append(
                    Fail("O3-missing-section", where, "no license section")
                )
            else:
                failures.append(Fail("O2-elf", where, payload))
            continue
        checks += 1
        want = item["runtime_declaration"].encode("utf-8") + b"\x00"
        if payload != want:
            failures.append(
                Fail(
                    "O3-mismatch", where,
                    f"decoded {payload[:32].hex()} != declared {want[:32].hex()}",
                )
            )
            continue
        checks += 1
        grant = item["source_grant"]
        offered = item["offered_options"]
        if (
            grant not in KNOWN_ATOMS
            or grant == item["runtime_declaration"]
            or grant not in offered
            or any(o not in KNOWN_ATOMS for o in offered)
            or item["runtime_declaration"] not in KNOWN_RUNTIME_TOKENS
        ):
            failures.append(
                Fail(
                    "O4-confusion", where,
                    "source grant and runtime token are not separate offered records",
                )
            )
            continue
        checks += 1
        record_path = os.path.join(root, item["emitter_record"])
        try:
            record = load_json(
                read_bounded(record_path, "O5-emitter-drift", where),
                "O5-emitter-drift", where,
            )
            emitter = record.get("emitter", {}).get("id")
        except Fail as fail:
            failures.append(fail)
            continue
        if emitter != item["emitter_id"]:
            failures.append(
                Fail(
                    "O5-emitter-drift", where,
                    f"manifest claims {item['emitter_id']}, record has {emitter}",
                )
            )
            continue
        checks += 1
    return failures, checks


def load_closure_manifest(bundle):
    manifest_path = os.path.join(bundle, "fixture-manifest.json")
    doc = load_json(
        read_bounded(manifest_path, "N5-pin", "fixture-manifest.json"),
        "N5-pin", "fixture-manifest.json",
    )
    if (
        not isinstance(doc, dict)
        or doc.get("schema_version") != 1
        or doc.get("kind") != "tt07-fixture-manifest-v1"
        or not isinstance(doc.get("files"), list)
        or not isinstance(doc.get("notices"), list)
    ):
        raise Fail("N5-pin", "fixture-manifest.json", "closure manifest malformed")
    return doc


def cmd_installed_notices(bundle):
    failures = []
    checks = 0
    manifest = load_closure_manifest(bundle)
    checks += 1
    pinned = {}
    for entry in manifest["files"]:
        checks += 1
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("path"), str)
            or entry.get("path", "").startswith(("/", "."))
            or ".." in entry.get("path", "").split("/")
            or not isinstance(entry.get("length"), str)
            or not entry["length"].isdigit()
            or not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))
        ):
            failures.append(Fail("N5-pin", "fixture-manifest.json", "pin record malformed"))
            continue
        target = os.path.join(bundle, entry["path"])
        if not os.path.isfile(target) or os.path.islink(target):
            failures.append(Fail("N5-pin", entry["path"], "pinned file missing"))
            continue
        data = read_bounded(target, "N5-pin", entry["path"])
        if len(data) != int(entry["length"]) or sha256_of(data) != entry["sha256"]:
            failures.append(
                Fail("N5-pin", entry["path"], "pinned bytes drifted")
            )
            continue
        pinned[entry["path"]] = data
    for notice in manifest["notices"]:
        if notice not in pinned:
            failures.append(
                Fail("N5-pin", str(notice), "notice is not a pinned file")
            )
    for dirpath, _, filenames in os.walk(bundle, followlinks=False):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, bundle).replace(os.sep, "/")
            if rel == "fixture-manifest.json":
                continue
            if os.path.islink(full) or not os.path.isfile(full):
                failures.append(Fail("N5-unpinned-byte", rel, "non-regular bundle byte"))
                continue
            if rel not in pinned:
                failures.append(
                    Fail(
                        "N5-unpinned-byte", rel,
                        "bundle byte without a closure record",
                    )
                )
    checks += 1
    notices_path = os.path.join(bundle, "THIRD-PARTY-NOTICES.md")
    if not os.path.isfile(notices_path):
        failures.append(Fail("N1-shape", "THIRD-PARTY-NOTICES.md", "notices file absent"))
        return failures, checks
    try:
        entries = notices_entries(
            read_bounded(notices_path, "N1-shape", "THIRD-PARTY-NOTICES.md"),
            "N1-shape", "THIRD-PARTY-NOTICES.md",
        )
    except Fail as fail:
        failures.append(fail)
        return failures, checks
    failures.extend(
        check_notices_entries(
            entries, "N1-shape", "N1-not-offered", "THIRD-PARTY-NOTICES.md"
        )
    )
    checks += 1
    bundle_texts = dict(pinned)
    distinct_options = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(
            entry.get("selected_option"), str
        ):
            continue
        atoms = selected_atoms(entry["selected_option"])
        if atoms is not None:
            distinct_options.update(atoms)
    for option in sorted(distinct_options):
        checks += 1
        markers = MARKERS.get(option)
        needle = next(
            (n for n, o in TEXT_OPTION_BY_NAME if o == option), None
        )
        if markers is None or needle is None:
            failures.append(
                Fail("N2-missing-text", option, "no canonical marker mapped")
            )
            continue
        # Presence is name-scoped: incidental marker prose in another
        # option's text (e.g. the MIT grant phrase inside the Unicode
        # license) must not satisfy a different option's coverage.
        if not any(
            needle in os.path.basename(rel)
            and all(marker in data for marker in markers)
            for rel, data in bundle_texts.items()
        ):
            failures.append(
                Fail(
                    "N2-missing-text", option,
                    f"no {needle} text carries the marker",
                )
            )
    for rel, data in sorted(bundle_texts.items()):
        for needle, option in TEXT_OPTION_BY_NAME:
            if needle in os.path.basename(rel):
                checks += 1
                if not all(marker in data for marker in MARKERS[option]):
                    failures.append(
                        Fail("N2-marker", rel, f"{option} marker absent")
                    )
    notices_hashes = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("files"), list):
            continue
        for finfo in entry["files"]:
            if isinstance(finfo, dict) and re.fullmatch(
                r"[0-9a-f]{64}", finfo.get("sha256", "")
            ):
                notices_hashes.add(finfo["sha256"])
    notices_dir = os.path.join(bundle, "notices")
    if os.path.isdir(notices_dir):
        for name in sorted(os.listdir(notices_dir)):
            full = os.path.join(notices_dir, name)
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            checks += 1
            if sha256_of(read_bounded(full, "N3-unpinned-text", f"notices/{name}")) not in notices_hashes:
                failures.append(
                    Fail(
                        "N3-unpinned-text", f"notices/{name}",
                        "text matches no manifest-pinned notice hash",
                    )
                )
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        atoms = (
            selected_atoms(entry["selected_option"])
            if isinstance(entry.get("selected_option"), str)
            else None
        )
        entry_hashes = {
            finfo["sha256"]
            for finfo in entry.get("files", [])
            if isinstance(finfo, dict)
            and re.fullmatch(r"[0-9a-f]{64}", finfo.get("sha256", ""))
        }
        if atoms is None:
            continue
        for option in sorted(atoms):
            checks += 1
            markers = MARKERS.get(option)
            if markers is None:
                continue
            covered = any(
                all(marker in data for marker in markers)
                and sha256_of(data) in entry_hashes
                for data in bundle_texts.values()
            )
            if not covered:
                failures.append(
                    Fail(
                        "N4-holder-gap",
                        f"{entry.get('name')} {entry.get('version')}",
                        f"no byte-matching {option} text for this entry",
                    )
                )
    return failures, checks


def main(argv):
    parser = argparse.ArgumentParser(prog="check_h33.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    default_root = str(Path(__file__).resolve().parents[2])
    src = sub.add_parser("source-closure")
    src.add_argument("--root", default=default_root)
    src.add_argument(
        "--closure-manifest", default="fixtures/h33/source-closure.json"
    )
    obj = sub.add_parser("final-object-license")
    obj.add_argument("--root", default=default_root)
    obj.add_argument("--manifest", default="fixtures/h33/object-license.json")
    noted = sub.add_parser("installed-notices")
    noted.add_argument(
        "--bundle",
        default=str(
            Path(default_root) / "crates/scopebase-conformance/delivery"
        ),
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 64 if exc.code == 2 else exc.code
    try:
        if args.command == "source-closure":
            failures, checks = cmd_source_closure(args.root, args.closure_manifest)
        elif args.command == "final-object-license":
            failures, checks = cmd_final_object(args.root, args.manifest)
        else:
            failures, checks = cmd_installed_notices(args.bundle)
    except Fail as fail:
        print(str(fail), file=sys.stderr)
        return 1
    if failures:
        for fail in failures[:20]:
            print(str(fail), file=sys.stderr)
        if len(failures) > 20:
            print(f"... and {len(failures) - 20} more", file=sys.stderr)
        return 1
    print(f"h33 {args.command}: PASS ({checks} checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
