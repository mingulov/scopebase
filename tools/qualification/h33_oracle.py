#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent H33 oracle: re-derives check_h33.py verdicts, minimal code.

Same CLI (source-closure / final-object-license / installed-notices), same
rule IDs, same exit codes (0 pass, 1 rule failure, 64 usage). Shares no code
with the checker: expression matching is normalize-and-split instead of a
recursive descent, the manifest license is sliced out of the [package]
section instead of line-parsed, the tree walk uses os.scandir recursion, and
the ELF walk unpacks only the fields it needs. Agreement between the two is
asserted by tools/qualification/tests/test_h33.py on the real tree and on
every bad-control mutant. Single-author cross-check, not independent
authorship.
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
KNOWN = {
    "Apache-2.0",
    "MIT",
    "Unlicense",
    "Unicode-3.0",
    # SPDX zlib license id; registry-only dep (foldhash via aya).
    "Zlib",
    "GPL-2.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "Apache-2.0 WITH LLVM-exception",
}
MARKERS = {
    "Apache-2.0": (b"Apache License", b"Version 2.0"),
    "MIT": (
        b"Permission is hereby granted, free of charge",
        b'THE SOFTWARE IS PROVIDED "AS IS"',
    ),
    "Unicode-3.0": (b"UNICODE LICENSE V3",),
}
TEXTS = {
    "Apache-2.0": "LICENSE-APACHE",
    "MIT": "LICENSE-MIT",
    "Unicode-3.0": "LICENSE-UNICODE",
}
NAME_OPTION = (
    ("LICENSE-APACHE", "Apache-2.0"),
    ("LICENSE-MIT", "MIT"),
    ("LICENSE-UNICODE", "Unicode-3.0"),
)


class Fail(Exception):
    def __init__(self, rule, location, detail):
        super().__init__(f"FAIL {rule} {location}: {detail}")
        self.rule = rule


def read(path, rule, location):
    try:
        with open(path, "rb") as stream:
            data = stream.read(MAX_BYTES + 1)
    except OSError as exc:
        raise Fail(rule, location, f"unreadable: {exc.strerror or exc}")
    if len(data) > MAX_BYTES:
        raise Fail(rule, location, "too large")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strip_wrapping(text):
    text = text.strip()
    while (
        len(text) >= 2
        and text.startswith("(")
        and text.endswith(")")
    ):
        depth = 0
        wraps = True
        for pos, char in enumerate(text):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            if depth == 0 and pos < len(text) - 1:
                wraps = False
                break
        if not wraps:
            break
        text = text[1:-1].strip()
    return text


def split_top(text, word):
    parts = []
    depth = 0
    current = ""
    idx = 0
    while idx < len(text):
        char = text[idx]
        if char == "(":
            depth += 1
            current += char
            idx += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
            current += char
            idx += 1
        elif depth == 0 and text.startswith(word, idx):
            before = text[idx - 1] if idx > 0 else " "
            after = text[idx + len(word)] if idx + len(word) < len(text) else " "
            if (before.isspace() or before in "()") and (
                after.isspace() or after in "()"
            ):
                parts.append(current)
                current = ""
                idx += len(word)
            else:
                current += char
                idx += 1
        else:
            current += char
            idx += 1
    if depth != 0:
        return None
    parts.append(current)
    return parts


def alternatives(text):
    text = strip_wrapping(text)
    ors = split_top(text, "OR")
    if ors is None:
        return None
    if len(ors) > 1:
        out = []
        for branch in ors:
            sub = alternatives(branch)
            if sub is None:
                return None
            out.extend(sub)
        return out
    ands = split_top(text, "AND")
    if ands is None:
        return None
    if len(ands) > 1:
        acc = [frozenset()]
        for factor in ands:
            sub = alternatives(factor)
            if sub is None:
                return None
            acc = [a | b for a in acc for b in sub]
        return acc
    atom = strip_wrapping(text)
    if not atom or atom in ("AND", "OR") or "(" in atom or ")" in atom:
        return None
    return [frozenset([atom])]


def offered(expression, selected):
    alts = alternatives(expression)
    want = alternatives(selected)
    if alts is None or want is None or len(want) != 1:
        return False
    if any(a not in KNOWN for alt in alts for a in alt):
        return False
    if any(a not in KNOWN for a in want[0]):
        return False
    return want[0] in alts


def grant_of(data):
    lines = data.split(b"\n")[:5]
    for line in lines:
        found = re.search(
            rb"SPDX-License-Identifier:\s*([A-Za-z0-9_.+:~-]+(?:\s+WITH\s+[A-Za-z0-9_.-]+)?)",
            line,
        )
        if found:
            return found.group(1).decode("ascii")
    return None


def cargo_license_value(data):
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return None, "manifest is not UTF-8"
    start = text.find("[package]")
    if start < 0:
        return None, "no [package] table"
    after = text[start + len("[package]") :]
    nxt = after.find("\n[")
    section = after[:nxt] if nxt >= 0 else after
    values = re.findall(r'(?m)^\s*license\s*=\s*["\']([^"\']+)["\']', section)
    if len(values) > 1:
        return None, "duplicate license declaration"
    if not values:
        if re.search(r"(?m)^\s*license\.workspace\s*=\s*true", section):
            return None, "license.workspace inheritance is not resolved"
        return None, "missing license declaration"
    return values[0], None


def notices_list(data, rule, location):
    text = data.decode("utf-8")
    fence = text.find("```json")
    if fence < 0:
        raise Fail(rule, location, "no ```json notices block")
    fence += 7
    end = text.find("```", fence)
    if end < 0:
        raise Fail(rule, location, "unterminated ```json notices block")
    try:
        entries = json.loads(text[fence:end])
    except ValueError as exc:
        raise Fail(rule, location, f"notices JSON invalid: {exc}")
    if not isinstance(entries, list):
        raise Fail(rule, location, "notices JSON is not a list")
    return entries


def check_entries(entries, shape_rule, offered_rule, location):
    failures = []
    for idx, entry in enumerate(entries):
        where = f"{location} entry {idx}"
        if not isinstance(entry, dict):
            failures.append(Fail(shape_rule, where, "entry is not an object"))
            continue
        need = (
            "name",
            "version",
            "source",
            "license_expression",
            "selected_option",
            "files",
            "bundled",
        )
        absent = [f for f in need if f not in entry]
        if absent:
            failures.append(Fail(shape_rule, where, f"missing {','.join(absent)}"))
            continue
        expr = entry["license_expression"]
        sel = entry["selected_option"]
        if not isinstance(expr, str) or not isinstance(sel, str):
            failures.append(Fail(shape_rule, where, "expression must be text"))
            continue
        if alternatives(expr) is None or alternatives(sel) is None:
            failures.append(Fail(shape_rule, where, "option expression unparsable"))
            continue
        if not offered(expr, sel):
            failures.append(
                Fail(offered_rule, where, f"{sel!r} is not offered by {expr!r}")
            )
        files = entry["files"]
        if not isinstance(files, list):
            failures.append(Fail(shape_rule, where, "files is not a list"))
            continue
        for finfo in files:
            if (
                not isinstance(finfo, dict)
                or not isinstance(finfo.get("path"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", finfo.get("sha256", ""))
            ):
                failures.append(Fail(shape_rule, where, "notice pin malformed"))
    return failures


def walk(root):
    found = []

    def visit(dirpath):
        with os.scandir(dirpath) as entries:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    # Gitignored preparation artifacts are never shipped.
                    if entry.name in (
                        "target",
                        ".git",
                        ".scopebase",
                        "__pycache__",
                        ".superpowers",
                    ):
                        continue
                    visit(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    rel = os.path.relpath(entry.path, root).replace(os.sep, "/")
                    if rel.startswith(
                        "crates/scopebase-conformance/delivery/notices/"
                    ):
                        continue
                    found.append((rel, entry.path))

    visit(root)
    if len(found) > 65536:
        raise Fail("S4-scan-cap", ".", "too many files")
    return sorted(found)


def cmd_source(root, closure_arg):
    failures = []
    checks = 0
    manifest = closure_arg if os.path.isabs(closure_arg) else os.path.join(root, closure_arg)
    try:
        doc = json.loads(read(manifest, "S4-closure-pin", closure_arg).decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Fail("S4-closure-pin", closure_arg, f"invalid JSON: {exc}")
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
    if own not in KNOWN:
        raise Fail("S4-closure-pin", closure_arg, f"unknown own grant {own!r}")
    checks += 1
    listed = {}
    for item in doc["third_party_inputs"]:
        checks += 1
        ok = (
            isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
            and isinstance(item.get("grant"), str)
            and item.get("grant") in KNOWN
        )
        if not ok:
            failures.append(Fail("S4-closure-pin", closure_arg, "input record malformed"))
            continue
        target = os.path.join(root, item["path"])
        if not os.path.isfile(target):
            failures.append(Fail("S4-closure-pin", item["path"], "listed input missing"))
            continue
        data = read(target, "S4-closure-pin", item["path"])
        if digest(data) != item["sha256"]:
            failures.append(
                Fail("S4-closure-pin", item["path"], "listed input bytes drifted")
            )
            continue
        if grant_of(data) != item["grant"]:
            failures.append(Fail("S4-closure-pin", item["path"], "listed grant drifted"))
            continue
        listed[item["path"]] = item["grant"]
    carriers = set()
    for item in doc["runtime_carriers"]:
        checks += 1
        ok = (
            isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
        )
        if not ok:
            failures.append(
                Fail("S4-closure-pin", closure_arg, "carrier record malformed")
            )
            continue
        target = os.path.join(root, item["path"])
        if not os.path.isfile(target):
            failures.append(
                Fail("S4-closure-pin", item["path"], "listed carrier missing")
            )
            continue
        if digest(read(target, "S4-closure-pin", item["path"])) != item["sha256"]:
            failures.append(
                Fail("S4-closure-pin", item["path"], "listed carrier bytes drifted")
            )
            continue
        carriers.add(item["path"])
    manifests = []
    if os.path.isfile(os.path.join(root, "Cargo.toml")):
        manifests.append("Cargo.toml")
    crates = os.path.join(root, "crates")
    if os.path.isdir(crates):
        for member in sorted(os.listdir(crates)):
            rel = f"crates/{member}/Cargo.toml"
            if os.path.isfile(os.path.join(root, rel)):
                manifests.append(rel)
    if not manifests:
        failures.append(Fail("S1-manifest", ".", "no crate manifests found"))
    for rel in manifests:
        checks += 1
        value, problem = cargo_license_value(
            read(os.path.join(root, rel), "S1-manifest", rel)
        )
        if problem is not None:
            if not (rel == "Cargo.toml" and problem == "no [package] table"):
                failures.append(Fail("S1-manifest", rel, problem))
            continue
        alts = alternatives(value)
        atoms = {a for alt in (alts or []) for a in alt}
        if alts is None or not atoms <= KNOWN:
            failures.append(Fail("S1-expression", rel, f"unknown option in {value!r}"))
            continue
        checks += 1
        parent = os.path.dirname(rel)
        for atom in sorted(atoms):
            name = TEXTS.get(atom)
            if name is None:
                failures.append(
                    Fail(
                        "S2-missing-text",
                        parent or ".",
                        f"no canonical text mapped for {atom}",
                    )
                )
                continue
            text_rel = f"{parent}/{name}" if parent else name
            text_path = os.path.join(root, text_rel)
            if not os.path.isfile(text_path):
                failures.append(Fail("S2-missing-text", text_rel, f"{atom} text absent"))
                continue
            content = read(text_path, "S2-marker", text_rel)
            if not all(m in content for m in MARKERS[atom]):
                failures.append(Fail("S2-marker", text_rel, f"{atom} marker absent"))
                continue
            checks += 1
        notices_rel = f"{parent}/THIRD-PARTY-NOTICES.md" if parent else None
        if notices_rel and os.path.isfile(os.path.join(root, notices_rel)):
            checks += 1
            try:
                entries = notices_list(
                    read(os.path.join(root, notices_rel), "S3-shape", notices_rel),
                    "S3-shape",
                    notices_rel,
                )
            except Fail as fail:
                failures.append(fail)
                continue
            failures.extend(
                check_entries(entries, "S3-shape", "S3-not-offered", notices_rel)
            )
            checks += 1
    for rel, full in walk(root):
        if not rel.endswith((".rs", ".py", ".c", ".h", ".ll", ".sh")):
            continue
        data = read(full, "S4-unknown-grant", rel)
        checks += 1
        grant = grant_of(data)
        if grant is not None:
            if grant not in KNOWN:
                failures.append(
                    Fail("S4-unknown-grant", rel, f"unknown grant {grant!r}")
                )
            elif grant != own and rel not in listed:
                failures.append(
                    Fail(
                        "S4-smuggled-grant", rel,
                        f"{grant} crosses without a closure record",
                    )
                )
        if rel.endswith((".c", ".h", ".ll")) and (
            b'SEC("license")' in data or b'section "license"' in data
        ):
            if rel not in carriers:
                failures.append(
                    Fail(
                        "S4-unlisted-runtime", rel,
                        "runtime license pattern without a carrier record",
                    )
                )
    return failures, checks


def license_bytes(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return False, "bad ELF magic"
    order = {1: "<", 2: ">"}.get(data[5])
    if data[4] not in (1, 2) or order is None:
        return False, f"unsupported class={data[4]} data={data[5]}"
    bits64 = data[4] == 2
    try:
        if bits64:
            fields = struct.unpack_from(order + "QQQIHHHHHH", data, 0x18)
            shoff, shentsize, shnum, shstrndx = fields[2], fields[7], fields[8], fields[9]
        else:
            fields = struct.unpack_from(order + "IIIIHHHHHH", data, 0x18)
            shoff, shentsize, shnum, shstrndx = fields[2], fields[7], fields[8], fields[9]
    except struct.error:
        return False, "truncated ELF header"
    need = 64 if bits64 else 40
    if shentsize < need or shnum == 0 or shoff + shentsize * shnum > len(data):
        return False, "truncated section headers"
    if shstrndx >= shnum:
        return False, "bad shstrndx"
    fmt = (order + "IIQQQQIIQQ") if bits64 else (order + "IIIIIIIIII")
    sections = []
    for idx in range(shnum):
        try:
            sections.append(
                struct.unpack_from(fmt, data, shoff + idx * shentsize)
            )
        except struct.error:
            return False, "truncated section header"
    stab = sections[shstrndx]
    if stab[4] + stab[5] > len(data):
        return False, "truncated section names"
    names = data[stab[4] : stab[4] + stab[5]]
    hits = []
    for sec in sections:
        if sec[0] >= len(names):
            return False, "bad section name offset"
        stop = names.find(b"\x00", sec[0])
        if stop < 0:
            return False, "unterminated section name"
        if names[sec[0] : stop] == b"license":
            if sec[4] + sec[5] > len(data):
                return False, "truncated license section"
            hits.append(bytes(data[sec[4] : sec[4] + sec[5]]))
    if len(hits) > 1:
        return False, "duplicate license sections"
    if not hits:
        return False, "missing"
    return True, hits[0]


def cmd_object(root, manifest_arg):
    failures = []
    checks = 0
    manifest = (
        manifest_arg if os.path.isabs(manifest_arg) else os.path.join(root, manifest_arg)
    )
    try:
        doc = json.loads(read(manifest, "O1-pin", manifest_arg).decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Fail("O1-pin", manifest_arg, f"invalid JSON: {exc}")
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
        shape = (
            isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
            and isinstance(item.get("source"), str)
            and re.fullmatch(r"[0-9a-f]{64}", item.get("source_sha256", ""))
            and isinstance(item.get("source_grant"), str)
            and isinstance(item.get("offered_options"), list)
            and bool(item.get("offered_options"))
            and isinstance(item.get("runtime_declaration"), str)
            and isinstance(item.get("emitter_id"), str)
            and isinstance(item.get("emitter_record"), str)
            and isinstance(item.get("donor_pattern"), dict)
        )
        if not shape:
            failures.append(Fail("O1-pin", where, "object record malformed"))
            continue
        pattern = item["donor_pattern"]
        anchors = pattern.get("anchors")
        pattern_ok = (
            isinstance(pattern.get("commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", pattern["commit"])
            and isinstance(anchors, list)
            and bool(anchors)
        ) and all(
            isinstance(a, dict)
            and isinstance(a.get("path"), str)
            and isinstance(a.get("header_line"), int)
            and a["header_line"] >= 1
            and isinstance(a.get("runtime_line"), int)
            and a["runtime_line"] >= 1
            and a.get("header")
            and a.get("runtime")
            and re.fullmatch(r"[0-9a-f]{64}", a.get("sha256", ""))
            for a in anchors
        )
        if not pattern_ok:
            failures.append(Fail("O1-pin", where, "donor pattern record malformed"))
            continue
        target = os.path.join(root, item["path"])
        if not os.path.isfile(target):
            failures.append(Fail("O1-pin", where, "bound object missing"))
            continue
        data = read(target, "O1-pin", where)
        if digest(data) != item["sha256"]:
            failures.append(Fail("O1-pin", where, "bound object bytes drifted"))
            continue
        checks += 1
        source = os.path.join(root, item["source"])
        if not os.path.isfile(source):
            failures.append(Fail("O1-pin", where, "recorded source missing"))
            continue
        if digest(read(source, "O1-pin", where)) != item["source_sha256"]:
            failures.append(Fail("O1-pin", where, "recorded source bytes drifted"))
            continue
        checks += 1
        ok, payload = license_bytes(data)
        if not ok:
            if payload == "missing":
                failures.append(Fail("O3-missing-section", where, "no license section"))
            else:
                failures.append(Fail("O2-elf", where, payload))
            continue
        checks += 1
        want = item["runtime_declaration"].encode() + b"\x00"
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
        offered_options = item["offered_options"]
        if (
            grant not in KNOWN
            or grant == item["runtime_declaration"]
            or grant not in offered_options
            or any(o not in KNOWN for o in offered_options)
            or item["runtime_declaration"] not in ("GPL",)
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
            record = json.loads(
                read(record_path, "O5-emitter-drift", where).decode("utf-8")
            )
            emitter = record.get("emitter", {}).get("id")
        except (Fail, UnicodeError, ValueError) as exc:
            failures.append(
                Fail("O5-emitter-drift", where, f"emitter record unreadable: {exc}")
            )
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


def cmd_notices(bundle):
    failures = []
    checks = 0
    manifest_path = os.path.join(bundle, "fixture-manifest.json")
    try:
        manifest = json.loads(
            read(manifest_path, "N5-pin", "fixture-manifest.json").decode("utf-8")
        )
    except (UnicodeError, ValueError) as exc:
        raise Fail("N5-pin", "fixture-manifest.json", f"invalid JSON: {exc}")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or manifest.get("kind") != "tt07-fixture-manifest-v1"
        or not isinstance(manifest.get("files"), list)
        or not isinstance(manifest.get("notices"), list)
    ):
        raise Fail("N5-pin", "fixture-manifest.json", "closure manifest malformed")
    checks += 1
    pinned = {}
    for entry in manifest["files"]:
        checks += 1
        path = entry.get("path", "") if isinstance(entry, dict) else ""
        valid = (
            isinstance(entry, dict)
            and isinstance(path, str)
            and path
            and not path.startswith(("/", "."))
            and ".." not in path.split("/")
            and isinstance(entry.get("length"), str)
            and entry["length"].isdigit()
            and re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))
        )
        if not valid:
            failures.append(
                Fail("N5-pin", "fixture-manifest.json", "pin record malformed")
            )
            continue
        target = os.path.join(bundle, path)
        if not os.path.isfile(target):
            failures.append(Fail("N5-pin", path, "pinned file missing"))
            continue
        data = read(target, "N5-pin", path)
        if len(data) != int(entry["length"]) or digest(data) != entry["sha256"]:
            failures.append(Fail("N5-pin", path, "pinned bytes drifted"))
            continue
        pinned[path] = data
    for notice in manifest["notices"]:
        if notice not in pinned:
            failures.append(Fail("N5-pin", str(notice), "notice is not a pinned file"))
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
        failures.append(
            Fail("N1-shape", "THIRD-PARTY-NOTICES.md", "notices file absent")
        )
        return failures, checks
    try:
        entries = notices_list(
            read(notices_path, "N1-shape", "THIRD-PARTY-NOTICES.md"),
            "N1-shape",
            "THIRD-PARTY-NOTICES.md",
        )
    except Fail as fail:
        failures.append(fail)
        return failures, checks
    failures.extend(
        check_entries(entries, "N1-shape", "N1-not-offered", "THIRD-PARTY-NOTICES.md")
    )
    checks += 1
    options = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(
            entry.get("selected_option"), str
        ):
            continue
        atoms = alternatives(entry["selected_option"])
        if atoms is not None:
            options.update(atoms[0])
    for option in sorted(options):
        checks += 1
        markers = MARKERS.get(option)
        needle = None
        for candidate, owner in NAME_OPTION:
            if owner == option:
                needle = candidate
        if markers is None or needle is None:
            failures.append(
                Fail("N2-missing-text", option, "no canonical marker mapped")
            )
            continue
        present = False
        for rel, data in pinned.items():
            if needle in os.path.basename(rel) and all(
                m in data for m in markers
            ):
                present = True
        if not present:
            failures.append(
                Fail(
                    "N2-missing-text", option,
                    f"no {needle} text carries the marker",
                )
            )
    for rel, data in sorted(pinned.items()):
        for needle, option in NAME_OPTION:
            if needle in os.path.basename(rel):
                checks += 1
                if not all(m in data for m in MARKERS[option]):
                    failures.append(Fail("N2-marker", rel, f"{option} marker absent"))
    hashes = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("files"), list):
            continue
        for finfo in entry["files"]:
            if isinstance(finfo, dict) and re.fullmatch(
                r"[0-9a-f]{64}", finfo.get("sha256", "")
            ):
                hashes.add(finfo["sha256"])
    notices_dir = os.path.join(bundle, "notices")
    if os.path.isdir(notices_dir):
        for name in sorted(os.listdir(notices_dir)):
            full = os.path.join(notices_dir, name)
            if not os.path.isfile(full):
                continue
            checks += 1
            if digest(read(full, "N3-unpinned-text", f"notices/{name}")) not in hashes:
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
            alternatives(entry["selected_option"])
            if isinstance(entry.get("selected_option"), str)
            else None
        )
        if atoms is None:
            continue
        own = {
            finfo["sha256"]
            for finfo in entry.get("files", [])
            if isinstance(finfo, dict)
            and re.fullmatch(r"[0-9a-f]{64}", finfo.get("sha256", ""))
        }
        for option in sorted(atoms[0]):
            checks += 1
            markers = MARKERS.get(option)
            if markers is None:
                continue
            if not any(
                all(m in data for m in markers) and digest(data) in own
                for data in pinned.values()
            ):
                failures.append(
                    Fail(
                        "N4-holder-gap",
                        f"{entry.get('name')} {entry.get('version')}",
                        f"no byte-matching {option} text for this entry",
                    )
                )
    return failures, checks


def main(argv):
    parser = argparse.ArgumentParser(prog="h33_oracle.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    default_root = str(Path(__file__).resolve().parents[2])
    src = sub.add_parser("source-closure")
    src.add_argument("--root", default=default_root)
    src.add_argument("--closure-manifest", default="fixtures/h33/source-closure.json")
    obj = sub.add_parser("final-object-license")
    obj.add_argument("--root", default=default_root)
    obj.add_argument("--manifest", default="fixtures/h33/object-license.json")
    noted = sub.add_parser("installed-notices")
    noted.add_argument(
        "--bundle",
        default=str(Path(default_root) / "crates/scopebase-conformance/delivery"),
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 64 if exc.code == 2 else exc.code
    try:
        if args.command == "source-closure":
            failures, checks = cmd_source(args.root, args.closure_manifest)
        elif args.command == "final-object-license":
            failures, checks = cmd_object(args.root, args.manifest)
        else:
            failures, checks = cmd_notices(args.bundle)
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
