#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CP10 structural controls: no output/panic paths in new modules, fixture shape."""
import re
import sys
from pathlib import Path

FORBIDDEN = [
    "println!", "print!", "eprintln!", "eprint!", "dbg!",
    "todo!", "unimplemented!", "panic!", "unwrap(", "expect(",
    "unreachable!",
]
SOURCES = ["src/neutral.rs", "src/replay.rs"]
KINDS = {
    "TooLarge", "TooDeep", "StringTooLong", "TooManyItems",
    "DuplicateMember", "Malformed", "TypeMismatch",
    "NonCanonicalNumber", "UnknownKind", "UnknownMember",
    "MissingMember", "LimitExceeded", "EpochMismatch",
    "TerminalMissing", "TerminalDuplicate", "TerminalNotFinal",
    "InventoryMismatch",
}
CONTRACTS = {
    "InvalidId", "DomainMismatch", "ArithmeticOverflow",
    "ReversedBounds", "ConservationMismatch", "MissingProvenance",
    "ConflictingProvenance", "DuplicateKey", "EpochExhausted",
    "GenerationMismatch", "CapacityExceeded", "MissingFeed",
    "DuplicateFeed", "StaleRevision", "InvalidInterval",
    "InvalidSample", "InvalidProfile", "IncompatibleVersion",
    "InvalidReplay", "SaturatedCount",
}


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    failures = []
    for name in SOURCES:
        path = root / name
        text = path.read_text()
        for token in FORBIDDEN:
            pattern = re.compile(re.escape(token) + (r"\b" if token[-1] == "(" else ""))
            if token[-1] == "(":
                pattern = re.compile(r"\b" + re.escape(token))
            for lineno, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    failures.append(f"{name}:{lineno}: forbidden {token}")
    fixtures = root / "../../fixtures/capture/replay-v1"
    vectors = (fixtures / "vectors.jsonl").read_text().splitlines()
    expected = (fixtures / "expected.jsonl").read_text().splitlines()
    if not vectors:
        failures.append("empty vectors.jsonl")
    if len(vectors) != len(expected):
        failures.append("vectors/expected line mismatch")
    accept = re.compile(r'^\{"expect":"accept"(,"records":\d+)?\}$')
    refuse = re.compile(r'^\{"expect":"refuse","kind":"([A-Za-z]+)(\(([A-Za-z]+)\))?"\}$')
    for lineno, line in enumerate(expected, 1):
        if accept.match(line):
            continue
        match = refuse.match(line)
        if not match:
            failures.append(f"expected.jsonl:{lineno}: bad shape")
            continue
        kind, _, contract = match.group(1), match.group(2), match.group(3)
        if kind == "Contract":
            if contract not in CONTRACTS:
                failures.append(f"expected.jsonl:{lineno}: bad contract {contract}")
        elif kind not in KINDS:
            failures.append(f"expected.jsonl:{lineno}: bad kind {kind}")
    if not (fixtures / "README.md").exists():
        failures.append("missing replay-v1 README.md")
    for failure in failures:
        print(f"cp10-controls: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
