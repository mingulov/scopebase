#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT03 independent /proc stat oracle (first increment).

Parses the comm/state/starttime triple from raw stat bytes using the LAST ')'
delimiter, independently of the Rust implementation. Checks the delivered
literal vectors plus one live stat line supplied by the driver test.
"""
import json
import sys


def parse_stat(data: bytes):
    """Return (comm, state, starttime) or raise ValueError."""
    open_paren = data.find(b"(")
    close_paren = data.rfind(b")")
    if open_paren < 0 or close_paren < 0 or close_paren <= open_paren:
        raise ValueError("missing comm delimiters")
    comm = data[open_paren + 1 : close_paren]
    rest = data[close_paren + 1 :].split()
    if len(rest) < 20:
        raise ValueError("stat has %d post-comm fields, need >= 20" % len(rest))
    state = rest[0]
    try:
        starttime = int(rest[19])
    except ValueError:
        raise ValueError("starttime field is not decimal")
    if len(state) != 1:
        raise ValueError("state field is not one byte")
    return comm, state, starttime


def main(argv):
    vectors_path = None
    live_stat = None
    expect_comm = None
    i = 0
    while i < len(argv):
        if argv[i] == "--vectors":
            vectors_path = argv[i + 1]
            i += 2
        elif argv[i] == "--live-stat":
            live_stat = argv[i + 1].encode("utf-8", "surrogateescape")
            i += 2
        elif argv[i] == "--expect-comm":
            expect_comm = argv[i + 1].encode("utf-8", "surrogateescape")
            i += 2
        else:
            print("unknown argument: %s" % argv[i], file=sys.stderr)
            return 2
    if vectors_path is None or live_stat is None or expect_comm is None:
        print("need --vectors, --live-stat and --expect-comm", file=sys.stderr)
        return 2
    with open(vectors_path, "rb") as fh:
        vectors = json.load(fh)
    checked = 0
    for row in vectors["vectors"]:
        raw = row["stat_hex"]
        data = bytes(int(raw[j : j + 2], 16) for j in range(0, len(raw), 2))
        if row["valid"]:
            comm, state, start = parse_stat(data)
            assert comm == row["comm"].encode("utf-8"), (comm, row["comm"])
            assert state == row["state"].encode("utf-8"), (state, row["state"])
            assert start == row["starttime"], (start, row["starttime"])
            assert (state == b"Z") == row["zombie"]
        else:
            try:
                parse_stat(data)
            except ValueError:
                pass
            else:
                print("invalid vector accepted: %s" % row["name"], file=sys.stderr)
                return 1
        checked += 1
    comm, state, start = parse_stat(live_stat)
    if comm != expect_comm:
        print("live comm mismatch: %r" % comm, file=sys.stderr)
        return 1
    verdict = {
        "verdict": "pass",
        "vectors_checked": checked,
        "live": {
            "comm": comm.decode("utf-8", "surrogateescape"),
            "state": state.decode("ascii"),
            "starttime": str(start),
        },
    }
    sys.stdout.write(json.dumps(verdict, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
