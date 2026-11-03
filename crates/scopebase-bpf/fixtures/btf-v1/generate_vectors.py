#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""BP09 bounded-BTF corpus vectors. Independent BTF v1 writer; no donor or
parser code imported. Layout follows the kernel UAPI (linux/btf.h): u16 magic
0xEB9F, u8 version 1, u8 flags, u32 hdr_len/type_off/type_len/str_off/str_len,
then 12-byte type headers plus kind-specific aux records, then the string
table. Split-module name offsets use base++module concatenated string space.
Regenerate: python3 generate_vectors.py ; verify: python3 generate_vectors.py --check
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGIC = 0xEB9F
VERSION = 1
KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_FWD = 7
KIND_TYPEDEF = 8
KIND_VOLATILE = 9
KIND_CONST = 10
KIND_RESTRICT = 11
KIND_FUNC = 12
KIND_FUNC_PROTO = 13
KIND_VAR = 14
KIND_DATASEC = 15
KIND_FLOAT = 16
KIND_DECL_TAG = 17


class Image:
    """Minimal deterministic BTF image builder with 1-based type ids."""

    def __init__(self, str_bias=0):
        self.types = bytearray()
        self.strs = bytearray(b"\0")
        self.str_bias = str_bias
        self.memo = {}
        self.log = []

    def string(self, text):
        """Append a deduplicated string; return its biased offset."""
        if text == "":
            return 0
        if text not in self.memo:
            self.memo[text] = self.str_bias + len(self.strs)
            self.strs += text.encode() + b"\0"
        return self.memo[text]

    def record(self, name_off, kind, vlen, size_or_type, aux=b"", kind_flag=0):
        info = (kind_flag << 31) | (kind << 24) | (vlen & 0xFFFF)
        self.types += struct.pack("<III", name_off, info, size_or_type)
        self.types += aux
        self.log.append({
            "id": len(self.log) + 1,
            "kind": kind,
            "name_off": name_off,
            "vlen": vlen,
            "kind_flag": kind_flag,
            "size_or_type": size_or_type,
            "aux_hex": aux.hex(),
        })
        return None

    def int(self, name, size, bits, encoding=0, offset=0):
        data = (bits & 0xFF) | ((offset & 0xFF) << 16) | ((encoding & 0xF) << 24)
        self.record(self.string(name), KIND_INT, 0, size, struct.pack("<I", data))

    def ptr(self, target):
        self.record(0, KIND_PTR, 0, target)

    def array(self, elem, index, count):
        self.record(0, KIND_ARRAY, 0, 0, struct.pack("<III", elem, index, count))

    def composite(self, kind, name, size, members, kind_flag=0):
        aux = b"".join(
            struct.pack("<III", n, t, o) for (n, t, o) in members
        )
        self.record(self.string(name), kind, len(members), size, aux, kind_flag)

    def enum(self, name, size, members, signed=False):
        aux = b"".join(struct.pack("<II", n, v) for (n, v) in members)
        self.record(self.string(name), KIND_ENUM, len(members), size, aux,
                     1 if signed else 0)

    def wrapper(self, kind, name, target):
        self.record(self.string(name), kind, 0, target)

    def func_proto(self, ret, params):
        aux = b"".join(struct.pack("<II", n, t) for (n, t) in params)
        self.record(0, KIND_FUNC_PROTO, len(params), ret, aux)

    def func(self, name, proto, linkage=1):
        self.record(self.string(name), KIND_FUNC, linkage, proto)

    def var(self, name, target, linkage=1):
        # S160: VAR linkage lives in the aux word; vlen must be 0.
        self.record(self.string(name), KIND_VAR, 0, target,
                    struct.pack("<I", linkage))

    def datasec(self, name, size, entries):
        aux = b"".join(struct.pack("<III", t, o, s) for (t, o, s) in entries)
        self.record(self.string(name), KIND_DATASEC, len(entries), size, aux)

    def decl_tag(self, name, target, component_idx=-1):
        self.record(self.string(name), KIND_DECL_TAG, 0, target,
                    struct.pack("<i", component_idx))

    def finish(self):
        header = struct.pack("<HBBIIIII", MAGIC, VERSION, 0, 24, 0,
                             len(self.types), len(self.types), len(self.strs))
        return bytes(header + self.types + self.strs)


def base_rivals():
    img = Image()
    img.int("dup", 4, 32, encoding=1)  # ID 1: signed 32-bit rival
    img.int("dup", 8, 64)  # ID 2: unsigned 64-bit rival
    img.ptr(1)  # ID 3: pointer at the first rival
    return img


def split_extra(base_str_len):
    img = Image(str_bias=base_str_len)
    img.int("split", 8, 64)  # module-local ID 1 -> global ID 4
    return img


def shapes():
    img = Image()
    img.int("u32", 4, 32)  # 1
    img.int("s64", 8, 64, encoding=1)  # 2
    img.wrapper(KIND_TYPEDEF, "my_u32", 1)  # 3
    img.wrapper(KIND_CONST, "", 3)  # 4
    img.ptr(1)  # 5
    img.array(1, 1, 4)  # 6
    x = img.string("x")
    y = img.string("y")
    img.composite(KIND_STRUCT, "Point", 16, [(x, 1, 0), (y, 2, 64)])  # 7
    pt = img.string("pt")
    flags = img.string("flags")
    img.composite(KIND_STRUCT, "Outer", 24, [(pt, 7, 0), (flags, 1, 128)])  # 8
    a = img.string("a")
    b = img.string("b")
    img.composite(KIND_UNION, "U", 8, [(a, 1, 0), (b, 2, 0)])  # 9
    ea = img.string("EA")
    eb = img.string("EB")
    img.enum("E", 4, [(ea, 0), (eb, 1)], signed=True)  # 10
    pa = img.string("a")
    pb = img.string("b")
    img.func_proto(1, [(pa, 1), (pb, 2)])  # 11
    img.func("do_work", 11)  # 12
    fmt = img.string("fmt")
    img.func_proto(0, [(fmt, 5), (0, 0)])  # 13: void return, variadic tail
    img.func("log_msg", 13)  # 14
    f = img.string("f")
    g = img.string("g")
    img.composite(KIND_STRUCT, "Bits", 4,
                  [(f, 1, (3 << 24) | 4), (g, 1, (8 << 24) | 8)],
                  kind_flag=1)  # 15
    w = img.string("w")
    img.composite(KIND_STRUCT, "HasAnon", 8, [(0, 17, 0), (w, 1, 32)])  # 16
    v = img.string("v")
    img.composite(KIND_STRUCT, "", 4, [(v, 1, 0)])  # 17: anonymous
    img.decl_tag("tag1", 7)  # 18
    img.int("narrow", 4, 12, offset=4)  # 19: 12-bit value at bit 4
    img.wrapper(KIND_VOLATILE, "", 4)  # 20 -> 4 -> 3 -> 1
    img.record(img.string("fwd_s"), KIND_FWD, 0, 0)  # 21: struct forward
    img.record(img.string("f32"), KIND_FLOAT, 0, 4)  # 22: 4-byte float
    m = img.string("M")
    img.record(img.string("E64"), 19, 1, 8,
               struct.pack("<III", m, 2, 1))  # 23: enum64, M = 0x1_0000_0002
    img.composite(KIND_STRUCT, "Riv", 4, [(x, 1, 0)])  # 24: first rival
    img.composite(KIND_STRUCT, "Riv", 8, [(x, 2, 0)])  # 25: second rival
    img.wrapper(KIND_TYPEDEF, "PointAlias", 7)  # 26 -> Point
    return img


def maps():
    img = Image()
    img.int("u32", 4, 32)  # 1
    img.int("u64", 8, 64)  # 2
    img.ptr(1)  # 3: key pointer
    img.ptr(2)  # 4: value pointer
    ty = img.string("type")
    key = img.string("key")
    value = img.string("value")
    img.composite(KIND_STRUCT, "map_def", 20,
                  [(ty, 1, 0), (key, 3, 32), (value, 4, 96)])  # 5
    img.var("my_map", 5)  # 6
    img.datasec(".maps", 20, [(6, 0, 20)])  # 7
    img.var("orphan_map", 5)  # 8: in no DATASEC
    img.composite(KIND_STRUCT, "novalue", 8, [(ty, 1, 0), (key, 3, 32)])  # 9
    img.var("broken_map", 9)  # 10
    img.datasec(".maps2", 8, [(10, 0, 8)])  # 11
    return img


def cycle():
    img = Image()
    img.wrapper(KIND_TYPEDEF, "c1", 2)  # 1 -> 2 -> 1
    img.wrapper(KIND_TYPEDEF, "c2", 1)  # 2
    img.ptr(99)  # 3: dangling pointee
    img.wrapper(KIND_TYPEDEF, "t0", 0)  # 4: VOID target
    return img


def expected():
    return {
        "version": 1,
        "base_rivals": {
            "dup_ids": [1, 2],
            "int1": {"bits": 32, "signed": True, "size": 4},
            "int2": {"bits": 64, "signed": False, "size": 8},
            "ptr_to": 1,
        },
        "split_extra": {
            "global_id": 4,
            "name": "split",
            "bits": 64,
            "signed": False,
            "size": 8,
        },
        "shapes": {
            "my_u32_canon": 1,
            "volatile_canon": 1,
            "array": {"element": 1, "count": 4, "size": 16},
            "point_size": 16,
            "point_x": {"byte": 0, "bit": 0, "width": None, "size": 4, "ty": 1},
            "point_y": {"byte": 8, "bit": 0, "width": None, "size": 8, "ty": 2},
            "outer_flags": {"byte": 16, "bit": 0, "width": None, "size": 4, "ty": 1},
            "nested_pt_y": {"byte": 8, "bit": 0, "width": None, "size": 8, "ty": 2},
            "union_b": {"byte": 0, "bit": 0, "width": None, "size": 8, "ty": 2},
            "enum": {"bits": 32, "signed": True, "size": 4},
            "func": {"result": 1, "params": [1, 2], "variadic": False},
            "void_func": {"result": 0, "params": [5], "variadic": True},
            "bitfield_f": {"byte": 0, "bit": 4, "width": 3, "size": 4, "ty": 1},
            "bitfield_g": {"byte": 1, "bit": 0, "width": 8, "size": 4, "ty": 1},
            "anon_direct": {"byte": 4, "bit": 0, "width": None, "size": 4, "ty": 1},
            "anon_descend": {"byte": 0, "bit": 0, "width": None, "size": 4, "ty": 1},
            "narrow": {"bits": 12, "signed": False, "size": 4},
            "rival_ids": [24, 25],
            "rival_first_x": {"byte": 0, "bit": 0, "width": None, "size": 4, "ty": 1},
            "rival_second_x": {"byte": 0, "bit": 0, "width": None, "size": 8, "ty": 2},
            "alias_canon": 7,
        },
        "maps": {
            "my_map": [1, 2],
        },
    }


def vectors():
    built = {}
    built["base-rivals"] = base_rivals()
    base_str_len = struct.unpack("<I", built["base-rivals"].finish()[20:24])[0]
    built["split-extra"] = split_extra(base_str_len)
    built["shapes"] = shapes()
    built["maps"] = maps()
    built["cycle"] = cycle()
    images = {"images/%s.bin" % name: img.finish() for name, img in built.items()}
    graphs = {
        "version": 1,
        "images": {
            name: {
                "str_bias": img.str_bias,
                "strings_hex": img.strs.hex(),
                "types": img.log,
            }
            for name, img in built.items()
        },
    }
    payload = dict(images)
    payload["graphs.json"] = (json.dumps(graphs, indent=2) + "\n").encode()
    payload["expected.json"] = (json.dumps(expected(), indent=2) + "\n").encode()
    manifest = {
        "generator": "generate_vectors.py",
        "layout": "BTF v1 little-endian, hdr_len 24",
        "files": {
            name: {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            for name, data in payload.items()
        },
    }
    payload["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    for name, data in vectors().items():
        target = root / name
        if args.check:
            assert target.read_bytes() == data, name
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    print("PASS btf-v1 vectors")


if __name__ == "__main__":
    main()
