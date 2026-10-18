#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent SHA-256 oracle recipe. Requires Python stdlib only, not sha2."""
import hashlib
import json

if __name__ == "__main__":
    vectors = [("empty", b""), ("abc", b"abc"),
               ("nist-two-block-padding", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")]
    vectors += [(f"sequence-mod251-{n}", bytes(i % 251 for i in range(n)))
                for n in (55, 56, 63, 64, 65, 127, 128, 129, 1024)]
    print(json.dumps([{"id": name, "length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                      for name, value in vectors], indent=2))
