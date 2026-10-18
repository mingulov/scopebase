# SB02 source-tree staging bound maintenance

Date: 2026-10-18. **Accepted helper maintenance; no additional product task or
profile is accepted.** The source-copy helper now uses an independent 16 MiB
aggregate source-tree limit. Its JSON input limit remains 1 MiB.

The old helper reused the JSON limit for an entire source tree. TT02's real
133-file package was already 1,045,188 bytes before required review repairs;
adding legitimate regression tests could therefore prevent staging. The new
finite limit applies only to aggregate source copying. Config/path checks,
generated-file rejection, symlink handling, post-copy equality and the existing
`FIXTURE_BYTE_BOUND` error are unchanged.

Luna captured the expected failing cases and implemented the two-hunk helper
change. Root reviewed the complete diff and tests, then ran:

```sh
python3 -m unittest discover -s tests/package-policy -p test_source_copy_bounds.py -v
```

All three tests passed: a 1,049,284-byte source tree copies byte-for-byte, an exact
source-cap boundary succeeds while the next byte refuses before destination
creation, and JSON retains its own exact/over-limit behavior. The small source
boundary test supplies a smaller cap to avoid a large fixture. No Cargo, full
package matrix or runtime tests were run for this helper change.

Final helper SHA256:
`121b5e023ce7f0a473469b6f620e7978d8ee9669ca90f55e981d8e464e503dc7`.
Controller receipt SHA256:
`36fe565fd172aab4ef9f69482b53c7d43ff45f07a3e7cca07d05485bbe71b233`.
Private evidence is retained in
`.scopebase/controller/source-copy-bound-20261018/`.

TT02 receives an immutable helper amendment and a private launcher that preloads
these exact helper bytes without editing its frozen shared files. Its task
drivers still use the explicit common build wrapper for compiler commands.
Earlier receipts keep their original helper identities; unchanged package
semantics are not requalified by this maintenance.
