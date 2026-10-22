# LX05 final review-fix preparation report

Status at original worker handoff: **BLOCKED_ENVIRONMENT** (historical).
Current post-format continuation: **RERUNS_PASSED_PENDING_INDEPENDENT_REVIEW**. This report is staged in the LX05-owned fuzz
project because the requested private job evidence directory is read-only in
this sandbox. No commit could be created because the shared worktree Git index
is also read-only. The preparation-index SHA-256 is returned separately.

## Diagnosis and pre-edit bindings

Daybreak's High finding is correct. The frozen A3 contract specifies three rows
with `r--p/r-xp/rw-p`, offsets `0/0800/1400`, one `0b:02 91`
`/fixtures/alpha` key/path, followed by literal `broken`. The candidate's
`refuses_mixed_valid_and_malformed` test and delivered `maps_invalid.bin` used
`r-xp/rw-p/r--s`, `0010/0050/0090`, three distinct keys and paths, and
`broken-tail`. They proved generic refusal but no exact A3 positive facts.

Pre-edit SHA-256:

- `tests/proc_parsers.rs`: `50aad0f80b24940c588e43e7820fdc987209bf7fc6bc3372fce9bd62b14f31f4`
- `tests/fixtures/procfs/maps_valid.bin`: `083ec1dda44fde90cf9010a82b6eb167e959fac7c66f0c0716565b2ede8b0545`
- `tests/fixtures/procfs/maps_invalid.bin`: `ab26045574b515d93ae833bb66b5537f8fcaa697e46d54a4a7b99aa10be3b9e1`
- `tests/fixtures/procfs/expected.json`: `459e77fcf2b1d5b885d010463f19ec387abd8201c3f6019a3efeeee3747fba36`
- `tests/fixtures/procfs/README.md`: `1f3a87c29db88e9b784a3b0aa38b594d4e82fb2a4dd859b387c92c3e9a518d16`
- `tests/support/maps_inventory.rs`: `967878252a12f8710a5655a401422dcccff20d3793c2fa920bbce6974c80a3ac`
- `tests/support/proc_reference.rs`: `28cb7cf07fee04f9af51593bbbaf130acc80685ea42ea1b1914d0b595dbef25e`
- `src/procfs/maps.rs`: `76212790b25c2a4db48c84576a1a83830ada1b8fdabbba87c21b5de6b2f46d38`

## Staged changes and static checks

Added exact A3 positive/negative fixtures, a new test with all literal row
facts, the seven address-to-offset assertions, independent oracle agreement,
and explicit whole-input refusal with stage/reason/line/validated count/zero
effects. The existing generic fixtures and test remain. The package-local
`maps_inventory` client checks the same literal population, and the offline
package helper now requires the named A3 test in delivered test inventory.
`expected.json` and fixture README distinguish A3 from the generic fixture.
The crate manifest already includes `tests/**`, so these paths are selected for
a future archive; no new archive was created or tested.

Added a separate `fuzz/scopebase-linux` workspace with reviewed draft targets,
a byte-identical copy of the independent oracle, 241 hashed seeds including
both exact A3 populations, a staged 18-package combined lock graph, and
preparation bindings. All 241 seed files are unique by target/name, hash-match
their manifest and fit the 4096-byte engine ceiling. The draft maps
`line-512` seed's expected result was corrected to refusal because its padding
extends the inode token. The seed bytes were retained. These are static
preparation checks, not fuzz execution.

A production skip-malformed-row mutation is frozen in
`controls/a3-skip-malformed-row.patch`; its expected semantic kill is the
`A3 whole-input refusal after three valid rows` assertion. The actual
production parser was never edited in this round and remains byte-identical to
the pre-edit SHA-256 above. The control is **NOT_RUN**.

## Commands and observed results

- Exact test request: `CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/tmp/lx05-a3-target /home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build -- cargo test --offline --locked -p scopebase-linux --test proc_parsers a3_exact_prefix_and_whole_snapshot_refusal -- --exact --nocapture`. Exit 64 before Cargo launch: `scopebase-build: [Errno 30] Read-only file system: 'build.lock'`.
- Offline graph request: `CARGO_NET_OFFLINE=true /home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build -- cargo metadata --offline --locked --format-version 1 --manifest-path /home/user/src/m/bpfscope/.worktrees/lx05-proc-20261018/fuzz/scopebase-linux/Cargo.toml`. Exit 64 before Cargo launch with the same read-only lock error.
- Static Python seed binding: **PASS**, 241 unique seed records, hashes, length bounds and exact A3 bytes.
- Absolute stable `rustfmt --edition 2021 --emit stdout` on the changed Rust test/client and both staged fuzz targets/oracle: exit 0, syntax parsed; no compilation.
- Static TOML lock parsing and archive checksum matching: **PASS** for 14 locally admitted registry archives; `rustix@1.1.5` and `bitflags@2.13.2` are missing from the controller fuzz admission. The staged combined graph has 18 packages but Cargo metadata and lock validation are **NOT_RUN**.
- The required Rust test source contains 29 named `#[test]` declarations; executed: **0**. A3 RED controls: **0/1 executed**; restored A3 checks: **0/1 executed**; crate full suite: **0 executed**; new source/archive delivery cells: **0 executed**. Prior receipts remain untouched.
- Fuzz builds, links, startup and both 10,000-run campaigns: **NOT_RUN**, as required before root admission.
- `git diff --check`: exit 0 for tracked edits. `git add --` of the owned changes: exit 128, `Unable to create '/home/user/src/m/bpfscope/.git/worktrees/lx05-proc-20261018/index.lock': Read-only file system`. No commit was created.

## Required root admission and completion

Root must make the common wrapper lock writable to this job and provide a
writable Git worktree index and private LX05 evidence destination, admit local sources for the two
missing locked dependencies without substitution, then review the final
candidate/oracle/corpus/combined graph/native flags. The implementation owner
must run the exact A3 test on the skip-row mutant to observe the intended
assertion, restore the byte-identical parser, run the positive/restored test,
crate full suite and causal source/archive delivery checks, and regenerate
validated Cargo lock/metadata and final evidence bindings through the absolute
wrapper. Only then may root admit separate build/link/startup and campaigns.

## Root completion on pre-format bytes (2026-10-18, historical)

Root completed those environment-owned steps without fetching or substituting
sources. The exact A3 candidate/mutant/restored receipt passed, all six affected
package cells and twelve source/archive helper receipts passed, locked/offline
metadata resolved the 18-package graph, and both address-sanitized fuzz targets
built, started and completed 10,000 runs without crash artifacts. The immutable
receipt paths and hashes are recorded in `qualification.md`; this section does
not relabel the blocked worker commands above as executions.

## Post-format continuation (2026-10-22)

The resumed worker executed all three prepared post-format gates, retaining
immutable predecessors and timeout-only launcher successors in
`.scopebase/controller/resume-20261022/lx05/`. The exact A3 candidate/mutant/
restored exits are 0/101/0 with the intended whole-input-refusal semantic kill.
All six compiler/configuration package cells passed; the derived gate has
56 PASS rows and all twelve source/archive helper receipts passed, representing
24 client executions. Both locked/offline ASan fuzz targets built, started,
and completed 10,000 runs each without crash artifacts. `qualification.md` and
`preparation-index.json.superseded_by` bind the actual new result paths/hashes;
`previous_superseded_by` preserves the pre-format receipts.

No Rust, parser, independent-oracle, fuzz-target, Cargo-lock or seed bytes
changed during this continuation. Three qualification metadata documents
changed after execution; their predecessor versions remain retained so that
the fuzz receipt's project-file snapshot is independently checkable. All
Cargo/native commands used the absolute shared build lease with a
1800-second acquisition allowance, including the one outer package-driver
lease. No donor/dependency refresh, installation or privileged probe ran.

The proper 27-file source/support/fuzz rustfmt check passed. A deliberately
broader exploratory check also included compile-boundary UI snippets and
reported existing formatting differences in 32 of them; each is identical to
the candidate base. The diagnostic and failed exploratory receipt remain
retained, and those fixture bytes were preserved.

Final independent Daybreak review and controller selected-port validation,
commit, canonical integration and acceptance remain open. This worker created
no approving reviewer and no commit. Runtime acquisition/identity/profile
qualification remains with the later owners.
