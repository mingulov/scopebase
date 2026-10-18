# Positional bounded reads and retained file observations

Status: implemented candidate `f11fed73c0fb86d49c8f40eccd4e8dc8b3c0cb66`, independently reviewed; controller integration acceptance remains separate. This issue records LX03, H06 and its LX-R reader/accounting obligations. Complete mapped-image, filesystem, installed-operator and migration gates remain open.

## Defects and preserved mechanisms

A shared file description has one cursor. A reader using that cursor can return only a suffix after another alias seeks or reads; neither a successful read nor a size check proves that offset zero was used. A bounded reader can also silently accept an early zero, grow its allocation beyond its advertised budget, miss a byte appended at the original end, lose work charges on cancellation, or publish content whose observed metadata changed. Equal before/after metadata still cannot prove immutable content.

The selected p11scope positional loop and early-zero refusal, checked work budget, OSSLscope cap/sentinel/final-stat checks, shared payload and raced-sibling regression are preserved. The [eleven-slice receipt](../../provenance/ports/LX03-20261018-reads.json), [preservation map](../../provenance/ports/LX03-preservation-20261018.md) and [immutable admission](../../provenance/admissions/2026-10-18-lx03-read.json) bind exact file hashes, source ranges and final destinations. Frozen P commit is `2c2713e66292b0d2688508a25f79e813ae823d81`; frozen O commit is `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`. Original source-license observations remain distinct from the user-owner Apache-2.0 host destination grant. No unrelated source or kernel grant follows.

## Minimal triggers and independent expected results

Create a regular file containing literal `0123456789`, adopt/retain it through HeldFile, and move the cursor through an alias before and during two reads. Each successful FileRead must contain the complete literal ten bytes; the alias cursor must retain its independently observed position. The wrong cursor-based reader must reach the full-content assertion and fail. A suffix-success mutant tests the complementary early-zero/truncation boundary. Scoped workers release and join under the fixture owner; their failure paths and exclusive temporary-path setup are tested separately.

Use literal sizes empty, one byte, exact cap, cap-plus-one and a sparse huge file. A separate operation ledger checks reserve/read calls and charges. Append a real byte at the old end and retain a stable-stat control population: the mandatory one-byte positive EOF sentinel distinguishes growth even when a final-stat observation is held constant by the seam. Inject short positive reads and EINTR with independently prescribed offsets/results; premature zero refuses. Requested, granted and retained capacities are separately asserted, including an overgrant and a real TryReserveError.

Observe a real same-size content rewrite and explicit device/inode/size/mtime/ctime variations; changed observations refuse publication. A deliberately mixed read with equal metadata remains `NotProven`, preserving the evidence limit. Cancel/deadline checkpoints retain already incurred work and failure errno precedence. The intentionally blocked-read fixture remains pending until explicit release; the wrong invocation owner returning before release fails its semantic custody assertion, and the child is still released/joined/reaped.

## Delivered checks and actual consumers

The package ships `src/file/read/tests.rs`, `tests/positional_read.rs`, read privacy/ownership compiler cases and both public clients. From an unpacked package, `cargo test --locked --offline --lib --test positional_read` runs the delivered assertions using the caller's installed compiler and existing offline dependencies. Existing held/control/trait tests and doctests are separate affected checks. Ordinary downstream cargo test does not execute a dependency's own tests automatically.

`tests/support/read_adopted.rs` independently adopts a positioned File and checks cursor, accounting and retained result. `tests/support/read_opened.rs` uses the retained ProcFdResolver/open route, replaces/unlinks a path, and concurrently reads original descriptor bytes while observing the replacement separately. Both were compiled as actual external clients against source and unpacked archives with exact dependency metadata. Their bounded fixtures establish this API increment, not complete application migration or installed conformance.

Worker evidence spans Rust1.88.0/1.98.1 and minimal/default/supported-union. Final fixture repair has 101 affected delivery rows and 55 selected control rows; earlier557/793 receipts remain bound to their original bytes and explicitly unchanged assertions. No changed archive is certified solely by an old receipt. The root package gate and acceptance record bind the final integrated package and policy. A semantic control must execute the named assertion after valid setup; compiler/setup failure, watchdog timeout or unresolved cleanup cannot count as the product defect being detected.

## Limits and later retirement

Caller limits bound bytes, attempted read calls and requested/granted capacity separately. Metadata calls and actual read attempts retain their charges. No implicit thread, path reopen, mapping, hard interruption or immutable snapshot is supplied. Kernel read/metadata calls can block; cooperative cancellation does not retire an in-progress syscall. Payload clones share one Arc allocation, so summing reported retained capacity across aliases double-counts storage.

LX06/LX07 own real Btrfs/overlay/namespace mappings, retained mapping proof and no-new-target-mapping checks. LX11/LX12 and TT02/TT03/TT06/TT07 own reusable conformance/session/operator delivery. MG01/MG02 may retire donor readers only after actual product adoption and their original application/producer regressions pass on the selected ScopeBase version. This issue does not retire any donor duplicate or authorize publication.
