# Cross-stage reservation evaluation (CP12)

CP-R14 requires an evidence-backed extraction decision for cross-stage
count/byte reservations against two independent consumers before any stable
extraction. The gated internal pilot lives in
`crates/scopebase-capture/tests/support/reservation_pilot.rs`, is exercised
by `crates/scopebase-capture/tests/reservation_evaluation.rs` (10 tests),
and is never exported from `lib.rs` nor gated by a feature. Two bounded
experiment-local stage pipelines run the consumer fit check: KryProbe-shaped
ingest -> fold -> report (`consumers/capture-kryprobe-reference`, 1 test)
and MemVeil-shaped observe -> view under pool pressure
(`consumers/capture-memveil-reference`, 2 tests).

## Decision: retain-internal/defer-stable-export

The mechanism works in all three harnesses, but no stable reservation
module is extracted. Only a reviewed subsequent API design can promote one.
The pilot and both consumer modules stay internal and experiment-local.

## Mandatory source decision

The accepted shared-ledger successor is the p11scope `StagingLedger` in
`.worktrees/v040-integration/src/semantics_objects/journal.rs` at commit
`2c2713e66292b0d2688508a25f79e813ae823d81` (branch `v040-h7-object-wire`,
clean frozen checkout), user-owned application code under grant
`OWNER-2026-10-23`. Adapted slices: one-ledger census (`:291-310`,
`:329-335`), byte-fit admission (`:337-341`), charge order with rollback
(`:347-360`), idempotent release (`:362-367`), checked monotone mint
(`:429-443`), reviewed-limit freeze (`:465-470`). Original regression:
`src/s2s3_tests.rs:2943`
(`s2s3_bounded_state_and_redaction_policy_scale_n_and_n_plus_one`) threads
one ledger through begin/complete/settle at N/N+1 scale. No
third-party/upstream lines are copied.

## What the evaluation proves

- One global budget across stages: count 2 / bytes 16 admits two 8-byte
  payloads and refuses a third 1-byte payload; staging -> retained keeps
  the total at 16. A per-stage-budgets control holds 32 joint bytes and is
  rejected as over-admission (`per_stage_budgets_overadmit`).
- Failed transfer returns the same charge: same-stage moves refuse with
  `DuplicateKey`, hand back the same ticket, and leave 16 bytes charged.
- Cancel refunds only after payload retirement: cancel marks custody and
  keeps the live charge; an early-refund control reporting 0 while the
  payload lives is rejected (`early_refund_loses_retained_charge`).
- Shared clones alias without charge; independent copies charge anew and
  refuse while the pool is full.
- A count-only pilot (`byte_limit = None`) admits any byte size and
  reports its byte guarantee as unknown; freezing a reviewed limit
  restores refusal without retroactively bounding the earlier phase.
- Conversion overlap is recorded: input + output held together peaks at
  16, and the peak survives the input's retirement.
- The u64 MAX boundary refuses without wrap: ceiling-first admission via
  remaining budget names `CapacityExceeded`, preserves totals, and mints
  no ticket; the independent oracle agrees on every refusal.

## Two-consumer fit

Both consumers run the same rules with different stage shapes and pass.
KryProbe's three-stage flow confirms moves never disturb the global total
and the peak records full overlap. MemVeil's pool confirms pressure
refuses loudly with no silent drop or eviction, shared views alias, and
cancel retains until the last view retires. Fit is behavioral only: each
consumer re-implements the rules in ~100 experiment-local lines because
the pilot is deliberately not exported. That duplication is the measured
cost of keeping the pilot internal, and it is small enough not to force
extraction on its own.

## Counted, retained and peak bytes are distinct

- Counted bytes are live ledger charges: they gate admission.
- Retained bytes are charges held by at least one live owner after cancel
  or aliasing: they gate nothing new but are still owed.
- Peak bytes are the highest counted total ever observed: a diagnostic of
  past overlap, never a pre-guarantee of future fit.
- With `byte_limit = None` there is no byte number at all: count pressure
  only. No cardinality bound, timeout, or count-only run is marketed as a
  memory or retirement bound.

## Why stable export is deferred

- Stage location rides on the handle, not the ledger: the pinned
  `transfer(self, stage)` takes no ledger, so cross-stage custody of a
  shared handle is asserted on handles, not mediated by the owner. A
  stable API needs mediated moves or a different custody story.
- No thread story: `Rc` payloads and `&mut` ledger access promise no
  `Send`/`Sync`. Threaded consumers would need an `Arc`/lock design with
  its own deadlock/poison review.
- `Drop` cannot retire into the ledger: release needs `&mut` access only
  explicit `retire` supplies, so a dropped-without-retire handle leaks its
  charge with no reclamation story. A public API built on explicit
  retirement is a footgun until that story exists.
- Byte charges are accounting, not allocator facts: the pilot charges
  structural bytes like the donor and owns one heap box per reservation,
  never a bytes-sized buffer. It bounds neither allocator behavior nor OOM
  outcomes, and the peak observes rather than guarantees.

## Alternatives considered

- `std::mpsc` channels bound queue length but account neither bytes
  across stages nor ticket custody, and offer no transfer-with-charge or
  cancel-retains semantics.
- Semaphore-style permits bound counts but not joint count + byte +
  ticket custody, peak overlap, or reviewed-limit freezing.
- The ledger's value over both is joint custody with explicit refusal
  taxonomy (`CapacityExceeded`, `DuplicateKey`, `ArithmeticOverflow`
  defense). That value is real but does not outweigh the open handle,
  thread, and reclamation design above; hence deferral, not rejection.

## Limits of this evidence

All thirteen checks are host-side model tests over experiment-local
ledgers; none qualifies producer, kernel-map, allocator, or live-runtime
behavior. The donor regression cited above stays a reference: it ran in
the donor, not here. Product migrations and duplicate retirement remain
with later MG tasks.
