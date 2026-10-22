# Scoped sweep order without metric authority

CP08 appends a sweep section to the accepted CP02 `time.rs` (no
existing line changed) and adapts MemVeil fix `6ea5ffc` via
`tests/unit/test_mappings.mojo:302-501`: release-before-acquire
half-open ties, out-of-order delivery withholding the dependent proof
while per-generation facts stand, and non-state events excluded from
the sweep. `MappingTracker`/`_note_peak_order` are concept references
only; this module validates submitted order and exports no metric
reducer.

Delivery order is not time order. Summing intervals in arrival order,
sorting everything to invent causal order, or inferring timestamp
order from numeric sweep IDs fabricates peaks. `validate_sweep_order`
therefore checks the submitted stream as given: one clock domain
(`DomainMismatch`), sweep-unique event IDs (`DuplicateKey`),
nondecreasing timestamps with Release before Acquire at ties
(`InvalidInterval`). Identity admission precedes temporal validation;
refusals change no caller state. `O(n log n)` work and `O(n)`
duplicate-set storage. The empty stream yields an ordering-only
proof, never activity or peak support.

Sweep IDs are unique within one sweep, not generation-local ordinals
or universal identities. The adapter maps each source
`(generation, local ordinal)` injectively and stably: distinct
generations legitimately reuse local ordinal 0
(`(7,0)->41,(8,0)->42`), repeats retain their ID, and IDs need not
increase. Passing local ordinal 0 for both generations is an adapter
bug caught as `DuplicateKey`. Ordering refusal never discards a
separately validated per-generation duration.

Bad controls: the tie-policy mutant (accept acquire-before-release
ties), the arrival-order-as-time mutant, and the checker mutant
(accept ID 41 twice) each fail the explicit ordering/duplication
assertion; the global-quality-poisoning mutant fails because refused
sweeps leave durations intact. Restored valid twins pass, and active
non-state facts with wild timestamps do not invalidate state
ordering. Donor vectors covered: ordered overlap/disjoint report,
release-first tie keeps, map-first tie withholds, reversed delivery
withholds, zero-tie withholds spike while the zero lifetime stands,
and non-state exclusion.

All mechanisms here are T0/T1 host evidence. Peak/live-byte
reducers, generation/loss coverage for metrics, causal identity and
any live mapping proof stay with product/BP owners; CP05 owns
generation matching, CP06 view/correction semantics, CP11 real
adapters. No donor duplicate is removed here.
