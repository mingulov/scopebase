# CP08 preservation map

Candidate sweep-order appendix for the accepted CP02 `time.rs` plus
`tests/interval_order.rs`, per [interval-order](../../issues/capture/interval-order.md).
This is a source/defect map, not acceptance or a test-result ledger.
Only frozen MemVeil `8307a17d4c1d01d2e6fa66679f0e7bed113fa416` and fix
`6ea5ffc43fafd0e67690be3b2da7192ecbaf2573` (FX04) are selected, one
inclusive line slice in total. All slice hashes were checked against the
gitless private capture
(`.scopebase/donor-snapshots/2026-10-18/memveil-ws/`); no live donor or
implicit Git lookup was used. Historical authorizations and OWNER grants
are separate; destination host/test terms are Apache-2.0. No
third-party or target/BPF/shared-source grant is inferred. Accepted
CP02 `time.rs` (lines 1–57) is already granted and unchanged; no new
slice is claimed for it. `MappingTracker`/`_note_peak_order` are concept
references only, not a slice.

Extraction: `sed -n '302,501p' checkout/repos/memveil/tests/unit/test_mappings.mojo | sha256sum`.
Fix-time bytes: `git --no-replace-objects --git-dir=histories/repo-001/history.git show 6ea5ffc:tests/unit/test_mappings.mojo`,
lines 302–501, hashed identically; `cmp` confirms the fix-time block and
the HEAD slice are byte-identical. Whole-file SHA256
`8348f3d7aac12c184629dac32fc1a49bafea571d65568106e2ea23a3b026f3e1`
matches the admission `observed_sha256`/`head_blob_sha256` exactly.

| Frozen source scope | Exact slice SHA256 | Origin and destination symbols | Preserved difference or limit |
|---|---|---|---|
| `M:tests/unit/test_mappings.mojo:302–501` @ `8307a17` | `8057c9a6e46f1d530c306a2aa50dc4e46d83d1e7fb4cca479e8ed6130a52aad7` | VECTORS_ONLY (nine test vectors) + ADAPT (ordering rule); `time.rs::{validate_sweep_order,EdgeKind,StateEdge,SweepProof}` + `interval_order.rs` seven tests | Preserve nondecreasing-timestamp sweep order, release-before-acquire half-open ties, withholding that keeps per-generation facts, zero as an ordinary timestamp, and non-state exclusion. Do not extract the tracker latch, any peak/live-byte reducer, the report fixture, or the uncertainty CLI test. DuplicateKey sweep-ID uniqueness and the (generation,ordinal)→ID adapter are NEW with no donor counterpart. |
| `M` fix `6ea5ffc` test hunk, `tests/unit/test_mappings.mojo:302–501` at that commit (defect record; bytes identical to the row above) | `8057c9a6e46f1d530c306a2aa50dc4e46d83d1e7fb4cca479e8ed6130a52aad7` | ADAPT (rule provenance: "Withhold occupancy peak without sweep-order proof (FX04)"); same destination symbols | Production hunks (`_peak_order_ok/_peak_ts_high/_peak_map_at_high`, `_note_peak_order`, `_break_peak_order`, metrics-row withholding) are concept-reference only. `tests/cli/test_uncertainty.py::test_reordered_delivery_withholds_peak` and `tests/fixtures/lifecycle/reordered-peak/*` are not selected. |

## Vector correspondence

Nine donor tests (lines 302–501) map to seven destination tests:

| Donor test (line) | Destination test |
|---|---|
| `test_overlapping_intervals_delivered_out_of_time_order` (302) | `reordered_edges_do_not_destroy_independent_duration` |
| `test_ordered_overlap_reports_peak` (357) | `release_before_acquire_tie_is_valid` (overlap part; 8192 peak value not ported) |
| `test_ordered_disjoint_reports_peak` (378) | `release_before_acquire_tie_is_valid` (disjoint part) |
| `test_equal_timestamp_release_first_keeps_peak` (396) | `release_before_acquire_tie_is_valid` |
| `test_equal_timestamp_map_first_withholds_peak` (416) | `acquire_before_release_tie_withholds_sweep` |
| `test_reversed_lifetime_withholds_peak` (436) | `acquire_before_release_tie_withholds_sweep` (backward-delivery part) |
| `test_ordered_open_intervals_keep_peak` (451) | `release_before_acquire_tie_is_valid` (ordered part; open-count/peak values not ported) |
| `test_zero_timestamp_tie_withholds_spike` (468) | `timestamp_zero_is_valid` |
| `test_non_state_events_ignore_peak_proof` (484) | `non_state_facts_do_not_break_the_sweep` |

`duplicate_sweep_event_id_refuses` and
`generation_local_zero_ordinals_map_to_distinct_sweep_ids` are NEW: the
donor has no sweep-unique-ID refusal or adapter mapping. `DomainMismatch`
admission reuses accepted CP02 `Timestamp`/`ClockDomain` machinery.

## Defect, independent truth and sensitivity

Delivery order is not time order: summing intervals in arrival order or
sorting everything to invent causal order fabricates peaks. The donor
latches the peak unavailable with a "timestamp order" reason on the
first sweep-order violation while live bytes, lifetimes and byte-time
stay valid. The destination checks the submitted stream as given —
one clock domain, sweep-unique IDs, nondecreasing timestamps, Release
before Acquire at ties — and refusals change no caller state. Bad
controls: the tie-policy mutant, the arrival-order-as-time mutant, the
checker mutant (accept ID 41 twice) and the global-quality-poisoning
mutant each fail the explicit ordering/duplication/duration assertions;
restored valid twins pass.

## Grant coverage

Checked against `docs/provenance/admissions/*.json` (all ten intake
snapshots) and `docs/provenance/adoption-decisions.md`:

- Slice `M:tests/unit/test_mappings.mojo:302–501`: **NEW-GRANT-NEEDED**.
  The file row `M:tests/unit/test_mappings.mojo` is
  `VECTORS_ONLY`/`READY_FOR_SELECTED_SCOPE` under `OWNER-2026-10-18`,
  but its ready `source_scope` is only `[544,559],[599,607],[768,783],[848,899]`
  (latest: `2026-10-22-next-host-scopes.json`; earlier snapshots grant
  only `[599,607],[768,783]`). Range 302–501 appears solely as an H27
  `inspected_donor_anchor` with coverage `INSPECTED_SOURCE`, which is
  inspection, not authorization. Missing question: does the owner extend
  the ready scope of `M:tests/unit/test_mappings.mojo` at `8307a17` to
  lines 302–501 (= fix `6ea5ffc` added test block, byte-identical) for
  CP08 `VECTORS_ONLY` vector adaptation plus `ADAPT` of the stated
  ordering rule, destination Apache-2.0?
- Fix `6ea5ffc` as defect record: **NEW-GRANT-NEEDED**, same missing
  question as above for its test hunk. Its production
  (`src/memveil/analysis/mappings.mojo`) hunks are concept-reference
  only and claim no copy; its `test_uncertainty.py`/fixture hunks are
  unselected. No grant is invented here.
- Accepted CP02 `time.rs`: already granted, no new slice.
- `MappingTracker`/`_note_peak_order`: concept reference only, no slice,
  no grant claimed.

## Later owners and duplicate retirement

All mechanisms here are T0/T1 host evidence. Peak/live-byte reducers,
generation/loss coverage for metrics, causal identity and any live
mapping proof stay with product/BP owners; CP05 owns generation
matching, CP06 view/correction semantics, CP11 real adapters. No donor
duplicate is removed here.
