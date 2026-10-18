# CP03 preservation map

Candidate `8ac03f73e62ffd5497a3a43d21dafdca5d2e11f9` adapts the six narrowly admitted K/O source rows below. The [immutable admission](../admissions/2026-10-18-cp03-counters.json) records source pins, original GPL-3.0-or-later labels and `OWNER-2026-10-18` authorization for the user-owned Apache-2.0 host destination. No full donor file or application state machine was copied. This map and its receipt record implemented selected scopes; independent review and final acceptance remain separate.

| Source and admitted lines | Destination symbols | Preserved behavior and intentional adaptation |
|---|---|---|
| `K:crates/kryprobe-abi/src/kcrypto_agg.rs` 133–161 | `crates/scopebase-capture/src/loss.rs` — `fold_capped_signals`, `CappedLossSignal` | Independent CPU/program diagnostic lanes sum with a cap. The byte API rejects cap zero and out-of-cap lanes, including lanes after saturation; it does not claim exact omitted events. |
| `K:crates/kryprobe-privilege/tests/kcrypto_who.rs` 862–888, 890–902, 904–917, 919–930, 932–954 | `crates/scopebase-capture/tests/loss_units.rs` — `k_lanes_cap_and_remain_independent`, `invalid_late_lane_is_not_hidden`, `diagnostic_exhaustive_pairs` | Preserve nonzero accumulation, repeated-attempt cap, already-capped stability and independent CPU/program observations. Pure pre-capped vectors do not qualify full-map or live producer behavior. |
| `K:crates/kryprobe-core/src/evidence/integrity.rs` 172–191, 235–259 | `crates/scopebase-capture/tests/counter_deltas.rs` — `saturation_is_lower_bound`; `crates/scopebase-capture/tests/loss_units.rs` — `k_lanes_cap_and_remain_independent` | Preserve saturation, queue-overflow and empty-population distinctions. The application integrity summary and once-only rollup remain local/later. |
| `O:src/capture.rs` 1504–1515, 8881–8890 | `crates/scopebase-capture/src/counter.rs` — `sample_delta`; `crates/scopebase-capture/tests/counter_deltas.rs` — `missing_baseline_is_unknown`, `monotonic_and_reset` | Keep a missing baseline unknown and preserve observed zero. The explicitly ratified generic protocol makes decreases ResetOrWrap instead of donor saturating subtraction. |
| `O:src/evidence.rs` 300–348 | `crates/scopebase-capture/src/loss.rs` — `LossFact`, `LossMagnitude`, `LossKind` | Preserve source, channel, unit, loss kind and exact/lower-bound/unknown distinctions without combining activity and loss or importing application finalization policy. |
| `O:tests/evidence_model.rs` 520–554 | `crates/scopebase-capture/tests/loss_units.rs` — `kinds_units_and_magnitudes_are_retained`, `k_lanes_cap_and_remain_independent` | Keep activity999 and loss1 separate in retained unit/source-tagged facts. No generic aggregate total or backend completeness claim is introduced. |

The selected source-to-destination map binds each destination file by hash in the [port receipt](CP03-20261018-counters.json). Existing CP02 receipt/source bytes are unchanged.

## New protocol and regression preservation

`Sample`, `AdvanceBound` and `Delta` implement the missing width-generic typed protocol under [D10 C1–C6](../../superpowers/specs/2026-10-18-scopebase-decisions.md#cp03-counter-and-loss-rulings). A bound retains the exact value/context/read-window pair and an explicit independently justified maximum/no-reset assertion. It does not infer proof from a residue or elapsed time. Constructor/comparison precedence, half-open read windows, saturating reset/plateau and width64 arithmetic follow that frozen contract.

`counter_deltas.rs` contains two independently constructed 4-bit populations (4,352 each), 256 no-bound pairs and separate literal width64/saturation rows. `loss_units.rs` checks 5,625,215 valid diagnostic pairs with a wider sum-and-clamp oracle, invalid late lanes, all seven kinds and units, and exact zero/lower-bound/unknown cases. The delivered mutation driver requires compile-valid mutants to fail their named semantic assertion and rebuilt restored twins to pass. Actual source/archive/compiler/client results are recorded separately; the existence of these tests does not certify their execution.

## Reference-only inputs and later owners

The worker input register also includes reference hashes outside the admitted scopes: K `SimAttrLoss`740–773 and full-map setup783–860; these are not copied scopes. P first-use acquisition and O `SeqState` half-range inference remain reference-only. The actual receipt uses only the explicit admitted ranges above.

CP04 retains full-map/insertion host models; BP02/BP07 retain actual ABI, producer storage/partition and live acquisition/order tests; CP06 owns persistent per-claim/once-only rollup; CP10 replay; CP11 real independently useful application consumers; CP13 installed conformance. The two new package examples exercise distinct public APIs but do not close CP11.

No donor duplicate is retired. Retirement requires a named migrated consumer bound to its actual ScopeBase version/features, original application and producer regressions, conformance checks and retained application policy. No runtime profile, product migration or publication is certified by this receipt.
