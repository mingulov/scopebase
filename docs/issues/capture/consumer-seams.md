# CP11 consumer seams

Reference-only consumer seams over `scopebase-capture`. NEW (CP11): no donor
lines copied. KryProbe/OSSLscope/MemVeil/p11scope product integrations remain
explicitly LATER; no product policy is normalized away for equality.

## Standalone consumers

Three materially different reference consumers, each with its own manifest,
lockfile, binary and `ConformanceAdapter` implementation. No code is shared
between them; each records its own fixed script constants.

| Consumer | Shape | Capture surface |
|---|---|---|
| `consumers/capture-kryprobe-reference/` | insertion/counter/loss | `fold_insertion_identity`, `sample_delta`, `fold_capped_signals`, `LossFact`, `FeedRegistry`, holders over `u64` |
| `consumers/capture-memveil-reference/` | facts/generations/views | `ObjectKey`/`require_generation`, `validate_sweep_order`, `ClaimLedger`/`QueryOverlay`, `FeedRegistry`, holders over view snapshots |
| `consumers/capture-ossl-reference/` | bounds/corrections | `SiteCount`/`classify_alternatives`/`combine_disjoint_sites`, `neutral::validate_v1` with versioned corrections, `FeedRegistry`, holders over `CountBounds<Events>` |

Each adapter dispatches on the invocation's operation name plus a `case=<name>;`
fixture script, encodes capture contract refusals as observed `refuse=<Variant>;`
bytes, and reserves `CaseError` for adapter-level failures (missing slot,
unknown operation/case, malformed script). Observations are schema-tagged
(`<name>-reference-v1`, revision 1) bounded actual bytes, never expected truth.

Shared script intent, independently recorded per consumer: 10 events, one
unknown mapping identity, 5 copy bytes, one missing release relationship (a
required feed), one partial query. Copy bytes survive occupancy uncertainty;
the partial marker disappears in the next view while actual loss persists.

## Correction holders

`crates/scopebase-capture/src/holder.rs` (`CorrectionHolder`, `HolderPair`,
`HolderDivergence`): paired report/export copies over `Versioned` values. Each
side advances only through its own apply; `divergence()` detects a dropped
update. Late contradiction replacement at revision 1 must equal the
independently expected revision 1 in both holders; the dropped-export mutant
fails that assertion in every consumer suite plus the holder unit tests.

## Unknown versus zero

Unknown and zero stay distinct on every seam: `Unknown` loss magnitudes,
`[0,None]` open bounds, `AtLeast(0)` damaging versus `Exact(0)` benign ledger
facts, `MissingBaseline` deltas, and unknown mapping identities that never
become known zero. Examples record closure provenance per call site and claim
no global completeness.

## Actual future product call sites (LATER)

- KryProbe aggregate lanes: insertion fold + capped signal fold behind a live
  acquisition adapter (MG producer work, not this task).
- MemVeil mapping tracker: generation checks + sweep order + claim views behind
  its evidence pipeline (MG producer work, not this task).
- OSSLscope evidence model: site bounds + neutral replay behind its capture
  ingest (MG producer work, not this task).

## Later MG requirements

Product migrations MG01–MG05 own live acquisition, duplicate retirement, and
installed qualification of these seams. CP13 owns the packaged conformance
closure over the CP11 consumers. Testkit-side capture adapter glue stays with
its single owner.
