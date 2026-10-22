# BP06 preservation map

Candidate host implementation map for [BP06 bounded ring](../../issues/bpf/bp06-bounded-ring.md)
(`crates/scopebase-bpf/src/ring/` + `tests/ring.rs` + `fixtures/ring-v1/`).
This is a source/defect map, not acceptance or a test-result ledger. It follows
the [CP06 precedent](CP06-preservation-20261022.md): per-slice frozen origins,
exact slice hashes, PORT/ADAPT/VECTORS_ONLY bindings and preserved
differences/limits (what was NOT extracted).

Only frozen KryProbe `d153f3aaf9a3931337b47c9e1b046c692da55083` (main checkout),
p11scope `2c2713e66292b0d2688508a25f79e813ae823d81` (`.worktrees/v040-integration`)
and libbpf-mojo `ff6ea5087cb6cab3db51a9ffaf99922f880da8c9` (checkout-002) are
selected, 23 inclusive line slices in total. All slice hashes were checked
against the gitless private capture
(`/home/user/src/m/bpfscope/.scopebase/donor-snapshots/2026-10-18/`); no live
donor or implicit Git lookup was used. Whole-file bytes match the intake:
K `5fd4a04a…978cb7`, P `e65365f3…8aecd` (v040-integration copy; the main-checkout
`p11scope/…` copy differs and is NOT selected), L `b931cb7a…96a24a`,
L-test `08d30f51…3ef4e1`. The v040-integration (w003), KryProbe main (w001) and
libbpf-mojo checkout-002 worktrees are clean (empty staged/unstaged/status).
Extraction: `sed -n '<first>,<last>p' <frozen file> | sha256sum` over patch-file
bytes (P slices) or source bytes (K/L slices), inclusive line ranges.

Grant state (checked against `docs/provenance/admissions/*.json` and
[adoption decisions](../adoption-decisions.md)): exactly one slice is COVERED
(L9, inside the ready `L:tests/native/ring_conformance.c` VECTORS_ONLY scope
`[536,538],[572,574]` under `OWNER-2026-10-18`, data-document/Apache-2.0, in
`2026-10-22-next-host-scopes.json`). The other 22 slices are NEW-GRANT-NEEDED;
no grant is invented. The sibling granted range `[536,538]` (session-side
conservation CHECKs) is granted but unselected: the session adapter is not
extracted. Destination host/test/data terms are Apache-2.0. No third-party,
target/BPF or shared-source grant is inferred.

| Frozen source scope | Exact slice SHA256 | Origin and destination symbols | Preserved difference or limit |
|---|---|---|---|
| `K:crates/kryprobe-privilege/src/drain/frame.rs:13–20` | `4d7296eb3e53a99c8c65ccda1fb39f60caa99f862239d7ffa56dd3aba1bf8815` | ADAPT; `frame.rs::{HEADER_BYTES,ALIGN_BYTES,MAX_PAYLOAD_LEN}` | Preserve 8-byte header, BUSY/DISCARD bits, length mask. Do not extract the GPL-3.0-or-later file grant (NEW-GRANT-NEEDED). |
| `K:crates/kryprobe-privilege/src/drain/frame.rs:33–51` | `4a67b72878f5d413a05b894e0cced51a4d91a62e8e76dbe94abdb372f1b068ac` | ADAPT; `frame.rs::FrameStep::{Pending,Emit,Discard,ReachedBoundary}` | Preserve Emit/Skip/Stop decision shape; variants renamed and a boundary outcome added. Live-walker revalidation ownership stays out. |
| `K:crates/kryprobe-privilege/src/drain/frame.rs:53–79` | `0d577b5ec6cbeff070d7334fa11190bec29d3d3fecb14da80591086d2218f7db` | ADAPT; `frame.rs::frame_step` | Preserve BUSY stop, discard skip, torn-tail stop, exact-fit emit, empty-payload emit. Saturating top-of-range arithmetic is NOT extracted; destination uses wrapping modular distances under capacity `< 2^63`. Over-capacity lengths become `Malformed`. |
| `K:crates/kryprobe-privilege/src/drain/frame.rs:81–152` | `f089999b7eead15b2c76bf8ed9e348767f6e9d948c26b458f5927b901dd43664` | VECTORS_ONLY; `tests/ring.rs::frame_*`, `fixtures/ring-v1/cursors.json` | Preserve emit-rounds-up/exact-fit/discard/busy/oversize/overrun/top-of-range witnesses. Saturating `u64::MAX` vectors re-expressed as wrapping-modular vectors; live-walker coupling not imported. |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:26–92` | `8c7b1f9f842cacd2d48d32fb104f0fd8c912df98a196cfd3bc9f6e84bf39ed39` | ADAPT; `frame.rs::{RingPositions,FrameStep}`, `bounded.rs::{DrainBudget,DrainResult,BoundaryState}`, `OperationError` kinds | Preserve snapshot triple, Item/Pending/Reached outcomes, InvalidBoundary/BoundaryOutOfRange/RecordCrossesBoundary taxonomy (stop crossing → `Incompatible`). Lifetime-bound `RingBufItem`, mmap/`MapData`/`AsFd` NOT extracted. |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:101–125` | `1599bdb237b7f4c879bfcfbea888bdea8d1faa3a35504d6fe713cef16d045585` | ADAPT; `bounded.rs::BoundedRingSource::snapshot`, `DrainResult.discarded` | Preserve fresh-producer snapshot and cumulative discard count. Live mmapped producer load NOT extracted (scripted sources; native adapters are BP10). |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:134–149` | `28dfa96d9be48beff04463e0c1e069a069c145127a3066f5831055f359391df8` | ADAPT; `bounded.rs::BoundedRingSource::consume_before` | Preserve fixed-stop exclusivity (`&mut self` sole reader, stop valid only for its source). Item-drop-advance NOT extracted; payloads copy out through `visit`. |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:177–180` | `24f2e3e8243803eb60b88baaf534f2475a05534e05088ed1146a16ed8aafcbb3` | ADAPT; `DrainResult.discarded` accounting | Preserve saturating discard count on consume-discarded. Discards additionally charge both drain budgets (BP06-owned). |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:223–256` | `e8cb540531a30085c78429a74ef59d251d3b54da54b72a282c0017eef25537fe` | ADAPT; `frame.rs::frame_step` stop/capacity validation | Preserve aligned cursors, power-of-two capacity, stop distance below capacity. `usize` terminal arithmetic → `u64` modular; mask→capacity derivation stays native (BP10). |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:257–308` | `9c28359f1760d7b737a479db18dd7167ae5d412e0e91ef39140d14a58547b522` | ADAPT; `frame.rs::frame_step` + drain-loop discipline | Preserve boundary-before-header precedence, BUSY→Pending, record-crosses-boundary refusal before payload access, discard accounting. mmap reads, `Item` lifetimes, Relaxed-load/Acquire-fence ordering NOT extracted (ordering is BP10). |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:369–371` | `3cb23207fb30e4ca48a1a3655da077248518a3abe3d85cfced0225727c098d48` | ADAPT; `frame.rs` aligned-total arithmetic | Preserve header-plus-8-aligned-payload advance. Native `read_record_data` mmap slicing NOT extracted. |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:544–754` | `2d0c8a790bb5a95b76a3483c087119fcba3eddff9a42ac31eb69e1489f840c25` | VECTORS_ONLY; `tests/ring.rs::drain_*` (fixed stop, producer extension, invalid stop, crossing refusal, busy-pending, zero prefix, word wrap) | Preserve bounded vector intents against scripted sources. memfd `Fixture` harness (patch 408–543), reader recreation (756–781) and unbounded consumer/item-drop tests (782–871) NOT extracted. |
| `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch:872–929` | `7a2a240fbdc02eb514fa5c7e3e5542d0b7cdcb028acba859880b37bcb9de0915` | VECTORS_ONLY; `tests/ring.rs::drain_discard_*`, `DrainResult.discarded` | Preserve consumed-discard counts on both read paths and discard-prefix advance. Item-drop mechanics NOT extracted. |
| `L:src/libbpf_mojo/buffer.mojo:14–33` | `5d8cefdecfa1c3933b5c3449db52b4cdd5524b15fa18b1e85185c5b21012a924` | ADAPT; `stage.rs::StagedRecord::copy_into` outcome | Preserve one-frame/empty/short/error outcome with used/needed sizes. Mojo `BufferPollResult` → `Result<usize, OperationError>` with required-size report. |
| `L:src/libbpf_mojo/buffer.mojo:35–43` | `fa84a225a1a14a5b65e2e1e2846e9e88c5b44da9f8a7c58c582330ce2d78e838` | ADAPT; `stage.rs::{StageStats,balanced}` | Preserve five-counter transport vocabulary and the conservation equation with checked arithmetic. Cumulative `staged` → occupancy `held` (0/1). |
| `L:src/libbpf_mojo/buffer.mojo:110–140` | `5238a41cae365bd6b87dfaa29ad5f553fffce6b105ca064f74d29c8ced442d88` | ADAPT; `stage.rs::StagedRecord::{offer,copy_into}` | Preserve short-destination retention with required-size report and `needed >= 9` zero-length rejection. Generation checks, native handle, retry/resize NOT extracted. |
| `L:src/libbpf_mojo/buffer.mojo:142–169` | `9e976c1dfc44c53470f7695be9c98a94b1ed8d64ca7fe0ae6870d5bd964cfa6a` | ADAPT; `stage.rs::StagedRecord::stats` | Preserve counter snapshot without polling. Closed-handle/generation errors and the v1 FFI struct NOT extracted. |
| `L:tests/native/ring_conformance.c:353–390` | `e28a0e4afc0c37249cdc3fd5f3616f54b2614b27c2fd367e964bf393df003ea7` | VECTORS_ONLY; `tests/ring.rs::stage_short_retained_then_delivers_once`, `fixtures/ring-v1/staging.json` short-retained-then-once | Preserve 23/23 retained across retries, 24 delivers once, sentinel-intact destination. `lmb_buffer_poll_v1`/event-count harness NOT extracted. |
| `L:tests/native/ring_conformance.c:421–446` | `a6f1f7c82375739eae05f9e12f771bc07ddf87b1f15c068d34e4d2e37fa11df6` | VECTORS_ONLY; `tests/ring.rs::stage_single_frame_per_call`, `fixtures/ring-v1/staging.json` single-frames | Preserve one frame per call (48-byte destination takes 24 + 24, sentinel tail). Session twin (394–420) NOT extracted. |
| `L:tests/native/ring_conformance.c:481–501` | `f2ffe321d55c74c087a41cd9b1e4d7561502c804d1bbfa532c3cd4a796113c41` | VECTORS_ONLY; `tests/ring.rs::stage_source_mutation_cannot_corrupt` | Preserve owned-copy-survives-source-clobber. Session twin incl. `lmb_ring_sample` direct path (451–480) NOT extracted. |
| `L:tests/native/ring_conformance.c:543–571` | `3dcbc5aba020ca06905f8076ee604c0d213e1c68079084a63ddf3cc4f89f5072` | VECTORS_ONLY; `tests/ring.rs::stage_conservation_sequence`, occupied-drop and zero/oversize vectors | Preserve short-then-occupied-drop, empty + 4097-byte malformed, third-frame delivery script. Native `ring_buffer__consume_n` driver NOT extracted. |
| `L:tests/native/ring_conformance.c:572–574` | `ea4e2cd55392cae41748a532333d357bdf5ac4eb18770a645906608ee8abaea8` | VECTORS_ONLY; `stage.rs::StageStats::balanced`, `tests/ring.rs::stage_conservation_sequence` | COVERED slice: 5 == 2 + 0 + 2 + 1 balance CHECKs. |
| `L:tests/native/ring_conformance.c:575–578` | `71e41a0b25274f1524f5b16d9d351fd9d35bee7772c04a3911a2d76ddfa821be` | VECTORS_ONLY; `tests/ring.rs::stage_conservation_sequence` tail | Preserve close/drained/puts vector tail. Trivial teardown lines, kept for function completeness. |

ADAPT retains donor mechanisms; VECTORS_ONLY retains case shape/literal
expectations without importing unselected helper implementations. In particular
the K live walker, P mmap reader/Fixture harness/item-drop mechanics and L
session adapter/native FFI/event harness are vector context only. Relaxed-load
plus Acquire-fence ordering, native adapters and live H12/H13 cells remain with
BP10/later owners per the issue doc.

## Defect, independent truth and sensitivity

| Defect/invariant | Original correspondence and delivered assertions | Independent truth and semantic control |
|---|---|---|
| A fixed-stop drain must not consume past the captured stop. | P `next_before`/`next_with_stop`/`validate_stop` map to `drain_producer_extension_keeps_stop`, `drain_invalid_stop_refuses_before_effects`, `drain_crossing_stop_is_error_with_tail_preserved`. | Scripted producer extension after snapshot; invalid/unaligned/out-of-range stops refuse before effects; crossing record errors with tail preserved. `stop-extension` mutant consumes past stop and fails. |
| BUSY/torn records stop the walk without advancing; discards skip once. | K `frame_step` + P busy/discard vectors map to `frame_busy_is_pending`, `drain_busy_is_pending_consumer_unchanged_then_commits`, `drain_discard_advances_once_and_charges_budget`. | BUSY→`Pending` with consumer untouched; discard advances once and charges both budgets. `busy-as-empty` mutant seals early and fails. |
| Short destinations retain the record; one call delivers one frame; source mutation cannot corrupt. | L `poll` short discipline + short/single/mutation buffer vectors map to `stage_short_retained_then_delivers_once`, `stage_single_frame_per_call`, `stage_source_mutation_cannot_corrupt`, `stage_framing_pins_length_and_version`. | 23/23 retained with required 24, then once-only 24 delivery; 24+24 across calls with sentinel tail; clobbered source still delivers pinned framed bytes. `short-buffer-consumes-input` mutant loses the record and fails. |
| Every received record is delivered, held, malformed or dropped. | L `BufferStats`/conservation buffer vectors map to `StageStats::balanced`, `stage_conservation_sequence`, `stage_occupied_drop_preserves_previous`, `stage_zero_and_oversize_are_malformed`. | 5 == 2 + 0 + 2 + 1 script; occupied-slot drop preserves previous bytes; empty/oversize count malformed with held preserved. `double-drop` mutant unbalances and fails. |

## Grant coverage (per slice; no grant invented)

- COVERED (1): `L:tests/native/ring_conformance.c:572–574` — admission
  `docs/provenance/admissions/2026-10-22-next-host-scopes.json`, row
  `L:tests/native/ring_conformance.c`, disposition VECTORS_ONLY, scope
  `[572,574]`, authorization `OWNER-2026-10-18`, role data-document,
  destination Apache-2.0.
- NEW-GRANT-NEEDED (22): every other slice. Missing authorization questions:
  - K slices (4): row `K:crates/kryprobe-privilege/src/drain/frame.rs` is
    `PORT_SOURCE`/`NEEDS_DECISION` with null scope/role/authorization. Is the
    user-owned host framing logic in the named ranges (as distinct from any
    upstream fragment) authorized for ADAPT/VECTORS_ONLY copying to an
    Apache-2.0 host destination, and under which authorization?
  - P slices (9): row `P:third-party/patches/aya-0.14.0/aya-ring-reader.patch`
    is `REFERENCE_ONLY`/`NEEDS_DECISION` with
    `MIXED_UPSTREAM_AND_LOCAL_PATCH_ATTRIBUTION_REVIEW_REQUIRED`. Which added
    (`+`) line ranges are user-owned patch additions (as distinct from Aya
    upstream context), what artifact role do they carry, and are they
    authorized for ADAPT/VECTORS_ONLY copying to an Apache-2.0 host
    destination, and under which authorization?
  - L `buffer.mojo` slices (4): row `L:src/libbpf_mojo/buffer.mojo` is
    `DEPENDENCY_ADAPTER`/`NEEDS_DECISION` with null scope/role/authorization.
    Are the named staging-semantics ranges authorized for ADAPT copying to an
    Apache-2.0 host destination (rather than dependency-adapter reuse), and
    under which authorization?
  - L `ring_conformance.c` slices except 572–574 (5): row
    `L:tests/native/ring_conformance.c` is VECTORS_ONLY/`READY_FOR_SELECTED_SCOPE`
    only for `[536,538],[572,574]`. Are the named short/single/mutation/
    conservation-script ranges additionally authorized as VECTORS_ONLY under
    `OWNER-2026-10-18` (or another authorization)?

## Later owners and duplicate retirement

Native Aya/libbpf adapters and ordering proofs: BP10. Live H12/H13 cells: later
owners (BP11/TT05). `!Sync` compile-fail UI control: integration owner. No
source duplicate, live/ABI/profile gate or later task is closed here.
