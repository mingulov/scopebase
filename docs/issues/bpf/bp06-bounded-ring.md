# BP06: bounded ring arithmetic, reader contract and copied staging

## Donor sources (frozen 2026-10-18, inspected)

- KryProbe `kryprobe/crates/kryprobe-privilege/src/drain/frame.rs`
  (`frame_step`): 8-byte header, BUSY stop, discard skip, torn-tail stop,
  exact-fit emit, top-of-range handling.
- p11scope `third-party/patches/aya-0.14.0/aya-ring-reader.patch`
  (`snapshot_positions`/`next_before`): aligned stop validation,
  power-of-two capacity, stop distance below capacity,
  record-crosses-boundary refusal, discard accounting, Relaxed-load plus
  Acquire-fence publication discipline (ordering belongs to BP10 adapters).
- libbpf-mojo `src/libbpf_mojo/buffer.mojo`
  (`BufferStats { received, delivered, staged, malformed, dropped }`) and
  `tests/native/ring_conformance.c` short/single/mutation vectors:
  short-destination retention across retries, one frame per call,
  source-mutation immunity, exact framed bytes.

## Delivered shape

- `frame_step`: capacity `8 <= pow2 < 2^63`, 8-aligned cursors, modular
  stop distance below capacity, available distance at most capacity,
  boundary-before-header precedence, BUSY/torn-tail `Pending`, reserved
  length bits and over-capacity lengths `Malformed`, stop crossing
  `Incompatible`, wrapping successor. Empty frame payloads emit at this
  layer (KryProbe); the staging layer rejects zero-length records
  (libbpf-mojo `needed >= 9`).
- `BoundedRingSource::{snapshot, consume_before}` plus
  `DrainBudget`/`DrainResult`/`BoundaryState`: fixed-stop drains with
  record+byte budgets, discards charged to both, no `Quiescent`/`Settled`
  outcomes. Non-cloneable, exclusive `&mut self`.
- `StagedRecord`: one owned slot, little-endian length plus pinned
  framing version envelope, `received = delivered + held + malformed +
  dropped` with checked counters (`held` is occupancy 0/1), short-copy
  retention with required-size report, occupied-slot drop preserving the
  previous bytes, `!Sync` sole-owner construction.
- No new raw mmap reader: `src/ring` performs no mapping or syscalls
  (verified by inspection; `mmap`/`MapData` absent from the module).

## Zero/overflow admissions (BP06-owned)

- `StagedRecord::new(0)` refuses (`LimitExceeded`); zero record/byte
  budgets exhaust without consuming; zero/invalid capacities refuse.
- Reserved length bits refuse before any arithmetic; `2^63+` capacities
  refuse; u32-unrepresentable payloads refuse; byte-budget addition is
  checked; u64 counters use checked increments with explicit `Overflow`.

## Mutants killed (bad controls)

- `busy-as-empty`: BUSY-as-`ReachedBoundary` seals early; oracle demands
  `Pending` with the consumer untouched.
- `stop-extension`: draining to the live producer consumes past the
  captured stop; valid twin reaches exactly at the stop.
- `double-drop`: delivered counted twice unbalances conservation; valid
  twin balances.
- `short-buffer-consumes-input`: clearing the slot on short loses the
  record; valid twin retains and delivers.

## Verification

- `cargo test --offline -p scopebase-bpf --test ring`: 37 passed
  (RED observed on `todo!()` skeleton: 32 failed, 5 lib-independent passed).
- Fixtures `crates/scopebase-bpf/fixtures/ring-v1/cursors.json` (34 frame
  vectors) and `staging.json` (framed-byte and stats vectors); scripted
  source drains (budgets N/N+1, EINTR tail preservation and resume,
  producer extension, invalid stop); seeded 500-script determinism sweep.

## Deferred (NOT_RUN / later owners)

- Native Aya/libbpf adapters and ordering proofs: BP10.
- Live H12/H13 cells: later owners (BP11/TT05).
- `!Sync` compile-fail UI control for `StagedRecord`: integration owner
  alongside the existing UI suite (negative bounds are not runtime
  assertable).
