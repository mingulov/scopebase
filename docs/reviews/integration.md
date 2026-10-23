# RL01 cross-package API and adversarial integration review

Date: 2026-10-23. Lane branch: `lane/w28-rl01`. Plan authority: `docs/superpowers/plans/2026-10-17-scopebase.md` RL01 section.

Binding scope (alpha-mode controller decision): review accepted-only NOW; RUN the LX06 negatives (LX06 accepted, old deferral lifted); DEFER NX-only negatives with a recorded list (NX domains do not exist). Prerequisites accepted: SB03, TT02, TT06.

## Method

Inspected the public surfaces of all six workspace packages (`scopebase-linux`, `scopebase-capture`, `scopebase-testkit`, `scopebase-bpf`, `scopebase-sdk`, `scopebase-conformance`) against their accepted contracts, then wrote cross-package negative tests that bind the real packages together. New tests live in `crates/scopebase-sdk/tests/rl01_adversarial.rs` (capture+linux+bpf+sdk combined) and `crates/scopebase-linux/tests/rl01_mapping_negatives.rs` (LX06 negatives, `required-features = ["mapping"]`). No `TODO.md`/traceability edits; no lockfile change (path-only deps, offline `--locked` throughout).

## Negatives assembled (plan item 1) and run (plan item 2)

| # | Negative | Binds | Verdict |
|---|---|---|---|
| N1 | Fabricated per-CPU topology | bpf | RUN: descriptive `CpuTopology::parse_possible` accepts caller bytes but never equals `LiveCpuTopology` kernel truth; `ValidatedMap::from_owned_fd` acquires live topology internally, so no descriptive value reaches map reads. Degenerate caps refuse `LimitExceeded`. |
| N2 | Wrong-domain mapping proof | linux (LX06) | RUN: existing `mapping_contract` 20/20 plus 3 new RL01 tests — cross-pool reuse verdict-identical (pool is accounting, not authority), same-pool wrong-range refuses `WrongContext` pre-effect. |
| N3 | Returned capture record promoted to live authority | capture + sdk | RUN: `validate_v1`-only construction (private fields), SDK `capture()` borrows, clones, charges bytes, moves no admission, refuses a second slot. |
| N4 | Native error-code drift | NX | DEFERRED (D01): no native error mapping exists; NX07/NX08 planned. |
| N5 | Dropped controller with pending resources | linux + bpf + sdk | RUN: pool-clone drop keeps the shared domain usable and closable (new test); last-handle terminal retention is contract-explicit; BPF `RetirementPool::close` returns `PoolClose::Unresolved(pool)` and `Drop` leaks charged state rather than detaching without proof (bpf retirement suite rerun green); SDK observer drop-behavior covered by SDK04's 11/11 observer suite. Bridge-lifetime half (NX06) DEFERRED (D03). |

## Findings (severity + owning task each)

| ID | Severity | Owner | Finding |
|---|---|---|---|
| RL01-F01 | Low | scopebase-linux docs (LX06/LX08/LX10) | Crate docs (`src/lib.rs`) and `README.md` claimed mappings/process APIs "remain later work" and that `process`/`mapping` "do not implement their future APIs" — stale after LX06, LX08-slice and LX10 acceptance. |
| RL01-F02 | Info | LX06 | Cross-pool retained-proof reuse is allowed: `recheck_retained` binds owner/stat/epoch/birth/view/range/fs, not pool domain. Contract-consistent (pools are explicit accounting domains), now locked by test. |
| RL01-F03 | Info | BP02 | `CpuTopology` is purely descriptive; only `LiveCpuTopology::acquire` (live `/sys`+`/proc` FDs, `!Send`) feeds map reads, acquired internally by `ValidatedMap`. Fabrication cannot cross the boundary. |
| RL01-F04 | Info | CP10/SDK03 | `ValidatedNeutralV1` has private fields and one constructor; SDK snapshots are immutable, byte-charged, admission-neutral. No promotion path to authority exists. |
| RL01-F05 | Info | BP04/BP05 | Drop-with-pending semantics reviewed: `RetirementPool` leaks charged state deliberately (never detaches without proof); `AttachmentSet`/`UnresolvedAttachments` Drop only marks orphaned. Matches the LX terminal-retention philosophy. |
| RL01-F06 | Info | LX06 | Dropped pool clone while a survivor lives keeps the domain queryable/closable; terminal retention applies only at last-handle loss, with no supported reacquisition (callers retain a clone). |
| RL01-F07 | Info | cross-cutting | Three `Stage` enums and four error carriers are deliberately domain-local (plan: no universal abstraction for local issues). Hygiene verified: BPF Display omits sources (<=256 ASCII), Linux Display omits path text, `ContractError` stays variant-typed by design, `ObserverError::ForeignPid` is a fixed PID-less string. `ObserverError::Spawn` echoing OS strerror is accepted (caller's own spawn input). |
| RL01-F08 | Info | SB02/SDK01 | Feature unification verified: `--no-default-features`, `--no-default-features --features bpf`, `--features bpf`, linux `mapping,process,walk`, and workspace `--all-features` all build/pass. Review caught one real instance: the new RL01 test initially broke `--no-default-features --features bpf` (uncaged `scopebase_capture` import); fixed with `cfg(feature = "capture")` gates. |

Considered and rejected: unifying the per-package `Stage`/error types (DISPUTED — the plan forbids inventing a universal abstraction for local contracts; each carrier's bounds are tested in its own package).

Observed but NOT RL01-owned (left for owning tasks): pre-existing warnings — `scopebase-testkit` lib unused imports, `scopebase-linux` process dead code (`creator_pid_refused`, `Reaped`), `fd_probe.rs` unused `r`. No RL01 file warns.

## Dispositions (plan item 4)

- FIXED in this commit: RL01-F01 (doc-only: `crates/scopebase-linux/src/lib.rs`, `crates/scopebase-linux/README.md`; covered by package doctests + suite reruns below), RL01-F08 test-side cfg gates (covered by the `--no-default-features --features bpf` run).
- DOCUMENTED with new characterization/negative tests, no production change: RL01-F02, RL01-F03, RL01-F04, RL01-F06, N1/N3/N5 portions.
- REVIEWED, covered by rerun of owning suites, no change: RL01-F05, RL01-F07.
- DISPUTED with rationale: error-type unification (see above).
- DEFERRED with owner + reason:
  - D01 native error-code drift — owner NX07/NX08 (planned); no native mapping exists to drift against.
  - D02 native copied-record retention/ABI negatives — owner NX03/NX07 (planned).
  - D03 existing-bridge lifetime/close/release negatives — owner NX06 (planned).
  - D04 C/Mojo validation-client negatives — owner NX08 (planned).

## Evidence (all `cargo --offline --locked`)

- `cargo test -p scopebase-linux --features mapping,process,walk`: lib 96, controls 2, held_file 17, mapping_contract 20 (LX06 negatives), positional_read 7, proc_parsers 29, process_observation 17, rl01_mapping_negatives 3 (new), traits 3, walk 34, doctests 2 — 0 failed.
- `cargo test -p scopebase-sdk --features bpf`: lib 2, capture_metadata 8, conformance_binding 4, context 13, dependencies 3, diagnostic 6, isolated_contexts 2, limits 3, observer 11, profile 16, rl01_adversarial 3 (new), doctests 6 — 0 failed.
- `cargo test -p scopebase-sdk --no-default-features --features bpf --test rl01_adversarial`: 2 passed (capture case correctly cfg'd out).
- `cargo test -p scopebase-sdk --no-default-features`: 12 suites ok, 0 failed.
- `cargo test -p scopebase-bpf`: 207 passed, 15 ignored (live cells), 0 failed.
- `cargo test -p scopebase-capture --features json`: 223 passed, 0 failed.
- `cargo check --workspace --all-features`: pass (feature-unification gate).

## Remaining support limits

Accepted-only review; TT04-cell populations (Btrfs/overlay/namespace/privileged), live-kernel cells, installed/offline routes and all NX/SDK04-binary work stay with their named owners. No release claim follows.
