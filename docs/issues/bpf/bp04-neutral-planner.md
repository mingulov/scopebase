# BP04: neutral pure attachment planner

## Donor sources (frozen 2026-10-18, inspected)

- p11scope `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
  `bisect_attach_counted`: bounded `<= 2n-1` attempts at log-n depth,
  permission fail-fast per slice, halt on exhaustion (`EMFILE`) and
  unsupported kernels (`ENOTSUP`/`EOPNOTSUPP`) with closed-leaf accounting.
- OSSLscope `osslscope/src/plan.rs` `bisect_attach`: salvage discipline --
  split every non-permission failure so one poison offset cannot sink good
  siblings; permission errors fail the slice.

Catalog anchor `src/plan.rs:675-707` is line-stale against the frozen copy
(both the `p11scope` and `v040-integration` checkouts place unrelated
plan-summary records at `561-611` and `675-707`); the live bisection
sources above were inspected instead.

## Preserved difference

| Failure class | OSSLscope | p11scope | Neutral planner |
|---|---|---|---|
| Poison/unknown errno | split (salvage) | split | caller `ErrorPolicy` vote |
| Permission | fail slice, continue | fail slice, continue | `Denied` kind: library-terminal, abort |
| Exhaustion/unsupported | (bisects) | halt run | `LimitExceeded`/`Overflow` kinds: library-terminal, abort |
| Verifier/license refusal | n/a | n/a | `Backend` kind incl. EPERM/EACCES errno: policy-decided, never auto-terminal (H33) |

Kind-based only, never errno-based: the `OperationError` carrier forbids
errno classifiers, and a `Backend` error with EACCES must not become a
permission terminal.

## Decision model (pinned in `adjudicate_split`)

Attempt each node once; split only side-effect-free isolatable multi
nodes; singleton refusal and terminal errors abort splitting. Refused
leaves are reported while the walk continues (donor bisect collects all
bad leaves); the first profile (all sites required) rolls back every
successful node when any leaf is refused. `AttachPlan::checked` reserves
worst-case `2n-1` attempts against `limits.work_steps` with checked
arithmetic and refuses duplicate offsets/cookies.

## Mutants killed (bad controls)

- `unbounded-singleton-retry`: retrying singletons needs 15 attempts at
  n=4, violating the `2n-1` bound the oracle enforces.
- `parallel-offset-cookie-swap`: rotated cookie vector diverges from the
  coupled site records the grouping assertion pins.
- `split-on-denial`: splitting a `Denied` root walks 7 nodes where the
  valid twin aborts after 1; call-count assertion discriminates.

## Verification

- `cargo test --offline -p scopebase-bpf --test attach`: 35 passed
  (RED observed on `todo!()` skeleton: 33 failed, 2 lib-independent passed).
- Fixture `crates/scopebase-bpf/fixtures/attach-v1/split-trees.json` pins
  the full bisection visit order for n=1..8; internal consistency plus
  lib-vs-fixture walks; exhaustive bad-leaf subsets (510 walks) and a
  seeded 2000-walk bounded sweep.

## Deferred (NOT_RUN / later owners)

- Effectful policy-panic and uncertain-native tests: BP05 pool executor.
- Live attach cells: later owners.
- Proptest trees: this lane cannot add the dev-dependency without touching
  the shared root lock (owned by the integration owner); the seeded sweep
  above stands in, and the integration owner runs the Proptest gate.
