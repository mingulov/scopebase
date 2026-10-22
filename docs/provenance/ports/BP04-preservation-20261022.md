# BP04 preservation map

Candidate host implementation for the neutral pure attachment planner described in
[bp04-neutral-planner.md](../../issues/bpf/bp04-neutral-planner.md). This is a
source/defect map, not acceptance or a test-result ledger. No selected-port receipt
exists yet; every slice below is NEW-GRANT-NEEDED (see Grant coverage).

Only frozen p11scope `2c2713e66292b0d2688508a25f79e813ae823d81`
(`.worktrees/v040-integration`) and frozen OSSLscope product root
`1a481831a85375ecb2d69ca65618d37c846de8b3` (`checkout/osslscope`) are selected,
16 inclusive line slices in total (285 P lines + 114 O lines). All slice hashes were
checked against the gitless private capture under
`.scopebase/donor-snapshots/2026-10-18/`; no live donor or implicit Git lookup was
used. Extraction: `sed -n '<first>,<last>p' <frozen-path> | sha256sum` (inclusive
lines, stored newlines). Historical GPL-3.0-or-later observations and OWNER
authorization are preserved separately; destination host/test/data terms would be
Apache-2.0. No third-party, target/BPF/shared-source or whole-file grant is inferred.
Earlier BP02/BP03/CP05/LX08 grants/receipts and production bytes remain unchanged.

## H21 anchor resolution

- H21 P anchor `crates/bpf-multi/src/lib.rs:268,398,408` is VALID against the frozen
  v040-integration file: `attach_group` at 268, `bisect_attach` at 398,
  `bisect_attach_counted` at 408 (same lines in the frozen main checkout; no p11
  frozen file places bisection at 561-611).
- H21 O anchor `src/plan.rs:675-707` is LINE-STALE against the frozen OSSL product
  root `checkout/osslscope/src/plan.rs` (1101 lines), where 675-707 holds unrelated
  test code (`plan_entries_aliases_groups` tail, `elf_cache_parses_once_per_identity`
  head). Corrected range **561-611** covers `attach_group` + `is_permission_err` +
  salvage docs + `TryAttach` + `bisect_attach` in that exact file.
- The admitted O pin `4bcb24ce` (preview-r21 worktree, 1198 lines) carries the same
  salvage core shifted +97 lines (670-708), byte-identical to checkout-001 573-611
  (verified by diff). Per [adoption-decisions](../adoption-decisions.md), "O's preview
  worktree remains distinct from its product root", so the pin divergence is a real
  grant gap either way (see Q-O-MECH/Q-O-VEC).

Frozen whole-file bytes: P lib.rs
`9f0bd281729c37fec8a3299121707c4c02f23a6c367015dc140e6618dcf5aa8a` (matches the
admitted observation); O checkout-001 plan.rs
`9654ef0923168b966e05b2b5cf8d5414e1238115592134f35c5428124cc446d8` (admitted
nowhere); O preview-r21 plan.rs `18132719...3a26299` (matches the admitted
observation, bisection ranges ungranted there too).

| Frozen source scope | Exact slice SHA256 | Origin and destination symbols | Preserved difference or limit |
|---|---|---|---|
| `P:crates/bpf-multi/src/lib.rs:285–308` | `e41fbf80f0be0c83be1d93901bf888734e4a1b2b9d658540b3fc813775a526a4` | ADAPT; `plan.rs::{is_terminal_error,adjudicate_split}`, `tests/attach.rs::{is_terminal_error_pins_kinds,backend_errno_is_not_terminal,terminal_denied_cannot_split_even_if_policy_requests,terminal_resource_cannot_split}` from `is_permission_err`/`is_exhaustion_err`/`is_unsupported_kernel_errno` | Preserve the three stop classes (permission fail-fast, EMFILE exhaustion halt, ENOTSUP/EOPNOTSUPP unsupported halt). Do not extract errno classifiers: destination decides by `ErrorKind` only, and a `Backend` EPERM/EACCES (verifier/license, H33) is policy-decided, never terminal. |
| `P:crates/bpf-multi/src/lib.rs:310–319` | `b8feae626a7e63f3091669a471983acbb927c3ae250b552b748b20224dae9382` | ADAPT; `plan.rs::is_terminal_error`, `tests/attach.rs::{terminal_denied_cannot_split_even_if_policy_requests,terminal_resource_cannot_split}` from `GroupHalt::{Unsupported,Exhausted}` | Preserve Unsupported-versus-Exhausted as distinct terminal kinds (`LimitExceeded`/`Overflow` vs `Denied`). `Display`/`Error` impls (321-336) are not extracted. |
| `P:crates/bpf-multi/src/lib.rs:338–348` | `cbb220e826b55ac6c54eb89eff9511b0e8804f0cde333767399a8c109b698e97` | ADAPT; `plan.rs::{adjudicate_split,ErrorAction::AbortAndRollback}`, `tests/attach.rs::first_profile_rolls_back` from `BisectHalt{halt,closed_leaves}` | Preserve halt-with-accounting: a halt after linked leaves closes and counts them; the first profile rolls back every success when any leaf is refused. `Display` impl (350-362) and the synchronous drop itself are not extracted; BP05 owns effectful retirement. |
| `P:crates/bpf-multi/src/lib.rs:364–382` | `422e627f3febcea56846471bda8cd6b8b60b8a254b21f9d118f070a00547ec88` | ADAPT; `tests/attach.rs::{model_mixed_bad_leaves,model_every_terminal_position,model_exhaustive_bad_subsets}` from `RefusedSite{index,error}`/`split_error` | Preserve per-index refusal with the refusing error (singleton keeps its own error; fail-fast slices share one error value per index) and refused leaves reported while the walk continues. `io::Error` round-trip mechanics are not extracted; destination carries `OperationError`. |
| `P:crates/bpf-multi/src/lib.rs:384–403` | `3d8188f861f7e4785032881a51ce995c4d6ed6bf143b7ef26169573163cfc41e` | ADAPT; `plan.rs::AttachPlan::checked`, `tests/attach.rs::checked_reserves_worst_case_attempts` from the `<= 2n-1` discipline docs/`TryAttach`/`bisect_attach` | Preserve the bounded-attempt contract (`<= 2n-1`, log-n depth) and generic-over-handle isolation. Destination reserves worst-case attempts with checked arithmetic at admission; native `attach_group` leaf (264-283) is never called. |
| `P:crates/bpf-multi/src/lib.rs:405–465` | `4d809f26f61542c207e17e7d4661c4580eadee90e7b8b3b1720bb8c9be0f9a8d` | ADAPT; `plan.rs::{AttachPlan::split_sites,adjudicate_split,ErrorPolicy,ErrorAction}`, `tests/attach.rs::{split_halves_even,split_halves_odd,split_cover_is_disjoint_and_exact,model_full_split_matches_fixture}`, `fixtures/attach-v1/split-trees.json` from `bisect_attach_counted` | Preserve one attempt per node, midpoint LIFO walk order, split-only-multi-nonterminal discipline and index-sorted refusals. Donor errno dispatch becomes caller `ErrorPolicy` votes plus library-terminal override; backend/link effects stay in BP05. |
| `P:crates/bpf-multi/src/lib.rs:872–895` | `6dc020621ccb4a7059a4577d459d1b5931b64f0c10587a69e1a2e20783ea411a` | VECTORS_ONLY; `tests/attach.rs::{model_all_success_single_attempt,checked_accepts_distinct_sites}` from `bisect_all_good_attaches_once`/`bisect_empty_sites_is_a_vacuous_success` | Retain single-attempt all-good and vacuous-empty vectors. Donor `(offset,cookie)` tuples become coupled `Site` records; destination additionally refuses empty batches at `checked`. |
| `P:crates/bpf-multi/src/lib.rs:897–925` | `f1d09981e34f65c67b0ae231308c8a73d4a438273c4fe2d3ea7e3911b8e118c8` | VECTORS_ONLY; `tests/attach.rs::{model_mixed_bad_leaves,model_exhaustive_bad_subsets,model_bounded_sweep_seeded,mutant_unbounded_singleton_retry_violates_bound}`, `fixtures/attach-v1/split-trees.json` from `bisect_isolates_one_poison_offset_with_bounded_attempts` | Retain poison-isolation shape with `calls < 2n` bound and full good-sibling coverage. Exact visit order is pinned in `split-trees.json` (n=1..8); the `unbounded-singleton-retry` mutant (15 attempts at n=4) must fail the bound assertion. |
| `P:crates/bpf-multi/src/lib.rs:927–948` | `1b98a1b4c6f52dbb953fbd9efb94283b547518378c3a5d0ba5b04229b68648b0` | VECTORS_ONLY; `tests/attach.rs::{terminal_denied_cannot_split_even_if_policy_requests,mutant_split_on_terminal_denial_over_attempts}` from `bisect_permission_fails_fast_without_splitting` | Retain one-attempt whole-slice condemnation on permission failure. The `split-on-denial` mutant (7 nodes vs 1) must fail the call-count assertion. |
| `P:crates/bpf-multi/src/lib.rs:950–978` | `bf1c447e199334bc4cfa8cd868a52584b9249025fa0c61863bcb1691c519a419` | VECTORS_ONLY; `tests/attach.rs::{terminal_resource_cannot_split,is_terminal_error_pins_kinds}` from `bisect_exhaustion_and_unsupported_halt_instead_of_refusing` | Retain halt-instead-of-refusal for EMFILE/ENOTSUP with exact stop-after-one-attempt. Donor `GroupHalt` display strings are not asserted; kind mapping is. |
| `P:crates/bpf-multi/src/lib.rs:980–1014` | `06a267a38eee704927b8a81cff87c801db84a01e713753fb75ccaa1c5412d927` | VECTORS_ONLY; `tests/attach.rs::{first_profile_rolls_back,model_every_terminal_position}` from `a_halt_after_a_linked_leaf_closes_and_counts_that_leaf` | Retain halt-after-linked-leaf accounting (`closed_leaves == 1`, live count returns to 0). Drop-based closing is donor-native context only; destination first profile rolls back instead of leaking custody. |
| `O:src/plan.rs:561–611` | `9310b841505cb28cf4e8e5eee08f03ca0bfde11619f3113962f31e0cafb697c6` | ADAPT; `plan.rs::{ErrorPolicy,ErrorAction::IsolateSites,adjudicate_split,AttachPlan::split_sites}`, `tests/attach.rs::{policy_vote_honored_for_isolatable_errors,policy_is_consulted_before_terminal_override}` from `bisect_attach`/`is_permission_err` | Preserve the salvage discipline: split every non-permission failure (EINVAL, unknown/RHEL-524 errnos) so one poison offset cannot sink good siblings; permission errors fail the slice without splitting. Native `attach_group` leaf (561-571) is context only, never ported or called. |
| `O:src/plan.rs:773–790` | `18fff503787d6e0e3b033b0f17d9739c58fbdabad038829879fbd26166768ee9` | VECTORS_ONLY; `tests/attach.rs::drive_model` from `poisoned_with`/`poisoned` | Retain poison-stub shape (errno iff slice holds a poison offset). Destination models carry `OperationError` kinds rather than raw errnos. |
| `O:src/plan.rs:792–811` | `65f331d4cc810b235fdb5496ce8c42ab6a2c32b17e6fcb686fede14fd1ad2c1b` | VECTORS_ONLY; `tests/attach.rs::{model_mixed_bad_leaves,model_exhaustive_bad_subsets,model_offset_cookie_pairs_exact}`, `fixtures/attach-v1/split-trees.json` from `bisect_isolates_poison`/`bisect_isolates_nonstandard_errno` | Retain two-poison isolation (`bad == [3,6]`, 4 links) and the RHEL-524 unknown-errno-must-bisect vector. Offset/cookie coupling is pinned by `model_offset_cookie_pairs_exact` against the `parallel-offset-cookie-swap` mutant. |
| `O:src/plan.rs:813–827` | `9fd59e223c69e7199a197c98e704b1173138467777def23b48e8b33b2be6336b` | VECTORS_ONLY; `tests/attach.rs::{terminal_denied_cannot_split_even_if_policy_requests,mutant_split_on_terminal_denial_over_attempts}` from `bisect_fails_fast_on_permission_err` | Retain systemic-EPERM vector: one attempt, whole slice condemned, no retry storm. |
| `O:src/plan.rs:864–873` | `a9e358ffe47551cfff235a8182fa5570c4bba52465331852939c720674ed43bc` | VECTORS_ONLY; `tests/attach.rs::{singleton_cannot_split,model_every_terminal_position}` from `bisect_non_einval_fails_slice` | Retain non-EINVAL permission slice-failure vector. Singleton splitting refusal is separately pinned by `split_singleton_returns_none`. |

ADAPT retains donor mechanisms re-expressed on kind-based carriers; VECTORS_ONLY
retains case shape/literal expectations without importing helper implementations.
Inspected but NOT selected: P native `attach_group` (264-283), link-create
syscall/attr code (246-262), `Display`/`Error` impls (321-336, 350-362), counting
probe, maps helpers and pid-filter/native tests (591-605 and 1179-1192 belong to
granted BP03 scope, not this map); O `attach_group` body as anything but context,
plan/group/cookie machinery (537-559), ELF/mapping/test scaffolding and all other
tests. The `AttachBackend`/`NativeAttach`/`NativeRetire`/`CustodyCharge` contracts
are separately specified NEW code for the BP05 executor, not a donor port.

## Grant coverage

Checked 2026-10-22 against all ten `admissions/*.json` and
[adoption-decisions](../adoption-decisions.md). Result: **0 of 16 slices COVERED,
16 NEW-GRANT-NEEDED.** No grant is invented.

- Disposition (not a grant): adoption-decisions.md records "P/O attachment planning
  and retirement" as `PORT_SOURCE` plus selected backend adapters for BP03–BP05,
  and the `attachment-owner-retirement` port group (owner BP03, tasks BP03/BP04/BP05,
  refs H21) names the bisect regressions as
  `selected_regressions_to_port_or_adapt` with
  `OBLIGATION_RECORDED_NOT_IMPLEMENTED_NOT_RUN` status. Per the ledger, "No
  whole-file or future-range grant follows from a selected range."
- P: maximum granted scope anywhere for `P:crates/bpf-multi/src/lib.rs` @2c2713e6
  is `[[591,605],[1179,1192]]` under `OWNER-2026-10-18`
  (`2026-10-22-next-host-scopes.json`, `2026-10-22-cp06-scopes.json`) — the BP03
  slices only. All eleven BP04 P ranges lie outside it.
- O: every admission pins `O:src/plan.rs` @4bcb24ce (preview worktree) with
  held-file scopes only (`[205,240],[287,292],[334,417],[1123,1141]`); no admission
  mentions pin 1a481831 (product root) at all, and the bisection ranges are outside
  the granted scopes at either pin.

Exact missing authorization questions:

- Q-P-MECH (P slices 285-308, 310-319, 338-348, 364-382, 384-403, 405-465): does the
  owner authorize PORT_SOURCE of these six finite-bisection mechanism ranges at
  P:crates/bpf-multi/src/lib.rs @2c2713e6 as host Apache-2.0 ADAPT for BP04 under
  attachment-owner-retirement?
- Q-P-VEC (P slices 872-895, 897-925, 927-948, 950-978, 980-1014): does the owner
  authorize PORT_SOURCE of these five bisect regression ranges at the same pin as
  host Apache-2.0 VECTORS_ONLY for BP04?
- Q-O-MECH (O slice 561-611): does the owner (a) admit O:src/plan.rs @1a481831
  (product root, whole-file `9654ef09...`) and authorize PORT_SOURCE of range
  561-611 as host Apache-2.0 ADAPT for BP04 — or (b) require selecting the
  byte-identical preview-r21 range 658-708 @4bcb24ce under a scope extension instead?
- Q-O-VEC (O slices 773-790, 792-811, 813-827, 864-873): same pin question for these
  four bisect regression ranges as host Apache-2.0 VECTORS_ONLY for BP04.

## Defect, independent truth and sensitivity

| Defect/invariant | Original correspondence and delivered assertions | Independent truth and semantic control |
|---|---|---|
| Isolation is bounded (`<= 2n-1` attempts, log-n depth) with deterministic midpoint order and coupled offset/cookie records. | P docs/walk plus P poison/O salvage tests map to `checked_reserves_worst_case_attempts`, `split_*`, `model_full_split_matches_fixture`, `model_exhaustive_bad_subsets` (510 walks), `model_bounded_sweep_seeded` and `split-trees.json` (n=1..8). | Fixture pins the full LIFO visit order independently of the walk model; lib-vs-fixture and internal-consistency checks both run. `unbounded-singleton-retry` and `parallel-offset-cookie-swap` mutants fail named assertions; restored twins pass. |
| Terminal failures never split: permission aborts the slice, exhaustion/unsupported abort the run, verifier/license refusal stays policy-decided. | P classifier/halt plus P permission/halt tests and O fail-fast tests map to `is_terminal_error_pins_kinds`, `terminal_*`, `backend_errno_is_not_terminal`, `policy_is_consulted_before_terminal_override`, `singleton_cannot_split`. | Kind-based only: a `Backend` error carrying EACCES must not become terminal. The `split-on-denial` mutant (7 nodes vs 1) fails the call-count assertion; restored twin passes. |
| Refused leaves are reported while the walk continues; the first profile rolls back every success when any leaf is refused. | P `RefusedSite`/halt-accounting plus halt-after-leaf vectors map to `model_mixed_bad_leaves`, `model_every_terminal_position`, `first_profile_rolls_back`. | Pre-authored site/error trees enumerate refused indices and attempt counts; refused-index multisets are asserted exactly, not merely non-empty. |

## Later owners and duplicate retirement

All model/fixture evidence is T0/T1 host qualification. The BP05 pool executor
(`AttachBackend` consumers), live attach cells, effectful policy-panic and
uncertain-native tests, the Proptest gate (blocked on shared root-lock ownership)
and product migration remain open under their existing owners. No source duplicate,
live/ABI/profile gate or later task is closed here.
