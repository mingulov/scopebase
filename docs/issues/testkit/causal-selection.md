# Causal selection core: affected checks, selection oracle, accounting

Status: proposed TT08 core increment (testkit core lane). Implements the causal
selector, independent selection oracle and scheduling/accounting records over
the TT01 `CaseCatalog` graph. CI workflow authoring/execution and any
`.github/**` or remote/secret handling are explicitly excluded, blocked on
owner CI-platform decision Q-TT08-1; no platform is invented here. No
PACKET_READY or execution admission follows from this core alone.

## Status and scope

Implemented, executed: `crates/scopebase-testkit/src/select/` (`manifest.rs`,
`selector.rs`, `oracle.rs`, `accounting.rs`, `mod.rs`), `tests/selection.rs`
(21 tests, all passing), additive `pub mod select;` in `src/lib.rs` and an
explicit `[[test]]` entry in the package manifest. The module is pure Rust with
no filesystem, network, CI or secret handling.

UNKNOWN — execution/scheduling integration; owner: TT08 follow-up lanes; exit
criterion: CI-platform decision Q-TT08-1 resolved and coordinator/lease design
bound to this core's records. UNKNOWN — installed-operator delivery of
selection; owner: TT07/TT08; exit criterion: run-only package route replays
these records. No donor source is ported: this is a NEW mechanism designed
from the TT08 plan section and TT-R11/TT-R12/TT-R14, not a PORT/ADAPT.

## Trigger and invariant

A dependency, feature, compiler flag, fixture/oracle or consumer change must
select every affected contract and cell; path-only filters cannot discard
required work; unknown impact broadens its declared boundary and cannot return
empty success; a retry after a semantic failure stays unresolved until an
explicit cause/fix/new-candidate resolution is recorded and a later passing
attempt evidences the resolved candidate (zero-pass histories never resolve);
`full_matrix_complete` holds only after the complete declared denominator of
a nonempty, fully resolved boundary executes, with status and scope asserted
separately. Conditional cases activate per requesting profile's own plan, so
no condition leaks across profiles through another profile's extension.

## Selected source and license

No donor bytes selected. Design inputs inspected in the worktree:
`docs/superpowers/plans/2026-10-17-scopebase-testing.md` (TT08 section),
`docs/superpowers/specs/2026-10-17-scopebase-testing-design.md` (TT-R11,
TT-R12, TT-R14), traceability row TT08, and the admitted TT01 catalog/profile
sources (`catalog.rs`, `profile.rs`, `ids.rs`). Destination code is user-owned
userspace Rust under the package's Apache-2.0 grant.

## Mechanism and destination

- `Change`/`ChangeManifest` (`select/manifest.rs`): case, cell, profile,
  extension, obligation, executable-registration-role, unknown-boundary and
  environment-attribute changes. Constructors are infallible; validation
  against the admitted catalog happens at selection time.
- `select_affected` (`select/selector.rs`): validates limits/manifest/request,
  seeds change targets, walks dependents over a reverse catalog index
  (conditional `when_extensions` entries create edges regardless of
  activation), intersects affected owners with the requested closures, and
  expands each affected owner's directly declared cases (each condition
  evaluated against the requesting profile's own plan extensions; entries
  active in no requesting profile's plan never select, so selected cells
  always stay inside the declaring profiles' denominator) into explained
  `CellKey` selections. Deterministic: sorted worklists,
  first/lowest-change-index-wins explanations, bounded paths. Out-of-scope
  affected nodes become reviewable `OutOfScopeNode` exclusions; broadenings
  become `UnresolvedImpact`. `is_full_selection` holds only for a nonempty,
  fully resolved denominator with every cell selected.
- `expected_selection`/`check_agreement` (`select/oracle.rs`): independent
  expected-set computation by forward per-owner closure intersection (never
  the reverse index), plus disagreement reports naming dropped (`missing`)
  and invented (`extra`) cells. Shared with the selector only: mechanical
  input validation, the per-requesting-profile condition rule and cell-key
  expansion; the affected-owner derivation is independent.
- `RunAccounting` (`select/accounting.rs`): executed-vs-plan records with
  explicit missing rows, unchanged gates split by inherited-evidence
  presence, unexpected executions, separate `Complete`/`Incomplete` status
  and `Full`/`Narrowed` scope, and `attest_complete` rejecting falsely
  claimed full results. Empty and unresolved boundaries never report `Full`
  and never attest complete.
- `qualification_gate` (`select/accounting.rs`): 1..=n attempt history with
  semantic failures requiring matching non-hollow resolutions plus a later
  qualifying pass bound to each resolved candidate; a resolution string with
  zero passes never resolves; infrastructure history is retained without
  blocking once a pass exists.

## Original regression

No donor regression exists for this new core. Delivered regression:
`tests/selection.rs` over an inline diamond catalog (`top-v1` depending on
`midb-v1`/`midc-v1`/`feat-v1`/`base-v1`, plus an unrequired orphan case):
transitive dependent selection, leaf scoping, conservative conditional
handling, fixture/oracle invalidation, cell-level impact, reviewable
out-of-scope exclusion, boundary broadening (named and whole-request, never
Full), environment broadening, empty-manifest honesty, explanation chains,
manifest/request validation, a 15-manifest oracle-agreement battery, a
two-profile cross-extension counterexample with independently specified
expected cells, full vs narrowed accounting, missing-row and
missing-evidence accounting, empty-denominator and unresolved populations
that never report Full or attest, and retry gate behavior including the
qualifying-pass requirement. From an unpacked package, `cargo test --offline
--test selection` runs the delivered assertions. Ordinary downstream `cargo
test` does not execute a dependency's own tests automatically.

## Independent oracle

The oracle recomputes expected sets forward (per-owner closure intersection)
while the selector walks reverse (dependent propagation); agreement is
asserted across the battery. Test expectations (exact cell sets per manifest)
are hand-derived from the fixture graph, not from implementation output; two
initial expectations were corrected during RED-phase analysis (dependents of
a broadened boundary are included; selection is request-scoped with
reviewable exclusions). Both engines read the same admitted catalog, so
independence is algorithmic, not a second implementation; validation,
condition evaluation and key expansion are shared and documented as such.

## Known-bad control and positive twin

- Dropped-dependent mutant: a narrowed plan checked against the full-change
  oracle expectation fails `check_agreement` with `missing == [cell-a,
  cell-c]` and empty `extra`; the over-selection mirror fails with the exact
  extra set. Positive twin: the 15-manifest agreement battery passes.
- Falsely-claimed-full mutant: narrowed-run accounting reports
  `full_matrix_complete == false` and `attest_complete` fails with
  `IncompleteDenominator` even with all selected cells executed; the
  oracle-starved variant (no executions) additionally reports
  `Incomplete` status with all selected cells missing. Positive twin: the
  fully executed, fully resolved, nonempty full selection attests. The
  empty-denominator (zero required cases; only-inactive conditions) and
  unresolved-broadening populations never report Full and never attest.
- Retry mutant: pass-after-semantic-failure without a resolution yields
  `Unresolved { failed_attempts: [2] }`; hollow and unmatched resolutions
  are rejected; a lone infrastructure failure and a resolution with zero
  passes likewise stay `Unresolved`. Positive twin: an explicit resolution
  plus a later pass evidencing the new candidate yields `Resolved`.
- Cross-profile mutant: under a union-extension rule the two-profile
  counterexample selects `cell-cond`, outside every profile's own
  denominator, while oracle agreement still passes. Positive twin: the
  per-profile rule selects exactly the independently specified cells and
  the oracle agrees.

## Contract references

Task TT08 (causal CI selection and safe parallel scheduling), requirements
TT-R11 (causal impact selection), TT-R12 (bounded tests/evidence),
TT-R14 (support derives from qualified profiles); T05/G19/G21 facets stay
with their named owners. This core satisfies the selector/oracle/accounting
slice only. CI workflows (`contracts`, `objects`, `linux`, `qualification`),
`select_affected.py`, `impact-v1.json`, coordinator leases and synthetic/real
CI execution remain open and platform-unbound.

## Effects bounds and cleanup

Pure computation: no threads, filesystem, network, subprocess or ambient
authority. `SelectionLimits` bounds changes, requested profiles, explanation
path steps, reason bytes and selected cells (defaults 1024/128/4096/4096
bytes/16384; nonzero, capped at defaults; no silent clamping). Evidence
labels, attempt details and resolution fields are capped at 4096 bytes;
cell ids at 65536 bytes. No retained state or cleanup obligation exists;
callers own all inputs and outputs.
