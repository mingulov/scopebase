# SDK02 bounded context, diagnostics and component bindings

Status: implemented in the M0 worktree (`crates/scopebase-sdk`), not
accepted. Covers SDK-R03/R05/R10 report metadata only: `Limits::validate`,
`AppContext::{new,profile,observe,bind,admission,diagnostic,report}`,
`ComponentBinding`, `ContextReport`, `Diagnostic`, `RetainedDiagnostic`,
`OmittedDiagnostics` and `ContextError`. Capture-metadata integration
(`AppContext::capture`), reference applications and packaging gates remain
open. No donor source is selected or copied; this is a NEW mechanism built
from the frozen SDK design.

## Trigger and invariant

An application context that grows without bounds, admits stray or replaced
observations, upgrades partial evidence into claimed support, or silently
drops diagnostics can certify readiness it never earned: an overlong
identifier truncated instead of refused, a denial replaced by a green
retry, a zero-artifact context reported Ready, or a truncated diagnostic
count that vanishes instead of being counted. The invariant is that the
context is inert and bounded metadata: declared observations only,
duplicates refused, every bound checked before any copy, over-cap
diagnostics omitted whole with an explicit saturating count, required
denials retained through the binding gate, and no verdict constructing
runtime authority.

## Selected source and license

NEW per the [SDK/native plan](../../superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk02-bounded-context-diagnostics-and-component-bindings)
and [design](../../superpowers/specs/2026-10-17-scopebase-sdk-native-design.md#sdk-interface-and-package-boundary),
traceability task SDK02. No donor bytes, no third-party (registry)
dependencies: only workspace path dependencies (`scopebase-capture` by
default, unused by this increment; `linux` and `bpf` as additive opt-ins).
Destination is user-owned Apache-2.0 userspace code (`LICENSE-APACHE`).

## Mechanism and destination

`crates/scopebase-sdk/src/limits.rs` implements `Limits::validate`, which
refuses zero fields and any `u64` count/byte value not representable as
`usize` on the build target, in field declaration order. The `u32` count
fields carry only the nonzero check (representable on every supported
target); the wait carries only the nonzero check (an observation deadline,
not a resource bound).

`crates/scopebase-sdk/src/context.rs` implements `ComponentBinding` and
`AppContext` with private fields. `observe` admits only profile-declared
ids (optional capabilities must be declared too) and refuses duplicate
ids, so a failed required observation can never be replaced with a green
retry. `bind` requires nonempty package/version within 128/64 bytes, a
present backend nonempty within 64 bytes, at most sixteen nonempty feature
names within 64 bytes arriving strictly sorted and unique, and unique
package coordinates (package, version, backend, features; digest evidence
excluded). At most 64 observations and eight bindings are stored.
Validation order is structural bounds first, then content, matching the
SDK01 constructors: a full store reports `Capacity` for unknown, duplicate
and malformed entries alike. The cumulative binding UTF-8 string payload
(package, version, backend, features) is charged against `retained_bytes`
with checked arithmetic before cloning; exceeding it refuses with
`Capacity`. Every refusal leaves the prior context unchanged.

`AppContext::admission` folds stored observations through
`Profile::admission` and then gates on exact bindings: `Refused` for a
required explicit unsupported/denied/incompatible observation, otherwise
`Incomplete` for a required missing/unknown observation, zero bindings, or
any binding without an artifact digest, otherwise `Ready`. `report`
borrows existing storage and allocates nothing.

`crates/scopebase-sdk/src/diagnostic.rs` implements bounded diagnostics.
Static codes are nonempty ASCII alphanumeric/underscore identifiers of at
most 64 bytes; invalid codes are discarded with truncation disposition and
an explicit omitted count. Retained text (verbatim UTF-8) plus escaped-path
bytes are capped at 4,096 per diagnostic and 65,536 aggregate bytes by the
host profile, with the configured count and aggregate allowance binding
first when smaller. Byte paths use deterministic C-style display escaping
(printable ASCII through, short escapes for `"`/`\`/newline/CR/tab,
lowercase `\xHH` otherwise); escaped output is printable ASCII only and no
raw captured byte survives. Escape length is measured before allocation
with early stop past the cap, so over-cap diagnostics cost bounded
scanning. Over-cap and invalid diagnostics are omitted whole -- retained
diagnostics are always complete -- and the loss increments a saturating
omitted count whose `at_least` flag turns true exactly on saturation.
Diagnostics never move admission.

`Profile::declares` is a new pure read-only membership predicate on the
accepted SDK01 profile; no accepted SDK01 behavior changes.

Interpretations pinned by tests: empty feature names are refused as
`InvalidBinding` (an empty string is not a feature name); per-diagnostic
cost is text plus escaped-path bytes combined; over-cap diagnostics are
omitted whole rather than retained truncated, so every retained diagnostic
is complete and every loss is counted.

## Original regression

No donor regression exists for this NEW mechanism. Delivered checks are
`tests/limits.rs` (per-field zero refusal, `usize` overflow tracking,
deterministic order, error rendering, bad zero control),
`tests/context.rs` (exact binding round-trip, every field/count/budget
boundary, structural-precedence pins, duplicate/undeclared refusal,
binding-gated admission table, borrow-only report, failed-operation
immutability, drop independence, bad controls), `tests/diagnostic.rs`
(per-diagnostic/aggregate/count caps before copy, exact escape table,
printable-ASCII guarantee, code validation, admission inertia, bad
controls), `tests/isolated_contexts.rs` (two-thread disjoint contexts with
independent limits/observations/bindings/diagnostics/omitted counts,
unchanged caught-signal mask and process limits, per-type Send/Sync
assertions), two `src/diagnostic.rs` unit tests (omitted saturation with
`at_least`, escape measurement agreement with early stop) and a README
SDK02 usage doctest.

## Independent oracle

`tests/context.rs` carries a separately written oracle transcribing the
capability sentence plus the binding gate with its own state/binding/
verdict types and no production admission calls.
`context_admission_matches_independent_oracle` cross-checks all 108
populations (two required capabilities, each missing or in any of five
states, crossed with zero/undigested/digested bindings).

## Known-bad control and positive twin

`bad_zero_limit_accepted_would_admit_unbounded_context` (zero refused,
nonzero accepted), `bad_silent_drop_hides_truncation` (omitted count is 1,
never 0), `bad_unescaped_path_leaks_raw_bytes` (escaped `\\x00\\xff\\n`,
never raw), `bad_zero_bindings_ready_would_certify_without_artifacts`
(Incomplete, never Ready), `bad_replaced_denial_would_hide_refusal`
(duplicate refused, Refused kept) and
`bad_undeclared_observation_would_forge_evidence` (`UnknownCapability`,
nothing stored) each fail unless the corrupted twin moves the verdict,
error or count. Five live production mutants were run and killed, each
failing its intended semantic assertion with setup intact: removed binding
gate (3 failures: gate, bad control, oracle), removed duplicate-observation
check (2 failures), bypassed path escaping (3 semantic failures),
ignored per-diagnostic text cap (1 failure) and skipped limit validation
(2 failures). Positive twins: all-required-supported with a digested
binding admits `Ready`, and the 64-observation / 8-binding / 128-64-64 /
16x64 / 4,096 / 65,536 boundaries construct or retain `Ok`.

## Contract references

Task SDK02; requirements SDK-R03 (separated resource configuration,
zero/overflow refusal before effects, wait as observation deadline),
SDK-R05 (opt-in bounded structured inert diagnostics, explicit truncation
count, safe path escaping) and SDK-R10 (independent concurrent contexts,
no hidden lock/handler/registry). Executed in the M0 worktree with Rust
1.98.1 on x86_64-unknown-linux-gnu via `cargo test --offline
-p scopebase-sdk` in both default and `--no-default-features` modes: 2
unit tests, 13 context tests, 6 diagnostic tests, 2 isolation tests, 3
limits tests, 16 unchanged profile tests, 2 dependency tests and 3 doctests
pass in each mode. No supported/qualified matrix cell is claimed.

## Effects bounds and cleanup

Constructors, validation, observation, binding, admission, diagnostics and
reporting perform no I/O, logging, threads, signal handling, process limit
changes or global state; storage is private vectors and owned display
strings within the documented caps. Admission runs in O(requirements x
observations) time plus O(bindings) digest scan with O(1) extra storage;
observation and binding checks are O(stored) scans; diagnostic measurement
stops early past the per-diagnostic cap. Dropping an `AppContext` affects
no external resource: an `Arc` strong count is unchanged and an externally
owned file keeps its exact bytes.

## Required environment and bindings

Host-only Rust tests; no BPF toolchain, fixtures, namespaces or privileges.
The isolation suite additionally snapshots this process's caught-signal
mask and resource limits from `/proc` where available (degrading to no
assertion elsewhere). Bound to the workspace `scopebase-sdk 0.1.0`
sources under test, not to an installed artifact: packaged delivery,
installed operator route and developer conformance API remain later work.

## Reference consumers and delivery

NOT_IMPLEMENTED: no independently usable consumer exists yet; the SDK04 host
observer and SDK05 starter are the planned first consumers. Ordinary
downstream `cargo test` does not execute these package tests automatically.
The `include` list ships sources and tests with the package.

## Upstream inclusion and removal test

Not applicable: no upstream issue, dependency or compiler workaround is
involved. Unknown external issue numbers: none referenced.

## Migration and duplicate retirement

No donor duplicate is retired and no product migrates on this increment.
MG work may adopt the context API only after SDK02+ acceptance and actual
reference consumers exist.
