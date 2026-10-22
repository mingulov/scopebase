# SDK01 explicit profile and effects admission

Status: implemented in the M0 worktree (`crates/scopebase-sdk`), not
accepted. Covers SDK-R01/R02/R12 report metadata only: `Profile::new`,
`CapabilityState`, `CapabilityObservation`, `Admission` and the
Ready/Incomplete/Refused table. SDK02 bounded context/diagnostics/bindings,
capture integration, reference applications and packaging gates remain open.
No donor source is selected or copied; this is a NEW mechanism built from the
frozen SDK design.

## Trigger and invariant

An application that probes environments before declaring prerequisites can
silently upgrade partial evidence into claimed support: an `Unknown`
capability read as success, a dropped denial, an overlong identifier
truncated instead of refused, or a stray report minted into authority. The
invariant is that admission is a pure, bounded fold over declared
prerequisites: required `Unsupported`/`Denied`/`Incompatible` refuses,
required missing/`Unknown` stays incomplete, anything else is ready, optional
failures stay visible without refusing, and no verdict constructs runtime
authority.

## Selected source and license

NEW per the [SDK/native plan](../../superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk01-explicit-profile-capability-and-effects-admission)
and [design](../../superpowers/specs/2026-10-17-scopebase-sdk-native-design.md#sdk-interface-and-package-boundary),
traceability task SDK01. No donor bytes, no third-party (registry)
dependencies: only workspace path dependencies (`scopebase-capture` by
default; `linux` and `bpf` as additive opt-ins). Destination is user-owned
Apache-2.0 userspace code (`LICENSE-APACHE`).

## Mechanism and destination

`crates/scopebase-sdk/src/profile.rs` implements the specified constructors
with private `Profile` fields. Structural bounds check before content:
nonempty ids of at most 64 bytes, at most 64 requirements, at most five
effects, then duplicate requirement ids (`DuplicateId`) and duplicate effects
(`DuplicateEffect`). `permits` gates declared effects only. `admission` folds
every observation for a declared required id, ignores undeclared ids and
allocates nothing. Errors are static `Display`/`Error` variants without
identifier payloads and never log. Binding-gated admission (zero bindings or
a digest-less binding refusing Ready) is explicitly deferred to SDK02
`AppContext`, which owns a separate admission function.

## Original regression

No donor regression exists for this NEW mechanism. Delivered checks are
`tests/profile.rs` (constructor caps at 64/65, 64-byte id boundary, exact
five-effect boundary, all five states, refusal outranking incompleteness,
optional visibility, undeclared-id handling, duplicate folding toward
refusal), `tests/dependencies.rs` (default `cargo tree` contains
`scopebase-capture`; `--no-default-features` tree is dependency-free; a
banned BPF/native/Mojo substring scan over package names runs in both modes)
and two README doctests (usage plus a `compile_fail` no-authority case).

## Independent oracle

`tests/profile.rs` carries a separately written oracle transcribing the
admission sentence with its own state/verdict types and no production calls.
`admission_matches_independent_oracle` cross-checks all 216 populations (two
required plus one optional capability, each missing or in any of five
states), each carrying one stray denial to pin that stray reports never move
the verdict.

## Known-bad control and positive twin

`bad_unknown_upgraded_to_supported_changes_verdict` (Incomplete versus Ready),
`bad_dropped_required_denial_changes_verdict` (Refused versus Incomplete),
`bad_optional_denial_promoted_to_refusal_is_wrong` (Ready, never Refused) and
`bad_removed_constructor_checks_stay_refused` (exact `DuplicateId`/`InvalidId`/
`Capacity` errors) each fail unless the corrupted twin moves the verdict or
keeps its refusal. Positive twins: all-required-supported admits `Ready`, and
the 64-requirement / 64-byte-id / five-effect boundaries construct `Ok`.

## Contract references

Task SDK01; requirements SDK-R01 (default host build with no BPF/native/Mojo
build input; default dependency is the pure `scopebase-capture` API),
SDK-R02 (explicit declaration before probing; distinct failure states; no
authority from reports) and SDK-R12 (packaged profile contract). Executed in
the M0 worktree with Rust 1.98.1 on x86_64-unknown-linux-gnu via
`cargo test --offline -p scopebase-sdk` with both default and
`--no-default-features` modes: 16 profile tests, two dependency tests and
two doctests pass in each mode. No supported/qualified matrix cell is
claimed.

## Effects bounds and cleanup

Constructors and admission perform no I/O, allocation beyond the validated
input vectors, logging, threads, signal handling or global state. Admission
runs in O(requirements x observations) time with O(1) extra storage. There is
nothing to clean up: dropping a `Profile` or verdict affects no external
resource.

## Required environment and bindings

Host-only Rust tests; no BPF toolchain, fixtures, namespaces or privileges.
Bound to the workspace `scopebase-sdk 0.1.0` sources under test, not to an
installed artifact: packaged delivery, installed operator route and
developer conformance API remain later work.

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
MG work may adopt the profile API only after SDK02+ acceptance and actual
reference consumers exist.
