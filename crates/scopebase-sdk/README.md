# scopebase-sdk

ScopeBase explicit application profiles (SDK01) and bounded application
contexts (SDK02): prerequisite capabilities, admitted effects, the
Ready/Incomplete/Refused admission table, explicit limits, exact component
bindings and bounded diagnostics. This is report metadata only; it carries
no executable authority and probes no environments.

```rust
use scopebase_sdk::profile::{
    Admission, CapabilityObservation, CapabilityRequirement, CapabilityState,
    Effect, Profile,
};

let profile = Profile::new(
    "file-observer",
    vec![CapabilityRequirement { id: "owned-files", required: true }],
    vec![Effect::ReadOwnedFiles],
).unwrap();
assert!(profile.permits(Effect::ReadOwnedFiles));
assert!(!profile.permits(Effect::LoadBpf));

let verdict = profile.admission(&[CapabilityObservation {
    id: "owned-files",
    state: CapabilityState::Supported,
    source: "fixture-ledger",
}]);
assert_eq!(verdict, Admission::Ready);
```

Constructor bounds are exact: profile and requirement ids are nonempty and at
most 64 bytes, at most 64 requirements, at most five effects, no duplicate
requirement ids and no duplicate effect entries. Structural capacity is
checked before content, so an overlong entry list reports `Capacity` even
when it also repeats an entry.

Admission folds one verdict per required capability. A required `Unsupported`,
`Denied` or `Incompatible` observation refuses; otherwise a required missing
or `Unknown` observation leaves the profile incomplete; otherwise the profile
is ready. Optional observations never move the verdict and stay in the
caller's report input, and observations for undeclared ids are ignored. Every
observation for a declared required id folds, so a denial is never masked by
a sibling `Supported` report.

An admission verdict describes declared prerequisites. It cannot mint an
attach handle, mapping proof, process capability or close receipt, and the
crate exposes no such route:

```compile_fail
use scopebase_sdk::profile::{
    Admission, CapabilityObservation, CapabilityRequirement, CapabilityState,
    Profile,
};
let profile = Profile::new(
    "demo",
    vec![CapabilityRequirement { id: "file", required: true }],
    vec![],
).unwrap();
let verdict = profile.admission(&[CapabilityObservation {
    id: "file",
    state: CapabilityState::Supported,
    source: "demo",
}]);
assert_eq!(verdict, Admission::Ready);
// There is no route from a metadata verdict to a live handle.
let _handle = verdict.into_held_file();
```

The crate has zero dependencies: pure standard library, no build script, no
BPF/native/Mojo tool invocation and no privilege changes. `tests/profile.rs`
pins every cap, the five-state table, a 216-population independent oracle
cross-check and bad controls; `tests/dependencies.rs` re-verifies the
dependency tree through `cargo tree`. Binding completeness (zero bindings or
a binding without an artifact digest refusing Ready) belongs to the SDK02
application context below, not to profile-level admission.

## Bounded application context (SDK02)

`AppContext` owns inert, bounded metadata for one application: its profile,
limits, declared capability observations, exact component bindings and
retained diagnostics. Actual component owners stay outside with their
callers, and dropping a context touches no external resource.

```rust
use scopebase_sdk::context::{AppContext, ComponentBinding};
use scopebase_sdk::diagnostic::{
    Diagnostic, DiagnosticDisposition, EffectState, Severity, Stage,
};
use scopebase_sdk::limits::Limits;
use scopebase_sdk::profile::{
    Admission, CapabilityObservation, CapabilityRequirement, CapabilityState,
    Profile,
};
use std::time::Duration;

let profile = Profile::new(
    "file-observer",
    vec![CapabilityRequirement { id: "owned-files", required: true }],
    vec![],
).unwrap();
let limits = Limits {
    input_bytes: 65_536,
    retained_bytes: 8_192,
    work_items: 64,
    live_owners: 8,
    diagnostic_count: 32,
    diagnostic_bytes: 65_536,
    wait: Duration::from_secs(2),
};
let mut context = AppContext::new(profile, limits).unwrap();
context.observe(CapabilityObservation {
    id: "owned-files",
    state: CapabilityState::Supported,
    source: "fixture-ledger",
}).unwrap();
context.bind(ComponentBinding {
    package: "scopebase-capture".to_owned(),
    version: "0.1.0".to_owned(),
    features: Vec::new(),
    backend: None,
    artifact_sha256: Some([0x42; 32]),
}).unwrap();
assert_eq!(
    context.diagnostic(Diagnostic {
        code: "OBSERVED",
        severity: Severity::Note,
        stage: Stage::Observation,
        effect: EffectState::None,
        text: "observed held file",
        path: None,
    }),
    DiagnosticDisposition::Retained
);
assert_eq!(context.admission(), Admission::Ready);
assert_eq!(context.report().omitted.count, 0);
```

Exact bounds: `Limits::validate` refuses zero fields and `u64` values that
do not fit `usize`; at most 64 observations and eight bindings per context;
binding package/version/backend bounded to 128/64/64 bytes with at most
sixteen sorted unique feature names of 64 bytes; binding string payload
charged against `retained_bytes` before cloning; diagnostics capped at
4,096 display bytes each and 65,536 aggregate bytes, with a saturating
omitted count and `at_least` flag. Observations for undeclared ids are
refused, duplicate observations and bindings are errors, and failed
operations leave the prior context unchanged. Structural capacity is
checked before content, matching the profile constructors.

Context admission folds stored observations through the profile table and
then gates on exact bindings: required `Unsupported`/`Denied`/`Incompatible`
refuses; otherwise required missing/`Unknown`, zero bindings, or any
binding without an artifact digest stays incomplete; otherwise ready.
Diagnostics never move admission. Two concurrent contexts are independent:
separate limits, observations, bindings, diagnostics and omitted counts,
with no shared lock, signal handler or registry.

`tests/limits.rs`, `tests/context.rs`, `tests/diagnostic.rs` and
`tests/isolated_contexts.rs` pin every cap, the 108-population context
oracle cross-check, the two-thread disjoint-context run with Send/Sync
trait assertions, and bad controls. Capture-metadata integration
(`AppContext::capture`) belongs to the later SDK03, not to this increment.

From the workspace root:

```sh
cargo test --offline -p scopebase-sdk --no-default-features
cargo tree --offline -p scopebase-sdk --no-default-features
```

SPDX-License-Identifier: Apache-2.0. See LICENSE-APACHE.
