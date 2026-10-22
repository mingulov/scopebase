# scopebase-sdk

ScopeBase explicit application profiles (SDK01): prerequisite capabilities,
admitted effects and the Ready/Incomplete/Refused admission table. This is
report metadata only; it carries no executable authority and probes no
environments.

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
a binding without an artifact digest refusing Ready) belongs to the later
SDK02 application context, not to this profile-level admission.

From the workspace root:

```sh
cargo test --offline -p scopebase-sdk --no-default-features
cargo tree --offline -p scopebase-sdk --no-default-features
```

SPDX-License-Identifier: Apache-2.0. See LICENSE-APACHE.
