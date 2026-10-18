# scopebase-capture

Version 0.1.0 establishes ScopeBase's pure Rust host package and feature wiring.
Capture APIs and advertised capability profiles remain **proposed until
implemented** and qualified; there are no runtime exports in this increment.
Product integrations are **LATER**.

The default feature set is empty. Optional `json` enables exactly pinned `serde`
and `serde_json` dependencies for later strict bounded replay work; it does not
provide a replay parser or serialization API yet. Neither normal consumption nor
building this package invokes Python, a BPF/native toolchain, platform syscalls,
logging or a product runtime. The admitted optional JSON closure may run ordinary
Rust dependency build scripts; this package has no build script.

The initial compiler matrix is Rust 1.88.0 and 1.98.1 on
`x86_64-unknown-linux-gnu`. A declared MSRV or successful import does not qualify
capture semantics, other targets, independent consumer usability or live/native
behavior.

The delivered development boundary tests explicitly require **Python 3.11+**
(`python3` on PATH, with standard-library `tomllib`). Missing Python fails the
required test. From an extracted package, run:

```sh
cargo test --offline --locked --no-default-features --test package_boundary
cargo test --offline --locked --features json --test package_boundary
cargo test --offline --locked --no-default-features --doc
cargo test --offline --locked --features json --doc
```

Offline execution requires the exact locked dependency sources to have been
prepared by the caller. The shipped test-only helper structurally reads the local
manifest; it does not resolve or compile a forbidden dependency. It checks the
original and Cargo-normalized manifest boundary and rejects owned negative
fixtures, including an inactive-target dependency. Explicit test subprocesses and
small temporary fixtures are retired after use. These tests establish package
wiring only; source provenance, script approval, notices and archive membership
are separately checked by the repository's package policy.

Source and original regression custody is recorded in the repository's
`docs/issues/capture/` register. CP02–CP13 own implementation, preservation tests,
independently useful consumers and installed conformance. Generic imports do not
exercise donor behavior. Project-owned code uses the provisional Apache-2.0
userspace terms; THIRD-PARTY-NOTICES.md preserves the distinct upstream dependency
terms. No publication or migration is implied.
