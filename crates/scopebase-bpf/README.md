# scopebase-bpf

Version 0.1.0 delivers std-only host error transport and explicit resource-cap
configuration on x86_64 Linux, edition 2021, Rust 1.88.0. Both default and
`--no-default-features` builds have no external dependencies, build script or
BPF/native toolchain requirement. The only initial feature is `default = []`.

`OperationError` preserves caller-supplied kind, stage, raw errno, original boxed
Send + Sync source and optional byte requirement independently. It never
classifies errno or reconciles source disagreement. Errors are move-only;
`source()` explicitly permits downcast and nested traversal. Display and Debug
emit at most 256 ASCII bytes without calling source formatters, including
alternate formatting. Explicit source traversal, creation and drop remain caller
code without a library time/memory bound. Diagnostic text is not a wire schema.
No raw paths, descriptors or verifier payloads are printed automatically.

`Limits` requires all six caps explicitly. Every representable configuration,
including zero/MAX and unrelated cross-field values, validates structurally.
Zero disables corresponding positive work at actual operation admission; MAX
is finite and never exempts checked arithmetic. Validation allocates nothing,
performs no derived arithmetic and grants no operational or native authority.
BP02 geometry, BP04 split work, BP05 cumulative custody, BP06 frame/staging,
BP09 parser and TC02 compiler owners retain actual zero/overflow checks.

Run delivered tests from the unpacked crate archive:

```sh
cargo test --offline --locked --all-targets
cargo test --offline --locked --doc
```

Ordinary downstream `cargo test` does not run dependency tests. These package
integration tests and UI source fixtures are delivered for explicit developer
use. The foundation boundary client is one package consumer; BP11/TT07 still
owe two independent behavioral consumers and an installed operator route.

External UI controls use the exact archive-derived dependency, offline locked
client manifests with `default-features = false, features = []`, and both Rust
1.88.0 and 1.98.1. Compile `tests/ui/positive.rs` successfully first. Compile each
negative with `cargo check --offline --locked --message-format=json` and the
same dependency. Check primary source locations with ScopeBase's accepted
`tools/build/common.py::rust_refusal(..., expected_primary=(file, line))`:
`non_exhaustive.rs` has two separate E0004 match sites (ErrorKind and Stage),
`limits_default.rs` E0599 at `Limits::default()`, `error_clone.rs` E0599 at
`error.clone()`, and `source_not_send.rs` E0277 at the Rc-containing box. Require
completed collection/cleanup and unchanged locks. A wrong-primary same-code
result and a compiling control must fail the refusal oracle; setup failures are
incomplete. These controls are not automatically run by the package test command.

This NEW foundation copies no donor implementation. Repository provenance keeps
frozen donor source references and deferred preservation gates. Apache-2.0
covers this userspace source. Future BPF source grants, final-object license
sections and loader runtime license bytes are separate checks; no third-party
target option is selected here. No live/object/kernel profile, complete
`bpf-host-v1`, installed operator route or application migration is qualified.
Future BTF, Aya, libbpf and producer features appear with their implementations.
