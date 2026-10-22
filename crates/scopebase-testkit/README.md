# scopebase-testkit

A pure host library for bounded catalog admission and immutable selection of
versioned case/profile requirements. The caller supplies catalog bytes; selection
accepts no environment or availability input. Catalog admission/selection performs no filesystem IO or execution.

```rust
use scopebase_testkit::{CaseCatalog, CatalogLimits, ProfileId, ProfilePlan};
let bytes = include_bytes!("tests/fixtures/catalog/cases-v1.json");
let catalog = CaseCatalog::load(bytes, CatalogLimits::default())?;
let plan = ProfilePlan::select(&catalog, &ProfileId::parse("compiler-object-v1")?)?;
assert_eq!(plan.required().len(), 2);
assert!(!plan.definition_complete());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Case records use exact `(CaseId, positive revision)` identity. Lookup requires
both; no implicit latest revision exists. Every active requirement survives
selection regardless of implementation status. Transport validation compares
against the original immutable plan, including case version and attribution.
Plans own their data and survive catalog drop.

The initial [catalog](tests/fixtures/catalog/cases-v1.json) preserves 86 tasks,
179 obligations, H01–H33, 19 DRAFT profiles, one extension and four UNIMPLEMENTED
H33 cases. Its [schema](tests/fixtures/catalog/profile-schema-v1.json) documents
strict fields; admission additionally checks references, graph and revision
conflicts. Every field is required. Duplicate members, unknown fields, malformed
IDs, invalid revisions, cycles and oversized unselected records reject.

Defaults and hard ceilings are 8 MiB input, 4096 case records, 128 profiles and
extensions each, 512 obligations, 256 cells, 8192 reference/ownership edges,
64 KiB UTF-8 bytes per string, depth 32 and 16384 selected cells. Tasks/families
are capped at 128. Callers may lower positive limits. These bound metadata bytes
and work; they promise no exact RSS or wall-clock guarantee.

The archive ships integration tests, independent literal closure expectations,
revision fixtures retaining the complete canonical envelope, small exact-budget
fixtures, invalid-input populations and harmless registered metadata
fixtures. Run `cargo test --offline --locked --lib --tests` and explicitly
`cargo test --offline --locked --doc` in an admitted archive environment with
its pinned dependencies. An application's ordinary cargo test does not run
these dependency tests automatically. The independent Python checker and full
authoring guide are delivered by the ScopeBase repository under
`tools/qualification/check_catalog.py` and `docs/testing/case-authoring.md`.

REGISTERED_EXECUTABLE only admits metadata. It does not execute artifacts or
establish independent oracle quality. FROZEN describes definitions and can still
select UNIMPLEMENTED cases. Catalog registration and selection alone do not provide subject authority,
environment discovery, native runtime behavior or qualification.

User-owned source is Apache-2.0. Actual parser dependency terms and notice hashes
are retained in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

TT02 adds checked subject/artifact bindings, SHA-256 positional file measurement,
a sequential `run_profile` engine, disjoint fixture inputs and independent oracle
truth, explicit effects/retirement, and strict contract-bound receipts. Catalog
selection retains its original pure semantics. The new runtime is cooperative:
custom hooks may block, and the execution/retirement deadlines do not interrupt
arbitrary code or syscalls. No compiler, privilege or host-policy change occurs.

`RunLimits::new` admits explicit values up to the hard ceilings; `lowered` also
requires each value no greater than its receiver. Streamed artifacts default to
256 MiB each, 1 GiB cumulative reservation, 65,536 reads and 4,096 attempts.
Vectors, observations, input manifests and receipts each retain their 8 MiB cap.
The shared meter charges failed attempts and EOF checks. All file reads are
positional and preserve caller cursors/handles. Validated vector bytes are retained;
streamed executable measurements retain descriptive bindings rather than native
bytes or loader authority.

The caller independently chooses `RunContract` from the exact catalog and plan,
then constructs a `VectorManifest`, reads caller-opened files with one
`ArtifactMeasurer`, and consumes the resulting `VectorBundle` in
`VectorFixtureSession`. Supply your adapter and independent oracle to
`run_profile`. The owned cancellation probe shares the caller's atomic flag;
configuration seals when the probe is acquired. Expected bytes are available only
to collect/oracle, after the adapter's borrowed fixture access has ended.

`RunReport::from_json` recomputes binding, checkpoint, assertion prerequisite,
intent, coverage and immutable effect-ledger dimensions against that external
contract. Every import has `ReportOrigin::Imported`; even coherent forged claims
acquire no process, file or BPF authority. The precedence is Invalid, Failed,
Incomplete, Qualified. Missing activity, required evidence, final checks or cleanup
cannot become passing support. A fixture error remains separate from an operation
refusal. A later run-scope retirement may settle a known resource while preserving
its original case-end custody; unknown inventory remains unresolved.

The shipped harness cases and clients demonstrate T0 arithmetic/model contracts.
Canonical domain cases remain UNIMPLEMENTED and profiles DRAFT. TT03 Linux
fixtures, TT05 real object/kernel evidence, TT06 campaigns, TT07 installed operator
routes and TT10 release admission remain later work. H33 model transcripts do not
establish kernel cause inference or legal/source compatibility. Run this archive's
own integration tests and doctests explicitly; downstream dependency tests do not
run them automatically. Repository `tools/qualification/bind_consumer.py` measures
actual linked consumers from retained build records without invoking Cargo or
fetching. Package hashes identify bytes and do not authenticate their authors.
