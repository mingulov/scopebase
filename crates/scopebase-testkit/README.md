# scopebase-testkit

A pure host library for bounded catalog admission and immutable selection of
versioned case/profile requirements. The caller supplies catalog bytes; selection
accepts no environment or availability input. It performs no filesystem IO,
execution or qualification.

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
select UNIMPLEMENTED cases. This package has no subject authority, verdict,
environment discovery, BPF toolchain, native runtime or qualification claim.

User-owned source is Apache-2.0. Actual parser dependency terms and notice hashes
are retained in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
