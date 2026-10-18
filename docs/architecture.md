# ScopeBase architecture and completion boundaries

SB03 documents the foundation contracts. The root Cargo workspace has no product members. These contracts do not implement or qualify a shared library, mapped-image capability, SDK, native runtime or installed conformance route. Accepted SB01 intake and SB02 development tools are separate from those completion levels.

## Independently useful components first

The [project specification](superpowers/specs/2026-10-17-scopebase-design.md) controls the boundaries: independent Rust components, reusable regression tests and issue documentation first; a small SDK after real independent reference consumers; selective C/Mojo interoperability after the relevant contracts exist. Packages version independently. There is no universal runtime, daemon, loader, shutdown protocol or application state machine.

| Boundary | Owner and downstream contract |
|---|---|
| Linux file/process/mapping observations and retained owners | LX tasks; [Linux specification](superpowers/specs/2026-10-17-scopebase-linux-design.md). File acquisition and bounded reads do not complete calibrated mapped-image support. |
| BPF host geometry, bounded adapters and retained links | BP tasks; existing Aya/libbpf interfaces plus narrow adapters. BPF target dependencies and toolchains stay outside host-only defaults. |
| Compiler closure, final object inspection and preserved workarounds | TC tasks; [BPF/toolchain specification](superpowers/specs/2026-10-17-scopebase-bpf-toolchain-design.md). Actual object ISA/helper/BTF/attach requirements remain explicit. |
| Pure capture quantities, provenance, intervals and replay | CP tasks; [capture specification](superpowers/specs/2026-10-17-scopebase-capture-design.md). Application reducers, privacy and schemas stay local. |
| Consumer-bound developer/installed conformance | TT tasks; [testing specification](superpowers/specs/2026-10-17-scopebase-testing-design.md). The oracle remains independent of the production adapter. |
| Composition and selective interoperability | SDK/NX tasks; [SDK/native specification](superpowers/specs/2026-10-17-scopebase-sdk-native-design.md). Existing native bridges and standard object formats retain their roles. |

The [shared interface registry](contracts/interfaces.md) freezes HeldFile, consumer conformance and canonical neutral seams. CP10 owns semantic validation once; NX07 preflights its own bounded wire envelope before that validator. Native status/discriminant assignments remain in the native specification. Similar-looking error or lifetime types do not imply interchangeable authority.

## Preservation and authority

Every promoted donor mechanism travels with its original defect, selected frozen source bytes/license attribution, affected callers, original regressions, independent oracle, sensitive bad control, real reference consumers and eventual duplicate-retirement criterion. Use the [executor contract](superpowers/specs/2026-10-18-scopebase-executor-contract.md) and [issue template](issues/TEMPLATE.md). Better APIs must preserve those behaviors; a fresh implementation needs the packet's concrete missing-mechanism justification.

A pathname/PID/descriptor number, stat/maps/mount key, BTF name or supplied digest alone is not universal identity. Process observation, control, birth and exec are distinct domains. A pidfd does not freeze exec; a descriptor does not freeze content. Reports, replay documents and neutral values never construct a live file/process/map/link owner. The owning constructor and retained object admit each live action.

Retain original file authority and outstanding charges through attachment retirement or explicit unresolved custody. Drop, cancellation, descriptor closure and quiet time do not certify fallible native cleanup. Application batch/live drivers, closure rules, schemas and shutdown policies remain local. Component-specific Send/Sync, caller-fork and lock policies are part of each public contract.

## Completion and change routing

| Level | Required evidence and limit |
|---|---|
| Specification | Reviewed decisions/contracts; no execution implied. |
| Implementation | A concrete destination mechanism and its affected regressions; no package readiness implied. |
| Package-ready | Real public-path distributed consumers, shipped developer conformance, package-relative fixtures and an independently installed operator route over actual bytes. |
| SDK/native-ready | Their real host/live or C/Mojo consumers and selected required profiles, using accepted components. |
| Product-migrated | Separate MG01–MG05 application behavior, rollback and duplicate retirement. Publication is also separate. |

Two thin wrappers over a mocked helper do not establish independent usability. Ordinary downstream cargo test does not run dependency tests. Missing required fixtures, cells, activity or cleanup remain incomplete. TT10 owns qualification closure; RL03 owns generated supported-capability claims. [Evidence tiers and result axes](contracts/evidence.md) remain separate.

One writer owns each shared interface/file; isolated build/evidence outputs and coordinated guest/host leases bound parallel work. The [development workflow](../DEVELOPMENT.md) governs dispatch and independent review. Interface, fixture, compiler or source changes invalidate the causally affected checks, with root TODO/traceability changes owned by the controller. Existing five direct SB03 traceability mappings remain unchanged; this document also explains the master plan's broader documentation facets.

```scopebase-doc
{
  "schema_version": 1,
  "id": "architecture",
  "mode": "contract",
  "owner_task": "SB03",
  "requirements": [
    "SB-R06",
    "SB-R15",
    "SB-R16",
    "SB-R18"
  ],
  "versions": [
    {
      "domain": "rust-package",
      "version": "0.1.0"
    },
    {
      "domain": "neutral-semantic",
      "version": "1"
    }
  ],
  "errors": [
    {
      "domain": "linux.reason",
      "category": "CleanupUnresolved"
    }
  ],
  "profiles": [],
  "subject_kind": "policy",
  "authority_claim": "none",
  "execution": "not_applicable"
}
```
