# ScopeBase Complete Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build independently qualified ScopeBase libraries, distributed regression/conformance tools, a useful application SDK and selective C/Mojo interoperability, retaining separate later product migrations.

**Architecture:** Independent Linux, BPF and capture packages share versioned contract tests while retaining different authority and shutdown semantics. Real standalone clients establish package usability; the SDK composes qualified boundaries and native clients use a narrow canonical interface plus existing libbpf-mojo. Product migrations preserve their own behavior and retire duplication later.

**Tech Stack:** Rust edition 2021, proposed MSRV 1.88.0, initial Linux x86_64 GNU target; selected existing syscall/ELF/BTF/BPF libraries; explicit compiler/object tools; C/Mojo interoperability and isolated Linux/BPF test environments.

**Spec:** [Project specification](../specs/2026-10-17-scopebase-design.md), plus its five subsystem specifications. [Traceability registry](2026-10-17-scopebase-traceability.json) maps every source obligation to tasks. [Root TODO](../../../TODO.md) is the current execution ledger; research TODO remains the source inventory.

**2026-10-18 transfer checkpoint:** The product goal is paused for an orderly transfer. Thirteen of86 tasks are accepted; TT02/BP02/LX05 have preserved candidates and70 tasks remain planned. The single [handoff](../../../handoff.md#resume-here) gives exact source/evidence/command references, root-only integration work and safe parallel restart lanes. The [transfer record](../../reviews/2026-10-18-scopebase-transfer.md) keeps interrupted work incomplete. The checklists below remain normative acceptance requirements; they do not override current TODO/registry states or justify repeating accepted foundations.

## Global Constraints

- Follow the [decision register](../specs/2026-10-18-scopebase-decisions.md) and [executor contract](../specs/2026-10-18-scopebase-executor-contract.md). The [task-origin routes and concrete repair packets](2026-10-18-scopebase-plan-repair.md#task-origins-and-decision-routes) supplement this task; broad source groups are not dispatch-ready source selections.
- PORT/ADAPT preserves the identified donor mechanism, affected call sites, original regression, independent oracle and bad control together. NEW requires the recorded missing-mechanism reason and frozen design. Unresolved architecture, source, license, support or expected-result choices return NEEDS_DECISION; no fresh approximation or weaker gate.
- Apply provisional Apache-2.0 userspace / GPL-2.0-only BPF / GPL-3.0-or-later application terms and the shared-source/third-party rules in D03–D04. Keep source SPDX, author authorization, actual target input option and kernel runtime declaration distinct.

- Brand `ScopeBase`; package names `scopebase-*`; initial package version `0.1.0`.
- Initial host target `x86_64-unknown-linux-gnu`, Rust edition 2021, proposed MSRV `1.88.0` requiring actual qualification.
- Pure host packages do not invoke BPF/native toolchains, install tools or change process-global policy.
- Preserve independent authority/observation/evidence/report types, typed partial effects, caller-scoped persistent custody accounting and explicit cleanup.
- Exact source/build/features/backend/object/fixture/profile inputs bind results. Required unavailable cases stay incomplete.
- All three priorities are planned; existing application migration is later MG work and never a package prerequisite.
- All implementation commands below describe future files/actions. No product code or runtime qualification was produced during planning.
- Donors remain read-only until an explicitly selected MG task changes its isolated checkout. Do not upgrade or freeze an active donor as a side effect of library work.
- A task ends with focused verification and one reviewable commit; no external publication or message follows automatically.

## Review Focus

1. WIP contains a necessary fix absent from main: SB01 and every donor intake record selected-file differences and hashes before copying.
2. A caller manufactures valid-looking topology/identity/receipt data: BP02/LX06/TT02 require live authority or explicitly weak observations, with safe-API controls.
3. Repeated cancellation/drop creates unbounded hidden work: LX06/LX09/BP05/TC02 retain permits across an explicit caller accounting domain and test reconstruction/failure loops.
4. A later SDK/native feature leaks compiler or runtime requirements into basic Rust use: SB02/SDK07/NX09 test independent feature unions and installed closure.
5. Final package approval accidentally claims donor migration: RL03/MG01–MG05 use separate completion records and independently executed application regressions.

## Program decomposition and reading order

| Task family | Detailed plan | Deliverable |
|---|---|---|
| SB01–SB03 | This file | Source/provenance, package/dependency and compatibility foundations |
| LX01–LX13 | [Linux](2026-10-17-scopebase-linux.md) | File/mapping/process/ownership library and migration handoff |
| BP01–BP11, TC01–TC08 | [BPF/toolchain](2026-10-17-scopebase-bpf-toolchain.md) | BPF/BTF primitives, producer contracts and compiler/object corpus |
| CP01–CP13 | [Capture](2026-10-17-scopebase-capture.md) | Pure provenance/accounting/evidence primitives and independent reference consumers |
| TT01–TT10 | [Testing](2026-10-17-scopebase-testing.md) | Shared tests, fixtures, runner, user distribution and causal CI |
| SDK01–SDK09, NX01–NX10 | [SDK/native](2026-10-17-scopebase-sdk-native.md) | Host/live applications, starter, native vectors/bridge contributions and C/Mojo clients |
| RL01–RL04 | This file | API/package acceptance, release preparation and support evolution |
| MG01–MG05 | This file, later | p11scope, OSSLscope, KryProbe, MemVeil and MojoBPF adoption |

Task numbers are identifiers, not a required linear order. For example LX04's control interface precedes completion of LX03's reads. The registry's `depends_on` records implementation prerequisites; `profile_gates` records additional selected-profile acceptance. A tooling task can be implemented and tested before all profiles use it. Composite profile/extension selection expands transitively before environment discovery and TT10 rejects omitted required components. TT10 implements the verdict checker; LX12/BP11/CP13/SDK09/NX10 later apply it to actual results, avoiding a dependency cycle.

## Milestones and acceptance

| Milestone | Scope | Exit criterion |
|---|---|---|
| M0 | SB01–SB03, TT01–TT02 first slice | Selected source/interface/license/dependency records, build probes, stable case/subject/verdict contracts and negative controls |
| M1 | Held-file/positional-read subset plus distributed host checks | Applicable LX/TT cases and two differently wired actual clients pass; explicitly not mapped-image-ready |
| M2 | Full advertised Linux mapping/process profiles | LX12 and required TT03/TT04/TT06–TT10 cells pass; both mapping policies and user-run delivery included; supervision qualified separately if advertised |
| M3 | Advertised BPF and compiler/object profiles | BP11/TC08 with actual required final objects, backend/old/current/reproducer cells and installed consumers |
| M4 | Capture package | CP13 with independent reducer clients, strict neutral validation and resource/model controls; no invented live closure |
| M5 | SDK | SDK09: both host and selected live reference applications, standalone starter, honest startup/output/stop/cleanup behavior |
| M6 | Native interoperability | NX10: actual C/Mojo clients, canonical validation, existing bridge regressions, standard-object checks and installed offline closure |
| M7 | Product migrations, separately scheduled | Each MG task passes its fresh application gates and retires old code without claiming unrelated products migrated |

M2/M3/M4 can proceed in parallel after their interfaces and M0 foundations exist. SDK host work starts when required Linux/capture boundaries are stable; native vectors/audit can start before full SDK completion. Priority order determines staffing and acceptance focus, not an artificial dependency between unrelated native corpus work and SDK UI/CLI details.

## Parallel ownership and coordination

| Lane | Exclusive writes | May run alongside | Must serialize |
|---|---|---|---|
| Integration | Root Cargo/config/lock, shared exports/profile indexes/traceability, release workflow | All lanes on their files | Every shared manifest/interface merge |
| Linux | `crates/scopebase-linux/`, Linux clients and component docs | BP pure planning, CP, TC fixtures | Shared error/identity/time modules; privileged FS resources |
| BPF | `crates/scopebase-bpf/`, semantic BPF fixtures/adapters | LX/CP and independent TC fixture work | Shared ABI/producer artifacts, backend object adoption, live guests |
| Toolchain | `tools/bpf-compat/`, testkit object/toolchain modules and compiler fixture subtrees | Host Rust/capture work | Toolchain caches/output paths, compiler job custody, admitted final objects |
| Capture | `crates/scopebase-capture/`, capture fixtures/reference clients | LX/BP/TC | CP02/CP08 `time.rs`, neutral schema/native mapping changes |
| Testing | Testkit core/runner, operator command, provisioners, profiles/CI | Domain case authors under frozen interfaces | Profile/catalog exports, guest leases, common fixture indexes |
| SDK | SDK package, two applications, starter | Native corpus and completed component qualification | Component API changes and common release records |
| Native | Interop corpus, selected ABI, C/Mojo clients and owned bridge patch overlays | SDK/LX when interfaces stable | Capture ABI mapping, native library/compiler pins, shared guests |

Assign one writer to each actual shared file, including subfiles listed inside these broad areas. Domain authors supply testkit adapters in their allocated subdirectories; TT integrates exports. Use separate worktrees/branches when implementation begins and separate `CARGO_TARGET_DIR`, compiler scratch, fixture, guest and result roots. A single coordinator controls shared heavy Cargo/native builds and privileged resources unless independently isolated resources are proved available. Read-only research can run freely.

Interface changes require a short proposal naming downstream signatures/cases, coordinated edits and affected checks. Unmerged private conventions cannot serve as integration assumptions. On interruption, record task commit/worktree, dirty owned paths, next command, pending resources and invalidated evidence in root TODO/handoff. Never transfer a running guest or pending native owner by copying a pathname alone.

## Foundation tasks

### SB01: Source intake, licensing and contract ledger

**Requirements:** SB-R01–SB-R03, SB-R05–SB-R09, SB-R17, TC-R10. **Depends on:** this specification. **Files:** create `docs/provenance/{donors.json,licenses.md,adoption-decisions.md}`, `docs/contracts/{interfaces.md,evidence.md}`, `docs/issues/README.md`, `tools/planning/check_traceability.py` and its tests; use the existing planning registry as input.

**Interfaces:** Donor record contains source repository/worktree, full commit, selected file paths/content hashes, WIP hashes, per-file license, source issue/test and intended contract. Public contract registry contains package/module/type signature, owner, consumers and version. These are provenance records, never runtime authority.

**Required repair packet:** Follow [intake validation](2026-10-18-scopebase-plan-repair.md#repair-intake-validation): no implicit partial-clone fetch; validate every nested family/regression reference; distinguish source SPDX from owner-authorized destination grants. H33 is a new planned obligation, so preserve the original 32 family observations and add its separately attributed input. Freeze per-mechanism symbols/tests/destinations before dispatch; 124 observed files alone do not satisfy that step.

- [ ] Verify selected donor refs/worktrees/dirty files read-only using their current instructions and existing inventories. Capture only relevant source/document deltas; never merge every branch or treat an old green result as current qualification.
- [ ] Write invalid-ledger checks for missing SHA/license/owner, dangling H/G/UC/TODO IDs, source absent from selected tree and a current branch name substituted for immutable bytes. `python3 -m unittest discover -s tools/planning/tests` must detect each invalid fixture.
- [ ] Implement ledger/traceability validation and fill decisions for copied source, dependency adapter, independently rewritten contract, vectors-only reuse or product-local mechanism. Preserve source licensing; resolve uncertain imports before copying them.
- [ ] Freeze shared HeldFile/testkit/neutral-validation interfaces from subsystem specs and add every newly found required gap to root TODO/traceability with acceptance. Validate all references with `python3 tools/planning/check_traceability.py docs/superpowers/plans/2026-10-17-scopebase-traceability.json`.
- [ ] Review donor custody and legal metadata, then commit the intake/contract records. No donor mutation or publication.

**Done:** Every selected input is attributable and every planned obligation has an owner. Unselected future sources remain explicitly research references.

### SB02: Workspace, dependency selection and independent builds

**Requirements:** SB-R03–SB-R04, SB-R12–SB-R15. **Depends on:** SB01. **Files:** create root `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.gitignore`, `mise.toml` if used; `tools/build/{dependency_probe,check_features}.py`, `tests/package-policy/`, `docs/dependencies.md`. Component owners supply their own package manifests; the integration owner serializes workspace membership.

**Interfaces:** `dependency_probe` records package/version/features/host toolchain and contract-fit tests; `check_features --manifest PATH --matrix PATH` builds independent external workspaces. No production dependency may point into a donor checkout.

**Decision ownership:** SB02 executes the [ratified dependency packet](2026-10-18-scopebase-sb02-packet.md), which expands the [repair amendment](2026-10-18-scopebase-plan-repair.md#first-dependencyworkspace-packet). The controller/expert records the selected implementation, feature set, actual public APIs and target license options from probe evidence. A failed comparator is not permission to raise MSRV, replace a parser/loader or rewrite a donor. Missing target policy gates only the affected BPF payload, not unrelated host components.

**TC-R10/H33 facet:** actual source/target dependency options and notices, distinct from source headers. Follow D03–D04; other facets remain with their named owners.

- [ ] Create scratch dependency probes for the actual rustix/nix/procfs/parser/backend candidates and required APIs. Run selected probes on Rust1.88.0 and pinned current stable. Missing MSRV support is a design/dependency decision, not silently raised policy.
- [ ] Write feature-policy controls that introduce a sibling path dependency or BPF build invocation into a host-only package; the checker must reject them. Add a two-client feature-union workspace with independent lockfile.
- [ ] Establish edition2021/version0.1.0 package templates, declared license policy, lock/toolchain inputs and isolated target roots. An initially empty workspace only establishes configuration; it is not a passing library build. Add real members as their owning tasks create them.
- [ ] Run `cargo metadata --no-deps --format-version 1`, the dependency probes and `python3 tools/build/check_features.py --matrix tests/package-policy/matrix.json` for existing members. Add explicit doctest jobs and package allowlists excluding private research/source-workspace evidence.
- [ ] Review dependency/feature/license choices and commit the workspace foundation; preserve exact unresolved compiler/backend profile gates.

**Done:** Selected dependencies and host toolchain build the required probe contracts independently; host-only paths do not acquire hidden native/BPF requirements. Full component build/test readiness remains its own task.

### SB03: Versioning, support and documentation contracts

**Requirements:** SB-R06, SB-R10–SB-R18. **Depends on:** SB01–SB02. **Files:** create `docs/{architecture,versioning,contributing,security-boundaries}.md`, `docs/issues/TEMPLATE.md`, `profiles/schema-versions.json`, `tools/planning/check_docs.py` and tests, `docs/contracts/compatibility.md`.

**Interfaces:** Separate Rust package, neutral schema, native ABI, case/fixture and support-profile versions. Error categories, ownership, effects and minimum evidence are public behavior. Issue template records trigger, invariant, independent oracle, known-bad control, affected scope, upstream status and removal condition.

- [ ] Write compatibility/document checks for an unknown major version, renamed error category, example claiming unsupported profile and a report described as runtime authority. Valid same-contract examples must remain accepted.
- [ ] Implement explicit pre-1.0 semver/support rules, initial host and per-BPF profile selection rules, MSRV update procedure and documented diagnostic privacy/effects. No blanket kernel floor or signing/remote service.
- [ ] Define user/developer documentation templates with prerequisites, operational limits, failure meanings, runnable-package location and support-report sanitization. Domain tasks fill and compile actual examples.
- [ ] Run `python3 tools/planning/check_docs.py` and fixture tests. Review requirement→task completeness and parallel file ownership.
- [ ] Commit this compatibility/documentation foundation; final generated support claims remain RL03/TT10 work.

**Done:** Implementers have stable compatibility and evidence rules; documentation templates cannot be confused with completed capability support.

## Integration, packaging and support tasks

### RL01: Cross-package API and adversarial integration review

**Requirements:** SB-R04–SB-R09, SB-R15–SB-R18. **Depends on:** selected implemented component interfaces and TT02/TT06; no requirement to wait for unrelated native profiles. **Files:** create `tests/integration/contracts/`, `docs/reviews/integration.md`; update only the owning package files implicated by validated findings.

**Interfaces:** External compile/API fixtures combine the actual selected public packages. Review covers safe-call memory safety, owning errors, fallible cleanup, capability invalidation, feature unification and schema/ABI consistency.

- [ ] Assemble cross-package negative examples: fabricated per-CPU topology, wrong-domain mapping proof, returned capture record promoted to live authority, native error-code drift, and dropped controller with pending resources.
- [ ] Run their compile/semantic tests and inspect production paths. Each safe API must check untrusted lengths/structural assertions before native access; every unresolved owner remains in its declared accounting domain.
- [ ] Review SDK/native adapters against exact component signatures and tests, then fix findings in owned files with the relevant regression. Do not require a universal backend abstraction to solve a local issue.
- [ ] Run the causal affected set and record remaining support limits. A review comment alone is not a fixed result.
- [ ] Commit the focused cross-boundary tests/fixes and review record.

**Done:** Selected public boundaries agree and concrete adversarial counterexamples have tests; unrelated profiles remain separately scoped.

### RL02: Package archives, offline artifacts and reproducible inputs

**Requirements:** SB-R02–SB-R04, SB-R10–SB-R14. **Depends on:** selected component distributed-client tasks, TT07–TT09, RL01. **Files:** create `tools/release/{build_artifacts,verify_bundle}.py`, `packaging/{manifest-schema.json,allowlists/}`, `.github/workflows/package.yml`, `docs/releasing.md`.

**Interfaces:** Bundle manifest names exact archive/library/binary/object/fixture identities, licenses, resolved build inputs and supported profile versions. Reproducibility means documented/pinned inputs and checked outputs; bit-for-bit claims require an actual repeated controlled build.

**TC-R10/H33 facet:** archive/bundle notice and source/object/option manifest closure. Follow D03–D04; other facets remain with their named owners.

- [ ] Write archive/bundle negatives for missing fixture/license, leaked donor absolute dependency, mismatched final object, absent native SONAME dependency and different feature build using the same metadata.
- [ ] Build from source archives in fresh workspaces, run minimal/default/union/MSRV/current and explicit doctests, then execute installed offline checks from read-only prefix.
- [ ] Verify include/exclude allowlists keep private research histories, transcripts, raw addresses and bulk evidence out of public packages. Preserve necessary license/provenance and minimized public reproductions.
- [ ] Repeat a controlled artifact build where reproducibility is claimed; compare hashes and explain any permitted nondeterministic fields rather than relabeling a mismatch.
- [ ] Review and commit packaging/CI tooling and results. Producing archives does not publish them.

**Done:** Every selected delivered artifact has complete offline closure and validated provenance/binding. External distribution remains separate.

### RL03: Candidate acceptance and release preparation

**Requirements:** SB-R01, SB-R10–SB-R18. **Depends on:** selected package readiness tasks, TT10, RL01–RL02; SDK09/NX10 only for corresponding release claims. **Files:** create `release/<version>/{candidate.json,acceptance.md,open-items.md}`, generated `docs/support.md`, changelog and prepared release description.

**Interfaces:** Candidate includes exact selected profiles and stage (package/SDK/native), not a generic whole-project complete flag. Product-migrated records are excluded unless their MG gate actually passed.

- [ ] Freeze candidate bytes, required profiles/cells and dependency/toolchain/fixture versions. Reject old green runs whose bindings differ.
- [ ] Run TT10 completion against actual results and RL02 installed artifacts; every required assertion, trigger, client and cleanup result must satisfy the frozen profile.
- [ ] Check public examples/support/MSRV/architecture/error/effects claims against results. Keep implementation-only or unavailable required cells open, with no silent downgrade.
- [ ] Recheck package-name availability and release metadata when preparing distribution; produce the complete reviewable artifacts and notes before any external publication step.
- [ ] Commit the candidate/acceptance record. Publishing/signing/tagging follows the user's selected release action and applicable repository policy, not automatically this planning task.

**Done:** A concrete release candidate is reviewable and accurately qualified for its named profiles. Migrating applications can begin later from this artifact.

### RL04: New kernels, architectures and long-term regression maintenance

**Requirements:** SB-R12–SB-R14, SB-R17–SB-R18. **Depends on:** initial qualified profile and TT08–TT10; independent of donor migrations. **Files:** extend `profiles/environments/`, `docs/support.md`, issue/workaround register and `tests/compatibility/`; add targets only when their contract is designed.

**Interfaces:** A support extension is a versioned profile amendment with exact new target/kernel/toolchain, independently expected behavior and required cells. A workaround removal is a code change linked to its retained negative/control tests.

- [ ] On dependency/compiler/kernel updates, select affected cases causally. Recheck opcode subsets, old/new-value atomics, verifier shape, final BTF, live behavior and owner cleanup as relevant.
- [ ] For Arm/other endianness/musl or new filesystem options, define ABI/ordering/permission assumptions and refusal paths first; run pure vectors, actual objects and real runtime cells before support promotion. Portability compilation alone cannot qualify it.
- [ ] For a claimed upstream repair, run the selected final consumer toolchain and issue reproducer/fixed control before deleting the workaround. Keep prior affected cells and removal criteria documented.
- [ ] Add newly discovered failures as minimized cases, update traceability/TODO and run affected consumers; measure support-maintenance cost before broadening promises.
- [ ] Review and commit each independently qualified extension/removal. There is no finite claim to have tested all future kernels.

**Done per extension:** The amended profile is qualified with its own evidence; the maintenance process remains ongoing rather than a task that can permanently close future bugs.

## Later product migration tasks

These tasks are fully planned but do not gate ScopeBase package, SDK or native readiness. Execute each only when that product is selected for migration. Each creates `migrations/<product>/{selection.json,contract-map.md,verification.json,rollback.md}` in this repository and uses a separately owned product worktree. `tools/migration/verify.py` validates exact selected product/library bytes, commands, expected populations and results; the first selected MG task introduces it with wrong-tip/missing-test/false-green tests under one integration owner, and all selected MG tasks reuse it. Creating this small shared verifier is serialized; product adapters can then proceed independently without requiring MG01 to finish first. The manifest records current product instructions and exact commands before edits; historical command names are not guessed into a future checkout.

### MG01: p11scope migration

**Depends on:** Selected LX12/BP11/TC08/CP13 package profiles, LX13 handoff and RL03 artifact. **Requirements:** SB-R02/SB-R09/SB-R18; research L07 and selected product-specific contracts.

- [ ] Refresh the active p11scope checkout, all relevant successor/WIP fixes and selected donor files; choose an isolated implementation worktree and pin both application and ScopeBase bytes.
- [ ] Freeze exact application verification commands and independent workloads in `migrations/p11scope/verification.json`; include file/maps identities, exec/lifecycle, retained attachment/retirement and affected ABI/compiler/generation/resource gates.
- [ ] Write adapter compatibility tests against the shared package and original observable contract; demonstrate plausible wrong-domain/early-release/zero-population controls fail.
- [ ] Replace one selected mechanism at a time, retain application-specific PKCS#11/privacy policies and actual producer control flow, then run focused application and required live/installed checks.
- [ ] Retire old copies only after the replacement passes; test/document dependency/adapter rollback and record exact migrated scope. Untouched mechanisms remain unmigrated.

**Done:** The selected p11scope behavior is preserved at its fresh tip, copied implementation is retired and unrelated v0.4/release work is not relabeled complete.

### MG02: OSSLscope migration

**Depends on:** Selected qualified packages/RL03 and LX13; may run beside MG01 only with distinct checkout/outputs/owned guest resources.

- [ ] Refresh remote workspace/product/preview branches and dirty documents, pin selected application/library bytes and retain existing custody.
- [ ] Freeze current application commands/workloads for descriptor identity, bounded reads, callback alias/conservation, attach error policy, count/deadline, output custody and late-hit shutdown countermodel.
- [ ] Implement the narrow package adapters while preserving provider/FIPS/algorithm interpretation and OSSL-specific salvage policy; native/final-object changes get their own affected live cells.
- [ ] Run independent actual callback and target lifecycle populations, installed capture and cleanup; shared vocabulary must not manufacture settlement beyond the existing guarantee.
- [ ] Remove superseded copies, verify rollback and record only the selected migrated mechanisms.

**Done:** OSSLscope's real policy and observation guarantees survive the shared mechanisms at the selected current tip.

### MG03: KryProbe migration

**Depends on:** Selected BP11/TC08/CP13/LX12 profiles and RL03. **Potential parallelism:** pure capture/map adapter work can follow agreed interfaces in its own product worktree; privileged lane remains leased.

- [ ] Refresh main and fix/selftest worktrees, choose selected scope and record actual consumers of each ABI, including every per-CPU stride.
- [ ] Freeze tests for insertion-time WHO identity, valid zero values, CPU migration/offline lanes, independent full-map diagnostics, frame/feed conservation, replay partitions and startup baselines.
- [ ] Replace selected map/BTF/capture/helper mechanisms; retain ADR-0007 batch/live separation and kernel-crypto request/transform policies.
- [ ] Exercise actual final producer objects, active workloads and application replay/report paths; architecture-scoped fences keep their own proof and refusal boundary.
- [ ] Retire duplicates, verify rollback and record exact migrated/source-qualified scope without reusing old release receipts.

**Done:** Each selected KryProbe consumer uses the shared contract with its own live and application evidence intact.

### MG04: MemVeil and consumed libbpf-mojo adoption

**Depends on:** Relevant CP13/NX10/BP11/TC08 profiles and RL03; no forced Rust rewrite.

- [ ] Refresh and record MemVeil's actually consumed bridge bundle separately from newer sibling/joint source, selected Mojo compiler and product kernel policy.
- [ ] Select neutral vectors/shared helpers/accepted bridge patches; freeze native ring retry/configuration/map-kind/lifetime and product fact/view/generation tests before changing the dependency.
- [ ] Apply only selected compatible dependency/adapters; keep DMA/confidential-memory reducers and report schemas local.
- [ ] Run exact C/Mojo installed clients and actual MemVeil workflows, independent byte/detail/aggregate/loss expectations, cleanup and any required live settlement gates. A model does not close an unimplemented live protocol.
- [ ] Retire selected duplication and record rollback plus consumed-version proof; newer sibling tests alone cannot qualify MemVeil.

**Done:** The chosen native/shared contracts are used by the actual product with preserved semantics and explicit remaining live limits.

### MG05: MojoBPF object-contract integration

**Depends on:** TC08/NX10 standard-object profiles; selected product integration request; no application/runtime rewrite.

- [ ] Refresh dev, typed-map BTF and relevant ahead/WIP worktrees, recording source and final producer artifacts rather than assuming the project is empty.
- [ ] Freeze accepted helper/call/map/relocation/BTF/type-domain contracts and independently expected layout/instruction vectors.
- [ ] Integrate the selected object admission/conformance route into its current build/validation workflow without adding a second loader.
- [ ] Test actual final ELF and kernel map type linkage/semantics where claimed, plus metadata-dropping/wrong-type/relocation controls and exact compiler bindings.
- [ ] Remove only superseded checker/vector duplication, retain producer-specific internals and record rollback/version compatibility.

**Done:** MojoBPF's selected output contract participates in shared qualification; no unrelated Mojo language/compiler capability is implied.

## Stop, resume and completion rules

Stop a dependent task on invalid oracle/fixture, mismatched artifact, unknown ownership, unqualified safe-API assumption or unresolved semantic failure. Continue independent unaffected work. Repeated retries cannot erase a failure; restore valid twins and produce a new exact candidate when the cause is repaired. A missing required environment leaves that profile incomplete, not the entire independent project blocked.

At each task handoff record files/commit, interface version, test commands/results, model/environment bounds, open items and owned pending resources. Root TODO is authoritative for progress; traceability is authoritative for coverage/dependencies; component plans contain implementation steps. A task checkbox closes only on its definition of done, not on code presence or a worker's message.

The full planned project is delivered when the selected M2/M3/M4 component profiles, M5 SDK and M6 native interoperability satisfy their gates and release preparation is complete. M1 is a useful internal increment. M7 remains separately schedulable and cannot be erased from the backlog. Support expansion and new regressions continue through RL04.
