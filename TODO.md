# ScopeBase TODO

Status: **Eight of 86 tasks accepted:** [SB01](docs/reviews/2026-10-18-sb01-foundation.md), [SB02](docs/reviews/2026-10-18-sb02-foundation.md), [SB03](docs/reviews/2026-10-18-sb03-foundation.md), [LX01](docs/reviews/2026-10-18-lx01-foundation.md), [CP01](docs/reviews/2026-10-18-cp01-foundation.md), [LX02](docs/reviews/2026-10-18-lx02-held-file.md), [CP02](docs/reviews/2026-10-18-cp02-values.md) and [TT01](docs/reviews/2026-10-18-tt01-registry.md). Final integrated subject `6b225d1ae8d3e9a67c87b65a1beb9a627b72e2de` passed all 134 package checks across 16 compiler/configuration cells. The packages now export held-file acquisition, pure capture values and bounded registry/profile selection. **No complete runtime/conformance profile is qualified.** This is the canonical execution ledger; designing a task or registering its cases does not complete it.

Read the [decision register](docs/superpowers/specs/2026-10-18-scopebase-decisions.md), [executor contract](docs/superpowers/specs/2026-10-18-scopebase-executor-contract.md), [repair plan](docs/superpowers/plans/2026-10-18-scopebase-plan-repair.md), master specification/plan and selected subsystem pair. [Traceability](docs/superpowers/plans/2026-10-17-scopebase-traceability.json) maps **120 requirements and 86 tasks** to **81 research TODO items, 32 initial families plus H33, 23 public-contract gaps, 14 user-conformance cases and 28 overlap rows**: 179 source-obligation mappings. G items also occur in the research TODO; these are not disjoint bug counts.

## Corrections and remaining dependent work

| Work / existing owner | Dependency | Exit criterion |
|---|---|---|
| Controller: frozen donor copies — complete | User's 2026-10-18 direction | All four private P/K/O/M source and history captures are complete and preserve refs, registered worktrees, staged/unstaged and untracked source/docs, with explicit omissions and no live Git pointers. Prune only private generated binaries/caches/VM images and bulk raw logs; retain source, history, WIP, small regression fixtures and defect summaries. Bind ports to these copies; no repeated live-head checks or wait for donor cleanliness |
| LX01/controller first product policy — accepted | Accepted SB02; real product manifests and frozen root lock | Product-role notices, explicit empty fixture workspace, full offline locked product-root metadata, before/after lock preservation including failures, and isolated staging for an actual member without nested `[workspace]`; missing/stale lock and staging defect controls fail semantically, valid twins pass |
| LX02 shared compiler-refusal helper; CP02 consumer — accepted | Reviewed exact-source predicate and actual controls | Exact primary file/line matching, preserved PP09 behavior, positive/negative/wrong-line controls on both compilers; actual LX02/CP02 checks bind accepted helper bytes |
| SB01 selected-port receipt maintenance — accepted | Immutable pre-copy grants and completed destination mappings | Bounded receipt validator and both actual first-port receipts passed; independent review checked retained originals and unported boundaries. Future ports require their own exact receipt; old intake flags remain historical |
| LX02/CP02 ports and LX04 source admissions | Completed frozen P/K/O/M/L inputs and existing owner grant | The eleven first-port grants have separate completed receipts. Five additional narrow LX04 grants bring intake to 128 files: 16 ready, 109 pending and three reference-only. The LX04 grant is pre-copy input, not implementation acceptance |
| BP01 single-client tool policy — accepted | Reviewed no-union schema repair and actual archive/client control | One or two clients without unions; two still required for a union. Existing source/field/feature checks and BP11 independent-consumer gates remain mandatory |
| TT02 in-process artifact hashing | Exact SHA-256 dependency admission and frozen binding/verdict contract | Admit the selected local sha2 closure with independent known-answer and active-negative controls on both compilers; verify actual bytes and retain reported-versus-measured provenance |
| BP01 configuration / later operation enforcement | Accepted SB01/SB02/SB03; frozen BP01 contract | Implement std-only lossless errors and explicit independent caps. BP02 geometry, BP04 split attempts, BP05 retirement, BP06 staging, BP09 parsing and TC02 execution retain actual zero/overflow admission tests; foundation validation cannot close them |
| LX04 generic controls / LX10 collection policy | Accepted LX02 error/ownership API and selected P/O source slices | Preserve shared cancellation, absolute deadlines, errno/effects and publication checkpoints. Generic controls have no collection-wide first-stop latch; LX10 must preserve P's original latched multi-worker outcome and traversal regressions |
| TT01 mandatory minimal dependencies — helper accepted | Exact admitted 11-package parser closure | Reviewed opt-in `minimal_dependencies` narrows existing grants, including default cells matching minimal; legacy guard and actual archived fixture controls preserved. TT01's registry/archive increment is now independently accepted; verdict execution remains TT02 |
| LX08 process source intake | Frozen P source copy and accepted SB01 schema | Add exact `src/pidns.rs` source/adoption/regression mapping before port; preserve the historical 124-file baseline and do not turn its cached PID namespace into universal library authority |
| SB01 local verification — accepted | Reviewed subject in SB01 record | Partial-clone missing blob/tree stays incomplete; wrong available object type/tree stays invalid; no lazy fetch, transport or donor mutation; complete local twin verifies |
| SB01 nested preservation integrity — accepted | Reviewed subject in SB01 record | Missing family/oracle/control or dangling donor/path/symbol/line/group/obligation fails; all original observations/regressions retained |
| SB01 source/destination policy — accepted | User's provisional D03 choice | Schema distinguishes owner authorization, destination and original third-party terms/roles; original 14 automatic copying blocks removed; actual source slices still require decisions |
| SB01/LX01/LX08 and CP01/CP03/CP04 source slices | Reviewed donor inventory | Correct process/pin and KryProbe insertion/loss inputs; exact source-to-destination/test map before dispatch |
| CP12 successor selection | CP06/CP11 and actual refreshed successor | Evidence-based extraction/internal/product-local evaluation; no invented stable replacement |
| SB02/BP01/TC01 upstream target option | Actual selected target closure and D03 scope | Explicit compatible option/notices for Aya target inputs; no automatic Apache-only GPLv2 output or silent third-party MIT choice; unrelated host work proceeds |
| BP03/TC03/TC06/TC07 and TT owners, H33 | Frozen actual source/object/kernel fixture | Source/runtime boundaries, final declaration, same-errno causes, GPL-only intended refusal and active valid/helper-free twins on applicable cells |
| TT02/TT03/TT04 and LX09 design inputs | Accepted foundation/component contracts | Frozen consumer identity recipe, worker/FD protocol, ownership transitions and real filesystem/audit recipes; ordinary executor receives specified choices |

The three SB01 corrections are accepted in the linked foundation record. Remaining rows are open obligations in their existing tasks. See the repair plan for original candidate custody, tests, source facts and all 86 origin/decision routes.

Package-ready, SDK/native-ready and product-migrated are separate statuses. Migrations MG01–MG05 stay open until selected later. A small held-file pilot is M1; the requested ready mapped-image library requires M2. The full SDK requires both host and actual live BPF applications. The native phase requires actual C and Mojo clients.

## Development setup

The [execution setup plan](docs/superpowers/plans/2026-10-18-scopebase-execution.md) is a separate preparatory checklist; it does not close any of the 86 product tasks. The active M0–M6 goal additionally requires preserving/porting donor fixes, allows justified API/architecture improvements and independently tested missing components, and permits appropriate CI/CD and privileged real-kernel tests. Follow [DEVELOPMENT](DEVELOPMENT.md) and the [current handoff](handoff.md).

- [x] EX01: isolated task briefs, model dispatch records and immutable review packages.
- [x] EX02: supplementary readonly Muse review and cooperative build/resource locking.
- [x] EX03: controller rules, templates, Git-aware document checks and a single restart route.
- [x] EX04: independent review and final setup verification. See the [accepted setup record](docs/superpowers/reviews/2026-10-18-scopebase-execution-verification.md): final implementation `79318cf`, 70 orchestration tests, doctor/dry-run, actual read-only preparation and reconciliation, planning/whitespace checks; no product qualification.

## Execution and parallelization

1. SB01 is accepted; retain its source observations and preserve donor WIP in private frozen copies. Bind selected copied bytes before an actual port; live development does not trigger repeated refreshes. SB02 established the selected dependency/compiler API probes and package-policy tools; SB03 has frozen compatibility/support rules.
2. After SB02, Linux foundation, capture foundation and testkit registry can proceed on disjoint files. After SB03, start BPF/toolchain foundations and the SDK profile shell. These early SDK files do not establish SDK usability.
3. Linux read/control/parser work uses agreed seams; LX04 must be complete before LX03 closes. Capture modules split after CP02. BP09 parsing and BP02 geometry can proceed alongside TC02 direct-tool execution. TC03 precedes TT05 guest orchestration; TC07 adds real whole-guest mixed builds after TT05.
4. Run independent pure/model/source checks in isolated outputs. One integration owner serializes root Cargo/lock, exports, interface/schema changes and shared catalogs. Lease privileged filesystem/kernel guests and coordinate heavy Cargo/native builds. Never share mutable fixture/run roots or compiler outputs.
5. SDK host consumers start on actual Linux/capture contracts; live SDK waits for selected real backend/object gates. Native vectors/audit may proceed independently after CP10; native package readiness requires its actual language/toolchain/environment cells. Priorities govern staffing, not unnecessary cross-lane dependencies.
6. RL review/package/release preparation accepts only selected qualified profiles. Product migrations use distinct owned worktrees and fresh application regressions; the first selected MG task creates the common verifier under serialized ownership.

The registry distinguishes implementation prerequisites (`depends_on`) from selected-profile acceptance (`profile_gates`). Its all-edges graph is acyclic. SDK/native selections expand their required component profiles and versioned extensions before environment discovery; missing component results cannot be hidden by a green top-level result. Never interpret a dependency on TT10 as requiring every future profile to be qualified before the checker exists.

## Testing gates for every selected mechanism

- Freeze the contract, donor/WIP pin, independent oracle, valid twin, semantic bad control, subject binding and required cells before checking environment availability.
- Exercise intended failures after valid setup: incorrect implementations must fail the named assertion. Missing required cells, inactive positive/excluded workloads, stale bytes and unresolved cleanup remain incomplete or invalid.
- Use applicable pure/property/model/fuzz/unsafe/sanitizer/object/real-host/live/distributed tiers. Record finite bounds and what each technique cannot prove. No arbitrary coverage percentage or stress count replaces the defect oracle.
- Ship both the developer conformance route and installed operator route, bound to the actual linked package/backend/features/objects. Test offline execution from a read-only prefix with separate writable roots and independently built clients.
- Cover actual Btrfs identity split/collision, overlay/copy-up, foreign namespace and denial cells for mapping claims; kernel/ISA/verifier/JIT behavior for BPF claims; native lifetime/retry/configuration/layout and real C/Mojo use for native claims.
- Preserve ownership across cancellation, timeout, failed cleanup, dropped handles and controller reconstruction. Test persistent accounting pools and independent concurrent observers.
- Rerun causally affected checks after source/dependency/compiler/oracle/profile changes. Preserve semantic failures across retries; no old green run qualifies changed bytes.

Each task link contains exact planned files, interfaces, test commands, acceptance and definition of done. All commands that refer to future crates/tools are implementation instructions, not executed results.

## M0: source and workspace foundations

- [x] [SB01: Source intake, licensing and contract ledger](docs/superpowers/plans/2026-10-17-scopebase.md#sb01-source-intake-licensing-and-contract-ledger) — prerequisites: none.
- [x] [SB02: Workspace, dependency selection and independent builds](docs/superpowers/plans/2026-10-17-scopebase.md#sb02-workspace-dependency-selection-and-independent-builds) — prerequisites: SB01.
- [x] [SB03: Versioning, support and documentation contracts](docs/superpowers/plans/2026-10-17-scopebase.md#sb03-versioning-support-and-documentation-contracts) — prerequisites: SB01, SB02.

## M1/M2: Linux files, mappings, processes and bounds

- [x] [LX01: Foundation choices and selected donor contract register](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx01-foundation-choices-and-selected-donor-contract-register) — prerequisites: SB01, SB02.
- [x] [LX02: Held regular-file authority, errors and encapsulation](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx02-held-regular-file-authority-errors-and-encapsulation) — prerequisites: LX01.
- [ ] [LX03: Positional full reads and explicit memory/work accounting](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx03-positional-full-reads-and-explicit-memorywork-accounting) — prerequisites: LX02, LX04.
- [ ] [LX04: Cooperative deadline/cancellation and structured effect handling](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx04-cooperative-deadlinecancellation-and-structured-effect-handling) — prerequisites: LX01.
- [ ] [LX05: Strict bounded maps/mount observations](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx05-strict-bounded-mapsmount-observations) — prerequisites: LX02.
- [ ] [LX06: Mapping relations, explicit calibration and retained custody](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx06-mapping-relations-explicit-calibration-and-retained-custody) — prerequisites: LX02, LX04, LX05, LX08.
- [ ] [LX07: Real filesystem, namespace and effect qualification adapters](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx07-real-filesystem-namespace-and-effect-qualification-adapters) — prerequisites: LX06, TT03, TT04.
- [ ] [LX08: Observation authority, task birth and observer epochs](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx08-observation-authority-task-birth-and-observer-epochs) — prerequisites: LX02, LX04, LX05.
- [ ] [LX09: Optional stopped-child supervision and explicit unresolved ownership](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx09-optional-stopped-child-supervision-and-explicit-unresolved-ownership) — prerequisites: LX04, LX08, TT03.
- [ ] [LX10: Explicit bounded descriptor-relative discovery](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx10-explicit-bounded-descriptor-relative-discovery) — prerequisites: LX02, LX04.
- [ ] [LX11: Two independently wired real clients and developer conformance](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx11-two-independently-wired-real-clients-and-developer-conformance) — prerequisites: LX02, LX03, LX04, TT01, TT02, TT03, TT07; selected-profile gates in registry.
- [ ] [LX12: Package/profile acceptance and affected-check routing](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx12-packageprofile-acceptance-and-affected-check-routing) — prerequisites: LX11, TT06, TT07, TT08, TT09, TT10, SB03; selected-profile gates in registry.
- [ ] [LX13: Product migration compatibility packet, without donor edits](docs/superpowers/plans/2026-10-17-scopebase-linux.md#lx13-product-migration-compatibility-packet-without-donor-edits) — prerequisites: LX02, LX06.

## M3: BPF primitives and existing-loader adapters

- [ ] [BP01: Freeze BPF boundaries and issue provenance](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp01-freeze-bpf-boundaries-and-issue-provenance) — prerequisites: SB01, SB02, SB03.
- [ ] [BP02: Checked possible-CPU map geometry and ABI-safe lookup](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp02-checked-possible-cpu-map-geometry-and-abi-safe-lookup) — prerequisites: BP01.
- [ ] [BP03: Capability and hazard evidence with non-vacuous probes](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp03-capability-and-hazard-evidence-with-non-vacuous-probes) — prerequisites: BP01, TT01, TT02.
- [ ] [BP04: Finite attachment planner and caller error policy](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp04-finite-attachment-planner-and-caller-error-policy) — prerequisites: BP01.
- [ ] [BP05: Held-file attachment custody and explicit retirement](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp05-held-file-attachment-custody-and-explicit-retirement) — prerequisites: BP04, LX02.
- [ ] [BP06: Ring frame arithmetic, bounded reader and copied staging](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp06-ring-frame-arithmetic-bounded-reader-and-copied-staging) — prerequisites: BP01.
- [ ] [BP07: Program/CPU writer ownership, insertion provenance and full-map diagnostics](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp07-programcpu-writer-ownership-insertion-provenance-and-full-map-diagnostics) — prerequisites: BP02, TC03.
- [ ] [BP08: Optional producer task/exec identity protocol](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp08-optional-producer-taskexec-identity-protocol) — prerequisites: BP03, BP09, TC05, TC06, TT05.
- [ ] [BP09: Bounded domain-aware BTF parser adaptation](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp09-bounded-domain-aware-btf-parser-adaptation) — prerequisites: BP01.
- [ ] [BP10: Narrow existing-loader adapters and native contract vectors](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp10-narrow-existing-loader-adapters-and-native-contract-vectors) — prerequisites: BP02, BP03, BP04, BP05, BP06, BP08, BP09, TC03, TC05, LX02.
- [ ] [BP11: BPF package and installed downstream conformance](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#bp11-bpf-package-and-installed-downstream-conformance) — prerequisites: BP01, BP02, BP03, BP04, BP06, BP09, TT01, TT02, TT06, TT07, TT08, TT09, TT10; selected-profile gates in registry.

## M3: compiler, instruction and final-object compatibility

- [ ] [TC01: Recover issue fixtures, toolchain pins and patch register](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#tc01-recover-issue-fixtures-toolchain-pins-and-patch-register) — prerequisites: SB01, SB02, SB03, BP01.
- [ ] [TC02: Explicit compiler closure and bounded nested-build helper](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#tc02-explicit-compiler-closure-and-bounded-nested-build-helper) — prerequisites: TC01.
- [ ] [TC03: Final-object inventory and explicit ISA profile admission](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#tc03-final-object-inventory-and-explicit-isa-profile-admission) — prerequisites: TC01, TC02; selected-profile gates in registry.
- [ ] [TC04: Atomic RMW old/new-value and AtomicLoad selector regressions](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#tc04-atomic-rmw-oldnew-value-and-atomicload-selector-regressions) — prerequisites: TC02, TC03.
- [ ] [TC05: ELF/BTF relocation, call graph and metadata preservation](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#tc05-elfbtf-relocation-call-graph-and-metadata-preservation) — prerequisites: TC03, BP09.
- [ ] [TC06: Restricted dead-code repair and verifier-sensitive rule manifests](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#tc06-restricted-dead-code-repair-and-verifier-sensitive-rule-manifests) — prerequisites: TC05.
- [ ] [TC07: Exact-artifact kernel behavior and concurrent compiler claims](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#tc07-exact-artifact-kernel-behavior-and-concurrent-compiler-claims) — prerequisites: TC03, TC04, TC05, TC06, TT05.
- [ ] [TC08: Distribute compiler/object suite and expire only proven workarounds](docs/superpowers/plans/2026-10-17-scopebase-bpf-toolchain.md#tc08-distribute-compilerobject-suite-and-expire-only-proven-workarounds) — prerequisites: TC01, TC02, TC03, TC04, TC05, TC06, TT07, TT08, TT10; selected-profile gates in registry.

## M4: capture semantics and general Rust reuse

- [x] [CP01: Package, donor custody and issue contracts](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp01-package-donor-custody-and-issue-contracts) — prerequisites: SB02.
- [x] [CP02: Domain, quantity, partition and interval foundations](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp02-domain-quantity-partition-and-interval-foundations) — prerequisites: CP01.
- [ ] [CP03: Counter protocol, loss units and diagnostic signals](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp03-counter-protocol-loss-units-and-diagnostic-signals) — prerequisites: CP02.
- [ ] [CP04: Insertion-frozen provenance and survives-full-map model](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp04-insertion-frozen-provenance-and-survives-full-map-model) — prerequisites: CP02, CP03.
- [ ] [CP05: Explicit generations and bounded lifecycle histories](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp05-explicit-generations-and-bounded-lifecycle-histories) — prerequisites: CP02.
- [ ] [CP06: Scoped immutable views, required feeds and corrections](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp06-scoped-immutable-views-required-feeds-and-corrections) — prerequisites: CP03, CP05.
- [ ] [CP07: Physical-site alternatives and checked count bounds](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp07-physical-site-alternatives-and-checked-count-bounds) — prerequisites: CP02.
- [ ] [CP08: Scoped interval ordering proof](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp08-scoped-interval-ordering-proof) — prerequisites: CP02, CP05.
- [ ] [CP09: Closure evidence profiles and late-evidence countermodels](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp09-closure-evidence-profiles-and-late-evidence-countermodels) — prerequisites: CP02, CP05.
- [ ] [CP10: Canonical neutral validation and strict replay vectors](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp10-canonical-neutral-validation-and-strict-replay-vectors) — prerequisites: CP03, CP04, CP05, CP06, CP07, CP08, CP09.
- [ ] [CP11: Independent real consumers, examples and correction holders](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp11-independent-real-consumers-examples-and-correction-holders) — prerequisites: CP10, TT01, TT02.
- [ ] [CP12: Cross-stage reservation evaluation with a gated internal pilot](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp12-cross-stage-reservation-evaluation-with-a-gated-internal-pilot) — prerequisites: CP06, CP11.
- [ ] [CP13: Packaged conformance, installed operator route and release gate](docs/superpowers/plans/2026-10-17-scopebase-capture.md#task-cp13-packaged-conformance-installed-operator-route-and-release-gate) — prerequisites: CP11, CP12, TT01, TT02, TT06, TT07, TT08, TT09, TT10.

## Cross-cutting: testing, user delivery and CI

- [x] [TT01: Versioned case/profile and traceability registry](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt01-versioned-caseprofile-and-traceability-registry) — prerequisites: SB01, SB02.
- [ ] [TT02: Subject binding, independent oracles and verdict engine](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt02-subject-binding-independent-oracles-and-verdict-engine) — prerequisites: TT01.
- [ ] [TT03: Owned Linux fixture worker and independent raw truth](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt03-owned-linux-fixture-worker-and-independent-raw-truth) — prerequisites: TT01, TT02, LX01.
- [ ] [TT04: Real filesystem cells and mapping-policy audit](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt04-real-filesystem-cells-and-mapping-policy-audit) — prerequisites: TT03, LX06.
- [ ] [TT05: Isolated object and live-kernel orchestration](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt05-isolated-object-and-live-kernel-orchestration) — prerequisites: TT01, TT02, TT03, BP02, TC03.
- [ ] [TT06: Fault schedules, property/model/fuzz and sanitizer campaigns](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt06-fault-schedules-propertymodelfuzz-and-sanitizer-campaigns) — prerequisites: TT02.
- [ ] [TT07: Installed operator command and downstream package delivery](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt07-installed-operator-command-and-downstream-package-delivery) — prerequisites: TT01, TT02, TT03, LX02, LX03, LX04.
- [ ] [TT08: Causal CI selection and safe parallel scheduling](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt08-causal-ci-selection-and-safe-parallel-scheduling) — prerequisites: TT01, TT02.
- [ ] [TT09: Resource, performance and concurrent-consumer qualification](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt09-resource-performance-and-concurrent-consumer-qualification) — prerequisites: TT03, LX03, LX04.
- [ ] [TT10: Qualified support matrix and test-delivery completion](docs/superpowers/plans/2026-10-17-scopebase-testing.md#tt10-qualified-support-matrix-and-test-delivery-completion) — prerequisites: TT02, TT07, TT08.

## M5: small SDK and real host/live applications

- [ ] [SDK01: Explicit profile, capability and effects admission](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk01-explicit-profile-capability-and-effects-admission) — prerequisites: SB01, SB02, SB03.
- [ ] [SDK02: Bounded context, diagnostics and component bindings](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk02-bounded-context-diagnostics-and-component-bindings) — prerequisites: SDK01.
- [ ] [SDK03: Capture metadata integration and consumer-linked conformance](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk03-capture-metadata-integration-and-consumer-linked-conformance) — prerequisites: SDK02, CP10, TT01, TT02, TT06.
- [ ] [SDK04: Independently useful owned-workload host observer](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk04-independently-useful-owned-workload-host-observer) — prerequisites: SDK03, LX02, LX03, LX04, TT03, TT06.
- [ ] [SDK05: Standalone starter and host package submilestone](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk05-standalone-starter-and-host-package-submilestone) — prerequisites: SDK04, LX11, CP13, TT07, TT10.
- [ ] [SDK06: Actual live observation recipe over existing Aya](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk06-actual-live-observation-recipe-over-existing-aya) — prerequisites: SDK04, LX09, BP04, BP05, BP10, TC03, TC05, TT05, TT06; selected-profile gates in registry.
- [ ] [SDK07: Package SDK and starter with both reference routes](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk07-package-sdk-and-starter-with-both-reference-routes) — prerequisites: SDK05, SDK06, BP11, TT07; selected-profile gates in registry.
- [ ] [SDK08: Fault, concurrency and causal CI qualification](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk08-fault-concurrency-and-causal-ci-qualification) — prerequisites: SDK07, TT06, TT08, TT09.
- [ ] [SDK09: SDK acceptance and MG handoff](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#sdk09-sdk-acceptance-and-mg-handoff) — prerequisites: SDK08, SB03, TT10; selected-profile gates in registry.

## M6: native contracts, C/Mojo clients and standard objects

- [ ] [NX01: Independent neutral corpus and semantic bindings](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx01-independent-neutral-corpus-and-semantic-bindings) — prerequisites: SB01, SB03, CP10, TT01, TT06.
- [ ] [NX02: Exact libbpf-mojo and MojoBPF integration audit](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx02-exact-libbpf-mojo-and-mojobpf-integration-audit) — prerequisites: NX01, SB01.
- [ ] [NX03: Native copied-record retention and retry contribution](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx03-native-copied-record-retention-and-retry-contribution) — prerequisites: NX01, NX02, TT06.
- [ ] [NX04: Transactional native configuration and stale views](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx04-transactional-native-configuration-and-stale-views) — prerequisites: NX02, NX03.
- [ ] [NX05: Exact native map geometry and live map control](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx05-exact-native-map-geometry-and-live-map-control) — prerequisites: NX02, NX03, BP02, TT05.
- [ ] [NX06: Existing bridge lifetime, close, release and standard objects](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx06-existing-bridge-lifetime-close-release-and-standard-objects) — prerequisites: NX02, NX03, NX04, NX05, TC05, TT05, TT06; selected-profile gates in registry.
- [ ] [NX07: Narrow stateless ScopeBase capture ABI](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx07-narrow-stateless-scopebase-capture-abi) — prerequisites: NX01, CP10, SB02.
- [ ] [NX08: Independently useful C and Mojo validation applications](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx08-independently-useful-c-and-mojo-validation-applications) — prerequisites: NX07, NX01, TT07.
- [ ] [NX09: Sanitizers, fuzzing and installed offline bundles](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx09-sanitizers-fuzzing-and-installed-offline-bundles) — prerequisites: NX03, NX04, NX05, NX06, NX07, NX08, TT06, TT07, TT08.
- [ ] [NX10: Native acceptance, contribution custody and MG handoff](docs/superpowers/plans/2026-10-17-scopebase-sdk-native.md#nx10-native-acceptance-contribution-custody-and-mg-handoff) — prerequisites: NX09, SB01, SB03, TT10; selected-profile gates in registry.

## Integration, release preparation and continuing support

- [ ] [RL01: Cross-package API and adversarial integration review](docs/superpowers/plans/2026-10-17-scopebase.md#rl01-cross-package-api-and-adversarial-integration-review) — prerequisites: SB03, TT02, TT06; selected-profile gates in registry.
- [ ] [RL02: Package archives, offline artifacts and reproducible inputs](docs/superpowers/plans/2026-10-17-scopebase.md#rl02-package-archives-offline-artifacts-and-reproducible-inputs) — prerequisites: TT07, TT08, TT09, RL01; selected-profile gates in registry.
- [ ] [RL03: Candidate acceptance and release preparation](docs/superpowers/plans/2026-10-17-scopebase.md#rl03-candidate-acceptance-and-release-preparation) — prerequisites: TT10, RL01, RL02; selected-profile gates in registry.
- [ ] [RL04: New kernels, architectures and long-term regression maintenance](docs/superpowers/plans/2026-10-17-scopebase.md#rl04-new-kernels-architectures-and-long-term-regression-maintenance) — prerequisites: RL03, TT08, TT09, TT10; ongoing per accepted extension.

## M7 later: existing product migrations

- [ ] [MG01: p11scope migration](docs/superpowers/plans/2026-10-17-scopebase.md#mg01-p11scope-migration) — prerequisites: RL03, LX13; selected-profile gates in registry.
- [ ] [MG02: OSSLscope migration](docs/superpowers/plans/2026-10-17-scopebase.md#mg02-osslscope-migration) — prerequisites: RL03, LX13; selected-profile gates in registry.
- [ ] [MG03: KryProbe migration](docs/superpowers/plans/2026-10-17-scopebase.md#mg03-kryprobe-migration) — prerequisites: RL03; selected-profile gates in registry.
- [ ] [MG04: MemVeil and consumed libbpf-mojo adoption](docs/superpowers/plans/2026-10-17-scopebase.md#mg04-memveil-and-consumed-libbpf-mojo-adoption) — prerequisites: RL03; selected-profile gates in registry.
- [ ] [MG05: MojoBPF object-contract integration](docs/superpowers/plans/2026-10-17-scopebase.md#mg05-mojobpf-object-contract-integration) — prerequisites: RL03, TC08, NX10.

## Adding discoveries and handing off

Add missing necessary work when found: stable new task/source ID, affected capability, owner lane, exact files/interface, dependency edges, independent oracle and acceptance. Update this ledger, the appropriate spec/plan, registry and affected-case selection together. Do not renumber existing H/G/UC IDs or silently weaken a required profile.

At a handoff record the current task and checkout/commit; dirty owned paths; completed commands and exact result scope; next actionable command; required unavailable cells; pending children/maps/links/output leases; and who owns shared resources. Keep a single current restart route here or in an explicitly selected root handoff, never competing completion narratives.

Planning verification is recorded in [the documentation review](docs/superpowers/reviews/2026-10-17-scopebase-verification.md). It cannot close any implementation checkbox above.
