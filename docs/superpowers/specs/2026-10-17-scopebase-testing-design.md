# ScopeBase testing and conformance specification

Normative 2026-10-18 amendment: [decisions and reasons](2026-10-18-scopebase-decisions.md), [executor contract](2026-10-18-scopebase-executor-contract.md), and [task-origin / repair plan](../plans/2026-10-18-scopebase-plan-repair.md). Porting and task readiness follow these amendments; no new implementation or support claim follows.
Date: 2026-10-17. Status: proposed implementation contract. TT01 registry/package evidence is recorded separately; the TT02 engine and complete runtime/conformance profiles remain unqualified. The [project specification](2026-10-17-scopebase-design.md) defines scope and completion levels. The [testing plan](../plans/2026-10-17-scopebase-testing.md) implements this document.

## Required outcome

Maintainers and library users must be able to test the advertised contract of the implementation they actually use. Ship a developer conformance API, versioned scenarios/fixtures, and an independently usable installed operator route. Preserve every applicable historical failure, including ones discovered in native code, without making every package depend on every environment.

Product migration is later. Package qualification uses real independently built reference clients and real production paths; it never claims that p11scope, OSSLscope, KryProbe or MemVeil has migrated. The [research delivery workflow](../../research/2026-10-17-shared-libraries/testing-delivery-plan.md) supplies the issue lifecycle; this specification makes its interfaces and acceptance executable work.

## Requirements

| ID | Requirement | Acceptance criterion |
|---|---|---|
| TT-R01 | Version and trace every contract/case/fixture/profile. | H01–H33, UC01–UC14, G01–G23 and all research TODO items resolve to implementation/disposition tasks. Selected families expand into named subcases with exact donor/WIP pins, oracle, control and required cells. |
| TT-R02 | Bind results to the actual subject. | A deliberately different crate version, feature union, backend, executable, BPF object or fixture prevents qualification. Testkit cannot silently exercise its own separately resolved production dependency. |
| TT-R03 | Separate production observations from expected truth. | Independent fixture/workload/model expectations are fixed or recorded through their own causal channel before comparison. A constant-success/wrong-domain/wrong-value implementation fails its named assertion. |
| TT-R04 | Fix required coverage before environment discovery. | Missing/denied/untriggered required cells remain incomplete; removing a required case or positive population cannot turn a profile green. |
| TT-R05 | Preserve independent assertion, capability, coverage, harness and cleanup results. | Expected refusal may pass while capability is denied/unknown; assertion failure, invalid harness and unresolved required custody cannot yield qualification. |
| TT-R06 | Exercise real ownership and filesystem behavior. | Controlled replacement, collision, copy-up, namespace churn, in-place mutation and both mapping policies pass their named real cells with independent raw evidence. |
| TT-R07 | Exercise final objects and actual kernel behavior where claimed. | Final object digest is the one loaded/executed; map/attach/event/ordering/cleanup assertions have active independent workloads and correctly scoped old/current/reproducer controls. |
| TT-R08 | Test failure paths and the harness itself. | Every named transfer/commit barrier and verdict branch has deterministic negative controls; setup failure cannot pass a semantic negative, retries cannot erase failures, forged success summaries fail. |
| TT-R09 | Combine tests according to their proof limits. | Table/property/model/fuzz/Miri/native-sanitizer/object/host/live tests cover distinct uncertainties and record bounds; model success never becomes kernel proof. |
| TT-R10 | Deliver complete offline run-only packages. | Installed checks run from a read-only prefix with separate writable roots, no donor source/network/compiler, through exact reference clients and operator binary. |
| TT-R11 | Select changed checks by causal impact. | Source/dependency/features/compiler/oracle/fixture changes select all affected contracts and cells; unknown impact broadens the named boundary. Path-only filters cannot discard required work. |
| TT-R12 | Bound tests, resource custody and retained evidence. | Owned scratch/worker/map/link resources respect declared caps; outer timeout retains unresolved custody; persistent resources have identity-checked recovery, ordinary tests do not require permanent journals. |
| TT-R13 | Measure performance and coexistence without hiding correctness. | Peak resources and operation complexity meet declared bounds; measured regressions have an explicit decision; two concurrent observers never retire each other's resources. |
| TT-R14 | Make support and documentation derive from qualified profiles. | Examples and published support entries reference real candidate results; missing required cells remain visible. Source-only, model, historical and installed evidence remain distinct. |

## Package and file structure

`crates/scopebase-testkit/src/` owns `ids.rs`, `adapter.rs`, `catalog.rs`, `profile.rs`, `observation.rs`, `oracle.rs`, `result.rs`, `runner.rs`, `fixture.rs`, and `artifact.rs`. The default crate supports pure contracts and TT02’s bounded vector-file session; optional `linux-fixtures` later enables TT03-owned host fixtures in a separate Linux module. TT02 owns the `FixtureSession` trait and `fixture.rs`; TT03 implements that existing seam rather than replacing it. The [TT02 engine addendum](2026-10-18-scopebase-tt02-engine.md#delivery-and-ownership) fixes its delivered corpus and exact file ownership. Case semantics live in focused `cases/linux.rs`, `cases/bpf.rs`, `cases/capture.rs` modules, with schema decoders beside their cases. They must not contain a second production resolver/reducer.

`crates/scopebase-conformance/` owns the operator command. `fixtures/{vectors,linux,bpf,native}/` owns independently authored data/workers; `profiles/` owns immutable-version required-case and environment manifests; `tests/downstream/` owns independent consumer workspaces. `tools/qualification/` owns provisioner/admission/cleanup scripts and CI selection, while `tools/bpf-compat/` and BPF producers belong to the TC/BP plan. Production packages have dev-dependencies or external adapters only; they never depend on testkit at runtime.

## Exact public adapter seam

The shared session seam has four arguments. The [TT02 engine addendum](2026-10-18-scopebase-tt02-engine.md#exact-public-seam-and-type-rules) defines the exact traits, immutable checked values, schemas and constructors. It replaces earlier concrete-session/oracle-observation-only forms.

```rust
pub fn run_profile(
    plan: &ProfilePlan,
    adapter: &mut dyn ConformanceAdapter,
    fixtures: &mut dyn FixtureSession,
    oracle: &dyn CaseOracle,
) -> Result<RunReport, HarnessError>;
```

`ConformanceAdapter` provides `subject`, `execute` and explicit `retire`. `FixtureSession` provides `contract`, `cancellation_requested`, `prepare`, `collect` and explicit `retire`; successful prepare/collect report newly created effects. `FixtureAccess<'_>` lends only that invocation's admitted inputs/resources, is neither Clone nor serializable, and is dropped before collect. `CaseOracle` provides `identity` and evaluates independent `ExpectedEvidence` against `CaseOutcome::Observed` or `CaseOutcome::OperationError`; a prepare failure cannot be an operation-under-test refusal. Partial operation progress and effects remain visible.

The external `RunContract` freezes exact catalog/selection, subject/build/artifacts, oracle, scripts, assertion prerequisites, attempts and limits. The additive read-only `CaseCatalog::source_sha256() -> Digest256` hashes the exact successfully admitted catalog bytes without changing TT01 lookup, wire or selection semantics. Four registered source roles and the separately measured consumer executable/final-object roles cannot substitute for one another. The [post-build binding recipe](2026-10-18-scopebase-tt02-engine.md#frozen-subjectbuild-recipe-and-actual-byte-checks) uses independently chosen expected inputs and measured actual completed consumer bytes, without a self-hashing executable cycle.

The [honest metadata prelude](2026-10-18-scopebase-tt02-engine.md#runner-binding-and-execution-state-machine) calls custom contract/subject/oracle code before preparation, with a no-effects/no-discovery obligation; it is neither a sandbox nor a hard timeout. Borrowed resources and descriptive provenance never reconstruct runtime authority. Independent truth and wrong-value controls remain mandatory.

`CaseId::parse` retains its 1–96 byte ASCII grammar; `ProfileId` retains its 64-byte cap. Exact `(CaseId, positive u32 revision)` lookup never selects latest. The addendum preserves TT01 admission semantics and separately bounds execution; it does not impose its Label grammar on existing cell strings.

The [32-field RunLimits contract](2026-10-18-scopebase-tt02-engine.md#exact-limits-and-bounded-artifact-measurement) retains 8 MiB parser/vector/observation/receipt limits, 4,096 planned attempts and 64 KiB diagnostics. Streamed executable/object measurement has separate finite file/work/read budgets and one 65,536-byte buffer. `new` explicitly chooses valid values up to hard maxima; `lowered` can only reduce its receiver, and external contract admission uses an explicit caller ceiling. No silent clamp, selection filtering or arbitrary larger parser profile is permitted.

TT01 admits all exact references, including inactive conditional requirements. Every declared root must reject an active closure requesting two revisions of the same CaseId, even with disjoint cells or different profile stems. Requirements merge only for the same case/revision/cell, retaining sorted declaring `required_by` identities. A condition mentioning an extension neither selects it nor creates a dependency edge; H33 runtime linkage is conditional on the base BTF shape profile. Selection transport compares exact revisions as well as every required-cell field.

Baseline validation retains every historical case pair and its owners, obligations, cells and referenced cell semantics, including unselected records. Old profile/extension declarations and their conditional predicates stay fixed in DRAFT as well as FROZEN; a successor revision does not authorize rewriting an old identity. Independently authored revision A/B fixtures retain the complete canonical task/family/obligation/profile envelope, with literal old/new expected closures and exact wrong-version controls.

Registry `definition_complete` describes a nonempty frozen definition, not executable readiness or task/profile qualification. Open owners are the selected profiles' explicit open-owner union; an extension's static task references do not perpetually make its definition incomplete. Initial cases are UNIMPLEMENTED and profiles DRAFT. REGISTERED_EXECUTABLE records admit bounded artifact metadata and locally checked bytes without executing them or creating runtime authority. Existing source descriptions are preserved verbatim; a missing family description uses its explicit research short contract, while absent obligation prose stays an empty required field rather than invented text. Every reference/ownership edge, including scalar case-family references, is charged before unbounded collection growth.

`scopebase-testkit` must not expose a safe custom-backend path that can cause unchecked buffer access. Structurally valid but false custom observations cannot be detected universally; the verdict records the adapter/oracle trust boundary. No report deserializer yields a live process/file/mapping/attachment capability.

The [ratified TT03 fixture addendum](2026-10-22-scopebase-tt03-linux-fixture.md), [complete normative support](tt03-linux/protocol.md) and [verification plan](../plans/2026-10-22-scopebase-tt03-verification.md) govern the concrete Linux provider/worker, full-key transport, independent raw truth, immutable counters, creator guard and original-owner outer/constructor cleanup. They preserve the accepted TT02 seam and the original fourteen P/seven F populations. This is design only: actual product/C7/provider/realm/EOF/audit/joint/execution bindings remain UNBOUND, and full TT03 remains planned.

## Result and verdict contract

The [closed intent/cause/capability matrix](2026-10-18-scopebase-tt02-engine.md#intent-cause-and-capability-matrix) and [strict contract-bound receipt rules](2026-10-18-scopebase-tt02-engine.md#result-schema-actual-contract-matching-and-import-boundary) govern the engine. Every case result preserves separate fields:

| Field | Values / rule |
|---|---|
| `execution` | `completed`, `blocked`, `not_run`, `skipped`, `harness_error`; skipped cases retain their required/optional selection status |
| `assertion` | `pass`, `fail`, `not_judged`; setup failure is not an operation-under-test semantic negative; assertion-specific missing coverage/twin prerequisites yield not_judged |
| `capability` | `supported`, `unsupported`, `denied`, `unknown`, `incompatible`, `not_applicable`, with method/context |
| `coverage` | Required branches/triggers/populations and achieved counts, including missing obligations |
| `harness` | Artifact/fixture/oracle/selection validation and handshake results |
| `cleanup` | `complete`, `unresolved`, `not_required`, with only owned pending resources and recovery information |
| `qualification` | `qualified`, `failed`, `incomplete`, `invalid`; computed from the frozen profile, not supplied by the adapter |

Qualification precedence is `Invalid > Failed > Incomplete > Qualified` across every frozen required attempt. Gate each assertion only on its declared coverage/positive-twin prerequisites: a missing twin does not hide an independently valid wrong-byte Fail. PositiveSupport requires Supported; cause-specific ExpectedRefusal requires its exact operation/step/stage/cause, functional positive twin and the matching Denied/Incompatible/Unsupported state. AssertionOnly may qualify only with Unknown/NotApplicable and makes no positive support claim. Preserve all underlying results, explicit entered stages, bindings and unresolved custody. A later passing attempt cannot erase a prior failure.

Operator exit codes are 0 success (describe/plan emitted, run qualified, receipt verified, cleanup done), 1 verdict failure (cases failed, receipt invalid or tampered, engine Invalid qualification), 2 usage error (bad argv, unknown option or mapping policy), 3 incomplete (missing input, unknown profile, no bound adapter, refused cleanup), and 64 broken package (tampered closure, missing notices, mismatched subject). Invalid input/harness outcomes map to exit 1, not 3. Successful `describe` and `plan` use exit 0 with `qualification: not_evaluated`; they do not claim behavioral support. Successful structural receipt verification uses exit 0 reporting the recorded qualification. A syntactically valid receipt containing a failed result remains failed when its profile verdict is verified. Signal termination preserves a partial run if possible and never fabricates a terminal success.

Ratification note (controller ruling RATIFY-2026-10-23-TT07-EXIT, binding): the pre-TT07 draft of this table (2 incomplete / 3 invalid / 64 usage) is superseded by the implemented convention above (0 ok, 1 failure including invalid, 2 usage, 3 incomplete, 64 broken package). It matches accepted TT08 (exit 3 = INCOMPLETE, `tools/qualification/ci_local.sh`) and the TT03 worker precedent (usage = 2, `crates/scopebase-testkit/src/bin/scopebase-tt03-worker.rs`); engine `Invalid` maps to exit 1 via `exit_for_qualification` (`crates/scopebase-conformance/src/delivery.rs`) and `ReceiptInvalid`/`Engine` map to exit 1 via `exit_for_kind` (`crates/scopebase-conformance/src/error.rs`), with `commands.rs` dispatch unchanged. This section now describes the implementation exactly.

The result schema starts at major version 1. `RunReport::from_json` binds to the separately supplied actual RunContract and recomputes selection, assertion gates, intent matrix and effect ledger; imported origin is always Imported. It neither reruns an arbitrary oracle nor authenticates coherent claims or produces live capabilities. The required runner observations retain actual entry/final subject/oracle values and fixed raw elapsed/cancellation checkpoints, including completion, so missing final checks or a late stop survives successful cases and import. Deterministic case/run terminal-after-cleanup references and exact operation/script/schema/tier/registration matches are required. Reject duplicate JSON members, duplicate case/terminal IDs, trailing data, non-finite numbers, booleans as counts, invalid decimal-u64 text, overflows and contradictory summary fields. Required schema fields are not defaulted from absence to zero. A local digest binds bytes but is not authenticity or a trusted-host claim. No evidence-signing service is needed.

## Required profiles and evidence selection

The normative base catalog lives at `profiles/cases-v1.json`; profile manifests name exact subcases, tiers and cell IDs. The research catalog's family tier inventories are descriptive; they cannot be executed as a blanket union or interpreted as no requirements.

| Canonical runnable profile ID | Required contract selection |
|---|---|
| `held-file-v1` | H04/H06 file-only branches; applicable G01–G11/G18–G22; UC01/UC08–UC11/UC13/UC14; no attachment claim |
| `mapped-image-v1` | Held-file plus H05, UC02–UC07, real namespace/filesystem and both mapping policies; UC12 only in added attachment profile |
| `process-observation-v1` | H01/H02 observation, birth/view continuity and stale/reused PID controls; no signaling authority |
| `owned-child-v1` | H02/H20 and caller-fork/global-state/cancellation/custody obligations, actual subprocesses |
| `bounded-walk-v1` | Discovery work/read/retained/clock limits and actual directory mutation; no permanent snapshot claim |
| `bpf-host-v1` | Host arithmetic, geometry, parser/planner/reader contracts and available real metadata/mapping paths from BP; no load/attach claim |
| `bpf-aya-uprobe-v1` | Actual Aya backend maps, ring, attach and retained-owner paths; H04/H07–H09/H12/H19/H21/H22, UC12/selected UC13 and reachable ABI cases with active positive/excluded populations |
| `bpf-libbpf-uprobe-v1` | Actual selected libbpf paths; H07/H10–H13/H19/H21/H22 as advertised; fixed-boundary behavior refuses if native API cannot supply it |
| `btf-shape-le-v1` | H08/H10/H11 bounded graph/shape/final-object linkage; real kernel key/value IDs additionally required when claiming runtime linkage |
| `producer-task-exec-v1` | H01/H03/H08 producer identity, independent exec ledger, map exhaustion and stale-domain controls; per-cell shape/refusal is explicit |
| `aggregate-writer-x86-v1` | H14–H18 per-program writer, reentry, possible-CPU ABI, diagnostic and startup/closure cases; real producer/map paths, architecture scope preserved |
| `compiler-object-v1` | H07–H11/H29–H32 selected final emitted objects, affected/fixed compiler controls and offline inspection |
| `compiler-runtime-x86-v1` | Same admitted final hashes in actual ISA/verifier/runtime cells; loading alone never proves old/new-value, filtering or cleanup semantics |
| `capture-core-v1` | H03/H15/H17/H18/H23–H27 applicable pure evidence/model/conservation branches and two distinct real reference clients |
| `capture-json-v1` | `capture-core-v1` plus strict JSON replay/framing, exact integer and duplicate/member/terminal/version negatives |
| `sdk-host-v1`, `sdk-live-aya-v1` | Applicable qualified component profiles plus SDK startup/output/stop/degradation contracts; live route is a separate explicit profile |
| `native-v1`, `mojo-elf-v1` | H13/H16/H28/H32 and native/producer obligations selected by the actual interface; independently installed C/Mojo consumers |

The v1 IDs in these initial planning tables, commands and exact-ID assertions are pinned planning references, not forever-fixed runnable versions. BP's `direct-no-children-v1` is a compiler build-scope contract, not a conformance profile. Case identifiers use dotted suffixes such as `H15.abi-stride`; slash-separated prose references never become `CaseId` values. Same-ID refinement may clarify implementation while preserving every recorded required semantic; it cannot change required cases, cells, component or extension versions, or support closure. Any such change requires an explicit successor profile ID, including while DRAFT: retain the old ID and definition, and update literal tests, commands, traceability and affected composition references together before discovery or execution. Canonical names are versioned exact identities, never aliases or automatic “latest” selectors; expected versions and required closures are selected literally by the controller and are never derived from candidate data. TT01 freezes each selected manifest before environment discovery.

A composite selection must expand to its entire required component-profile closure before fixture/environment discovery. The registry's `profiles[].requires_profiles` defines this graph; `requires_extensions` adds only declared versioned capabilities. The runner stores both requested and expanded selections, and TT10 independently recomputes them. A receipt that lists only the top-level SDK/native result while omitting a required component result is incomplete even when the supplied result is green. Unknown IDs, cycles and conflicting versions are invalid. No component-profile dependency may be disabled because its environment is absent.

Required composition: the host SDK uses held-file and capture-core; the live SDK also uses the Aya-uprobe and owned-child profiles. Both uprobe profiles require held-file and compiler-object; producer/aggregate/runtime compiler profiles require compiler-object. Native validation uses capture-core and the native standard-object route; Mojo ELF uses BPF-host, compiler-object and BTF shape with the declared runtime-linkage extension. Capture JSON includes capture-core. Complete M5 requires `sdk-live-aya-v1` (which includes host); complete M6 requires `native-v1` (which includes `mojo-elf-v1`).

The BTF base profile covers host graphs and final objects. `btf-runtime-linkage-v1` is a versioned **extension identifier**, not a standalone runnable profile. It is bound to `btf-shape-le-v1` and adds actual kernel key/value linkage checks plus TT05/TC07. Registry gates use an explicit `when_extensions` condition for it; free-text reasons do not determine execution. The selected extension set is part of the immutable profile/result binding and cannot be dropped after discovery. Base-only results cannot claim the extension.

Additional backend profiles are new declared obligations, not automatic aliases of Aya. A development subset is useful but reports `development_subset` and cannot claim its parent profile qualified. The initial v1 strings are pinned planning references. A change to recorded required cases, cells, component or extension versions, or support closure requires an explicit successor ID even in DRAFT; retain the old definition and update literal tests, commands, traceability and affected compositions together before discovery or execution. Same-ID refinement preserves all required semantics. Discovering that a case is unavailable cannot change a version in place.

## Finite real filesystem matrix

TT04 creates provisioner manifests and immutable base-image/config identities for the following cell groups. A single cell can serve several subcases. Initial positive host qualification covers the project-spec 5.15/6.12/current environments; filesystem-trigger cells use the actual environment needed to demonstrate the behavior and record that narrower scope. Do not multiply every compiler with every filesystem.

| Cell IDs | Required fixture / independent evidence |
|---|---|
| FS01 | Ordinary ext4 control: owned A/B files, hardlink alias, rename/delete and actual mapped ranges; independent bytes and retained worker FDs |
| FS02–FS03 | Btrfs base/subvolume stat-versus-maps split and distinct snapshot/subvolume objects with actually colliding raw maps keys; independent subvolume/mount/raw-range evidence |
| FS04–FS05 | Overlay xino off/on with metacopy off, named lower/upper/work placement; lower-only and upper-existing files, aligned and split observations |
| FS06 | Independently observed overlay copy-up while old FD/range remains held; new acquisition must not inherit old-object evidence |
| FS07 | Overlay metacopy-on behavior as a separately declared profile with its own verified metadata/data transition, or explicitly unsupported with exercised refusal until this cell qualifies |
| FS08 | Foreign mount namespace and wrong-view negative; synchronized bind/mount churn while retained views remain distinct |
| FS09 | Actually restricted credential/proc/mmap denial; no root-bypassed mode-bit test credited as denial |
| FS10 | Independent syscall audit detects even transient target-backed mmap during the production no-new-mapping phase; allocator/runtime maps are outside that target-scoped promise |

FS02/03/05/06 require their actual split/collision/copy-up triggers. A fixture that does not produce one is unexercised, not passing. The aligned or refusal branch can pass separately. Unknown or unsupported conversion returns its specified outcome; tests never force equality merely to obtain a positive. Exact range identity requires the stronger evidence specified by LX, not raw maps-key equality.

Default user runs consume an explicitly supplied writable scratch root and create only owned files/workers. Privileged filesystem/namespace provisioners are separate commands in disposable guests or explicitly selected environments. They never format an arbitrary device, auto-mount host paths or broaden privileges to turn a denial green. Preprovisioned manifests are inspected against actual mounts and ownership before use. Ship the audit worker and declare tracing prerequisites; denied audit remains an explicit missing enforcement subcase.

## Test techniques and sensitivity

Use deterministic transition barriers and separate fixture truth first. Named ownership/commit/error branches require table/fault tests; parser and arithmetic boundaries require invalid/overflow/N/N+1 inputs; simultaneous consumers require explicit schedules. Model code must be small and independently derived from the contract, not a copy of production logic.

Property tests use fixed regression seeds plus generated valid/invalid histories, shrink failures and persist minimized examples. The initial focused CI budget is 512 generated cases per affected property; that is a reproducible exploration budget, not a correctness percentage. Each parser/decoder has a fuzz target and checked-in minimized seeds. Initial qualification runs at least one recorded 60-minute campaign per target; scheduled affected-target runs use 10 minutes. A reported crash/semantic counterexample blocks the affected claim until triaged and fixed or scoped out explicitly. Corpus growth is bounded and duplicate minimized inputs are removed deliberately.

Loom/Shuttle are used only for represented Rust synchronization. Each selected model states thread/operation/preemption bounds and must exhaust its configured finite search or report incomplete; omitted syscalls/mmap/BPF/FFI are listed. Miri targets supported pure unsafe boundaries. Native ASan/UBSan run supported C/FFI fixtures; thread sanitizer is added only to interfaces advertising concurrency and with known tool limitations recorded. None of these closes a live-kernel gate.

Real integration uses IPC barriers, not sleeps as synchronization proofs. For schedules needing stress, define workload IDs, intended transition counters, repetitions and a wall-clock cap before running. At least one observed intended trigger is required, plus the case's independently expected population; elapsed stress time alone proves nothing. Reproduction and repaired-kernel controls remain distinct for H09. H29 asserts both old return and new memory values; concurrent atomic ordering has its own case.

The runner's own mandatory planted-invalid controls are: wrong library/object/worker, modified fixture, replayed unrelated ledger, missing trigger, empty positives, inactive excluded target, silent case filtering, setup errno disguised as mismatch, unknown schema, duplicate terminal, false zero-exit summary, leaked ownership and stale receipt reuse. Each rejection has a restored valid twin. A known-bad control is detected only at its intended assertion layer; an unrelated crash or compiler failure does not count.

## Distributed execution and CI

The operator exposes `describe`, `plan`, `run`, `verify-receipt` and identity-checked `cleanup`. These are future commands defined by TT07. `run` requires an explicit profile and fixture/output roots; active effects appear in the plan and CLI documentation. `--mapping-policy no-new-target-mappings` and `allow-private-calibration` are separate tested policies. Missing dependencies are explained; no automatic network, compiler installation or privilege changes occur.

Build packaged source archives in fresh downstream workspaces with independent lockfiles and no sibling-source resolution. Test documented minimal/default/feature unions and MSRV/current compiler, plus doctests explicitly. Then run the installed offline closure from a read-only prefix without source/compilers/network. An installed standalone command qualifies its compiled subject only. Application users embed the adapter/command against their own resolved version for application-specific evidence.

CI has fast contract/API/package checks, selected object builds, owned host fixtures, isolated live cells, and scheduled broad fuzz/performance/compatibility lanes. The change author records affected contracts and the reviewer checks exclusions. Dependency, feature, compiler, fixture and oracle changes can affect unchanged production files. Requalify affected results when inputs change. Do not rerun unaffected successful cells merely to increase counts.

Execution lanes have unique build/output/run roots and explicit ownership. One writer owns shared Cargo/workspace/ABI manifests. Privileged guests/host resources and heavy builds are leased; never run parallel live tests against the same mutable fixture or object path. A failed fixture or escaped owner stops dependent execution but need not stop independent pure work.

## Cleanup, evidence and performance

TT02 uses the [immutable effect ledger and cumulative retirement schedule](2026-10-18-scopebase-tt02-engine.md#effect-ledger-and-retirement-reconciliation): fixed adapter-then-fixture slots at case and run scopes, one cumulative allowance, no zero-budget callback, explicit uncalled participation outcomes, and sticky unknown inventory. Only an explicit exact-owner/origin Pending→Retired transition may settle known custody; a later run-scope transition retains the earlier case-end state. Drop, empty snapshots, zero exit and timeout cannot certify retirement. Byte/work/retention/cardinality bounds and cooperative timing have distinct proof limits. Stronger Linux/process supervision belongs to TT03/TT05/TT07.

Ordinary in-process tests use owned handles and a bounded run marker. Persistent mounts/pins or crash-recovery profiles record identity-checked durable custody before handoff. A durable text record cannot recreate a lost live capability. Abrupt death means reconciliation, not proof that Drop ran. Explicit cleanup errors remain visible; repeated unresolved resources exhaust admission rather than accumulating without a bound.

Keep minimized failures and compact qualification manifests: candidate/package/build/object hashes, exact dependency/features/toolchain, case/fixture/oracle/profile versions, selected cells and effective context, workload/trigger counts, seed/model limits, resource peaks and cleanup. Ordinary unit tests do not require permanent raw transcripts. Sharing sanitized diagnostics is opt-in; there is no automatic upload.

Performance tests freeze workloads and observable resource units before optimization. Include allocation peaks during reallocation/clone, FD/worker/link counts, scan/attach attempts, queue/reservation conservation, and two supported concurrent consumers. Gate correctness on declared bounds and algorithmic caps. Report wall-time/CPU distributions against a same-environment baseline; a justified measured tradeoff can be reviewed, but a cap violation cannot be waived as performance noise.

## Definition of done

A testing capability is ready only when case selection, fixture truth, known-bad sensitivity, subject binding, result validation, cleanup and installed delivery are themselves tested. Every advertised profile must have all required subcases/cells accounted for and passing at its exact candidate versions. Missing required environments stay open. Documentation names supported/refused/unknown behavior and effects accurately. Product-migration regressions remain separately open until their applications change.

The [testing implementation plan](../plans/2026-10-17-scopebase-testing.md) assigns all TT requirements, interfaces, fixtures, negative controls and delivery steps to TT01–TT10. The [master traceability registry](../plans/2026-10-17-scopebase-traceability.json) retains every source obligation and its owner.
