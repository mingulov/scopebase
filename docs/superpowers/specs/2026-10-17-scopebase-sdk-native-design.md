# ScopeBase SDK and selective native interoperability design

Date: 2026-10-17. Status: proposed specification for future implementation. This document implements no SDK, native library, reference application, compiler support or qualification. ScopeBase is the project branding; `scopebase-sdk` and `scopebase-ffi` are proposed package names, with availability and publication still unverified. Product migrations are later MG work, not a prerequisite for building independently usable reference applications.

Read with the [project design](2026-10-17-scopebase-design.md), [Linux design](2026-10-17-scopebase-linux-design.md), [BPF/toolchain design](2026-10-17-scopebase-bpf-toolchain-design.md), [capture design](2026-10-17-scopebase-capture-design.md), [testing design](2026-10-17-scopebase-testing-design.md), [implementation plan](../plans/2026-10-17-scopebase-sdk-native.md), and existing [overlap analysis](../../research/2026-10-17-shared-libraries/overlap-matrix.md). Cross-document interfaces are integration contracts; missing qualifications in another component remain missing when the SDK imports it. Initial Rust package version is `0.1.0` on `x86_64-unknown-linux-gnu`; extra target support requires explicit qualification. Original code follows the root SB01-reviewed license policy; no imported file is silently relicensed.

## Deliverables and ordering

Priority 2 delivers a small, host-first `scopebase-sdk`, an independently installable non-crypto observer, a standalone starter project, and a selected live BPF observer recipe. The host-only package is an earlier submilestone; complete priority-2 acceptance requires both actual host and live integrations. This is application composition software: selecting a profile, making permitted effects and resource limits explicit, aggregating diagnostics without inventing evidence, and connecting existing component sessions to application-owned orchestration. It does not introduce a shared daemon, loader, process tracker, global registry or universal batch/live driver.

Priority 3 delivers independently authored Rust/C/Mojo vectors, an exact consumed-versus-candidate libbpf-mojo capability audit, direct reusable native regression additions, a standard ELF/BTF object integration recipe, and a narrowly scoped Rust C ABI with independently useful C and Mojo reference clients. Native vector and audit work may begin before SDK completion. The C ABI follows demonstrated need for ScopeBase capture validation; it is not the BPF transport bridge. Rust components and their default builds never require a C/Mojo runtime, libbpf, BPF compiler or privileged host setup.

An independent application is an executable with its own application logic, meaningful workload, expected results and distribution instructions. A wrapper that merely runs crate tests does not count. The SDK observer and the standalone reference applications in the Rust/testing designs establish composition before MG product migrations. A later p11scope/KryProbe/OSSLscope/MemVeil migration still needs its own changed-tip tests and duplicate-retirement decision.

## Evidence and source selections

The donor reports were read, not their tests rerun. The [KryProbe note](../../research/2026-10-17-shared-libraries/kryprobe.md) records main `d153f3aaf9a3931337b47c9e1b046c692da55083` and moving selftest work `67173c8dbeb33cba114ca68f8cc5cc475c7a6427`; ADR-0007's split drivers and checked session vocabulary are design inputs. The evolving selftest AST analyzer is not an SDK dependency or trusted generic analyzer. Main versus WIP qualification remains distinct.

The [native donor note](../../research/2026-10-17-shared-libraries/memveil.md) records MemVeil `8307a17d4c1d01d2e6fa66679f0e7bed113fa416`, consuming libbpf-mojo source `681096cb588379307d0c8e94e1d77e53de4be22f` with source-bundle SHA-256 `c5a3fd69e0afc00a5dcb16909bad5ad65f8d583e7e0f80936aeab8fd3b836253`. Sibling main was `ff6ea5087cb6cab3db51a9ffaf99922f880da8c9`; joint integration was `54bcebd5e7e417694e1f0cae2d3a50a20ddc382c`. These are source selections to refresh before implementation, not proof of what MemVeil currently executes. Recorded Mojo 1.1.0 compiler `8189361e`, libbpf 1.7.0 `f5dcbae736e5d7f83a35718e01be1a8e3010fa39`, and clang 21.1.8 are historical metadata until actual binary identities are captured.

Important existing native regression inputs are `tests/native/ring_conformance.c`, `native/src/ring_stage.h`, `native/src/object_maps.c`, `tests/native/generic_object.c`, `native/include/libbpf_mojo_generic.h`, and `docs/ownership.md` in the selected libbpf-mojo tree. Fixes `59fd017a8ebb805be49364172057de8181b0bafb` (transactional configuration), `c5ea7eafe29097f6c182e76575ccb27409ec67a5` (bloom lookup refusal), and `497279c63c247922dfc3f516e6e09c7a623f1478` (shared ring staging/statistics) require separate inclusion/removal records. Historical live tracepoint/cleanup claims on the joint tip exclude other generic loading/map/test-run/consumer gates. They do not qualify new bytes or every bridge operation.

## SDK requirements

| ID | Required behavior and acceptance |
|---|---|
| SDK-R01 | `scopebase-sdk` composes public components with explicit Cargo features. Rust edition 2021; proposed MSRV 1.88.0, requiring actual qualification. Default host build has no BPF/native/Mojo tool invocation or privilege changes. Independent downstream default and supported feature-union builds prove this. |
| SDK-R02 | Profile declares required capabilities and admitted effects before probing environments. `Unsupported`, `Denied`, `Unknown` and `Incompatible` remain distinct. A successful refusal case never upgrades capability support; imported reports cannot construct runtime authority. |
| SDK-R03 | Resource configuration separates input bytes, retained bytes, visited work, live owners, diagnostics and elapsed wait. Invalid/zero/overflowing limits are refused before effects. Time allowance is an observation deadline, not guaranteed syscall interruption or cleanup. |
| SDK-R04 | App context integrates capture epoch/window metadata and component bindings while leaving application state machines, scopes, privacy and session closure local. A summary carries the actual component's receipt strength; no SDK `close()` or `drain()` may synthesize quiescence. |
| SDK-R05 | Diagnostics are opt-in, bounded, structured and inert by default. No implicit logging or raw captured bytes; byte paths use safe escaping in display. Exceeding diagnostic count/byte allowance produces an explicit truncation count, never silent disappearance or arithmetic wrap. |
| SDK-R06 | The owned-workload file observer is a genuine non-crypto application of the Linux and capture components. It observes held descriptors, independently generated A/B file contents and path replacement; it reports effects, limits, inconclusive states and final owner disposition. It neither scans unrelated processes nor changes credentials, limits, signals or namespaces. |
| SDK-R07 | An owned fixture ledger establishes expectations independently of production reads and capture reducers. Positive A and active negative B both execute. A path-reopen mutant, unknown-as-zero mutant and fabricated complete-session mutant each fail their intended assertion after verified setup. |
| SDK-R08 | The standalone starter builds outside the monorepo against packaged artifacts and invokes the developer conformance API on its own linked production adapter. It includes application-owned host and optional BPF orchestration examples, not copied loader/tracker implementations. |
| SDK-R09 | A selected non-crypto BPF observer recipe uses the existing Aya backend through `scopebase-bpf`; its independent workload, final ELF/BTF inspection, live positive/negative and cleanup gates are required for complete SDK acceptance. Its build/run is opt-in for users and is not a default Rust dependency. Host-only package readiness remains a separate submilestone. |
| SDK-R10 | Two concurrent SDK host contexts have independent epochs, limits, fixture roots, diagnostics and owner outcomes. No hidden global lock, signal handler or resource registry is introduced. Shared backend resources require explicit adapter ownership. |
| SDK-R11 | Packaging includes versioned profile documentation, developer conformance calls and an installed operator route from the delivered artifacts. Offline checks work after staging prerequisites with no donor/monorepo checkout. Exact dependency versions/features and executable/library hashes bind results. |
| SDK-R12 | SDK compatibility, feature additions, MSRV policy, provenance and donor issue/removal records are published with the package. Completion maps every advertised operation to a required case and qualified cell; missing required cells remain incomplete. MG migration readiness is reported separately. |

## SDK interface and package boundary

Proposed files are `crates/scopebase-sdk/src/{lib,profile,limits,context,diagnostic}.rs`, `crates/scopebase-sdk/tests/{profile,limits,context,diagnostic,isolated_contexts}.rs`, and `crates/scopebase-sdk/README.md`. The crate depends by default on `scopebase-capture`'s pure standard-library API. `linux` adds `scopebase-linux`; `bpf` adds `linux` and `scopebase-bpf`, without selecting both loader ecosystems. The reference observer enables `linux`; JSON output enables the capture crate's optional `json` feature. Cargo feature unification may add APIs/dependencies but never grant effects or make denied capabilities supported.

The SDK owns these exact new API names. Value enums and borrowed report descriptors are Copy/Clone where their fields permit; owned reports/bindings are Clone but AppContext is not Clone. Input vectors and caller copies are not a global shared budget. The live-owner/work/wait limits are explicit configuration propagated to the selected component, not proof that AppContext controls external resources:

```rust
pub enum CapabilityState { Supported, Unsupported, Denied, Unknown, Incompatible }
pub enum Effect {
    ReadOwnedFiles, WriteOwnedFixtures, PrivateReadOnlyCalibration,
    SpawnOwnedChild, LoadBpf,
}
pub struct CapabilityRequirement { pub id: &'static str, pub required: bool }
pub struct Profile { /* private, validated fields */ }
pub struct Limits {
    pub input_bytes: u64, pub retained_bytes: u64, pub work_items: u64,
    pub live_owners: u32, pub diagnostic_count: u32, pub diagnostic_bytes: u64,
    pub wait: std::time::Duration,
}
impl Profile {
    pub fn new(id: &'static str, required: Vec<CapabilityRequirement>,
               effects: Vec<Effect>) -> Result<Self, ProfileError>;
    pub fn id(&self) -> &'static str;
    pub fn permits(&self, effect: Effect) -> bool;
}
impl Limits { pub fn validate(&self) -> Result<(), LimitsError>; }
pub struct CapabilityObservation {
    pub id: &'static str, pub state: CapabilityState,
    pub source: &'static str, // report provenance, never executable authority
}
pub struct ComponentBinding {
    pub package: String, pub version: String, pub features: Vec<String>,
    pub backend: Option<String>, pub artifact_sha256: Option<[u8; 32]>,
}
pub struct AppContext { /* profile, limits, bounded diagnostics and metadata */ }
impl AppContext {
    pub fn new(profile: Profile, limits: Limits) -> Result<Self, ContextError>;
    pub fn profile(&self) -> &Profile;
    pub fn observe(&mut self, report: CapabilityObservation) -> Result<(), ContextError>;
    pub fn bind(&mut self, binding: ComponentBinding) -> Result<(), ContextError>;
    pub fn admission(&self) -> Admission;
    pub fn diagnostic(&mut self, value: Diagnostic<'_>) -> DiagnosticDisposition;
    pub fn capture(&mut self,
        report: &scopebase_capture::neutral::ValidatedNeutralV1
    ) -> Result<(), ContextError>;
    pub fn report(&self) -> ContextReport<'_>;
}
pub enum Admission { Ready, Incomplete, Refused }
pub enum DiagnosticDisposition { Retained, Truncated }
pub enum Severity { Note, Warning, Error }
pub enum Stage { Configuration, Admission, Observation, Output, Retirement }
pub enum EffectState { None, Partial, Unresolved }
pub struct Diagnostic<'a> {
    pub code: &'static str, pub severity: Severity, pub stage: Stage,
    pub effect: EffectState, pub text: &'a str, pub path: Option<&'a [u8]>,
}
pub struct RetainedDiagnostic {
    pub code: &'static str, pub severity: Severity, pub stage: Stage,
    pub effect: EffectState, pub text: String, pub escaped_path: Option<String>,
}
pub struct OmittedDiagnostics { pub count: u64, pub at_least: bool }
pub struct ContextReport<'a> {
    pub profile: &'static str, pub admission: Admission, pub limits: &'a Limits,
    pub observations: &'a [CapabilityObservation], pub bindings: &'a [ComponentBinding],
    pub diagnostics: &'a [RetainedDiagnostic], pub omitted: OmittedDiagnostics,
    pub capture: Option<&'a scopebase_capture::neutral::ValidatedNeutralV1>,
}
pub enum ProfileError { InvalidId, DuplicateId, DuplicateEffect, Capacity }
pub enum LimitField {
    InputBytes, RetainedBytes, WorkItems, LiveOwners,
    DiagnosticCount, DiagnosticBytes, Wait,
}
pub enum LimitsError { Zero(LimitField), OutOfRange(LimitField) }
pub enum ContextError {
    Limits(LimitsError), InvalidBinding, DuplicateBinding, DuplicateObservation,
    UnknownCapability, Capacity, CaptureAlreadyPresent,
}
```

`Profile::new` rejects duplicate/empty IDs, IDs longer than 64 bytes, duplicate effect entries, and more than 64 requirements or five distinct effects. `Limits::validate` rejects zero fields and any count/byte value not representable as `usize` on the build target. AppContext admits at most 64 capability observations, eight component bindings, and the configured bounded diagnostics. `observe` refuses IDs absent from the profile; optional capabilities must be declared too. Duplicate capability IDs are errors; evidence changes require a new explicit observation context, preventing replacement of a failed required observation with a green retry. Profiles hold only static identifiers, never dynamically supplied unbounded strings. Binding package/version/backend are nonempty when present and bounded to 128/64/64 bytes; at most 16 feature names, each 64 bytes, sorted uniquely; package coordinates must be unique. Bound fields are checked before copying. Admission is `Refused` for a required explicit unsupported/denied/incompatible observation, `Incomplete` for any required missing/unknown observation, zero bindings or any binding without an artifact digest, otherwise `Ready`. The registered actual adapter remains responsible for honest binding, since a coherent false digest is not detectable from metadata. An admission result describes declared prerequisites; it cannot mint an attach handle, mapping proof, process capability or close receipt. Optional failing observations remain present in output. Errors implement Display/Error, preserve structured variants and never log implicitly; adding public variants follows the root pre-1.0 compatibility policy. Invalid constructors perform no external effects.

Session integration uses `scopebase_capture::neutral::ValidatedNeutralV1` and its `source`, `counters` and `claims` accessors. `capture` records a bounded immutable copy, preserving capture/producer/epoch/binding/origin and separate per-claim reasons; no imported observation is converted to live closure authority. A context accepts at most one capture snapshot; later snapshots use a new explicit context, while the application owns ongoing component sessions. It must use those exact capture types rather than create a second universal identity. The SDK's application envelope leaves any component-owned cleanup/closure receipt in its original component type; no report deserialization feeds a constructor for a trusted runtime receipt. `AppContext` has no generic `start`, `poll`, `stop`, `close`, `signal`, `attach` or `quiesce`. Each application checks `profile().permits(effect)` before its selected component operation and owns ordering, retries and recovery. This is explicit application policy, not a sandbox capable of blocking arbitrary caller code. Dropping AppContext has no effect on an independently held file or native link.

SDK-owned logical retained payload accounting is deterministic: binding UTF-8 string lengths plus `128 + 32*counters + 8*claims + 4*reasons` for the one neutral snapshot must fit `retained_bytes`, using checked arithmetic before cloning. Diagnostics have their separate `diagnostic_bytes` bound and do not consume the same allowance twice. Fixed-capacity object/Vec overhead is reported separately, not mislabeled as payload bytes. Application file buffers and component-owned resources require their own component limits/reservations; AppContext does not reserve their memory by storing the same Limits value. Tests cover snapshot N/N+1, a simultaneous largest binding and snapshot, and failed admission leaving the prior context unchanged. `report()` borrows existing storage and allocates nothing; callers cloning/reporting outside that borrow assume their own memory custody.

`Diagnostic` borrows its input for the call and contains a static code, severity, stage, effect classification, optional byte-path and human text; raw captured payload bytes are not a field. Static codes must be nonempty ASCII alphanumeric/underscore identifiers of at most 64 bytes; invalid codes are discarded with truncation disposition and explicit omitted count, rather than emitted as corrupt framing. Retained diagnostic text/path display is capped at 4,096 bytes per diagnostic and 65,536 aggregate bytes by the host profile. The implementation bounds scanning/escaping before allocating a copy and truncates on a character/escape boundary. Count/byte overflow increments a saturating omitted count with an explicit `at_least` flag. Caller-owned input and allocator bookkeeping are outside retained-byte limits; report copies and escaped diagnostic storage are charged before allocation, without claiming a universal resident-memory ceiling. Diagnostics never change an underlying failure to success. SDK structs are `Send + Sync` only where all fields and imported types permit; shared mutation needs caller synchronization. No callback or thread is created by the SDK.

## Reference applications and onboarding

`apps/scopebase-file-observer` is a host Linux binary installed independently as `scopebase-file-observer`. Its `observe --fixture-root DIR --operations 16 --output report.json` command creates one private owned run directory through retained parent authority, generates two distinct 4,096-byte patterns from literal fixture constants and operation index, opens A using `scopebase_linux::file::HeldFile` and retains it in an owned `Arc`. It uses `AsFd` for borrowed descriptor operations. Setup then atomically replaces A's pathname with B under an explicit channel barrier; observation reads the held A, while independent fixture control reads the expected replacement B. Its fixture controller runs in the same process and requires no child supervision. The app counts bounded successful read operations, reports unknown losses as unknown, and emits one application terminal summary carrying capture's actual closure strength. It does not claim mapped-image support from a file-only run.

Truth lives in the fixture controller: byte patterns, operation IDs, requested lengths and replacement acknowledgements are written before observation. A tiny independent oracle uses raw positional reads only for fixture verification, not the production resolver/reducer to compute expected bytes. Tests compare identities/bytes and counted operation populations, never entire normalized product reports. Workload failure, no positive activity, no executed B branch, mismatched operation IDs or unresolved fixture cleanup make the run incomplete. Default caps are 16 operations, 65,536 total input bytes, 8,192 retained bytes, 64 work items, eight live owners, 32 diagnostics, 65,536 diagnostic bytes and a two-second wait budget. `--operations` accepts 1 through 16; the wait budget bounds cooperative waits, not all filesystem calls. Uncertain cleanup is separately reported with retained owner disposition and no automatic recursive deletion of unowned paths.

`templates/scopebase-observer` is a standalone Cargo project with its own `[workspace]`, published-version dependencies and a committed lockfile in each release artifact. It demonstrates explicit Profile, Limits, held-file lifetime, capture session/report integration and a developer conformance test using the application's resolved adapter. `cargo test` on this project runs its own conformance invocation; dependency tests are never assumed to run automatically. `GETTING_STARTED.md` explains prerequisites, effects, refusal examples, where to place application logic, and the installed diagnostic route. The starter does not embed internal workspace paths or require donor repositories.

`apps/scopebase-workload-observer-bpf` is the selected second SDK recipe, opt-in for application users and required for complete SDK acceptance. It traces an owned fixture's non-crypto operation IDs through a file-backed uprobe using the existing Aya backend and the `scopebase-bpf` attachment adapter, with an active excluded workload in a separately admitted process. The fixture is an independently compiled C executable exporting `scopebase_fixture_tick(uint64_t operation_id)` and invoking IDs 1 through 16 under an IPC barrier; the excluded process invokes distinct IDs 1001 through 1016. The expected ledger is established before either runs. The recipe never promises hook availability merely from a kernel release. Qualification binds emitted object hash, BTF/config, architecture, backend, toolchain and actual fixture trigger; wrong-PID/filter/object mutants must fail semantic assertions. It verifies link/map disappearance and retained file authority through cleanup or explicit unresolved custody. BPF loading is an explicit allowed effect and never the default SDK build or starter run.

Ordinary semantic population runs release the owned/excluded workloads only after application readiness and pre-first-attach baselines are recorded. A separate adversarial early-activity case releases additional ledger IDs during startup; the app must label its partial admission interval and avoid certifying a complete population there. It cannot reject all early activity silently or invent an atomic startup boundary from an all-or-rollback attachment helper. Stop-with-in-flight work similarly preserves observed facts and pending protocol predicates instead of converting detach/quiet polling into closure.

Attachment custody belongs to one persistent caller-owned `RetirementPool<AyaBackend>`, created with `RetirementPool::new(RetirementCapacity { max_groups, max_links, max_retained_bytes })`. The live application calls `execute_plan(&mut pool,backend,authority,plan,policy,limits)`; the pool retains the actual native backend/program/file/link and uncertain effects. Returned `AttachmentSet`/`UnresolvedAttachments` values are move-only domain/generation custody tickets. Retirement is `ticket.retire(&mut pool)` or `ticket.retry_retire(&mut pool)`; wrong-pool rejection returns the original custody unchanged. Dropping a ticket marks its entry orphaned without freeing capacity or native ownership. Application retries/controller reconstruction retain the same pool and call bounded `pool.reconcile(RetirementBudget)` before new admission; reconciliation addresses pending/orphan entries only. `pool.close()` returns Closed or Unresolved(pool), and the latter remains explicit retained custody, never a successful SDK terminal. Replacing an exhausted pool is a new accounting domain and cannot reset the claimed bound for the same application session. No SDK metadata object is accepted as an ownership ticket, and no process-global capacity is claimed.

The underlying BP acquisition result is `NativeAttach::{Attached(link),NoEffect(error),Uncertain{custody,cause}}`. Only proven no-effect errors permit the relevant isolation policy; an uncertain effect is retained in the pool before return and terminates splitting/new attachment attempts. The app consumes `AttachOutcome::{Active{owner,summary},RolledBack{summary,cause},Unresolved{custody,summary,cause}}` without collapsing Unresolved into an ordinary error or treating absent link FD as no effect. Reconciliation calls the backend's owner-bearing `retire_uncertain` route; cancellation/timeout cannot release charge or grant cleanup success. Before each new attempt the app examines `PoolReconcile { retired_groups,pending_groups,failed_groups,usage }` and uses `RetirementBudget { max_native_calls }`; pending/failed groups remain visible and fully charged. Unknown native effects without finite audited custody support cause a pre-effect refusal in the selected built-in adapter.

The live app owns a persistent caller-visible `SupervisorPool`, using `SupervisorPool::new(SupervisorLimits,ReapIntegration)` and `ChildSupervisor::new(VerifiedHelper,&SupervisorPool)` for its fixture children. Cloning shares the same admission domain; dropping/reconstructing an application controller must not create a fresh allowance while old children remain unresolved. `spawn_stopped` failures retain any `OwnedChildCustody`; release failures distinguish still-stopped from already-running owners, and pending/unresolved wait outcomes retain their original child owner. App shutdown explicitly drains only queued/dropped owners under a selected `ChildDrainPolicy`, never children still owned by application handles. `pool.close(self,&control)` checks cancellation before its shared admission-stop commit; after transition to Closing, all stale controllers/clones refuse new spawns. A later close failure returns the Closing pool/report/error for drain/close retry and remains incomplete. No implicit running-child kill or success from Drop occurs. The application keeps its pool handle until all children are reaped and explicit close succeeds, or records terminal retained custody. ScopeBase makes no global resource-cap claim for callers deliberately constructing independent pools. The host-only file observer needs neither this pool nor a mapping-custody pool; a later mapping recipe must use the Linux mapping pool rather than infer its cleanup from SDK metadata.

## Native requirements

| ID | Required behavior and acceptance |
|---|---|
| NX-R01 | Author a small versioned neutral corpus independently of production encoders/reducers: framing, integer boundaries, unknown/zero, epoch mismatch, quality dependencies, short output/retry and cleanup outcomes. Rust/C/Mojo clients share expected semantics, not generated observed answers. |
| NX-R02 | Audit the actually consumed libbpf-mojo source/bundle separately from main/joint candidates and preserve all branch/WIP evidence. Report API, ownership, tracepoint/map/test-run scope, source-only tests and missing emitted/live/installed qualification per operation. No donor edits or implicit upgrades follow. |
| NX-R03 | Deliver copied-record retry regression additions against the existing libbpf reader: repeated short output, source mutation, EINTR, malformed/discard/pressure, held once and conservation. A direct-pointer or consume-on-short mutant must fail the held-byte assertion. |
| NX-R04 | Deliver transactional configuration tests against the existing bridge: failed autoload/target update leaves native configuration and generation unchanged; success changes generation once; stale views refuse. Fault setup and independent native observation prove transactionality. |
| NX-R05 | Deliver map buffer geometry tests using possible CPUs including offline lanes, eight-byte alignment, checked multiplication, exact consumer stride, bloom distinction, alias/short output refusal and untouched error output. Host mocks and actual live map checks remain separately labeled. |
| NX-R06 | Deliver close/release/loader-lifetime tests: child references keep parent/library alive, `EBUSY` preserves usable owner, delayed cleanup remains unresolved, short retries do not duplicate delivery, and every permitted disposal path retires exactly once. Single-thread scope remains explicit. |
| NX-R07 | MojoBPF integration consumes standard ELF/BTF through the existing libbpf-mojo/libbpf boundary. Actual object checks cover map BTF, relocations, section/call/helper shape and version/profile binding. Verifier success, live semantics and cleanup are separate required gates for an advertised recipe. |
| NX-R08 | `scopebase-ffi` exports only the pure capture-validation operation specified below, justified by independently usable C and Mojo validation clients. No BPF loader, syscall wrapper, foreign application reducer or custom ring protocol is added. Rust packages stay usable without FFI. |
| NX-R09 | The ABI freezes version, widths, enum codes, ownership, alignment, alias rules, buffer retry, error precedence, allocation, threading, fork/exec and panic behavior. Header/Rust/C/Mojo layout tests and negative controls enforce the same contract. |
| NX-R10 | Sanitizer, fuzz and independent cross-language tests cover unaligned input, malformed/overflowing lengths, integer extremes, bad versions/reserved fields, duplicate/unknown fields, partial output and concurrent disjoint calls. Invalid raw pointers remain caller contract violations, not catchable parse errors. |
| NX-R11 | Installed C and Mojo clients work offline from staged release artifacts without donor/monorepo source, locate the intended shared library, report ABI/library/build identity and run positive and negative vectors. System ABI/toolchain prerequisites are explicit and qualified. |
| NX-R12 | Deliver per-file license/provenance, versioned package support/patch register, operation-specific qualification matrix and MG handoff. Source/vector/host/object/live/installed tiers are reported independently; future C/Mojo use is planned work until these gates pass. |

## Neutral corpus and existing bridge contributions

`interop/vectors/v1/manifest.json` lists case ID, semantic family, licensed source or original authorship, input hash, literal expected result, required clients, evidence tier and intended mutant. Inputs are bounded byte files or small JSON descriptions using canonical decimal strings for u64 values. Families include `0`, `9007199254740993`, u64 max/overflow, signs/leading-zero/whitespace refusal, unknown versus measured zero, epoch mismatch, duplicate terminal, quality partial-overlay then completion, and short-buffer retained-data retry. No product schemas, private logs or raw addresses are copied. Rust, C and Mojo consumers parse fixture descriptions independently; the corpus generator cannot call the production implementation. A reproducibility check regenerates bytes and compares committed fixture hashes, without regenerating the independent expected verdict file.

The native contributions are real plan outputs: a distributable conformance overlay in `interop/libbpf-mojo-conformance/` with C/Mojo clients and a reviewed patch bundle targeting a refreshed exact libbpf-mojo revision. It may contain new bridge-local test cases and minimal production fixes exposed by them, but no second bridge implementation. Patch publication, donor application and dependency upgrades are separate authorized work. A case already complete in the selected donor becomes an external consumer regression against that public ABI rather than a duplicate implementation. Its issue record preserves the original defect, fix inclusion, failing control and when the overlay can be retired.

The libbpf-mojo close contract stays its own: an owner with live children can return `EBUSY`; release drops one external reference; library lifetime extends through descendants and destructors. An adapter cannot equate Rust Drop, Mojo destruction or a successful release with native detach completion. No ScopeBase wrapper may mark these owners `Send`/`Sync` from their pointer representation or Arc alone. The overlay tests same-thread diagnostics immediately before another native call can overwrite them.

## ScopeBase pure C ABI v1

This new ABI validates a bounded neutral capture-quality envelope using `scopebase_capture::neutral::validate_v1(input: &NeutralObservationV1, limits: NeutralLimits) -> Result<ValidatedNeutralV1, ContractError>`; it does not parse application events. The native adapter alone owns a byte encoding and translates to canonical semantic types. `scopebase-capture` does not gain a competing JSON or wire framing format. The ABI writes a normalized envelope so C and Mojo applications can inspect a delivered ScopeBase capture record without implementing the Rust validation algebra. This distinct use justifies the ABI; libbpf-mojo is still the BPF bridge.

The v1 wire format uses little-endian integers and a 128-byte header: magic `SCBNCV1\0` at 0..8, wire version u16=1 at 8, header size u16=128 at 10, total length u32 at 12, capture ID bytes at 16..32, producer ID bytes at 32..48, epoch u64 at 48, binding bytes at 56..88, origin u32 at 88, counter count u32 at 92, claim count u32 at 96, and zero reserved bytes at 100..128. Exactly the declared counters then claims follow; trailing bytes are malformed. The decoder preflights the complete checked extent and caps input before allocating semantic vectors. Empty/truncated input is malformed; zero counter/claim counts are permitted when the capture validator admits their semantics. Counts are at most 4,096 each, with at most 16 reasons per claim; total input and normalized output are each at most 65,536 bytes.

Each counter is 32 bytes: channel u32 at 0, unit u8 at 4, magnitude tag u8 at 5, capped-signal cap u8 at 6, zero reserved byte at 7, magnitude u64 at 8, zero reserved bytes at 16..32. Units map `Events=1`, `Records=2`, `Bytes=3`, `Objects=4`, `Attempts=5`, `Nonexecutions=6`, `DiagnosticSignals=7`. Tags map `Unknown=0`, `Exact=1`, `AtLeast=2`, `CappedSignal=3`. Unknown requires zero magnitude/cap; Exact/AtLeast require zero cap; CappedSignal requires magnitude at most 255 and canonical capture capped-signal validation with DiagnosticSignals units. A claim is claim ID u32, reason count u16, zero u16, then reason-count u32 reason tags. Origin tags are `AdapterReported=1`, `Synthetic=2`, `Replayed=3`; quality reason tags are `ConsumedLoss=1`, `MissingEvidence=2`, `QueryPartial=3`, `Ambiguous=4`, `Capacity=5`. Assignments are frozen in `interop/abi/v1.json`, with unknown tags refused. Decoder validation covers encodings; only canonical `validate_v1` decides valid IDs, duplicate channels/claims, units, capped magnitudes and scoped reasons. Normalization retains caller ordering and writes every reserved field as zero; accepted input therefore normalizes byte-for-byte. `QueryPartial` remains local to its report, never converted into consumed loss. No sorting implies causal order or stronger quality. Versions remain independent even though initial ABI and wire majors are both one.

Native files are `crates/scopebase-ffi/src/{lib,abi,validate}.rs`, `interop/include/scopebase_capture_v1.h`, `interop/abi/v1.json`, and `interop/pkgconfig/scopebase-capture.pc.in`. The library artifact is `libscopebase_capture.so.1` with development symlink `libscopebase_capture.so`; Cargo crate type is `cdylib` plus `rlib` for Rust boundary tests. Initial supported target is x86-64 Linux, LP64, little-endian; other Rust host targets do not imply native ABI support. Version symbols and support matrix list both ABI major and capture wire major independently.

```c
/* C99; all structures have natural alignment, no packed layout. */
typedef struct {
    uint32_t abi_version;       /* exactly 1 */
    uint32_t struct_size;       /* exactly 32 for v1 */
    uint64_t max_input_bytes;   /* 1..65536 */
    uint64_t reserved0;         /* zero */
    uint64_t reserved1;         /* zero */
} scopebase_validate_options_v1;

typedef struct {
    uint32_t abi_version;       /* exactly 1 */
    uint32_t struct_size;       /* exactly 40 for v1 */
    uint32_t status;            /* matches return value */
    uint32_t diagnostic_code;   /* stable code, zero on success */
    uint64_t required_bytes;    /* normalized output size when known */
    uint64_t error_offset;      /* byte offset, UINT64_MAX if inapplicable */
    uint64_t reserved0;         /* zero */
} scopebase_validate_result_v1;

uint32_t scopebase_capture_abi_version(void); /* returns 1 */
uint32_t scopebase_capture_validate_v1(
    const uint8_t *input, uint64_t input_len,
    const scopebase_validate_options_v1 *options,
    uint8_t *output, uint64_t output_capacity,
    scopebase_validate_result_v1 *result);
```

The function is synchronous and stateless. All pointers remain caller owned and none is retained. It creates no handle, callback, worker, FD, mapping or background resource; no `close`/`release` function exists or is necessary. The only library lifetime obligation is that the loaded library remains mapped for the duration of each call. C/Mojo wrappers own any dynamic-library handle until their calls complete. There is no allocator transfer or library-owned error string. Calls with disjoint caller buffers are reentrant and thread safe; simultaneous writes through shared output/result memory violate the caller contract. Fork/exec requires no internal reset and no async-signal-safety is advertised.

Input may be unaligned and is copied/decoded by bytes. Options/result must be naturally aligned, point to initialized/readable options and writable result storage, and remain valid for the call. All spans must refer to allocated objects of the declared lengths and be representable as `usize` and `isize` without address wrap. Input, output, options and result memory must be pairwise disjoint. Null input is permitted only for zero input length; null output only for zero output capacity. Null options/result return `BAD_ARGUMENT` without dereferencing them; no result is written when result is null. Invalid non-null pointers cannot be validated safely and are caller undefined behavior. Safe Rust and Mojo wrappers must establish these obligations before the unsafe call.

Status codes are fixed: `OK=0`, `BAD_ARGUMENT=1`, `ABI_MISMATCH=2`, `LIMIT=3`, `MALFORMED=4`, `OUTPUT_SHORT=5`, `INTERNAL=6`. Validate pointer nullness/numeric lengths/overlap first, options version/size/reserved fields second, input cap third, complete wire semantics fourth, output capacity last. `max_input_bytes` greater than 65,536 or zero is `BAD_ARGUMENT`; input above a valid cap or exceeding wire cardinality maxima is `LIMIT`. Unknown wire major is `MALFORMED` with its own stable diagnostic code, independent of ABI major. Where the result pointer's basic contract is valid it is completely initialized on every return, with unknown offset `UINT64_MAX`, zero reserved fields and `required_bytes=0` until normalization size is known. On pairwise overlap result is not written if that would modify the input/output/options region; the returned status is sufficient. ABI mismatch does not read beyond the exact v1 prefix; larger structure sizes are refused in v1, not silently accepted as new semantics. Caller must still provide complete initialized v1 options/result objects as specified; a truncated allocation does not become safe merely because its prefix claims a small size.

Diagnostic codes are `NONE=0`, `SPAN=1`, `OVERLAP=2`, `OPTIONS=3`, `ABI_VERSION=4`, `ABI_SIZE=5`, `INPUT_LIMIT=6`, `WIRE_HEADER=7`, `WIRE_LENGTH=8`, `WIRE_RESERVED=9`, `WIRE_TAG=10`, `WIRE_MAGNITUDE=11`, `WIRE_VERSION=12`, `SHORT_OUTPUT=13`, `PANIC=14`. Canonical semantic error codes use the explicit named mapping below. Rust enum declaration order/discriminants never determine ABI values; adding or moving a variant cannot renumber an existing code.

| Canonical ContractError variant | Native diagnostic code |
|---|---|
| InvalidId | 100 |
| DomainMismatch | 101 |
| ArithmeticOverflow | 102 |
| ReversedBounds | 103 |
| MissingProvenance | 104 |
| ConflictingProvenance | 105 |
| DuplicateKey | 106 |
| EpochExhausted | 107 |
| GenerationMismatch | 108 |
| CapacityExceeded | 109 |
| MissingFeed | 110 |
| DuplicateFeed | 111 |
| StaleRevision | 112 |
| InvalidInterval | 113 |
| InvalidSample | 114 |
| InvalidProfile | 115 |
| IncompatibleVersion | 116 |
| InvalidReplay | 117 |
| ConservationMismatch | 118 |
| Any unrecognized future variant (`SEMANTIC_OTHER`) | 199 |

`crates/scopebase-ffi/src/abi.rs` owns private `semantic_code(error: Option<&scopebase_capture::ContractError>) -> u32`: match every named variant explicitly and return 199 for `None` or the nonexhaustive wildcard. Production passes `Some(error)`; the private `None` sentinel permits a direct fallback test without claiming a current upstream enum contains a future variant. Exhaustive named fixtures assert all 19 assignments and the fallback independently; reordering/inserting canonical variants cannot change existing expectations. Canonical semantic rejection is MALFORMED; decoder cardinality/byte refusal is LIMIT. Error offsets point to the first offending wire field when known; semantic errors without a unique field retain UINT64_MAX. No diagnostic embeds captured input. These maps, output sizes/offsets and exported symbols are fixture-tested in `interop/abi/v1.json`.

Output is caller allocated. Parse/validate fully before copying output; every non-OK status leaves the entire output unchanged. A size-only call with null output/zero capacity returns `OUTPUT_SHORT` and exact required bytes for valid nonempty normalized output. Repeated short calls return the same bytes-required/result; a later adequate call returns exactly those normalized bytes once, with no consumed input/session state. No partial output, NUL terminator or implicit encoding conversion exists. Canonical normalized output is specified by the shared capture envelope version; output capacity larger than required leaves the tail untouched. Required normalization is at most 65,536 bytes, with no unbounded allocations or diagnostics. Out-of-memory/abort is outside an `INTERNAL` recovery promise; catchable Rust panics must not cross C, must leave output unchanged, and return `INTERNAL`. Builds using `panic=abort` document process termination rather than pretending it is catchable.

The exported header is normative with the ABI schema. Export allowlisting prevents Rust implementation symbols or accidental dependencies becoming ABI. V1 layout/code assignments and diagnostic meanings are immutable; additive operations receive new symbols, incompatible fields require v2 symbols and SONAME major. Wire/schema/ABI/profile versions are separate. C and Mojo consumers compare library ABI/build metadata, and report a library mismatch before validation instead of searching donor paths.

## Qualification and completion

SDK host profile needs pure limits/admission/diagnostic checks, Linux file lifecycle cases, independent A/B workload, isolated parallel contexts, downstream composition and installed offline route. It must pass the applicable H04/H06 and G03–G06/G09–G11/G18–G22 obligations selected by those operations. Mapping claims add H05/UC01–UC14's applicable real cells; SDK file-only success cannot satisfy them. Optional BPF recipe adds applicable H03/H04/H07–H19/H29–H32 based on actual geometry, attachment, producer and transport reachability; pin the final selection in its profile before environment discovery.

Native corpus/ABI readiness needs all Rust/C/Mojo semantic positives and active negatives; installed consumers; layout/export checks; supported ASan/UBSan C boundary runs; supported Rust Miri/fuzz coverage over byte decoders; short-output and alias controls; and exact package/toolchain binding. Compile-from-source clients use explicitly provisioned C/Mojo toolchains; installed run-only clients ship their runtime closure and require no compiler, source checkout or network. The installed prefix is read-only, with separate writable fixture/results directories. The libbpf-mojo overlay additionally needs actual selected bridge objects and separate live/installed operation gates before advertising those operations. MojoBPF needs emitted-object, verifier, owned workload and cleanup evidence at its refreshed compiler/adapter pin, not only equivalent source or successful loading.

Every requirement has an implementation task in the companion plan. A required missing tool, fixture, kernel permission or object is `BLOCKED`/`NOT_RUN`, never a successful semantic negative or a clean supported profile. A denied-operation assertion can pass while the capability is denied. A new object/compiler/backend invalidates affected object/live evidence. Two wrappers agreeing on a shared bug cannot replace independent truth; a mutant must reach the operation and fail its specified semantic assertion. No product migration, external submission, release publication or donor mutation is authorized by writing this specification.
