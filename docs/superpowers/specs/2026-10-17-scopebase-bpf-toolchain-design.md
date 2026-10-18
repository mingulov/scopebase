# ScopeBase BPF, BTF and compiler regression design

Normative 2026-10-18 amendment: [decisions and reasons](2026-10-18-scopebase-decisions.md), [executor contract](2026-10-18-scopebase-executor-contract.md), and [task-origin / repair plan](../plans/2026-10-18-scopebase-plan-repair.md). Porting and task readiness follow these amendments; no new implementation or support claim follows.
Date: 2026-10-17. Status: proposed complete component specifications for review. The active goal authorizes M0–M6 implementation through the selected task contracts; product migration, release and upstream submission remain later. BPF packages and commands below remain future deliverables until their own acceptance. The current [workspace](../../../README.md) includes four package foundations. [BP01](../../reviews/2026-10-18-bp01-foundation.md) implements `scopebase-bpf` host error/limit configuration; operational BPF/backend APIs and runtime/conformance qualification remain open.

This specifies two independently deliverable workstreams: `scopebase-bpf` host contracts and optional backend adapters; and compiler/object regression tools with packaged testkit fixtures. The accompanying [implementation plan](../plans/2026-10-17-scopebase-bpf-toolchain.md) separates their tasks and gates. Product migrations are deferred: package readiness requires real external package consumers of the delivered API, but does not require p11scope, KryProbe, OSSLscope or MemVeil to migrate. It confers no product-integration claim.

## Inputs, boundaries and decisions

The [main study](../../research/2026-10-17-shared-libraries/README.md), [B/C backlog](../../research/2026-10-17-shared-libraries/TODO.md#f2-bpf-support-and-compilerkernel-compatibility), [kernel/toolchain investigation](../../research/2026-10-17-shared-libraries/kernel-toolchain-notes.md), [testing strategy](../../research/2026-10-17-shared-libraries/testing-strategy.md), [delivery workflow](../../research/2026-10-17-shared-libraries/testing-delivery-plan.md), [KryProbe](../../research/2026-10-17-shared-libraries/kryprobe.md), [MemVeil/libbpf-mojo/MojoBPF](../../research/2026-10-17-shared-libraries/memveil.md), [external comparison](../../research/2026-10-17-shared-libraries/external-comparison.md), and [gap analysis](../../research/2026-10-17-shared-libraries/gap-analysis.md) are the evidence inputs. Their source pins are observations, not newly reproduced qualification. H/UC/G names retain their original meaning.

Use Aya, libbpf and their object/BTF implementations. This project adds geometry validation, ownership protocols, bounded operations, explicit semantic evidence and reusable regressions around them. It does not supply a universal ELF loader, replace libbpf-mojo, unify product shutdown, or promise one safe BPF fence. No new standalone `scopebase-btf` or build-support crate is planned now. BTF starts in `scopebase-bpf::btf` behind a host-only feature; compiler helpers start in `tools/` and `scopebase-testkit`. Splitting a crate requires two concrete independent build/API callers, a dependency/maintenance benefit and a recorded decision.

Default and `--no-default-features` builds of `scopebase-bpf` are host-only. The first BP01 package implements only the host error and explicit budget configuration foundation, with `default = []` and no external dependencies. Do not export empty feature promises: BP09, BP10 and BP07/BP08 add `btf`, `aya`, `libbpf` and `producer-fixtures` only with their actual implementations, reviewed source/dependency closure and affected compiler/package checks. The complete optional feature separation and supported backend union remain required by the final package design. BP01 records accepted candidate inputs and unresolved actual-use choices; a future native/target decision does not gate this std-only foundation. No build script downloads tools or changes rlimits, credentials, signals, namespaces or kernel configuration. Producer fixture compilation and live execution are separate explicit tools. Public API names below are normative. Host crates use edition 2021 and proposed MSRV 1.88.0; SB02 must qualify selected dependencies at that compiler before implementation claims support. SB01 owns the contract/provenance registry; SB03 owns compatibility/document policy.

## File and package map

| Future path | Responsibility |
|---|---|
| `crates/scopebase-bpf/src/{lib,error,limits}.rs` | Feature boundary, typed errors and explicit bounds. |
| `crates/scopebase-bpf/src/maps/{mod,topology,geometry,handle,provenance}.rs` | Possible-CPU topology, checked map I/O, ABI and insertion-lane selection. |
| `crates/scopebase-bpf/src/{capability,writer,loss,identity}.rs` | Scoped evidence, writer declarations, diagnostic-cap folding and producer identities. |
| `crates/scopebase-bpf/src/attach/{mod,plan,execute,retire,pool}.rs` | Validated target batches, finite split tree, rollback and retained authority. |
| `crates/scopebase-bpf/src/ring/{mod,frame,bounded,stage}.rs` | Frame arithmetic, fixed-boundary outcomes and owned staging contract. |
| `crates/scopebase-bpf/src/btf/{mod,domain,query,adapt}.rs` | Existing-parser admission, bounded domain-aware semantic queries. |
| `crates/scopebase-bpf/src/adapters/{aya,libbpf}.rs` | Selected upstream APIs and individually tracked minimal patches. |
| `crates/scopebase-bpf/include/scopebase/{task_identity,producer_contract}.h` | Narrow optional C protocol and schema; no application maps or policy. |
| `crates/scopebase-bpf/tests/{maps,capability,attach,retirement,ring,btf,writer_identity}.rs` | Public API tests and named issue regressions. |
| `crates/scopebase-testkit/src/bpf/{mod,adapter,cases}.rs` | Developer conformance API against a supplied actual candidate implementation. |
| `crates/scopebase-testkit/src/object/{mod,manifest,inspect,graph,rules}.rs` | Final object checks over an existing ELF/BTF decoder. |
| `crates/scopebase-testkit/src/toolchain/{mod,identity,invoke,executor,scope}.rs` | Explicit compiler closure and bounded nested build helpers. |
| `tools/bpf-compat/{README.md,profiles.schema.json,profiles/,issues/,patches.json}` | CLI entry guidance, strict profiles, durable issue/patch records. |
| `fixtures/bpf/{maps,btf,ring,identity,writers,atomic-rmw,atomic-load,isa,metadata,object-graph}/` | Packaged sources, generated-input recipes, independent expected vectors and mutant definitions. |
| `tests/downstream/bpf-{minimal,aya,libbpf,feature-union}/` | Independent dependency consumers; no donor/workspace source access. |
| `tests/installed/bpf-conformance/` | Read-only-prefix/offline operator closure and invocation tests. |

Shared testkit runner/report identity and installed CLI belong to the conformance workstream. Implement `scopebase_testkit::adapter::ConformanceAdapter` with `subject(&self) -> SubjectBinding` and `execute(&mut self, invocation: &CaseInvocation, fixture: &FixtureAccess) -> Result<Observation, CaseError>`. Observations are versioned bounded bytes; independent oracles decode them and supply expected truth. Production crates never depend on testkit. TT01 owns the registry, TT02 the harness, TT05 provisioning/orchestration for these semantic fixtures, TT07 installed delivery, TT08 causal CI and TT10 release profiles. This lane supplies case implementations and the BPF profile extension; it must use that runner's single verdict engine. If the shared runner has not landed, the BPF case API may ship for developers but the advertised operator-ready profile remains incomplete. Paths are ownership seams, not reasons to create empty placeholder modules.

## Normative BPF requirements

| ID | Requirement | Owning tasks / cases |
|---|---|---|
| BP-R01 | Host-only geometry and model use need neither loader, BPF compiler nor privilege. Features, errors, resource bounds and intended owner traits are public. | BP01, BP11; G03/G04/G09/G10/G19/G20. |
| BP-R02 | Allocate checked `align_up(value_size, 8) × possible_cpu_count` for per-CPU I/O; validate map metadata, key/value ABI and every actual consumer stride before syscall. Parsed/model topology cannot authorize a lengthless kernel copy; use opaque internally acquired live topology and refuse unauthenticated source/change. Reject unknown/overlapping topology and overflow. | BP02; H15/H16. |
| BP-R03 | Capability state, evidence stage, hazard outcome and runtime authority are distinct. Bind cached observations to object/profile/context; no diagnostic receipt can mint authority. | BP03; H22; G12/G14. |
| BP-R04 | Attachment plans preserve file authority and offset-cookie associations, use at most `2n−1` attempts for nonempty n-site split isolation, and obey caller error policy without retrying terminal denial/resource failures. | BP04/BP05; H04/H21. |
| BP-R05 | Every partial attachment has a terminal disposition: returned active owner, retired, pending or unresolved custody. Retain the original file through native retirement; caller-owned persistent pool permits remain charged for active, uncertain, pending and orphaned effects. Drop is no cleanup proof. | BP05; H19/H21; G06–G10/G15/G23. |
| BP-R06 | Ring arithmetic is checked, modular wrap is explicit, BUSY is pending, fixed-tail crossing is an error, and bounded drain never grants quiescence. Preserve the backend's documented mmap memory ordering and sole-consumer authority. | BP06/BP11; H12; G10/G15. |
| BP-R07 | Copied staging survives callback-source mutation; a short destination retries the same record once delivered. Preserve separate received/delivered/held/malformed/dropped conservation and error tails. | BP06; H13. |
| BP-R08 | Writer ownership names program, site, CPU lane, guard and architecture. Different programs on one CPU do not share an unprotected slot. Guard refusal has its own miss channel. | BP07; H14/H18. |
| BP-R09 | Insertion identity uses one valid ownership marker; zero identity values stay valid. Independent preallocated diagnostic storage survives primary-map full failure; a cap of 255 is a degradation indication, not an exact event count. | BP07; H15/H17. |
| BP-R10 | Producer task/exec identity distinguishes birth/thread/exec success/failure, session domains and exhaustion; poll/PID/starttime tracking is never upgraded into this protocol. | BP08; H01/H03/H08. |
| BP-R11 | Adapt an existing BTF parser; preserve bounded wrapper/type/member/prototype queries and base/module type and string domains. Equal names or sizes alone do not establish identity or map type linkage. | BP09; H08/H11. |
| BP-R12 | Loader adapters stay narrow, independently optional and validated on exact emitted objects. Track upstream patches separately; no source-green/metadata-green result establishes live support. | BP10/BP11; H07–H11/H21/H22. |
| BP-R13 | Each advertised profile ships public developer cases, fixtures, a source-free installed operator path and at least two independent downstream package consumers of its actual APIs. Required old/current/affected kernel cells are selected before availability discovery. Product migrations are deferred. | BP11; T5/UC14/G19/G20. |
| BP-R14 | Wrong map-kind operations refuse before extent arithmetic, allocation or native lookup; configuration failure preserves native state and generation or returns poisoned/unresolved ownership. | BP02/BP10; H28. |

## Public host types, errors and budgets

Initial packages use version `0.1.0`; pre-1.0 breaking public behavior increments the minor version. All public enums are `#[non_exhaustive]` except fixed wire enums. Live backend owners are not usable in a caller-fork child before exec: inherited native locks/threads/resources are not re-admitted there; the documented supported route is fork+exec followed by new acquisition. Pure immutable arithmetic values may be used after fork. No destructor in the child may claim native retirement; child disposal does not certify the parent owner was retired. BP05/BP10 test this refusal contract in an owned subprocess. Owners are move-only. Errors expose typed `kind`, `stage`, optional raw errno and a standard `source`; callers never parse display text. BP01 implements `ErrorKind` and `Stage` as `#[non_exhaustive]` enums deriving `Debug, Clone, Copy, PartialEq, Eq`, preserving existing variants and order without repr/discriminant or wire-number promises. `OperationError::new(kind, stage, raw_errno, source)` stores caller-supplied kind, stage, optional errno and boxed `Send + Sync + 'static` source independently and verbatim, including zero, negative and unknown errno values; it does not infer or reconcile classification. Its getters are `kind()`, `stage()`, `raw_os_error()`, `required_size()` and consuming `with_required_size(usize)`; required size is an operation-supplied byte requirement, starts absent and can be replaced by any value, including zero or `usize::MAX`, without authorizing allocation. It implements `std::error::Error`; `Error::source` returns the original boxed source by shared reference with the standard trait-object lifetime. The type is `Send + Sync`, and is not `Copy`, `Clone`, `Default`, `Eq`, serializable, or promised `UnwindSafe`/`RefUnwindSafe`. ErrorKind/Stage add no `Ord`, `Hash`, serde, discriminant or numeric wire promise. It has no blanket `From<io::Error>` or errno classifier. Display uses fixed variant labels and decimal optional numbers as diagnostic text, not a wire schema; custom Display and Debug stay at most 256 ASCII bytes and never format the source in normal, alternate or nested formatting. Debug may include only the bounded text and `source_present=true|false`; explicit source access/downcasting and caller source-chain behavior remain caller code. `OperationError` is for operations without retained partial owners; effectful operations return their explicit owner-bearing result types.

```rust
pub enum ErrorKind { InvalidInput, Malformed, Incompatible, Unsupported,
    Denied, Disappeared, Changed, LimitExceeded, Overflow, Backend, Poisoned }
pub enum Stage { Admission, Metadata, Allocate, Read, Attach, Drain, Retire,
    BtfQuery, Compile, Inspect, Execute }
pub struct OperationError { /* private fields */ }
impl OperationError {
    pub fn new(kind: ErrorKind, stage: Stage, raw_errno: Option<i32>,
        source: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self;
    pub fn kind(&self) -> ErrorKind;
    pub fn stage(&self) -> Stage;
    pub fn raw_os_error(&self) -> Option<i32>;
    pub fn required_size(&self) -> Option<usize>;
    pub fn with_required_size(self, required: usize) -> Self;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub input_bytes: usize, pub retained_bytes: usize, pub work_steps: u64,
    pub sites: usize, pub live_links: usize, pub pending_retirements: usize,
}
impl Limits { pub fn validate(&self) -> Result<(), OperationError>; }
```

At v0.1, `Limits::validate` validates configuration only. Every representable combination of its independent unsigned caps is structurally valid, including zero and the type maximum; it returns `Ok(())` without allocation, operation-derived arithmetic or operational permission. There are no cross-field ordering restrictions, `Default` implementation or implicit unlimited sentinel. Each operation must refuse positive work/resources against a zero corresponding cap and use checked arithmetic before allocation or effects, even with maximum caps. BP02 owns CPU/alignment/extent arithmetic, BP04 split-attempt calculations, BP05 cumulative retirement charges, BP06 frame/staging arithmetic, BP09 parser budgets and TC02 executor charges; their existing zero/overflow regressions remain mandatory. A valid cap configuration does not validate an ABI value or authorize a live operation. Persistent retirement-pool and compiler-executor charges additionally bound outstanding effects across operations; per-operation bounds include both initial and split attempts; every retained attachment, ring staging slot, BTF graph and transformed object is charged to its configured bound. Byte, iteration, FD/link, retained-custody and elapsed limits are separate. A synchronous syscall can outlive a deadline; elapsed budgets constrain checks/retries, not arbitrary kernel syscall interruption. Worker cancellation, if later offered, needs the separate ownership-transfer contract and does not appear as an unimplemented async API here.

Pure values are `Send + Sync`. The initial RetirementPool/CompilerExecutor and their tickets are `!Send + !Sync`, with serialized mutable operations; supporting movable/concurrent native factories needs a separate qualified profile. BP02 `LiveCpuTopology` and `ValidatedMap` are `!Send + !Sync` under their [native ownership contract](2026-10-18-scopebase-bp02-native.md#authentic-topology-and-task-context), with exclusive `&mut self` for lookup. Active attachment owners are `Send` only where their separately selected backend ownership permits it, with exclusive `&mut self` for changing operations. `RingReader` and `StagedRecord` are `!Sync`; one reader cannot be cloned or imported twice. Backend native handles do not acquire unsafe auto-traits by wrapping pointers. Public callback/policy code runs outside internal locks; policy panic propagates while the enclosing acquisition guard preserves links and authority. Poisoned state cannot provide evidence; destructors do not panic. `panic=abort`, malicious unsafe backend code and process crash are outside unwinding guarantees.

## Map topology, metadata and ABI

The controller-ratified [BP02 map/public contract](2026-10-18-scopebase-bp02-maps.md), [native authority/syscall/resource contract](2026-10-18-scopebase-bp02-native.md) and [preservation/verification contract](../plans/2026-10-18-scopebase-bp02-verification.md) replace this section's earlier proposed signatures and live-admission wording. They own the exact APIs, algorithms, error order, bounded effects and required controls, including independently approved BP02-R1. They specify implementation and acceptance obligations; no implementation or runtime qualification follows from this amendment.

Pure CpuTopology/PerCpuGeometry values remain descriptive and portable. The native API is restricted to the admitted x86_64 Linux GNU little-endian 64-bit cfg, retains authentic task/source/map authority internally and exposes no caller-topology/native-injection route. LiveCpuTopology and ValidatedMap are !Send and !Sync. The immutable global possible-mask Linux ABI is the lengthless-copy bound; source checks and the exact original-task text/fresh-stat predicate detect observed substitution/task loss and suppress publication without claiming continuous observation or arbitrary ABA detection.

Only the checked perCPU array/hash byte-buffer lookup contracts are included. Actual bloom permits the metadata query needed to discover kind and then refuses before extent arithmetic, allocation, topology, key witness and value lookup. Fully implemented optional linked-BTF raw-image SHA-256/type-ID equality supplies no semantic layout or producer-object proof; BP09 owns semantic BTF. WHO88 remains package-delivered regression/client fixture policy, with every selected lookup/decoder/fold/report path preserved. Exact evidence cells and source/archive clients remain required before this increment closes.

## Capability observations and explicit probes

```rust
pub enum CapabilityState { Supported, Unsupported, Denied, Unknown, Incompatible }
pub enum EvidenceStage { Metadata, Object, Load, Attach, Behavior }
pub enum HazardState { Clean, Affected, Unknown }
// ArtifactId is the shared root-exported value from artifact.rs, delivered by BP02.
pub struct ProfileId(String);
impl ProfileId {
    pub fn new(value: &str) -> Result<Self, OperationError>;
    pub fn as_str(&self) -> &str;
}
pub struct ProbeContext { pub kernel_build: [u8; 32], pub btf: Option<ArtifactId>,
    pub architecture: String, pub namespace_context: [u8; 32],
    pub security_context: [u8; 32], pub topology: [u8; 32] }
pub struct CapabilityObservation { /* private, serializable evidence */ }
impl CapabilityObservation {
    pub fn state(&self) -> CapabilityState;
    pub fn stage(&self) -> EvidenceStage;
    pub fn applies_to(&self, object: &ArtifactId, profile: &ProfileId,
        context: &ProbeContext) -> bool;
}
pub struct ProbePopulation { pub expected_owned_hits: u64,
    pub observed_owned_hits: u64, pub independently_executed_excluded: u64,
    pub observed_excluded_hits: u64 }
pub fn assess_filter_probe(population: &ProbePopulation)
    -> Result<CapabilityState, OperationError>;
```

`ArtifactId` is defined once by the [BP02 shared public API](2026-10-18-scopebase-bp02-maps.md#exact-public-api) in `scopebase-bpf/src/artifact.rs` and reexported at the crate root. BP03 consumes that same descriptive `[u8;32]` value instead of declaring a second domain; linked BTF uses SHA-256 of exact raw image bytes and capability callers still bind their actual object/profile context. The value itself grants no runtime authority.

`ProfileId::new` admits 1..128 ASCII bytes matching `[a-z0-9][a-z0-9._/-]*`; the shared testkit maps its independently validated ID by that string and does not use raw unchecked constructors. Construction records object/profile/context, operation, stage, actual outcome and reason. Public constructors for descriptive observations must label their provenance; they cannot yield loaded-link or retirement authority. `expected_owned_hits > 0`, independent owned-ledger completion and `independently_executed_excluded > 0` are prerequisites for a support verdict. Exact counts and per-thread identities supplement the abbreviated population structure through case data. Zero observations from a disabled trigger are Unknown/incomplete, never Supported. An excluded hit is Incompatible. Permission denial remains Denied at its stage, not Unsupported. Preserve operation, raw errno and bounded verifier/backend evidence: EPERM/EACCES alone does not establish permission denial for BPF_PROG_LOAD. A demonstrated verifier or license refusal remains a distinct cause; an ambiguous cause is Unknown. The donor initialized-padding defect returned verifier EACCES on older kernels, so an errno-only classifier is forbidden. Seccomp/uretprobe hazard classification and attach feature classification use separate results and caller policy; an unsafe override cannot cure missing privilege.

Explicit probe entry points reside in selected adapters/testkit workloads. They require owned workload resources and declared effects. No probe runs in a type constructor or ordinary host test. Namespace/security/object/profile/BTF/topology changes invalidate reuse. Runtime denial always overrides cached allowed evidence; the observation is advisory, with no API accepting it as a license to skip native errors. Required semantic fallback is selected before attachment/admission. Ring-to-perf, lifecycle-to-polling or behavior-to-metadata downgrade requires a named allowed weaker profile and a new epoch when already active; no implicit fallback is supplied here.

## Attachment planning, finite splitting and retirement

`AttachPlan::split_sites` is the pure split primitive: validate a nonempty in-bounds site range, return None for a singleton, otherwise return the deterministic left/right halves divided at `start + len/2`; ranges stay disjoint and cover the original exactly. BP04 delivers this pure planner; BP05 delivers the effectful pool-backed executor. The shared planner accepts already validated offsets; ELF discovery remains with Linux/image adapters and existing parsers. A `Site` couples its offset and cookie in one record so parallel vectors cannot diverge. A batch refers to one original file authority, one program and one selected attach mode. Duplicate sites/cookies are refused for this first profile, rather than relying on backend-specific duplicate semantics.

```rust
pub struct Site { pub offset: u64, pub cookie: u64 }
pub enum AttachMode { EntrySingle, ReturnSingle, EntryMulti, ReturnMulti }
pub struct AttachPlan { /* private validated nonempty sites */ }
impl AttachPlan {
    pub fn checked(sites: Vec<Site>, mode: AttachMode, limits: &Limits)
        -> Result<Self, OperationError>;
    pub fn sites(&self) -> &[Site];
    pub fn split_sites(&self, batch: std::ops::Range<usize>)
        -> Result<Option<(std::ops::Range<usize>, std::ops::Range<usize>)>, OperationError>;
}
pub enum ErrorAction { IsolateSites, AbortAndRollback }
pub trait ErrorPolicy {
    fn classify(&mut self, error: &OperationError, batch_len: usize) -> ErrorAction;
}
pub enum NativeRetire { Retired, Pending, Failed(OperationError) }
pub enum NativeAttach<L, U> {
    Attached(L),
    NoEffect(OperationError),
    Uncertain { custody: U, cause: OperationError },
}
pub struct CustodyCharge { pub link_slots: usize, pub retained_bytes: usize }
pub unsafe trait AttachBackend {
    type Authority;
    type Link;
    type Uncertain;
    fn custody_charge(&self, authority: &Self::Authority, sites: &[Site])
        -> Result<CustodyCharge, OperationError>;
    fn attach(&mut self, authority: &Self::Authority, sites: &[Site],
        mode: AttachMode) -> NativeAttach<Self::Link, Self::Uncertain>;
    fn retire(&mut self, link: &mut Self::Link) -> NativeRetire;
    fn retire_uncertain(&mut self, custody: &mut Self::Uncertain) -> NativeRetire;
}
pub struct RetirementCapacity { pub max_groups: usize, pub max_links: usize,
    pub max_retained_bytes: usize }
pub struct PoolUsage { pub groups: usize, pub links: usize, pub retained_bytes: usize }
pub struct RetirementBudget { pub max_native_calls: usize }
pub struct PoolReconcile { pub retired_groups: usize, pub pending_groups: usize,
    pub failed_groups: usize, pub usage: PoolUsage }
pub struct RetirementPool<B: AttachBackend> { /* owns native custody entries */ }
impl<B: AttachBackend> RetirementPool<B> {
    pub fn new(capacity: RetirementCapacity) -> Result<Self, OperationError>;
    pub fn usage(&self) -> PoolUsage;
    pub fn reconcile(&mut self, budget: RetirementBudget) -> PoolReconcile;
    pub fn close(self) -> PoolClose<B>;
}
pub enum PoolClose<B: AttachBackend> { Closed, Unresolved(RetirementPool<B>) }
pub struct AttachmentSet<B: AttachBackend> { /* private pool/generation ticket */ }
pub struct UnresolvedAttachments<B: AttachBackend> { /* retained pool custody ticket */ }
pub struct AttachSummary { pub attempts: usize, pub attached_sites: usize,
    pub refused_sites: Vec<Site> }
pub enum AttachOutcome<B: AttachBackend> {
    Active { owner: AttachmentSet<B>, summary: AttachSummary },
    RolledBack { summary: AttachSummary, cause: OperationError },
    Unresolved { custody: UnresolvedAttachments<B>, summary: AttachSummary,
        cause: OperationError },
}
pub fn execute_plan<B: AttachBackend, P: ErrorPolicy>(pool: &mut RetirementPool<B>,
    backend: B, authority: B::Authority, plan: AttachPlan, policy: &mut P,
    limits: &Limits) -> AttachOutcome<B>;
pub enum Retirement<B: AttachBackend> {
    Retired, Pending(UnresolvedAttachments<B>),
    Failed { custody: UnresolvedAttachments<B>, error: OperationError },
}
impl<B: AttachBackend> AttachmentSet<B> {
    pub fn retire(self, pool: &mut RetirementPool<B>) -> Retirement<B>;
}
impl<B: AttachBackend> UnresolvedAttachments<B> {
    pub fn retry_retire(self, pool: &mut RetirementPool<B>) -> Retirement<B>;
    pub fn remaining_links(&self, pool: &RetirementPool<B>)
        -> Result<usize, OperationError>;
}
```

`AttachBackend` is unsafe because false no-effect, custody-charge or retirement statements can discard kernel-active resources or exceed the declared resource bound. `custody_charge` supplies an audited upper bound for one entire plan, including backend/authority/program references, all split leaves and one terminal uncertain native attempt; it cannot be a safe caller estimate. `link_slots` bounds admitted native link/uncertain-resource slots and `retained_bytes` bounds library-owned host custody buffers/metadata; pre-existing caller-owned program/map allocation is identified separately and is not falsely reported as newly bounded by these two counters. The adapter declares any additional admitted native memory bound in its selected profile. Bounds on native allocations are part of each built-in adapter contract. If a native API cannot provide a finite pre-effect charge, that route refuses before attachment. Safe built-in adapters retain the backend and native objects in the persistent pool entry referenced by the owner ticket; creation accepts no arbitrary pathname-only authority. `Authority` in the Linux adapter is `std::sync::Arc<scopebase_linux::file::HeldFile>`; `HeldFile: AsFd` yields the retained `BorrowedFd`, and private Linux constructors own validation; its attachment route uses the held FD/proc-fd path with same-object checks and typed procfs denial. It never reopens the historical pathname as fallback. The generic pure planner depends on neither Linux crate nor loader. The first public foreign/imported links profile is unsupported; imported map FDs confer only admitted lookup use, no permission to remove foreign pins.

Configuration of backend program autoload/attach-target state is transactional before attachment: preflight all values, snapshot admitted native state, apply autoload before attach-target when required by the selected native API, restore on failure, and increment configuration generation only after full success. A failed rollback poisons and returns explicit retained ownership; unchanged generation alone cannot conceal mutated native state. BP10 packages the libbpf-mojo configuration vectors without replacing that bridge or claiming a Rust test executed its native code.

The selected built-in constructors are:

```rust
pub struct ProgramAdoptError<T> { /* original T plus error */ }
impl<T> ProgramAdoptError<T> {
    pub fn into_parts(self) -> (T, OperationError);
}
impl AyaBackend {
    pub fn from_loaded(program: aya::programs::UProbe, domain: ProducerDomain)
        -> Result<Self, ProgramAdoptError<aya::programs::UProbe>>;
}
impl LibbpfBackend {
    pub fn from_loaded(object: libbpf_rs::Object, program_name: &std::ffi::CStr,
        domain: ProducerDomain)
        -> Result<Self, ProgramAdoptError<libbpf_rs::Object>>;
}
```

These signatures are feature-gated and validate loaded program kind before adoption; on error the original loaded owner is returned. Domain identity host types are available without enabling producer compilation. `ProducerDomain` is session provenance, not evidence of a successfully loaded identity protocol. No generic load/compile/configure API is added; vector tests cover native configuration through NX03–NX06, where an actual bridge configuration route exists.

`NativeAttach::NoEffect` is allowed only when the built-in adapter proves no surviving native effect and no retained asynchronous operation. `Uncertain` carries native acquisition/recovery ownership even when an API has not delivered a link FD, and is registered in the reserved pool entry before returning, unwinding or invoking policy. Its `retire_uncertain` reconciles/cancels the native operation and all partial links; only confirmed no surviving effects returns Retired. An uncertain result is terminal, never split/retried into more attachment effects; successful earlier nodes roll back while the same pool retains unresolved ownership. Unknown errno without effect proof cannot become NoEffect. If an API cannot produce recoverable custody for ambiguous effects, its built-in safe adapter refuses that route before calling it. A successful link may cover several sites. Test both pre-return partial native acquisition and late completion after timeout; no Result-only error branch can discard those states.

For an n-site plan, split only a failed multi-site node into two disjoint nonempty children. Attempt each node once; at most `2n−1` calls. Successful nodes are not reattached. Failed singleton leaves are reported. Permission, allocation/resource exhaustion and unknown-effect failures are terminal regardless of a permissive policy; `IsolateSites` may operate only on side-effect-free, site-isolatable errors explicitly admitted by the backend. EINVAL alone is insufficient classification. The caller selects whether any refused singleton makes the whole operation terminal through its plan/profile requirement; the first profile requires all sites, so any refused leaf rolls back every successful node. A later best-effort profile must be named, not inferred from an Active summary.

Baseline configuration and program/map admission precede the first live link; no generic API certifies the application's capture-ready point. Work can fire during attachment. Cases state whether it is outside the admission window or included in a product-owned startup protocol (G23). No library all-or-nothing event-observation promise follows from all-or-rollback link setup.

The caller creates one persistent `RetirementPool<B>` for its declared accounting/session domain and reuses it across attach attempts. The pool owns every backend, program, original file, successful link and uncertain native acquisition from before the first effect until positive retirement; returned owners are private, non-serializable custody tickets into that pool. Reserve one group and the full audited `CustodyCharge` before attaching, in addition to per-call `Limits`; reject capacity exhaustion before the first native call. Active, pending, failed, uncertain and orphaned entries remain fully charged; no credit is restored by a dropped ticket, a cancelled wait, a timeout or a merely requested detach. Overflow in reservation calculation refuses before effects.

Retirement consumes the ticket and requires the same pool. Retired releases the original file and charges only after every successful/uncertain effect is confirmed gone; Pending/Failed returns a custody ticket with charges intact. Foreign pool/session/generation refusal returns the original ticket unchanged. A retry cannot create links or duplicate retirement. Dropping a ticket marks that entry orphaned without calling native code or releasing ownership/charges; `pool.reconcile` visits only pending/orphaned entries within its native-call budget, never still-active entries whose tickets are held by a caller. `pool.close` returns the pool itself while entries remain, keeping recovery possible. Pool Drop is non-panicking and, if unresolved, retains/leaks the whole charged state as a last resort; it is not a clean close. There is no hidden global registry or worker.

The bound is over the lifetime of this persistent accounting domain, not one function call and not the whole process. Repeated unknown/pending failures plus dropped tickets must saturate the same pool and refuse new admission while old charges remain. Creating another pool explicitly creates a separate accounting domain; callers/SDK must count all such pools and must not replace a full/unresolved pool while reporting its old capacity as an application-wide bound. The initial SDK keeps one pool alive until `Closed` and reports all unresolved groups at exit. Operator conformance rejects unresolved cleanup. Tests inspect exact held-file/native identities and retained charges throughout repeated failure, reconciliation and eventual positive retirement; net-zero FD counts are insufficient.

## Ring arithmetic, reader adaptation and staging

```rust
pub struct RingPositions { pub consumer: u64, pub producer: u64 }
pub struct RecordHeader { pub payload_len: u32, pub busy: bool, pub discard: bool }
pub enum FrameStep { Pending, Emit { payload_len: usize, next: u64 },
    Discard { next: u64 }, ReachedBoundary }
pub fn frame_step(positions: RingPositions, stop: u64, capacity: usize,
    header: Option<RecordHeader>) -> Result<FrameStep, OperationError>;
pub struct DrainBudget { pub max_records: usize, pub max_bytes: usize }
pub enum BoundaryState { Reached, Pending, BudgetExhausted }
pub struct DrainResult { pub boundary: BoundaryState, pub records: usize,
    pub bytes: usize, pub discarded: usize }
pub trait BoundedRingSource {
    fn snapshot(&mut self) -> Result<RingPositions, OperationError>;
    fn consume_before(&mut self, stop: u64, budget: DrainBudget,
        visit: &mut dyn FnMut(&[u8])) -> Result<DrainResult, OperationError>;
}
pub struct StageStats { pub received: u64, pub delivered: u64, pub held: u64,
    pub malformed: u64, pub dropped: u64 }
pub struct StagedRecord { /* one bounded owned slot */ }
impl StagedRecord {
    pub fn new(max_record_bytes: usize) -> Result<Self, OperationError>;
    pub fn offer(&mut self, source: &[u8]) -> Result<(), OperationError>;
    pub fn copy_into(&mut self, destination: &mut [u8])
        -> Result<usize, OperationError>;
    pub fn stats(&self) -> &StageStats;
}
```

The ring capacity must be a supported power of two and less than half the cursor modulus; all available-distance checks use bounded modular distance rather than ordinary cursor ordering. Header size is 8 bytes, alignment is 8, and reserved bits/lengths, missing header, oversized records, invalid stop and a record crossing stop refuse before payload access. Discard advances exactly once and is charged to record/work budgets; BUSY does not advance. A producer extending beyond the captured stop does not extend this drain. Budget exhaustion stays separate from pending BUSY and reached boundary. `Reached` means only that captured boundary was consumed, with no closure/settlement statement. Passing a future producer value or a boundary behind the admitted consumer refuses.

Adapters preserve upstream ownership and record-guard Drop semantics. Aya adaptation uses one maintained minimal reader patch plus a separately tracked bounded-consumption patch if the chosen release still needs it. Preserve the donor's read-only mapped atomic load contract: Relaxed loads plus Acquire fence, Release cursor publication and the required wakeup barrier; confirm emitted/native behavior and supported architecture. Do not clone its private ring parser. libbpf adaptation uses supported consumption APIs and explicit copied staging; negative callback return already consumes the source record. A libbpf API that cannot enforce a fixed boundary must return Unsupported for that profile rather than approximate it with an empty poll.

Staging rejects zero/oversized records as malformed. An occupied slot drops the newly offered record while preserving the previous bytes. Short output returns LimitExceeded with required size in its structured source/context, leaves destination unchanged and retains the record across repeated retries. Successful copy consumes once; changing source after offer cannot alter held bytes. The frame envelope pins little-endian length and framing version independently of payload/ABI/report schema versions. Per-source-period conservation is `received = delivered + held + malformed + dropped`, with checked counters and explicit overflow failure. Kernel reservation failure, queue overflow and callback diagnostics have separate units/epochs; staging never manufactures kernel loss counts. Stop/error/panic reports preserve already consumed tail records and stats. Shared testkit H13 vectors reuse libbpf-mojo semantics, with C/Mojo bridge execution deferred rather than silently implied by Rust tests.

## Writer, identity and independent diagnostic contracts

```rust
pub struct WriterPartition { pub program_ordinal: u16, pub site_ordinal: u16,
    pub cpu_id: u32 }
pub enum WriterModel { GuardedPerProgramCpu, AtomicShared }
pub struct WriterDeclaration { pub programs: u16, pub sites_per_program: u16,
    pub model: WriterModel, pub architecture: String }
pub fn writer_slot(declaration: &WriterDeclaration, partition: WriterPartition,
    topology: &CpuTopology) -> Result<usize, OperationError>;
pub struct IdentityLane<'a> { pub marker: u8, pub identity: &'a [u8] }
pub fn insertion_owner(lanes: &[IdentityLane<'_>]) -> Result<usize, OperationError>;
pub struct DiagnosticFlag { /* private capped indicator */ }
pub fn fold_degradation_255(lanes: &[u8]) -> DiagnosticFlag;
impl DiagnosticFlag { pub fn value(&self) -> u8; pub fn is_degraded(&self) -> bool; }
pub struct ProducerDomain(pub [u8; 16]);
pub struct TaskCookie(pub std::num::NonZeroU64);
pub struct ExecGeneration(pub u64);
pub struct ProducerIdentity { pub domain: ProducerDomain, pub task: TaskCookie,
    pub exec: ExecGeneration }
pub fn same_execution(left: &ProducerIdentity, right: &ProducerIdentity) -> bool;
```

Identity marker 0 means absent and 1 present; other values refuse. Exactly one inserting lane must own identity. Absent lanes may contain no claimed identity; conflicting/multiple markers refuse even if bytes match. A present all-zero UID/stack payload is valid. Generic selection returns the owner index; product key/layout/UID semantics stay outside. Counts in secondary CPU lanes may accumulate without redefining insertion identity. Domain, nonzero task cookie and zero-valid exec generation remain separate; no wrap is allowed.

`writer_slot` computes a checked program × site × possible-CPU index and rejects absent CPU IDs; ordinals are a frozen producer ABI. The KryProbe nine-program/eight-drop-site layout is a fixture. A per-CPU slot shared by distinct fexit programs has no exclusivity claim. Guarded same-program reentry self-refuses and records a separate kernel-nonexecution miss. AtomicShared is admitted only with matching final-object lowering and architecture tests, not merely a host atomic twin. Functions expose partition arithmetic and declarations, not a universal live admission or fence implementation. Application stop protocols remain local. Testkit carries every-lane/stuck-writer/deadline/late-entrant countermodels; no timeout or detach grants Quiescent.

Independent diagnostics are a preallocated program/CPU array separate from the identity/full primary map. Both each lane and final fold saturate at 255. A value above zero signals observed degradation; 255 is not an exact omission count. Map/session/profile and counter epoch bind samples; reset, map replacement, partial read and saturation produce the declared weaker result, never synthetic exact deltas. The capture component owns general typed loss reports; this module's flag cannot be converted into an exact count. Product-specific failure sites and KCTX units stay local.

The optional C identity protocol has the following packaged header seam (fixed-width C types from `<stdint.h>`):

```c
struct scopebase_producer_identity_v1 {
    uint8_t producer_domain[16];
    uint64_t task_cookie;
    uint64_t exec_generation;
};
enum scopebase_identity_status_v1 {
    SCOPEBASE_IDENTITY_OK = 0,
    SCOPEBASE_IDENTITY_ZERO_COOKIE = -1,
    SCOPEBASE_IDENTITY_EXHAUSTED = -2
};
static inline int scopebase_identity_assign_task_v1(
    struct scopebase_producer_identity_v1 *out,
    const uint8_t producer_domain[16], uint64_t nonzero_cookie);
static inline int scopebase_identity_advance_exec_v1(
    struct scopebase_producer_identity_v1 *identity);
```

The fixed layout is 32 bytes, 8-byte alignment, offsets domain=0, cookie=16, exec=24 on the initial x86-64 profile. Assignment copies the caller domain, requires nonzero cookie and initializes exec to zero; failure leaves output unchanged. Advance requires nonzero cookie and exec below `UINT64_MAX`; overflow refuses with unchanged output. These helpers do not allocate cookies, infer exec success, provide ordering, access maps or establish birth continuity. The TT-owned independent fork/exec workload fixture supplies the operation/IPC ledger and observed syscall success/failure; Linux supplies process birth/view/owned-child authority only and does not provide an exec-proof seam. The production hook fixture owns the task-storage/atomic allocation and successful-exec transition protocol; inspect its actual final object and live behavior rather than treating these small helpers as that proof.

The optional C identity protocol supplies shared structs/constants and bounded helpers for task-storage identity. It must preserve the donor's fork versus CLONE_THREAD distinction, leader/nonleader successful exec transitions, failed-exec non-transition, token-zero refusal, map exhaustion/refusal and stale domain rejection. Task birth and exec are emitted by production hooks, not inferred from userspace polling. Task replacement across exec must follow the selected native protocol and retain continuity only when independently proved. BTF/config/CO-RE guards run before optional field access, handling missing, scalar and bitmap exec fields. Include initialized explicit padding and emitted ABI assertions. Native helpers are packaged source with provenance and a feature-specific compile route; moving a donor header wholesale with START/privacy/discovery layouts is forbidden. ScopeBase makes no cross-restart identity persistence or arbitrary-architecture claim. A package may ship the host identity values before this producer feature, but cannot advertise producer continuity until BP08's object/live cells pass.

## BTF parser adaptation and semantic domain API

```rust
pub struct BtfDomainId(pub [u8; 32]);
pub struct TypeRef { pub domain: BtfDomainId, pub id: u32 }
pub struct BtfLimits { pub image_bytes: usize, pub types: usize,
    pub strings: usize, pub wrapper_depth: usize, pub work_steps: u64 }
pub enum ByteOrder { Little, Big }
pub struct BtfImages<'a> { pub base: &'a [u8], pub module: Option<&'a [u8]>,
    pub byte_order: ByteOrder }
pub struct BtfView { /* owned admitted backing/parser indexes */ }
pub struct MemberExtent { pub byte_offset: u64, pub bit_offset: u8,
    pub bit_width: Option<u8>, pub size_bytes: u64, pub ty: TypeRef }
pub struct FunctionShape { pub result: TypeRef, pub parameters: Vec<TypeRef>,
    pub variadic: bool }
pub enum TypeKind { Integer { bits: u16, signed: bool }, Pointer { to: TypeRef },
    Struct, Union, Array { element: TypeRef, count: u32 },
    Enum { bits: u16, signed: bool }, Function, FunctionPrototype, Other }
pub struct TypeShape { pub kind: TypeKind, pub size_bytes: Option<u64> }
impl BtfView {
    pub fn parse(images: BtfImages<'_>, limits: BtfLimits)
        -> Result<Self, OperationError>;
    pub fn domain_id(&self) -> BtfDomainId;
    pub fn types_named(&self, name: &str) -> Result<Vec<TypeRef>, OperationError>;
    pub fn shape(&self, ty: TypeRef) -> Result<TypeShape, OperationError>;
    pub fn canonical(&self, ty: TypeRef) -> Result<TypeRef, OperationError>;
    pub fn member(&self, parent: TypeRef, path: &[&str])
        -> Result<MemberExtent, OperationError>;
    pub fn function(&self, ty: TypeRef) -> Result<FunctionShape, OperationError>;
    pub fn map_types(&self, map_name: &str)
        -> Result<(TypeRef, TypeRef), OperationError>;
}
```

Start with btf-rs at the research comparator pin for a corpus trial, then select and lock a release or exact commit by BP01/BP09. Existing Aya/libbpf parser views may also back the narrow interface when already selected; they are alternatives, not mandatory stacked dependencies. The safe adapter caps bytes/types/string storage before materialization where the parser permits it and adds a bounded preflight if not. A parser allocating without an enforceable cap is unsuitable for the advertised hostile-input profile. Do not silently replace it with a new complete parser. A documented narrow preflight or upstream correction needs its own tests and provenance.

Domain IDs bind exact base and optional module images; split IDs are interpreted in their paired base/module context. `types_named` returns every matching candidate within the work/type cap; it never picks the first name match as compatible. `shape` exposes primitive signedness/width, pointer identity and known extent so callers can impose their exact prototype/layout rules. Route both type IDs and combined string offsets correctly. Reject foreign refs, truncated records, unknown unsupported kinds, invalid alignment, arithmetic overflow, wrapper cycles/depth exhaustion, malformed DECL_TAG lengths, out-of-range names and parent escape. Anonymous members and qualifiers require bounded explicit traversal. Return exact resolved identity, primitive width/signedness, bitfield offsets and nested containment; equal spelling or size is insufficient for pointer/pointee compatibility. Prototype queries validate return/parameter types and argument count; profile-specific crypto/DMA/hook rules remain caller-owned.

`map_types` verifies keyed-map definition linkage to actual key/value type IDs, not just `.BTF`, `.maps`, VAR/DATASEC presence or matching sizes. Test the final object's loader-requested/kernel-reported key/value IDs in live cells where promised. BTFHub metadata can supply an admitted image with exact provenance; it cannot supply an absent helper or hook. The first bounded semantic profile is little-endian; Big input returns Unsupported until separate parser/ABI/corpus results qualify it. This explicit refusal is preferable to a false portability claim.

## Compiler/object requirements

| ID | Requirement | Owning tasks / cases |
|---|---|---|
| TC-R01 | Preserve issue provenance, source/toolchain pins, exact effective command/CPU/features, loaded backend identity, output hashes and expected layer-specific outcome. No implicit compiler installation; persistent executor jobs own descendant scope and output-root reservations across timeout. | TC01/TC02; H29–H32; G21. |
| TC-R02 | Profile admission checks decoded final instructions and architecture/endianness/ABI; CPU preset names alone cannot broaden support. Separate ISA, helpers/maps/kfuncs, loader relocation, BTF shape, attach and behavior requirements. | TC03; H30/H31. |
| TC-R03 | Used-result RMW tests check old returned and new stored values for each width/op, independent arithmetic, unused-result/CAS controls and selected fixed/unfixed compilers. Concurrent-map/ordering claims have separate live schedules. | TC04; H29. |
| TC-R04 | AtomicLoad compile refusal/ordinary-load/acquire-load distinctions are tested against explicit features. No volatile substitution or classifier that calls compiler failure a verifier rejection. | TC04; H31. |
| TC-R05 | Final mixed Rust/C outputs retain valid debug metadata/BTF/BTF.ext with meaningful function/map types through every transformation. Exit zero or parser replay is insufficient. | TC05; H32/H11. |
| TC-R06 | Object graph transformations are restricted, relocation/callback-aware, and fail closed on unsupported shape. Named stack/linkage/padding/prologue rules preserve old and new kernel workarounds with mutation controls. | TC05/TC06; H07–H11. |
| TC-R07 | Load, verifier/JIT acceptance, execution correctness, concurrency, performance and cleanup are separate judgments on exact final object bytes. Freeze oldest/current/affected/backport cells before execution. | TC07; H07–H11/H29–H32. |
| TC-R08 | Upstream patches/workarounds have individual scope, application hash/preimage, test, upstream status and expiration evidence. Merged source alone never retires a workaround or updates a consumer pin. | TC01/TC08. |
| TC-R09 | Shipped tools and fixtures run from source archives and an installed offline closure, plus downstream actual-library/backend users. No testkit-private resolver copy can certify another candidate. | TC08; T5/UC14/G19/G20. |
| TC-R10 | Separate authorized source/destination grants and actual host/BPF/shared/tool input closure from the final ELF and loader-supplied runtime license. Qualify GPL-only helper/type/kfunc admission only for advertised profiles with intended-reason refusals, active positive twins and delivered notices. No Apache-only GPLv2 target input or errno-only proof. | SB01/SB02/BP01/BP03/TC01/TC03/TC07/TC08/TT01/TT02/TT05/TT07/NX02/RL02; H33. |

## Compiler/object public tool interfaces

These APIs live in the testkit, behind opt-in host features `object` and `toolchain`; fixture compilation is never a testkit build script. Existing `object`/Aya/libbpf decoders supply ELF/BTF parsing. Full structures are owned, bounded data; strict serialized forms reject duplicate fields, unknown required schema versions and malformed exact hashes.

```rust
pub struct ToolBinary { pub executable: std::path::PathBuf,
    pub sha256: [u8; 32], pub version_output: Vec<u8> }
pub struct CompilerClosure { pub cargo: Option<ToolBinary>, pub rustc: Option<ToolBinary>,
    pub rust_sysroot: Option<std::path::PathBuf>, pub clang: Option<ToolBinary>,
    pub llc: Option<ToolBinary>, pub linker: Option<ToolBinary>,
    pub loaded_llvm: ToolBinary }
pub struct BuildRequest { pub source_root: std::path::PathBuf,
    pub output_root: std::path::PathBuf, pub target: String,
    pub cpu: Option<String>, pub features: Vec<String>,
    pub environment: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    pub deadline: std::time::Instant, pub max_output_bytes: usize,
    pub max_artifact_bytes: usize }
pub enum ScopeStart<J> {
    Started(J), NoEffect(OperationError),
    Uncertain { custody: J, cause: OperationError },
}
pub enum BuildExit { Exited(i32), Signaled(i32) }
pub enum ScopePoll {
    Running,
    Settled { exit: BuildExit, objects: Vec<std::path::PathBuf>, diagnostic: Vec<u8> },
    Unresolved(OperationError),
}
pub unsafe trait BuildScopeBackend {
    type Job;
    fn start(&mut self, tools: &CompilerClosure, request: &BuildRequest)
        -> ScopeStart<Self::Job>;
    fn poll(&mut self, job: &mut Self::Job) -> ScopePoll;
    fn request_stop(&mut self, job: &mut Self::Job) -> ScopePoll;
}
pub struct ExecutorLimits { pub max_jobs: usize, pub max_reserved_output_bytes: usize,
    pub max_retained_diagnostic_bytes: usize }
pub struct ExecutorUsage { pub jobs: usize, pub reserved_output_bytes: usize,
    pub retained_diagnostic_bytes: usize }
pub struct ExecutorBudget { pub max_scope_calls: usize }
pub struct ExecutorReport { pub settled_jobs: usize, pub pending_jobs: usize,
    pub failed_jobs: usize, pub usage: ExecutorUsage }
pub struct CompilerExecutor<S: BuildScopeBackend> { /* owns scopes and output leases */ }
impl<S: BuildScopeBackend> CompilerExecutor<S> {
    pub fn new(scope: S, limits: ExecutorLimits) -> Result<Self, OperationError>;
    pub fn usage(&self) -> ExecutorUsage;
    pub fn reconcile(&mut self, budget: ExecutorBudget) -> ExecutorReport;
    pub fn close(self) -> ExecutorClose<S>;
}
pub enum ExecutorClose<S: BuildScopeBackend> {
    Closed, Unresolved(CompilerExecutor<S>),
}
pub struct CompileJob<S: BuildScopeBackend> { /* executor/domain/generation ticket */ }
impl<S: BuildScopeBackend> CompileJob<S> {
    pub fn reconcile(self, executor: &mut CompilerExecutor<S>,
        deadline: std::time::Instant) -> CompileOutcome<S>;
    pub fn request_stop(self, executor: &mut CompilerExecutor<S>,
        deadline: std::time::Instant) -> CompileOutcome<S>;
}
pub struct CompileOutput<S: BuildScopeBackend> { /* sealed output-root lease */ }
pub struct OutputReleaseError<S: BuildScopeBackend> {
    pub output: CompileOutput<S>, pub error: OperationError,
}
impl<S: BuildScopeBackend> CompileOutput<S> {
    pub fn objects(&self) -> &[std::path::PathBuf];
    pub fn release(self, executor: &mut CompilerExecutor<S>)
        -> Result<(), OutputReleaseError<S>>;
}
pub enum CompileOutcome<S: BuildScopeBackend> {
    Emitted { output: CompileOutput<S> },
    Refused { diagnostic: Vec<u8>, output: CompileOutput<S> },
    ToolMissing { name: String }, Rejected(OperationError),
    TimedOut { job: CompileJob<S> },
    Unresolved { job: CompileJob<S>, error: OperationError },
}
pub fn compile_fixture<S: BuildScopeBackend>(executor: &mut CompilerExecutor<S>,
    tools: &CompilerClosure, request: &BuildRequest) -> CompileOutcome<S>;
pub struct ObjectContract { /* decoded from strict versioned profile */ }
pub struct RuleViolation { pub rule_id: String, pub section: Option<String>,
    pub offset: Option<u64>, pub kind: ErrorKind }
pub struct ObjectInspection { /* inventory and per-rule results */ }
impl ObjectContract {
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError>;
}
impl ObjectInspection {
    pub fn object_id(&self) -> &ArtifactId;
    pub fn violations(&self) -> &[RuleViolation];
    pub fn conforms(&self) -> bool;
}
pub fn inspect_final_object(bytes: &[u8], contract: &ObjectContract,
    limits: &Limits) -> Result<ObjectInspection, OperationError>;
pub fn prune_dead_code(bytes: &[u8], contract: &ObjectContract,
    limits: &Limits) -> Result<Vec<u8>, OperationError>;
pub struct AtomicCase { pub width_bits: u8, pub operation: AtomicOperation,
    pub initial: u64, pub operand: u64, pub compare: Option<u64> }
pub enum AtomicOperation { Add, Sub, And, Or, Xor, Exchange, CompareExchange }
pub struct AtomicExpected { pub returned_old: u64, pub stored_new: u64 }
pub fn atomic_reference(case: &AtomicCase) -> Result<AtomicExpected, OperationError>;
```

Path APIs preserve non-UTF8 paths; subprocesses use argument arrays and an explicit environment allowlist, never shell interpolation. The compiler closure records which LLVM library bpf-linker actually loaded, independently of Rust's embedded LLVM and Clang's LLVM. Each build profile declares its exact required tool roles: a direct llc/Clang fixture does not require Cargo, rustc or a Rust sysroot. Missing required roles refuse; absent unused roles never trigger discovery/installation. When selected, Cargo/rustc/sysroot must form a verified selected pair. Host environment, generated target and runtime target are separate fields; conflicting inherited `RUSTC`, target or CPU settings refuse. `cpu: None` is distinct from empty string, generic, v3 and v4. Tool hashes and actual effective arguments enter the manifest. Before any spawn, the persistent caller-owned executor reserves a job slot, diagnostic allowance and `max_artifact_bytes` for the held output-root identity. Its safe front end creates/opens only an owned isolated task root, detects alias/reuse of an already reserved root and retains the descriptor/context; lexical path differences cannot bypass the reservation. `max_output_bytes` bounds collected stdout/stderr separately from final artifact bytes and aggregate executor retained bytes. N/N+1 checks and storage/workload enforcement are scope-backend obligations, not merely an after-build file-size check. No concurrent writer or successor build may reuse a reserved root.

`ToolMissing` and `Rejected` are permitted only with no surviving scope or output-root ownership. `ScopeStart::NoEffect` proves worker effects absent, but does not itself release a root already reserved by the executor: failed root cleanup returns an Unresolved CompileJob retaining output-only custody. `Emitted` additionally requires `BuildExit::Exited(0)` and valid admitted outputs; signaled or nonzero exits yield Refused only after whole-scope settlement. Wrong-executor/session/generation job and output tickets return their original custody with a typed error and make no scope calls.

`CompileJob` and `CompileOutput` are non-serializable custody/lease tickets; the executor retains actual worker scope and output ownership when a ticket is returned, times out, unwinds or is dropped. A timed-out `CompileJob` reconciles or requests stop through the same executor; it is never summarized as an unowned boolean. Dropped job tickets mark orphaned work, retaining all reservations until `executor.reconcile` proves the scope settled and cleans only its owned outputs. A completed output remains leased until explicit checked `release`; refusal output can be inspected but is not a valid object claim. Failed cleanup returns the original output ticket and keeps reservations. `close` returns the executor while any scope/output ownership remains. Drop with unresolved entries retains/leaks the whole charged executor state as a documented last resort, not a clean completion. Repeated timeout/drop/retry cannot reset per-call capacity or release an output root. New executors are distinct accounting domains and the caller/SDK must include every outstanding domain in any application-wide limit.

`BuildScopeBackend` is unsafe because `Settled` is an authority claim that every process/thread/descendant capable of writing the job outputs has ceased, pending I/O has reached the declared stable boundary, and owned-scope cleanup is complete. Its `Job` must retain every native scope/control/output resource, including ambiguous start effects; `NoEffect` requires proof of no surviving effect. The executor registers the returned scope owner in its reserved entry before callbacks/unwinding. `ScopePoll::Unresolved`, immediate-child exit and a requested stop are not Settled. Poll/stop/reconcile budgets bound cooperative control calls and retained work, not arbitrary syscall interruption; an exceeded wait retains the scope owner and cannot manufacture a terminal result. All effectful worker state must reside in `Job`; a backend cannot hide active per-job work solely in a dropped factory/configuration object.

Two build-scope contracts are explicit. `direct-no-children-v1` is a BuildScope ID, not a conformance profile or a value accepted by `--profile`. The narrow host scope runs only pinned audited direct tools/arguments such as `llc` or Clang cc1, with a child-only pre-exec seccomp sandbox that kills/refuses fork/vfork/clone/clone3, socket/socketpair/connect/sendto/sendmsg and disallowed helper-IPC attempts; audited argument rules disallow plugins, compiler services, response files outside the declared immutable fixture closure and implicit executable helpers. It refuses before exec if that enforcement cannot be installed. The scope owns the immediate child, all inherited writable descriptors are closed except the declared outputs, and positive reaping plus output stabilization can establish Settled. A helper attempting to spawn a linker is a build-scope admission refusal. Cargo/rustc/build scripts/mixed Rust/C linking are not admitted to that host BuildScope.

The required mixed-build profile uses an explicitly owned disposable build guest/job scope supplied by TT05's controller through `BuildScopeBackend`. That adapter must own the whole guest execution tree and its exclusive writable output device; it accepts no VM-ID string or immediate `OwnedChild` as whole-scope authority. Finish/timeout reconciliation shuts down/destroys the owned guest and positively retires/reaps its controller and writable backends before extracting/sealing final objects or releasing output reservations. No writable host source/output sharing, daemonized helper or external compiler service can escape that scope. If any descendant/controller/backend remains unresolved, the CompileJob and root reservation remain live and no Emitted/Refused terminal result is produced. TC02 first owns the executor/scope interface, model tests and direct-no-children backend, independently of TT05. TT05 orchestration is then built over BP02 and TC03 direct/prebuilt-object admission. TC07 owns integration of BuildScopeBackend with TT05 whole-guest authority, and TC08 gates the mixed-build distributed profile on its real tests. TC03–TC06 implement/test inspectors/oracles/rules with direct-tool actual emitted C/IR objects or pinned genuine actual-object fixtures before that integration; they do not require a new mixed Cargo build to establish those reusable mechanisms. TC07 reruns the completed checks on newly built final mixed objects through the owned guest path, and TC08 gates that advertised profile; core-tool completion cannot be reported as mixed-build qualification. This order avoids TC02→TT05→TC03→TC02. TT05 owns explicit guest provisioning/lifecycle authority. Linux's immediate-child contract alone does not claim Cargo→rustc→linker tree containment. Tests force a parent to exit while a linker descendant continues writing and verify that root reuse, artifact admission and clean completion all refuse until the owned scope is positively settled.

Helpers use bounded retry only for a classified transient failure after the prior job is settled and its output lease explicitly released; compiler wrong-code never retries into PASS. Request stop only through the actually owned scope, retain uncertain custody, and never signal a guessed PID/process group. No public async runtime dependency is introduced.

`ObjectContract` has schema version, artifact/profile IDs, target triple/architecture/endian/pointer ABI, compiler/linker/backend closure IDs, explicit CPU and enabled/disabled backend features; permitted/required ISA forms; map/helper/kfunc requirements; required BTF/CO-RE field/prototype shape; allowed section/symbol/relocation/call graph; per-function initialized-byte and path-specific stack/control-flow/linkage rules; and required runtime cells. Separate required and optional rules. A final object with an unknown instruction or unsupported graph shape fails admission instead of being assumed baseline-compatible. Rule results identify function/path/offset and violated requirement. Manifests must not globally ban memcpy/memset when only one path has a verifier constraint.

`prune_dead_code` exists only as a restricted reusable tool for KryProbe's demonstrated dead builtins case. Admit supported ELF/BPF graph forms, preserve live root reachability, rewrite symbol/call/relocation/BTF references consistently and fail on shifted entry targets, interior/ambiguous ownership, truncation, misalignment or unknown relocation. Do not grow it into a replacement loader. Keep original and transformed hashes and a rule-by-rule comparison. The transformed object is a new final artifact requiring admission and relevant load/behavior tests. A compiler flag disabling creation of builtins does not prove previously rooted builtins disappeared.

## Required issue families and discriminating tests

Each case record has issue explanation, selected donor pin/license, capability/profile, exact trigger, API under test, independent expected result, valid twin, bad control, tier/cells, fixture build recipe and removal/reopen rule. Requirements below refine existing H IDs without adding/renumbering H families.

| Cases | Required subcases, oracle and mutant |
|---|---|
| H07 | Compiler-emitted local section-symbol relocations resolve two distinct sentinel FDs; reject interior/ambiguous/missing definition and signed-addend confusion. A forced same-FD alias mutant fails per-map identity assertions. Live map IDs supplement emitted/translated image checks when a loader backend is advertised. |
| H08 | Task-storage metadata and CO-RE missing/scalar/bitmap shape predicates on actual objects; initialized explicit ABI padding. Invalid field read mutant fails the read-path rule and oldest verifier/owned exec behavior gates, not only a source grep. |
| H09 | Stack-preserving out-of-range tail-call prologue and endpoint attach-type map remain in final object. Removal mutant fails the current object rule. On affected kernel 7.0 fixture, same-CPU preempted threads have independent START keys and operation ledger; non-reproduction without exercised preemption is inconclusive. Repaired-kernel twin plus all remaining gates is required for expiration. |
| H10 | Dead builtins/text strip, live roots, call/function-pointer relocation owner, alignment, callback BTF, translated image comparison and exact N×M live callbacks. Dead relocation removal twin passes; shifted entry, wrong call target and missing callback type mutants fail their intended rule or callback count. |
| H11 | Cyclic qualifiers, nested refcounts, parent-bound escape, rival same-name request types, anonymous members, DECL_TAG length, malformed prototypes, split module types/strings, absent key/value map linkage. Independent small graph oracle supplies exact refs/offsets; same-name and zero-ID mutants must be rejected despite matching sizes. |
| H12 | Controlled read-only mapping exercises reader, BUSY, discard, aligned wrap (`usize::MAX−15` case), producer extension, invalid stop and crossing record; record Drop advances once. Arithmetic model and real mapping/backend tests remain separate. BUSY-as-empty and stop-extension mutants fail the boundary assertion. |
| H13 | Repeated short buffers, source mutation after callback, EINTR, zero/oversize/malformed records, occupied slot, error and stop tail. Independent rows prove byte identity and conservation. Consuming short-buffer callback mutant loses the row and fails delivery semantics. |
| H14 | Same-CPU interleaving of different programs, guarded same-program refusal, every possible lane, stuck writer and deadline boundary. Plain-store shared-slot countermodel fails independent expected increments; host atomic model is not a BPF plain-store proof. |
| H15/H16 | WHO 88-byte schema on every actual lookup/fold path; migration with changing UID/cgroup/parent/stack; competing insert; real zero UID/stack; absent/conflicting marker. Sparse/overlapping/offline possible CPU lists, missing source, contradictory counts, 1/7/8/9/13-byte values, overflow, changed topology and safe well-formed caller undercount/wrong-source attempts. Parsed topology cannot enter the safe live constructor; independent source authentication and immutable-mask boundary are required. Independent task ledger/guarded kernel output buffer detects stale stride and insertion-provenance overwrite. |
| H17 | Below-capacity valid twin and primary-full population with independently known insert failures; preexisting loss, repeated cap, cross-CPU/program fold and separate KCTX result. Primary-map diagnostic mutant suppresses the indicator and fails nonzero-degradation assertion. No capped flag is checked as exact failure count. |
| H28 refinement | Bloom-as-output lookup refuses before arithmetic/allocation/native call with sentinel outputs unchanged; valid output-value lookup twin and allowed insertion are preserved. Fail configure at autoload, attach-target and rollback boundaries; independently inspect native target/autoload state and generation. Generation-only success mutant fails unchanged-native-state assertion. |
| H21 | All split-tree failure positions through n=1..8 with attempts ≤2n−1, exact offset-cookie grouping and owner identities; terminal permission/resource errors make one failing call and rollback existing successful nodes. Owner-bearing ambiguous native attach, late completion after timeout, fake retire failure and live mixed valid/invalid sites retain custody. Repeated unresolved outcomes/dropped tickets consume the same persistent pool permits and eventually refuse admission; restored positive retirement releases exactly those permits. |
| H22 | Owned thread positives and independently active excluded child/process through actual backend; disable attach/trigger and widen-PID mutants must fail observed identity/count verdict. Quiet-zero is incomplete. Seccomp/uretprobe hazard uses separately admitted isolated fixture and preserves Denied/Unknown. |
| H29 | i32 add/sub/and/or/xor and i64 add/sub used-result regressions plus remaining supported op/width cases, CAS and unused-result controls. Reference width-masked arithmetic is independent of BPF source. Decode fetch bits; force non-fetch to reach execution and fail returned-old assertion even with correct stored-new value. Selected known-affected and fixed backend plus actual mixed Rust/C final build path. |
| H30 | Minimal emitted fixture for every advertised optional ISA family: extended jumps, JMP32/ALU32, signed loads/moves, unconditional byte swaps, signed division/remainder, long direct jumps, immediate stores, acquire/release and indirect jumps as applicable. Empty/generic/v3/feature-controlled-v4 distinctions are effective compiler inputs, not release-string inference. Forbidden-opcode and preset-drift mutants fail profile admission. |
| H31 | Minimal C/IR/Rust monotonic aligned i64 atomic load with explicit feature masks; expected compile refusal is distinct from ordinary-load and acquire-load emission. Wrong feature expectation fails at compile/decoded-output assertion. Successful ordinary load cannot be labeled an acquire-opcode kernel requirement. |
| H32 | Mixed C/Rust debug records verified before/after each sanitation/link pass; final BTF/BTF.ext retain meaningful map/function types and relocations. Dropping debug parser/metadata-strip mutants exit zero but fail the metadata rule; valid twin passes. Loader/verifier/callback behavior separately required by selected profile. |

H01/H03 supplement the optional identity producer, H04/H19 attachment custody, and H18 startup/close countermodels. H23 strict profile/result parsing and H28 bridge ownership are consumed as applicable; running a Rust vector does not qualify the existing C/Mojo bridge. Unrelated filesystem mapping UC cells are not BPF-host profile gates, but a combined retained-file live profile must satisfy the Linux component's actual authority contract.

## Explicit support profiles and environment cells

Profiles are versioned finite sets, selected before discovery. A generic package does not inherit the union of donor support floors. Initial live claims target x86-64 little-endian Linux only; AArch64, big-endian and arbitrary weak-memory claims are Unsupported until separately designed and qualified. Pure arithmetic remains portable and tests host pointer-width boundaries independently.

| Future profile | Required exact-artifact cells / evidence |
|---|---|
| `bpf-host-v1` | T0/T1, applicable real host map metadata/mapping tests on x86-64 GNU 5.15/6.12 plus the exact-current control pinned by SB02, source package and two downstream host consumers. No kernel load/attach claim. |
| `bpf-aya-uprobe-v1` | Selected Aya release/patch closure; x86-64 kernel 5.15 oldest verifier lane, modern 6.12 lane, affected private-stack 7.0 cell; H07–H09/H12/H19/H21/H22 plus reachable identity/ABI cases. Exact kernel build/config/BTF and object hashes frozen before runs. |
| `bpf-libbpf-uprobe-v1` | Selected libbpf release closure; explicit oldest candidate 6.12 and new 7.0 cell for this adapter; H07/H10–H13/H19/H21/H22 where advertised. Fixed-boundary feature remains Unsupported if the selected native API cannot meet it. |
| `btf-shape-le-v1` | Host hostile/split corpus and actual emitted keyed-map/prototype objects; runtime key/value IDs in selected 6.12/current cells for a claimed live linkage extension. Profile alone does not prove attach semantics. |
| `producer-task-exec-v1` | Optional producer objects on 5.15 oldest shape/refusal lane, 6.12 modern and 7.0 changed-shape/new behavior lane; H01/H03/H08, independent exec ledger, map exhaustion and stale-domain controls. Per-cell supported/refused shape is explicit. |
| `aggregate-writer-x86-v1` | KryProbe-style test fixture only: 6.12 aggregate baseline and 7.0 current; lifecycle/FSESSION fixture requires 7.0 and a real 6.12 refusal lane. H14–H17/H18; these are testkit protocol fixtures, not a migrated or universally supported KryProbe implementation. |
| `compiler-object-v1` | H07–H11/H29–H32 T2 under frozen affected/fixed toolchains and final mixed C/Rust output; offline installed inspection needs no compiler. Compilation profile explicitly requires its listed tools. |
| `compiler-runtime-x86-v1` | Same final hashes in 5.15 baseline-subset verifier lane; original-v4 eligibility lane 6.9; acquire/release lane 6.15; indirect-jump lane 6.19; ordinary modern and affected 7.0 cell where distinct. Each ISA fixture declares support/refusal independently. Config/backport probing and actual decode/load/behavior determine verdicts. |

These are proposed qualification targets, not newly established kernel support facts. Exact distro build/config/guest image/BTF pins and expected outcomes must be admitted in TC01/BP01 manifests; a missing required cell leaves that advertised profile incomplete. A smallest package can advertise only `bpf-host-v1` while recording live profiles as unqualified. Future component-ready statements name each completed profile. The user-requested full BPF/toolchain specification includes every row; implementing only host geometry cannot close the whole plan.

The 6.9/6.15/6.19 references preserve research's source/ancestry observations: original v4 positive source support, acquire/release handlers and indirect-jump introduction are different facts. They do not assert every v4 form first appeared there or that all configs/JITs qualify. An LLVM upgrade does not silently raise an application's kernel floor. Backport counterexample cells include an admitted distro uretprobe/seccomp variant and denied privilege profile, chosen by exact behavior trigger; a kernel release string is insufficient. Newer kernel cells remain required because private-stack preemption shows support is not monotonic.

## Pins, licensing and patch expiration

The provisional host/BPF/shared-source policy is [D03–D04](2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination); the observed inputs and compatibility rationale are in [license boundaries](../../research/2026-10-17-shared-libraries/license-boundaries.md). Userspace scopebase-bpf may use Apache-2.0; BPF-target code and generated/shared fragments have their own compatible closure. Historical donor SPDX, author authorization, selected upstream option, destination terms and actual runtime license bytes are separate. The user owns their contributions; a historical GPL label does not forbid the approved destination grant. Preserve concrete upstream terms and do not make a fresh implementation solely to evade a label.

For GPL-2.0-only target programs use a kernel-recognized runtime declaration such as `GPL`, separately from source SPDX. Do not invent `Dual Apache/GPL` or submit `GPL-2.0-only` as if the kernel parsed SPDX. TC03 checks the final object's single bounded unambiguous declaration after transformation and the adapter records bytes actually passed to BPF_PROG_LOAD. H33 requires a reachable GPL-only helper positive with actual owned activity, its otherwise-valid non-GPL declaration refusal at the intended check, and a helper-free non-GPL control where that program type permits it. Type/kfunc-specific checks are required only for advertised profiles. Denial, missing helper/BTF, unrelated verifier failure and an untriggered workload cannot satisfy the license control. Source/notice compliance cannot be established by a successful kernel load.

The current Aya target packages offer MIT OR Apache-2.0, while their ordinary Apache-only option does not resolve GPLv2 compatibility. SB02/BP01/TC01 explicitly settle the upstream option and the scope of the user's no-MIT preference; do not silently choose a branch, rewrite Aya or block unrelated host work. Inspect real target and generated inputs separately from host compiler/proc-macro dependencies. Preserve the exact LLVM-exception grant where supplied; being compiled by LLVM does not create one.

| Donor/reference | Selected research pin / refresh action |
|---|---|
| p11scope integration | `cf413029dc9e092925a00b7eabdd8acbe02fa3fb` initial BPF inspection; final research refresh `eb6bbe1df910a3cf40b6b7e8965cc65c69f203ae`. Refresh cited BPF/maps/native/patch/checker files and dirty hashes before extraction; no assumption that unrelated journal delta is relevant. |
| Preserved compiler research | Workspace commit `33fdd75ee69575cf3f309da1ddef2e0fad5d3181`; select reproducible minimal fixtures rather than private archives. |
| KryProbe | `d153f3aaf9a3931337b47c9e1b046c692da55083`; refresh product mapops/BTF/ABI/drain/object-strip and active worktrees/WIP read-only. |
| OSSLscope | `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a` preview-r21 baseline; refresh loader/plan/callback/BTF sources and relevant refs over the existing SSH route. |
| libbpf-mojo | Sibling `ff6ea5087cb6cab3db51a9ffaf99922f880da8c9`; MemVeil actually consumes `681096cb588379307d0c8e94e1d77e53de4be22f`. Ring-conformance fix `497279c63c247922dfc3f516e6e09c7a623f1478` is not automatically in consumed bundle. |
| MojoBPF | Typed keyed-map BTF commit `f520a529ddd9572165d18f9560a45c1cd13288c1`; refresh CR09-M1 and joint integration separately, including WIP hashes, before reusing neutral vectors. No migration here. |
| BTF comparator | btf-rs `0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0`; trial only, release/adoption pin selected by corpus fit. |
| Atomic upstream correction | LLVM `9d18ac3e726403b493a54079d5c760f36db33244` (PR210371, research observed merged 2026-10-13). Verify actual selected backend inclusion and H29; no claim about installed compilers follows. |
| Private linker repair | `4727b154a014dd74b9cceb038c365b058f48a53a` on bpf-linker `24ccdfd47d0627f2dd88066e26a51526dac14cc4`; separate patch entry, upstream status unrefreshed. |

The [master specification](2026-10-17-scopebase-design.md) governs completion levels. SB01/SB02/SB03 own foundation policy, TT01–TT10 shared orchestration/delivery, and MG01–MG05 later actual product migrations. NX03–NX06 own actual libbpf-mojo ring/configure/map/native lifetime execution and packages; this BPF lane supplies shared neutral vectors and Rust adapter checks without claiming those native results.

BP01/TC01 record full refs/worktrees, selected file hashes/deltas, SPDX and compatible license decisions. Do not copy differently licensed native/host code under one assumed license. Public issue documents rewrite the technical lesson without private coordination history. Donors remain read-only throughout this plan; no checkout/reset/merge/cleanup/fetch is required to record visible refs.

Patch entries independently cover Aya minimal ring atomic/wrap repair, bounded ring API, local-map relocation, multi-uprobe backport, LLVM used-result RMW, separate AtomicLoad selector issue, linker metadata repair, private-stack prologue and any restricted-strip tool fix. Each entry has exact upstream base/preimage, patch hash, applicability, affected object/profile, owner, reproduced defect test, upstream source/release status, selected-binary inclusion test and removal test. Apply only to a selected vendored/build output with preimage checking and no fuzzy success. Upstream merge is one field; expiration requires the replacement release's same minimized bad/valid control, final consumer artifact path, relevant exact-kernel cells and package/downstream checks. No automatic upstream publication.

## Package delivery and definition of done

The shared conformance adapter registers BPF cases against the actual candidate's API and final objects; record package ID/version/source digest, resolved features, backend/native version, producer object hashes, suite/fixture/oracle versions and selected profile/cells. Two independent downstream fixtures call the delivered library from packaged archives using independent lockfiles, without sibling sources. One must intentionally introduce a second semver/source copy and show that a receipt for copy A cannot qualify candidate B. A runner's internally linked convenient library is not the candidate by default. Ordinary downstream `cargo test` does not run dependency tests; the delivered conformance API and installed route explicitly run them.

Runnable CaseId strings use 1..96 ASCII bytes: an alphanumeric first byte followed only by alphanumeric, dot, underscore or hyphen bytes; slash is forbidden. Named subcases include `H15.abi-stride`, `H28.bloom-output`, `H04.held-file-live` and `H22.filter-canary`. References such as H15/H16 elsewhere in prose denote historical family combinations, not runnable IDs or CLI selectors. A requested conformance profile selects its frozen required case set.

The future canonical installed invocation is `scopebase-conformance run --profile ID --fixture-root PATH --output PATH`, with the testing specification's optional fixture manifest. For example, after implementation and installation:

```bash
scopebase-conformance run --profile bpf-host-v1 --fixture-root /owned/scopebase-fixtures --output /owned/results/bpf-host.json
scopebase-conformance run --profile compiler-object-v1 --fixture-root /owned/scopebase-fixtures --output /owned/results/compiler-object.json
```

These are future operator commands, not commands available in this documentation-only repository. Live profile invocations require the separately admitted explicit environment/effects. The eight conformance profile IDs are exactly those in the support table above; BuildScope IDs are a separate namespace.

The operator closure contains prebuilt workload objects, static fixtures, profile/schema/issue data and the shared runner; compilation fixtures/tools are a separately declared developer profile. Install into a read-only prefix, use a separate writable owned scratch root and execute without source checkout, compilers or network. Live routes require explicit selected effects/environment; host-only install never auto-loads BPF. Each package advertised feature has an independently runnable package test and operator selection path, with omitted live assertions visible.

Completion requires all mapped requirements and task tests, source/doctest/feature-union/package tests, intended trait/unsafe review, independent valid/negative population, mutant sensitivity and all preselected required cells for the exact advertised profile. Reports separate assertion result, capability, coverage, harness validity and cleanup; expected denial/refusal can PASS its assertion while capability remains Denied/Unsupported. Required BLOCKED/SKIPPED/NOT_RUN/ERROR, zero activity or unresolved custody cannot close a positive support profile. Evidence tiers remain T0–T5 and old donor receipts remain historical. Product integration, SDK extraction and C/Mojo changes are separate future milestones. Duplicate-retirement criteria are specified for later migrations but are not library package-ready gates: only then may consumers remove old mechanisms after exact-tip product tests show equivalent retained behavior.
