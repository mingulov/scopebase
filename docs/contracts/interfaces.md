# Shared interface registry

Contract revision 1, 2026-10-18. Owner: SB01. These frozen implementation contracts copy the selected signatures from the normative subsystem specifications. No Rust package or symbol is implemented by this record. A change to a signature, ownership/effect rule or schema updates its specification, this registry, consumers, tests and traceability before dependent work proceeds. Package version `0.1.0`, contract revision, neutral schema version and test case/profile versions are separate identities.

| Contract | Package / module | Implementing owner | Required consumers | Authority and version |
|---|---|---|---|---|
| Retained file owner | `scopebase_linux::file` | LX01/LX02; SB01 freezes handoff | BP04 attachment custody, LX03–LX08 reads/mapping, LX11 clients, SDK04 file observer; NX uses existing bridge ownership | [Linux file API](../superpowers/specs/2026-10-17-scopebase-linux-design.md#public-file-interfaces), revision 1 |
| Consumer conformance adapter | `scopebase_testkit::adapter` and testkit profile runner | TT01/TT02 | LX/BP/CP domain adapters, TT07 installed runner, SDK/NX consumers | [Testing seam](../superpowers/specs/2026-10-17-scopebase-testing-design.md#exact-public-adapter-seam), revision 1; per-invocation schema/case/fixture versions |
| Canonical neutral semantic validation | `scopebase_capture::neutral` | CP10 | CP replay import, SDK metadata, NX07 byte-envelope adapter, independent C/Mojo clients through NX | [Capture seam](../superpowers/specs/2026-10-17-scopebase-capture-design.md#canonical-neutral-validation-seam-for-selective-interoperability), exact neutral v1 |

The registry records provenance and design contracts; it cannot instantiate any runtime authority. Dependencies in the [master plan](../superpowers/plans/2026-10-17-scopebase.md) remain controlling. These entries do not move tasks or profiles to implemented/qualified states.

## Held file

The exact selected public declarations are:

```rust
// scopebase_linux::file
pub struct HeldFile { /* private File and acquisition evidence */ }
pub struct ProcFdResolver { /* private held /proc/self/fd directory */ }
pub enum SymlinkPolicy { Follow, RejectFinal }
impl ProcFdResolver {
    pub fn open_self() -> Result<Self, LinuxError>;
}
impl HeldFile {
    pub fn open(path: &Path, resolver: &ProcFdResolver,
                symlinks: SymlinkPolicy) -> Result<Self, LinuxError>;
    pub fn from_file(file: std::fs::File) -> Result<Self, AdoptFileError>;
    pub fn stat(&self) -> Result<StatObservation, LinuxError>;
    // LX03/LX04: export only with the read/control implementation, never as an LX02 stub.
    pub fn read_all(&self, limits: ReadLimits,
                    control: &OperationControl) -> Result<FileRead, LinuxError>;
}
impl AsFd for HeldFile {
    fn as_fd(&self) -> BorrowedFd<'_>;
}
```

`AdoptFileError` exposes `error: LinuxError` and `file: File`; refusal returns exactly the submitted owner/FD. Adoption validates fstat/type, F_GETFL readable mode and F_GETFD before optional F_SETFD(original OR CLOEXEC), the final fallible step. It never dup/reopens, reads/seeks or changes shared status/cursor. A failed set retains its primary errno, performs one flag observation, and reports Unchanged/CloexecSet/Unknown without restoration; before any set the effect is NotAttempted. Success cannot retroactively close the incoming non-CLOEXEC inheritance window.

`open` admits nonempty raw paths up to 4095 bytes without NUL, with fixed 4096-byte C-string scratch and zero operations on admission refusal. Then it checks creating PID, retains an O_PATH regular inode before any data open, reopens only through the retained resolver, and compares regular type plus raw device and inode while both owners remain live. No fallback/retry; RejectFinal concerns only the final symlink. No read/control placeholder is exported in LX02.

The [resolver validation sequence](../superpowers/specs/2026-10-17-scopebase-linux-design.md#retained-resolver-validation-and-support-boundary) requires procfs type, bounded self/PID checks and a fresh CLOEXEC pipe created after candidate acquisition, reopened as O_PATH and checked by type/device/inode. It supports ordinary procfs/shared FD tables with main-thread proc entries available; coherent hostile proc/FD substitution, unshared-table reuse and fork-without-exec reuse are outside guarantees. This is not namespace attestation. Ambient `/proc` replacement alone does not invalidate a retained directory; never reacquire ambient paths, and report observed retained-resolution failure/mismatch. Fresh-pipe denial/unavailability refuses resolver creation. Its approved dependency closure is rustix 1.1.5 `std,fs,pipe`, with exact inputs/features bound before implementation.

HeldFile and ProcFdResolver have private fields and no Clone, raw-owning conversion, mutable File access, Deref, serde or owner construction from keys/reports. Callers share Arc; attachments retain original authority through successful retirement or explicit unresolved custody. AsFd is borrowed integration, not protection against deliberate descriptor misuse. Both are Send+Sync in the supported shared-table context. Positional reads remain interval observations. Drop releases its FD once without close-EINTR retry and proves no backend retirement or hard latency bound.

The [stat handoff](../superpowers/specs/2026-10-17-scopebase-linux-design.md#lx02-stat-observations) is exact:

```rust
// identity; private fields, Copy/Clone/Eq/PartialEq and bounded custom Debug
pub struct StatFileKey { /* raw device:u64, inode:u64 */ }
impl StatFileKey {
    pub fn device_raw(&self) -> u64;
    pub fn inode(&self) -> u64;
}
pub struct StatObservation { /* key, len:u64, mtime:(i64,u32), ctime:(i64,u32) */ }
impl StatObservation {
    pub fn key(&self) -> StatFileKey;
    pub fn len(&self) -> u64;
    pub fn mtime(&self) -> (i64, u32);
    pub fn ctime(&self) -> (i64, u32);
}
```

No public raw/serde/MapsFileKey/owner conversion exists. Observation conversion rejects invalid nanoseconds, negative/unrepresentable length and unrepresentable seconds/device/inode as ValidateFile/Malformed without invented errno. Equality creates no live authority; acquisition itself need not require unchanged size/times.

The [error/effect/charge contract](../superpowers/specs/2026-10-17-scopebase-linux-design.md#controls-errors-and-effects) has private fields and no public constructors. LinuxError implements std Error/Display/bounded Debug and has `&self` getters `stage()->Stage`, `reason()->Reason`, `source()->Option<&io::Error>`, `effect()->&EffectSummary`, `charges()->&ResourceCharges`. EffectSummary getters are `attempted_operations()->u64`, `completed_operations()->u64`, `target_mappings_created()->u64`, `target_mappings_retired()->u64`, `cleanup()->CleanupDisposition`, `descriptor_flags()->DescriptorFlagEffect`; ResourceCharges getters are `syscall_attempts()->u64`, `fd_acquisitions()->u64`, `peak_new_fds()->u64`, all taking `&self`.

Stage/Reason/CleanupDisposition/DescriptorFlagEffect are non-exhaustive Copy/Clone/Eq/PartialEq. LX02 stages are ResolveProc/AcquirePath/ValidateFile/ReopenHeld; reasons InvalidInput/NonRegular/Unreadable/Denied/Unavailable/Disappeared/ChangedSource/WrongContext/Malformed/Inconclusive. Initial cleanup is NotNeeded/Complete; descriptor flags NotAttempted/Unchanged/CloexecSet/Unknown. Future variants/custody wrappers arrive only with implementing owners. Preserve actual errno and operation-specific classifications from the specification.

Charge every explicit operational syscall, including failure, before execution; successful results complete an operation even if a predicate refuses. PID queries count operations, not explicit syscall charges; successful pipe2 counts two FD acquisitions. RAII closes are excluded; counts do not claim every process syscall. Complete means temporary ownership released, not observed close/durable-write/detach success. Resolver success: 11 explicit calls/13 operations/6 acquired FDs/peak4/final1; file open: 4/5/2/peak2/final1; stat one call/no new FD; adoption three or four calls/no new FD, with failed-set verification charged. Target mapping counts are zero in LX02. No hidden surviving file resource, hard syscall wait or kernel-memory bound follows.

Default LinuxError/AdoptFileError Display/Debug, including alternate/nested formatting, is at most 256 ASCII bytes: static labels and optional numeric errno, no raw path/PID/FD/key/payload or nested source/File rendering. Owner/stat Debug contains fixed type labels only. Explicit getters are opt-in; library output/logging is absent.

Dependent read signatures remain ReadLimits/FileRead/ReadObservations/ReadCharges/OperationControl. LX02 qualifies acquisition; LX03/LX04 implement reads/controls independently. LX05–LX08 separately implement mapping/process domains and evidence. LX11/LX12 and their required cells/installed consumers gate profile readiness; a file acquisition increment cannot close held-file-v1 or mapped-image capability.

## BPF host error and explicit budget configuration (BP01)

**Status:** [BP01 foundation accepted](../reviews/2026-10-18-bp01-foundation.md). This host increment does not establish a runner or runtime qualification.

**Owner:** BP01. **Next consumers:** BP02, BP03, BP04 and TC02.

The std-only host foundation exports non-exhaustive `ErrorKind` and `Stage` enums with the existing ordered variants and `Debug + Clone + Copy + PartialEq + Eq`. `OperationError::new(kind: ErrorKind, stage: Stage, raw_errno: Option<i32>, source: Option<Box<dyn Error + Send + Sync>>) -> Self` stores these caller-supplied values independently and verbatim; `source` is implicitly `'static`. `Error::source` returns the original source by shared reference with the standard trait-object lifetime. Its accessors are `kind()`, `stage()`, `raw_os_error()`, `required_size()` and consuming `with_required_size(usize)`. Required size starts absent and can be replaced by any value, including zero and `usize::MAX`. It implements `Error`, bounded custom `Display`/`Debug` (at most 256 ASCII bytes, never formatting the source, including alternate/nested use), and `Send + Sync`; it is not `Copy`, `Clone`, `Default`, `Eq` or serializable. No `From<io::Error>` or errno-only classifier is provided. Explicit source access/downcasting may run caller code. Effectful operations retain their owner-bearing result types; this carrier creates no authority.

`Limits` contains independent `input_bytes`, `retained_bytes`, `work_steps`, `sites`, `live_links` and `pending_retirements` caps. It is `Debug + Clone + Copy + PartialEq + Eq`; `validate(&self) -> Result<(), OperationError>` returns `Ok(())` for every representable combination, including zero, maximum and cross-field-inconsistent values, without allocation, derived operation arithmetic or permission. `Limits` has no `Default` or unlimited sentinel. Each real operation must deny positive work against a zero corresponding cap and use checked arithmetic before allocation/effects, even with maximum caps. BP02 owns geometry, BP04 split attempts, BP05 cumulative retirement, BP06 frame/staging, BP09 parser and TC02 executor checks. BP01 implements and tests this foundation; later owners implement operational enforcement. Downstream `cargo test` does not run dependency tests.

## Testkit adapter and runner

The exact seam is:

```rust
pub trait ConformanceAdapter {
    fn subject(&self) -> SubjectBinding;
    fn execute(
        &mut self,
        invocation: &CaseInvocation,
        fixture: &FixtureAccess,
    ) -> Result<Observation, CaseError>;
}

pub fn run_profile(
    plan: &ProfilePlan,
    adapter: &mut dyn ConformanceAdapter,
    fixtures: &mut FixtureSession,
    oracle: &dyn CaseOracle,
) -> Result<RunReport, HarnessError>;
```

`SubjectBinding` names the actual consumer's package/version/features/backend/target/source/build identities. The testkit's separately resolved implementation cannot become the subject. Invocation carries versioned bounded operation data, limits and run/operation IDs; it cannot carry arbitrary shell commands. Fixture access supplies only owned handles/paths/synchronization endpoints for that case. FixtureSession owns separate teardown and workload truth.

Observation supplies a SchemaId and bounded actual bytes; expected evidence comes from an independent fixture or model. `CaseOracle::evaluate(&self, case: &CaseSpec, expected: &ExpectedEvidence, observed: &Observation) -> AssertionVerdict` remains outside the production adapter. `CaseError` retains observed stage/category/partial effects; `HarnessError` means the harness cannot judge. Neither means pass by default. Custom adapter/oracle declarations remain explicitly self-reported.

`CaseId::parse(&str) -> Result<CaseId, IdError>` accepts 1–96 bytes, and ProfileId the same grammar up to 64 bytes: initial ASCII alphanumeric followed by ASCII alphanumeric, dot, underscore or hyphen. There is no trimming, normalization or slash selector. H04 family membership does not by itself produce a runnable subcase. TT01 selects required cases, tiers and cells before discovering environments; TT02 computes independent execution/assertion/capability/coverage/harness/cleanup/qualification outcomes. Required missing evidence remains incomplete.

Production packages do not depend on testkit. Developer adapters, independently installed operator tooling and real distributed consumers use this seam; ordinary downstream cargo test does not execute a dependency's tests. A report deserializer never yields a live process/file/map/link owner.

## Neutral semantic validation

The exact v1 declarations are:

```rust
// scopebase_capture::neutral
pub enum UnitTag { Events, Records, Bytes, Objects, Attempts, Nonexecutions, DiagnosticSignals }
pub enum NeutralMagnitudeV1 {
    Exact(u64), AtLeast(u64), Unknown,
    CappedSignal { observed: u8, cap: u8 },
}
pub struct NeutralCounterV1 {
    pub channel: u32, pub unit: UnitTag, pub magnitude: NeutralMagnitudeV1,
}
pub struct NeutralClaimV1 { pub claim: u32, pub reasons: Vec<QualityReason> }
pub struct NeutralObservationV1 {
    pub capture: [u8; 16], pub producer: [u8; 16], pub epoch: u64,
    pub binding: [u8; 32], pub origin: Origin,
    pub counters: Vec<NeutralCounterV1>, pub claims: Vec<NeutralClaimV1>,
}
pub struct NeutralLimits {
    pub counters: usize, pub claims: usize, pub reasons_per_claim: usize,
}
pub struct ValidatedNeutralV1 { /* private checked source/counters/claims */ }
pub fn validate_v1(input: &NeutralObservationV1, limits: NeutralLimits)
    -> Result<ValidatedNeutralV1, ContractError>;
impl ValidatedNeutralV1 {
    pub fn source(&self) -> &SourceRef;
    pub fn counters(&self) -> &[NeutralCounterV1];
    pub fn claims(&self) -> &[NeutralClaimV1];
}
```

CP10 owns validation once. Default/max v1 limits are 4,096 counters, 4,096 claims and 16 reasons per claim; callers may lower them, including zero for empty collections. Check counts before cloning; reject duplicate channels/claims/reasons, all-zero byte-array IDs, invalid capped signals and capped signals outside DiagnosticSignals. Exact zero and Unknown remain distinct accepted values; numeric IDs and epoch may be zero. QueryPartial is transient view evidence, not persistent consumed loss.

NX07 owns bounded binary preflight, count×stride arithmetic, discriminants and version mapping before constructing these raw values, then calls `validate_v1`. Capture does not gain a second native codec or competing validation algebra. SDK uses the three validated accessors for metadata; the result creates no trusted completeness, closure, file or process authority. The validator cannot bound Vec allocations already performed by its caller. Replay imports route through the same semantic validator where applicable and retain historical origin; deserialization is not a live observation.

## Cross-owner change gate

TT01's catalog key is `(CaseId, positive u32 revision)`, and `CaseCatalog::case(&self, id: &CaseId, version: u32) -> Option<&CaseSpec>` performs exact lookup without a latest alias. Every required case reference and selected/transported cell preserves that revision. Historic pairs coexist; active mixed revisions refuse. Private immutable plans survive catalog drop. `ArtifactRegistration` exposes id/entrypoint/path/sha256 as `&str` and revision as `u32`; those getters reveal metadata, not execution authority. Complete frozen definitions and registered artifact bytes remain distinct from test execution, task acceptance and runtime qualification.

Changes to HeldFile invalidate dependent acquisition/read/mapping/attachment/native-owner checks as affected. Changes to the adapter invalidate binding/oracle/runner and all consuming adapters. Changes to neutral v1 semantics invalidate CP10, replay, SDK metadata and NX codec/client vectors. Keep case/profile/schema support revisions and exact consumer/object bindings visible. Root TODO/traceability changes belong to the integration owner; task authors report newly found obligations before dependent implementation proceeds.

LX04 control implementation adds `control::{CancelToken,MonotonicDeadline,OperationControl}` with private fields. Token/control are Clone + Send + Sync; deadline is Copy + Clone + Send + Sync. Cancellation is shared by token clones, deadlines are copied unchanged, and invocation effects/terminal state stay with each operation owner. No public clock/checkpoint/raw-time constructor exists. ConfigureControl/InvalidInput records checked deadline-construction overflow with zero effects/charges; existing failed syscall errno remains primary over concurrent cancellation. Later production operation owners wire the private checkpoint/context seam and retain their actual resource custody.
