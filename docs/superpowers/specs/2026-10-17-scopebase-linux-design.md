# ScopeBase Linux files, mappings and process authority

Normative 2026-10-18 amendment: [decisions and reasons](2026-10-18-scopebase-decisions.md), [executor contract](2026-10-18-scopebase-executor-contract.md), and [task-origin / repair plan](../plans/2026-10-18-scopebase-plan-repair.md). Porting and task readiness follow these amendments; no new implementation or support claim follows.
Status: proposed implementation contract, 2026-10-17. No ScopeBase production code, package, command, fixture or passing result is created by this specification. Product migrations may happen later. A package qualifies through distributed, independently wired real clients; it does not thereby qualify p11scope or OSSLscope.

The normative [master specification](2026-10-17-scopebase-design.md) defines version 0.1.0, the provisional Apache-2.0 userspace policy, pre-1.0 breaking minor releases and distinct completion levels. Historical source licenses and authorized destination terms are distinct; third-party terms remain preserved. Apply [D03](2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination). The implementation plan is [scopebase-linux](../plans/2026-10-17-scopebase-linux.md). The research obligations are [L01–L09 and G01–G23](../../research/2026-10-17-shared-libraries/TODO.md), [H families](../../research/2026-10-17-shared-libraries/testing-strategy.md) and [UC01–UC14](../../research/2026-10-17-shared-libraries/user-conformance.md). Stable existing IDs keep their meaning; LX IDs below identify implementation work rather than new regression families.

## Boundary and delivery profiles

`scopebase-linux` is a Linux-only Rust package. Rust edition 2021 and proposed host MSRV 1.88.0 are subject to foundation compile qualification. The additive Cargo features are `process`, `mapping = [process]`, `supervision = [process]` and `walk`, with default `[]`; each preserves default file semantics. Its host-only default has no BPF, Aya, libbpf, LLVM, native-compiler, async-runtime or donor-application dependency. It does not install tools, change resource limits/credentials/signals, join namespaces or mount filesystems. Initial runtime qualification targets `x86_64-unknown-linux-gnu`; other targets are unsupported until added to the matrix with build and runtime evidence. The named host qualification cells are Linux 5.15, Linux 6.12 and a pinned current control selected by SB02 before qualification; they do not establish a universal BPF floor. Kernel release strings are descriptive; each operation handles syscall availability and denial directly.

| Profile | Implemented boundary required before advertising | Ready-package evidence |
|---|---|---|
| `held-file-v1` | Regular-file authority, stat observations, positional bounded full reads and cooperative controls | H04/H06 and UC01/UC08–UC11/UC13/UC14 as applicable; independent host clients and installed route |
| `mapped-image-v1` | Above plus strict maps/mount parsing, range association, retained proof, explicit calibration and no-new-target-mapping policies | Full selected UC01–UC14 mapping branches and real filesystem/namespace matrix; no BPF requirement |
| `process-observation-v1` | Retained pidfd/proc view and birth/namespace evidence; observation only | H01/H02 applicable birth/reuse/exec/view cases; no exact event stream/current-mm claim |
| `owned-child-v1` | Explicit helper supervision, stopped-child custody, identity-bound signal/wait, cancellation and bounded unresolved admission | H20 and relevant H19/G07–G11/G13; installed helper and actual process tests |
| `bounded-walk-v1` | Explicit caller roots and independently charged traversal resources | H06/H20 work/byte/FD/deadline boundaries through inner operations |

The canonical future installed invocation is `scopebase-conformance run --profile ID --fixture-root PATH --output PATH [--fixture-manifest PATH] [--mapping-policy POLICY]`. ID is exactly one of `held-file-v1`, `mapped-image-v1`, `process-observation-v1`, `owned-child-v1` or `bounded-walk-v1` for these contracts. Filesystem cells use `mapped-image-v1` with an admitted fixture manifest; there is no separate filesystem-matrix alias. Mapping policy values are `no-new-target-mappings` and `allow-private-calibration`. Shared CaseId and ProfileId constructors accept only ASCII `[A-Za-z0-9][A-Za-z0-9._-]*`, with maximum lengths 96 and 64 bytes respectively; slash, non-ASCII, empty values and overlong identifiers refuse at admission. H/UC/G labels remain research cross-references, not an alternative unchecked case-ID grammar.

All five have a specified implementation below. Their readiness gates are independent: shipping a file slice cannot close mapped-image work. No descriptor-bound BPF attachment support is advertised by this crate. The BPF package owns actual attach/detach qualification and retains this crate's owner through unresolved retirement. Output publication, destination alias registries, application shutdown, privacy policy, descendant tracking, proc-connector transport, kernel task-cookie issuance and durable crash recovery stay outside this package.

## Requirements

| ID | Contract | Work / existing obligations |
|---|---|---|
| LX-R01 | Adopt upstream dependencies where they supply the selected contract; record wrappers and provenance | LX01; L01/F02 |
| LX-R02 | Retain the opened regular inode; refuse proc-fd failure without reopening a pathname | LX02; L02–L03/G02/G06/H04 |
| LX-R03 | Full read starts at offset zero, preserves shared cursor, bounds every attempted read and rejects observed change | LX03; L03/G01/H06 |
| LX-R04 | Separate input bytes, syscall work, buffer capacity, retained memory and cooperative wait bounds | LX03/LX04/LX10; G04/G05/G17 |
| LX-R05 | Return stage/reason/source/effect and explicit cleanup disposition; do not parse error strings | LX02/LX04/LX09; G03/G08 |
| LX-R06 | No safe construction of live authority from observation/report data; explicit AsFd borrowing, Arc sharing and CLOEXEC | LX02/LX06/LX08; G06/G10/G11 |
| LX-R07 | Preserve stat/maps/mount/view/content/birth/exec domains and raw pathname bytes | LX05/LX06/LX08; L02/H02/H05 |
| LX-R08 | Raw maps-key equality, hash equality and a matching pathname never establish unique file identity | LX06/LX07; L04/UC02–UC05 |
| LX-R09 | Calibration is explicit, bounded, nonexecuting and fallibly retired; no-new mode never creates a target-backed mapping | LX06/LX07; UC06–UC07/G12 |
| LX-R10 | Proof binds original held owner, object/view/range/method and validity bracket; changed context refuses or reobserves | LX06/LX07; UC04/UC08–UC11/G12 |
| LX-R11 | Metadata stability is best-effort; no atomic content snapshot or current-mm promise follows from it | LX03/LX06/LX08; UC09/H01 |
| LX-R12 | Observation cannot signal/reap; only owned-child authority can control its original child | LX08/LX09; L05/H01/H02/H20 |
| LX-R13 | No hidden global handlers, waitpid(-1), registries, pre-exec callbacks or parent-state mutations | LX09; L06/G11/G13 |
| LX-R14 | Cancellation ends a wait/attempt at documented checkpoints; pending work keeps explicit custody charged to a caller-owned accounting domain through failed Drop and controller reconstruction | LX04/LX09; G04/G07/G08/H19/H20 |
| LX-R15 | Concurrent reads are positional; shared state, panic and post-fork behavior are explicit | LX02–LX04/LX09; G09–G11/G18 |
| LX-R16 | Restart starts a new observer epoch; old generation/proof/partial counters are incompatible | LX08/LX10; L09/H03/G12 |
| LX-R17 | Bound traversal before enqueue/read/sort, and include global plus per-round costs | LX10; L08/H06 |
| LX-R18 | Independently wired clients and developer/operator checks exercise their actual package copy | LX11/LX12; T05–T07/U03–U08/UC14 |
| LX-R19 | Real ordinary/Btrfs/overlay/namespace/restriction cells establish claimed behavior, with active bad controls | LX07/LX12; L04/U05–U06/H05 |
| LX-R20 | Migrations preserve exact-tip donor oracles and retire duplication only after product acceptance | LX13; L07/T06; later work |
| LX-R21 | Diagnostics emit no unsolicited output; safe bounded rendering is separate from sensitive raw fields | LX02/LX11; G22 |
| LX-R22 | Versioned additive features and non-exhaustive outcomes reject incompatible evidence | LX01/LX11/LX12; G19/G20 |

## Public file interfaces

The following signatures are the selected public API, to be implemented, not existing symbols. Module paths form the cross-package handoff.

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
    pub fn read_all(&self, limits: ReadLimits,
                    control: &OperationControl) -> Result<FileRead, LinuxError>;
}
impl AsFd for HeldFile {
    fn as_fd(&self) -> BorrowedFd<'_>;
}
```

`AdoptFileError` exposes `error: LinuxError` and `file: File`; refusal never loses the submitted owner. `from_file` accepts only a readable regular descriptor, rejects O_PATH/write-only/nonregular descriptors, and sets FD_CLOEXEC before admission. It does not change shared open-description status flags or the cursor. A failure setting CLOEXEC returns the original File and reports whether its descriptor flag changed. `open` accepts raw OS path bytes, obtains O_PATH|O_CLOEXEC with O_NOFOLLOW for `RejectFinal`, validates the inode is regular, reopens the held descriptor through the retained proc-fd directory with O_RDONLY|O_CLOEXEC|O_NONBLOCK, and validates the resulting descriptor against the original held inode. Follow applies to ordinary kernel pathname resolution; RejectFinal rejects only the final symlink, not intermediate symlinks. Neither mode promises resolution beneath a trusted root.

The resolver validates a procfs mount and obtains its FD directory in the calling process. Proc-fd reopening is a documented dependency. Missing, mismounted, denied, exhausted or changed resolution returns a stage-specific error. It never retries through the input pathname. Resolver use after caller fork without exec is unsupported. No `/proc/self/fd/N` string is exported as a self-authenticating durable identity. Consumers needing an attachment path must retain the HeldFile and their own resolver through the backend operation.

Fields are private. HeldFile has no public Clone, IntoRawFd, `into_inner`, Deref<File>, mutable file accessor or serde implementation. Consumers share `Arc<HeldFile>`. `HeldFile`, `ProcFdResolver` and immutable read results are Send+Sync; unrelated or same-owner reads may overlap. AsFd is a borrowed escape for integrations, not protection against a caller deliberately closing raw FDs, issuing mutating syscalls, clearing CLOEXEC, changing file contents or defeating the documented semantic contract. These actions invalidate affected guarantees; ordinary safe interleaved reads remain supported. Descriptor duplication by callers is their resource charge and does not create trusted evidence. Drop closes only this owned descriptor, does not panic, does not retry Linux close after EINTR, and supplies no fallible attachment-retirement receipt or hard latency bound.

## Positional reads and resource contracts

```rust
pub struct ReadLimits {
    pub max_bytes: u64,
    pub max_read_calls: u64,
    pub max_buffer_capacity: usize,
}
pub struct FileRead { /* private Arc<Vec<u8>>, before/after stats, charges */ }
impl FileRead {
    pub fn bytes(&self) -> &[u8];
    pub fn observations(&self) -> &ReadObservations;
    pub fn charges(&self) -> ReadCharges;
}
```

FileRead is cheaply Clone and shares one allocation; it has no mutable payload access. The backing Vec is never exposed. The allocation strategy is fixed: try-reserve exactly the validated initial length plus one sentinel byte, reject capacity above max_buffer_capacity after reserve before use, and read directly into initialized storage. The documentation reports requested working capacity, actual granted capacity and retained capacity. Vec allocator over-allocation and allocator metadata are outside the requested-capacity ceiling; a strict process-RSS bound is not advertised. The conservative requested payload bound is one max_buffer_capacity reservation per live read, plus fixed metadata and Arc control storage; actual allocator-granted capacity is separately accounted and can transiently exceed a request before refusal. Concurrent reads and retained results add their independently charged capacities. A strict granted-allocation/RSS ceiling is not advertised. No Vec-to-Arc-slice payload copy is introduced. `try_reserve_exact` failure returns Allocation; allocation aborts in Arc/control metadata or foreign allocators are not claimed recoverable.

Before allocating: check cancellation/deadline, fstat regular/readable object, nonnegative representable size, `size <= max_bytes`, checked `size+1 <= max_buffer_capacity` and nonzero max_read_calls. Bytes read use `pread`/FileExt::read_at from logical offset zero. Short positive reads advance only the local checked offset. Each attempted syscall, including EINTR, consumes one work unit. No individual call requests more than the remaining validated size plus one sentinel byte, and no call requests more than 64 KiB. EOF before the initial size is ChangedSource; a byte beyond that size is ChangedSource, or LimitExceeded if it crosses max_bytes. A final EOF probe is required unless size itself reaches an already observed positive sentinel refusal. Empty regular files succeed only after the EOF probe and matching final metadata. Final stat compares descriptor identity, size, mtime and ctime; disagreement rejects and no partial payload is returned. Same-size concurrent mutation with restored metadata remains unproven; successful bytes are bytes observed during an interval, possibly torn, not an immutable snapshot. No hashes are used as physical identity.

Bytes/work counts include actual calls even on failure; errors expose charges so callers do not silently refund work. Public production reads have no arbitrary reader trait. Development scripted sources live in testkit/internal tests and return separately tagged model observations; they cannot instantiate HeldFile, MapRangeProof or Linux provenance. Safe adapter responses exceeding requested extent, backwards offsets, invalid lengths or impossible charges are rejected structurally before indexing/allocation. A coherently lying model retains model provenance.

## Controls, errors and effects

`scopebase_linux::control` provides `CancelToken::new()`, `cancel(&self)`, `OperationControl::unlimited()` and `OperationControl::new(deadline: Option<MonotonicDeadline>, cancel: CancelToken)`. CancelToken is shared, Send+Sync and idempotent. `MonotonicDeadline::after(Duration) -> Result<Self, LinuxError>` uses checked `Instant::checked_add`; elapsed suspension behavior is the platform Instant/monotonic behavior, not CLOCK_BOOTTIME. Deadline values are process-local and nonserializable; wall/kernel timestamps cannot be substituted. Production clock reads and arithmetic failures never become zero time. A deadline equal to now is expired.

Cancellation is checked before each effect, before/after each syscall, and before result publication. Synchronous open/stat/read/close are not interrupted while in kernel. A cancellation observed after a read discards bytes, returns incurred charges and drops temporary buffers; it does not mutate or close the caller's HeldFile. These APIs do not launch abandonment threads. A mutex, callback or blocked syscall cannot acquire a hard duration claim from a cooperative deadline. An owned subprocess in the supervision profile is the isolation route for bounded waiting, with explicit unresolved outcomes.

`LinuxError` is a non-exhaustive structured error with getters for `stage: Stage`, `reason: Reason`, `source: Option<io::Error>`, `effect: EffectSummary`, and `charges: ResourceCharges`. Stage variants cover ResolveProc, AcquirePath, ValidateFile, ReopenHeld, ReadFile, ReadProc, ParseMaps, ParseMounts, Calibrate, AssociateRange, AcquireProcess, SpawnChild, SignalChild, WaitChild, RetireMapping and Walk. Reason variants cover InvalidInput, NonRegular, Unreadable, Denied, Unavailable, Disappeared, ChangedSource, WrongContext, Malformed, Inconclusive, LimitExceeded(LimitKind), Allocation, Cancelled, Deadline, AlreadyWaited, IntegrationConflict and CleanupUnresolved. Preserve original errno/source; callers never parse Display. Unsupported syscall versus access denial remain distinct.

EffectSummary contains attempted and completed operation counts, target mapping creation/retirement counts and a `CleanupDisposition` of NotNeeded, Complete or Unresolved(ResourceId). File errors have no hidden surviving resource; errors that can retain mappings/children return the typed owner in the operation's failure wrapper as well. No automatic retry follows an ambiguous effect. Structured raw OS path/PID/view fields require explicit accessor opt-in. Default Display/Debug uses bounded escaped labels, no file contents or raw path; the library writes nothing to stdout/stderr and has no global logger. The operator client owns its diagnostic sink and truncation accounting.

Public production code runs no user callbacks while holding internal locks. File operations use no shared cursor/cache locks. Panic unwinds with ordinary RAII; destructors do not panic. Mutable supervision/walk state poisoned by a caught helper panic becomes unavailable until discarded; no poisoning recovery manufactures proof. `panic=abort`, unsafe FD misuse, malicious host kernels and malicious fixtures are outside recovery claims. Calling stateful library APIs in a multithreaded post-fork child before exec is unsupported; no atfork hooks are installed. All internal FDs have atomic CLOEXEC where created.

## Identity domains and proc snapshots

`scopebase_linux::identity` exports separately named, privately fielded observation types: `StatObservation`, `StatFileKey`, `MapsFileKey`, `MountId`, `MountViewId`, `ProcViewId`, `TaskBirthObservation`, `ContentObservation` and `ObservationInterval`. Keys have equality within their own documented domain only. MountId is paired with its view; stat devices cannot be cast into maps devices. Raw device/inode values have explicit constructors for parser/model use returning `UntrustedObservation<T>`; no live proof constructor accepts them. ReadObservations reports `content_snapshot: NotProven` even when metadata checks agree.

`scopebase_linux::procfs` supplies:

```rust
pub fn parse_maps(input: &[u8], limits: ParseLimits)
    -> Result<MapsSnapshot, LinuxError>;
pub fn parse_mountinfo(input: &[u8], limits: ParseLimits)
    -> Result<MountTableSnapshot, LinuxError>;
impl ProcessObservation {
    pub fn acquire(pid: Pid, epoch: &ObserverEpoch, limits: ProcLimits,
                   control: &OperationControl) -> Result<Self, LinuxError>;
    pub fn read_maps(&self, limits: ProcLimits, control: &OperationControl)
        -> Result<MapsObservation, LinuxError>;
    pub fn read_mountinfo(&self, limits: ProcLimits, control: &OperationControl)
        -> Result<MountObservation, LinuxError>;
    pub fn verify_birth(&self, control: &OperationControl)
        -> Result<BirthStatus, LinuxError>;
}
```

Pid is a checked positive pid_t in the captured procfs PID view. The supporting public limit types are fixed as follows; no implicit unlimited Default exists:

```rust
pub struct ParseLimits {
    pub max_bytes: usize, pub max_entries: usize, pub max_line_bytes: usize,
}
pub struct ProcLimits {
    pub parse: ParseLimits, pub max_read_calls: u64,
}
```

All ProcLimits fields are nonzero; callers select explicit ceilings. Parsers preserve raw path bytes (including spaces, escapes and deleted suffix as separate evidence), reject malformed numeric fields, unsorted/overlapping/empty-invalid ranges, duplicate mount IDs, invalid escapes and checked arithmetic overflow. Valid absence is distinct from malformed input. A single parser invocation bounds allocation/entry/sort work; no parser trusts st_size for proc files. Prefer a procfs crate parser only if it meets these exact refusal/path/budget contracts; wrap or add the narrow missing parser otherwise.

Acquire retains the original pidfd, proc directory, birth starttime and PID/mount namespace handles sampled around acquisition. It rejects death, mismatched birth/view or inability to obtain the requested pidfd semantics. A caller may explicitly request a separate `ProcSnapshot::read_unpinned(pid, ...)` descriptive snapshot API; it returns UntrustedObservation and cannot become ProcessObservation. No automatic stat-only fallback satisfies this profile. Retained proc directory pins a PID object, not an mm. verify_birth reports AliveSameBirth, Exited, Changed or Inconclusive; it never reports SameImage. Namespace handles identify a namespace but do not freeze its mount table. Observed exec changes cannot be inferred reliably from birth alone; task/exec producer generation belongs to its own BPF/transport adapter.

## Mapping evidence and calibration

```rust
// scopebase_linux::mapping
pub enum MappingPolicy {
    NoNewTargetMappings,
    AllowPrivateCalibration { max_mapped_bytes: usize },
}
pub struct MappingPool { /* clone shares one accounting domain */ }
pub struct MappingPoolLimits {
    pub max_mappings: usize, pub max_mapped_bytes: usize,
}
impl MappingPool {
    pub fn new(limits: MappingPoolLimits) -> Result<Self, LinuxError>;
    pub fn status(&self) -> MappingPoolStatus;
    pub fn retry_unresolved(&self, control: &OperationControl) -> MappingDrainReport;
    pub fn close(self, control: &OperationControl)
        -> Result<MappingPoolClosed, MappingPoolCloseFailure>;
}
pub struct MappingRequest<'a> {
    pub pool: &'a MappingPool,
    pub held: Arc<HeldFile>,
    pub process: &'a ProcessObservation,
    pub range: MapRange,
    pub policy: MappingPolicy,
    pub retained: Option<&'a MappingProof>,
    pub limits: MappingLimits,
}
pub fn observe_mapping(request: MappingRequest<'_>, control: &OperationControl)
    -> Result<MappingOutcome, MappingFailure>;
```

MapRange is a checked nonempty half-open virtual range with page-offset and length arithmetic validation. MappingLimits has `proc: ProcLimits`, `max_mount_refreshes: u8` (0 or 1), `max_open_fds: usize` and `max_live_mappings: usize`; max_live_mappings is 0 in NoNew mode and 1 for calibration. The FD ceiling charges additional FDs acquired by this operation; caller-retained HeldFile/ProcessObservation/proofs remain separately owned and accounted. It never implies a deadline for a blocked mmap or proc read. MappingOutcome is one of ExactRange(MapRangeProof), KeyCompatible(MappingProof), Mismatch(MismatchEvidence), or Inconclusive(InconclusiveReason). Proofs are opaque, nonserializable, Send+Sync retained values. MappingFailure contains `observation: Option<MappingOutcome>`, `error: LinuxError` and `unresolved: Option<MappingCustody>`; successful observation and failed cleanup remain separately inspectable; MappingCustody keeps the mapped range, original Arc<HeldFile> and a nonforgeable private pool permit until successful munmap; it exposes consuming `retry_unmap(self, &OperationControl) -> Result<(), MappingFailure>`. Admission must satisfy both the operation ceiling and its shared MappingPool's outstanding mapping/byte limits. MappingPool::clone shares the same domain; a fresh operation or reconstructed client with that pool never resets occupied charges. Limits are domain-scoped, not process-global. Creating a different MappingPool is an explicit additional domain/resource budget chosen by the caller; the library cannot cap a caller deliberately creating independent pools.

Pool state is Send+Sync; a private per-slot exclusive Retiring transition prevents concurrent retries or drain of an active custody owner. No pool lock is held across mmap/munmap, proc reads or user code; an acquisition guard restores still-charged custody on unwind. Poisoning refuses admission and retains the anchored records for explicit unresolved reporting. The pool preallocates at most max_mappings records and reserves a slot, page-rounded mapped-byte charge and the held owner before mmap. A pre-effect failure returns the reservation. A successful mmap transfers it to active MappingCustody; successful checked munmap alone releases mapping/byte/retained-owner charge. Failed munmap returns custody with the charge intact. Drop attempts munmap once without claiming a hard wait bound. On failure it transfers the complete address/length/file/permit record into the pool's preallocated unresolved slot, requiring no allocation and never releasing the Arc while the mapping remains unretired. A private retained pool-state anchor keeps that record alive even if the last public handle disappears; no owner is silently forgotten. MappingPoolStatus reports domain ID and active/unresolved/reserved mapping and byte counts. retry_unresolved attempts only records owned by this domain, retains failed records, and returns attempted/retired/unresolved counts plus errors; it cannot release another owner's active slot. close first checks control; cancellation before its state transition returns the unchanged Open pool. Its admission-stop commit atomically changes the shared domain from Open to Closing before reconciliation, blocking new admissions through every clone; it returns MappingPoolClosed and changes state to Closed only with zero occupied records and no active operation; failure returns `MappingPoolCloseFailure { pool: MappingPool, report: MappingDrainReport, error: LinuxError }` in Closing state for drain/close retry. Closed domains cannot reopen, and a stale clone cannot start new work after a successful close.

Dropping the last public pool handle with unresolved records deliberately leaves its preallocated state, file owners and occupied charges retained indefinitely while the process remains alive. This is terminal unresolved retention, not cleanup, reap or a future process-exit receipt. It creates no background worker or global registry. Explicit close is the supported clean shutdown route; callers needing later recovery retain a pool clone. MappingPoolClosed proves closure only for that domain. The state anchor is released after the last occupied record retires and the domain has no active work; an empty domain does not retain resources indefinitely. max_mappings=0 and max_mapped_bytes=0 together admit no mappings and are valid for no-new mode; otherwise both are nonzero. A checked close result is required before qualification can report complete cleanup.

ExactRange uses a separately acquired descriptor for the actual `/proc/<pid>/map_files/<start>-<end>` mapping and compares it against the original retained descriptor in the same validated stat/mount/view domain. Both descriptors remain alive through the comparison. Before/after bounded maps reads must retain the named range, offset and permissions; task birth/view checks bracket the operation. Disappearance, exec-observed contradiction, mount churn or denial yields inconclusive/mismatch, not a path reopen. This proves association for the observation interval and actual acquired map-files object. It does not freeze the target mm or prove uninterrupted mapping between samples; requests for atomic-current-image authority are refused. For Btrfs/colliding raw maps keys, exact association requires this independent per-range route. If it is denied, key equality can give only KeyCompatible; two unrelated same-key objects must never give ExactRange. Overlay copy-up cannot transfer a proof from the old held FD to a newly opened merged path.

MappingProof records original Arc<HeldFile>, stat observations, map key, filesystem classification with error-bearing fstatfs, namespace/proc/mount view, source method, observed range and limits, and the caller epoch. It authorizes only its documented key relation; serialization produces a report without proof authority. No global proof cache exists. The caller owns a bounded collection and supplies retained proof explicitly. Reuse rechecks owner continuity, birth/view, current metadata, method and filesystem eligibility; stale/foreign/unknown proof refuses. Initial reuse allowlist is ordinary ext4 under unchanged held-object/view observations. Btrfs/overlay/tmpfs/unknown raw-key identity reuse is denied; per-range reacquisition can establish a fresh ExactRange. The existence of a prior calibration does not override current permission denial. A self-calibration source view and the requested target view are recorded separately; the observer mount table or self maps evidence cannot silently authorize a foreign namespace association.

NoNew mode never calls mmap on the requested target in any branch, including errors, empty-file handling and retained-proof validation. Existing mapping observations and valid retained proof may be used, otherwise return Inconclusive. Calibration mode permits at most one page-aligned private PROT_READ mapping, never PROT_EXEC/SHARED, with length `min(file_size, page_size)` rounded only for kernel mapping granularity and charged against max_mapped_bytes. Empty files and cap below a page-granularity mapping are inconclusive without mapping. Its own address-containing maps line comes from a bounded self proc read and a distinct minimal oracle in tests. It can establish the held object's kernel-rendered key, not uniqueness across all files. Inability to unmap creates unresolved custody and no clean result. fstatfs failure does not mean ordinary filesystem.

## Process supervision and restart

`scopebase_linux::process` holds observation and child types in separate modules. ProcessObservation exposes no signal, wait or owner-adoption API. An arbitrary PID cannot be converted to OwnedChild. Public process control is optional feature `supervision`; host defaults do not spawn helpers.

```rust
pub struct SupervisorPool { /* clone shares one child accounting domain */ }
impl SupervisorPool {
    pub fn new(limits: SupervisorLimits, integration: ReapIntegration)
        -> Result<Self, LinuxError>;
    pub fn status(&self) -> SupervisorStatus;
    pub fn drain(&self, policy: ChildDrainPolicy, control: &OperationControl)
        -> SupervisorDrainReport;
    pub fn close(self, control: &OperationControl)
        -> Result<SupervisorClosed, SupervisorCloseFailure>;
}
pub enum ChildDrainPolicy { ReapOnly, TerminateStopped, TerminateAllQueued }
pub struct ChildSupervisor { /* helper and clone of explicit pool */ }
impl ChildSupervisor {
    pub fn new(helper: VerifiedHelper, pool: &SupervisorPool)
        -> Result<Self, LinuxError>;
    pub fn spawn_stopped(&mut self, spec: ChildSpec, control: &OperationControl)
        -> Result<StoppedChild, ChildSetupFailure>;
}
impl StoppedChild {
    pub fn release(self, control: &OperationControl)
        -> Result<RunningChild, ReleaseFailure>;
    pub fn terminate(self, control: &OperationControl)
        -> ChildWaitOutcome;
}
impl RunningChild {
    pub fn wait(self, control: &OperationControl) -> ChildWaitOutcome;
    pub fn terminate(self, control: &OperationControl) -> ChildWaitOutcome;
    pub fn detach(self) -> DetachedChild;
}
```

VerifiedHelper is an explicit absolute helper file plus distributed build identity, never a PATH search or implicit download. ChildSpec has executable/argv/environment/cwd, explicit stdin/out/err OwnedFd transfers, maximum argument/environment bytes and no user pre_exec closure. The installed helper prepares descriptor routing, reports readiness through a private bounded IPC channel, stops itself and later execs the requested executable after release. No application code or allocator is run in the Rust library's post-fork child; standard Command launches the helper, and its child-side setup is limited to the audited standard process-spawn path. Helper protocol and sources ship with the package. No output staging/publication is included; a supplied FD's destination/truncation policy belongs to the caller.

ReapIntegration initially has one explicit mode CallerExclusive: the caller guarantees no competing waiter or external SIGCONT/release/kill of this child. This is a caller contract, not independently proven authority. The caller must serialize changes to signal/reaper integration during supervisor use. Preflight rejects detectable SIGCHLD=SIG_IGN or SA_NOCLDWAIT; the library neither installs handlers nor blocks signals globally. A competing reaper causing ECHILD yields AlreadyWaited/Unresolved with original pidfd and known status, not successful reaping or permission to kill a recycled PID. A custom SIGCHLD handler is allowed only when it does not reap owned children. Library code uses exact-child wait operations and pidfd_send_signal; never PID/PGID kill, waitpid(-1), or signal a foreign target. No proc lifecycle transport fallback is hidden here.

SupervisorLimits has `max_children: usize`, `max_pending_setup: usize`, `max_unresolved: usize` and `max_protocol_bytes: usize`. All are nonzero; max_pending_setup and max_unresolved cannot exceed max_children. Every admitted child reserves one unresolved-capable slot before spawn, so effective admission is bounded by min(max_children, max_unresolved) as well as max_pending_setup during setup; no occupied slot is promised twice. A slot and immediate std::process::Child custody are recorded before any fallible post-spawn setup. The helper readiness/birth bracket and original pidfd must be acquired before signaling; acquisition failure cannot fall back to PID kill and returns original child custody. A slot is released only after successful exact-child reap with observed exit disposition. Detach transfers the same still-charged slot to DetachedChild; it never releases or resets the domain charge. Transfer to a separately bounded caller domain is not exposed in v1. Failure before spawn releases it; failure after spawn returns ChildSetupFailure with optional OwnedChildCustody and phase. Running wait cancellation returns `ChildWaitOutcome::Pending { child: OwnedChildCustody, reason }`; it does not silently detach/kill. Failure wrappers retain the input child owner unless the child was demonstrably reaped. ChildWaitOutcome is Exited(ChildExit), Pending { child: OwnedChildCustody, reason: WaitPendingReason }, or Unresolved { child: OwnedChildCustody, error: LinuxError }. OwnedChildCustody preserves the current phase/pidfd/slot and exposes consuming `wait(self, &OperationControl) -> ChildWaitOutcome` and `terminate(self, &OperationControl) -> ChildWaitOutcome` for reconciliation. A pending custody owner cannot be mistaken for a stopped or unreleased child. Terminate uses original pidfd, checks its return, then exact-child wait; timeout leaves custody. Release has a single commit point at successful pidfd SIGCONT and records Released even if exec subsequently fails. ReleaseFailure is Unreleased { child: StoppedChild, error: LinuxError } or Released { child: RunningChild, error: LinuxError }. Retry after committed release is forbidden by the returned RunningChild type; it cannot call release again. No error returns a StoppedChild after SIGCONT committed. DetachedChild retains child identity, reap responsibility and supervisor slot and exposes consuming `wait(self, &OperationControl) -> ChildWaitOutcome` for explicit reconciliation; detaching is a visible transfer, not cleanup success.

SupervisorPool and its shared state are Send+Sync; ChildSupervisor changing operations require exclusive &mut self. Per-slot exclusive reconciliation prevents two drains/waits from acting on one queued child. No pool lock spans a signal/wait syscall or user code; panic guards restore charged ownership, and poison refuses admission while retaining unresolved records. SupervisorPool owns fixed-capacity shared state, the preallocated unresolved queue, reaping integration and every child reservation. ChildSupervisor, StoppedChild, RunningChild, DetachedChild and OwnedChildCustody each retain that state; dropping a controller before or after children cannot destroy outstanding custody or reset capacity. Each child owner exposes `pool(&self) -> SupervisorPool` to retain/reconstruct the same accounting domain. A replacement ChildSupervisor::new(helper, &same_pool) observes all prior active/detached/queued slots. A different SupervisorPool::new intentionally creates an independent domain; limits are per explicit domain and are not a global limit against callers deliberately making more domains.

Drop does not wait indefinitely or claim reap. A stopped-child Drop may request identity-bound termination once, then transfers exact-child wait authority, pidfd, phase, helper/output FDs and the still-charged slot into its pool queue. RunningChild, DetachedChild and OwnedChildCustody Drop transfer all custody there without a hidden kill. Queue capacity and backing storage are reserved before admission, so these transfers do not allocate. A failed or unconfirmed signal never releases custody. No active-child permit is released on controller or child-handle Drop. When the same domain has no free slot, subsequent controllers refuse spawn before effect, including after earlier controllers were dropped.

SupervisorStatus exposes domain ID, active handle count and pending-setup/running/detached/queued/unresolved/reaped counters with occupied-slot counts; reaped history counters never authorize a different child. drain visits only queued owners in that domain, never live child handles. ReapOnly performs exact-child nonblocking reap/poll with cooperative checks; TerminateStopped may signal only queued stopped children, and TerminateAllQueued explicitly permits signaling any queued immediate child through its original pidfd. Pending wait, ECHILD, timeout or failed signal stays charged and appears independently in SupervisorDrainReport attempted/reaped/pending/unresolved counts and errors. close checks control before effects and returns the unchanged Open pool if already cancelled. Its admission-stop commit atomically changes its shared domain from Open to Closing, blocking new spawn through every controller/clone, and uses ReapOnly; SupervisorClosed changes that domain to Closed and requires no active handles, setup or queued/unresolved child. Otherwise `SupervisorCloseFailure { pool: SupervisorPool, report: SupervisorDrainReport, error: LinuxError }` returns the still-live Closing domain for drain/close retry. Closed/Closing domains cannot admit new children or reopen; stale controllers refuse. close never kills a running child implicitly.

A retained private state anchor prevents deallocation of unresolved queue owners when the last public controller/pool/child handle disappears. That last-handle Drop produces terminal unresolved retention: the queue, original pidfds/child wait authority and slots stay alive indefinitely while the caller process continues. It does not synthesize exit or successful reaping, authorize a recycled PID, release a budget, or launch an unbounded waiter. There is no global recovery registry; if every public pool handle is discarded there is no supported reacquisition by PID/report. Applications retain a pool clone and explicitly drain/close when recovery is needed. An empty pool releases its state normally after the last handle drops; the private anchor exists only while unresolved ownership remains. This terminal fallback is bounded by the domain's previously reserved capacity and is a failed shutdown, never readiness evidence. No process-exit handwave substitutes for this still-live disposition.

No global worker, destination registry or output alias state exists. Only the immediate child is owned; daemonized/double-forked descendants are not tracked or controllable through this API. Compiler-process-tree supervision needs its separate TC contract. Caller fork before exec invalidates supervisor/pool use in the child; no inherited wait on absent threads is allowed.

`ObserverEpoch::new() -> ObserverEpoch` creates a process-local non-reused owner identity using a retained Arc allocation; live equality uses its retained identity, not a serialized counter. Reports include a diagnostic run ID assigned by the runner, which cannot recreate the epoch. A new observer/restart always creates a new epoch and rescan. Birth observations and producer exec generations are not interchangeable; old cookies/counters/partial windows cannot be merged merely because PID/path bytes repeat. Persistent crash-resume, adoption of preexisting children and durable BPF recovery are unsupported.

## Discovery budgets

`scopebase_linux::walk::walk(root: &HeldDirectory, budget: &mut WalkBudget, control: &OperationControl) -> Result<WalkBatch, WalkFailure>` is a separate optional `walk` feature. HeldDirectory opens an explicit caller root through a directory FD; traversal is descriptor-relative, never follows directory symlinks, never crosses mount boundaries unless `WalkPolicy::AllowMountCrossing` is explicit, and has no ambient default root. It does not replace cap-std/pathrs where those meet the contract. A root regular-file reader does not depend on traversal.

WalkBudget is created by `WalkBudget::new(per_round: WalkLimits, total: WalkLimits, epoch: &ObserverEpoch) -> Result<Self, LinuxError>`. WalkLimits contains `max_entries_visited: u64`, `max_entries_queued: usize`, `max_depth: usize`, `max_path_bytes: usize`, `max_read_bytes: u64`, `max_output_bytes: usize`, `max_open_fds: usize`, `max_stat_calls: u64` and `max_read_calls: u64`; each is an explicit nonzero limit. All sums and conversions are checked and a per-round ceiling cannot exceed its total ceiling. WalkPolicy is fixed by `HeldDirectory::open(path: &Path, policy: WalkPolicy) -> Result<Self, LinuxError>`; the default explicit variant is StayOnMount, with AllowMountCrossing opt-in. Charge before enqueue, path clone, allocation, open, read or sort; no collect-then-check path exists. Batches are bounded and sorted only within their charged batch; deterministic global ordering is not promised. Failure carries partial output, consumed charges and remaining queue custody; retry can resume only that same state and epoch. Cancelled scans cannot refund spent work. A deadline check in an outer directory loop does not establish inner blocked operation cancellation; tests place the block after entering the charged open/read. No hidden filesystem worker threads are created.

## Qualification, acceptance and definition of done

SB01–SB03 own source/license/interface registration, foundation/dependency/MSRV and compatibility documentation. TT01–TT10 own the shared case registry, harness, Linux fixture worker, real filesystem provisioners/no-mmap audit, BPF objects/live cells, faults/models/fuzz, installed delivery, causal CI, performance/coexistence and release profiles. The root testkit/provisioner work supplies immutable case versions, fixture workers, operator result schema and environment recipes. This subsystem supplies production adapters and case-specific oracles; it does not duplicate the root runner. The frozen adapter is `scopebase_testkit::adapter::ConformanceAdapter { fn subject(&self) -> SubjectBinding; fn execute(&mut self, invocation: &CaseInvocation, fixture: &FixtureAccess) -> Result<Observation, CaseError>; }`. The subject identifies actual compiled package/build/features/backend; observations are bounded schema-tagged bytes, independently decoded against fixture truth. An adapter cannot supply its own expected answer. Production scopebase-linux never depends on scopebase-testkit. Required cells are selected before checking local availability. A missing required cell stays incomplete. The finite mapping matrix is ordinary ext4 control; Btrfs base/subvolume plus actual distinct-object raw-key collision (snapshots admitted when needed); overlay lower/upper split behavior and aligned control plus verified copy-up; foreign mount-view/churn; real proc/mmap/audit denial. Overlay fixture manifests explicitly identify layer filesystems, xino off/on/auto or excluded choices, metacopy and credential context. Do not claim a Cartesian union from one generic overlay result. Both policies exercise their applicable positive and refusal branches.

| Layer | Required independent oracle and bad control |
|---|---|
| Unit/parser | Handwritten raw byte fixtures and integer interval reference; wrong delimiter, overlap, escape, zero/missing, overflow and budget mutants |
| State/model | Append-only acquisition/transfer ledger; early owner release, raw-key equality, generation erasure, silent work refund and cancellation-after-commit mutants |
| Real Linux | IPC barriers and actual held FDs/children/mappings; A→B→A, unlink, duplicate cursor, grow/truncate, exec/reuse/namespace, ECHILD and FD exhaustion |
| Mapping effects | Isolated syscall audit sees transient target-backed mmap between setup and production observation; hidden-calibration mutant fails UC07 even after successful unmap |
| Distributed clients | `examples/held-file-inspector` inspects existing owned-worker mappings; `tests/downstream/linux-adapter` supervises a child then reads/maps its inputs; each independent lockfile and real API wiring |
| Later attachment | BPF client's actual backend/final object plus active A and excluded B workloads; held original file through failed detach; separate BPF owner, never replaced by a fake link |

Each positive has independently generated nonempty fixture activity and an active negative population where exclusion is claimed. An assertion-killing mutant must reach the semantic check; crash/setup failure does not count. Hold byte patterns and fixture ledgers outside production helpers. For key-collision tests, prove two distinct held objects and actual equal raw keys before testing the resolver. For copy-up, prove the transition occurred before evaluating reuse. A correct refusal case can PASS while capability remains denied/unknown; it cannot satisfy a required positive support branch.

Every LX task is done only when its listed production path, API contract, deterministic valid/bad controls, bounds, cleanup and affected tests exist and pass at the candidate bytes, with provenance/license records. Required custody tests include repeated failed munmap plus dropped custody and later admission in the same pool; supervisor reconstruction with the same pool; detached owners holding their slot; every controller/child/pool destruction order; explicit drain/close recovery; and last-public-handle terminal retention without forgetting original authority. Deliberately new independent domains are reported as separate budgets rather than being claimed globally bounded. Package ready adds source-archive and read-only installed/offline downstream runs, immutable fixture closure, minimal/default/supported-feature-union and qualified MSRV builds, doctests, required real cells, independent review and no unresolved required cleanup. User-local diagnostic success supplements the maintainer matrix and never replaces runtime revalidation. Product migrated additionally requires master MG01/MG02 donor acceptance; LX13 only supplies their compatibility packet. No task is complete merely because this specification, a test source or a proposed command exists.
