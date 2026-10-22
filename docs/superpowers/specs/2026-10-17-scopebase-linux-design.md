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
    // LX03/LX04: export only with the read/control implementation, never as an LX02 stub.
    pub fn read_all(&self, limits: ReadLimits,
                    control: &OperationControl) -> Result<FileRead, LinuxError>;
}
impl AsFd for HeldFile {
    fn as_fd(&self) -> BorrowedFd<'_>;
}
```

`AdoptFileError` exposes `error: LinuxError` and `file: File`; every refusal returns exactly the submitted File, retaining its FD number and ownership. Adoption performs fstat/type validation, F_GETFL, then F_GETFD. Reject O_PATH and any access mode other than RDONLY or RDWR; RDONLY is numerically zero, so test the masked access mode by equality. Preserve shared open-description status flags and cursor; never dup, reopen, seek, read or F_SETFL. If CLOEXEC is absent, F_SETFD(original flags OR CLOEXEC) is the final fallible admission step, followed by infallible publication. An already-CLOEXEC descriptor needs no set. Validate supporting state before this commit.

If F_SETFD fails, preserve its errno as primary, perform exactly one F_GETFD observation, and return the original File. DescriptorFlagEffect is Unchanged if the observed flags equal the original, CloexecSet if they equal original OR CLOEXEC, and Unknown if verification fails or observes any other combination. Never substitute the verification errno, claim rollback, restore flags or retry. NotAttempted means F_SETFD was never issued. Adoption establishes CLOEXEC on success; an incoming non-CLOEXEC File's preexisting/concurrent-exec inheritance window is not retroactively eliminated. Library-created descriptors have atomic CLOEXEC at creation.

`open` admits nonempty raw Unix path bytes of length at most 4095, excluding the terminating NUL, with no embedded NUL. Check length before scanning or copying. Rejected input returns AcquirePath/InvalidInput with no source, PID query, syscall or copied path. Copy admitted bytes once into fixed `[u8;4096]` storage, append NUL and pass a validated borrowed CStr; no growing path/CString allocation. Non-UTF8 bytes are accepted. Kernel component/resolution limits still apply; not every reachable path is promised a one-call open.

After path admission, compare a fresh `std::process::id()` to the resolver's creating PID; mismatch returns ResolveProc/WrongContext before acquiring any file FD. Obtain O_PATH|O_CLOEXEC, adding O_NOFOLLOW for RejectFinal; fstat and refuse nonregular files before any data open. Retain this owner while reopening its decimal FD number through the retained resolver with O_RDONLY|O_CLOEXEC|O_NONBLOCK. Fstat the reopened FD and require regular type plus raw stat device **and** inode parity while both owners are live; then release the O_PATH owner. No pathname fallback or retry. Acquisition extracts type/key; it does not require unchanged length/timestamps. Follow uses ordinary kernel path resolution; RejectFinal rejects only the final symlink, not intermediate ones. Neither promises confinement beneath a trusted root.

Fields are private. HeldFile and ProcFdResolver have no public Clone, raw-owning conversion, `into_inner`, Deref<File>, mutable File accessor, serde or constructor from observation/report/raw-FD data. Consumers share Arc owners. HeldFile, ProcFdResolver and immutable read results are Send+Sync in the supported context below. AsFd is borrowed integration access, not protection against deliberate FD closure, mutating syscalls, clearing CLOEXEC or changing content. Such misuse invalidates affected guarantees; ordinary safe interleaved reads remain supported. Caller duplication is caller-charged and creates no trusted evidence. Drop releases its descriptor once, does not panic or retry close after EINTR, and supplies no fallible attachment-retirement receipt or hard latency bound. Consumers needing attachment paths retain the HeldFile and their resolver through the backend operation; no self-authenticating durable `/proc/self/fd/N` string is exported.

### Retained resolver validation and support boundary

The supported context is ordinary Linux procfs serving the creating process's shared FD table, with main-thread proc entries available and no deliberate/coherent substitution of proc links or descriptor slots. Ordinary threads sharing that table are supported. Fork-without-exec reuse, thread-specific FD-table unsharing, malicious mount/FD manipulation and malicious kernels are unsupported. The PID check is defensive, not support for library calls in a multithreaded post-fork child or detection of same-PID unsharing. Recreate the resolver after a supported context transition; no epoch registry is introduced.

`open_self` executes these steps once, without fallback or retries:

1. Query `std::process::id()`. Open `/proc` O_PATH|O_DIRECTORY|O_CLOEXEC and require fstatfs PROC_SUPER_MAGIC.
2. Read `self` relative to that root with readlinkat_raw into a 32-byte initialized stack buffer. Reject full-buffer/truncated, empty, signed, whitespace, leading-zero, nondigit, overflowing or zero values; require canonical positive decimal equal to the queried PID.
3. Open `self` relative to the root O_PATH|O_DIRECTORY|O_CLOEXEC, then `fd` relative to it O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW. Require fstatfs on the candidate directory to be procfs.
4. Query the PID again, repeat the bounded self-link check against the held root, and require agreement with both PID observations. Drop root/self-directory owners, retaining only the candidate FD-directory owner.
5. Create a fresh anonymous pipe using rustix 1.1.5 `pipe::pipe_with(PipeFlags::CLOEXEC)`, retaining both returned owners. Fstat the read end and require FIFO type. Format its FD number as canonical decimal in fixed 32-byte storage.
6. Open that decimal entry relative to the candidate directory with O_PATH|O_CLOEXEC, without O_NOFOLLOW. Fstat the result and require FIFO type plus raw device/inode parity with the still-held read end. This is not a pipe data open; no read/write, polling, splice, ioctl or content exchange occurs.
7. Drop the check FD and both pipe ends; infallibly publish the candidate directory with creating PID. Any refusal releases every acquired owner. Missing/denied/unavailable pipe validation refuses resolver creation, never skips the check.

The exact `std,fs,pipe` feature closure and additional API trials must be bound through controller-owned package policy before implementation; no `process`, mm/event or linux_latest expansion is implied. Pipe creation is an explicit kernel resource effect, with no claimed pipe-buffer/inode byte or process-RSS ceiling. Fixed userspace scratch does not bound kernel memory. No production target reads, mappings, hidden helper threads or global state occur in LX02 acquisition.

Filesystem type/PID alone cannot establish FD context. Fresh-pipe validation addresses the inherited-directory hole: a foreign independently inherited FD table does not already own a pipe created after candidate acquisition; a genuinely shared table resolves the same new descriptors. This is a supported-context check, not cryptographic process/namespace attestation or a global uniqueness promise for stat keys. Coherent hostile slot substitution, coordinated live descriptor transfer/aliasing, manufactured identity collisions and hostile mounts beneath the retained directory are outside the claim. Final held-file parity remains mandatory and cannot repair an unsupported resolver context, including identity collisions on filesystems such as Btrfs.

Ordinary replacement/unmount/overmount of the ambient `/proc` pathname does not itself invalidate a retained directory: continue using that directory only. Observed lookup failure or final parity disagreement returns a stage-specific error. “Changed resolution” means observed retained-resolution failure/mismatch, not universal detection of ambient mount or namespace changes. `from_file` remains available without proc access. Required real mount/namespace qualification remains separate from model/private-seam tests.

## Positional reads and resource contracts

```rust
// scopebase_linux::file
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReadLimits {
    pub max_bytes: u64,
    pub max_read_calls: u64,
    pub max_buffer_capacity: usize,
}
// No Default. Fields are explicit caller limits.
impl HeldFile {
    pub fn read_all(&self, limits: ReadLimits,
                    control: &OperationControl) -> Result<FileRead, LinuxError>;
}
#[derive(Clone)]
pub struct FileRead { /* private data:Arc<Vec<u8>>, observations, charges */ }
impl FileRead {
    pub fn bytes(&self) -> &[u8];
    pub fn observations(&self) -> &ReadObservations;
    pub fn charges(&self) -> ReadCharges;
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ReadObservations { /* private before, after:StatObservation */ }
impl ReadObservations {
    pub fn before(&self) -> StatObservation;
    pub fn after(&self) -> StatObservation;
    pub fn content_snapshot(&self) -> ContentSnapshot;
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContentSnapshot { NotProven }
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ReadCharges {
    /* crate-visible only: read_calls:u64, bytes_read:u64,
       requested_capacity:usize, granted_capacity:usize, retained_capacity:usize */
}
impl ReadCharges {
    pub fn read_calls(&self) -> u64;
    pub fn bytes_read(&self) -> u64;
    pub fn requested_capacity(&self) -> usize;
    pub fn granted_capacity(&self) -> usize;
    pub fn retained_capacity(&self) -> usize;
}
// scopebase_linux::error
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LimitKind { InputBytes, ReadCalls, BufferCapacity }
// Add Stage::ReadFile and Reason::{Allocation,LimitExceeded(LimitKind)}.
impl ResourceCharges {
    pub fn read(&self) -> Option<ReadCharges>;
}
```

`ReadCharges` lives in file/read.rs and is re-exported through file/mod.rs; error.rs can refer to `crate::file::ReadCharges`. Existing ResourceCharges gains `pub(crate) read: Option<ReadCharges>`. All existing construction sites use None, including LX04 tests; read_all always supplies Some. This introduces no recursive layout or public constructor. Existing getters/enum attributes stay unchanged. FileRead, ReadObservations and ReadCharges use fixed-label bounded custom Debug; errors preserve their 256-ASCII-byte bound even with nested LimitKind. FileRead/ReadLimits/ReadObservations/ReadCharges/ContentSnapshot are Send+Sync. FileRead cloning shares allocation; observations and quantitative charge copies do not acquire runtime authority.


The ratified [LX03 read-contract addendum](2026-10-18-scopebase-lx03-read-contract.md) fixes the exact execution order, private seams, source preservation and R01–R15 tests. Read admission, all refusal winners and consumed resource history follow that addendum; an executor does not infer the missing choices from these signatures.

`max_bytes=0` is valid. `max_read_calls=0`, `max_read_calls>u64::MAX-3` or zero buffer capacity refuses InvalidInput before any syscall/allocation, after the entry checkpoint. Exactly three non-read calls (initial fstat, F_GETFL, final fstat) need that u64 headroom; attempts and completed operations are exact, never saturated or refunded. Reads start at local offset zero using rustix pread, preserve the shared open-description cursor, request at most 65536 bytes and the remaining initial size plus one sentinel, and count every attempted pread including EOF/EINTR. Successful publication requires actual EOF at the initial size and matching final held-descriptor identity/length/mtime/ctime. No partial bytes are returned on refusal.

One `Vec::new().try_reserve_exact(initial_size+1)` follows all checked u64/usize/isize/signed-offset admission checks. Report requested, allocator-granted and retained capacities separately; reject overgrant before initialization/read, without hiding its transient allocation. Initialization uses at most 65536-byte chunks and no second payload scratch buffer. FileRead cheaply clones one `Arc<Vec<u8>>` without a Vec-to-Arc-slice copy or shrink. Every error retains historical work/bytes/requested/granted charges and reports retained capacity zero; no strict RSS/granted-allocation or recoverable Arc-allocation promise follows.

Successful syscall effects/bytes are recorded before the post-call checkpoint and its stop wins before interpreting that successful result. A failed syscall preserves its primary errno/classification. An interrupted pread is charged once; a stop at its post-call checkpoint returns Inconclusive with original EINTR, while permitted continuation retries only through the next checkpoint/work admission. Work exhaustion there returns LimitExceeded(ReadCalls), source None. Initial/final fstat and F_GETFL EINTR are terminal. The final publication checkpoint occurs after Arc construction and metadata validation; subsequent cancellation does not retract success.

Read observations and quantitative charges create no runtime authority. Even matching metadata yields `ContentSnapshot::NotProven`; bytes may be torn by same-size/restored-metadata mutation. FileRead retains no HeldFile, proof, map, attachment owner or authority to reread. Borrow the original HeldFile throughout the call and never close or replace it on read failure. Cleanup NotNeeded describes no newly acquired native resource, not a native-retirement receipt. Cooperative cancellation never interrupts a blocked syscall or abandons a worker.

## Controls, errors and effects

`scopebase_linux::control` provides `CancelToken::new()`, `cancel(&self)`, `OperationControl::unlimited()` and `OperationControl::new(deadline: Option<MonotonicDeadline>, cancel: CancelToken)`. CancelToken is shared, Send+Sync and idempotent. `MonotonicDeadline::after(Duration) -> Result<Self, LinuxError>` uses checked `Instant::checked_add`; elapsed suspension behavior is the platform Instant/monotonic behavior, not CLOCK_BOOTTIME. Deadline values are process-local and nonserializable; wall/kernel timestamps cannot be substituted. Production clock reads and arithmetic failures never become zero time. A deadline equal to now is expired.

LX04 freezes controls as immutable deadline plus shared cancellation observations: CancelToken and OperationControl are Clone + Send + Sync; MonotonicDeadline is Copy + Clone + Send + Sync. Token clones share cancellation, while control clones copy the original absolute deadline without resetting it. There is no generic shared first-stop latch: each invocation returns its terminal reason, and collection-wide first-stop policy remains with the collection adapter. A fresh checkpoint checks cancellation before deadline equality/expiry. An already failed syscall retains its primary reason/source errno even if cancellation races; successful effects and charges are recorded before the post-call checkpoint. The final publication checkpoint defines the cooperative race boundary, not a promise that a later cancellation retracts a published result.

MonotonicDeadline construction overflow is ConfigureControl/InvalidInput with source None, zero effects/charges, NotNeeded cleanup and NotAttempted descriptor flags. ConfigureControl is added to the public Stage only with that implemented constructor. Clock/configuration queries are not recorded as operational syscall effects. Checkpoints perform no explicit I/O, allocation, locking, sleeping or background work, but the platform implementation of Instant::now may enter the kernel; this is neither a zero-syscall nor a hard-duration promise. Private test-only clock injection runs at most once per checkpoint (zero for pre-cancelled or deadline-free controls), and no injection API is public.

For operations accepting OperationControl, cancellation is checked before each effect, before/after each syscall, and before result publication. The LX02 acquisition/adoption/stat signatures accept no control and do not imply cancellation checkpoints. Synchronous open/stat/read/close are not interrupted while in kernel. A cancellation observed after a read discards bytes, returns incurred charges and drops temporary buffers; it does not mutate or close the caller's HeldFile. These APIs do not launch abandonment threads. A mutex, callback or blocked syscall cannot acquire a hard duration claim from a cooperative deadline. An owned subprocess in the supervision profile is the isolation route for bounded waiting, with explicit unresolved outcomes.

`scopebase_linux::error::LinuxError` has private fields, no public production constructor, and is non-exhaustive. It implements std Error, Display and bounded Debug. Its inherent getters, all taking `&self`, are `stage()->Stage`, `reason()->Reason`, `source()->Option<&io::Error>`, `effect()->&EffectSummary` and `charges()->&ResourceCharges`; std Error::source exposes the same primary error through the trait. Preserve actual errno without stringifying it; callers never parse Display.

Stage, Reason, CleanupDisposition and DescriptorFlagEffect are Copy/Clone/Eq/PartialEq, non-exhaustive enums. LX02 initially implements Stage::{ResolveProc,AcquirePath,ValidateFile,ReopenHeld} and Reason::{InvalidInput,NonRegular,Unreadable,Denied,Unavailable,Disappeared,ChangedSource,WrongContext,Malformed,Inconclusive}. Later implementing owners add the remaining categories below. These future requirements remain; do not create placeholder exports to satisfy them early.

The following complete planned inventory binds the documentation registry, not the set already implemented by LX02. Stage variants cover ConfigureControl, ResolveProc, AcquirePath, ValidateFile, ReopenHeld, ReadFile, ReadProc, ParseMaps, ParseMounts, Calibrate, AssociateRange, AcquireProcess, SpawnChild, SignalChild, WaitChild, RetireMapping and Walk. Reason variants cover InvalidInput, NonRegular, Unreadable, Denied, Unavailable, Disappeared, ChangedSource, WrongContext, Malformed, Inconclusive, LimitExceeded(LimitKind), Allocation, Cancelled, Deadline, AlreadyWaited, IntegrationConflict and CleanupUnresolved.

EffectSummary has private fields and getters taking `&self`: `attempted_operations()->u64`, `completed_operations()->u64`, `target_mappings_created()->u64`, `target_mappings_retired()->u64`, `cleanup()->CleanupDisposition`, `descriptor_flags()->DescriptorFlagEffect`. Initial cleanup variants are NotNeeded/Complete; mapping/child owners later add Unresolved(ResourceId) with the actual failure wrapper retaining typed custody. DescriptorFlagEffect variants are NotAttempted/Unchanged/CloexecSet/Unknown with the adoption meanings above. ResourceCharges has private fields and getters taking `&self`: `syscall_attempts()->u64`, `fd_acquisitions()->u64`, `peak_new_fds()->u64`. LX03 adds `read()->Option<ReadCharges>` with the exact [read contract](2026-10-18-scopebase-lx03-read-contract.md#public-api-frozen-by-lx03-r1): None for all existing non-read operations and Some for every read_all failure, including zero-effect refusal. Mapping/supervision work adds its real charge fields before exporting that behavior. Supporting structs have bounded Debug; no public constructors manufacture charges or effect evidence.

Each explicit open/openat/fstat/fstatfs/readlinkat/fcntl/pipe2 attempt increments attempted_operations and syscall_attempts immediately before the call. Success increments completed_operations even if a later semantic predicate refuses. Each std::process::id query increments attempted/completed operations once but not syscall_attempts; std implementation details are outside the explicit-syscall counter. No EINTR retry. Successful pipe2 counts one completed operation and two acquired FDs; successful open counts one FD. Peak counts simultaneously owned newly acquired FDs in this call, excluding the borrowed resolver and submitted/held File. Failed syscalls acquire zero. Releasing temporaries does not refund counts; pure checks/formatting add none.

The successful resolver sequence has 11 explicit syscall attempts, 13 operations including two PID queries, 6 cumulative FD acquisitions, peak 4 and final 1. Successful HeldFile::open has 4 explicit syscall attempts, 5 operations including the PID query, 2 acquisitions, peak 2 and final 1. Stat has one fstat and no new FD. Adoption success has fstat/F_GETFL/F_GETFD and optional F_SETFD: three or four attempts and zero new FDs. Failure counts include each actual prefix and any failed-set flag verification.

RAII closes are excluded from these operational/syscall counts, which do not claim all process syscalls. File cleanup Complete means every newly acquired temporary owner was released once before error return, not that close/durable-write/backend-detach success was observed. NotNeeded means no new FD was acquired. Adoption failure returns its submitted File explicitly; stat never closes its caller's owner. Target mapping counts are zero in LX02. No hidden surviving file resource, invented file Unresolved receipt, automatic ambiguous-effect retry, close-EINTR retry or hard syscall/Drop/RSS bound follows.

| Condition | LX02 classification |
|---|---|
| Caller path admission failure | AcquirePath/InvalidInput, source None |
| ENAMETOOLONG/ELOOP/ENOTDIR during original pathname acquisition | AcquirePath/InvalidInput, actual source |
| Non-proc type; malformed/truncated/mismatching self link; check-pipe type/key mismatch; creating PID mismatch | ResolveProc/WrongContext, source None |
| ENOTDIR/ELOOP in fixed proc layout traversal | ResolveProc/WrongContext, actual source |
| First regular predicate fails, including RejectFinal symlink | ValidateFile/NonRegular, source None |
| O_PATH or nonreadable adoption access mode | ValidateFile/Unreadable, source None |
| Reopened file nonregular or raw device/inode mismatch | ReopenHeld/ChangedSource, source None |
| Invalid stat observation conversion | ValidateFile/Malformed, source None |
| EACCES/EPERM from these file/proc/pipe operations | Current stage/Denied, actual source |
| ENOSYS/EOPNOTSUPP/EMFILE/ENFILE/ENOMEM | Current stage/Unavailable, actual source |
| ENOENT/ESTALE | Current stage/Disappeared, actual source |
| EINTR/EIO/EBADF/unclassified errno, including unexpected EINVAL from fixed internal flags | Current stage/Inconclusive, actual source |

Failed syscall classification precedes semantic checks on successful results. All resolver steps use ResolveProc; original open uses AcquirePath; first fstat and all adoption/stat calls use ValidateFile; reopened fstat uses ReopenHeld. A missing descriptor does not prove foreign identity. These operation-specific categories are not BPF load diagnoses.

Default Display/Debug of LinuxError and AdoptFileError, including alternate Debug and the complete nested value, is at most 256 ASCII bytes. Emit static type/stage/reason/effect labels and optional numeric errno only; omit paths, payloads, PID/FD numbers, keys and source-error Display/Debug. Use explicit formatting, never derived Debug through File/io::Error, with no growing diagnostic allocation. HeldFile, resolver and stat key/observation Debug use fixed type labels without raw fields. Explicit getters provide opt-in observations/errno; caller formatting of those values is outside this bound. No path is copied for diagnostics. The library writes nothing to stdout/stderr, uses no global logger, and leaves operator sinks/truncation accounting to the operator client. Later structured raw path/PID/view access remains explicit opt-in.

Public production code runs no user callbacks while holding internal locks. File operations use no shared cursor/cache locks. Panic unwinds with ordinary RAII; destructors do not panic. Mutable supervision/walk state poisoned by a caught helper panic becomes unavailable until discarded; no poisoning recovery manufactures proof. `panic=abort`, unsafe FD misuse, malicious host kernels and malicious fixtures are outside recovery claims. Calling stateful library APIs in a multithreaded post-fork child before exec is unsupported; no atfork hooks are installed. All internal FDs have atomic CLOEXEC where created.

## Identity domains and proc snapshots

`scopebase_linux::identity` implements separately named, privately fielded observation types as their owning tasks deliver them: `StatObservation`, `StatFileKey`, `MapsFileKey`, `MountId`, `MountViewId`, `ProcViewId`, `TaskBirthObservation`, `ContentObservation` and `ObservationInterval`. Keys have equality within their own documented domain only. MountId is paired with its view; stat devices cannot be cast into maps devices. Later retained-view/model owners may add explicitly reviewed raw-value constructors returning `UntrustedObservation<T>`; LX02 exports no raw constructor, and no live proof constructor accepts these values. ReadObservations reports `content_snapshot: NotProven` even when metadata checks agree.

LX05's [exact parser contract](2026-10-18-scopebase-lx05-proc-contract.md) owns MapsFileKey, decimal MountDevice, owned immutable MapsSnapshot/MountTableSnapshot and borrowed ParsedMountId. ParsedMountId compares a live table-object borrow plus numeric mount number and is descriptive parse-instance provenance only; it is not MountId, MountViewId, ProcViewId, a namespace generation or runtime authority. The existing two-argument parser APIs remain unchanged. LX08/LX06 own retained runtime view IDs, their binding constructors and any later UntrustedObservation raw/model constructors; LX05 exports none of them. Raw maps tuple equality, raw mount numbers and equal parsed text cannot construct proof, a file owner or process authority.

### LX02 stat observations

```rust
// scopebase_linux::identity; private fields and crate-private constructors
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

Both implement Copy/Clone/Eq/PartialEq and bounded custom Debug; equality creates no authority. Stat uses fresh held-descriptor metadata, never a stored pathname. Signed seconds preserve pre-epoch times; nanoseconds must be in 0..1_000_000_000. Negative/unrepresentable length, seconds or raw device/inode conversion overflow, or invalid nanoseconds refuse observation construction with ValidateFile/Malformed and no invented errno. Acquisition may extract type/key alone; no unchanged-content predicate is added. No public raw constructors, serde, MapsFileKey or owner conversion, extra time wrapper or content hash is introduced. Size/times support later consistency observations, not immutable snapshots or universal identity.

The [ratified LX08 addendum](2026-10-22-scopebase-lx08-process.md) governs the process API and replaces this original process outline with the exact strict constructor, six-FD observation owner, creator authority checks, descriptive results and bounded accounting. Its [verification plan](../plans/2026-10-22-scopebase-lx08-verification.md) remains NOT_RUN; LX08 is not accepted. Pure parser interfaces retain their separate LX05 contract.

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
        -> Result<BirthVerification, LinuxError>;
}
```

Pid is a checked positive pid_t in the captured procfs PID view. The supporting public limit types are fixed as follows; no implicit unlimited Default exists:

```rust
pub struct ParseLimits {
    pub max_bytes: usize, pub max_entries: usize, pub max_line_bytes: usize,
}
pub struct ProcLimits {
    pub parse: ParseLimits, pub max_read_calls: u64,
    pub max_metadata_bytes: usize,
}
```

All ProcLimits fields are nonzero; callers select explicit ceilings. Parsers preserve raw path bytes (including spaces, escapes and deleted suffix as separate evidence), reject malformed numeric fields, unsorted/overlapping/empty-invalid ranges, duplicate mount IDs, invalid escapes and checked arithmetic overflow. Valid absence is distinct from malformed input. A single parser invocation bounds allocation/entry/sort work; no parser trusts st_size for proc files. Prefer a procfs crate parser only if it meets these exact refusal/path/budget contracts; wrap or add the narrow missing parser otherwise.

LX05 uses the [exact pure parser contract](2026-10-18-scopebase-lx05-proc-contract.md) and [verification plan](../plans/2026-10-18-scopebase-lx05-verification.md): mount text decodes non-NUL octal 001..377 exactly once; duplicate mount diagnostics sort by `(number, original_row)` and retain original record order. Parsed observations and table-local IDs carry no runtime authority. The acquisition interfaces below remain LX08 work.

Acquire retains the original pidfd, proc directory, birth starttime and PID/mount namespace handles sampled around acquisition. It rejects death, mismatched birth/view or inability to obtain the requested pidfd semantics. A separate future unpinned descriptive API would need its own selected contract; LX08 adds no unpinned API or descriptive-to-authority upgrade. No automatic stat-only fallback satisfies this profile. Retained proc directory pins a PID object, not an mm. verify_birth reports AliveSameBirth, Exited, Changed or Inconclusive; it never reports SameImage. Namespace handles identify a namespace but do not freeze its mount table. Observed exec changes cannot be inferred reliably from birth alone; task/exec producer generation belongs to its own BPF/transport adapter.

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

`ObserverEpoch::new(ProcLimits,&OperationControl) -> Result<Self,LinuxError>` strictly acquires the original creator pidfd and authenticated active-PID namespace under the [LX08 addendum](2026-10-22-scopebase-lx08-process.md). Real epochs retain two authority FDs and a separate FD-free marker; live equality uses that marker identity, not a serialized counter. Descriptive results retain no authority FD; creator checks precede target operations. Reports include a diagnostic run ID assigned by the runner, which cannot recreate the epoch. A new observer/restart always creates a new epoch and rescan. Birth observations and producer exec generations are not interchangeable; old cookies/counters/partial windows cannot be merged merely because PID/path bytes repeat. Persistent crash-resume, adoption of preexisting children and durable BPF recovery are unsupported.

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
