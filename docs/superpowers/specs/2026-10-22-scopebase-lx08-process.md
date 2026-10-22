# LX08 strict process observation contract

Date: 2026-10-22. Root-selected normative design, promoted from the exact
independently reviewed r2 contract. The [verification plan](../plans/2026-10-22-scopebase-lx08-verification.md)
supplies execution steps and the complete selected/deferred original-test map.
This refines the [LX08 task](../plans/2026-10-17-scopebase-linux.md#lx08-observation-authority-task-birth-and-observer-epochs)
under [D01/D07/D08/D09/D11–D14](2026-10-18-scopebase-decisions.md) and the
[executor contract](2026-10-18-scopebase-executor-contract.md).

**Execution status: INPUTS_UNBOUND; PACKET_READY=false.** Design ratification
does not implement or accept LX08, change task counts, accept TT03, qualify a
profile or report a passing product test. The actual future product base, C7
dependency proof, independently accepted TT02 borrowing maintenance, TT03/TT04
runtime resources, closed actual-EOF orchestration, capable no-control auditor
and final-index joint compatibility remain UNBOUND. [Reviewed input custody](#reviewed-input-custody)
records the exact reviewed bytes and the later TT03 protocol change.

The documentation preparation base is `fbfaae7ee81d1b5627ff81109b67c6650969fae8`;
it does not bind the future LX08 product execution base.

## Claim, source and ownership

Deliver the complete strict observation core: original pidfd, authenticated
retained proc root/directory and PID/mount namespace handles; complete bounded
relative maps/mountinfo reads; sampled birth/liveness; process-local epoch/view
provenance. No signal/wait/adoption, raw pidfd export, unpinned fallback, global
registry, mount-table cache, current-mm/image identity or durable recovery.

Host admission is matched **Own** proc numbering in the observing process's
active PID namespace, whether initial or nested. Own does not imply global
initial membership. Retain and authenticate the actual context; a label, inode,
report, caller-built PidNumbering or failed NS_GET_PARENT is insufficient.
Initial-TGID agreement remains a BPF-adapter policy. An initial observer may
observe a target in a nested PID namespace; do not require their namespaces equal.

The actual common immutable source admission is
`docs/provenance/admissions/2026-10-22-next-host-scopes.json`, SHA256
`e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1`.
Use the selected 83 LX08 ranges in the [adopted source admission](../../provenance/next-host-scopes-20261022.md), from P w003
`2c2713e66292b0d2688508a25f79e813ae823d81` and O checkout-018
`4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`; frozen files remain immutable.
Historical GPL observations and existing OWNER-2026-10-18 host Apache grant stay
distinct. Selected code is ADAPT; bounded root/reader/accounting composition is
NEW because the selected donor has no complete bounded reusable composition.
The selected seccomp cBPF test filter is host-test fixture code, not an eBPF ELF
payload or a load-license qualification. No new dependency source grant follows.

## Exact public surface

All new items below are gated by `feature="process"`. Existing pure proc parsers
remain available without it. Existing file/control behavior is unchanged.

```rust
// scopebase_linux::process
pub struct Pid { /* private positive i32 */ }
impl Pid {
    pub const fn new(raw: i32) -> Option<Self>;
    pub const fn as_raw(self) -> i32;
}
pub struct ObserverEpoch { /* private authority Arc plus FD-free marker */ }
impl ObserverEpoch {
    pub fn new(limits: ProcLimits, control: &OperationControl)
        -> Result<Self, LinuxError>;
    pub fn creation_interval(&self) -> &ObservationInterval;
    pub fn creation_charges(&self) -> &ResourceCharges;
    pub fn creation_effects(&self) -> &EffectSummary;
}
pub struct ProcLimits {
    pub parse: scopebase_linux::procfs::ParseLimits,
    pub max_read_calls: u64,
    pub max_metadata_bytes: usize,
}
pub struct ProcessObservation { /* six FDs, shared real epoch, provenance */ }
impl ProcessObservation {
    pub fn acquire(pid: Pid, epoch: &ObserverEpoch, limits: ProcLimits,
                   control: &OperationControl) -> Result<Self, LinuxError>;
    pub fn read_maps(&self, limits: ProcLimits, control: &OperationControl)
        -> Result<MapsObservation, LinuxError>;
    pub fn read_mountinfo(&self, limits: ProcLimits, control: &OperationControl)
        -> Result<MountObservation, LinuxError>;
    pub fn verify_birth(&self, control: &OperationControl)
        -> Result<BirthVerification, LinuxError>;
    pub fn pid(&self) -> Pid;
    pub fn epoch(&self) -> &ObserverEpoch;
    pub fn birth(&self) -> &TaskBirthObservation;
    pub fn proc_view(&self) -> &ProcViewId;
    pub fn mount_view(&self) -> &MountViewId;
    pub fn acquisition_interval(&self) -> &ObservationInterval;
    pub fn acquisition_charges(&self) -> &ResourceCharges;
    pub fn acquisition_effects(&self) -> &EffectSummary;
}
#[non_exhaustive]
pub enum BirthStatus { AliveSameBirth, Exited, Changed, Inconclusive }
pub struct BirthVerification { /* descriptive values, not descriptors */ }
impl BirthVerification {
    pub fn status(&self) -> BirthStatus;
    pub fn retained_birth(&self) -> &TaskBirthObservation;
    pub fn sampled_birth(&self) -> Option<&TaskBirthObservation>;
    pub fn leader_state(&self) -> Option<u8>;
    pub fn interval(&self) -> &ObservationInterval;
    pub fn charges(&self) -> &ResourceCharges;
    pub fn effects(&self) -> &EffectSummary;
}
pub struct MapsObservation { /* owns MapsSnapshot and descriptive provenance */ }
pub struct MountObservation { /* owns MountTableSnapshot and provenance */ }
impl MapsObservation {
    pub fn snapshot(&self) -> &MapsSnapshot;
    pub fn birth(&self) -> &TaskBirthObservation;
    pub fn proc_view(&self) -> &ProcViewId;
    pub fn mount_view(&self) -> &MountViewId;
    pub fn interval(&self) -> &ObservationInterval;
    pub fn charges(&self) -> &ResourceCharges;
    pub fn effects(&self) -> &EffectSummary;
}
impl MountObservation {
    pub fn snapshot(&self) -> &MountTableSnapshot;
    pub fn birth(&self) -> &TaskBirthObservation;
    pub fn proc_view(&self) -> &ProcViewId;
    pub fn mount_view(&self) -> &MountViewId;
    pub fn interval(&self) -> &ObservationInterval;
    pub fn charges(&self) -> &ResourceCharges;
    pub fn effects(&self) -> &EffectSummary;
}
// scopebase_linux::identity (re-exported from process for ergonomic use)
pub struct ProcViewId { /* Arc marker, no descriptor */ }
pub struct MountViewId { /* distinct Arc marker, no descriptor */ }
pub struct TaskBirthObservation { /* pid, ticks, retained ProcViewId */ }
impl TaskBirthObservation {
    pub fn pid(&self) -> Pid;
    pub fn start_ticks(&self) -> u64;
    pub fn proc_view(&self) -> &ProcViewId;
}
pub struct ObservationInterval { /* private Instant pair */ }
impl ObservationInterval {
    pub fn started_at(&self) -> std::time::Instant;
    pub fn finished_at(&self) -> std::time::Instant;
}
```

Pid accepts exactly 1..=i32::MAX in all build modes and is
Copy/Clone/Debug/Eq/PartialEq/Hash. No From<rustix::process::Pid>, unchecked/raw
owner constructor or serde conversion. Private rustix conversion occurs only
after checking positivity: rustix 1.1.5's from_raw negative check is debug-only.
ProcLimits and BirthStatus are Copy/Clone/Debug/Eq/PartialEq; no Default for limits.

ObserverEpoch, ProcViewId, MountViewId and TaskBirthObservation are
Clone/Eq/PartialEq with bounded Debug, no Hash/Ord/serde/raw/pointer API. A strict
fresh epoch has a private authority Arc holding its checked creator Pid, original
creator pidfd, authenticated active-PID namespace FD/key, creation receipts and a
separate fresh FD-free marker Arc. Epoch clones share exactly those two authority
FDs; cloning never dup's either FD. Equality uses the retained marker identity,
not a numeric PID, namespace inode, descriptor number or reconstructed report.

A fresh acquire creates a distinct ProcView marker retaining ONLY the FD-free
epoch marker, and a distinct Mount marker retaining that ProcView provenance.
The live ProcessObservation retains a real ObserverEpoch authority clone plus
its own six FDs. Its epoch() getter borrows that real authority. ProcViewId,
MountViewId, TaskBirthObservation, BirthVerification and maps/mount observations
retain descriptive markers only, never the epoch authority Arc or any target FD.
Retaining all such results after dropping the last actual epoch and observation
owner retains no creator or target FD. No marker/report can construct an epoch.
Same-epoch independent acquisitions remain different views even if raw PID/ticks/
namespace values match. MountView means retained namespace provenance, not a
mount-table version. No ParsedMountId/capture-ID/BPF-cookie conversion exists.

ProcessObservation, BirthVerification, MapsObservation and MountObservation are
non-Clone/non-Copy/nonserializable, with bounded custom Debug omitting paths,
proc bytes, descriptor numbers and allocation addresses. ObservationInterval is
Copy/Clone/Debug/Eq/PartialEq, privately constructed, not serializable. All these
types are Send+Sync; sharing an observation uses caller Arc. No public descriptor
borrow or signal/wait/child conversion is implemented. Descriptive markers have
no I/O method, and do not preserve any FD even privately.

ObserverEpoch::new is strict and fallible: it captures real creator authority by
the algorithm below. Its constant-size Arc allocations retain ordinary allocator
abort limitations, as existing control tokens do; no hard RSS quota is claimed.
Every public acquire/read/verify authenticates the current creator before any
target I/O. Numeric getpid equality alone is insufficient: both a nonterminal
original creator pidfd and matched authenticated active-PID namespace are needed.
An actual nested PID1 child can otherwise collide with a PID1 parent; an inherited
same-namespace numeric PID can also outlive the creator. Newly invoked inherited
post-fork calls refuse, while a fresh child epoch/session can work in matched Own.
Cross-thread calls in the original creator use fresh descriptions and independent
budgets. No atfork handler or async-signal-safety is advertised; in particular this
is not atomic exclusion of an already in-flight call resumed by a fork in a signal
handler. Use active `pid`, never `pid_for_children`, for the creator namespace.

The interval starts before the entry checkpoint and ends after the final success
checkpoint. It describes operation chronology. Acquisition's admission finish is
sampled only after identity/view validation; no timestamp becomes event authority.
BirthVerification::sampled_birth/leader_state are None on a terminal first TARGET poll
after the complete creator guard; they are Some after a successful retained-stat
sample, including terminal post-poll. A
Changed result's sampled birth carries the same ProcView marker and different
ticks; it is a contradiction report, not newly acquired process authority.

## Error and accounting additions

Append these non-exhaustive Stage variants:
`ConfigureProcess`, `AcquireProcRoot`, `AuthenticateProcView`, `OpenPidfd`,
`AcquireProcess`, `OpenProcMember`, `ReadProc`, `ParseProcStat`, `ParseProcStatus`,
`CheckProcessNamespace`, `PollPidfd`, `VerifyBirth`.
Existing ParseMaps/ParseMounts remain parser stages. Add
`LimitKind::MetadataBytes`. Existing reasons and other limit kinds suffice.

```rust
// scopebase_linux::error; feature process for the new process value types
#[non_exhaustive]
pub enum ProcOperation { CreateEpoch, Acquire, VerifyBirth, ReadMaps, ReadMountinfo }
#[non_exhaustive]
pub enum ProcNamespaceKind { Pid, Mount }
#[non_exhaustive]
pub enum ProcMember {
    Root, SelfLink, CreatorPidfd, Pidfd, ObserverDirectory, ObserverStatus,
    ObserverPidNamespace,
    TargetDirectory, TargetStatus, TargetStat, TargetPidNamespace,
    TargetMountNamespace, Maps, Mountinfo,
}
pub struct PidfdPollEvidence { /* count:usize, revents:i16 */ }
impl PidfdPollEvidence {
    pub fn ready_descriptors(&self) -> usize;
    pub fn revents(&self) -> i16;
}
pub struct ProcessErrorContext { /* operation, optional member, optional poll */ }
impl ProcessErrorContext {
    pub fn operation(&self) -> ProcOperation;
    pub fn member(&self) -> Option<ProcMember>;
    pub fn poll(&self) -> Option<PidfdPollEvidence>;
    pub fn namespace_kind_expected(&self) -> Option<ProcNamespaceKind>;
    pub fn namespace_kind_observed(&self) -> Option<i32>;
    pub fn descriptor_flags_observed(&self) -> Option<u32>;
    pub fn retained_start_ticks(&self) -> Option<u64>;
    pub fn sampled_start_ticks(&self) -> Option<u64>;
    pub fn leader_state(&self) -> Option<u8>;
}
pub struct ProcCharges { /* data fetches and transport capacities */ }
impl ProcCharges {
    pub fn read_calls(&self) -> u64;
    pub fn metadata_bytes(&self) -> u64;
    pub fn body_bytes(&self) -> u64;
    pub fn requested_transport_capacity_bytes(&self) -> usize;
    pub fn peak_granted_transport_capacity_bytes(&self) -> usize;
    pub fn retained_transport_capacity_bytes(&self) -> usize;
}
impl LinuxError {
    pub fn process_context(&self) -> Option<&ProcessErrorContext>;
}
impl ResourceCharges {
    pub fn process(&self) -> Option<ProcCharges>;
}
```

ProcessErrorContext birth fields are present only when birth parsing/guard
comparison reached them; they are descriptive raw values, not constructors for
TaskBirthObservation. Unperformed polls/kind/flag queries have None evidence.
Terminal guard refusal retains the reached poll evidence; Changed/Inconclusive
guard refusal retains sampled/retained ticks and leader state.

New enums/evidence/context/ProcCharges are Copy/Clone/Eq/PartialEq with bounded
Debug; no constructors/serde. Error context contains no raw target bytes or FDs.
The optional process fields are initialized None in all existing unrelated error
constructors. Root serializes these shared-file edits. ProcCharges is the one
transport counter set; ResourceCharges owns syscall/FD counters and existing
parse charges. Do not maintain duplicate parse/syscall totals in ProcCharges.
On reads, ResourceCharges.parse equals the reached parser's actual charges, even
on parser refusal; process context remains present without changing parse stage.

ResourceCharges.syscall_attempts counts each explicit library OS operation:
getpid, open/openat/openat2/pidfd_open, fcntl_GETFD, fstatfs/fstat/fstatat,
read/readlinkat, namespace-kind ioctl and poll. RAII close, allocator/clock internals are excluded as in
the existing package. Effect attempted/completed use the same attempted count and
nonnegative syscall completions, including poll zero and EOF reads. FD acquisitions
count every successful new FD; peak_new_fds excludes borrowed authority FDs:
two at acquire, eight total for one observation/epoch at read/verify, zero at
CreateEpoch. It counts all fresh creator-guard FDs. No target mappings are created/
retired. Cleanup is only relinquishment of temporary Rust descriptor owners; it
never means target exit/reap. Errors close all call-local FDs; constructor success
retains two creator authority FDs, acquisition transfers six more to the owner.
Descriptor flags are NotAttempted before any successful FD acquisition, CloexecSet
after all acquired FDs are checked CLOEXEC, Unknown if a successful acquisition
has not established that bit (failed check or missing bit). A missing-bit error
retains actual returned flags in ProcessErrorContext; a failed flag query has
None there. Other error contexts have no flag payload unless that check failed.
No caller descriptor flags are changed. Observation Drop relinquishes its six
OwnedFd handles and real epoch clone; last actual epoch Drop relinquishes its two
authority handles. Descriptive markers do not keep either set alive. Cleanup is NotNeeded if no call-local temporary owner was created,
Complete after all temporary Rust FD owners were relinquished through the
existing Linux RAII contract; it does not report a close syscall diagnostic or
prove any child/namespace/mount effect was retired. Never retry a consumed raw FD
integer after close. No additional fallible native detach/unmap/delete occurs.

Map errno at the actual operation: EACCES/EPERM -> Denied;
ENOSYS/EOPNOTSUPP/EMFILE/ENFILE/ENOMEM -> Unavailable;
ENOENT/ESRCH/ESTALE -> Disappeared; other transport errno -> Unreadable. Preserve
the original io::Error and raw errno. Poll ERR/NVAL/count contradictions have
Reason::Inconclusive plus exact PidfdPollEvidence and no invented errno.
Structural wrong view is WrongContext; bad syntax/converted fields is Malformed;
a nonpositive native getpid result during CreateEpoch checked conversion is
ConfigureProcess/Malformed (errno/source absent; impossible-native-value test
seam only, no observed nonpositive result; Pid::new remains a checked Option).
nonleader `Tgid != Pid` is InvalidInput at AuthenticateProcView. Target namespace/birth
key changes relative to a retained same-kind sample are ChangedSource; an
otherwise valid namespace handle of the wrong kernel-confirmed kind is
WrongContext. A changed current observer namespace relative to the epoch is
WrongContext, never ChangedSource. Valid insufficient target birth is Inconclusive.

### Exact error-stage routing

| Operation | Stage and member |
|---|---|
| Entry control/limits/getpid creator comparison | ConfigureProcess; member None |
| Valid original creator terminal poll | ConfigureProcess/WrongContext; CreatorPidfd, raw poll |
| Capturing or fstatfs-checking global root, including its flag check | AcquireProcRoot; Root |
| Opening creator directory | AuthenticateProcView; ObserverDirectory |
| Reading root self link, including EINTR/exhaustion | AuthenticateProcView; SelfLink |
| Any pre/retained target numeric directory open/flag check | AcquireProcess; TargetDirectory |
| Original target / creator pidfd syscall/flag check | OpenPidfd; Pidfd / CreatorPidfd respectively |
| Opening/flag-checking an ordinary status/stat/body file | OpenProcMember; actual corresponding status/stat/maps/mountinfo member |
| Reading an ordinary metadata/body file | ReadProc; actual member |
| Parsing complete stat/status | ParseProcStat/ParseProcStatus; actual member |
| Structurally inconsistent own numbering or target Pid/Tgid | AuthenticateProcView; SelfLink/ObserverStatus/TargetStatus as appropriate |
| Any namespace directory/link/FD/stat/kind syscall or comparison | CheckProcessNamespace; ObserverPidNamespace/TargetPidNamespace/TargetMountNamespace |
| Original target / creator pidfd readiness syscall/flag/count consistency | PollPidfd; Pidfd / CreatorPidfd respectively |
| Translating a valid birth result into acquire/read refusal | VerifyBirth; Pidfd for Exited, TargetStat for Changed/Inconclusive |
| Pure maps/mount parser | Existing ParseMaps/ParseMounts and existing parse_line; Maps/Mountinfo process member |

After an open succeeds but its flag check fails, count the acquired FD and retire
its owner on error; a later missing field cannot hide the flag query's actual
stage/errno. Namespace-check byte/read exhaustion uses that stage/member. Any
allocation/limit/control error uses the stage of the work being attempted with
unchanged consumed counters. No stage is guessed from the final enum name. Every CreateEpoch success/refusal,
including entry refusal, has ResourceCharges.process=Some; body_bytes=0,
parse=None and retained_transport_capacity_bytes=0. Existing unrelated operations
continue to have process=None. Nested creator/birth/view guards retain the OUTER
ProcOperation (ReadMaps/ReadMountinfo/VerifyBirth/Acquire), never fabricate a
public VerifyBirth/CreateEpoch invocation or reset its counters. Creator refusal
performs no target poll/open/read; the first actual creator transport/parse error
is retained rather than overwritten by a later inferred context error.

## Proc root, namespace and metadata primitives

**Root-selected ordinary traversal; dependency/runtime proof UNBOUND:** ordinary
descriptor-relative proc descendants use rustix fs::openat2 with
`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV` and
`RDONLY|CLOEXEC` (plus DIRECTORY where required). Global `/proc` is opened once per strict epoch constructor and independently
once per new acquire, with DIRECTORY|CLOEXEC|NOFOLLOW and checked by fstatfs for
procfs. The constructor closes its temporary root; acquire never reuses it. openat2 denial
or absence is an explicit exact-stage error with no openat fallback. The existing
selected kernels are at least 5.15, but kernel version alone cannot prove syscall
availability. The rejected openat+NOFOLLOW alternative has weaker child-overmount
guarantees. Symlink/child-overmount controls require owned namespace fixtures.

Each successful new FD is checked once with fcntl_GETFD. A missing CLOEXEC bit is
Malformed at the acquisition stage, without a silent fixup. `checked_open` means
one open operation and that one flag check; it is exactly two counted attempts
on success. Paths are internally selected single names/numeric positive PID,
never caller-provided arbitrary paths after capturing root.

`namespace_sample(procdir, "pid"|"mnt")` opens a fresh ordinary `ns` directory
through the retained procdir, then intentionally follows that named proc namespace
magic link using openat(RDONLY|CLOEXEC). This route does not apply NO_MAGICLINKS
to the intentionally followed final link. Before and after following it:
readlinkat obtains an exact `pid:[decimal]` or `mnt:[decimal]` link, and
fstatat(SYMLINK_NOFOLLOW) checks a stable proc symlink identity. The opened handle
must be nsfs by fstatfs; fstat supplies its retained device/inode and must agree
with the typed link's inode. Query NS_GET_NSTYPE on the acquired handle; require
CLONE_NEWPID for pid or CLONE_NEWNS for mnt. A mismatch returns
CheckProcessNamespace/WrongContext with expected/observed kind evidence. This
combines kernel-confirmed type and retained proc provenance; neither raw inode,
link nor caller label alone is authority. It does not prove continuity against
unobserved A-to-B-to-A. NS_GET_PARENT is neither used nor needed.

On success this primitive counts nine fixed non-data syscalls (checked ns-dir
open=2, two no-follow link stats=2, checked namespace open=2, nsfs stat=1, handle
stat=1, namespace-kind ioctl=1) and two readlink data attempts, plus bounded EINTR retries. It holds
at most two temporary FDs; caller may retain the namespace handle and closes the
directory before returning. Type/key/link comparisons allocate no unbounded data.


### Private namespace-kind adapter and ABI

Root selected an explicit kernel-confirmed kind query. The local rustix 1.1.5
source has no safe namespace-kind helper. Its generic `Ioctl` trait does expose
the successful kernel `IoctlOutput` (c_int/i32); use a narrowly scoped private
implementation returning that integer directly. Private signature:

```text
process::native::namespace_kind(fd: BorrowedFd<'_>) -> Result<i32, rustix::io::Errno>
```

Its one private audited unsafe boundary contains the custom `unsafe impl Ioctl`
and call: Output=i32, IS_MUTATING=false, opcode=opcode::none(0xb7,0x03), null
operand, output_from_ptr returns the successful `out` value without dereferencing
any pointer. Use only an actual newly acquired namespace BorrowedFd from this
module. No public raw-FD/Ioctl constructor, callback or report route reaches it.
`NoArg` is wrong because it discards the returned integer; `Getter<i32>` is wrong
because NS_GET_NSTYPE returns the integer as the syscall result, not pointed-to
output. There is no retry, fallback or state mutation. A failed ioctl retains
actual errno; ENOTTY is Unavailable for this operation, and unknown nonnegative
kind is WrongContext, never assumed expected. Exact expected/observed kind lives
in ProcessErrorContext, with observed=None on syscall failure.

The ABI reference is Linux UAPI `linux/nsfs.h`: NSIO=0xb7,
NS_GET_NSTYPE=_IO(NSIO,0x3), with CLONE_NEWPID=0x20000000 and
CLONE_NEWNS=0x00020000. Scope is admitted Linux x86_64 GNU only. Derive the opcode
with rustix's existing opcode function; no copied generic syscall framework.
Bind the exact local rustix `src/ioctl/{mod,patterns}.rs` and UAPI evidence hashes
in the immutable private bindings record identified under [reviewed input custody](#reviewed-input-custody). This is a NEW narrow adapter because the safe upstream helper
is absent. It uses existing rustix, requiring no new production libc dependency;
test-only libc=0.2.191 still needs actual closure proof. These inspected interfaces
are not a compiled qualification. The public core stays safe. Positive PID/mount
FD queries, swapped-kind refusal, preserved ioctl denial/unavailability, counted
calls and a wrong-return-extraction control are mandatory before acceptance.

Metadata is read to actual EOF in a fresh open file description with a reusable
Vec; no st_size or first-short-read completion. Every self/namespace link uses
`rustix::fs::readlinkat_raw` on an initialized stack subslice of EXACT length
`min(64, remaining_M + 1)`, which is always nonzero. This freezes the requested
kernel buffer, not merely a post-hoc accounting limit. Charge the attempted call
and all returned bytes, run the successful effect's post-control checkpoint,
then test metadata oversize BEFORE typed-link grammar or full-buffer checks.
If consumed>M, refuse LimitExceeded(MetadataBytes) immediately; at most M+1 bytes
can have been consumed in the whole call. Otherwise returned_len==supplied_len
is a truncated/Malformed refusal; do not allocate/retry a larger link buffer.
Do not use allocating readlinkat helpers with hidden growth. Full-buffer,
invalid and truncated links refuse at their actual SelfLink/namespace stage.
Every returned byte and attempt, including EINTR, counts in the same M/R budget.
The creator's self link is exact decimal getpid(), and own status contains exactly
one each of Pid/Tgid/NSpid; Pid and Tgid equal getpid(), NSpid is exactly that one
positive decimal value. Duplicate/missing/malformed fields refuse; other lines
remain ignored within the complete bounded input. An NSpid sequence in an
ancestor proc view is Foreign/WrongContext, not an automatic translation.

Target status similarly has exactly one positive Pid/Tgid, both equal to requested
Pid. Do not require target NSpid to be a singleton or target PID namespace to
equal the observer's. This increment admits userspace process/TGID leaders whose
required proc members can be acquired; no general arbitrary-TID/kernel-thread
capability is promised. Preserve any earlier reached pidfd/open errno.

Stat ADAPTs the donor last-')'/field22 parser. Require whole-input UTF-8, a
canonical positive PID prefix matching the requested Pid followed by ` (`, last
`)` alignment, a single ASCII alphabetic state token and a checked decimal u64
field22 (post-comm token19). Split the suffix on ASCII whitespace. Comm may contain
spaces, newlines and deceptive parentheses/state bytes; its bytes are not used as
field separators. Start ticks may be zero, never a globally unique task key.
Reader positives 4095/4096/4097/9000 bytes remain valid when the explicit bound
admits them; parser validity is a separate question. Invalid UTF-8 remains refusal.
The pure original classifier may retain its historical Initial/Nested labels for
regression truth, but it is not a host-admission authority constructor.

## Strict epoch creation and creator guard

All effects have control checkpoints immediately before/after; charge returned
effects before the post-check. Failed syscall errors win over a post-check stop.
For successful syscalls, post-check stop wins before interpreting bytes/flags.
Capture interval start before entry control; validate all nonzero/representability
limits before native work. Limits include ParseLimits although constructor and
verify invoke no maps/mount parser. There is no body/parser allocation or charge
in CreateEpoch. Arc allocation/clock internals and RAII close are excluded native
counts under the existing accounting contract.

**ObserverEpoch::new(limits,control), exact order:**

1. Entry control, common limit/capacity validation, counted getpid and checked
   positive-Pid conversion. No target exists in this operation.
2. Fresh checked `/proc` root and procfs fstatfs; bounded exact self link; strict
   checked current numeric observer directory; complete bounded Own status.
3. `namespace_sample(observer_dir,"pid")`; authenticate and retain its active-PID
   namespace FD/key. Close namespace directory and observer directory (status FD
   already closed). Do not use pid_for_children or infer initial membership.
4. pidfd_open(creatorPid,0), check CLOEXEC, then one original creator nonterminal
   zero-timeout poll. The constructor runs in its own original TGID, so it is not
   accepting a pre-birth sample of another process as authority.
5. Close the temporary proc root and drop transport storage; form the FD-free
   marker and real authority Arcs, record validated finish/final control and
   return exactly the two FDs. Final refusal returns no epoch; RAII relinquishes
   every acquired FD, including the would-be retained ones.

Fixed non-data calls=20: getpid1 + checked root2 + root fstatfs1 + checked observer
numeric dir2 + checked status2 + namespace_sample9 + checked creator pidfd2 +
creator poll1. Minimum data attempts=5: self1 + complete status data/EOF2 + pid
namespace links2. It acquires six FDs, peaks at four new FDs, retains two and
retires four temporary FDs on success. Attempts<=20+R. Only one reusable metadata
Vec requested at M+1 is allocated; successful retained transport capacity is zero.
Creation receipts are immutable and observable through the three exact getters.

**Creator guard for acquire:** entry control/limits, counted getpid comparison,
then one poll requiring original creator pidfd nonterminal. Next use acquire's
new authenticated root/self/current numeric Own status/active-PID namespace
sample, and compare the actual current namespace kind/key to the retained epoch.
Keep the new root and observer namespace in acquire's six returned owner FDs.
This completes BEFORE the temporary target pre-probe. A closed constructor root
is never reused or recovered by a path/report.

**Creator guard for read/verify:** use ONLY the observation's retained authenticated
root. Count getpid, compare creator Pid, require the original creator pidfd poll
nonterminal. Read dynamic self through that retained root and require exact current
getpid text; strictly open the CURRENT numeric observer directory, read complete
Own Pid/Tgid/NSpid status, namespace_sample its active `pid`, and compare to the
epoch namespace key/kind. Close ALL four newly acquired temporary FDs before any
target poll/open/read. A cached creator numeric directory without dynamic self/
Own proof is insufficient. No fresh global `/proc` reopen/fallback is allowed.
This uses 15 fixed calls: getpid1 + creator poll1 + checked current dir2 + checked
status2 + namespace_sample9. Minimum data=5 (self1,status2,links2); new acquisitions4,
peak new3 (observer dir+namespace dir+namespace handle), all retired. These data
attempts/bytes share the OUTER operation's single R/M; no creator budget reset.

A retained epoch namespace handle prevents key recycling. Compare its established
key; do not add hidden fstat/ioctl/dup/flag checks to the retained FDs. A fresh
namespace_sample has its one counted kind ioctl. A valid terminal creator poll
is ConfigureProcess/WrongContext/CreatorPidfd with raw poll evidence. It is never
a target Exited result. Poll failure/invalid readiness remains PollPidfd with the
actual error/evidence. Own structural mismatch is AuthenticateProcView/WrongContext;
current namespace wrong-kind or unequal same-kind key is CheckProcessNamespace/
WrongContext/ObserverPidNamespace. Earlier transport/syntax/limit/control errors
keep their actual stage/reason/cost; do not replace denial by WrongContext.

## Acquisition and fixed resource inventory

After entry control and common limits, getpid and original creator poll, complete
the fresh-root creator guard above before step2. Record interval start before
entry and finish only after validated identity/view and final success control.

1. Fresh checked `/proc` root; self link; current observer numeric directory and
   complete Own status; capture active-PID namespace and compare epoch. Close the
   observer directory. This is the current-creator authentication, not a target.
2. Open temporary numeric target directory under root; read/parse pre-birth stat
   and target Pid/Tgid status; close it. These are descriptive pre-samples.
3. pidfd_open(requested Pid,0), check CLOEXEC. It defines this acquisition's original
   target process owner. A zero-timeout target poll must be nonterminal.
4. Open retained numeric target directory under the same root, target poll again;
   read stat and compare PID/ticks with the pre-sample, target poll a third time.
   Preserve the donor's independent three brackets. Read retained target status
   and require Pid/Tgid. Numeric/tick equality cannot reset original-pidfd exit.
5. Capture target active-PID and mount namespaces with namespace_sample. Run the
   full target view_guard below; refuse Exited/Changed/Inconclusive/view change.
6. Create distinct FD-free Proc/Mount markers and retain a real epoch clone;
   validated admission finish, final control, return six new owner FDs.

Returned roles: proc root, observer active-PID namespace, original TARGET pidfd,
target proc directory, target active-PID namespace, target mount namespace. These
six are additional to the epoch's two shared authority FDs, even if namespace keys
agree. No directory cursor is used for data reads. On success acquisitions21,
peaknew8, returned6, temporary retirements15. Borrowing epoch2 gives peak reachable
FDs10; a completed observation/epoch pair reaches8. Another owner in the same epoch
adds6, never another creator pair. There is no global FD quota; concurrent calls
retain their independent temporary peaks.

Fixed successful non-data calls=76: 21 checked acquisitions42 + five namespace
samples' two no-follow link stats/handle stat/fs20 + five kind ioctls5 + root
fstatfs1 + six target polls6 + getpid1 + original creator poll1. Data calls are
additional, so attempts<=76+R. Minimum data23: six complete metadata data/EOF
pairs12 + five namespace samples' links10 + self1. Files need not fit one read;
these minima are not universally sufficient user limit defaults.

Root/path replacement after capture never rebinds an owner. Reads/verify use the
retained root/directory. New acquire independently captures/authenticates current
root. No later global `/proc/<pid>` or self-fd path fallback is allowed.

## Birth verification, guards and read algorithm

Public verify uses metadata/read ceilings stored immutably at acquire; parse
limits are validated at construction but no maps/mount parser is invoked. It
uses a fresh call-local budget. It completes the full retained-root creator guard
above, then polls the original TARGET pidfd, reads complete relative target stat
if nonterminal, and polls that original TARGET pidfd again.
No target namespace change is encoded as BirthStatus::Changed. BirthVerification
does not claim a current mount view and has no mount_view getter.

`view_guard` runs that same internal birth check in the *current operation's*
aggregate budget; requires AliveSameBirth; fresh namespace_samples compare target
PID and mount keys to the retained handles; then one final pidfd poll must remain
nonterminal. A guard has **23 fixed non-data attempts**: birth check4,
two namespace samples18, final poll1. It holds at most two new temporary FDs.
There is no separately resetting public verify invocation inside a read.

read_maps/read_mountinfo execute: entry validation/full retained-root creator guard;
full TARGET view_guard;
fresh body-member checked_open; original pidfd poll; then a loop with original
pidfd poll before each actual body read attempt, and after successful reads or
retryable EINTR, including successful EOF. The private cfg(test) actual-native-reader EOF hook in
the [verification plan](../plans/2026-10-22-scopebase-lx08-verification.md#actual-native-readdeath-original-exact-evidence-and-custody-binding) is call-local and runs after native body read returns zero, before
that postread poll or EOF interpretation; production has no enabled hook. A
non-retryable read error stops before a second poll; preserve its actual errno.
Every new data attempt preflights budget, commits its charge only when issued,
and uses nonempty initialized output. A final body EOF is required. Close body;
run the unchanged LX05 parser with the call's ParseLimits; full view_guard again;
final control checkpoint; publish the parsed snapshot and descriptive markers.
No prefix is returned on any error. Parsing may succeed while the final guard
fails; then return its error with reached parser charges, no observation result.

On successful complete reads, new acquisitions15 (creator4 + target guards5+5
+ body1), peaknew3, all temporary. Borrowed owner6+epoch2 gives total reachable
peak11. Let Rm=metadata data attempts, including all creator/self/namespace links,
and Rb=body attempts. Fixed non-data64 = creator15 + target guards46 + checked
body open2 + initial target poll1. Success calls=64+Rm+3*Rb. An error may add one
pre-read poll before control prevents issuing data: conservative ceiling65+3R,
where Rm+Rb<=R. Minimum metadata data17 = creator5 + two target guards6+6.

Full nonterminal verify fixed19 = creator15 + two target polls2 + checked stat2,
plus its data calls R: attempts<=19+R, new acquisitions5, peaknew3, all retired.
Minimum data7 = creator5 + target stat data/EOF2. If the first TARGET poll is valid
terminal after the complete creator guard, fixed16 + RmCreator, data minimum5,
total minimum21 calls, new acquisitions4, peaknew3, no target stat FD/sample.
There is no two-call/no-allocation/no-FD public terminal shortcut.

| Path | Non-data fixed / conservative calls | Minimum data | New acquisitions / peaknew | Borrowed / success retained / temporary retired | Peak reachable FDs |
|---|---|---|---|---|---|
| CreateEpoch | 20 / <=20+R | 5 | 6 / 4 | 0 / 2 / 4 | 4 |
| Acquire | 76 / <=76+R | 23 | 21 / 8 | 2 / 6 / 15 | 10 |
| Complete read | 64 / success64+Rm+3Rb; refusal<=65+3R | metadata17, plus actual body attempts including EOF | 15 / 3 | 8 / 0 / 15 | 11 |
| Full nonterminal verify | 19 / <=19+R | 7 | 5 / 3 | 8 / 0 / 5 | 11 |
| First target poll terminal verify | 16 / 16+RmCreator | creator5 | 4 / 3 | 8 / 0 / 4 | 11 |

All are static algorithm inventories, not executed kernel/resource measurements.
Early errors may reach smaller prefixes. All acquired FDs are flagged once, no
hidden retries/dup/global reopen. Borrowed authority is not newly acquired; RAII
close attempts and allocator/clock internals remain excluded as stated above.

## Full status, errno and precedence table

Each poll uses one actual original creator or target pidfd, requested POLLIN,
timeout zero; it never takes a report/raw-injected descriptor. Accept count0 with
revents0 as nonterminal. Accept count1 with IN and optional HUP as terminal.
ERR/NVAL wins even with IN. HUP without IN, unknown flags, count>1, count0 with
events or count1 without a recognized event is Inconclusive **error**, with raw
poll evidence. Never turn that into a false nonterminal success.

| Encountered condition, in algorithm order | verify result |
|---|---|
| Entry cancellation/deadline | Err ConfigureProcess/Cancelled or Deadline, no OS attempts |
| Zero numeric limits or unrepresentable syscall-count ceiling | Err ConfigureProcess/InvalidInput, no OS attempts |
| B+1/M+1/combined parser-capacity formula overflows or exceeds isize::MAX | Err ConfigureProcess/LimitExceeded(BufferCapacity), no OS attempts |
| Counted getpid differs from epoch/owner creator | Err ConfigureProcess/WrongContext, memberNone; charged getpid, no creator poll/target work |
| Original CREATOR poll syscall fails, including EINTR | Err PollPidfd/mapped reason, CreatorPidfd, original errno; no target work |
| Original CREATOR poll ERR/NVAL/unknown/inconsistent flags/count | Err PollPidfd/Inconclusive, CreatorPidfd/raw poll, no fake errno; no target work |
| Original CREATOR valid IN | Err ConfigureProcess/WrongContext, CreatorPidfd/raw poll; NEVER target Exited |
| Current creator self/Own structural mismatch | Err AuthenticateProcView/WrongContext, actual SelfLink/ObserverStatus; no target work |
| Current creator namespace wrong kind or same-kind unequal epoch key | Err CheckProcessNamespace/WrongContext, ObserverPidNamespace and reached kind evidence; no target work |
| Any current creator transport/parse/byte/read/allocation/control refusal | Actual typed stage/reason/cost; first encountered error, no target work |
| TARGET pre-poll syscall fails, including EINTR | Err PollPidfd/mapped reason, original errno |
| TARGET pre-poll ERR/NVAL/unknown or inconsistent flags/count | Err PollPidfd/Inconclusive, exact poll payload, no fake errno |
| TARGET pre-poll valid IN, after creator guard | Exited, sampled_birth/state=None; no target stat attempted, creator costs remain |
| TARGET pre-poll nonterminal then stat open/read fails, even ENOENT/ESRCH | Typed Err at member stage; no secondary poll; not terminal proof |
| Stat malformed/invalid UTF-8/field overflow | Err ParseProcStat/Malformed; no secondary poll |
| Byte/work/capacity/allocation refuses | Typed Err at actual stage; preserve all spent charges |
| TARGET post-poll syscall/flag/count failure | Typed Err; sampled stat cannot erase failure |
| TARGET post-poll valid IN | Exited, retain sampled birth/state, including same-birth zombie or contradictory ticks |
| Both polls nonterminal and sampled ticks differ | Changed: contradiction in the retained birth source, not PID-reuse proof |
| Both polls nonterminal, same ticks, state in R/S/D/T/t/I | AliveSameBirth: sampled original-owner birth/liveness only |
| Both polls nonterminal, same ticks, state Z/X/x or another alphabetic state | Inconclusive: valid insufficient leader observation |

First encountered non-retryable syscall/parse failure stops the operation. A valid original
terminal poll dominates later unperformed work, not an already encountered error.
If a successful syscall's post-check reports cancellation/deadline, that stop
precedes semantic interpretation of its returned bytes/flags; its actual bytes,
FDs and completions remain charged. On EINTR data read, preserve the errno if
post-check stops; otherwise retry under the same data budget. No poll retry.

Acquire/view_guard translate Exited -> VerifyBirth/Disappeared;
Changed -> VerifyBirth/ChangedSource; Inconclusive -> VerifyBirth/Inconclusive.
They return no owner/snapshot. A changed same-kind namespace key ->
CheckProcessNamespace/ChangedSource; wrong kernel-confirmed kind -> WrongContext,
separately from birth. Denied namespace read is Denied at that
stage, not manufactured Foreign. Structural own/self/NSpid mismatch ->
AuthenticateProcView/WrongContext. New acquire pidfd EPERM/ENOSYS -> OpenPidfd/
Denied or Unavailable with raw errno and no fallback. Earlier pre-target failure
may legitimately prevent reaching pidfd_open, especially after death/reap.

Leader Z with live siblings is deliberately insufficient when pidfd remains
nonterminal; it is not whole-group Exited. Required real leader/nonleader-exec
fixtures must independently establish which row was reached. Exec, failed exec
and A-to-B-to-A at unchanged birth may still yield AliveSameBirth: never SameImage.

## Byte, capacity, work and time bounds

Validate nonzero ParseLimits fields, max_metadata_bytes M and max_read_calls R;
checked B=parse.max_bytes plus1 and M+1 must fit isize::MAX/usize; require
R <= (u64::MAX-76)/3 = 6148914691236517179 so every declared conservative
syscall/count expression fits u64. Checked-convert M/B to charge widths; checked
preflight M+1/B+1 and full worst parser/combined capacity in usize/isize/u64 before
opening any root/member. Reject rather than clamp or overflow. No unlimited Default. read/verify store no mutable shared
budget; counters reset only for a new explicitly invoked operation.

M is one aggregate ceiling over every returned metadata/readlink byte in that
invocation; B is the one complete body ceiling. EOF and one-byte oversize probes
are charged. When remaining bytes are zero, request one byte, never a zero-length
read. A single oversize witness may consume M+1 or B+1 bytes before refusal; no
later data fetch occurs. Actual charged bytes include that witness. Returned
success metadata<=M/body<=B; this exact one-byte refusal overrun is documented.
R counts *all* read/readlink attempts including EINTR, EOF, sentinel and repeated
checks; no per-file reset. Self/namespace-link reads share M/R and issue exactly min(64,remaining_M+1)
initialized stack bytes, with oversize-before-grammar precedence above.

Transport allocates at most one reusable metadata Vec requested capacity M+1 and
one body Vec requested capacity B+1; the latter exists only for read calls. Strict
epoch creation and current-creator guards share the same operation-wide metadata
Vec/budget with later target metadata; neither gets a fresh M or R. Use
try_reserve_exact; reject an actual granted capacity exceeding its requested
ceiling before initialization/processing. Initialize in <=4096-byte chunks with
control checkpoints. Metadata String parsing borrows UTF-8 bytes; no unbounded
String clone, split collect or overflow read_to_end. Transport vectors are dropped
before publication; retained_transport_capacity_bytes=0. Namespace/PID path
buffers are fixed: 64-byte link and 11-byte positive-PID decimal scratch.

Parser allocations keep LX05's exact formulas. For actual body N and entry count E:
maps capacity request N+E*sizeof(MapRecord); mounts 2N+E*(sizeof(MountRecord)+
sizeof((u64,usize))). Requested transport heap plus parser request is bounded by
**M+B+2+parser_request(N,E)**. Derive checked worst case at the admitted B/E before
the body allocation; parser overflow has its existing BufferCapacity error.
Account actual overgrant before refusing; allocator bookkeeping, allocation
addresses, Arc headers and RSS are not this logical capacity measure. At most
two new provenance Arc markers are made per successful acquire; a successful
strict epoch makes one authority Arc and one FD-free marker Arc. No growing history.
Ordinary Arc/allocator abort limitations remain explicit, not a hard memory quota.

Metadata scan work is linear in charged bytes, with fixed-field scans and no
sorting. Body/parser work is the existing LX05 bounded scan/sort behavior. Fixed
effect counts and declared linear syscall bounds are independent of elapsed time.
Control is cooperative before/after effects, initialization and publication;
parser invocation receives pre/post checks but its existing pure API has no inner
control parameter. Do not claim cancellation can interrupt blocked read/open/poll
or interrupt an already-running pure parser. No workers, credentials, limits,
namespaces, handlers, mounts, signals or process spawns are changed by the library.

## Adopted choices and remaining execution bindings

Root selected the preserved r1 API/algorithm plus ALL independent-review amendments
F01/F02/F03: strict fallible epoch/receipts, creator pidfd+active-PID namespace and
FD-free markers, pre-target current-Own guards, revised count/limit tables,
bounded raw readlink request and byte precedence, and the actual native EOF
cfg(test) barrier with separately owned parent truth and combined bad control.
The immutable amendment record under [reviewed input custody](#reviewed-input-custody) retains their input hashes and explicit source/adaptation
limits. These are adopted design directions, not observed implementation results.

The actual post-BP02 base, process/event/test-libc dependency proof (C7), TT02
fixture maintenance, TT03/TT04 implemented session/worker/helper/realm artifacts,
closed actual-EOF orchestration and capable no-control tracer binding remain
UNBOUND. Focused independent r2 review found no additional blocking contract choice; root adopted those exact design semantics. Actual execution bindings must precede
product dispatch. No required missing cell is optionalized. Verification includes
all 34 selected originals and 12 separately deferred references unchanged.

## Decision record: retained selections and explicit additions

| Root-adopted or preserved exact choice | Why / alternative and cost if wrong |
|---|---|
| r1 public value/result/error types, recognized state set and control-first entry | Keeps bounded observable successes and first-error truth. Wider future states need evidence; creator-first entry would add an OS call on pre-cancel. |
| Strict fallible epoch, original creator pidfd plus authenticated active-PID namespace | Numeric PID alone collides across namespaces/reuse. Namespace-only misses dead-creator reuse; pidfd-only misses live PID1 parent/nested-child collision. Cost two shared retained FDs and strict new()/guard work. |
| Separate FD-free epoch marker | Descriptive results cannot keep authority or reconstruct it. Storing authority Arc in ProcView is a resource-lifetime leak; a numeric registry needs generation/lifetime machinery and would replace the selected Arc contract. |
| Fresh-root Own check at acquire, retained-root dynamic Own check at read/verify | Prevents inherited view/creator substitution before target access while preserving retained-root replacement semantics. A global reopen breaks authority continuity; numeric-only checks miss the reviewed collision. |
| Namespace double link/lstat, nsfs key and direct-return kind ioctl | Existing r1 composition retained. One source/link check reduces work but weakens detection; no choice proves unobserved ABA. |
| Acquire21 new/peak8 + epoch2; read15/peak3 + borrowed8; verify5/peak3 | Preserves existing donor brackets plus full creator proof. Weaker guards cost less but reintroduce F01; concurrent calls have independent peaks, no global quota. |
| Shared M/R, min(64,remaining_M+1) raw link requests, oversize before grammar | Exact one-byte refusal witness and original tail/EINTR/EOF preservation. Always64 can exceed M+1; allocating growth is unbounded work. |
| Private actual-native EOF cfg(test) hook and combined omit-postread/final-target-guard control | Preserves original actual read/death trigger with owned truth. Between-operation phases miss it; timing stress cannot bind the boundary. Test object is a separate tier from external production. |
| Explicit separate fixture-package-root and two external production clients | No unpublished sibling/runner-copy assumption. More supplied artifacts are a delivery cost; duplicating fixtures forks protocol/oracle ownership. |

Root additionally selected completion choice N01: an impossible nonpositive
native creator getpid conversion is ConfigureProcess/Malformed, errno/source
absent, charged getpid and no further creator/target work; Pid::new remains Option.
This is an impossible-native-value guard/test seam, not an observed Linux getpid
result or qualification. It adds no public error variant. Alternative InvalidInput blames a native result on caller input; cost if
wrong is one new unreachable-in-ordinary-kernel error row and its model assertion.
The closed EOF orchestration schema/actual artifact IDs are intentionally UNBOUND;
verification states necessary ordering, capacities and ownership, not fabricated
implemented protocol bytes. No new public API/provider trait is added.

All actual ABI/dependency build-policy, fixture/artifact/kernel/audit identities
remain UNBOUND even where design directions are adopted. The independent r2 review covered the amended counts/oracles at design level; actual execution binding and changed-product verification remain separate. No repeated user permission is needed.


## Reviewed input custody

The following are exact private custody references relative to the repository
root. They identify frozen controller evidence; they are not files promised in a
published package. This normative contract and its verification plan carry the
design; private evidence remains preserved without rewriting its historical
pending-review labels. No donor byte was read or requalified during promotion.

| Record | Private path | SHA256 |
|---|---|---|
| Exact reviewed r2 index | `.scopebase/controller/resume-20261022/lx08-crossreview-r1/contract-draft-r2/artifact-index.json` | `b2947891d9750c4b522cec8302875467b3a657eb137528161f1ad62a02f0e839` |
| Contract input | Same r2 directory, `contract.md` | `34b83738f42d7eb232cffb8dd01eac636baf52c12e63d54f504507e9aa7a56e5` |
| Verification input | Same r2 directory, `verification.md` | `5487d210e3fadec4407d1c10c74dc0acaff083895b9721535c482e07a208d655` |
| Original preservation map | Same r2 directory, `original-test-map.json` | `6acefd1e1887f9798886b9d857e247dd85d80669bd4326bc26a64f631509bbc0` |
| Immutable amendment record | Same r2 directory, `amendments.md` | `bccc5c573565d8175cb2cc57cc3fbe18444fff4b5b7c16ad74d42e4017cd1f6e` |
| Bound inputs and UNBOUND execution records | Same r2 directory, `bindings.json` | `948807b95d4e0f9c8ff22da77474942c94d18a8dfe925f13c4fc91cd68fd58c1` |
| Independent r2 review index | `.scopebase/controller/resume-20261022/lx08-contract-r2-review-r1/artifact-index.json` | `4e9a798441cadf23b0c889bc1ec7a5d11ecb7be42879411dd9579ed402fa2f23` |
| Independent r2 review | Same review directory, `review.md` | `7664ed7c57ce7fc1e0cfa817b84b60cb7285d811a8eef603a9a37e6e468efb0b` |
| Root design ratification | `.scopebase/controller/resume-20261022/lx08-root-design-ratification-r1.json` | `6554094b675f620acd12527229e8ff57954df09ba66a2fcb2d1719d70e18e051` |

The independent disposition is READY_FOR_ROOT_RATIFICATION, DESIGN_ONLY, with no
additional blocking finding. Root adopts the exact r2 semantics, including F01,
F02, F03 and N01. This administrative promotion changes status/navigation/custody
wording; the public API, authority, errors, bounds, algorithms and required
oracles remain the reviewed design. The complete original-test data is embedded
in the [verification appendix](../plans/2026-10-22-scopebase-lx08-verification.md#frozen-original-test-preservation-map).
All 34 selected source objects and their original destination names remain;
all 12 deferred objects retain their owners and non-closure by LX08. These are
source-object counts, not runnable or passing-test counts.

### TT03 observed-primary and final-protocol boundary

LX08 r2 observed only three individually frozen TT03 proposal documents under
its own `inputs/tt03-primary-r2/`, in their original source-tree context:

| Frozen primary document | SHA256 observed by LX08 r2 |
|---|---|
| `packet.md` | `0daf15f0794e2bd6c52d0e66391d5d84cb4a2755e636fae773766f7cd2f422bf` |
| `protocol.md` | `e70e2e1ae655665074bc636e1958d76f75ddd508fe46bb77df9e3378a3253712` |
| `contract-data.json` | `fdc3bd9df3f9e31289887c30d5c6e7d4f20a84ec6b7c5f8c949d63800350b0dd` |

The controller subsequently identifies TT03 final r2 at private
`.scopebase/controller/resume-20261022/next-tt03-packet/r2/artifact-index.json`,
SHA256 `1105d700199c7ec4a512f2d122495728eaa042ef0006ca3a8e0752534b5bf194`,
with final `protocol.md` SHA256
`475f603d98cc8595153d10df4e61eef8a9a0a8805e7626b3378a271c7dc9cbe6`.
The protocol changed after LX08's observed-primary snapshot. Neither LX08 r2 nor
its independent review is represented as having observed or qualified those
final bytes. Root must separately bind both final indexes and resolve per-case
adapter/protocol compatibility before execution, without a hash cycle. That
joint compatibility record and all actual TT03/TT04 resources remain UNBOUND.
