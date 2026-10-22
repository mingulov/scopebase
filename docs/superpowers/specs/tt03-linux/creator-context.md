# TT03 retained-root creator/context contract

**Ratified private implementation design; implementation/native/C7
checks NOT_RUN.** Root adopted the expert translation in
`.scopebase/controller/resume-20261022/tt03-context-custody-review-r1/creator-context-translation.md`.
Its final source hash965eb9a5f3cacc983f53251568a5ea492917bf99854ef8eaefd7f9aa8199f466
and root ruling2072302ddaaf1cf3575076b4174d81866fd96f0fc406ec4d0c79cc1a7cb56b36
are bound by inputs.json. The algorithm below is the selected
private TT03 specialization of the ratified LX08 semantics, not a dependency on
future production LX08 code/API or a new public generic process abstraction.
[schemas.md](schemas.md) closes its guard evidence, counters and custody; actual
provider/worker/source/archive/resource bindings remain UNBOUND.

## Retained owners and lifetime

Private `CreatorContext` retains exactly three distinct original owners:
authenticated proc-root FD, original creator pidfd, authenticated active-PID
namespace FD. It also retains the checked positive creator TGID and namespace
device/inode key as descriptive values tied to those owners. None is imported
from a report, raw FD integer or caller namespace label. Supplied `Files.root`
continues to mean the fixture workspace; the supplied root/image A/image B are
three separate admission assets. Thus successful construction retains six
original FD owners before any invocation creates further owners.

The three context owners survive normal TT02 case and run retirement. Run
retirement may close shared supplied assets after their dependants settle; it
cannot consume the context needed by the later first-valid outer finalizer.
The outer campaign authenticates first, settles original fixture/admission
inventory, then closes the context owners last. A sealed report needs no native
authority. No work is admitted after the campaign is latched. Unresolved owners,
including context/guard temporaries, remain in the same session or its original
failed-shutdown anchor. Reports retain no FD and cannot reconstruct one.

## Constructor algorithm and exact inventories

Before native work, validate the complete manifest equals the accepted contract
schedule, reserve all terminal/custody/ledger storage, check capacities and fixed
deadlines, and bind the existing session parent pool. The schedule is nonempty:
accepted `RunContract::load` rejects an empty plan and `CaseRule` rejects zero
attempts. Therefore N >= 1. Zero entered Prepare is a distinct supported path.

Use LX08 constructor order, retaining its root instead of closing it:

1. Count `getpid`; require positive i32. Open `/proc` using
   RDONLY|DIRECTORY|CLOEXEC|NOFOLLOW, check GETFD once, require procfs by fstatfs.
2. Read exact current `self` through that root. Open the canonical numeric
   current-PID directory and `status` through checked ordinary relative
   `openat2`. Read status to actual EOF; require exactly one Pid/Tgid/NSpid,
   Pid=Tgid=current getpid and singleton NSpid=[current getpid]. Close status.
3. Obtain and authenticate `namespace_sample(current_dir,"pid")` below. Close
   the namespace directory and current numeric directory; retain the namespace
   handle and original proc root. Use active `pid`, never `pid_for_children`.
4. Open the original creator pidfd with flags0, check GETFD once, and perform the
   exact nonterminal zero-timeout poll below. Retain that original pidfd.
5. Finish control/accounting validation and return the context with exactly its
   three owners; no duplicate, fallback root, namespace entry, child or thread.

Successful auxiliary acquisition count=6, peak auxiliary owners=4, retained=3,
explicit temporary closes=3 (status, namespace directory, numeric directory).
The retained root is the difference from LX08's two-FD epoch constructor.

Let R be the actual aggregate data attempts for self/status/namespace links,
including EOF and bounded EINTR attempts. LX08's fixed non-data count20 remains
20; TT03 additionally counts its three explicit closes. Constructor context work
is **23+R native attempts**, minimum **28** with R=5. This excludes neither the
three explicit closes nor extra actual input-file validation work. Admission
file/manifest work is additional admission_parent consumption, never assigned
to an unentered invocation/effect. All such work consumes the existing reserved
session parent pool without refund or a reset of per-invocation ceilings.

## Namespace primitive

Ordinary proc descendants use RDONLY|CLOEXEC plus DIRECTORY where needed, with
openat2 BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV. Each successful new FD is owned
and registered immediately, then checked with GETFD exactly once. Missing
CLOEXEC is a refusal with actual returned flags, never a silent fixup.

For the namespace sample, open the ordinary `ns` directory that way. Obtain
before readlinkat and no-follow fstatat samples of its fixed `pid` entry; follow
only that deliberate namespace magic link with openat(RDONLY|CLOEXEC). Check its
GETFD, nsfs fstatfs, fstat device/inode, and one NS_GET_NSTYPE=CLONE_NEWPID result.
Obtain after readlinkat/no-follow fstatat samples. Require stable typed
`pid:[decimal]` links, stable symlink identity and link inode agreeing with the
actual handle. Preserve the LX08 statement that no unobserved A-to-B-to-A proof
is promised. A retained namespace FD prevents namespace-key recycling.

The private namespace-kind adapter uses admitted rustix 1.1.5 generic Ioctl:
Output=i32, IS_MUTATING=false, opcode::none(0xb7,0x03), null operand, successful
IoctlOutput returned directly without pointer dereference. NoArg discards the
required output and Getter<i32> expects the wrong ABI. Only a module-owned newly
acquired namespace BorrowedFd can reach this private unsafe boundary. No retry,
fallback, new dependency framework or public raw-FD constructor is introduced.
Keep the ratified Linux x86_64 GNU ABI scope. Actual compilation remains C7 work.

The primitive has nine fixed non-data attempts plus two readlink data attempts;
its one explicit namespace-directory close is counted by TT03 separately. Its
two temporary FD owners are immediately inventoried. It never rechecks or dup's
the retained context namespace FD merely to compare its established key.

## Guard before control and exact inventories

Guard every native fixture control entry: Prepare before creation/launch, a
shared endpoint advance before worker/parent action, native Collect work, actual
case/run retirement before control, and first-valid outer finalization before
original-owner cleanup. One guard covers one sequential entered operation under
its same aggregate budget; internal calls cannot refresh that budget. Cached
contract/cancellation-token/getter/raw-ledger/report exports perform no guard
I/O and convey no new authority. Pure hook-entry/discovery bookkeeping may
record the actual call before a refused guard; no callback is fabricated.

1. Count current getpid and compare the checked original creator TGID.
2. Poll the original creator pidfd with the exact rules below.
3. Through only the retained authenticated proc root, read dynamic self; open
   fresh current numeric Own directory/status; fully validate complete Own
   status as at construction; close its status FD.
4. Take a fresh active-PID namespace sample and require confirmed kind and same
   established retained namespace key. Close all four fresh temporary owners
   (status, namespace directory, namespace handle, numeric directory) before
   performing any fixture control action. No global proc reopen, cached numeric
   directory, fresh replacement pidfd or `pid_for_children` substitution.

Guard fresh acquisitions=4, peak fresh=3, retained fresh=0, explicit closes=4.
Its fixed non-data count15 plus four explicit closes gives **19+R native
attempts**, minimum **24** with R=5. The guard borrows context 3; its own peak is
6 auxiliary FDs including those originals, plus supplied assets and any actual
invocation inventory. The session-wide open-owner64 ceiling applies throughout.
These are successful-path static inventories, not native measurements; refused
prefixes retain their actually consumed counters and owners.

## Control, budgets and partial failure

Normal entry uses its cancellation/deadline and aggregate native/read/byte/
encoded/report allowances. Retire uses its actual request deadline/allowance;
outer cleanup uses its one fixed admitted deadline/allowance. Neither cleanup
guard is vetoed by the already-set execution cancellation flag or expired normal
execution deadline: otherwise the required zero-Prepare cancellation cleanup
would always fail before closing an asset. This changes no normal-operation
stop or cumulative count. Work and returned effects are charged before
post-checks. A failed syscall keeps its actual error ahead of a later stop;
after success, the post-check stops before interpreting bytes/flags.
Constructor work uses admission_parent; it cannot invent an InvocationKey.
Explicit clock wrappers are charged as actual TT03 rules require; allocator/
Instant internals retain their separately declared exclusions. No syscall is
claimed interruptible by a deadline.

Reuse the existing bounded source/transport workspace for the complete status
read; do not add an uncounted Vec or JSON DOM. Let G be the admitted existing
raw_file_bytes (whose ceiling already includes an overflow probe), require G>=2
before native work, and set M=G-1 with checked arithmetic. Let R's ceiling be the
existing read_calls_per_source. Apply that single aggregate M/data-attempt bound
across self/status/namespace reads in one guard; the most it consumes before
oversize refusal is M+1=G bytes. The session source workspace is at most G bytes.
Readlink uses initialized stack length min(64,remaining_M+1); status reads also
request no more than remaining_M+1. Charge returned bytes and check oversize
before grammar/full-buffer refusal. The reached bound maps to the existing
raw_file_bytes/read_calls_per_source/native limit, without new public limit
types. Lowered insufficient limits may refuse. The population-specific report reserve
must include all guard errors, acquired owners and their subsequent close events.

Immediately after every successful FD acquisition, enter its actual owner into
reserved private inventory before GETFD or another fallible action. Explicit
close consumes it once on every Linux result, including EINTR. Preserve close
errno and sticky EBADF/inventory uncertainty; never retry its bare integer or
allow a later Drop to close a reused number. If budget/error prevents a close,
retain that actual temporary owner in inventory. A temporary close failure is
recorded as reached guard-work error; it is not rewritten as a semantic namespace
contradiction. The guard is not complete until its temporary owners have been
retired. Outer guard failure/incomplete guard seals Unresolved with no original
fixture/admission/context cleanup; guard operations and temporary closes remain
explicit context_read_only attempts.

At any constructor failure, return exact supplied Files3+paths+contract and move
all still-pending auxiliary owners with the reached constructor ledger into the
root-selected opaque move-only admission custody. Previously consumed auxiliary
owners remain descriptive errors/ledger entries, never reimported owners. This
custody's one-shot bounded campaign is FD-close-only and requires no complete
control guard; it cannot signal, wait, mutate paths/namespaces, reopen or adopt.
The pre-reserved 1MiB outer slot belongs exclusively to success OR failure.
The driver's supplied 3 asset guard and the auxiliary-custody campaign have
separate original owners/reports; neither fabricates fixture retirement.

## First error and poll projection

Use the enclosing TT03 lifecycle stage plus a closed private guard-stage/member
projection distinguishing CreatorPid, ProcRoot, SelfLink, ObserverDirectory,
ObserverStatus, ActivePidNamespace, CreatorPidfd and TemporaryClose. Keep exact
native operation and reached errno; no later mismatch overwrites earlier
open/read/parse/kind/flag/control/limit error. Wrong current PID, valid terminal
creator, foreign Own view, wrong namespace kind or changed current namespace
refuse before control; creator terminal is never target Exited.

The single authoritative [guard-error-map.json](guard-error-map.json) closes all
private reason names and enclosing Failure categories. Its exact readable table
appears below; there is no separate competing vocabulary or category rule here.
Native errno, actual stop precedence, successful poll outputs and original custody
remain as already specified. No public FixtureErrorCategory is introduced.

Poll uses original creator pidfd, requested POLLIN and timeout0. Exactly
count0/revents0 is nonterminal. Count1 with IN and optional HUP is terminal and
refuses WrongContext. ERR/NVAL wins even alongside IN. HUP-only, unknown flags,
count>1 or count/event inconsistency is an inconclusive guard error with no
invented errno. An actual poll syscall error preserves errno; no output evidence
is invented from an initialized input field.

The parent Failure/outer diagnostic must contain a closed nullable GuardEvidence
projection, null on nonguard failures. It includes exact guard-stage/member,
poll ready_descriptors as canonical u64 and raw signed revents as i32 when the
poll succeeded (including malformed/terminal success); both null on a failed or
unperformed poll. Include expected/observed namespace kind and actual descriptor
flags only when those queries reached them. Enclosing operation, first error and
actual native event identify the relevant attempt. No raw FD ownership or proc
contents are exported. This parent-only projection adds no worker exchange or
raw record; amend its closed schema and terminal reservation explicitly.

At minimum the private native-operation ledger must distinguish openat2 from
the intentional openat and include pidfd_open; the observed r3 NativeOperation
set lacked those names. Numeric result alone cannot preserve poll revents.

## Required focused controls

Future implementation must exercise constructor failure after each auxiliary
acquisition and before/after GETFD; exact original auxiliary transfer; close
error/EINTR consumption; outer budget stopping with a guard temporary pending;
getpid mismatch; terminal original creator with same numeric PID/namespace model;
valid count/revents and every invalid flag/count class; changed/wrong-kind/foreign
Own namespace; no control ledger entry after first guard refusal; real nested
PID1 collision refusal and fresh matched-Own twin in owned later realms; guard 3
survival through actual run retirement; and source/archive borrowed-reference
finalize rejection. These controls remain NOT_RUN. They are bounded translations
of existing contracts, not a new runtime or a substitute for native qualification.

## Exact enclosing projections and error mapping

GuardEvidence's exhaustive fields/types are in schema-contract.json. Enclosing
Failure has nullable guard_evidence, null on nonguard failure. GuardEvidence
contains closed guard_stage/member/reason/native_operation and actual attempt
index, nullable actual successful poll count/raw signed flags, reached expected/
observed namespace kind, GETFD flags, checked expected/observed creator PID and
namespace keys. A failed/unperformed poll has both poll fields null. Successful
nonterminal evidence is count0/revents0; actual syscall failure retains errno.

[guard-error-map.json](guard-error-map.json) is the sole mapping authority for
this r4 successor. The following table is its checked projection. It resolves
TT03-R3-FINAL-01 using root's selected adopted-advisory categories: semantic
context contradictions and inconclusive poll use Other; malformed/CLOEXEC uses
InvalidProtocol. Actual non-close errno mappings, genuine stops, non-time limits
and consumed temporary-close errors keep their original precedence and evidence.

| Population | Failure.category | Failure.reason | errno | GuardEvidence.reason |
|---|---|---|---|---|
| semantic_wrong_context | Other | WrongContext | null | WrongContext |
| inconclusive_poll | Other | Other | null | Inconclusive |
| malformed | InvalidProtocol | Protocol | null | Malformed |
| native_denied | Denied | Denied | actual | Denied |
| native_unavailable | Unavailable | Unavailable | actual | Unavailable |
| native_io | Io | Io | actual | Io |
| non_time_limit | Unavailable | Limit | null | Limit |
| cancelled | Cancelled | Cancelled | null | Cancelled |
| timed_out | TimedOut | TimedOut | null | TimedOut |
| temporary_close_error | Io | CloseError | actual | CloseError |

Private GuardReason names are exactly WrongContext, Inconclusive, Malformed,
Unavailable, Denied, Io, Cancelled, TimedOut, Limit and CloseError, as already
closed by schema-contract.json. Native failures use Denied/Unavailable/Io rather
than an unrecognized umbrella reason. EACCES/EPERM are Denied; ENOSYS/EOPNOTSUPP/
EMFILE/ENFILE/ENOMEM are Unavailable. ENOTTY is Unavailable specifically for the
namespace-kind ioctl; otherwise actual transport errno follows native_io. Actual
missing proc members preserve their errno/member and do not prove WrongContext.
Every native row has its actual errno; every semantic/malformed/inconclusive/stop/
limit row has errno null. A temporary close error keeps actual errno, Io/CloseError
and consumed owner state. Non-time limits retain exact LimitKind/charges.

The poll population follows the unchanged count/flag rules above. No native
output is invented for failed/unperformed poll. A malformed status, invalid
native value or missing CLOEXEC is InvalidProtocol/Protocol/Malformed without
invented errno. This projection does not turn ordinary endpoint error into a
Refused case or synthesize Collect/retire entry, cleanup or target Exited.

Parent-only guard_events in Snapshot and context_read_only events in constructor/
outer reports preserve reached native attempts and GuardEvidence on success or
failure without another raw record/message/exchange. Each is precharged inside
its actual L/constructor/outer envelope allowance before the syscall. Events
have increasing order; the parent merges order with chronological raw when
checking barriers. The actual successful guard is complete only after all fresh
temporaries consumed without error and current guard/budget postchecks pass.
No original fixture/admission/context cleanup starts on a failed/incomplete
outer guard. Context3 survives actual TT02 run retirement and closes last.
