# TT03 exported bytes, counters and original-owner finalization

**Ratified normative design; product/native controls NOT_RUN.**
[schema-contract.json](schema-contract.json) is the exhaustive field/type/array/
scalar contract. Every object is closed; every field is required, and only a `?`
suffix permits null. Its named types, this relation table and protocol.md together
are required. This file does not add a worker message, action or raw-record kind.

R4 narrows only the guard-error relation required by TT03-R3-FINAL-01.
[guard-error-map.json](guard-error-map.json) is the single authoritative mapping;
[creator-context.md](creator-context.md) has its checked readable table. Closed
wire/object fields, private reason enum values, bounds and owner rules are
unchanged from frozen r3. Schema metadata binds the exact mapping digest.

## Scalar and identity rules

`U64`, `PositiveU64` and `I64` are bounded canonical decimal strings, never JSON
numbers or padded/plus-signed strings. `U32`, `PositiveU32`, `I32` and
`PositiveI32` are bounded JSON integers; booleans are not integers. Label/CaseId
uses actual accepted ASCII validation, RunId is exact 32 lowercase hex, Digest
exact 64 lowercase hex, hex fields are lowercase and even length. All lengths
are encoded UTF-8 bytes or decoded byte counts as named, never character counts.

InvocationKey is the accepted complete run/case/version/cell/attempt/operation
object. Canonical encoded key <=16384, inside the existing metadata allowance,
is an additional explicit fixture transport admission condition. Accepted cell
validation, Unicode/control content and exact canonical JSON escapes are in
protocol.md. The binder must apply actual RunLimits.name_bytes as well as this
closed schema. Complete key equals manifest, every boot/resume Hello, appended
exec key and producer raw identity. Snapshot's key supplies each registration's
immutable invocation origin; outer report's invocation list maps each operation
ID to its complete admitted key. No operation-ID inference substitutes for that
mapping. Native numbers/paths in reports are descriptive and never owner imports.

## Snapshot, raw publication and failure truth

`Snapshot` exhaustively includes revision/kind, complete invocation, seal, actual
hook entries, exact completed-step prefix, failures, chronological raw, incomplete
transport, registrations/subowners/unknown inventory, independent parent and
claimed worker charges, admitted limits, retained capacities, cached timing and
work-stopped state. An unentered invocation still has this descriptive key and
zero hook entries; it does not acquire a fabricated fixture effect.

| Seal kind | Fixed slot / admission |
|---|---|
| early_export | 0; only if no snapshot has ever been published for this invocation |
| first_failure | 1; first native failure, exactly once |
| collect | 1; only actual entered Collect, and only if first_failure has not already sealed it |
| case_retire | 2; only actual entered case-retirement hook |
| run_retire | 3; only actual entered run-retirement hook |

`publish_ordinal` is actual monotone publication order 1..4; it is not the slot
number. `native_event_index` is the actual cached event counter at that seal.
Hook counts are actual Prepare/Collect/case-retire/run-retire entry totals at
that point. Per invocation each is 0 or 1 for this fixed runner route; outer
aggregate counts are sums of actual entries across the admitted roster. A first
failure sealed before Collect remains unchanged; later counts appear only in
later actual seals. No Collect or retirement callback is invented after runner
omission/budget exhaustion. Absence is an observed zero count, without a guessed
native reason. Last-clock sample is cached; raw_ledger never samples the clock
or performs native I/O to make an early export look more recent. After first
valid finalization it can only return existing published bytes or None; it cannot
create an early seal under a closed allowance. Driver freezes its raw exports
before finalizing and only then compares existing bytes again.

Publication uses separately pre-reserved per-slot buffers and OnceLock, as in
[the primary contract](../2026-10-22-scopebase-tt03-linux-fixture.md). The returned slice comes from a stable immutable published slot after
the internal lock is released. An already returned slice is never overwritten.
Each valid shared endpoint failure can publish slot1 without modifying slot0;
mutable hooks and finalization require all outstanding borrows to end. Returning
a slice borrowed from a temporary MutexGuard or refreshing a published Vec is
forbidden. All reserves exist before effectful work; publication cannot allocate
an unbudgeted replacement snapshot.

`ChronologicalRaw.order` increases for every complete record as independently
accepted by the parent. Within each producer, raw record_index remains contiguous
across exec, sequence reflects the real channel request, and key matches the
snapshot. Records retain their original canonical object bytes inline, with no
new quote/hex layer. `values` is exactly the RawValues variant selected by
record_kind; no other variant's keys are accepted. Proc bytes appear only in
bytes_hex; other kinds use their explicit fields and bytes_hex=null. Parent
records have producer_charges=null; worker records have ProducerCharges. Source
is parent_kernel/worker_kernel/worker_ack, preserving claim provenance. There is
no Pass, capability or clean-shutdown field in a raw record.

Failures retain the first actual native failure byte for byte. Subsidiary errors
are chronological, at most 32; a saturated list increments subsidiary_omitted
without erasing the first error or silently asserting no later errors. Failure
has actual category/reason/stage/step/actor/epoch/sequence/result/errno/limit and
consumed parent charges plus <=1024 diagnostic bytes. Native absence uses null;
it is not zero errno/success. A non-time reservation stop has category
Unavailable, errno=null, reason=Limit, exact LimitKind and consumed charges.
No FixtureErrorCategory::LimitExceeded exists. A real cancellation is Cancelled;
actual local deadline is TimedOut; framing is InvalidProtocol; native transport
preserves Io/Denied/Unavailable as reached. CloseError retains its actual errno.

An ordinary endpoint failure returns a non-Refused CaseError with Unknown cause.
The corresponding typed fixture error appears in the actual runner report only
if that fixture hook was entered. A runner-only execute.after timeout can leave
fixture_failure=None and native first failure=null. Separate driver/runner
receipts supply that actual checkpoint; no snapshot fabricates a native stop.

## Partial transport and evidence admission

At most one exchange is pending: parent service is sequential and stops on the
first failure. PartialTransport binds direction, actor/image, exact step,
sequence/index, expected total/hash where actually learned, received-byte count,
retained exact prefix, malformed datagram bytes where present, native result/
errno and stop reason. An incomplete download is never a complete RawRecord or
oracle truth. Download received_bytes equals decoded prefix_hex length. Upload
prefix records only bytes actually committed by the parent, with receiver
completion still unproved. Missing total/hash is null, never guessed from later
reports. Malformed datagram bytes are their exact received prefix, at most65600.
MSG_TRUNC/MSG_CTRUNC remain explicit protocol/native failures and sticky inventory
uncertainty; the truncated ancillary control must fail that flag assertion.

The actual encoded length of every complete inline raw object, array separator,
partial prefix's hex expansion and malformed datagram is charged inside L. Before
a native action/receive, reserve both its largest admitted evidence increment and
the terminal envelope computed below. Before each fragment, reserve exact hex
expansion of the existing prefix plus that next chunk until complete canonical
record validation; completion replaces the partial representation without an
extra raw record. A partial record that cannot fit refuses before its next
request, retaining its already obtained exact prefix. One raw source ceiling
never promises all maximum-size sources or incomplete re-encodings fit L.

No completed bytes are discarded to fit a summary; no oversized prefix is
silently truncated into success. Already frozen positive low-L populations must
still pass if their exact admitted envelope/evidence fits. A formerly assumed
but unbound low-L population that cannot fit now has an explicit before-effects
Unavailable/Limit admission refusal. Required reached partial-effect controls
use independently bound allowances large enough to reach their named actual
owner/effect prefix, then exhaust their selected later resource. Admission
refusal cannot satisfy those reached-control rows.

## Seal's own serialization and hash charges

Snapshot, OuterReport and AssetGuardReport include exact `seal_charge` with
encoded_bytes, hash_work_bytes and scope=this_seal_only. Their counter projections
are the observed boundary **before** their own encoding/hash; prior completed
seals are already included. To obtain the delivered boundary's charge, add the
current seal_charge once. Do not add it again to a later cumulative snapshot.
This keeps self-encoding and self-hash work explicit without a digest self-cycle
or a fabricated observed worker tail.

Compute exact canonical envelope length including the decimal seal_charge fields
with a bounded length fixed point (at most20 count-only iterations); no bytes are
emitted or hashed in those count-only passes. Precharge that exact encoded length
and one whole-envelope hash, then encode once into the reserved slot and hash
once. Abort/error before publication is incomplete, never a falsely sealed report.
The actual materialized length must equal the charged length; independent output
hash verifies the delivered bytes. Record traversal/count work has a finite
<=20 passes over the already bounded envelope; it is separate from byte/hash
counters and within the fixed campaign/publication time allowance. No unbounded
DOM/temporary encoding is needed. All envelopes and own charges still fit L or
the one outer/driver report slot. `as_bytes()` exposes the immutable actual outer
report; admission errors expose closed kind and bounded diagnostic bytes.

## Counter domains and continuity

Charges has exactly twelve u64-decimal fields: native_attempts, native_successes,
read_attempts, read_bytes, file_work_bytes, hash_work_bytes, encoded_bytes,
retained_capacity_bytes, datagram_send_attempts, datagram_receive_attempts,
datagrams_sent and datagrams_received. Attempt charges occur before the wrapper
syscall, including EINTR/EAGAIN, poll, EOF, error and close. Native_successes
counts actual nonnegative completions (including poll0/EOF0). Reads count all
read/readlink attempts and actual bytes, including probes. File work counts actual
write/readback bytes. Hash work counts actual bytes hashed per logical digest;
encoded_bytes counts actual materialized/copied canonical or hex bytes, including
prior completed seals; the current seal's exact additional charge is seal_charge. Retained capacity is cumulative admitted capacity; no refund is
claimed after close, freeing a transport record or retirement.

Datagram send/receive attempts include unsuccessful wrapper calls; committed
sent/received count only actual successful datagrams. One committed request is
never retransmitted after uncertain reply. Wire cap counts committed traffic;
native attempts still bound repeated EAGAIN/EINTR. A malformed reply replaces
one normal reply. Encoding/hash/byte/native/retention limits remain independent.

Snapshot.parent counters are actual parent observations for that invocation.
SessionCounters separates constructor admission parent work from cumulative
invocation-parent work; it never assigns an unentered invocation/effect to
admission. Constructor charges the existing session parent pool N*16384, preserving
N*512 cleanup reserve. Per-invocation parent maxima and all image budgets remain
limits as well; no admission or per-case pool refund occurs. Session aggregate
explicit native attempts <=N*40960 before outer cleanup; outer adds <=16384 once.
Standard Command/loader/runtime/kernel/allocator work excluded by actual C7 is
separately described and never represented as fully counted native activity.

WorkerEpochCharges has operation ID, actor, actual image_epoch, boundary, coverage,
last complete record index, known prefix, carried four-counter header values,
parent-observed wire counts and unknown reasons. Operation ID maps through the
full outer invocation list or equals the snapshot key. ProducerCharges records
per-image prefix **before encoding itself**. The existing header carries cumulative
worker datagrams/native/raw-encoded/file-work counters across real exec; they
cannot reset. Per-image counters may start at0 only with an actual authenticated
new image_epoch. Parent retains prior epoch entries and adds known lower bounds;
retire never resets them. Hash/read/self-encoding/send tails not actually observed
remain Unknown, including after exec/death; no absent report becomes zero or an
exact total. The four carried counters and parent wire observations corroborate
only their measured subsets, not every worker claim.

CounterProjection.exact=false whenever any unobserved worker tail or unknown
inventory affects its total; known_lower_bound never decreases. Exact true
requires a fully corroborated selected explicit domain, and an empty unknown
reason list. A zero-worker never-entered invocation can have exact zero, but a
dead/missing worker cannot. Outer before/after aggregate snapshots preserve the
worker projections unchanged (zero outer wire); original per-image detail stays
in the separately hashed last invocation snapshots rather than being copied into
an unbounded outer epoch roster. Outer lifetime totals add outer work separately.

## Immutable original inventory

Seven registration IDs and their meanings are unchanged. Every actual original
subowner gets one stable ID immediately on acquisition/creation, before the next
fallible action. Registration references partition actual subowners; their union
has at most128 IDs. Subowner carries role/operation/actor/create-order, descriptive
native number/name/identity, native state/result/errno, returned-registration and
sticky error/unknown flags. No report reference owns a File, Child, pidfd or name.
Subowner state is KnownPresent, Closed, Reaped, Removed,
ConsumedWithCleanupError, Unresolved or Unknown. Unknown is never inferred absent.
Created-name authority requires the actual original-parent create/open ledger.
created_order is the local custody/acquisition/creation registration order; for
supplied Files it records receipt and never asserts that the constructor created
the file. Constructor asset work follows context capture: validate supplied root/
image flags/type/identity and expected image bytes through original Files with
cursor-safe pread under the same admission pool. Any failure returns context/
temporary originals in the separate opaque custody; constructor creates no child
or case name.

A registration's invocation origin and Owner::Fixture never change. It is
returned exactly once from an actually entered hook; later discovery changes
returned_in only from null to that actual hook. Real subowners may extend the
same registration. No alias/child pidfd creates a second logical effect.
Registration Retired requires actual known settlement of all members. A consumed
close error is physically settled but still makes clean shutdown fail. Unknown
inventory remains sticky even if all known members settle. Cleanup errors and
unobserved reap are not erased by an exit0/quiet channel or ECHILD guess.

Only one invocation can hold unsettled native inventory; a next Prepare refuses
before creating anything if a previous case still has unsettled/unknown owners.
Parent open-owner bound64 is session-wide, including admission/context owners.
The outer current-original inventory is consequently <=128 subowners. Settled
prior history remains in immutable invocation snapshots and their references;
this does not recreate owners from those records. Original supplied root/image
A/imageB are exactly three admission_assets entries. Actual creator/context FDs
are separate context subowners with their real acquisition/close counts; the
three supplied asset closes are never described as three total FD closes.

## One-shot outer campaign and constructor-error route

The exact API is in [the primary contract](../2026-10-22-scopebase-tt03-linux-fixture.md). OuterAdmissionError's closed kinds cover pure
ExpiredDeadline, DurationExceedsRetirement, AllowanceOutOfRange,
InsufficientTerminalCapacity, ArithmeticOverflow and InvalidSessionState. An error
has bounded diagnostic bytes and no native attempts/cleanup; it leaves the same
session and owners. max_native_attempts may be0; max_records includes one terminal
summary and is1..16384; max_retained_bytes must fit the selected terminal envelope
and be<=1048576. First remaining time is positive and <=contract retirement
milliseconds converted with checked arithmetic. No live context query happens
while those pure admission checks remain unaccepted.

First statically valid call permanently stops work, fixes this one allowance and
reserves its summary. The original creator/context guard is the first counted
read-only campaign work. Guard failure seals Ok(Unresolved) with exact reached
failure and zero original-owner cleanup. This refines the review's initial
admission wording as root directed: native guard attempts cannot be unbounded
pre-admission retries or hidden work. A sealed report is returned before validating
any later supplied budget, including a larger/expired argument; it is always the
same report with no new effects/records/clock queries or allowance refresh.

Every native campaign attempt has a CleanupEvent with operation_class
context_read_only or cleanup. Guard opens/closes of its own temporary descriptions
are context_read_only; actual original-owner cleanup is the other class. Charge
an event slot/maximum encoded outcome before the syscall, then record exact
result/errno/transition. Records include one terminal summary, so at most16383
native events fit even when native attempt cap is16384. Missing room/deadline
means no next attempt; preserve first unattempted original owner and count.

Outer uses zero wire messages, no normal step/thread/child/mount/namespace/filter,
no guessed reopening/bare-PID signal/wait, no report-derived authority or new
RetireRequest. It may signal only an already held original pidfd, poll/observe
its actual state, wait/reap only the exact original Child, close actual original
FD owners once, and remove only names originally created relative to held parent
owners. Before pidfd exists, exact Child can be polled/waited without PID-kill
fallback. Close admission assets only after dependants settle, and context owners
last. An invalid context cannot be repaired by minting another epoch/session.

Explicit close consumes the passed owner on every Linux result including EINTR;
record ConsumedWithCleanupError, never retry a numeric FD or double-Drop a reused
number. EBADF also sets sticky inventory violation. Clean requires all originals
settled plus no error/unknown. SettledWithCleanupErrors requires settlement with
errors retained and known inventory. Unresolved covers any outstanding owner,
unknown inventory, unobserved reap, guard failure or exhausted budget. No native
allowance guarantees shutdown; unresolved originals stay in the same session.
Drop makes no cleanup-success promise and only retains the failed-shutdown anchor.
Outer cannot create/retire TT02 effects, edit snapshots/RunReport or release leases.

OuterReport exhaustively binds RunId/contract digest, budget and timing, state,
actual aggregate hook counts, all admitted full invocation summaries/last seal
hashes, three original admission assets, current original subinventory, chronological
cleanup events, first/subsidiary errors, sticky unknown, pre/outer/post/lifetime
charges and terminal reason. end_clock_ns is an actual sampled value if possible;
when no further read-only attempt is allowed it is the last observed sample with
end_time_sample_kind=last_observed, never a fabricated exact completion time.
A completed native attempt crossing a deadline remains charged and cannot prove
the syscall was interrupted. Admission assets already consumed by actual run
retirement stay consumed; outer never closes them again.

Constructor Err has no successful session. LinuxFixtureAdmissionFailure returns
exact supplied 3 Files/paths and contract separately from move-only opaque
LinuxFixtureAdmissionCustody. This custody holds every pending original auxiliary
creator/context/temporary FD, at most16, and its bounded immutable ConstructorLedger.
No raw FD/clone/control authority escapes. `constructor_ledger()` is borrowed
immutable bytes; end its borrow before mutable finalization. Ledger seals on failure,
with actual supplied/auxiliary projections, chronological native attempts, first/
subsidiary errors, consumed constructor charges and sticky unknown inventory.
No constructor entry is given an unentered InvocationKey or TT02 effect.

ConstructorLedger permits at most4096 records including one terminal summary,
at most4095 native attempt entries and524288 encoded bytes. Reserve its summary
and next native record before acquisition; cap exhaustion returns the partial
custody, never drops it. Every FD is immediately wrapped/registered before later
fallible work. Successful temporary closes are explicit charged consumed operations;
all still-pending auxiliaries move unchanged into custody on any error. Constructor
charges the existing parent pool and retains actual cursor-safe pread/image work;
it never resets counters in the admission-custody cleanup.

The custody has the same one-shot finalize(&mut self, LinuxOuterCleanupBudget)
and immutable admission_cleanup_report() shape. It shares the private budget/
consumed-close mechanism with the session finalizer, but its only native operation
is close on an actually retained pending auxiliary FD, once each. It cannot spawn,
signal/wait, remove a path, change a namespace or reopen. Closing these FDs does
not exercise process control, so it requires no complete creator control guard.
First static-valid call fixes its additional allowance and seals one report;
zero/small valid attempt/record allowance can leave Unresolved. Repeat returns
that same report, ignoring later budget changes, with zero work. Closed auxiliary
owners never reappear by numeric FD. Unknown close outcomes/errors stay explicit;
EINTR/error consumes the owner and EBADF leaves sticky inventory uncertainty.
Unattempted originals remain in the same custody; Drop only retains the failed-
shutdown anchor. At most16 actual close events plus one summary are needed, while
input allowance maxima remain16384/16384/1048576 and remaining time<=retirement.

AdmissionCleanupReport binds RunId/contract digest where already established,
immutable constructor-ledger digest/length, exact auxiliary owners/states, budget/
timing, close events, errors/unknown, constructor/outer/additive lifetime charges
and terminal state. There are no worker claims/messages, hooks or fabricated
invocation effects. Current own seal_charge is separate as above. Pure budget
admission errors retain custody. The ledger's own completed seal work is included
once in the report's constructor charges; current report seal work is added once
for the delivered boundary. This is not a reset of constructor work.

The one previously reserved1048576-byte slot moves exclusively to either the
successful session or failed constructor custody. Failure divides it into immutable
constructor-ledger <=524288 plus admission-report <=524288; combined actual lengths,
capacities, encoded/hash work are checked. Constructor ledger and admission report
hashes together consume the same <=1048576 outer session hash allowance, instead
of the successful session's report, never both. On successful construction its
unpublished constructor scratch may be reused by the full outer report; admission
aggregate counters remain. No extra report slot or memory is silently allocated.

Reserve the full slot before the first auxiliary acquisition/native admission
work. A pre-reservation failure has zero auxiliaries and uses a fixed16384-byte
inline empty ConstructorLedger/admission report pair, with not_started, actual
zero native/read/file/hash counters before its own seal and the explicit16384
inline capacity charge, no fake digest if not yet computed, and a fixed <=64-
byte first diagnostic. No event/subsidiary/auxiliary list exists on that path.
If no CLOCK_MONOTONIC relation was ever sampled, nullable deadline/entry/end clock
fields stay null and sample kind is unavailable; actual remaining Instant duration
still bounds the budget. No clock is fabricated. Full session reports require
their established non-null monotonic values. Exact combined encoding must fit16384 before return; fixed metadata explicitly
includes that buffer. There is no fallible cleanup hidden in that empty path.
This is the narrow zero-native allocation-failure representation, not permission
to place a partial native inventory outside the reserved slot.

The driver's original asset guard separately owns the exact returned supplied
Files. Its one-shot direct path permits at most3 explicit consumed File closes,
and AssetGuardReport includes its actual outcomes plus constructor-ledger and
auxiliary-cleanup report references. Combined Clean requires both auxiliary and
supplied owners actually settled without cleanup errors/unknown; a constructor
failure itself is a failed operation, not evidence of cleanup error or capability
support. SettledWithCleanupErrors/Unresolved preserve either domain's errors or
custody. An absent auxiliary campaign is not clean merely because supplied 3 closed.
The driver never reconstructs auxiliary owners from a digest/report. Its fixed
131072 storage remains separate; no second library outer slot is allocated.

TT03's native creator guard is a private specialization of the ratified pidfd+
active-PID-namespace Own semantics. Root selected the exact private algorithm in creator-context.md; actual
source/artifact/resource bindings remain separate before execution. It has no public dependency on future
production LX08, no provider trait and no new donor intake. Partial-constructor
controls must fail at each actual auxiliary-acquisition prefix, retain originals,
then exercise close-only cleanup, low budget, consumed-close error, Unknown,
repeat with larger budget and the zero-native preallocation-failure route. Native
identity/custody assertions, all NOT_RUN here, cannot be certified by JSON alone.

## Exact encoding and reservation arithmetic

The private checker computes the upper encoded length recursively from every
closed object key, colon/comma/bracket, scalar maximum and array bound. Nullable
uses max(null, value). U64 strings reserve22 bytes; I64 strings at most22;
label<=98 encoded bytes; keys use their actual admitted canonical length,
<=16384. String controls count six encoded bytes per UTF-8 control byte. Each
Subowner bound is717 bytes; 128 entries plus brackets/commas are91905.
Registrations conservatively bound each of seven lists at128 IDs, even though
the actual partition union is<=128. This deliberate overestimate costs91169 bytes
and cannot underreserve the actual projection.

Parent guard_events are separately chronological inside Snapshot, with exact
GuardEvidence tied to the reached native operation; they add no worker raw record.
Each native event body is dynamically precharged inside L before the attempt.
A simple bounded private representation uses one sequential encoded event tape
in the already reserved working arena, with framed length/order and linear
iteration; it needs no per-attempt heap object or offset table. Only bounded
worker transport indices and actual live owner/registration state use typed
metadata. Immutable descriptive/historical guard data stays encoded in L, and
consumed guard temporary ownership slots can be reused after their original
close outcome is recorded, with fresh unique event/owner IDs. Actual live-owner
layout, labels, offsets, hashes and all Vec/arena capacities must fit the stated
32768-per-invocation typed metadata budget; otherwise admission refuses before
effects. This is narrow fixture storage, not a public storage framework.

Snapshot terminal reserves all fixed envelope fields, largest legal failures/
errors/counters/registrations/subowners, records' empty brackets and one partial
entry's metadata with empty byte strings. Outer terminal reserves all fixed
fields,16 full invocation summaries, three assets,128 live subowners, errors,
counters and empty cleanup-event brackets. Dynamic complete records, partial hex
bytes/malformed packets, and cleanup-event bodies are added by actual encoding
before their action, within L or the one outer report slot respectively.
Per-population bounds substitute actual full invocation-key lengths and roster;
if some future subowner values are not known, their exhaustive type maximum is
reserved. No raw record/error/counter/inventory field is omitted to fit.

The static-check.json terminal_encoding_upper_bounds are reproducible exact
syntax upper bounds, not observed native allocations. Current recursive terminal bounds are Snapshot255019, OuterReport411019,
AssetGuardReport41556, DriverHoldReport17213, ConstructorLedger50742 and
AdmissionCleanupReport67239 bytes (dynamic event bodies are charged separately). The first two are <=524288;
that constant is only a guard ceiling. There is **no new universal minimum L**.
Admission reserves that population's computed snapshot terminal bound inside
its L, and reserves its outer terminal bound inside the already full 1MiB outer
slot. Too-small L before effects is distinguished from reached partial-effect
controls. Evidence work reserve also includes maximum next native/receive
outcome, every actual hex/JSON increment and the immutable final summary.

Full library retained reservation is
`4*N*L+2*L+3*65600+3*N*65536+3*1048576`:
4NL immutable slots,2L serialization/expected work,3 datagram buffers,3 blobs per
invocation, source buffer, fixed metadata, full outer slot. N15/maxL=266338496
fits268435456; N16/maxL=283312320 refuses. All arithmetic/actual capacities and
stricter actual TT02 allowance are checked before effects; no positive allocation
result is claimed. Fixed metadata suballocates at most278528 roster/global,
148608 three binary+hex handovers,524288 typed state (32768*16),8192 global state,
plus16384 inline empty-failure storage, total976000 of1048576, leaving72576. Actual layout/Vec capacity must fit; excluded
allocator/kernel/RSS overhead is separately measured at future qualification.

Hash cap per invocation becomes294453760 =8I+6L+6F+6*65536+4*16512. Encode work
cap is34145792 =8L+6*65536+4*(16512+33024). Session manifest hash<=6569984 and
outer report hash<=1048576 once, total7618560, are separate additive work.
Worker retained capacity remains14942272 per live image; three live maximum.
No new worker record/exchange is introduced. Existing forced chunks and total
encoded worker bytes<=L keep the per-scenario432/472/440/352/556/568/552 wire
bound. Additional outer native/report/driver work has its separately named
allowance; no global bound across arbitrarily many leaked sessions is asserted.
