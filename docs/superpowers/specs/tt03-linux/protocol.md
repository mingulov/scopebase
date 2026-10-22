# TT03 closed core protocol

**Ratified exact design / product checks NOT_RUN / not PACKET_READY.** This is one Linux fixture dialect,
not a reusable protocol framework. No codec/helper exists yet. The immutable
arrays and ceilings in [contract-data.json](contract-data.json) are normative
with this document; disagreement is an admission error, not executor discretion.
TT02's types, runner checkpoints, effects and retirement requests are unchanged.
[schemas.md](schemas.md) and [schema-contract.json](schema-contract.json) close
the exported bytes/counters and are normative with this document.

## Encoding, launch and envelope

Only the parent issues requests. Each immediate child has a private nonblocking
CLOEXEC AF_UNIX SOCK_SEQPACKET socketpair; its explicitly inherited protocol end
is fd 0. Parent holds the other original endpoint. stdout/stderr are null; no
stdout readiness parser, ambient socket, reader thread or unbounded queue exists.
All installed received descriptors are immediately wrapped/registered before
fallible decoding. Receive uses MSG_CMSG_CLOEXEC, capacity for two received FDs
(to reject the one-extra-FD control), and rejects MSG_TRUNC/MSG_CTRUNC, any other
ancillary kind or cardinality mismatch. Close extracted invalid FDs once and
record errors/uncertainty. FD integers in data never transfer ownership.

One datagram is a 64-byte envelope followed by exactly payload_len bytes:

| Offset | Width | Value, little endian unless bytes |
|---|---|---|
| 0 | 8 | ASCII SBFIX001 |
| 8 / 10 | 2 / 2 | major 1 / minor 0 |
| 12 / 14 | 2 / 2 | kind / flags 0 |
| 16 | 4 | payload_len, 0..65536 |
| 20 / 22 | 2 / 2 | FD count 0 or 1 / reserved 0 |
| 24 | 16 | RunId decoded from its exact lowercase hex |
| 40 | 8 | positive invocation operation_id |
| 48 | 8 | positive per-child request sequence |
| 56 / 60 | 4 / 4 | exact script index, or 0 at handshake/retire / reserved 0 |

Sequence starts at 1 and increments for every request on that child's channel;
exec keeps the original channel and sequence. The sole reply matches exact
run/op/sequence/step and declared expected kind. No unsolicited messages, retry
datagrams, sequence reset, duplicate/gap, new ACK for a lost ACK or extra payload
are accepted. EINTR/EAGAIN attempts charge native calls; they do not authorize
resending a committed SEQPACKET datagram. One malformed reply replaces one normal
reply and stops the exchange. Worker/main service is single-reader/single-writer.

JSON objects are canonical UTF-8 JSON with keys sorted lexically by UTF-8 bytes,
no whitespace, duplicates, floats or trailing bytes. Strings use literal UTF-8
for every non-control scalar except quote/backslash, escaped as `\"`/`\\`.
Every U+0000..001F uses exactly lowercase `\u00xx` (including tab/newline); slash
is unescaped. Reject lone surrogates/invalid UTF-8. Other fixture enum/Label/hex
strings remain ASCII. **Accepted cell_id is the explicit exception**: preserve
its original arbitrary nonempty Rust UTF-8 string, including Unicode and controls,
its accepted <=65536-byte and actual RunLimits.name_bytes bounds, and the escaping
above. Do not normalize/filter/replace it. Numeric u64/i64 values are canonical
decimal strings; positive u32 revision/attempt/indices and PIDs/TIDs are JSON
integers. Unknown/missing keys/enums refuse; nullable fields stay explicit.

The complete accepted invocation is exactly
`{run_id,case_key:{case_id,case_version,cell_id},attempt,operation_id}`;
run_id is 32 lowercase hex, case_id the accepted <=96-byte CaseId, case_version
and attempt positive u32, operation_id positive decimal-u64 string. It passes
actual TT02 CaseKey/InvocationKey checks and equals the admitted manifest key.
Canonical key length must be 1..16384 **within** the existing per-invocation
metadata ceiling; this is a named fixture transport admission bound, not a change
to TT02's wider accepted Cell type. A key or combined metadata too large returns
Unavailable/Limit before native effects. No case/attempt inference from scenario,
operation number or manifest digest is permitted.

Initial argv is exactly `[supplied_absolute_image_path,
"--scopebase-fixture-v1","--slot",S,"--handover","-"]`, where S is `a`, `b`,
`inventory-positive` or `inventory-negative`. No other flags/argv are accepted.
Command uses explicit absolute supplied path, env_clear, no shell/PATH/build
script/pre_exec callback, null stdout/stderr and the explicit protocol stdin.
Absolute path bytes are nonempty, at most 4096, NUL-free and encoded as path_hex
in Hello. These trusted explicit fixture paths are not arbitrary adapter input.

Hold original Child, acquire original pidfd, open actual original-child proc and
PID/mount namespace handles, and authenticate actual executable bytes against
the retained premeasured expected File before case-root grant. A Hello marker
does not authenticate an executable. Before pidfd exists preserve exact Child
custody without a PID kill fallback. Wrong image retains partial/unknown effects;
it cannot prove an untrusted same-UID image did nothing. Hostile same-UID path/
proc replacement is outside this trusted fixture claim and never silently
reclassified as a supported adversarial execution environment.

## Every message kind and exact body

All unused binary fields are zero and all lengths/cardinalities exact.

| Kind | Exact body / FD rule |
|---|---|
| 1 HelloRequest | Canonical JSON object below, at most 65536 bytes; 0 FDs |
| 2 HelloReply | Canonical JSON object below, at most 4096 bytes; 0 FDs |
| 3 AdvanceRequest | 16 bytes: opcode:u16, actor:u16, image_epoch:u32, blob_mask:u32, reserved:u32; 0 FDs |
| 4 AdvanceReply | 32 bytes: opcode:u16, actor:u16, image_epoch:u32, pid:u32, tid:u32, first_record:u32, record_count:u32, phase_flags:u32, reserved:u32; 0 FDs |
| 5 RawRequest | 16 bytes: record_index:u32, offset:u32, max_chunk_bytes:u32, reserved:u32; 0 FDs |
| 6 RawReply | 48-byte fragment prefix below, then exact fragment bytes; 0 FDs |
| 7 FdTransferRequest | 16 bytes: direction:u16, role:u16, image_epoch:u32, grant_id:u32, reserved:u32; FD rule below |
| 8 FdTransferReply | Same exact 16 bytes, echoing request; FD rule below |
| 9 CloseRequest | 16 bytes: reason:u16, actor:u16, image_epoch:u32, last_completed_step:u32, reserved:u32; 0 FDs |
| 10 CloseReply | Same exact 16 bytes, echoing request; 0 FDs |
| 11 Error | Canonical JSON object below, at most 4096 bytes; 0 FDs |
| 12 InputChunkRequest | 48-byte fragment prefix then exact decoded blob bytes; 0 FDs |
| 13 InputChunkAck | 16 bytes: blob_index:u32, total_bytes:u32, next_offset:u32, reserved:u32; 0 FDs |
| 14 InventoryRequest | Canonical JSON object below, at most 4096 bytes; 0 FDs |
| 15 InventoryReply | 16 bytes: entry_count:u32, first_record:u32, record_count:u32, reserved:u32; 0 FDs |

Actor codes are a=1, b=2, inventory-positive=3, inventory-negative=4. Image epoch
starts at 1 per initial child and increments once per successful exec of A;
counter B and inventory roles cannot exec. Header operation/step selects the
exact immutable action; body opcode/actor/epoch must agree subject only to the fixed heartbeat and
successful-exec rules below. Phase flags: bit0
validated sibling held live, bit1 leader-only exit reached with sibling held,
bit2 deliberately failed exec returned; other bits zero. Flags are raw fixture
acknowledgements, not production truth. Each ordinary Advance creates 1..9 raw
records contiguous from first_record; parent verifies/drains them before returning
advance or admitting the next action. Capture consists of at most eight records
plus one action record. A control can remove an ACK but cannot make missing
records into completed truth.

The exact Advance request mapping is as follows. A's worker-backed step uses
its action opcode from contract-data; blob_mask is 3 only for create_files, 4
only for mutate_file_a, and 0 for every other request. B receives opcode ready
only at ready, then one opcode capture_raw at each later non-close step to keep
the active negative population responsive. For parent-only offer_files A has no
Advance request (only the two pulls); parent_exit/parent_reap have no A request;
inventory gets one A capture_raw after both inventory children settle. For later
capture_raw after A exit/reap there is no A request. No B request creates files,
threads, execs or exits. These fixed B/A heartbeat exceptions may use capture_raw
with the parent/action's header step; every other opcode must equal the step's
worker action. This is the only exception to opcode/script equality, and remains
within two Advance exchanges per step. A and B close use only CloseRequest.

For a non-exec reply image_epoch echoes the request. Successful exec replies
carry request epoch+1, actual new pid/tid and no sibling flags; a deliberate
failed exec keeps its epoch and sets bit2. start_sibling sets bit0 after actual
validation; exit_leader and its following sibling captures set bits0+1; other
captures reflect only the currently held validated phase. No flag or blob bit
outside this exact mapping is accepted. Each record index is contiguous in that
producer's persistent sequence; exec handover carries its next index.

HelloRequest has exactly these keys:
`schema_version`, `invocation`, `mode`, `slot`, `scenario`, `manifest_sha256`, `images`, `steps`,
`completed_steps`, `image_epoch`, `next_record_index`, `execution_deadline_ns`,
`limits`, `blobs`, `control`, `inherited_fds`. Values:

- invocation is the full admitted canonical key above, in both boot and resume.
  It equals manifest and envelope run/operation; resume is byte-identical to boot
  and appended exec key. Exact complete Hello encoding (including escaped cell)
  must fit 65536 at constructor admission and every fixed resume form; no
  truncated/approximate size check. Workspace is reserved before effects.
- schema_version=1; mode=`boot` or `resume`; slot is its fixed actor string;
  scenario and exact `{id,action,actor}` steps come from the admitted scenario.
- manifest_sha256 binds the externally constructed full fixture manifest; it
  never measures the RunContract containing its own hash.
- images is exactly two entries in A,B order, each `{artifact,marker,path_hex,sha256}`.
  Marker is `A`/`B`; artifact is the exact prebound WorkerExecutable Label.
- completed_steps is exact consumed prefix length (0 boot); image_epoch and
  next_record_index match the parent's retained state (1 and 1 boot).
- execution_deadline_ns is the one fixed absolute CLOCK_MONOTONIC deadline;
  limits is the exact closed numeric-key object in contract-data.json.
- blobs is the exact 0- or 3-entry array `{index,total_bytes,sha256}`; indices
  1=A bytes, 2=B bytes, 3=equal-size A mutation, in that order. Inventory actors
  and process-only scenarios receive an empty list. Blob bytes never enter Hello.
- control is null or the exact allowed triple; inherited_fds is exactly `[0,1,2]`.
  It declares intentional inherited descriptors, not a claim about loader activity.

HelloReply has exactly `{schema_version,mode,slot,manifest_sha256,image_marker,
image_epoch,pid,tid,inherited_fds,signal_profile}`. Revision=1; other values echo
the request/actual compiled image. PID/TID are actual syscall results in 1..i32MAX,
validated against original Child and parent observations, never adopted as owners.
`signal_profile` is exactly `{term_disposition:"default",term_blocked:false}`
after worker-only configuration/checking; no host parent's signal state changes.
Its self-report corroborates, and does not replace, actual executable/child checks.

FdTransfer direction Push=1/Pull=2; roles CaseRoot=1/FileA=2/FileB=3.
Push/CaseRoot request carries exactly one FD; its reply carries zero. Pull/FileA
or FileB request carries zero; reply carries exactly one. Other pairs refuse.
CaseRoot grant_id=image_epoch (1..3); FileA=4 and FileB=5, once each at
offer_files in the file scenarios. The worker and parent retain original owners
throughout; a successful transfer neither retires nor transfers the sender's
registration. No separate unsolicited offer/ack, parent-invented File or later
resource publication exists. Each received owner is CLOEXEC and registered before
body/role checks. No inventory actor ever receives CaseRoot or blobs.

Close reason Normal=1/CaseRetire=2/RunRetire=3/SetupFailure=4; actor/epoch/current
prefix must match. Reply means the worker committed to cooperative exit after
sending that reply; parent still observes actual exit/reap. Close generates no
new worker raw record, offers no retirement shortcut and does not reset limits.
After close no ordinary request is admitted. If A is dead, skip its close request
and record actual absence; do not demand a reply or fabricate one.

Error has exactly `{category,native_stage,errno,call_result,step_id,
completed_steps,diagnostic_hex,reason,limit_kind,producer_charges}`. Category is InvalidProtocol/Unavailable/Denied/
Cancelled/TimedOut/Io/Other; native_stage is Ready/Advance/Read/Retire; errno is
i32 or null, call_result is signed decimal string or null, diagnostic bytes ≤1024. `reason`, `limit_kind` and `producer_charges` use the
closed WireError schema. Non-time limits are category Unavailable, errno null,
reason Limit, actual LimitKind and consumed worker prefix charges; never an
invented LimitExceeded category. Cancellation/deadline/protocol/native errors
retain their actual categories/stages. The entire Error encoding must fit 4096;
its fixed summary reservation precedes any action. First encode-length-check
the non-diagnostic fields, then choose at most min(1024,floor((4096-fixed)/2))
diagnostic bytes. The exhaustive full-field bound is4107 with1024 diagnostic
bytes, while empty diagnostic is2059; at least1018 diagnostic bytes fit even
at maximal other fields. The diagnostic is an optional explanatory prefix, never
the sole source of stage/result/errno/limit/charge truth. Missing hook entry is not an
Error message or a native timeout.
It replaces the sole pending reply, retains the original header identity except
an admitted malformed-header control, and seals the first native failure. A valid
deliberately failing exec uses AdvanceReply and raw exec evidence, not Error.

InventoryRequest has exactly `{schema_version,mode,slots}`. Revision=1; mode is
`sensitive-positive` or `absence-negative`; slots is the frozen sorted array of
`{slot,fd_number}` for at most 32 actual parent owners, including `canary`.
FD numbers are nonnegative i32 descriptors actually owned by the parent at that
post-owner launch barrier; they are read-only inspection inputs, never close/
signal/wait authority. InventoryReply has entry_count=slots length,
record_count=entry_count+1 (one task plus one fd result per slot), and positive
first_record. It is followed only by separately requested RawRequest exchanges.

## One bounded fragment rule, two directions

RawRequest record_index is positive, max_chunk_bytes is exactly
`min(65488,total-offset)` after the first reply supplies total; the first request
uses 65488. The frozen record must be positive length. RawReply prefix is
`index:u32,total_encoded_bytes:u32,offset:u32,chunk_bytes:u32,whole_sha256:[u8;32]`.
It carries canonical raw JSON bytes **without another hex layer**. The first
offset is 0; each later offset is precisely previous offset+length. The parent
checks complete run/op/step/index/total/digest consistency, contiguous full chunks
(except the final chunk), total within ledger reservation, exact payload length
and final SHA/schema before using semantic truth. Duplicate/gap/overlap/mixed
record or changed hash stops work. A partial prefix is exported as partial
transport with its actual length; it is never a complete raw record.

InputChunkRequest uses the same 48-byte prefix (index is blob_index, total is
decoded blob length) and whole hash. Initial/mutation file input is decoded from
manifest lowercase hex once and sent as **plain bytes**, never rehexed. Each
request has one matching InputChunkAck and a fresh channel sequence. Force full
65488 chunks except final; all three blobs are uploaded after first root grant
and before create_files. Zero-length blobs have SHA256(empty), no chunk and are
already complete. Completion validates whole SHA and exactly the prebound total;
partial upload cannot enable create/mutate. No extra commit kind exists. No blob
can be replaced, grow or consume another blob's reservation. Mutation blob has
exactly FileA's original length, offset 0; no extending/truncating write.

All immutable worker records are frozen at capture and retained until copied
completely to parent; worker frees a completed record's transport storage only
after its final requested slice was successfully sent, while retaining its digest/
index bookkeeping. Parent already owns the full encoded original before advancing
or exec. Lost final reply is failure, not permission to replay/resend. Parent raw
records use the same schema and ledger reservation but never consume wire packets.

## Private creator/context authentication

The selected [creator-context.md](creator-context.md) algorithm is mandatory:
retained authenticated proc root + original creator pidfd + active-PID namespace
FD/key/TGID, distinct from the supplied workspace root. Constructor6 acquisitions/
peak4/retain3/close3 costs23+R (minimum28). Each guarded entry fresh4/peak3/retain0/
close4 costs19+R (minimum24), all inside its aggregate existing budget. Normal
work uses normal cancellation/deadline; actual retirement/outer cleanup guards
use their own fixed allowance, so expired/cancelled execution does not veto them.
Context3 survives TT02 run retirement and outer closes it last. Guard temporary
failure/incomplete retirement leaves original custody and no original cleanup.
GuardEvidence preserves actual poll count/raw signed revents/errno, reached kind/
GETFD/namespace proof and first error. Parent guard events are inside L and add
no worker wire record/exchange. Missing actual guard artifact remains UNBOUND.

## Closed scripts, files and native phases

Only these actions exist (exact opcodes in contract-data.json): ready, capture_raw,
set_tricky_comm, exec_b, exec_a, exec_missing, start_sibling, exit_leader,
exec_from_sibling, create_files, offer_files, replace_file_a, unlink_original_a,
mutate_file_a, inventory, parent_exit, parent_reap, close. No action arguments are
accepted; exact byte inputs, steps and controls are bound in the manifest.

The full scripts/prefixes/resources are in contract-data.json. In particular,
tricky-comm is ready → set_tricky_comm → capture live → parent exit → capture
zombie → parent reap → capture reaped → close. The literal bytes are
`6129205a2031202862` (`a) Z 1 (b`); direct raw comm/stat check precedes successful
set_tricky_comm completion. Repeated capture actions have unique Labels.

Each raw capture uses fresh independently opened source descriptions relative to
retained original proc/task handles, never a dup/shared seq_file cursor. Up to
eight records per child are task, view, proc(stat), proc(status), proc(maps),
proc(mountinfo), fd(actual exe) and exec state. A source refusal records actual
syscall/errno and remains missing truth; it does not guess a result. Parent's
original pidfd/WNOWAIT/proc/fstat/pread observations are separately sourced.

Case directory is created exclusively as `tt03-<RunId>-<operation_id>` relative
to the caller's original root, mode 0700; existing name refuses rather than
adopts. RunContract globally rejects duplicate operation IDs across case rules
and attempts; RunId is 32 hex and decimal operation ID at most 20 bytes, so this
component is at most 5+32+1+20=58 bytes. Preserve it without renaming. Allowed leaves are `a`, `b`, `a-original`, `missing-executable`; creation
uses exclusive no-symlink relative operations. missing-executable must be proven
absent immediately before deliberate exec_missing; any surprise occupant is
fixture failure. create_files creates a and b from immutable blobs 1/2 with
direct independent readback. offer_files lends both actual owners. replace_file_a
renames a→a-original then b→a; unlink_original_a removes only a-original;
mutate_file_a writes blob 3 at offset 0 through original FileA (still owned after
unlink). Equal bytes on A/B are a separate bound population, not proof of identity.
Parent checks actual retained descriptors, created-name ledger and content.

Live→zombie→reaped uses parent-only original pidfd signal/poll/WNOWAIT/exact reap.
Before A exits, all required worker records have been fully downloaded. Later
capture samples retained original-proc outcomes and B heartbeat, with **no dead-A
request**. ECHILD is success only if trusted exact-owner ledger already recorded
that exact reap; otherwise unresolved. Parent cleanup is always outside a future
subject audit window.

start_sibling creates exactly one real sibling. A fixed CLOEXEC internal command
pipe and bounded shared state transfer sole protocol service to it once; main
thread ceases channel access and waits only for its explicit internal exit byte.
The sibling reports actual GETTID distinct from TGID; parent validates the held
task and stores the descriptive TID. For exit_leader the sibling instructs main;
main releases fixture locks and executes fixture-only SYS_exit, never exit_group.
The sibling remains the sole service thread and ACKs its own live phase. Parent
must independently reach raw main-terminal (Z or missing main-task entry) while
the actual sibling still responds under original unreaped group custody; failure
to reach this barrier is incomplete. These raw trigger alternatives are not an
LX08 result/errno table. No leader ACK is expected after its exit.

exec_missing runs on the current serving thread, preserves service on actual
failed syscall and records actual errno/image. During thread-lifecycle this is
the same live sibling. exec_from_sibling invalidates the retained nonleader TID
before initiating exec; a failing unexpected exec is fixture failure and leaves
TID None until a new actual task validation, with no false liveness promise.
Successful nonleader exec preserves original TGID/Child/pidfd custody, destroys
the old sibling TID and authenticates new image B; getter remains None. Reaped,
dead or unknown sibling state also clears it.

## Exec handover and authenticated root regrant

exec_b/exec_a/exec_from_sibling keeps the existing pending Advance request.
Old worker drains/finalizes prior raw records, closes no parent owner, and execs
the exact supplied destination path with fixed argv above but handover set to
lowercase hex of this 128-byte **header** plus its complete canonical invocation
key, with no new FD/message/exchange:

| Offset | Width | Field |
|---|---|---|
| 0 | 8 | ASCII SBFH0001 |
| 8 | 16 | RunId |
| 24 / 32 | 8 / 8 | operation_id / pending sequence |
| 40 | 4 | pending exact script index |
| 44 / 46 | 2 / 2 | scenario code / actor=a=1 |
| 48 / 52 | 4 / 4 | destination image_epoch / next raw record index |
| 56 | 8 | unchanged absolute monotonic deadline ns |
| 64 / 68 / 72 / 76 | 4 each | cumulative worker datagrams / native calls / encoded raw bytes / file-work bytes spent |
| 80 | 32 | immutable fixture manifest SHA256 |
| 112 / 114 | 2 / 2 | source marker (A=1,B=2) / destination marker |
| 116 | 4 | invocation_bytes:u32, 1..16384 |
| 120 | 8 | reserved zero |
| 128 | invocation_bytes | exact canonical accepted InvocationKey JSON |

The binary is exactly 128+invocation_bytes, at most 16512; the argv argument is
exactly twice that many lowercase hex characters, at most 33024. Reserve one
binary and hex workspace for each of three physical child slots in fixed metadata.
Reject trailing/truncated key bytes, bad JSON/escaping, any missing/unknown key,
wrong case/version/cell/attempt, header run/op mismatch or changed key on resume.
The new image validates full key/schema/canonical bytes and scenario/exact-step
admission **before** its first post-exec raw record. Parent rejects raw whose
key differs from the admitted key and authenticates actual image before root
regrant; Resume Hello repeats the same complete key. No parent patches a worker's
frozen record after download. The new compiled image validates the fixed handover, resets no counters and first
sends the original pending AdvanceReply with its actual pid/tid, new epoch and
its one post-exec raw exec record. This is an after-exec response, never an
about-to-exec success. The parent authenticates the actual new executable through
its retained proc-root route under original immediate-child custody. Any newly
needed post-nonleader-exec raw exec descriptor is separately registered; it does
not relabel/replace old retained proc owners or become production authority.
All ordinary descriptor owners including case root/internal pipe are CLOEXEC;
only protocol fd 0 and null stdout/stderr are intentionally inherited.

After actual image authentication, parent sends HelloRequest(mode=resume) with
the identical manifest/script/deadline/counter continuity and exact next index;
then pushes CaseRoot with grant_id=new epoch. No further action is admitted until
both replies validate. Process-only exec scenarios have no file owners/blobs to
reconstruct. Failed exec_missing remains in the original epoch/image and resumes
the existing service; no fake regrant is performed. The parent holds expected
executable Files and actual per-phase executable observations through retirement.

## Third-child descriptor inventory and sensitive canary

Only descriptor-inventory admits inventory action. At that barrier root, A/B
Child/pidfd/proc/namespace/executable owners, channels and both parent FileA/FileB
already exist. Freeze up to 32 selected **actual parent owner identities** and FD
numbers before launching anything. No total-FD-count oracle is used. Make a
separate read-end canary pipe with a fixed 16-byte token
`53424649585455524543414e41525931`, retain its original writer, and include the
read-end identity in slots. Admission requires every selected fixture owner FD
number and the canary to be greater than 2; the caller supplies such original
files, and created owners use F_DUPFD_CLOEXEC(minimum 3) if necessary before
registration. Otherwise refuse this inventory population before launch; do not
claim sensitivity for an FD overwritten by intentional stdio. The one canary
duplication/close is charged and recorded. Inventory child receives no root or file grants.

First launch inventory-positive in reserved third slot after clearing CLOEXEC
only on that intentional canary, restore the parent flag immediately, authenticate
actual image B, then issue InventoryRequest. Before opening files, it performs
F_GETFD/fstat on the listed numbers and reads the canary token if present, records
actual results, and responds. Oracle requires canary identity+token present and
all other selected fixture owner identities absent. Reap/retire this original
child and its subowners before reusing the physical third slot. Then launch
inventory-negative with all selected owners CLOEXEC; require canary and every
selected owner identity absent. Reused numeric descriptors alone are not a leak;
match the original recorded identity plus type-specific canary where applicable.

The inherit_canary bad control clears only this canary before the negative exec;
the reached negative assertion must fail for that identity/token. Both actual
inventory children have separate immutable registrations and raw evidence. A
failed positive, missing canary, incomplete inventory or unreaped third slot
cannot pass or spawn another probe. Loader-before-main FD reuse sensitivity and
exact runtime closure must be qualified under C7. A fixture-only pass does not
certify subject ProcessObservation CLOEXEC; the same arrangement after acquiring
actual subject owners, or an equally sensitive bound audit, remains **UNBOUND**.

## Closed control pairings

Every invocation has `control:null` or exactly `{kind,step_id,point}`. The named
step must be in its exact script and the pairing below must be applicable; reject
before effects otherwise. No magic env/argv, free-form arguments or arbitrary code.

| Kind | Allowed exact point / step |
|---|---|
| parent_failure_after_register | after_case_root_register / s01-ready; after_child_register / s01-ready (A only); after_pidfd_register / s01-ready (A only) |
| worker_exit | after_root_grant / s01-ready (A only); after_file_register / s02-create-files (FileA registered first, before FileB) |
| partial_file_write | before_ack / s08-mutate in file-replacement; A and mutation have equal length ≥2; bytes 0 and 1 each differ; write exactly one byte then exit without ACK |
| wrong_run, wrong_operation, wrong_sequence, wrong_step, unknown_major, extra_fd, truncated_payload, truncated_ancillary | before_ack / s01-ready; replace A's sole AdvanceReply; B/valid twin normal |
| inherit_canary | before_inventory_exec / s04-inventory; affects only inventory-negative canary |
| cancel_before_create | before_first_creation / s01-ready; set the actual constructor Arc AtomicBool before case-root creation |
| cancel_after_ack | immediately_after_ack / any worker-backed ready/capture/set-comm/exec/start/leader-exit/create/replace/unlink/mutate step; same actual AtomicBool, after all raw records for that ACK drain |

Malformed deterministic replacements: wrong_run toggles low RunId bit;
wrong_operation adds 1 checked (maximum id refuses this control at admission);
wrong_sequence adds 1 checked; wrong_step changes ready index1→2; unknown_major=2;
extra_fd attaches one duplicate protocol FD to the otherwise FD-free reply;
truncated_payload declares one more byte than sent; truncated_ancillary sends
three duplicates into the receiver's fixed two-FD ancillary capacity. Every
received/extracted owner and possible truncated inventory is accounted. Pure
literal corpus independently covers other malformed positions, duplicates,
unknown/extra JSON fields and length/hash/offset controls without pretending to
be a live setup failure.

Low-resource controls use separately prebound manifests lowering only declared
limits. Wrong-actual-executable is a separately bound incorrect supplied file/path,
never just a changed self-report marker. Normal restored twins have control:null.
The active control must fail the intended semantic/protocol/custody assertion
after its trigger, not merely fail unrelated setup.

## Raw record schema and independent oracle

Schema `tt03.linux.raw` revision1; each canonical JSON record has exactly
`schema_version`, `invocation`, `step_id`, `record_index`, `sequence`, `actor_slot`,
`record_kind`, `source`, `bytes_hex`, `values`, `call_result`, `errno`, `producer_charges`.
producer_charges is null for parent records, and the closed ProducerCharges
object for worker records. Its per-image counters are captured immediately before
encoding this record; self-encoding/hash/send work appears only in a later
observed prefix and is not fabricated into a circular self-count. Parent
independent counters and missing worker tails are projected in the Snapshot.
record_index positive and contiguous per producer/invocation; actor_slot is
parent/a/b/inventory-positive/inventory-negative. sequence is actual channel
sequence or null for parent-only operation. source is parent_kernel/worker_kernel/
worker_ack. Not-applicable fields are null. Closed values keys:

| record_kind | Exact values object keys |
|---|---|
| task | pid,tid,parent_slot,self_link_hex,thread_self_link_hex |
| fd | slot,device,inode,file_type,size,fdinfo_hex,getfd,getfl,canary_hex |
| view | proc_root_slot,proc_fs_type,pid_ns_slot,pid_ns_device,pid_ns_inode,mount_ns_slot,mount_ns_device,mount_ns_inode,self_link_hex,nspid |
| proc | descriptor_slot,file_name,read_calls,bytes_read,eof,overflow_probe |
| exit | child_slot,method,poll_revents,si_pid,si_code,si_status,exit_status |
| exec | image_before,image_after,executable_slot,executable_sha256,birth_ticks |
| mutation | original_slot,replacement_slot,operation,offset,byte_count,readback_hex |
| failure | native_stage,reason,limit_kind,completed_steps,subsidiary_errors |

PID/TID/si_pid are positive i32 or null; raw flags/status/errno are i32 or null;
counts/device/inode/offset/size/work/ticks are u64 decimal strings or null;
call_result is signed-i64 decimal or null. file_type is regular/directory/socket/
pipe/other; file_name is stat/status/maps/mountinfo; method is pidfd_poll/
waitid_nowait/reap. nspid is a bounded nonempty positive-i32 array (≤32) or null.
Booleans are actual booleans; slot/image fields are validated Labels or null.
operation is a closed script action; native_stage is Admission/Launch/Ready/
Advance/Read/Collect/Retire. reason is Protocol/Unavailable/Denied/Cancelled/
TimedOut/Io/Limit/Injected/CloseError. limit_kind is an exact limits-object key or
null. subsidiary_errors is chronological, ≤32 entries exactly
`{native_stage,reason,errno}`. completed_steps is exact bounded Label prefix.
task's raw stat/status are separate proc records, never an alternate bytes field.
proc stores its exact source bytes in bytes_hex; other kinds use values' explicit
hex fields and bytes_hex=null. All required fields stay present on native failure,
with unavailable native values null and actual result/errno retained.

No record asserts Pass/capability/clean shutdown. Bytes precede parsing; production
observations cannot supply expected values. Independent Python oracle parses final
comm delimiter, field positions, lifecycle/exec/image and literal file outcomes,
with its own literal malformed/positive corpus. ExpectedEvidence uses the actual
invocation/oracle/schema and IndependentLedger truth kind only after complete
raw validation. Parent-owned pidfd/WNOWAIT/reap and actual retained file readback
are independent causal witnesses, not just a second production parser.

The raw values/types and required relations are fully specified in
[schema-contract.json](schema-contract.json) and [schemas.md](schemas.md).
Exported `raw_ledger` is a Snapshot envelope, not a bare array of these records.
Complete records are inlined as JSON objects, preserving original canonical bytes;
partial prefixes are explicitly hex with actual lengths and charged expansion.

## Reached actual-runner deadline control

The separate driver schedule is null or exactly contract-data.json's
`runner_deadline_after_ack` schedule. It is never a worker action/control,
message, refreshed fixture/runner deadline or fabricated clock. The frozen
population is exec-aba at real s06-a2: actual A→B→A and live unrelated B, original
case-root/A/B owners, complete validated ACK and full raw drain. Prepare and
Execute have already been entered. Cancellation stays false.

The driver caches its valid actual Observation at this barrier, samples its own
Instant, then waits at least the **full contract execution duration from this
point** (execution_ms=30000). Runner entry necessarily preceded this ACK. It
returns Ok(the cached normal non-refusal Observation) without invoking another
fixture phase. The completed prefix remains through s06-a2; s07-close is not
invented. The accepted runner's own execute.after check must actually sample
elapsed>=execution_ms*1000000 and omit Collect/Judge. fixture_failure may be None;
no native TimedOut is invented. Case/run retirement follows only where actually
entered, then the separate finalizer.

The driver fixes outer deadline once before construction, at most 120000ms,
with contract retirement_ms<=30000. Hold admission requires remaining outer time
>=31000ms plus the selected retirement allowance. Wait uses <=64 clock checks,
<=64 waits, each requested sleep<=500ms, and a maximum reached hold of 31000ms.
Clock/wait attempts consume the separately declared driver allowance <=128;
no fixture native counter is reset or worker wire sent. Scheduler overshoot,
short/failed wait, outer expiry, expired-before-ACK setup, false barrier or changed
cancellation is Incomplete, retaining original custody, never reached control PASS.
The hold cannot interrupt a syscall or guarantee retirement.

An active unpaused twin uses the same ABI/images/owners/barrier/cached actual
Observation, consumes s07-close normally, returns normally and reaches Collect.
The typed fixture-local TimedOut population is separate. DriverHoldReport is a
closed descriptive artifact in the fixed 32768-byte driver slot, not evidence
inserted into old fixture records or a new worker exchange.

## Bounds and derived packet allowance

contract-data.json fixes every explicit ceiling, its units and all per-scenario
caps. Lower limits may deliberately refuse; they cannot shrink the selected
required population into a supported claim. Parent ledger L≤4194304 bytes is a
combined ceiling for worker and parent encoded records, transport prefixes,
snapshot envelope and failure/retirement events. Use the population-specific
terminal reservation in schemas.md, computed before effects from the exhaustive
schema and actual admitted keys. Its global snapshot upper bound is 255019 bytes;
524288 is only an upper ceiling, never a universal minimum L. A lowered valid L
that cannot hold its exact envelope refuses before effects; reached partial-effect
controls separately require enough admitted L to reach their named owner prefix. Raw source file≤1048576 bytes
including an overflow probe; file blobs≤65536 each, read calls≤4096/source.
Stop on the first exhausted reservation, retaining a bounded partial prefix.
One source ceiling does not promise all maximum-size sources fit the ledger.

Parent native attempts≤16384 across normal execution and retirement, reserving
512 for actual case/run cleanup. Each of at most six image entries has at most
4096 explicit worker syscall attempts (128 cleanup reserve); original exec
handover also preserves cumulative worker counters. Session admission pre-reserves
all six image budgets, never replenishes them on exec; explicit total≤40960 per
invocation. Constructor admission charges its native attempts once against the
session parent pool N*16384 (preserving N*512 cleanup reserve), separately from
per-invocation counters; it never invents a participating InvocationKey. Parent
pool consumption cannot be refunded to later cases. Outer finalization has its
additional once-only <=16384 allowance, so session explicit native total is
<=N*40960+16384. Runtime/Command calls excluded below remain excluded.
Every attempted wrapper syscall, poll, retry and close is charged first. C7 must
identify any standard Command/runtime internal syscalls excluded from this
explicit count; this is not an all-kernel-calls promise. Parent open owners≤64,
children concurrent≤3, total child registrations≤4, sibling threads≤1, created
case directories≤1 and leaf names≤4. No root/child/FD capacity refund until
actual settlement; consumed-close errors still retain failed-shutdown evidence.

Let S=script length (≤10), E=successful exec count (≤2), Q=inventory child count
(0 or2), D=inventory slots≤32, U=uploaded blobs (0 or3), C=65488, F=65536.
At most R=18S+Q(D+1) transported worker records exist (≤8 capture+1 action per
child/step; inventory task+D fd records). Every positive record consumes ≥1
ledger byte, total encoded bytes≤L. Forced full chunks give
`raw_chunks ≤ R+floor((L-R)/C)`; no arbitrary tiny-chunk requests are allowed.
`upload_chunks ≤ U*ceil(F/C)`. Other exchange allowance is
`4 + P + 2E + 2S + 2Q + (2+Q) + 6`, where P=2 for file scenarios else0:
initial A/B Hello+root, FileA/B pulls, exec Hello+root regrants, up to two
step exchanges, inventory Hello+request, cooperative closes and case/run closes
for three simultaneous child slots. Parent-only actions use fewer exchanges;
the overapproximation is intentional and charged once. Each exchange is at most
one request plus one reply; Error/malformed controls replace that reply.

Thus the hard datagram caps per invocation are **432, 472, 440, 352, 556, 568,
552** respectively for leader, tricky, ABA, failed-exec, thread, file, inventory.
The global ceiling is **568 datagrams across all channels including retirement**,
not the old arbitrary 256 per child. Header/buffer maxima are 65600 bytes. Outer finalization and driver hold add
zero worker exchanges. Additional schema fields fit inside the same L and add no
raw record; the transported-worker-record R formula is unchanged. Partial hex
expansion/envelope bytes reduce usable payload when necessary, never spend
outside L. Thus the old algebra is retained, not treated as a functional test.
Bytes, native attempts, hashes, memory and wall time have separate bounds; a
packet allowance does not excuse native or retained-byte exhaustion.

Four immutable ledger snapshots per invocation reserve `4*N*L`. Add `2L`
working/expected serialization, three 65600-byte packet buffers, three F-byte
decoded blobs for EACH of the N admitted invocations, one 1048576-byte source buffer, 1048576 fixed metadata bytes and the full
additional 1048576-byte outer report slot. Three (16512+33024)-byte handover
workspaces are suballocated inside fixed metadata, not uncounted allocations.
Checked reservation must fit both the explicit 268435456-byte parent retention
ceiling and the admitted TT02 retained-byte allowance before effects; N≤16 is
also limited by that arithmetic (N=16 at max L refuses). Worker per-image explicit
retention ceiling is `3L+1048576+3F+65600+1048576`; at most three are live.
These are retained capacities, not global RSS/kernel socket/allocator/dynamic
loader bounds. Four snapshot slots never grow on repeated export. Runtime
qualification must measure excluded overhead; no aggregate bound across
arbitrarily many sessions or leaked terminal anchors is claimed.

Explicit hashing ceiling is 294453760 bytes/invocation at full limits:
two expected images plus ≤6 actual image authentications at I=33554432 bytes,
plus 6L (worker/raw validation and four seals), 6F (both sides of three blobs)
and six 65536-byte Hello validations, plus four 16512-byte handover validations
(two sides of at most two execs). Encode work separately caps at
8L+6*65536+4*(16512+33024)=34145792 bytes. Canonical byte equality does not
authorize redundant uncharged hashes. Image size>I or extra required hash work
refuses; RunContract artifact measurement has its separate accepted TT02 budget.
Whole raw chunks are not redundantly rehashed per request; each logical digest
is charged once per specified producer/consumer. Actual implementation must
account encoded snapshot envelopes within L, rather than double-spend capacity.

Parent execution Instant is fixed at construction. The proposed worker absolute
CLOCK_MONOTONIC deadline is sampled once conservatively: sample parent Instant
i0, monotonic K, parent Instant i1; use K+max(0,parent_deadline-i1). Recheck parent
deadline before every operation. Same time namespace and checked clock relation
are admission requirements; inherited/nested/time-realm behavior must follow the
ratified creator/context contract (actual native artifact UNBOUND). Retire uses the actual RetireRequest
deadline/remaining allowance instead of the expired normal-work deadline, with
unreset native counters; neither call refreshes its own cumulative cleanup clock. No entered
syscall interruption, bound on arbitrary adapter code or deadline-guaranteed
process retirement is promised.

Constructor parsing is bounded separately: encoded manifest bytes are at most
`N*(6*F+16384)+16384`, maximum 6569984 at N=16 and F=65536. The 6F term
is the three hex blobs; invocation metadata is at most 16384 encoded bytes and
global metadata at most 16384. Parse directly into bounded configs and decoded
blobs, retaining no whole duplicate hex/JSON DOM. Session admission hashes the
manifest once under a separate 6569984-byte work cap; it is not free work hidden
inside the per-invocation image/raw hashing allowance. Full retained reservation
is `4*N*L+2*L+3*65600+3*N*F+1048576+1048576+1048576` before effects. At N=16 and
maximum L it is 283312320 bytes and refuses the 268435456-byte session cap; at
N=15 it is 266338496 and fits that explicit cap, still subject to stricter actual
TT02 allowances. The outer report is hashed at most once under an additional session 1048576-byte
allowance: manifest+outer hashing <=7618560 bytes. Actual returned arena/Vec
capacities, inlined owner/slot bookkeeping, handover scratch and hash/encoding
work must all be checked; an allocator capacity larger than the budget refuses
before native effects. The arithmetic is a checked reservation premise, not
observed product allocation. Driver separately reserves 131072 bytes (65536
asset-guard report, 32768 hold report, 32768 fixed state); it is outside this
library session cap and independently declared. Caller input buffer and excluded runtime/kernel memory remain
separate; no arbitrary manifest-size parsing or per-case retention reset exists.

Worker-local files are subowners of the original child/case-root inventory. The
separate FileA/FileB effect registrations name the parent's actual SCM_RIGHTS
receipts only. On after_file_register worker exit before an ACK, known child/root
registrations survive and missing worker inventory remains sticky. Parent may
inspect the exact permitted names through its original exclusive case directory
to discover partial native objects, recording actual observations before cleanup;
it cannot infer complete inventory from a missing ACK or report text. Mutate's
partial-write control occurs after both parent Files were actually lent, so direct
retained FileA readback proves the one-byte partial effect independently.

The partial-write population additionally requires mutation[0] != originalA[0]
and mutation[1] != originalA[1]. Parent readback must be exactly mutation[0]
followed by originalA[1..], distinguishing no write, one-byte write and full
mutation without a worker ACK. A short/zero/error native write does not reach
this control's positive trigger and remains incomplete.
