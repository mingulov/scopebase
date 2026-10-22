# TT03 repair map and decision record

**Ratified detailed design; no product acceptance or execution.**
Root adopted all four recommendations from the immutable independent r2 review
index `68284c34bf0eb3f1d2b2c2f819439a7ad28f05b3ad76ebc8a2cb5acb9acc8560`,
reviewing r2 packet index
`1105d700199c7ec4a512f2d122495728eaa042ef0006ca3a8e0752534b5bf194`
and final protocol
`475f603d98cc8595153d10df4e61eef8a9a0a8805e7626b3378a271c7dc9cbe6`.
R1/r2, all reviews and historical receipts remain unchanged. New exact fields
and finite accounting here are within the ratified directions; actual separately
bound product execution remains a later root gate. No further
human approval is inferred or requested.

| Finding | WHAT: exact detailed repair | WHY, finite cost and future evidence |
|---|---|---|
| TT03-R2-01 | Full accepted InvocationKey in boot/resume Hello; existing128-byte header uses116..119 key length,120..127 zero and appends1..16384 canonical key bytes. Binary<=16512; hex argv<=33024. Actual complete Hello<=65536. Preserve arbitrary accepted cell content/escaping. | Workers previously lacked case/attempt before first post-exec raw. No parent-patched raw, new message or exchange. Workspace is inside fixed metadata; +66048 hash work/invocation explicitly reserved. Literal wrong case/version/cell/attempt/run/op/trailing/noncanonical/changing-exec controls and actual A→B→A/nonleader twins remain NOT_RUN. |
| TT03-R2-02 | Exact mutable LinuxOuterCleanupBudget/finalize/outer_cleanup_report API; first static-valid call permanently stops work/latches one budget, read-only live creator guard first; Ok(Unresolved) if it fails. Zero wire original-owner campaign with attempts/records<=16384 and full additional1MiB report slot. Constructor Err returns exact supplied Files/contract and opaque original auxiliary custody. Close-only one-shot custody cleanup is separate from the driver's actual three supplied-File closes, using the same exclusive1MiB outer slot. | Actual runner may omit every fixture hook or skip cleanup for exhausted allowance. Repeated native admission retries would be unbounded, so root refined live guard failure into the sealed one-shot report. Repeat returns original report only; original unresolved owners stay in same session. No RetireRequest, effect/receipt mutation or successful Drop. Explicit native/lifetime totals, consumed close truth and no-Prepare/uncalled/repeat/constructor controls remain NOT_RUN. |
| TT03-R2-03 | Exhaustive closed schema-contract.json, schemas.md and literal-controls.json: Snapshot/Failure/HookEntries/Charges/WorkerEpoch/Subowner/PartialTransport/OuterReport/AssetGuardReport/WireError. Raw worker producer-prefix charges added inside existing records; no extra record/exchange. Four stable immutable OnceLock slots return &[u8] after lock release. | External bytes previously lacked a checkable envelope/counters. Parent actual counters and worker claims/Unknown tails remain distinct. Non-time limits are Unavailable/errnoNone with exact LimitKind/charges. Terminal envelope is derived per population from the schema, with a524288 ceiling rather than an unapproved universal minimum L. Every dynamic encoded/hex byte is inside L; actual allocation/semantic controls remain NOT_RUN. |
| TT03-R2-04 | Separate driver exec-aba/s06-a2 reached schedule after real ACK+full raw drain/known originals, cancellation false; wait full30000ms from that barrier under <=31000ms hold and <=120000ms fixed outer deadline, then return normal actual cached Observation. Active unpaused twin continues close/Collect. | Constructor time does not prove runner deadline elapsed. Runner entry necessarily preceded ACK; only its real execute.after checkpoint must timeout. No fabricated time/native failure or worker action. Bounded128 clock/wait attempts and131072 driver storage are separate. Real stage/checkpoint/first-failure/charge/retirement evidence and separate typed fixture-local timeout remain NOT_RUN. |

The existing exclusive `tt03-<RunId>-<operation_id>` directory is retained:
RunContract's one global operation-ID set rejects duplicates across case/attempt
rules.32 hex+20 decimal+6 delimiters=58 maximum bytes. No renaming is needed and
no pathname becomes owner authority. This counterevidence is not a substitute for
transmitting the full key to workers.

R1 preservation is unchanged:

| Finding | Retained design and new residual coverage |
|---|---|
| RV1 | Real descriptive GETTID getter only at held validated sibling phase, clear before real nonleader exec/on loss; full raw key now preserved. |
| RV2 | Seven exact Prepare prefixes/resources/first-unconsumed steps; both actual Files exist before borrowed access; actual accepted maintenance is bound. |
| RV3 | Full tricky-comm sequence/literal and original14 closed worker-control triples remain byte-identical. Reached deadline is separate driver scheduling, not another worker action. |
| RV4 | All15 kinds/fixed envelope/shared fragment/input transport/authenticated exec remain; bounded full key and closed WireError/producer charges fill the reviewed gap. |
| RV5 | Actual failure/early/Collect/case/run publication and omitted hooks remain truthful; outer campaign cannot rewrite them. Exhaustive schema, unreset counters and reached runner deadline supply the missing contracts. |
| RV6 | Third positive/negative inventory after real selected parent owners, sensitive canary and two immutable children remain; actual subject arrangement/loader sensitivity is still UNBOUND. |

R1 preservation.md remains the exact source/pin/original-regression map. Existing
e29cc admission remains the only authority (14 admitted scopes/one reference-only,
three observed files); no source/history refresh or new intake occurred. Full14 P
and7 F names stay stable. A core increment cannot close full TT03 mapping,
acquisition/link/rename/unlink/mutation/raw fstat/fdinfo/maps/mount/credential/
worker-death/helper exits, TT04, TT07, runtime or installed requirements.

Accepted TT02 maintenance source2921606 equals candidate309190e fixture bytes,
root acceptance SHA256
dd9362f4bbdc7b0c55180f3cae47ccb4ab6961956e587cf0f21f372e64ad9e0a.
Its current borrowed-array signature is consumed; inner owner/byte lifetime
refusals remain. Old243 PASS and later three expected old-source premise failures
are preserved and never replayed or relabelled here. The bound6aaf00 partial C7
compile/API report grants no product dependency/archive/runtime qualification.

Matched Own initial+nested and ratified68a86c6 LX08 creator pidfd+active PID
namespace/EOF design are preserved. Actual product, C7, TT04, EOF, tracer,
provider/consumer/helper/archive resources and final joint compatibility remain
UNBOUND. There is no cross-index hash dependency: root later binds independently
finalized TT03/LX08 indexes in a separate joint record. Root owns any future
source/dependency/build/lease/acceptance changes.

The constructor/context advisory exposed a remaining ownership gap and root
selected explicit auxiliary custody: at most16 pending creator/context/temp FDs
plus <=524288 immutable ConstructorLedger, and <=524288 close-only admission
report share the already reserved 1MiB slot exclusively with the success outcome.
No raw owner export, silent Drop, control operation or production LX08 dependency
is introduced. A zero-native allocation failure has a checked16384-byte inline
empty-ledger/report path included in fixed metadata. Constructor and cleanup
charges remain additive; ledger/report hashes share the existing 1MiB outer hash
allowance. Partial-prefix failure, exact owner transfer, close-only operation,
consumed-error, low-budget/Unknown/repeat and exclusive-slot controls are NOT_RUN.
Root adopted the retained-root algorithm in creator-context.md; actual guard
implementation/source/artifact resources remain UNBOUND before product execution.

The sealed context advisory index0db2ed7a, translation965eb9a5 and root
ruling2072302d are now exact inputs. R3 adopts retained proc-root/creator-pidfd/
active-PID-namespace context3; constructor6 acquisitions/peak4/close3,23+R min28;
guard fresh4/peak3/close4,19+R min24. Parent-only closed GuardEvidence preserves
successful poll count/raw signed flags (also invalid/terminal) and null failed
outputs, kind/flags/creator/namespace members and first errno. Guard events use
existing L, metadata/source workspace and allowances; no worker exchange is
added. Execution cancellation/expiry cannot veto a valid cleanup guard. Failed
or incomplete temporary retirement seals Unresolved with original inventory
untouched. The exact r4 successor is ratified design; actual execution stays separately bound.
