# TT02 typed fixture failure receipt amendment

Status: controller-ratified normative amendment to the [TT02 engine](2026-10-18-scopebase-tt02-engine.md). Original immutable Astra supplement SHA-256: `d38b4e3ac616b949a6369a32c853e49bf687766aa24fdbc030b0b6a0d19d718e`. This fixes the unreleased schema-major-1 contract in place, with no compatibility alias/default. No implementation acceptance or profile qualification follows.

## What and why

A returned prepare/collect FixtureError is neither an adapter CaseOutcome nor ExpectedEvidence. Its category can independently stop the run, and its effects/progress must survive. A diagnostic reason string cannot reconstruct that typed fact. Add one required nullable fixture_failure field to CaseResult, holding the actual FixtureError. There can be at most one returned prepare/collect error per invocation because that error closes the invocation. The existing entered-stage prefix fixes the actual call; the error's declared stage must agree. No event log, additional clock, new checkpoint, operation outcome variant or fake observation is needed.

## Exact data and wire amendment

The complete CaseResult field list becomes:

`key`, `script_sha256`, `tier`, `entered_stages`, `execution_checkpoints`, `execution`, `reason`, `outcome`, **`fixture_failure`**, `expected_evidence`, `oracle_verdict`, `effective_checks`, `capability`, `coverage`, `effect_batches`, `case_cleanup_call_ids`, `terminal`.

fixture_failure is a required JSON member: null when no returned fixture failure is recorded, otherwise the exact bounded FixtureError object below. It is an immutable runner-owned Option<FixtureError>, exposed by `CaseResult::fixture_failure(&self) -> Option<&FixtureError>`; there is no setter permitting insertion into ExecutedHere. The existing FixtureError checked constructor is retained and its previously abbreviated fields are frozen as:

```rust
pub struct FixtureErrorValues {
    pub key: Option<InvocationKey>,
    pub stage: FixtureStage,
    pub category: FixtureErrorCategory,
    pub errno: Option<i32>,
    pub diagnostic_bytes: Vec<u8>,
    pub effects: EffectBatch,
    pub read_progress: Option<InputReadProgress>,
}

pub enum FixtureStage { Admission, Prepare, Collect, Retire }
pub enum FixtureErrorCategory {
    Unavailable, Denied, InvalidProtocol, Cancelled, TimedOut, Io, Other,
}
// Existing admitted-value pattern; no mutable fields or Deserialize bypass:
// FixtureError::new(FixtureErrorValues, &RunLimits)
//     -> Result<FixtureError, HarnessError>
```

The nested error object has exactly `key`, `stage`, `category`, `errno`, `diagnostic_bytes`, `effects`, `read_progress`. Enum wire strings are `admission/prepare/collect/retire` and `unavailable/denied/invalid_protocol/cancelled/timed_out/io/other`. diagnostic_bytes is an even-length lowercase hex string, subject to the existing diagnostic_bytes decoded limit and aggregate/encoded limits. It may be empty. errno is an i32 JSON integer or null; it does not determine category/capability. Every nullable field is present explicitly. Unknown/duplicate fields, alternate spellings, arbitrary reason tags and unsupported categories are rejected. FixtureError has no cause, capability, assertion, completed-step, expected-value or qualification field.

InputReadProgress, when present, uses exactly `file_id:Label`, `expected_length:u64`, `bytes_returned:u64`, `read_calls:u64`, using canonical decimal-string counts. This preserves the existing measurement/read record; it does not add a reader or retry. In a case receipt file_id must reference the frozen artifact being read, expected_length must equal its bound length, bytes_returned must be at most checked expected_length+1 (the existing possible EOF sentinel), and read_calls must be within the existing run allowance. Zero progress is allowed; positive bytes require positive read_calls. The report cannot infer successful admission from this progress. A failing read/retry does not replenish the shared meter, alter a caller File cursor or erase preceding meter usage. Absent progress is null, never fabricated zero progress.

FixtureError outside a case may still use key=null and stage=Admission, for example bundle admission or vector setter refusal. Such an error is not inserted into a case receipt. The case slot accepts only key=Some(the exact enclosing InvocationKey) and a declared Prepare/Collect stage matching the actual returned call. Retire is not a case failure route: retire still returns RetirementReport, with CleanupError in its scheduled cleanup record. No new retirement error channel is introduced.

## Call placement, return recording and partial rules

Record fixture participation immediately before prepare as already required. On a returned Err(error), move/retain the admitted error and its bounded effect batch before taking that call's required after checkpoint. A failure in the subsequent cancellation poll cannot erase the returned error. An over-deadline after sample coexists with the error; do not replace either fact with the other. The same owned cancellation probe and fixed clock/deadline from the ratified borrow amendment apply.

| Actual returned call | Required complete case shape |
|---|---|
| prepare returns Err | entered_stages is exactly [prepare]; fixture_failure is non-null with stage=prepare and exact key; outcome and expected_evidence are null. Adapter never participates; fixture does. Execute/collect/judge are not entered |
| collect returns Err | entered_stages is exactly [prepare,execute,collect]; fixture_failure is non-null with stage=collect and exact key; preserve the already returned adapter outcome without alteration; expected_evidence is null. Fixture and adapter both participated. Judge is not entered |
| prepare/collect returns Ok, or the call is never entered | No failure for that call is fabricated. fixture_failure remains null unless the other permitted fixture call actually returns Err |

A collect call following an adapter Cancelled/TimedOut or an already-stopping checkpoint is invalid protocol; that earlier stop cannot be bypassed merely to obtain expected evidence. A non-stopping well-formed operation CaseError still allows collect and may therefore coexist with a collect FixtureError. It remains an adapter error with its own progress/effects, never converted into the fixture error.

For every returned failure, the matching before gate must permit entry and its after gate is sampled in a complete receipt. Later unentered stages use prior_stop when the typed error or any observed gate has closed normal work; otherwise they use stage_not_reached. Their after slots use not_entered. Local failure cannot justify omitting an independent later invocation. Required case/run retirement retains its exact fixed slots, ownership and cumulative budget, including when the error reports no effects.

A partial receipt with run_terminal=null may retain a returned fixture_failure followed by a not_recorded after slot, but only under the existing unfinished-tail rule. Its typed stop/effects are still real received evidence; the missing sample remains incomplete. Conversely, entering a call does not prove it returned: an unfinished tail may have fixture_failure=null and no after sample/return data. Do not invent Cancelled/TimedOut for a hook that did not return. A complete receipt with a sampled after gate must account for that returned call's success or failure under the table and effect rules below. Dropping a failure and retaining only its reason is not an alternative encoding.

Unimplemented/not-entered cases have fixture_failure=null. The nonempty zero-executable path introduces no fixture call/failure. Before-effects admission errors may use the existing Err/partial_report=None route; a returned prepare error is already after fixture participation and cannot use that escape. After effect-capable entry, preserve the available partial report and attempt the existing retirement schedule even on invalid protocol. Arbitrary blocking/panic/abort still cannot be guaranteed to return a receipt.

A declared stage/key different from the actual invocation is not silently rewritten. It is InvalidProtocol; retain available bounded error data in the runner's partial evidence and mark custody uncertain where the response cannot be admitted. Such a malformed report is not a valid completed receipt, and from_json rejects its contradictory key/stage/effect binding. A well-formed matching FixtureError whose category itself is InvalidProtocol is different: it is a representable failure record that deterministically contributes Invalid.

## Effect retention and exactly-once reconciliation

The existing effect_batches field is the chronological list of returned effect-producing stage batches: prepare, then execute if returned, then collect if returned. It includes empty complete batches. Each such call contributes exactly one position; judge contributes none and retirement has its separate records. No batch exists for a call that did not return. This specifies the existing list's indexing; it adds no new batch wrapper or caller-chosen event name.

| Returned stage | Source / consistency check |
|---|---|
| prepare Ok | effect_batches[0] retains FixtureAccess.effects, since the borrowed access itself is not serialized |
| prepare Err | effect_batches[0] must equal fixture_failure.effects exactly |
| execute Ok/Err | effect_batches[1] must equal the enclosed Observation.effects or CaseError.effects exactly |
| collect Ok | effect_batches[2] must equal expected_evidence.effects exactly |
| collect Err | effect_batches[2] must equal fixture_failure.effects exactly |

These are **serialized mirrors of one response**, not two registration submissions. The pure ledger fold processes the chronological effect_batches positions once after checking exact equality to every available typed source. Never separately register the nested error/outcome/expected copy. A missing, changed, extra or reordered mirror is InvalidProtocol. Identical resource IDs in two different call positions remain illegal new registrations, as before; identical nesting and its one mirror is the explicitly permitted representation. This cannot excuse a second callback submission or a replayed transition.

A returned successful prepare is represented by its batch plus the absence of a prepare failure; a returned execute requires outcome, and a returned collect requires exactly one of expected_evidence or collect failure. These requirements also apply when a returned stage's after slot is not_recorded in an honest partial tail. Commit the response and mirror together before the next custom hook; allocation/validation failure retains the existing bounded partial/uncertainty path rather than inventing successful empty effects. All copies, if actually owned twice, count twice against retained/receipt limits; shared immutable storage may avoid a memory copy but does not remove wire bytes.

Every valid fixture error registration has owner=Fixture and origin=the exact current key. It can add new resources and complete=false uncertainty; it cannot settle or erase prior prepare/adapter effects. A collect failure therefore preserves all three received batches. Unknown inventory remains sticky under the existing rule even if later retire settles every known ID. Case/run cleanup reconciliation, duplicate IDs, scope constraints, unresolved participation and budget exhaustion remain unchanged.

## Pure reconstruction and precedence

Use the same fold in run_profile and from_json. First validate typed placement/key, returned-stage accounting, bounds and exact batch mirrors. Then derive the following independently of reason or terminal summaries:

| Fixture category | Case execution field after this returned failure | Run scheduling/result contribution |
|---|---|---|
| unavailable, denied, io, other | blocked | Close/retire this case; required assertions lacking expected evidence are NotJudged and the case is Incomplete. Continue the next independent invocation if no separate stop occurred |
| cancelled | blocked | Set the existing sticky cancellation stop and derived runner.cancelled reason; skip all later normal-work calls, retain retirement, contribute Incomplete |
| timed_out | blocked | Set the existing sticky deadline/timeout stop and derived runner.deadline reason; skip all later normal-work calls, retain retirement, contribute Incomplete |
| invalid_protocol | harness_error | Set the existing sticky protocol stop and contribute Invalid; retain the failure/effects and applicable retirement/partial report |

TimedOut is an explicit provider-reported timeout, so it can stop work even when all checkpoint times are below D; it does **not** assert the runner clock reached D or that a syscall was interrupted. Similarly Cancelled can be explicit even when surrounding flag samples are false. Compute checkpoint predicates from their raw samples separately, then OR these typed stop facts into the existing sticky run latch. Preserve both cancellation and deadline reasons when both occur. The slot/category identifies the source; no extra stop-summary field is authoritative.

A valid returned fixture failure precludes completed/not_run/skipped for that invocation; its terminal execution must agree with the derived blocked/harness_error value. A separate invalid protocol discovered in the received records has higher precedence and uses the existing harness_error/partial path. The case diagnostic reason is still nullable inert diagnostic data and need not repeat the typed category. Null/empty/contradictory prose cannot change scheduling or qualification; changing only reason bytes must not change those computed results.

No judge call follows a fixture failure. Its oracle_verdict is null (no invented oracle response); effective_checks contains every frozen required assertion as NotJudged for missing expected evidence. Coverage cannot gain a population from a failed prepare/collect or read-progress counter; retain existing actually observed adapter progress and earlier evidence, while missing required independent ledger data remains missing. Capability is Unknown with no invented capability witness. In particular, fixture Denied cannot satisfy ExpectedRefusal(Permission), AssertionOnly, or any other operation assertion; errno cannot convert it into adapter Refused. Restoring a valid fixture and obtaining/judging a genuine adapter outcome is the valid twin.

Previously judged independent cases retain their effective Fail/Pass results. Fold Invalid > Failed > Incomplete > Qualified without masking a prior valid semantic Fail because a later fixture times out or cannot collect. A collect error preserves the current adapter outcome/progress but cannot itself create an oracle judgment of it. Any supplied effective checks, execution, terminal qualification or reasons contradicting this fold are rejected. Removing the typed failure while retaining only a stopping reason does not establish that stop; a resulting unsupported omission or incomplete returned-call accounting is InvalidProtocol. As elsewhere, a fully coherently forged replacement transcript is not authenticated by structural import.

## Bounds, compatibility and focused tests

At most one optional fixture error is retained per planned invocation: at most case_attempts (hard 4,096). Its diagnostic/progress/effects reuse existing limits and registration/uncertainty counts; no new RunLimits field or raised maximum. Reserve the mandatory nullable field/record overhead with the existing admitted case representation before effects, then charge payload growth before retaining it. Oversize/malformed provider responses use existing bounded invalid partial retention and unresolved custody, never dropped effects followed by qualification. Schema major remains 1; imports missing fixture_failure now reject rather than guess legacy semantics. Top-level fields, four metadata slots, 8*N+10 checkpoint bound, 2*N+2 cleanup slots, task IDs and H/UC/G inventory counts do not change.

| Focused test | Independent expectation / bad control / restored twin |
|---|---|
| `verdict::fixture_prepare_stop_roundtrip` | Separate prepare Cancelled and TimedOut cases with all actual flag samples false and times <D. Both import as Incomplete, with exact distinct typed category/derived runner reason, no execute/collect/judge, fixture retirement and later cases NotRun. Restore successful prepare plus real downstream evidence to permit completion |
| `verdict::fixture_collect_stop_preserves_outcome` | Separate collect Cancelled/TimedOut after actual Observed and non-stopping CaseError outcomes. Retain exact outcome, errno/diagnostic/progress and prepare/execute/collect effects; no judge. Include another prior independently judged semantic Fail: Failed survives both execution and import. Restored successful collect supplies independent expected bytes and allows judgment |
| `verdict::fixture_denial_is_not_refusal` | Local Unavailable/Denied/Io/Other fail this invocation incompletely but allow a later valid independent case to run. Same-errno fixture Denied cannot qualify an ExpectedRefusal case; its true adapter Permission refusal with successful fixture/twin is the valid control |
| `verdict::fixture_failure_closed_wire` | Independently authored literal receipts cover null and each legal category; required key/stage/errno/hex/progress round-trip. Mutate missing field, bad enum, admission/retire stage, key, returned-call prefix, successful expected evidence plus error, forged completed status, or a raw oracle verdict after failure: reject the specific inconsistency; restore only that field and accept |
| `verdict::fixture_failure_is_stop_evidence` | Remove typed failure while keeping reason/summary and prior_stop omissions; or retain typed stop while enter a later stage/case. Reject unsupported omission/entry/return accounting. Alter only diagnostic reason to contradictory prose: derived result unchanged. A typed InvalidProtocol with exact valid binding contributes Invalid |
| `verdict::fixture_error_after_gate_and_partial_tail` | Retain error before an after sample that also crosses D or sees cancellation, with both facts preserved. Returned error plus trailing not_recorded after in a partial receipt remains incomplete and keeps effects/retirement. No-return partial tail has null failure and cannot claim provider cancellation; full receipt lacking the required returned-call accounting rejects |
| `verdict::fixture_error_effect_mirror_once` | Nonempty fixture failure effects plus exact chronological mirrors register once; complete=false remains unresolved after known IDs retire. Mutate the mirror, duplicate a registration in another call, change owner/origin, drop earlier adapter effects, or use run retirement to erase identity: reject. Restored exact mirror and lawful transitions succeed |

Tests must assert literal expected state/reasons and independently authored raw fixtures, not only producer/parser round-trip agreement. Malformed UTF-8/JSON corpus bytes use .bytes/.bin with valid checked JSON metadata under the current delivery rule. No Cargo/product tests were run for this design-only amendment; these focused cases are required implementation acceptance work, not passing product claims.

## Related contract amendments

The [complete oracle response amendment](2026-10-18-scopebase-tt02-oracle-verdict.md) replaces the original flattened raw-check field with required nullable oracle_verdict. The [owned cancellation probe](2026-10-18-scopebase-tt02-cancellation.md) preserves safe polling while fixture resources remain borrowed. Private original supplements remain sealed; this canonical copy applies both rulings. Existing task IDs, limits, authority and qualified-profile state remain unchanged.
