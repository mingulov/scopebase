# TT02 complete oracle response amendment

Status: controller-ratified normative amendment to the [TT02 engine](2026-10-18-scopebase-tt02-engine.md). Original immutable Astra supplement SHA-256: `c63b83bcaa0f08320189be41814ecc426a7dd7ac335d9ec9df508922c4febc70`. This fixes the unreleased schema-major-1 contract in place, with no compatibility alias/default. No implementation acceptance or profile qualification follows.

## Ruling and rationale

Replace CaseResult.oracle_checks with **oracle_verdict: Option<AssertionVerdict>**, retaining the complete actual response from the one judge call. An optional response naturally distinguishes no returned verdict from a returned verdict whose harness is Invalid. A zero/one vector adds an unnecessary cardinality protocol; flattening checks loses the independent harness result and the original capability evidence.

Keep effective_checks and the nonnullable capability field as derived summaries. They never supply missing raw evidence. No second raw checks/harness/capability slot is added.

The complete CaseResult fields are now:

`key`, `script_sha256`, `tier`, `entered_stages`, `execution_checkpoints`, `execution`, `reason`, `outcome`, `fixture_failure`, `expected_evidence`, **`oracle_verdict`**, `effective_checks`, `capability`, `coverage`, `effect_batches`, `case_cleanup_call_ids`, `terminal`.

Expose `CaseResult::oracle_verdict(&self) -> Option<&AssertionVerdict>`. It is runner-created/read-only in ExecutedHere and strictly admitted in Imported. No setter or writable result fields. oracle_checks is no longer a wire field; its presence, even together with oracle_verdict, is rejected as unknown. References to raw oracle checks mean oracle_verdict.checks when a response exists.

## Exact response and placement

oracle_verdict is required and either null or an object with exactly `harness`, `checks`, `capability`, using the existing bounded AssertionVerdict/CapabilityEvidence records. Its harness wire form is exactly `{"kind":"valid"}` or `{"kind":"invalid","reason":"bounded diagnostic"}`. Invalid.reason is a required nonempty UTF-8 string under diagnostic_bytes; the reason text is diagnostic, while the invalid variant itself supplies the typed harness failure. A valid variant cannot carry reason. Unknown/duplicate fields or tags reject. checks retains the actual ordered `{id,status,reason}` entries; it is not overwritten with effective checks. capability retains the actual complete CapabilityEvidence. Existing bounded checked constructors and no-Deserialize-bypass rule remain.

| Judge state | oracle_verdict / checkpoints |
|---|---|
| Judge not entered | null; existing justified before omission or stopping sample, and after=not_entered |
| Judge returned | Non-null actual complete response; judge entered, permitted sampled before, sampled after in a full receipt |
| Entered but no returned response recorded in an unfinished partial tail | null, run_terminal=null and after=not_recorded; this proves no verdict, not a successful return or an invented error |
| Returned response retained before interruption of the after checkpoint | Non-null actual response, run_terminal=null and after=not_recorded under the existing unfinished-tail rule; preserve its available findings and missing-checkpoint incompleteness |

Judge entry still requires the complete prepare/execute/collect prefix, actual outcome, actual expected_evidence and no fixture_failure or prior stop. A present verdict without judge entry, a full returned judge with null verdict, or a verdict after fixture failure is InvalidProtocol. A partial receipt cannot use not_recorded between later normal-work evidence. Store a returned verdict before the required after poll, including harness Invalid; a late stop cannot discard it. There is no new return timestamp, effect batch or callback.

The fixture-failure amendment's sentence requiring an empty raw oracle_checks list is superseded by **oracle_verdict=null**. Its requirement of no judge and all required effective checks NotJudged is unchanged. The same applies to every other legitimately unjudged case, including UNIMPLEMENTED selections.

## Exact fold and capability summary

First validate structure, judge placement, external contract binding and the returned assertion set. Every admitted returned AssertionVerdict must have the original nonempty unique check list, and its ID set must exactly equal the frozen required assertion set. Preserve actual order in the raw response; compute effective checks in the frozen assertion-list order. A returned nonempty subset, extra ID, duplicate, empty list or unsupported status is a protocol violation, **not** a valid oracle response silently padded with NotJudged. The no-response case is different: synthesize only derived effective NotJudged entries, never a raw verdict.

For structurally valid and contract-matching records:

1. If oracle_verdict is null, every effective check is NotJudged with reason `oracle.not_returned`. capability is exactly the unjudged sentinel below. Missing judgment contributes Incomplete; other valid evidence keeps its usual precedence.
2. If harness is Invalid, retain its raw checks/capability/reason unchanged. Every effective check is NotJudged with reason `oracle.harness_invalid`; capability is the unjudged sentinel. This typed harness failure contributes Invalid and the derived run reason `oracle.harness_invalid`, and closes normal work under the existing invalid-harness/protocol stop rule. The execution field is harness_error. The required after sample and retirement still occur; later normal-work omissions use prior_stop. A complete coherent receipt may represent this Invalid result, and import reconstructs it from the raw variant.
3. If harness is Valid and the response matches the contract, apply the existing per-assertion coverage/twin/progress gating to its checks. Keep independently judgeable Fail even when another check is gated. capability is an exact copy of oracle_verdict.capability, including method/context/evidence IDs. Missing coverage does not invent a different raw capability; the existing intent/cause/twin/coverage matrix determines whether that capability can qualify the claim.

The unique derived unjudged sentinel is:

```json
{"state":"unknown","method":"runner.unjudged","context":"","evidence_ids":[]}
```

It asserts no witness. It is used when no valid, contract-matching oracle judgment is available, including a retained protocol-invalid response in the runner's error/partial path. The raw oracle capability, when returned, is preserved only inside oracle_verdict; it is never replaced by the sentinel there. The sentinel is an ordinary existing CapabilityEvidence value, not a new capability enum or authority token.

from_json recomputes effective_checks and capability by these rules and compares the submitted summaries exactly. Terminal qualification/reasons and case reason cannot supply an omitted harness result. A harness Invalid with submitted Pass/Supported summaries is contradictory and rejected. A matching Invalid receipt remains Invalid even when all raw checks say Pass; restoring the raw harness to Valid and the corresponding legitimately derived summaries is the positive twin. Changing only diagnostic prose cannot change the typed result.

Fold Invalid > Failed > Incomplete > Qualified as before. Retain earlier independently valid semantic failures; a later Invalid dominates the final qualification without erasing those earlier records. A missing judgment or partial checkpoint never turns a prior valid Fail into Incomplete. The importer checks the protocol and prerequisites; it does not rerun arbitrary external oracle code, authenticate raw judgments, infer causal capability from errno, or grant runtime authority.

## Malformed responses and honest partial evidence

A returned harness Invalid is a validly encoded response describing an invalid harness. A structurally malformed or contract-mismatched response is a different protocol error. Checked constructors already prevent malformed empty/duplicate/oversized admitted values within their supplied limits; the runner still checks its own frozen limits and exact required IDs. An oracle may construct a bounded response for a different assertion set, which the runner must reject without replacing it with invented results.

On such a post-entry protocol error, preserve the actual bounded available response in the error/partial evidence, apply the existing invalid/retirement rules, and do not claim a conforming complete report. No new generic raw-payload escape or unbounded salvage buffer is introduced. from_json rejects malformed/binding-inconsistent oracle records with InvalidProtocol (or the existing syntax/limit error as applicable), including inside a partial receipt; partial mode does not relax those rules. Missing checks in a claimed returned response cannot be rehabilitated by a partial terminal. A hook that never returns/panics supplies no completed verdict and has the existing no-guaranteed-report limitation.

## Focused controls and handoff

| Control | Independent expectation and restored twin |
|---|---|
| `verdict::oracle_harness_invalid_is_retained` | Complete returned Invalid plus raw all-Pass checks survives serialization as Invalid; independent literal parser fixture verifies the harness variant is the cause. Dropping it, claiming Qualified, or submitting copied raw capability as an effective Supported summary rejects. Restore actual Valid response and corresponding derived values to qualify at the harness tier |
| `verdict::oracle_nonentry_is_distinct_from_return` | Fixture failure and UNIMPLEMENTED cases carry null with exact unjudged sentinel/all NotJudged. A genuine returned Valid response with all raw NotJudged is non-null and remains distinguishable. Null after a full returned judge, a response without judge entry, and a response after fixture failure reject; restored shapes pass |
| `verdict::oracle_partial_return_is_preserved` | Returned response before trailing unrecorded after checkpoint is retained; missing checkpoint stays incomplete unless Invalid/Failed wins. No-return partial tail has null. Neither may fabricate a returned success or bypass tail/cleanup rules |
| `verdict::oracle_response_set_and_summary_controls` | Fixed required two-assertion case: missing/extra/duplicate check IDs and unknown fields/status reject. Valid raw independent Fail plus a different coverage-gated check preserves Failed. Alter only effective check or capability summary, old oracle_checks alias, or raw harness diagnostic prose: inconsistent summaries/alias reject, diagnostic-only change leaves derived result unchanged. Restored exact response/summary succeeds |

Replace one case field, so the 17-field CaseResult count is unchanged from the fixture amendment. At most one bounded oracle response exists per invocation. Existing assertion/diagnostic/retained/receipt limits include the complete response and any owned derived copies; reserve required optional-slot overhead before effects. No checkpoint, cleanup slot, limit maximum, dependency, task ID, H/UC/G count or schema major changes. Update only the exact case field/getter, oracle response/fold prose and the superseded fixture-amendment sentence; preserve all other ratified behavior. These four controls are implementation acceptance requirements, not tests run by this design task. No Cargo, product/canonical edits or broad architecture work occurred.
