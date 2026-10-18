# TT02 typed adapter dialect rejection amendment

Status: controller-ratified normative amendment to the [TT02 engine](2026-10-18-scopebase-tt02-engine.md), 2026-10-18. Original independent Astra ruling SHA-256: `0fc84db5ab225bfb58ac6fdfcd7046f00cc7efef7bb6b3da3d75907b870b31f7`. This amends unreleased schema major 1; no task acceptance or qualification follows.

## WHAT / WHY

Add exactly one category, `CaseErrorCategory::UnsupportedSchema`, serialized as `unsupported_schema`. Keep `ConformanceAdapter::execute -> Result<Observation, CaseError>` and both `CaseOutcome` variants unchanged. The category means **adapter dialect preflight rejected the script before any operation step was attempted**. It is distinct from `HarnessErrorKind::UnsupportedSchema`, which rejects an unsupported structural envelope during admission, and from `InvalidOutput`, which can describe malformed operation data under a supported dialect.

The existing `InvalidOutput` plus `stage="unsupported-schema"` proposal loses this distinction unless every consumer interprets an otherwise diagnostic string. It also contradicts the canonical typed UnsupportedSchema promise. `Refused` plus cause UnsupportedOperation is worse: it fabricates an attempted operation and can enter the qualifying expected-refusal matrix. A new category is the smallest representation change that preserves the promise without expanding the public adapter method or adding another result channel.

Shipped adapters preflight the **entire bounded script**, including all steps, before their first input-slot/resource access. This chooses a precise meaning for “before reading operation data.” Prior vector byte measurement/admission and fixture preparation are allowed; this requirement governs the adapter's consumption of operation data, not earlier fixture I/O.

The rejection uses `step_id=None`, `completed_steps=[]`, and `partial_observation=None`. An offending second step is a diagnostic location, not the next attempted operation. Putting its ID in `step_id` either violates the existing exact-prefix rule or grants a trigger for work that never ran. The rejection can name that ID inside bounded diagnostic bytes; no extra field is necessary.

## Exact API, representation and invariants

The enum is now:

```rust
pub enum CaseErrorCategory {
    Unavailable,
    Refused,
    InvalidOutput,
    UnsupportedSchema,
    Cancelled,
    TimedOut,
    Io,
    Other,
}
```

Only the new variant/wire name is added. No public method, capability variant, KnownRefusalCause, RefusalCause, ExecutionState, CaseOutcome variant, or receipt field is added. `UnsupportedOperation` retains its operation-under-test meaning.

For every `CaseError` whose category is UnsupportedSchema, the intrinsic checked-value invariants are:

| Field | Required value / meaning |
|---|---|
| `key` | Actual invocation key, checked against the scheduled invocation as today |
| `step_id` | `None` / required wire `null`; no operation was attempted |
| `completed_steps` | Empty |
| `partial_observation` | `None` / required wire `null` |
| `errno` | `None` / required wire `null`; this is local vocabulary admission, not an OS rejection |
| `cause.cause` | `RefusalCause::Unknown`; no operation cause was established |
| `stage` | Bounded diagnostic Label; shipped adapters use `adapter-schema`. No execution, cause, progress, or qualification branch may be selected by this string |
| `diagnostic_bytes` | Bounded inert explanation; may name schema/opcode/offending step. No magic diagnostic parsing |
| `cause.method/evidence_ids/tier` | Shipped adapters use `adapter-dialect`, `[]`, T0. These describe local validation, not independent operation evidence |
| `effects` | Preserve the actual response batch. Shipped pure preflight produces empty/complete. Do not globally reject or erase a custom adapter's reported effects/uncertainty merely because it rejected its dialect; adapter entry and existing fixture participation still require retirement |

Enforce the intrinsic invariants in `CaseError::new`/shared bounds validation; invalid values return the existing `HarnessErrorKind::InvalidInput` construction error. Report decoding uses the same checked constructor. `validate_outcome` retains exact key and context checks, including the new category's no-step/no-prefix rule; a post-entry inconsistency is the existing InvalidProtocol path with retained bounded evidence and retirement. No partial/import exception rehabilitates inconsistent progress.

A supported dialect with missing/malformed operation data returns structured `InvalidOutput`, cause Unknown, actual attempted next step, actual completed prefix and applicable prior partial observation. The arithmetic overflow case remains `Refused`, cause Unknown, suitable only for AssertionOnly. Unsupported model transcript version/kind/field/enum is malformed operation data after dialect admission, not an adapter dialect preflight result. It must not panic or manufacture UnsupportedSchema.

The model input's `error.category` vocabulary stays the original seven operation categories: `unavailable`, `refused`, `invalid_output`, `cancelled`, `timed_out`, `io`, `other`. The new `unsupported_schema` category is reserved for the adapter's own pre-read preflight and cannot be replayed from operation input. Replace the canonical transcript's broad `CaseErrorCategory` reference with this explicit subset; no new public enum is needed. The expected transcript uses the same subset. This prevents a consumed input transcript from claiming that no input was consumed. Existing operation categories retain their existing semantics and stopping rules.

## Runner, oracle, progress and qualification

1. Structural `OperationScript` major/kind/scalar-kind rejection remains admission `HarnessErrorKind::UnsupportedSchema`; malformed fields/bounds use the existing admission errors. Unknown but structurally valid `schema_id`/operation labels pass generic envelope admission. A custom adapter may support them; the engine does not gain a dialect interpreter.
2. A well-formed returned UnsupportedSchema is a non-stopping case-local execute result, transported as `CaseOutcome::OperationError`. That variant is the execute-error channel; it alone is not evidence of an attempted script operation. Preserve the actual returned record before the after checkpoint, admit its effect batch once, and follow existing collect/judge and retirement rules. Later independent invocations continue unless an independent cancellation/deadline/protocol stop occurs.
3. No new ExecutionState is needed. A case whose collect/judge completed can have `execution=completed`, as existing operation-error cases do; this describes completed case evaluation, not completed script steps. Collect failure still leaves the existing blocked row, retained outcome, null verdict and unjudged summary. Do not mislabel an entered execute as NotRun or skip its retirement.
4. Existing coverage rules now yield zero effective Trigger, ActiveExcluded and Positive populations for UnsupportedSchema because both attempted-step and completed-prefix evidence are absent. Raw authored ledger counts are retained, even if positive. Setup may retain its independently supported value after successful preparation; it cannot supply operation activity. Receipt import must recompute these same values.
5. Shipped arithmetic/model oracles return capability Unknown for UnsupportedSchema and NotJudged for assertions about the unattempted operation/result/cause. They must not infer capability Supported, Unsupported, Denied or Incompatible from schema rejection, stage text, or errno. Independent assertions about separately available input evidence keep their legitimate Pass/Fail. In the model oracle, compare the actual typed error category whenever judging an operation error; the existing literal `want["category"] == "refused"` without checking `err.category()` is not sufficient.
6. A PositiveSupport or ExpectedRefusal claim cannot qualify on UnsupportedSchema: no observed success, no Refused operation/cause, and no trigger. Missing activity yields Incomplete unless a separate valid semantic Fail or Invalid has higher precedence. Do not globally downgrade unrelated Fail.
7. An explicitly frozen AssertionOnly test of **the adapter's preflight behavior itself** may judge the structured rejection and qualify that assertion claim with Unknown/NotApplicable, subject to all other gates. Its assertions must not declare an operation-trigger prerequisite that never happened. Such a test establishes no product operation support or refusal. Direct adapter acceptance tests can check this without manufacturing a qualifying production profile.
8. Preserve the complete raw `oracle_verdict` and existing derived-capability rule from the oracle amendment. Do not introduce a blanket summary rewrite that loses actual oracle responses. A custom erroneous Supported response remains raw submitted evidence and cannot qualify the positive/refusal claim under the existing outcome/coverage matrix; the shipped oracle itself must return Unknown. The engine does not authenticate custom code or arbitrary ungated assertions.

## Receipt and schema edits

- Add `unsupported_schema` to `profiles/result-schema-v1.json` `$defs.CaseErrorCategory.enum` and the Rust closed enum decoder/serializer. Unknown spelling/case remains invalid. Schema major 1 remains unreleased and is amended in place.
- Preserve `CaseOutcome={kind:"operation_error",error:...}` and the exact existing CaseError fields. Null fields remain required. `InvalidOutput` plus a magic stage is not an alias and is never normalized into UnsupportedSchema during import; it remains the actual old category if otherwise valid.
- Add a category-conditional CaseError schema constraint (or the schema's equivalent supported form) requiring `step_id:null`, `completed_steps:[]`, `partial_observation:null`, `errno:null`, and `cause.cause:"unknown"` for `unsupported_schema`. Implement the same intrinsic checks in Rust; a JSON-schema description is not the executable gate.
- Use one independently authored valid receipt row with the new category and raw nonzero ledger, plus literal contradictory controls. Verify raw category/stage/diagnostic/effect/oracle records survive import/serialization while progress gates derive zero operation coverage. A diagnostic-only/stage-only change must not alter typed classification. Imported origin remains Imported. As in the existing receipt contract, a coherent fabricated record is not authenticated by the parser; it must not become ExecutedHere or confer runtime authority.
- If collect fails or execution stops after returning UnsupportedSchema, retain it exactly with the already prescribed nullable expected/verdict/checkpoint forms. Do not synthesize a completed oracle response or erase a returned error to make the report fit.
- Add no schema alias, generic raw escape, checkpoint, cleanup slot, limit maximum, dependency, task ID, or H/UC/G family. Regenerate only existing source/artifact/corpus hash bindings affected by actual changed bytes.

## Focused acceptance and sensitive wrong controls

These eight groups are required acceptance checks, not results obtained by this design amendment. Use independent literal expectations and active controls that fail their named assertion, not only fixture setup. Parent selects affected package cells after actual changes.

| ID / owner | Deterministic case and expected result | Sensitive wrong control / restored twin |
|---|---|---|
| S1 adapter dialect rejection | For each shipped adapter, structurally valid scripts with unknown schema/opcode, zero/two inputs, one unexpected parameter; model also two steps. Each returns typed UnsupportedSchema with exact no-operation fields, Unknown cause, empty complete shipped effects, and zero input/resource accesses; no panic | Old InvalidOutput + unsupported-schema stage fails the category assertion; old model asserts fail a test that expects a returned CaseError. Restore valid dialect and independent valid data to execute |
| S2 all-step preflight | U64 two-step script with valid first operation and invalid second opcode/arity. Bind an input-access counter in the actual shared private fixture implementation. Expect zero slot/resource calls, no prefix and step_id=null even though the bad step is second | Move validation into execution loop: counter becomes positive or prefix grows; assert the exact zero-access/progress property. Do not make the control fail only because a poison input crashes setup |
| S3 admitted data versus dialect | Supported dialect with malformed decimal bytes and malformed model JSON/transcript; expect structured InvalidOutput/Unknown at the first attempted step. Include model transcript category unsupported_schema as malformed data. Actual overflow remains Refused/Unknown. Independent correct numeric/model twins succeed | Treat all parse failures as UnsupportedSchema, or accept transcript unsupported_schema, or panic on malformed data: intended category/attempted-step assertion fails |
| S4 progress and raw coverage | Returned preflight error with authored raw Setup/Trigger/Positive/ActiveExcluded counts all one. Keep raw counts; zero the latter three; keep legitimate Setup. PositiveSupport and ExpectedRefusal remain Incomplete and dependent checks NotJudged | Assign offending step to step_id, retain a fictitious completed prefix, or copy raw trigger count to effective: checked construction/import rejects or precise coverage assertion fails. Restore a real observed/attempted-operation twin and corresponding evidence |
| S5 oracle/category independence | UnsupportedSchema gives shipped oracle Unknown and unattempted-operation NotJudged. Separate available independent input assertion can still Fail. For a real model error, alter actual category while preserving stage/cause/errno/diagnostic and expected category | Stage/method/diagnostic-only changes do not change classification; hardcoded expected refused without comparing actual category fails. UnsupportedOperation/Permission cause cannot be substituted into UnsupportedSchema |
| S6 receipt strictness and preservation | Independently authored literal new-category receipt round-trips as Imported with exact raw error, oracle response, ledger and zero effective operation coverage. Required nullable fields remain present | Unknown category spelling, omitted null, nonnull step/partial/errno, nonempty prefix, known cause, forged effective activity/qualification, or a serializer/importer normalizing stage-only InvalidOutput into UnsupportedSchema fails the intended schema/progress/summary assertion |
| S7 lifecycle and partial returns | Preflight error followed by successful collect/judge retires entered owners and permits a later independent valid invocation. Collect failure or a stop after execute preserves the actual UnsupportedSchema outcome and effect mirror with existing null verdict/checkpoint semantics | Treat category as global stop, NotRun, no adapter participation, discard outcome on collect failure, or invent judge response: call-order/custody/raw-preservation assertion fails |
| S8 genuine operation refusal and assertion boundary | Existing typed Refused/UnsupportedOperation with independent witness, actual attempted step and functional twin remains distinct; the unknown dialect cannot stand in for it. An explicit AssertionOnly preflight assertion can pass with Unknown and no invented trigger, subject to ordinary binding/cleanup gates | Convert UnsupportedSchema to Refused/UnsupportedOperation, claim Supported, or satisfy an operation-trigger-dependent assertion using preflight rejection: exact intent/progress assertions fail. Also use an always-reject adapter against independently valid arithmetic/model positives so a vacuous rejector fails |

For S1/S2, a private fixture-local input accessor closure/counter is sufficient; both real `execute` and the tests must use the same preflight/operation body. No public FixtureAccess hook or generic interpreter is needed. Increment before returning a slice, so a premature access yields a deterministic count assertion; a callback that merely panics is a weaker oracle. Source inspection verifies no bypass access exists outside that body. Tests demonstrate adapter access ordering, not that prior fixture admission did no I/O or that custom dishonest adapters are sandboxed.

## Alternatives rejected

- Existing InvalidOutput plus stage string: small textual diff but untyped distinction, ambiguous data-versus-dialect category, and hidden stage-based semantics.
- Existing Refused/UnsupportedOperation: confuses an adapter vocabulary limit with a witnessed operation result; can fabricate expected-refusal capability.
- HarnessError from execute or a new public execute-error sum type: unnecessary signature/outcome/receipt churn; the existing structured CaseError already carries key, progress, diagnostics and effects.
- Per-step syntax validation while executing: consumes earlier input before discovering later unsupported syntax, forces a preflight location into attempted-step progress, and does not satisfy the chosen whole-script pre-read guarantee.
- Reject all unknown schema IDs in RunContract: breaks the explicit custom-adapter contract and turns the engine into the dialect owner.
