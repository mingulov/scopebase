# TT02 cancellation borrow amendment

Status: controller-ratified normative amendment. It repairs the [TT02 engine contract](2026-10-18-scopebase-tt02-engine.md), whose pre-amendment SHA-256 was `971d76fac2d90fba7181281c2e9e19c87abcb6e2eb75e46fe35dec8fe580ec23`. Original Astra amendment SHA-256: `f276eb47bad0b761712f3857b2f905fa382d14b4512ed98f0ce2f21dcf7c7a05`. Prior private packets remain unchanged. This decision does not promote implementation or qualification status.

## What and why

The current FixtureSession::prepare(&mut self)->FixtureAccess<'_> deliberately retains the mutable session borrow while adapter.execute uses the borrowed resource view. Calling fixtures.cancellation_requested(&self) at after_prepare or before_execute conflicts with that live borrow; the same conflict applies to after_execute if the access is still live. Removing checkpoints, copying fixture bytes, ending resource custody early, or unsafe aliasing would change the contract rather than repair it.

Separate the cancellation observer from the session borrow. The runner owns one independently owned 'static probe, acquired before prepare. It polls that probe throughout the run. The actual FixtureAccess borrow and all existing checkpoint slots remain intact.

## Exact API amendment

```rust
pub trait CancellationProbe {
    fn cancellation_requested(&self) -> bool;
}

pub trait FixtureSession {
    fn contract(&self) -> &RunContract;
    fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static>;
    fn prepare(&mut self, invocation: &CaseInvocation)
        -> Result<FixtureAccess<'_>, FixtureError>;
    fn collect(&mut self, invocation: &CaseInvocation)
        -> Result<ExpectedEvidence, FixtureError>;
    fn retire(&mut self, request: &RetireRequest) -> RetirementReport;
}
```

Remove cancellation_requested from FixtureSession; it belongs only to CancellationProbe. run_profile's signature, prepare's borrowed lifetime and the adapter/oracle seams do not change. The return type is explicitly 'static, **not** `Box<dyn CancellationProbe + '_>` and not a borrowed trait object. It may own an Arc/Rc to cancellation state; it cannot capture a reference tied to the current fixture borrow. The session itself need not be 'static. No Send/Sync requirement is added to this sequential engine, and no default always-false implementation is supplied.

Acquisition is a custom **no-effects metadata hook**, despite its &mut receiver. It may seal local cancellation configuration and construct the owned observer. It must not discover an environment, open native resources, launch a task/thread, acquire fixture effects, or change requirements/truth. Probe polling and disposal have the same no-effects obligation; the observer carries no fixture/process/file/BPF cleanup authority. These are behavioral requirements, not a sandbox: safe Rust enforces the returned lifetime, not truthful custom code or absence of hidden interior-mutability effects.

## Exact prelude and call order

1. Start the existing monotonic entry clock before contract(). Call contract once, record contract_returned_elapsed_ns immediately after return, snapshot/validate the independently chosen contract and external plan, and reserve the existing mandatory records. End the borrow of the session's contract reference before acquiring the probe. Invalid prelude admission may retain the existing before-effects Err/partial_report=None behavior.
2. Derive the unchanged checked deadline D from the frozen limits. Read the same entry-relative monotonic clock immediately before probe acquisition. If already >=D, **do not acquire** a probe. Proceed to after_contract as an expired sampled gate; cancelled=null and the two poll times equal the current elapsed value. Since the deadline is fixed and time is monotonic, all later required sampled gates are also expired and need no probe.
3. Otherwise call fixtures.cancellation_probe() exactly once and store its owned return before after_contract. Acquisition has no separate checkpoint: it is bootstrap metadata needed to perform the first cancellation poll. If it returns late, its full elapsed time lies between contract_returned_elapsed_ns and after_contract.poll_started_elapsed_ns. If that start is now >=D, after_contract records the deadline stop with cancelled=null and makes no probe poll. No deadline or clock is restarted. Scheduling delay/acquisition can cross D; this is cooperative checking, not guaranteed preemption.
4. If after_contract starts before D, sample the **owned probe** once and record its Boolean and the actual finished time using the existing checkpoint algorithm. Continue entry subject/oracle checks only if permitted. Use this exact same probe for every subsequent actual checkpoint poll, including all per-stage, final-metadata and completion samples. Never reacquire it per case, after a stop, or after retirement.
5. During prepare/execute, the runner may immutably poll the independent probe while FixtureAccess retains its mutable session borrow. Preserve after_prepare, before_execute and after_execute slots and their actual samples/justified omissions. Do not call any session method until the access borrow ends. Drop the borrowed access after the relevant checks and before collect or retirement; if a gate stops execution, preserve prepare effects, omit later normal-work calls under the existing rules, end access, then perform required retirement.

The receiver mutation used to freeze cancellation configuration does not make the fixture Participating. Participation still begins only at prepare/execute as already defined. A session that has an acquired probe but no effect-capable calls has NotRequired cleanup and receives no fabricated retire call.

A missing probe when an unexpired checkpoint requires polling is InvalidProtocol, never an implicit false result. The acquisition method is infallible in this minimal API; it does not invent an unavailable/false result on allocation failure, panic or non-return. Such failures may prevent a report exactly as other misbehaving metadata hooks can. An acquired probe stays available through completion even after session run retirement; retirement must not invalidate or rebind its cancellation source.

## VectorFixtureSession behavior

Keep the existing shared Arc<AtomicBool> source, initially a private false flag. Its probe is a private AtomicCancellationProbe holding Arc::clone of that **same allocation**. Its cancellation_requested uses load(Ordering::Acquire). The caller may request cancellation through the shared flag, normally using store(true, Ordering::Release). A later false value cannot clear the runner's existing sticky stop predicate.

Add a private cancellation-bound flag to VectorFixtureSession. The first cancellation_probe call seals the chosen source and returns a Box containing its Arc clone. Repeated direct caller acquisitions may return observers of that same sealed source; the runner itself acquires at most once. set_cancellation now returns FixtureError/InvalidProtocol once the source has been bound, or once prepare has been entered or the session is finished, whichever occurs first. Before these boundaries it replaces the source as before. This closes a stale-observer bug: rebinding after acquisition but before prepare must not silently disconnect the runner from the caller's intended flag.

Cloning the Arc shares an actual cancellation state cell; it does not snapshot a Boolean, clone a fixture resource view, or reconstruct live runtime authority from data. The vector probe owns only the shared flag and has no custom destructor. Future providers retain their actual native owners in the session/adapter, not in the probe.

## Wire, limits, cancellation and error preservation

No serialized field, enum, schema-major change, checkpoint slot or case/result count is added. after_contract now explicitly includes contract snapshot/validation **and possible probe acquisition** in its elapsed prelude. contract_returned_elapsed_ns keeps its original precise meaning. The wire does not claim to distinguish time spent cloning metadata from time spent acquiring the observer; the existing elapsed gate truthfully detects their combined deadline cost. Poll times still surround only the actual cancellation poll, not acquisition.

The existing after_contract/completion/per-stage sample rules, cancelled=null only for already-expired polls, both stop predicates, sticky latch, partial-tail rules, no-executable-member behavior and pure import fold are unchanged. For a nonempty all-UNIMPLEMENTED selection, acquire once if its prelude is not already expired, then take after_contract/completion samples through the probe; no prepare/execute/collect/judge/retire or entry/final subject/oracle call is introduced. Truly empty selection remains invalid.

There are at most one acquisition and the existing `8 * case_attempts + 10` checkpoint polls; an expired checkpoint does not poll. No new RunLimits axis, dependency, thread, raw pointer, signal handler or runtime service is needed. The builtin observer uses one constant-sized Box payload and one additional Arc reference. Account this ordinary metadata storage in existing engine-managed overhead; arbitrary custom probe allocation is outside the engine's control, just as other custom provider allocation is.

Completion remains the last explicit metadata **poll/call** before finalization. Ordinary destruction of the owned observer afterward must not poll, cancel, retire native effects or perform other externally visible work; it is metadata disposal, not a new runner gate. Custom destructor behavior is a trust boundary, not a guarantee of prompt return. There is no added hard time bound on acquisition, polling, disposal or arbitrary custom hooks. Qualification remains as of the recorded completion checkpoint, and no disposal result proves native cleanup.

## Required focused tests and controls

| Test | Valid behavior / independent control |
|---|---|
| `harness_controls::owned_probe_during_fixture_borrow` | A non-Clone typed resource is borrowed from the session through execute and all three checkpoints. The owned probe permits safe compilation and subsequent collect/retire after access ends. The original session-poll seam must fail E0502; a probe returning a captured session reference must fail the 'static return lifetime. No unsafe code or fake copied resource |
| `harness_controls::shared_probe_cancellation_and_sealing` | Independently set the caller flag in prepare and execute; their respective after checkpoints see true, preserve received effects/outcomes, skip subsequent normal work and retain retirement. Resetting the flag afterward does not clear the stop. Restored false-flag case runs normally; rebinding after acquisition but before prepare is InvalidProtocol |
| `harness_controls::probe_acquired_once_before_effects` | A recorded call counter/order witnesses contract/snapshot then one probe acquisition then after_contract/entry metadata, before any prepare. Same observer survives all attempts and run retirement. No reacquisition or per-case always-false replacement can satisfy the count/shared-flag control |
| `verdict::probe_acquisition_time_is_in_after_contract` | Private deterministic clock: prelude already expired means zero acquisition/poll; acquisition begun before D but returning after D means one acquisition, zero after_contract poll, cancelled=null and Incomplete. An in-budget acquisition with true flag records cancellation; a slow returning poll records its finished time/deadline. Round-trip derives identical gates; no fabricated timeout interruption |
| `verdict::probe_keeps_checkpoint_receipts` | Literal checks retain after_prepare/before_execute/after_execute and completion records, including late cancellation, deadline, omitted prior_stop slots and sticky false-after-true behavior. Deleting a required sample, null-as-false, stale copied flag, or a contradicted summary fails the intended assertion; restored receipt succeeds |
| `harness_controls::probe_no_effect_prelude_paths` | Nonempty all-UNIMPLEMENTED remains Incomplete/NotRun with only permitted metadata operations; invalid prelude may return no report before effects. Probe acquisition creates no cleanup resource ID or Participating owner; dropping the probe cannot retire the fixture's effects |

## Local proof and handoff

A standalone private proof used the already installed absolute Rust 1.88.0 compiler, without Cargo or dependency access. The old seam fails E0502; a borrowed 'static probe is rejected; the owned-probe program compiles and runs. Its assertions cover a live non-Clone resource borrow through the three polls, shared-flag visibility, sticky stop, pre-prepare rebinding refusal, cancellation suppressing collect, retirement after access ends, and a restored uncancelled path. This is a borrow/local-state proof, **not** execution of the product runner, receipt parser or full required matrix.

Proof directory: `cancellation-borrow-proof-20261018/`. Result record SHA-256: 0eb6098bf5bd81fe5a91f54f0e6ef7d7166149d06d3c8dcd379513d0d9e0180d. No Cargo, broad suite, donor/source reread outside the specified canonical input, subagent, canonical edit or product implementation occurred.

Root ratified this exact seam and updated the canonical public seam, vector setter rule, prelude and sampling prose. Existing packet IDs and all wire records remain unchanged; the six named controls above are added to the required TT02 tests. The separately reported fixture-error receipt gap is handled in its own amendment; it does not delay this ownership correction.
