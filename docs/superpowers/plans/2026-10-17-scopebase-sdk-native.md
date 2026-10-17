# ScopeBase SDK and selective native interoperability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a thin ScopeBase application SDK with real host/live reference applications, then useful installed C/Mojo interoperability through shared vectors, the existing native bridge and a narrow capture-validation ABI.

**Architecture:** Compose independently delivered Rust components without a universal application driver. Preserve libbpf-mojo as native BPF transport owner and use standard ELF/BTF for MojoBPF. A separate stateless `scopebase-ffi` adapter delegates capture semantics to `scopebase-capture` and serves actual C and Mojo validator applications.

**Tech Stack:** Rust edition 2021, proposed MSRV 1.88.0 requiring qualification; `scopebase-capture` default standard library with optional `json`; optional Linux/Aya adapters; C99/CMake; selected Mojo compiler and existing libbpf-mojo; existing compiler/object tooling.

**Spec:** [SDK and native specification](../specs/2026-10-17-scopebase-sdk-native-design.md). Also read the component and testing specifications linked there. Every command below is a future implementation/verification command; no SDK/Cargo/native suite exists or was run by writing this plan.

## Global Constraints

- ScopeBase branding; proposed `scopebase-sdk` and selectively justified `scopebase-ffi` package names are not published/reserved.
- Rust edition 2021; proposed MSRV 1.88.0, requiring actual qualification.
- Initial package version 0.1.0 and target x86_64-unknown-linux-gnu; original-source license policy follows SB01 review.
- Rust default builds never require BPF/C/Mojo runtime setup, privilege changes or compiler installation.
- `scopebase-capture` defaults to pure standard library; JSON is an explicit optional feature.
- Use `scopebase_linux::file::HeldFile`, retained with owned `Arc`, and `AsFd`; no second SDK file capability.
- Bind tests to the actual consumer-resolved production version/features/backend/artifacts; testkit cannot certify its own separately resolved copy instead.
- No SDK universal live/batch, close/drain, shutdown, process tracker or BPF loader implementation.
- Complete SDK delivery requires the host example and selected actual live example; host-only is an earlier named submilestone.
- Reuse the existing libbpf-mojo bridge and standard ELF/BTF; no new native BPF bridge or implicit donor upgrade.
- C ABI initial support is x86-64 Linux LP64 little-endian; wire/schema/ABI/profile versions remain independent.
- Independent truth, active positive/negative populations, semantic mutant failures and cleanup are mandatory for advertised claims.
- Product migrations and duplicate retirement remain later MG work; no donor edits, external submissions or publications follow from this plan.

## Review Focus

- Activity begins during partial attachment: preserve the partial window instead of inventing atomic application startup; SDK06 tests immediate first-site activity.
- Output fails after useful observation: preserve measured facts and cleanup ownership separately; SDK04 tests a failing output sink after replacement acknowledgement.
- Unknown or query-partial evidence reaches presentation: retain unknown units and local partial reasons; SDK03 and NX07 test against fabricated completeness/zero mutants.
- Foreign loader lifetime ends during close failure: retain parent/library until children and actual disposal finish; NX06 tests `EBUSY` and poisoned cleanup with live descendants.
- Callers supply overlapping buffers or version prefixes shorter than normal: refuse before output writes or out-of-bounds access; NX07/NX08 add alias, unaligned and guard-page controls.

---

## File map, interfaces and ownership

| Owner lane | Files/directories it may write | Main responsibility |
|---|---|---|
| SDK | `crates/scopebase-sdk/`, `apps/scopebase-file-observer/`, `apps/scopebase-workload-observer-bpf/`, `templates/scopebase-observer/`, `tools/reference/` | Composition, real applications and onboarding. |
| Native corpus/audit | `interop/vectors/`, `interop/libbpf-mojo-conformance/`, `docs/interop/` | Neutral independent truth, selected bridge audit and contributions. |
| ABI | `crates/scopebase-ffi/`, `interop/include/`, `interop/abi/`, `interop/pkgconfig/`, `interop/clients/` | Thin canonical capture boundary and independent clients. |
| Integration owner | root Cargo/config/lock files, common profile/catalog/CI/release files | Serialized workspace additions, exact dependencies, support profiles and release gates. |

Task-local tests live with their owner files; shared testkit remains TT ownership. Cargo-heavy work and all writes to shared lock/config/profile files are serialized. Each worker uses a distinct target/evidence directory. Live filesystem/BPF/guest resources require one named lease owner and an isolated fixture root; never run live probes solely to make documentation look verified. Native contribution patches are prepared in this repository; donor application and publication require a separately authorized implementation task.

SDK depends on SB01 provenance/contracts, SB02 workspace/dependency policy, SB03 compatibility/docs; selected Linux/capture/BPF packages and TT conformance. BPF API seam is `AttachPlan::checked(Vec<Site>, AttachMode, &Limits) -> Result<AttachPlan, OperationError>` followed by `execute_plan<B: AttachBackend,P: ErrorPolicy>(pool:&mut RetirementPool<B>, backend:B, authority:B::Authority, plan:AttachPlan, policy:&mut P, limits:&Limits) -> AttachOutcome<B>`. Use `AyaBackend::from_loaded(program: aya::programs::UProbe, domain: ProducerDomain) -> Result<AyaBackend, ProgramAdoptError<aya::programs::UProbe>>` after the existing loader admits the final object. Built-in authority is `Arc<HeldFile>`; the caller-owned pool owns actual backend/program/file/link effects and returned active/unresolved values are move-only pool-domain custody tickets. Enable the BPF package's `aya` feature only; optional features are `btf`, `aya`, `libbpf`, `producer-fixtures`, with empty default.

The conformance adapter is the shared TT interface, not a new SDK testing abstraction:

```rust
trait ConformanceAdapter {
    fn subject(&self) -> SubjectBinding;
    fn execute(&mut self, invocation: &CaseInvocation, fixture: &FixtureAccess)
        -> Result<Observation, CaseError>;
}
```

`SubjectBinding` includes package coordinate, compiled build digest, feature set and backend. Invocation is a versioned bounded script; Observation is schema-tagged bounded bytes. An independent case oracle owns expected results. `run_profile` preselects required cases before environment discovery and reports assertion/capability/coverage/harness/cleanup separately. Production crates never depend on testkit.

## SDK work packages

### SDK01: Explicit profile, capability and effects admission

**Dependencies:** SB01–SB03; stable component profile vocabulary. **Requirements:** SDK-R01/R02/R12. **Files:** create `crates/scopebase-sdk/{Cargo.toml,README.md,src/lib.rs,src/profile.rs,tests/profile.rs}`; integration owner adds workspace/lock entries.

**Interfaces:** produce `Profile::new(&'static str, Vec<CapabilityRequirement>, Vec<Effect>) -> Result<Profile,ProfileError>`, `CapabilityState`, `CapabilityObservation` and `Admission` exactly as specified. These contain report metadata, no executable authority. Default dependency is capture; `linux` and `bpf` are additive opt-ins.

- [ ] Write `profile_rejects_duplicates_and_oversize`, `required_unknown_is_incomplete`, `required_denied_is_refused` and `optional_denied_stays_visible`: assert 64/65 requirement boundary, duplicate IDs/effects, all five states, missing required positive and optional failure retention.
- [ ] Run `cargo test -p scopebase-sdk --no-default-features --test profile`; verify the new assertions fail because the required API/behavior is absent, without treating setup/build failure as a semantic mutant result.
- [ ] Implement the specified constructors, validation and admission table; cap profile identifiers at 64 bytes and prohibit empty IDs. Do not probe environments from constructors.
- [ ] Run the profile test and `cargo tree -p scopebase-sdk --no-default-features`; require passing semantics and no BPF/native/Mojo build dependency. Add the no-authority compile-fail example to README doctests and run `cargo test -p scopebase-sdk --doc`.
- [ ] Review diff/provenance and commit only this task's files plus serialized workspace changes: `feat(sdk): add explicit profile and effects admission`.

### SDK02: Bounded context, diagnostics and component bindings

**Dependencies:** SDK01. **Requirements:** SDK-R03/R05/R10. **Files:** create `src/{limits,context,diagnostic}.rs` and `tests/{limits,context,diagnostic,isolated_contexts}.rs` under the SDK crate.

**Interfaces:** produce `Limits::validate()`, `AppContext::{new,observe,bind,admission,diagnostic}`, `ComponentBinding`, `Diagnostic`, `DiagnosticDisposition` per spec. AppContext is inert and bounded; actual component owners remain outside it.

- [ ] Write `limits_zero_overflow_and_independent_units`, `diagnostic_cap_precedes_copy`, `weird_path_escapes_without_payload`, `binding_is_actual_component`, `duplicate_observation_cannot_replace_failure`, and `contexts_do_not_share_state`. Assert cap 4,096 per diagnostic/65,536 host aggregate, 64 observations/eight bindings, saturating omitted count and untouched external owners on context drop.
- [ ] Run `cargo test -p scopebase-sdk --test limits --test context --test diagnostic --test isolated_contexts`; confirm intended failures, then implement the exact limits/metadata operations without hidden I/O, callbacks, logging or threads.
- [ ] Add component-binding length checks and copy-before-allocation bounds; context result must retain required denials and report incomplete on missing exact artifact binding.
- [ ] Re-run the focused tests and a two-thread test with disjoint contexts; assert independent counters/epochs/diagnostics and no installed signal handler or process limit changes. Trait tests check supported Send/Sync behavior rather than inferring it from Arc use.
- [ ] Commit the bounded context/diagnostics deliverable: `feat(sdk): bound diagnostics and application context metadata`.

### SDK03: Capture metadata integration and consumer-linked conformance

**Dependencies:** SDK02; CP10 neutral validation/accessors; TT01/TT02/TT06. **Requirements:** SDK-R04/R07/R08. **Files:** modify SDK `src/context.rs`; create `tests/{capture_metadata,conformance_binding}.rs` and `tests/adapters/consumer.rs`.

**Interfaces:** consume `neutral::validate_v1(&NeutralObservationV1,NeutralLimits)->Result<ValidatedNeutralV1,ContractError>`; produce `AppContext::capture(&ValidatedNeutralV1)->Result<(),ContextError>`. Consume TT adapter/observation types above. Capture limits 4,096 counters/claims and 16 reasons per claim remain hard maxima.

- [ ] Write `unknown_stays_unknown`, `query_partial_does_not_become_consumed_loss`, `distinct_epochs_remain_distinct_contexts`, `snapshot_cannot_mint_closure`, `snapshot_retained_n_and_n_plus_one`, `binding_and_snapshot_share_payload_allowance`, `second_capture_snapshot_refused`, and `wrong_production_build_digest_rejected` against independently authored fixture inputs. A coherent different epoch is valid standalone metadata; only an attempted incompatible combination is refused by the owning capture operation.
- [ ] Run `cargo test -p scopebase-sdk --test capture_metadata --test conformance_binding`; establish failing behavior before adding the metadata adapter and TT consumer adapter.
- [ ] Implement bounded immutable copying with source/units/reasons unchanged. Instantiate actual consumer-side production adapter in this integration test; expected data stays in the independent case oracle.
- [ ] Run the tests against unknown-as-zero, partial-as-complete and wrong-artifact targeted mutants. Require intended assertions to fail after valid setup, then restore the valid implementation and pass the same cases. No serialized report gains a runtime owner/closure constructor.
- [ ] Commit: `feat(sdk): integrate capture summaries without upgrading evidence`.

### SDK04: Independently useful owned-workload host observer

**Dependencies:** SDK03; LX02/LX03 held-file/read support and LX04 operation control; TT03/TT06. **Requirements:** SDK-R06/R07/R10. **Files:** create `apps/scopebase-file-observer/{Cargo.toml,README.md,src/main.rs,src/fixture.rs,src/observe.rs,src/report.rs,tests/owned_workload.rs,tests/output_failure.rs}`.

**Interfaces:** produce installed binary `scopebase-file-observer observe --fixture-root DIR --operations 16 --output report.json`; consume Arc<HeldFile>/AsFd, bounded positional reads, SDK context and capture semantics. Fixture controller owns expected A/B byte patterns and operation ledger, not production read output.

- [ ] Write `held_a_survives_path_b_replacement`, `positive_and_active_negative_execute`, `denied_effect_precedes_fixture_write`, `zero_activity_is_incomplete`, `output_error_preserves_facts_and_cleanup`, and `foreign_entry_is_never_deleted` with explicit same-process channel barriers and spec defaults 16 operations/4,096-byte patterns/65,536 input bytes/8,192 retained bytes/eight owners/two-second cooperative waits. A denied profile effect must produce no attempted write/spawn/BPF operation in an independent effect audit.
- [ ] Run `cargo test -p scopebase-file-observer --test owned_workload --test output_failure`; implement only owned fixture creation, replacement, independent raw verification, production observation and bounded reporting necessary to pass.
- [ ] Run path-reopen and fabricated-complete mutants through the same fixture; require byte mismatch and receipt-strength assertions to fail, respectively. Record operation IDs and setup acknowledgement so missing activity cannot become a passing negative.
- [ ] Create the explicitly caller-owned scratch parent with `mkdir -p target/sdk04-fixtures`, then run `cargo run -p scopebase-file-observer -- observe --fixture-root target/sdk04-fixtures --operations 16 --output target/sdk04-report.json` and focused tests. Require A/B nonempty populations, exact operation counts, effects/limits, distinct assertion/capability/cleanup fields and no unresolved owner for the ordinary control. Report blocked inner syscalls honestly; a deadline is not proof of forced retirement.
- [ ] Commit the real host application: `feat(examples): add owned-workload file observer`.

### SDK05: Standalone starter and host package submilestone

**Dependencies:** SDK04; LX11 and CP13 genuine Rust reference consumer/package outputs; TT07/TT10. **Requirements:** SDK-R08/R11/R12. **Files:** create `templates/scopebase-observer/{Cargo.toml,Cargo.lock,GETTING_STARTED.md,src/main.rs,tests/conformance.rs}`, `tools/reference/test_starter.py`; integration owner updates package/profile listings.

**Interfaces:** starter owns its `[workspace]`, released package coordinates/lockfile and actual TT conformance invocation. `test_starter.py --bundle DIR --work-dir DIR --offline` stages dependencies and isolates the project from all sibling/donor source.

- [ ] Write script tests that fail on a workspace-path dependency, unavailable staged prerequisite, wrong resolved subject and a starter that only runs dependency-free smoke tests. Validate documented refusal and unknown output as structured states.
- [ ] Implement the small project using only public composition APIs and app-specific observation logic; include explicit effects, limits, failure/cleanup paths and conformance test. Stage all external dependencies before offline execution; do not silently download from the offline route.
- [ ] Run `python3 tools/reference/test_starter.py --bundle dist/sdk-host --work-dir target/sdk05-independent --offline`; require standalone `cargo test --offline --locked` plus the installed file observer from distributed artifacts, actual linkage metadata and independent fixture truth.
- [ ] Run `cargo +1.88.0 check -p scopebase-sdk --no-default-features` with a provisioned explicit toolchain and supported feature unions. Missing MSRV/tool prerequisites are BLOCKED, not silently installed or waived. Publish only the named host submilestone in local qualification docs.
- [ ] Commit: `feat(sdk): ship standalone host observer starter`.

### SDK06: Actual live observation recipe over existing Aya

**Dependencies:** SDK04; LX09 supervised-child pool; BP04/BP05/BP10; selected toolchain/object tasks; TT05/TT06. **Requirements:** SDK-R09 plus R02/R04/R07. **Files:** create `apps/scopebase-workload-observer-bpf/{Cargo.toml,README.md,src/main.rs,src/workload.rs,src/driver.rs,bpf/tick.bpf.c,fixture/tick.c,tests/object_contract.rs,tests/live_workload.rs}`, `tools/reference/build_workload_observer.py`.

**Interfaces:** explicit build script accepts `--toolchain-manifest FILE --output DIR`, emits final BPF object plus build manifest; fixture exports `scopebase_fixture_tick(uint64_t)`. App uses BP AttachPlan/execute_plan with Arc<HeldFile>, Aya backend and application-owned orchestration. It constructs one persistent `RetirementPool::<AyaBackend>::new(RetirementCapacity { max_groups, max_links, max_retained_bytes }) -> Result<RetirementPool<AyaBackend>,OperationError>`; `execute_plan` receives `&mut pool`. BP's `NativeAttach::{Attached(link),NoEffect(error),Uncertain{custody,cause}}` becomes `AttachOutcome::{Active{owner,summary},RolledBack{summary,cause},Unresolved{custody,summary,cause}}`; Uncertain/Unresolved is terminal retained custody, not an ownerless error or permission to retry attachment. Ticket disposal is `AttachmentSet::retire(self,&mut pool)` or `UnresolvedAttachments::retry_retire(self,&mut pool)`; wrong-pool failures preserve custody. `pool.reconcile(RetirementBudget { max_native_calls })->PoolReconcile` addresses pending/orphan entries only and exposes retired/pending/failed groups plus usage; `pool.close(self)->PoolClose<AyaBackend>` returns Closed or Unresolved(pool). Fixture spawning uses `SupervisorPool::new(SupervisorLimits,ReapIntegration)->Result<SupervisorPool,LinuxError>` and `ChildSupervisor::new(VerifiedHelper,&SupervisorPool)->Result<ChildSupervisor,LinuxError>`; both pools live across controller reconstruction. `spawn_stopped`, `StoppedChild::release`, running-child wait/terminate and pool drain/close preserve the owner-bearing variants from LX09, rather than coercing partial setup/release into ownerless errors. No state machine moves into SDK.

- [ ] Write object tests for the emitted uprobe program, map BTF/type linkage, relocation/call/section expectations and exact object/binding hash. Write live assertions for owned IDs 1..16, active excluded IDs 1001..1016, immediate attach-time activity, failed second acquisition, denied loading, in-flight stop, output error and unresolved native cleanup. Add `controller_reconstruction_preserves_child_pool_charge`, `release_failure_retains_correct_child_state`, `supervisor_close_failure_returns_live_pool`, `closing_supervisor_refuses_stale_controller`, `dropped_attach_ticket_keeps_pool_charge`, `wrong_pool_retirement_returns_original_ticket` and `pool_close_unresolved_cannot_report_success`; an exhausted domain refuses new spawn/attachment even after the application controller is dropped/rebuilt. A separately created pool is explicitly a different domain, never proof that the old session's capacity was released.
- [ ] Add TT06 deterministic fault controls `uncertain_native_effect_is_not_reattached` and `late_completion_after_timeout_retains_pool_charge`: inject owner-bearing Uncertain before a link FD is delivered, inspect the same file/backend/native acquisition identity and assert no split/new attach plus retained charge until `retire_uncertain` proves all effects gone. Label these model/fault controls separately from the actual live observer cases; an adapter unable to represent the custody must refuse before effects.
- [ ] Run `cargo test -p scopebase-workload-observer-bpf --test object_contract` with a deliberately wrong final object; require the intended artifact/shape assertion. Build from the selected explicit toolchain using `python3 tools/reference/build_workload_observer.py --toolchain-manifest qualification/sdk-bpf/toolchain.json --output target/sdk06-objects` only after prerequisites are provisioned.
- [ ] Implement the application driver using the existing Aya loader and BP adapters. Keep the same explicit SupervisorPool for positive/excluded fixture children and controller retries; select queued-owner drain policy explicitly and retain a failed close's pool/custody. Keep the same RetirementPool for attachment attempts/controller retries, reconcile its pending/orphan tickets under the BP budget before new admission and preserve any Unresolved(pool) from close. Fixture readiness and release use IPC barriers; preserve the partial admission interval across first/last attachment instead of claiming atomic startup. A successfully bounded drain does not create writer quiescence or final closure.
- [ ] In the leased isolated runtime cell, run `SCOPEBASE_LIVE=1 SCOPEBASE_OBJECT_DIR=target/sdk06-objects cargo test -p scopebase-workload-observer-bpf --test live_workload -- --ignored --test-threads=1`. Required no-permission/no-trigger states stay incomplete. Verify wrong-PID/filter and excluded-population-removal mutants fail their intended semantics after setup.
- [ ] Verify link/map disappearance and file-owner retention through retirement or explicit unresolved custody, then commit `feat(examples): add qualified owned-workload Aya observer` only with the precise checked scope in its description. Record unqualified cells if this task remains blocked; do not call complete SDK delivery done from SDK05.

### SDK07: Package SDK and starter with both reference routes

**Dependencies:** SDK05/SDK06; BP11; TT07. **Requirements:** SDK-R01/R08/R11. **Files:** extend starter `GETTING_STARTED.md`; create `tools/reference/package_sdk.py`, SDK `tests/feature_unions.rs`; integration owner wires artifact packaging.

**Interfaces:** `package_sdk.py --output DIR` emits SDK crate archive, host observer, optional selected BPF recipe sources/object manifest, starter, notices and offline prerequisite manifest. A host install does not load BPF or require its compiler.

- [ ] Write packaging controls for omitted fixtures, transitive workspace paths, feature unification selecting both backends and stale object hashes. Require explicit BPF opt-in and exact backend selection.
- [ ] Implement artifact staging with crate package lists, reproducible manifests and standalone paths. Ship human-readable prerequisites/effects/limits/refusals and machine-readable component bindings.
- [ ] Run `python3 tools/reference/package_sdk.py --output dist/sdk`, then `python3 tools/reference/test_starter.py --bundle dist/sdk --work-dir target/sdk07-independent --offline` against staged host prerequisites; separately run the installed live recipe in its qualified runtime cell with the same final objects.
- [ ] Commit: `build(sdk): package standalone host and live recipes`.

### SDK08: Fault, concurrency and causal CI qualification

**Dependencies:** SDK07; TT06/TT08/TT09. **Requirements:** SDK-R03/R05/R07/R10/R12. **Files:** create SDK `tests/fault_paths.rs`, reference apps `tests/concurrent_runs.rs`, and `qualification/sdk/{host-profile.json,live-profile.json,coverage.md}`; shared CI integration remains single-writer.

**Interfaces:** profiles list required cases before fixture discovery. Causal impact includes profile/effect interpretation, limits, capture metadata, file ownership, backend, final objects, workload, oracle and package inputs.

- [ ] Add N/N+1 byte/work/owner/diagnostic limits, panic during metadata copy, two contexts/apps in parallel, output failure, cancellation at each application acquisition barrier and exhausted bounded custody. Cross-context owner/epoch/diagnostic leakage is an assertion failure.
- [ ] Run `cargo test -p scopebase-sdk --test fault_paths` and both applications' concurrent-run tests; run affected live fault cases once in the leased cell. Check limit assertions reach the intended inner operation, rather than a prior setup timeout.
- [ ] Wire CI so host metadata edits select host/capture tests, file lifetime changes select Linux/application cases and backend/object/producer changes select exact object/live recipe cells. Preserve failed attempts across retries; required skipped cells cannot pass the live profile.
- [ ] Commit: `test(sdk): qualify faults and independent concurrent contexts`.

### SDK09: SDK acceptance and MG handoff

**Dependencies:** SDK08; SB03; TT10. **Requirements:** SDK-R01–SDK-R12. **Files:** create `docs/sdk/{support.md,migration-seams.md,issue-register.md}`; update SDK README/starter and shared qualification index through integration owner.

**Interfaces:** handoff records exact package version/features/backend, public extension points, tests/objects/fixtures, open cells, donor-specific behavior still local and MG duplicate-retirement criteria. It does not mark product migrations complete.

- [ ] Audit requirement-to-task/profile/case mapping, two real component consumers and both SDK apps; fix missing documentation or implementation rather than waive an advertised gate.
- [ ] Run the already selected affected package/installed/host/live checks against final packaged bytes; do not repeat unrelated stress after unchanged inputs. Run `git diff --check` and inspect untracked package content/provenance.
- [ ] Write qualification status per profile with assertion/capability/coverage/harness/cleanup separate. Complete SDK requires final object/live/installed evidence; host-only is recorded as its own narrower achieved submilestone.
- [ ] Commit: `docs(sdk): record supported profiles and migration handoff`.

## Native work packages

### NX01: Independent neutral corpus and semantic bindings

**Dependencies:** SB01/SB03; canonical capture neutral API; TT01/TT06. **Requirements:** NX-R01/R10/R12. **Files:** create `interop/vectors/{README.md,v1/manifest.json,v1/expected.json,v1/inputs/}`, `interop/vectors/generate_inputs.py`, `interop/vectors/tests/test_vectors.py`, `docs/interop/issue-register.md`.

**Interfaces:** manifest names IDs/inputs/hashes/origin/tier/clients/intended mutant; independent literal expected file is never generated by production code or replaced from observed output. Wire mapping is the exact v1 spec; semantic validation uses capture canonical API.

- [ ] Author literal positives and negatives for 0/9007199254740993/u64 max/overflow, unknown/zero, capped signals, distinct epochs, duplicate claim/channel, partial-view recovery, repeated short retry and untouched error output. Distinct coherent standalone epochs are valid; a context-mixing script tests refusal by the owning capture operation. Every vector names the violated semantic assertion and valid restored twin.
- [ ] Write `test_expected_is_independent`, `test_vector_hashes_and_cardinality`, `test_declared_negative_reaches_contract`, and exact byte-offset/tag checks; run `python3 -m unittest discover -s interop/vectors/tests` before generating inputs to establish intended missing behavior.
- [ ] Implement only fixture-byte generation and independent fixture verification. Preserve origin/licensing and do not copy product schemas/private logs or compute expected answers through capture/native reducers.
- [ ] Re-run tests and regenerated-hash comparison. Prepare issue records with H/UC/G mapping where applicable, selected donor source, original defect, mutant and removal criterion; leave new nonmatching semantic families explicit.
- [ ] Commit: `test(interop): add independently expected neutral vectors`.

### NX02: Exact libbpf-mojo and MojoBPF integration audit

**Dependencies:** NX01; SB01. **Requirements:** NX-R02/R07/R12. **Files:** create `docs/interop/{libbpf-mojo-inputs.md,object-contract.md,support-matrix.json}`, `interop/libbpf-mojo-conformance/inputs.json`.

**Interfaces:** input register distinguishes consumed source/bundle, sibling main, joint candidate, refs/worktrees/WIP and selected-file deltas. Operation matrix separately records object parse/load, map kind/test-run, attach, ring, lifetime and installed C/Mojo route evidence.

- [ ] Refresh only selected remote source metadata read-only against the exact research pins, preserving uncommitted/untracked work and no fetching/reset/build/runtime operations. Record moving heads; do not freeze another owner's checkout.
- [ ] Compare public headers/symbols/source to ownership/support prose and specifically detect buffer-statistics documentation drift. Audit actual MemVeil dependency inclusion of each fix rather than infer from sibling main.
- [ ] Freeze target operations and admitted architecture/toolchain/ABI, library lifetime and tracepoint-only scope; record unknown uprobe/fentry support as unknown. Define MojoBPF ELF/BTF admission against its actual compiler/adapter objects, no new compiler/loader.
- [ ] Validate JSON parsing, exact pins, local links and operation coverage; independent reviewer checks that source/host/historical/live evidence was not conflated. Commit `docs(interop): freeze consumed and candidate native contracts`.

### NX03: Native copied-record retention and retry contribution

**Dependencies:** NX01/NX02; TT06; selected bridge build prerequisites. **Requirements:** NX-R03/R10. **Files:** create `interop/libbpf-mojo-conformance/{CMakeLists.txt,c/ring_retry.c,mojo/ring_retry.mojo,tests/test_ring_contract.py,patches/ring-retry.patch}`.

**Interfaces:** overlay builds with explicit `-DLIBBPF_MOJO_PREFIX=DIR`; use installed public operations and reviewed bridge test hook only where public API cannot create the precise controlled callback source. Underlying libbpf remains reader/synchronization owner.

- [ ] Add repeated short calls with occupied retained slot, source mutation immediately after callback, malformed/discard records, EINTR and queue pressure; assert exact bytes once and `received = delivered + held + malformed + dropped` under the documented units/epoch.
- [ ] Build the overlay against the selected bridge and demonstrate borrowed-source and consume-on-short mutants fail the byte-retention assertion after verified record delivery. A crash during setup does not count.
- [ ] Add minimal bridge-local regression patch where absent, or record an already-complete donor case with its public installed-consumer route; keep sessions/generic statistics lifetime differences explicit.
- [ ] Run `cmake -S interop/libbpf-mojo-conformance -B target/nx03 -DLIBBPF_MOJO_PREFIX=target/native-prefix`, `cmake --build target/nx03`, and `ctest --test-dir target/nx03 -R ring_retry --output-on-failure`. Label controlled-host reader results separately from live producer behavior.
- [ ] Commit the distributable contribution: `test(interop): preserve copied-record retry semantics`.

### NX04: Transactional native configuration and stale views

**Dependencies:** NX02; NX03 shared overlay infrastructure. **Requirements:** NX-R04/R10. **Files:** create overlay `c/config_transaction.c`, `mojo/config_transaction.mojo`, `patches/config-transaction.patch`; extend independent vectors/issue mapping without replacing expectations.

**Interfaces:** selected bridge configure/get-generation/view API from NX02; tests independently inspect native autoload/attach-target state. ScopeBase does not invent another configuration engine.

- [ ] Write failed-autoload, failed-target-after-autoload, rollback-failure poison, successful-once and stale-view cases. Assert actual native state and generation unchanged on an ordinary failed transaction; poisoned rollback cannot appear reusable or committed.
- [ ] Run the case against commit-sensitive rollback-omission mutant; require native-state assertion failure with unchanged independent expected values. Implement only the missing regression/minimal selected-bridge fix in the prepared patch bundle.
- [ ] Run `cmake --build target/nx03` and `ctest --test-dir target/nx03 -R config_transaction --output-on-failure` through both C and Mojo routes. Capture errors immediately on the same native thread and assert next call cannot alter the copied diagnostic.
- [ ] Commit: `test(interop): pin transactional native configuration`.

### NX05: Exact native map geometry and live map control

**Dependencies:** NX02/NX03; BP02; TT05. **Requirements:** NX-R05/R10. **Files:** create overlay `c/map_geometry.c`, `mojo/map_geometry.mojo`, `fixtures/percpu_map.bpf.c`, `patches/map-geometry.patch`, `profiles/map-live.json`.

**Interfaces:** geometry contract is checked `align8(value_size) * possible_cpus`, including offline CPUs. Bloom membership is not output-value lookup; match BP neutral vectors without copying BP implementation as expected arithmetic.

- [ ] Write 80/88-byte stride, 1/2/possible-versus-online CPU, malformed topology, multiplication overflow, exact/short/aliased output and bloom controls. Kernel-call interceptor must observe no allocation/native operation for semantic refusal cases.
- [ ] Run stale-consumer-stride, online-CPU-only and bloom-as-output mutants; require intended extent/operation assertions, not a guard-page crash alone. Preserve untouched caller output on all ordinary errors.
- [ ] Extend the reviewed selected-bridge regression patch where necessary, then run `cmake --build target/nx03` and `ctest --test-dir target/nx03 -R map_geometry --output-on-failure` for controlled-host results.
- [ ] In the separately leased admitted cell, build the declared fixture once with selected compiler, inspect final object, run the installed C/Mojo map-live clients and independent raw 41→42 control with unchanged-oracle mutant 43, then verify owned-ID disappearance. Required missing live eligibility stays incomplete.
- [ ] Commit: `test(interop): qualify map extents and map-kind refusals`.

### NX06: Existing bridge lifetime, close, release and standard objects

**Dependencies:** NX02–NX05; selected MojoBPF final object; TT05/TT06. **Requirements:** NX-R06/R07/R10. **Files:** create overlay `c/lifetime.c`, `mojo/lifetime.mojo`, `c/standard_object.c`, `mojo/standard_object.mojo`, `profiles/object-live.json`; extend object-contract docs and patch bundle.

**Interfaces:** retain selected public libbpf-mojo parent/child/library ownership and `EBUSY` close versus release semantics; no new ScopeBase BPF owner ABI. Standard ELF/BTF objects enter the existing bridge; inspect typed map linkage, relocation/call/helper/section shape against independent NX02 expectations.

- [ ] Write parent-close-with-child, loader-drop-before-child, missing-destroy-symbol preflight, repeated close/release, failed-detach/poison and same-thread diagnostic cases; exactly-once destruction counts must be independently instrumented. Reject calling cached symbols after library unload.
- [ ] Run early-unload, close-means-release and false-cleanup-success mutants after acquiring real descendants; require lifetime/cleanup assertion failure. Prepare minimal missing native tests/fixes without changing donor source.
- [ ] Run `cmake --build target/nx03` and `ctest --test-dir target/nx03 -R 'lifetime|standard_object' --output-on-failure` for selected host/parser results. Then run admitted selected standard objects in the leased live cell, with active known operations/excluded population, verifier behavior and owned cleanup checks.
- [ ] Record final ELF hashes, exact compiler/adapter/library/binary identity, BTF/config and source/output provenance; missing config or unrun generic operations cannot be filled by old tracepoint receipts. Commit `test(interop): preserve bridge ownership and standard object gates`.

### NX07: Narrow stateless ScopeBase capture ABI

**Dependencies:** NX01; CP10 canonical neutral API; SB02; demonstrated C/Mojo application need from the client requirements in this spec/NX08 (not NX08 implementation). **Requirements:** NX-R08/R09/R10. **Files:** create `crates/scopebase-ffi/{Cargo.toml,src/lib.rs,src/abi.rs,src/validate.rs,tests/abi.rs,tests/wire.rs}`, `interop/{include/scopebase_capture_v1.h,abi/v1.json,pkgconfig/scopebase-capture.pc.in}`.

**Interfaces:** exact C structs, symbol signatures, 128-byte wire header, 32-byte counter records, variable claims and status/error precedence from the spec. Rust byte adapter calls `neutral::validate_v1` once after complete preflight and translates errors; it does not duplicate semantic validation. Private `abi::semantic_code(Option<&scopebase_capture::ContractError>) -> u32` matches named variants explicitly with stable codes 100..118 and `None`/nonexhaustive wildcard 199; never cast or index Rust discriminants/declaration order.

- [ ] Write layout/offset/export tests and `short_output_never_writes`, `repeated_query_is_stateless`, `unaligned_input_is_valid`, `zero_reserved_enforced`, `unknown_tag_refused`, `numeric_extent_and_alias_refused`, `query_partial_stays_local`, `panic_never_unwinds_to_c` and `capacity_tail_untouched`. Add `named_contract_error_codes_frozen` with one literal `(variant, code)` assertion for every 19-variant table row, including `ConservationMismatch=118`, preserving the preexisting InvalidId100..InvalidReplay117 assignments; add `unrecognized_contract_error_uses_199` using the private None sentinel. The sentinel tests fallback assignment, while review confirms the production wildcard reaches it; it does not simulate a newly released capture variant. Use the independent corpus, exact option size 32/result size 40, limits 1..65,536 and stable status codes 0..6.
- [ ] Run `cargo test -p scopebase-ffi --test abi --test wire`; verify missing behavior, then implement natural-layout structs and bounded byte decoding, canonical validator call and copy-only-after-success normalization.
- [ ] Validate input/header/record/reason extents with checked arithmetic before allocation; map frozen Origin/Unit/QualityReason tags explicitly. Do not transmute unchecked integers into Rust enums. Treat null, alias and bad-version results according to the documented output-validity contract.
- [ ] Run tests plus no-partial-output, wrong-origin and unknown-as-zero mutants. Confirm output unchanged for every non-OK result and no implicit FD/thread/global state. Export only the two v1 functions; build SONAME/install metadata and document no close/release because no resources are retained.
- [ ] Commit: `feat(ffi): expose stateless capture envelope validation`.

### NX08: Independently useful C and Mojo validation applications

**Dependencies:** NX07; NX01 vectors; TT07. **Requirements:** NX-R08/R09/R10/R11. **Files:** create `interop/clients/c/{CMakeLists.txt,main.c,tests/independent_oracle.c}`, `interop/clients/mojo/{main.mojo,owned_library.mojo,test_vectors.mojo}`, `interop/clients/{README.md,build_clients.py,tests/test_client_binding.py}`.

**Interfaces:** installed CLIs `scopebase-capture-check --input FILE --output FILE` and `scopebase-capture-check-mojo --input FILE --output FILE`; each reports ABI/library path and hash, semantic status and independently parsed summary. C/Mojo handle ownership retains loaded library through calls. Their application use is validating received capture-quality envelopes, not merely asserting a Rust roundtrip.

- [ ] Write independent expected-summary checks for measured zero versus unknown, `9007199254740993`, u64 max, capped signal, scoped reasons/QueryPartial, malformed/truncated/unknown-version/overflow input, short retry and prefix/tail preservation. Neither client computes expected results by first calling the FFI.
- [ ] Build clients against only the installed header/shared library using `python3 interop/clients/build_clients.py --prefix target/native-prefix --output target/nx08-clients`; missing provisioned C/Mojo toolchain is BLOCKED, no silent install.
- [ ] Run each client against all required vectors and compare semantic results to independent expected file. An independent C oracle and independent Mojo fixture parser check field values; byte equality alone does not qualify shared semantics.
- [ ] Run `python3 -m unittest discover -s interop/clients/tests`; reject wrong shared-library path/hash/ABI, unloaded-library call, output alias and absent-negative population. Preserve user input/output owners and same-call diagnostics.
- [ ] Commit: `feat(interop): ship C and Mojo capture validation clients`.

### NX09: Sanitizers, fuzzing and installed offline bundles

**Dependencies:** NX03–NX08; TT06/TT07/TT08. **Requirements:** NX-R09/R10/R11. **Files:** create `interop/tests/{boundary_sanitizers.c,CMakeLists.txt}`, `fuzz/fuzz_targets/native_capture_wire.rs`, `tools/reference/package_native.py`, `tools/reference/test_native_install.py`, `qualification/native/profiles.json`.

**Interfaces:** bundle contains ABI header, SONAME library, pkg-config metadata, version/support/notice files, neutral vectors, compiled C/Mojo clients and installed bridge overlay routes. Build-prerequisite manifest explicitly names compilers; run-only manifest names loader/system ABI and staged runtime dependencies. Installed run-only offline checks require no compiler, donor/monorepo source or network, use a read-only prefix and separate writable fixture/results directory.

- [ ] Add guard-page/unaligned/truncation/maximum-count/checked-overflow, large numeric lengths, supported raw alias refusal, disjoint multithreaded calls and panic-injection boundary tests. Invalid arbitrary pointers are caller violations; do not claim the parser safely validates them.
- [ ] Run boundary C cases under admitted ASan/UBSan builds with Rust boundary instrumentation where supported. Run Miri only on supported pure Rust decoding and `cargo fuzz run native_capture_wire -- -max_total_time=60` as a recorded bounded campaign; report unsupported instrumentation explicitly.
- [ ] Run `python3 tools/reference/package_native.py --output dist/native`, then `python3 tools/reference/test_native_install.py --bundle dist/native --work-dir target/nx09-installed --offline`. Remove checkout access in the subprocess environment and verify installed resolved library path/hash/ABI, C/Mojo vector semantics and cleanup independently.
- [ ] Run the selected installed bridge live routes in their leased runtime cells with the packaged final objects. CI selects these after ABI/library/compiler/object/fixture/oracle changes; pure capture updates select canonical and C/Mojo semantic cases even when ABI source is unchanged.
- [ ] Commit: `test(interop): qualify installed native boundaries and offline use`.

### NX10: Native acceptance, contribution custody and MG handoff

**Dependencies:** NX09; SB01/SB03; TT10. **Requirements:** NX-R01–NX-R12. **Files:** create `docs/interop/{release-checklist.md,migration-seams.md}`, update issue/support/input registers and native package README.

**Interfaces:** delivery manifest includes selected bridge consumed/candidate distinction, prepared patch bundle/test overlay, neutral vectors, standard object recipe, ScopeBase pure ABI and both actual clients. Handoff distinguishes ready supported operations from implemented-but-unqualified candidates and later MG product migrations.

- [ ] Trace all requirements and contribution invariants to cases, independent oracles, reached mutants, final artifacts and installed consumers. Check both C and Mojo routes are meaningful applications and do not merely wrap a common test helper.
- [ ] Inspect per-file SPDX/authorship/notices and selected dependency license inventory; no blanket relicensing or private evidence copying. Record patch inclusion, upstream status and removal test without publishing/submitting automatically.
- [ ] Re-run only affected final-package checks from the frozen profile matrix. Missing live/object/installed requirements stay incomplete; document whether a passing expected refusal leaves capability denied/unknown.
- [ ] Commit acceptance/handoff documents: `docs(interop): record supported native profiles and migration seams`. External submission, donor application, releases and product migration are separate work.

## Dependency graph, completion and restart

SDK chain is `SDK01 → SDK02 → SDK03 → SDK04 → SDK05`; SDK06 branches from SDK04 when BP/toolchain/TT dependencies are ready; SDK07 joins SDK05/06, then SDK08 → SDK09. NX01/NX02 can proceed in parallel with SDK work. NX03 supplies shared overlay infrastructure; NX04 and NX05 can then use disjoint test sources, with one integration writer for CMake/register changes. NX06 joins them. NX07 can proceed after canonical capture API/NX01 and the NX08 client requirements are frozen; NX08 → NX09 joins native overlay/object gates; NX10 closes native delivery. Shared Cargo/config/native fixture writes and leased live lanes remain serialized.

| Requirement | Implementation acceptance tasks |
|---|---|
| SDK-R01/R02 | SDK01, SDK07, SDK09 |
| SDK-R03/R05/R10 | SDK02, SDK08 |
| SDK-R04 | SDK03, SDK06 |
| SDK-R06/R07 | SDK03, SDK04, SDK06, SDK08 |
| SDK-R08/R11 | SDK05, SDK07 |
| SDK-R09 | SDK06–SDK09 |
| SDK-R12 | SDK01, SDK05, SDK08, SDK09 |
| NX-R01/R02 | NX01, NX02, NX10 |
| NX-R03/R04/R05 | NX03, NX04, NX05, NX09 |
| NX-R06/R07 | NX02, NX06, NX09 |
| NX-R08/R09 | NX07, NX08, NX09 |
| NX-R10/R11 | NX01, NX03–NX09 |
| NX-R12 | NX01, NX02, NX10 |

A task is not complete merely because its test source or prepared patch exists. Implementation completion, named-profile package readiness and later MG product migration are separate states. Restart from the first unchecked task after reading its spec, exact dependency/task outputs, selected donor delta register, current worktree status and active lease owner. Preserve existing outputs; bind a fresh run to changed bytes and keep independent target/evidence paths. Use affected-contract selection rather than rerunning every unrelated profile. Plan-only completion does not authorize any commands here to execute now.
