# ScopeBase Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete independently useful `scopebase-capture` package and its executable conformance checks while preserving provenance, loss, bounds, replay and closure limitations.

**Architecture:** Small synchronous pure Rust modules check explicit caller evidence; no module drives a universal capture session or grants live authority. Product-specific reducers remain in independent donor-shaped consumer adapters. Shared testkit supplies independent oracles and offline installed delivery over the actual resolved package.

**Tech Stack:** Stable Rust edition 2021, target MSRV 1.88.0, standard library core, optional `serde`/`serde_json` under `json`, test-only Proptest and shared ScopeBase testkit.

**Spec:** [ScopeBase capture and provenance design](../specs/2026-10-17-scopebase-capture-design.md).

## Global Constraints

- Follow the [decision register](../specs/2026-10-18-scopebase-decisions.md) and [executor contract](../specs/2026-10-18-scopebase-executor-contract.md). The [task-origin routes and concrete repair packets](2026-10-18-scopebase-plan-repair.md#task-origins-and-decision-routes) supplement this task; broad source groups are not dispatch-ready source selections.
- PORT/ADAPT preserves the identified donor mechanism, affected call sites, original regression, independent oracle and bad control together. NEW requires the recorded missing-mechanism reason and frozen design. Unresolved architecture, source, license, support or expected-result choices return NEEDS_DECISION; no fresh approximation or weaker gate.
- Apply provisional Apache-2.0 userspace / GPL-2.0-only BPF / GPL-3.0-or-later application terms and the shared-source/third-party rules in D03–D04. Keep source SPDX, author authorization, actual target input option and kernel runtime declaration distinct.

- Brand: ScopeBase; Rust package: `scopebase-capture`; library import: `scopebase_capture`.
- Core uses stable Rust, edition 2021, `rust-version = "1.88.0"`, and the standard library; `default = []`.
- Feature `json` adds only `serde` and `serde_json` for the neutral replay format; feature activation is additive and cannot change core semantics.
- No BPF/compiler/build-script requirement, platform syscalls, hidden logging, automatic effects or product dependency in this package.
- All public invariant-bearing fields are private; validating constructors also run on replay and version conversion.
- All public error/outcome enums are `#[non_exhaustive]`; errors expose structured codes, never required text matching.
- All collections are admitted against explicit limits before mutation; rejected operations preserve previous state.
- A count bound is not a retained-byte, peak-memory, time, syscall-interruptibility or native-cleanup bound.
- Product migrations are LATER; standalone ScopeBase consumers and real donor-shaped adapters qualify this package without implying product integration.

Every command below is a **future implementation command**, currently NOT_RUN. The repository contains no Cargo workspace today. Foundation SB02 owns workspace creation, root manifest/lockfile and tested dependency/MSRV selection; this plan consumes that result and never races its owner on those files. SB02 must compile the selected optional dependencies on 1.88.0 before making that support claim. No product build, donor write, privileged probe, commit or publication occurs while writing this plan.

## Review Focus

- Two identical insertion-owner payloads must still fail cardinality, while real identity field zero succeeds; CP04 tests `two_equal_owners_still_conflict` and `zero_identity_is_known`.
- An overlapping sample interval or a wrapped/reset counter must not invent a delta; CP03 tests `overlapping_samples_are_partial` and `modulo_without_independent_bound_is_unknown`.
- Loss ledger capacity failure must preserve the prior ledger and keep the caller informed that the new loss was unrecorded; CP06 tests `capacity_refusal_preserves_ledger`.
- Corrected reports can disagree if one holder ignores late evidence; CP11 tests `dropped_correction_holder_is_detected` against independently expected replacements.
- A native caller can allocate huge vectors before invoking capture validation; CP10 tests validator cardinality but explicitly leaves preallocation/byte-framing limits with the native codec, and `neutral_count_limit_precedes_clone` proves capture adds no oversized clone.

---

## File and ownership map

Paths below are future deliverables. The spec contains exact normative type/method signatures; each task's Interfaces block names the exports it owns and consumes, and no task may invent alternative semantics.

| Owner/task | Files | Responsibility |
|---|---|---|
| CP01 | `crates/scopebase-capture/Cargo.toml`, `src/lib.rs`, `README.md`; `docs/issues/capture/donor-manifest.json`, `contract-map.md`, `provenance.md` | Package boundary, selected pins, issue/provenance inventory and applicable H/UC/G/TODO map |
| CP02 | `src/{domain,error,quantity,conservation,time}.rs`; tests `domain_quantity.rs`, `time_domains.rs` | Checked domains, units, partitions and clock-tagged interval base |
| CP03 | `src/{counter,loss}.rs`; tests `counter_deltas.rs`, `loss_units.rs` | Counter protocol and independent loss magnitudes |
| CP04 | `src/provenance.rs`; tests `insertion_provenance.rs`, `full_map_loss_contract.rs` | Insertion fold and producer-shaped full-map loss vectors |
| CP05 | `src/generation.rs`; tests `generation_histories.rs` | Scoped generations, match checks and bounded adapter histories |
| CP06 | `src/{view,feeds,correction}.rs`; tests `report_views.rs`, `feed_integrity.rs`, `corrections.rs` | Per-claim persistent loss, transient views, exactly-once feeds, versioned replacements |
| CP07 | `src/bounds.rs`; tests `alternative_bounds.rs` | Conserved physical-site alternatives |
| CP08 | Adds sweep section to `src/time.rs`; tests `interval_order.rs` | Ordering proof, separate from domain reducer metrics |
| CP09 | `src/closure.rs`; tests `closure_profiles.rs`, `closure_countermodels.rs` | Bounded evidence DAG checking, not native shutdown |
| CP10 | `src/neutral.rs`, feature-gated `src/replay.rs`; tests `neutral_validation.rs`, `strict_replay.rs`; `fixtures/capture/replay-v1/` | Canonical semantic seam, strict neutral replay/vector format |
| CP11 | `consumers/capture-{kryprobe,memveil,ossl}-reference/`; crate examples; testkit adapter glue | Independent actual standalone consumers and public examples |
| CP12 | `tests/support/reservation_pilot.rs`, `tests/reservation_evaluation.rs`; `docs/issues/capture/reservation-evaluation.md` | Required gated reservation evaluation, no automatic stable export |
| CP13 | `crates/scopebase-testkit/src/capture/`, `fixtures/capture/manifest.json`, `tools/check-capture-package.py`; capture distribution docs | Testkit/operator integration, packaged fixtures, exact-consumer installed qualification |

All production module paths in the table are under `crates/scopebase-capture/`; crate examples are in its `examples/`; conformance fixtures are top-level `fixtures/capture/`. Tests are ordinary package integration tests unless a testkit path is explicit. Do not make a production dependency from capture to testkit. Foundation/testkit/native owners own their corresponding cross-package files; CP11/CP13 changes use one agreed writer or a handed-off patch, never concurrent writers. CP12 internal pilot is not exported by `lib.rs`.

Dependency order: SB02 → CP01 → CP02; CP03, CP04, CP05, CP07 and CP08 use CP02; CP04 additionally uses CP03; CP06 uses CP03/CP05; CP09 uses CP02/CP05; CP10 uses CP03–CP09; CP11 uses CP10 and testkit TT01/TT02; CP12 uses CP06/CP11; CP13 uses CP11/CP12 and TT01/TT02/TT06/TT07/TT08/TT09/TT10. Applicable tests are bounded T0/T1/T5; BP/live tiers remain separate. After CP02, disjoint module/test owners may run small pure tests in isolated target directories; root Cargo.toml/Cargo.lock and `lib.rs` exports are serialized through the capture integration owner. Never parallelize heavy Cargo work or share one evidence output directory.

## Task CP01: Package, donor custody and issue contracts

**Requirements:** CP-R01, CP-R15–CP-R18. Existing F02–F05/F06; Q01–Q06; T01/T07; G19/G20. Depends on SB02.

**Files:** Create `crates/scopebase-capture/{Cargo.toml,src/lib.rs,README.md,tests/package_boundary.rs}` and `docs/issues/capture/{donor-manifest.json,contract-map.md,provenance.md}`. Root Cargo files belong to SB02 integration owner.

**Interfaces:** Consumes SB02's edition 2021/MSRV 1.88.0 workspace and dependency policy. Produces package name `scopebase-capture`, initial version `0.1.0`, import `scopebase_capture`, initial qualified target `x86_64-unknown-linux-gnu`, no default features, optional `json`; no runtime exports yet. Manifest records exact refreshed selected donor files/pins/SPDX/hashes and original defect → invariant → oracle → bad control → case → later migration/removal criterion.

- [ ] **Step 1: Write `package_has_no_platform_or_codegen_dependency` in `tests/package_boundary.rs`.** Assert `default=[]`, no `build.rs`, no Linux/BPF/product normal dependency and only optional JSON dependencies; parse the manifest structurally. The independent expected allowed production set is std plus optional `serde`/`serde_json`, rather than a list derived from actual dependencies.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test package_boundary package_has_no_platform_or_codegen_dependency -- --exact`.** Initially FAIL because the package/manifest does not exist; after SB02 exists, a forbidden dependency fixture must fail the semantic dependency assertion.
- [ ] **Step 3: Create package boundary and provenance inventory.** Read selected donor status/refs/files without mutation, compare the spec pins to refreshed sources, record deltas and accepted/rejected WIP. Preserve notices and keep active evolving AST validators out of trusted core. Apply D03 before copying code/fixtures: record the author-authorized destination grant separately from historical source SPDX and preserve actual upstream terms. An executor cannot choose a fresh semantic rewrite to evade the intake or historical GPL label; a genuinely necessary replacement needs the controller's recorded design and retained regression map. Map CP-R01–CP-R18 to Q01–Q06/H03/H13–H15/H17/H18/H23–H27, UC14 and applicable G/T obligations; preserve all original IDs. Add README state “proposed until implemented; product integrations LATER.”
- [ ] **Step 4: Run the boundary test, `cargo metadata --no-deps --format-version 1`, and parse `docs/issues/capture/donor-manifest.json` with Python `json.load`.** Expect PASS, correct package/features and complete selected source/license entries; no dependency update in donors. No green host boundary result qualifies donor behavior.
- [ ] **Step 5: Review and commit only CP01 files:** `git add crates/scopebase-capture docs/issues/capture` then `git commit -m "chore(capture): establish host package and provenance contracts"`.

**Acceptance:** A standalone host package boundary and explicit selected donor/case custody exist; no implementation item is closed by the manifest alone.

## Task CP02: Domain, quantity, partition and interval foundations

**Requirements:** CP-R01/CP-R02/CP-R09/CP-R18. Depends on CP01.

**Files:** Create `src/{domain,error,quantity,conservation,time}.rs`, tests `domain_quantity.rs`, `time_domains.rs`; modify `src/lib.rs` through the integration writer. Create `tests/ui/count_units_do_not_mix.rs` and its compile-fail expectation using testkit's selected compile-test support.

**Interfaces:** Produces the spec's `CaptureId::new([u8;16])`, `ProducerId::new([u8;16])`, `BindingId::new([u8;32])`, `ClockDomain::new([u8;16])`, `Epoch::{new,successor,capture,producer,ordinal}`, `SourceRef::{new,epoch,origin,binding}`, ID newtypes, `Origin`, `ContractError`, sealed `Unit`, `Count<U>::{new,get,checked_add,checked_sub}`, `CountBounds<U>::{new,lower,upper}`, `ScopePartition<U>::new`, `check_conservation<U>`, `Timestamp::new`, `TimeInterval::{new,duration_ns}`. All signatures exactly match the spec.

- [ ] **Step 1: Write failing tests with explicit values.** `zero_numeric_ids_but_not_absent_domains` accepts channel/claim/site/ordinal 0, rejects zero byte-array IDs; `epoch_exhaustion_refuses` rejects successor at u64 max; `units_and_checked_partitions` accepts total=9, matched=2, nonmatched=3, unknown=4, rejects total=8 and u64 max+1; `bounds_preserve_unknown_upper` distinguishes `[0,None]` from `[0,Some(0)]`; `half_open_zero_and_clock_mismatch` accepts `[0,0)` in one clock and rejects cross-clock/reversed intervals. Compile-fail test tries adding `Count<Records>` to `Count<Events>`.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test domain_quantity --test time_domains`.** Expect FAIL for missing exports; unit-mixing compile-fail must fail to compile for the intended type mismatch once exports exist.
- [ ] **Step 3: Implement private checked value types and same-unit arithmetic.** Use checked u64 operations and no public implicit conversions. Error construction has no raw payload; add bounded redacted Debug implementations where identity payloads could leak. Clock reading/conversion is not added.
- [ ] **Step 4: Run both tests and `cargo test -p scopebase-capture --doc --no-default-features`.** Expect all assertions and doctests PASS. Independent oracle computes the partition with small literal integers and u128 bounds. Known-bad unchecked-add, unknown-as-zero and cross-clock-equality variants must reach the tested call and fail its arithmetic/domain assertion.
- [ ] **Step 5: Commit CP02 files:** `git add crates/scopebase-capture` then `git commit -m "feat(capture): add scoped domains and checked units"`.

**Acceptance:** Exact core signatures, compile-time unit separation and checked temporal/domain invariants exist on no-default features; not an identity authority or memory-bound claim.

## Task CP03: Counter protocol, loss units and diagnostic signals

**Requirements:** CP-R02/CP-R04/CP-R05/CP-R18. H03/H17/H24/H26, G16/G23. Depends on CP02.

**Files:** Create `src/{counter,loss}.rs`, tests `counter_deltas.rs`, `loss_units.rs`; update exports serially.

**Interfaces:** Consumes `SourceRef`, `TimeInterval`, `Count<U>`. Produces spec-exact `CounterPolicy`, `Sample<U>::new(...)`, `AdvanceBound<U>::new(...)`, `sample_delta<U>(Option<&Sample<U>>, &Sample<U>, Option<&AdvanceBound<U>>) -> Result<Delta<U>,ContractError>`, `Delta`, `DeltaUnknown`, `LossKind`, `LossMagnitude<U>`, `LossFact<U>::new(...)`, `CappedLossSignal::new(...)`, `fold_capped_signals(&[u8],u8) -> Result<u8,ContractError>`.

**Mandatory source decision:** Include K `crates/kryprobe-abi/src/kcrypto_agg.rs` and `kattrloss_fold` alongside the loss/counter donors. Retain missing-versus-zero, independent capped diagnostics and actual units; do not infer this input from the broad capture group.

**Frozen implementation rulings:** [D10/C1–C6](../specs/2026-10-18-scopebase-decisions.md#cp03-counter-and-loss-rulings) and the capture specification bind `AdvanceBound::new(&baseline, &current, maximum) -> Result<_, ContractError>` to the complete immutable pair, with explicit no-reset/max-advance caller assertion. Preserve constructor/comparison refusal order, marker-bound-free traits, redacted Debug and all public getters. Source grants come from the immutable CP03 admission; earlier admissions and port receipts remain historical. This is a pure increment without new dependencies, features or BPF/native effects.

- [ ] **Step 1: Write `missing_baseline_is_unknown`, `overlapping_samples_are_partial`, `epoch_or_binding_replacement_refuses`, `decrease_is_not_unsigned_delta`, `saturation_is_lower_bound`, `modulo_without_independent_bound_is_unknown`, `modulo_bound_is_checked`, `loss_units_do_not_merge`, `capped_signal_is_not_exact_events`.** Pin monotonic 7→12=5; 12→7 unknown; missing baseline unknown; 8-bit 250→3 with max advance=12 yields Exact(9), without bound unknown, with bound=8 rejects contradictory sample; saturating maximum255, 250→255 yields AtLeast(5), 255→255 unknown; signal fold `[254,4,0]` cap255=255. Cap0 and observed>cap refuse.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test counter_deltas --test loss_units`.** Expect FAIL on missing interfaces, then verify known-bad wrap subtraction produces the wrong huge result in the intended delta assertion.
- [ ] **Step 3: Implement policies and loss types exactly.** Require full context equality including origin, exact bound-pair matching and ordered nonoverlapping sample intervals; use u128 for 64-bit modulus. A bound cannot supply an absent explicit baseline. Check a decrease before saturation-at-baseline, and validate every diagnostic lane even after reaching cap. Keep capped signals separate from typed exact event magnitudes. No inferred reset, synthetic-zero baseline or lost-total scalar.
- [ ] **Step 4: Run the two tests.** Expect PASS with independently generated 4-bit mathematical and transition-table oracles (4,352 bounded cases each), 256 unbounded pairs, literal width64/saturation rows and all 5,625,215 valid capped diagnostic pairs. Vary each bound context field, interval endpoint and value with valid wrong-pair inputs and matching/new-bound twins. Mutants treating no baseline as0, cap255 as255 exact omitted events, resetting context by subtraction or hiding an invalid late lane must fail semantic assertions; restored valid twins pass. Add interval overlap review-focus test without a clock/syscall dependency. Ship `counter_windows` and `diagnostic_lanes` examples, exact-primary unit refusals and the bounded production-mutant runner; exercise tests/docs/examples/controls and two external API clients against source and actual extracted archives on Rust1.88.0/1.98.1 and no-default/default/json. These examples are not CP11's real application adapters.
- [ ] **Step 5: Commit:** `git add crates/scopebase-capture` then `git commit -m "feat(capture): preserve counter epochs and loss semantics"`.

**Acceptance:** Counter sampling meaning, not mere integer arithmetic, is pinned. Full-map producer storage and actual live baseline ordering remain BP/product tests.

## Task CP04: Insertion-frozen provenance and survives-full-map model

**Requirements:** CP-R03/CP-R04/CP-R15/CP-R18. H15/H17, B01/B08. Depends on CP02/CP03.

**Files:** Create `src/provenance.rs`, tests `insertion_provenance.rs`, `full_map_loss_contract.rs`; fixture `fixtures/capture/insertion-v1.json`; issue `docs/issues/capture/insertion-loss.md`.

**Interfaces:** Produces exact `ObservedIdentity<I>`, `IdentityUnknown`, `LaneIdentity<I>`, `ProvenanceLane<I,U>::{new,saturated}`, `InsertionFold<I,U>::{identity,total}`, `fold_insertion_identity<I:Eq+Clone,U:Unit>(&[ProvenanceLane<I,U>]) -> Result<InsertionFold<I,U>,ContractError>` and the payload-free `ContractError::SaturatedCount`. Consumes CP03 signal folding. This is host fold/model code, not an 88-byte decoder or producer implementation. The [ratified exact CP04 contract](../specs/2026-10-18-scopebase-cp04-insertion.md) and [P1–P5/S1–S2 decisions](../specs/2026-10-18-scopebase-decisions.md#cp04-insertion-provenance-rulings) govern all steps below, including the full named populations, trait/cost boundaries, fixture schema, two independent consumers and source/archive sensitivity matrix. Twelve selected ranges across two already-ready KryProbe rows are admitted in the [immutable CP04 snapshot](../../provenance/admissions/2026-10-18-cp04-insertion.json); earlier grants remain immutable.

**Mandatory source decision:** Include K `crates/kryprobe-abi/src/kcrypto_agg.rs`, `try_fold_vwho` and `identity_present` with successful-inserter, genuine-zero, migration and survives-full-map regressions. Freeze the exact source signatures and destination transition map.

- [ ] **Step 1: Write `migration_keeps_inserting_identity`, `zero_identity_is_known`, `missing_owner_refuses`, `two_equal_owners_still_conflict`, `secondary_counts_are_conserved`, `full_table_signal_survives_repeated_failure`.** Fixture identity `(uid0,stack0)` wins on one lane; secondary count7 plus owner count3 totals10; migration display identity99 never replaces owner. Full-map model capacity1 permits first insert and refuses operations2..5; independent attempted-operation ledger expects four failures and a nonzero separate signal. Below-capacity twin capacity5 has five identities and exact signal0; preexisting254 plus four signals folds255.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test insertion_provenance --test full_map_loss_contract`.** Expect missing-code FAIL. Verify bad zero-as-missing and multiple-owner-dedup variants fail the intended provenance assertions, not setup.
- [ ] **Step 3: Implement the fold.** Exactly one insertion marker owns identity, all lane counts checked; no inferred first nonzero identity. Put the bounded producer-shaped table only in test support. Document an independent loss channel requirement and BP proof obligations for actual full maps, writer partition/reentry and every real stride consumer.
- [ ] **Step 4: Run the tests.** Expect PASS. Known-bad model storing loss in the same full table yields zero signal and must fail `full_table_signal_survives_repeated_failure`; independent ledger is not derived from the model's loss field. Restore positive twin. Label evidence T0/T1, not live migration/full-kernel-map qualification.
- [ ] **Step 5: Commit:** `git add crates/scopebase-capture fixtures/capture/insertion-v1.json docs/issues/capture/insertion-loss.md` then `git commit -m "feat(capture): freeze insertion provenance with loss controls"`.

**Acceptance:** Valid zero, migration, competing insert and cap semantics preserved in core/models; wire/native/producer claims are explicitly unqualified here. Required checks include ordered missing/conflicting/saturation/overflow errors, exact-MAX twins, zero-clone refusal/zero-Eq calls, caller Clone effects and redacted Debug. Preserve all seven original migration shapes and historical gate256/WHO2048/full and below128 populations alongside small cases. The independently generated oracle, actual JSON-generated assertions, semantic mutants/restored twins, precise E0308 unit refusal, two external clients and six affected archive/twelve source/archive cells are mandatory. Also run one actual archive helper campaign in direct mode under one outer coordinator lease, proving no hidden repository-wrapper dependency. This extra route is not another matrix cell. CP02/CP03 unchanged controls retain their prior evidence; no full unchanged-package campaign is required.

## Task CP05: Explicit generations and bounded lifecycle histories

**Requirements:** CP-R01/CP-R06/CP-R09/CP-R15. H03/H25, L09. Depends on CP02.

**Files:** Create `src/generation.rs`, `tests/generation_histories.rs`, `tests/support/{generation_models.rs,generation_oracle.rs,check_cp05_controls.py}`, named `tests/ui/` controls, `examples/{transform_generations,mapping_generations}.rs` and issue `docs/issues/capture/generations.md`; root serializes exports/package-policy/provenance updates.

**Interfaces:** Produces `ObjectKey<K>::new(Epoch,K,u64) -> Self`, `next_generation(&self) -> Result<Self,ContractError> where K:Clone`, `matches(&self,&Self)->bool where K:Eq`, `require_generation<K:Eq>(&ObjectKey<K>,&ObjectKey<K>)->Result<(),ContractError>`. Consumes CP02 epoch semantics. No generic transform/allocator lifetime machine is exported.

**Frozen implementation rulings:** Follow the [CP05 contract](../specs/2026-10-22-scopebase-cp05-generations.md) and [verification plan](2026-10-22-scopebase-cp05-verification.md). The [immutable source admission](../../provenance/admissions/2026-10-22-next-host-scopes.json), SHA256 `e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1`, remains the authority for eight exact source selections. [Scoped package acceptance](../../reviews/2026-10-22-cp05-generations.md) binds integrated `7d992e1`, candidate/root archive gates, seventeen originals and exact helper evidence reuse. Complete application/runtime/installed/profile and migration owners remain separate.

- [ ] **Step 1:** Root binds actual post-BP02 base, immutable source admission and twelve-field packet. Write the linked plan's direct tests and all seventeen mapped original subsets; initial missing-code RED is separate from semantic control RED.
- [ ] **Step 2:** Implement immutable keys/conditional traits and exact epoch → generation → one raw equality; overflow returns ArithmeticOverflow before cloning, require refusal returns GenerationMismatch. Supplied 0/MAX stay valid. Run direct production trait/callback/control tests with restored positives; fixture equality cannot qualify them.
- [ ] **Step 3:** Adapt only selected donor mechanisms into separate test-local K/M models. Run the independent 55,987-script/324,726-action population, every prefix, at most six journal rows/eighteen facts, plus all original/literal vectors. Preserve duplicate-token flags, stable IDs, first-seen unknown creation counted once at admission, unknown IDs and post-eviction uncertainty. No ungranted first-seen/validator body or shared reducer is copied.
- [ ] **Step 4:** Deliver and run actual source/archive tests/helpers/examples/two independent external clients on both pinned compilers and all three feature selections. Run one archive helper direct under one outer lease. Root obtains independent Sol max review, validates actual selected-port/destination/preservation bindings, and runs six affected capture archive cells; unchanged package campaigns retain prior evidence.
- [ ] **Step 5:** Root accepts/commits only the verified increment using `feat(capture): enforce scoped generation matching`, preserving current admissions/receipts, TODO/handoff and later gates.

**Acceptance:** Key reuse cannot imply continuity. Exact errors/traits/callback order, all seventeen original subsets, bounded independent truth, semantic controls/restored twins, package delivery and two clients are required. CP08 ordering, CP11 actual application adapters, CP13/TT07 installed qualification, UC14/full profiles and MG runtime/duplicate retirement remain open. The detailed linked plan owns exact commands/selectors/claims.

## Task CP06: Scoped immutable views, required feeds and corrections

**Requirements:** CP-R07/CP-R11/CP-R13/CP-R18. H13/H26/H27, Q01/Q02/Q04. Depends on CP03/CP05.

**Files:** Create `src/{view,feeds,correction}.rs`, tests `report_views.rs`, `feed_integrity.rs`, `corrections.rs`, issue `docs/issues/capture/view-isolation.md`.

**Interfaces:** Produces spec-exact `QualityReason`, `LedgerLimits`, `ClaimAssessment::{claim,reasons}`, `QueryOverlay::new`, `ClaimLedger::{new,record_loss,record_signal,snapshot}`, `FeedRegistry::{new,feed,finish}`, `Revision::new`, `Versioned<T>::{new,revision,value,apply}`, `Correction<T>::new`. `Versioned::apply(self,Correction<T>)->Result<Self,(Self,ContractError)>` preserves the original value on rejection. Consumes unit/source/loss/generation types; does not own application fact reducers.

- [ ] **Step 1: Write `partial_snapshot_does_not_poison_later_view`, `consumed_loss_stays_in_epoch`, `independent_fact_claim_survives_relationship_loss`, `capacity_refusal_preserves_ledger`, `zero_feed_is_not_missing`, `second_feed_refuses`, `correction_is_exact_next_revision`.** Claims1=bytes,2=occupancy; relationship loss affects2 only; transient partial view of1 leaves the next plain view of1 unchanged. Capacity1 ledger accepts first fact, rejects second and equals its prior snapshot. Required channels0 and1 require explicit exact0 feeds; duplicate0 refuses. Revision0→1 succeeds; old0 correction to holder1 rejects with holder1 value returned unchanged.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test report_views --test feed_integrity --test corrections`.** Expect FAIL before implementation. Permanent-query-taint, missing-as-zero and double-feed controls must fail the intended assessment/feed assertions.
- [ ] **Step 3: Implement bounded transactional state.** Validate whole affected-claim set before commit. Preserve unit/source tags after internal erasure; no aggregate completeness Boolean. Unknown loss degrades selected claims, exact0 does not; nonzero diagnostic signal degrades without inventing event count. New epoch requires a new ledger. No hidden correction distribution, callback or global state.
- [ ] **Step 4: Run the three tests plus deterministic fault/panic input coverage.** Expect PASS and unchanged pre-error owners. `Eq`/`Clone` panic boundaries follow the spec without `catch_unwind` in production; tests may catch unwind to inspect already-published state. Verify `ClaimLedger`'s safe Rust trait use does not add interior global synchronization; compile-time trait tests respect generic payload constraints.
- [ ] **Step 5: Commit:** `git add crates/scopebase-capture docs/issues/capture/view-isolation.md` then `git commit -m "feat(capture): isolate report views and enforce feed integrity"`.

**Acceptance:** Snapshot overlay and consumed evidence have separate lifetimes; each feed and correction has explicit cardinality/epoch semantics.

## Task CP07: Physical-site alternatives and checked count bounds

**Requirements:** CP-R02/CP-R08/CP-R15. H24/H26, Q04. Depends on CP02.

**Files:** Create `src/bounds.rs`, `tests/alternative_bounds.rs`, issue `docs/issues/capture/alternative-measurements.md`.

**Interfaces:** Produces exact `CandidateCoverage<C>`, `MatchClass`, `SiteCount<C>::new(Epoch,PhysicalSiteId,Count<Events>,CandidateCoverage<C>,usize)`, `classify_alternatives<C>(&SiteCount<C>,&[MatchClass])->Result<CountBounds<Events>,ContractError>`, `combine_disjoint_sites<C>(&[SiteCount<C>],&[CountBounds<Events>])->Result<CountBounds<Events>,ContractError>`.

- [ ] **Step 1: Write `one_physical_count_is_not_duplicated_across_aliases`, `unknown_candidates_cannot_prove_absence`, `all_candidates_vs_mixed_bounds`, `duplicate_site_or_epoch_refuses`.** n=5 alternatives `[A,B]`: classes Definite/Excluded yields `[0,5]`, Definite/Definite `[5,5]`, Excluded/Excluded `[0,0]`, Possible/Definite `[0,5]`; unknown candidates with n0 yields `[0,None]`. Empty complete set and wrong class count refuse. Two distinct exact sites5 and7 combine12; duplicate same site refuses rather than10.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test alternative_bounds`.** Expect FAIL before API exists; alias-per-candidate multiplication control fails the explicit upper/lower assertion.
- [ ] **Step 3: Implement alternatives as bounds on one physical observation.** Check duplicate candidates, limits, site identity and epoch before arithmetic. Unknown upper propagates through combination. Classification meanings remain application supplied; domain taxonomies do not enter the crate.
- [ ] **Step 4: Run the test.** Expect PASS against a separate small-world oracle enumerating which single alternative could have produced each physical count. The oracle never calls production classification. Unknown-as-empty and sum-counter-plus-detail mutants must fail; corrected twin passes.
- [ ] **Step 5: Commit:** `git add crates/scopebase-capture docs/issues/capture/alternative-measurements.md` then `git commit -m "feat(capture): conserve counts across candidate alternatives"`.

**Acceptance:** Alternative measurements cannot be mistaken for additive populations or create a definite/absence conclusion from an unknown candidate set.

## Task CP08: Scoped interval ordering proof

**Requirements:** CP-R09/CP-R15/CP-R18. H24/H27, G17. Depends on CP02/CP05; serialize edits to CP02's `time.rs`.

**Files:** Modify `src/time.rs` sweep section; create `tests/interval_order.rs`, issue `docs/issues/capture/interval-order.md`.

**Interfaces:** Consumes `Timestamp`/`TimeInterval`; produces `EdgeKind::{Release,Acquire}`, `StateEdge::new(at: Timestamp,kind: EdgeKind,sweep_event_id: u64) -> StateEdge`, `SweepProof`, `validate_sweep_order(&[StateEdge])->Result<SweepProof,ContractError>`. Adapters must map `(ObjectKey<K>, generation-local event ordinal)` injectively and stably to IDs unique within each sweep; they never pass a generation-local ordinal as the sweep ID directly. No metric reducer is exported.

- [ ] **Step 1: Write `release_before_acquire_tie_is_valid`, `acquire_before_release_tie_withholds_sweep`, `reordered_edges_do_not_destroy_independent_duration`, `timestamp_zero_is_valid`, `generation_local_zero_ordinals_map_to_distinct_sweep_ids`, `duplicate_sweep_event_id_refuses`.** One generation [0,5) keeps duration5 even if a second generation's delivery violates timestamp order. At tick5 release then acquire is valid; reversed tie order refuses. Clock mismatch and backward tick6→5 refuse. Independent fixture ledger has source events `(generation7,local ordinal0)` at tick1 and `(generation8,local ordinal0)` at tick2; adapter mapping41/42 must produce an accepted sweep. A repeated source event keeps ID41, and a sweep containing ID41 twice returns `DuplicateKey` without changing any independently validated duration. IDs need not increase: distinct IDs42/41 with valid timestamp order also succeed. Empty stream yields an ordering-only proof, never activity/peak support.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test interval_order`.** Expect FAIL before proof API. Arrival-order-as-time and sort-everything controls must fail the explicit ordering assertion.
- [ ] **Step 3: Implement timestamp/tie validation plus sweep-ID duplicate checking.** Do not reorder records or infer timestamp order from numeric IDs. Use an ordered set bounded by admitted edge count, with `O(n log n)` work and `O(n)` duplicate-set storage; duplicate IDs return `DuplicateKey`. In test support, map source-generation/local-event tuples stably to distinct u64 IDs, refusing assignment exhaustion. Keep interval duration independent of sweep state and document that metric reducers need additional generation/loss coverage.
- [ ] **Step 4: Run the test.** Expect PASS; independent expected endpoint ordering comes from fixture intent, not production sort keys. Active non-state facts in the donor-shaped adapter do not invalidate state ordering. A tie-policy mutant and a global-quality-poisoning mutant fail their intended assertions. An adapter mutant using local ordinal0 as the sweep ID for both generations fails the valid two-generation control; a checker mutant accepting ID41 twice fails the true-duplicate assertion. The independent source ledger supplies both tuple identities and expected distinct/repeated correspondence.
- [ ] **Step 5: Commit:** `git add crates/scopebase-capture docs/issues/capture/interval-order.md` then `git commit -m "feat(capture): validate scoped half-open interval order"`.

**Acceptance:** Only the dependent metric loses its proof; timestamp proximity never becomes causal identity.

## Task CP09: Closure evidence profiles and late-evidence countermodels

**Requirements:** CP-R01/CP-R05/CP-R10/CP-R15/CP-R18. H18, G12/G14/G23, Q03. Depends on CP02/CP05.

**Files:** Create `src/closure.rs`, tests `closure_profiles.rs`, `closure_countermodels.rs`, fixture `fixtures/capture/closure-v1.json`, issue `docs/issues/capture/closure-evidence.md`.

**Interfaces:** Produces spec-exact `PredicateId::new`, `BoundarySerial::new`, `ClosureProfile::new(u32,&[PredicateId],&[(PredicateId,PredicateId)],usize)`, `PredicateObservation::new`, `ClosureRecord::{new,observe,invalidate}`, `assess_closure(&ClosureProfile,&ClosureRecord)->Result<ClosureAssessment,ContractError>`, `ClosureGap`. Read-only `ClosureAssessment::{satisfied,missing,invalidated,source}` signatures match the spec, with no authority/complete conversion.

- [ ] **Step 1: Write `cycle_duplicate_and_limit_profiles_refuse`, `baseline_after_admission_cannot_satisfy_profile`, `late_submit_invalidates_drain_and_sample`, `pending_writer_never_supplies_quiescence`, `quiet_detach_does_not_fill_predicates`, `foreign_epoch_or_origin_refuses`.** Freeze local test IDs1=baseline,2=admission,3=closed,4=quiescence,5=drain,6=sample; required edges1<2<3<4<5<6. Full scripted serials1..6 and one source satisfy those reported predicates. Drop4 or place6 before5 leaves prerequisites unsatisfied. Late submit invalidates5 and6; a new record with a later drain/sample attempt can satisfy them. Version0, >64 predicates and a cycle refuse.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test closure_profiles --test closure_countermodels`.** Expect FAIL initially. The “return final on quiet poll” model must fail missing-quiescence/sample assertions while an explicitly weaker bounded-drain profile reports only its own predicates.
- [ ] **Step 3: Implement bounded profile DAG and record checks.** Check common epoch/binding/origin and drain-generation dependencies, duplicate observations, transitive invalidation, ordered serials and failure atomicity. Add source-labeled KryProbe every-slot, MemVeil late-submit and OSSL delayed-hit scripts with explicit model assumptions. No live fence constructor, sleep, polling, detach or universal session state is added.
- [ ] **Step 4: Run the tests.** Expect PASS, including a late admitted event that arrives after a final bounded drain in the countermodel. Independent script ledger supplies predicate occurrences; mutant sample-before-drain, detach-as-quiescence and timeout-as-settled fail at the intended predicate. Model success remains T1 only and preserves live MemVeil settlement as open.
- [ ] **Step 5: Commit:** `git add crates/scopebase-capture fixtures/capture/closure-v1.json docs/issues/capture/closure-evidence.md` then `git commit -m "feat(capture): check scoped closure evidence without runtime authority"`.

**Acceptance:** Missing/late/context-invalid evidence remains visible, startup baseline ordering is checked, and a test/replay record never constructs live authority.

## Task CP10: Canonical neutral validation and strict replay vectors

**Requirements:** CP-R01/CP-R02/CP-R12/CP-R16/CP-R18. H23/H24/H25, G18/G20/G22, Q05. Depends on CP03–CP09; coordinate frozen native seam.

**Files:** Create `src/neutral.rs`, `src/replay.rs`, tests `neutral_validation.rs`, `strict_replay.rs`, `fixtures/capture/replay-v1/{vectors.jsonl,expected.jsonl,README.md}`; optional fuzz target `fuzz/fuzz_targets/capture_replay.rs` via TT06; issue `docs/issues/capture/strict-replay.md`.

**Interfaces:** Core exports `neutral::validate_v1(&NeutralObservationV1,NeutralLimits)->Result<ValidatedNeutralV1,ContractError>` and exact spec raw input/validated accessor types. `NeutralLimits::default()` = counters4,096/claims4,096/reasons16, also hard maxima. Feature `json` exports exact `ReplayLimits`, raw `ReplayRecord`/`ReplayValue`/`ReplayTerminal`, opaque `ReplayDocument::{new,records,binding,origin}`, `ReplayError::{kind,offset}`, `decode(&[u8],ReplayLimits)->Result<ReplayDocument,ReplayError>`, `encode(&ReplayDocument)->Result<Vec<u8>,ReplayError>`. Native v1 byte codec stays native-owned; capture is the sole neutral semantic validator.

- [ ] **Step 1: Write `neutral_known_zero_and_unknown_differ`, `neutral_count_limit_precedes_clone`, `duplicate_channels_claims_or_reasons_refuse`, `signal_unit_mismatch_refuses`, `precision_u64_max_and_overflow`, `nested_duplicate_members_refuse`, `bool_nan_and_bad_decimal_refuse`, `duplicate_missing_or_nonfinal_terminal_refuses`, `constructors_and_replay_agree`, `synthetic_origin_cannot_promote`.** Exact valid count strings: `"9007199254740993"`, `"18446744073709551615"`; invalid: `"18446744073709551616"`, `"01"`, `"+1"`, true,1.5. Reject duplicate member at nested source/counter/terminal depth, newline-suffixed binding, mixed epochs, partition9≠2+3+5, correction0→2 and records after terminal. At max records4,096 succeeds if semantically valid;4,097 refuses before buffer growth.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --no-default-features --test neutral_validation` and `cargo test -p scopebase-capture --features json --test strict_replay`.** Expect missing-code FAIL; last-member-wins and floating-count controls must later fail specific duplicate/precision diagnostics rather than setup.
- [ ] **Step 3: Implement neutral validation, then bounded streaming replay validation.** Exact-v1 source and unit semantics call existing constructors; neutral source/counter/claim accessors provide immutable SDK metadata only. JSON checks duplicate members before map construction; limits precede DOM/collection growth; terminal inventories refer to unique prior records; schema/version and origin stay explicit. Installed replay limits are bytes1,048,576/records4,096/nesting16/items4,096/string256. No raw payload in ReplayError. No encode/decode self-roundtrip is the sole oracle.
- [ ] **Step 4: Run both suites and `cargo test -p scopebase-capture --features json --doc`.** Expect PASS against independently hand-authored expected outcomes; test every truncation boundary of each small valid vector, with only the full vector accepted. Bounded fuzz campaign uses seed corpus and recorded bounds through TT06, never a limitless release gate. Mutants dropping synthetic flag, defaulting missing loss0 or accepting duplicate terminals must fail their named semantic assertion. Verify no stdout/stderr output from library calls in an owned subprocess.
- [ ] **Step 5: Commit:** `git add crates/scopebase-capture fixtures/capture/replay-v1 docs/issues/capture/strict-replay.md` then `git commit -m "feat(capture): validate neutral evidence and strict replay"`.

**Acceptance:** Public constructors, strict neutral replay and native semantic seam agree; framing/byte preallocation in FFI remains the native adapter's obligation, not a claimed capture feature.

## Task CP11: Independent real consumers, examples and correction holders

**Requirements:** CP-R07–CP-R09/CP-R11/CP-R13/CP-R16/CP-R17. Q04, T06/T07, UC14. Depends on CP10 and TT01/TT02.

**Files:** Create separate standalone `Cargo.toml`, `src/main.rs`, `src/adapter.rs`, `tests/consumer_contract.rs` under each `consumers/capture-{kryprobe,memveil,ossl}-reference/`; create `examples/{provenance_fold,bounded_counts,partial_views,closure_assessment,replay_check}.rs`; issue `docs/issues/capture/consumer-seams.md`. Testkit adapter glue is handed to its single owner.

**Interfaces:** Each consumer implements `ConformanceAdapter::subject(&self)->SubjectBinding` and `execute(&mut self,&CaseInvocation,&FixtureAccess)->Result<Observation,CaseError>`. Subject names the consumer's resolved production package/features/build/backend; observation is schema-tagged bounded actual bytes, never expected truth. KryProbe-shaped adapter composes insertion/counter/loss primitives; MemVeil-shaped adapter composes independent fact claims/generation/interval/views; OSSL-shaped adapter composes alternative bounds and versioned late corrections. The independent oracle lives in testkit and never reuses their reducers.

- [ ] **Step 1: Write `kryprobe_shaped_fold_and_loss`, `memveil_shaped_independent_facts_and_views`, `ossl_shaped_shared_site_bounds`, `dropped_correction_holder_is_detected`.** Shared operation script independently records10 events, one unknown mapping ID,5 copy bytes, one missing release relationship and one partial query. Assert copy bytes5 survive occupancy uncertainty; query partial disappears in the next view; actual loss persists. For late contradiction replacement revision1, both report and export holders must equal independently expected revision1, while an intentional dropped export update fails that holder assertion.
- [ ] **Step 2: Run each `cargo test --manifest-path consumers/capture-<name>-reference/Cargo.toml --test consumer_contract` for names `kryprobe`, `memveil`, `ossl`.** Initially FAIL because consumers/adapters do not exist. Testkit expected populations include nonempty admitted and actively excluded known operation IDs; no all-zero script can qualify.
- [ ] **Step 3: Implement the three materially different standalone consumers and examples.** Consume exact packaged production code, use independent Cargo lockfiles, and keep source-level product-shaped selectors/reducers in their adapters. Examples must explain unknown versus zero, record closure provenance and avoid global completeness. Document actual future product call sites and later MG requirements without changing donor source or claiming migration/duplicate retirement.
- [ ] **Step 4: Run all three suites and `cargo test -p scopebase-capture --all-targets --features json`.** Expect PASS against independent fixture intent. Erased generation, merged activity/loss, permanently tainted view, alias multiplication, missing required feed and dropped correction mutants must fail semantic assertions after nonempty setup; restored valid twins pass. Require at least two materially different real standalone consumer builds; a mirror reducer or testkit's own library copy does not count.
- [ ] **Step 5: Commit:** `git add consumers crates/scopebase-capture/examples docs/issues/capture/consumer-seams.md` then `git commit -m "test(capture): add independent standalone reference consumers"`.

**Acceptance:** Independent examples and actual resolved-code consumers exist; KryProbe/OSSLscope/MemVeil/p11scope integrations remain explicitly LATER. No product policy is normalized away for equality.

## Task CP12: Cross-stage reservation evaluation with a gated internal pilot

**Requirements:** CP-R14/CP-R15/CP-R18. Q06, G04/G05/G07/G09/G10, T02/T04/T06. Depends on CP06/CP11 and refreshed accepted shared-ledger candidate; no stable production API is presumed.

**Files:** Create `tests/support/reservation_pilot.rs`, `tests/reservation_evaluation.rs`, `docs/issues/capture/reservation-evaluation.md`; bounded stage-pipeline modules in the two standalone consumers by agreement with CP11 owner. Do not export from `lib.rs` or add a production feature.

**Interfaces:** Internal test-only `StageId(u8)`, `PilotBudget::new(count_limit:u64,byte_limit:Option<u64>)->Result<Self,ContractError>`, `reserve(&mut self,count:u64,bytes:u64)->Result<Reservation,ContractError>`, consuming `Reservation::transfer(self,stage:StageId)->Result<Reservation,(Reservation,ContractError)>`, and explicit ticket retirement mediated by its owning ledger. Choose one ledger owner; no `Arc<Mutex>` or `Send`/`Sync` promise by convenience. Stage moves carry the payload storage charge until its actual last owner drops. This interface is a pilot experiment, not the selected public API.

**Mandatory source decision:** Select the actual accepted shared-ledger successor and source/regression hashes after CP06/CP11; the current intake has no selected source for this task. If absent or unsuitable, execute the stated evaluation and document the internal/product-local outcome. Do not silently create a stable replacement abstraction.

- [ ] **Step 1: Write `one_global_budget_across_stages`, `failed_transfer_returns_same_charge`, `cancel_refunds_only_after_payload_retired`, `shared_clone_not_double_charged`, `independent_copy_is_charged`, `absent_byte_limit_cannot_claim_memory_bound`.** Limit count2/bytes16: two8-byte payloads succeed, third1-byte payload refuses; staging→retained keeps total16; failed transfer leaves16; shared clone leaves16; an independent8-byte copy refuses while full. Count-only pilot reports byte guarantee unknown. Record peak overlap when a conversion temporarily holds input+output.
- [ ] **Step 2: Run `cargo test -p scopebase-capture --test reservation_evaluation`.** Expect missing-pilot FAIL; independent per-stage budgets and early-refund mutants must fail literal global peak/retained-charge assertions after real payload allocation, not setup crashes.
- [ ] **Step 3: Implement the bounded internal pilot and two real consumer-stage experiments.** Compare existing channel/semaphore primitives against accepted donor successor before inventing a production abstraction. Independent oracle enumerates live payload allocations/last owners; it does not read budget totals to calculate expected charge. Exercise failure before/after transfer, repeated cleanup, cancellation, panic and u64 overflow; one clear owner/custody record survives each case.
- [ ] **Step 4: Run the suite and both consumer stage tests.** Expect PASS for conservation and explicit limitations. Write decision `accept-for-separate-public-design` or `retain-internal/defer-stable-export` with concrete two-consumer fit, counted/retained/peak-byte distinctions, allocator/OOM/traits and alternatives. Either decision completes this evaluation requirement; only a reviewed subsequent API design can promote a stable reservation module. This does not excuse missing core capture work.
- [ ] **Step 5: Commit:** `git add crates/scopebase-capture/tests consumers docs/issues/capture/reservation-evaluation.md` then `git commit -m "test(capture): evaluate conserved cross-stage reservations"`.

**Acceptance:** A reproducible evidence-backed extraction decision exists; no `byte_limit=None`, cardinality bound or timeout is marketed as a memory/retirement bound.

## Task CP13: Packaged conformance, installed operator route and release gate

**Requirements:** CP-R15–CP-R18 and final coverage of CP-R01–CP-R14. F04/F05, T01–T07, UC14, G18–G20/G22. Depends on CP11/CP12 and applicable TT01/TT02/TT06/TT07/TT08/TT09/TT10; no Linux live suite dependency.

**Files:** Coordinate/create `crates/scopebase-testkit/src/capture/{mod,adapter_cases,oracle}.rs`, `fixtures/capture/manifest.json`, `tools/check-capture-package.py`, `docs/issues/capture/{qualification-profile,release-checklist}.md`; modify capture README and shared package lists through their owners. Test `crates/scopebase-testkit/tests/capture_installed.rs`.

**Interfaces:** The initial planning references are `capture-core-v1` and `capture-json-v1`; CP13 asserts the literal controller-selected successor pair and complete literal required closure from CP02–CP11, with strict replay in the JSON profile when advertised. Preserve each old v1 ID and definition; old-v1 results cannot discharge successor requirements. The native profile separately maps the same neutral semantics and receives a successor if its recorded required closure changes. The installed route uses the literal controller-selected core successor: `scopebase-conformance run --profile <selected-core-successor> --fixture-root <installed-dir> --output <writable-dir>`; TT07 owns CLI dispatch/exit protocol; optional `--fixture-manifest PATH` selects the manifest explicitly. These are canonical runnable ProfileIds, never aliases or “latest”; expected versions/closure are not derived from candidate data. Register case/profile IDs through TT01 constructors: first character ASCII alphanumeric, remainder ASCII alphanumeric/dot/underscore/hyphen, no slash, CaseId maximum 96 bytes and ProfileId maximum 64 bytes. No local alternative parser or slash-bearing selector is permitted. Artifacts bind subject package/source/features/backend, suite/schema, fixture digests and executable identity, not the testkit's separately linked package. Invocation/observation use the frozen `ConformanceAdapter` seam.

- [ ] **Step 1: Write `source_archive_has_complete_capture_closure`, `installed_two_consumers_use_subject_bindings`, `required_case_omission_is_incomplete`, `wrong_subject_or_fixture_is_rejected`, `zero_positive_population_is_not_success`, `zero_exit_cannot_erase_semantic_failure`, `capture_profile_ids_follow_registry_grammar`.** Assert the literal controller-selected successor pair and complete literal required closure; do not derive expected versions or denominators from the candidate manifest. Old v1 cannot satisfy successor requests; unknown versions and alias/“latest” requests reject. All selected CaseIds/ProfileIds pass the shared TT01 grammar/length constructors. Freeze the expected successor IDs before fixture discovery; test duplicate terminals, wrong build binding, mismatched fixture digest, missing required case/component, untriggered positive and unresolved cleanup controls. Correct refusal may pass its assertion while capability/coverage remain separately unknown/incomplete.
- [ ] **Step 2: Run `cargo test -p scopebase-testkit --test capture_installed`.** Initially FAIL on missing capture registration/package closure. A source-free installed route must later reject a wrong-subject mutant even when its semver matches the testkit's own library.
- [ ] **Step 3: Package production code, neutral fixtures, independent oracles, developer adapter API and installed offline runner.** `cargo package --list -p scopebase-capture --allow-dirty` must include only intended public closure/notices; no private donor archives. Build source archives and two standalone consumers with independent lockfiles outside the repo; install read-only binaries/fixtures and run with writable separate output, source/compiler/network absent. Use TT07 package tooling to arrange the sandbox rather than ad hoc host policy changes.
- [ ] **Step 4: Run final affected commands once on unchanged candidate bytes:** `cargo test -p scopebase-capture --no-default-features --all-targets`; `cargo test -p scopebase-capture --features json --all-targets`; `cargo test -p scopebase-capture --features json --doc`; `cargo test -p scopebase-testkit --test capture_installed`; `python3 tools/check-capture-package.py --profile <selected-core-successor> --offline`. The literal selected successor is recorded with the test expectations before discovery; the initial `capture-core-v1` example cannot discharge it. Also run SB02's declared MSRV/default/union/cross-host package cells and TT07's source-free two-consumer route. Expect every required assertion PASS, compatible exact subject/fixtures, nonempty populations and clean owned resources. Preserve FAIL/ERROR/BLOCKED/NOT_RUN distinctions; no environment-driven deselection or endless reruns. Complete CP-R → case → candidate result matrix, not only a count of passing tests.
- [ ] **Step 5: Review full requirement mapping and commit:** `git add crates/scopebase-capture crates/scopebase-testkit fixtures/capture tools/check-capture-package.py docs/issues/capture` then `git commit -m "test(capture): ship exact-consumer offline conformance"`.

**Acceptance / definition of done:** Every CP-R01–CP-R18 has its production/evaluation artifact, independent expected truth, semantic bad-control failure/restored twin, packaged runnable case and exact candidate result. Pure/package claims have evidence at their actual tiers; source-only donor tests and historical receipts remain references. At least two independent actual standalone installed consumers exercise distinct semantics. Default/json/MSRV/feature union/docs/package tests pass on declared hosts, no hidden BPF/compiler dependency exists, notices are preserved, and no product migration/live gate is falsely closed. Reservation's stable-export decision is explicit. Product migrations and duplicate retirement happen only in later master MG01–MG05 tasks against changed donor tips.

## Affected-check and completion rules

Changed arithmetic/domain/representation triggers CP02–CP10 callers; changed sample/epoch policy triggers CP03/CP04/CP06/CP09/CP10/CP11. Changed views or correction semantics triggers CP06/CP08/CP11. Changed optional dependency/features/schema/oracle/fixture invokes the relevant semantic suite plus CP10/CP11/CP13 packaging and subject-binding checks. Native translation changes must reach the shared neutral validator and its native consumer tests, without claiming producer behavior. A model-only change never obliges arbitrary privileged stress runs; a later BP producer change does oblige its own final-object/live cells. Testkit/oracle modifications invalidate results that depended on those bytes. Broaden checks only for a named uncertainty, changed input or failure.

No task can declare a required case passing from inspection alone. Missing required fixtures, assertion setup failure, incomplete closure, unresolved cleanup, wrong binding and an empty required population prevent qualification. A narrowed successful profile is named as such. Ordinary unit tests need reproducible diagnostics; compact release/support receipts keep source/build/suite/features, fixture/op IDs, limits, expected/observed populations and selected cleanup evidence, without automatic upload or bulk private transcripts.

## Self-review and implementation handoff

- [x] CP-R01–CP-R18 each maps to named tasks and a final CP13 gate; H/UC/G/TODO references retain original IDs.
- [x] Exact public signatures are centralized in the spec; consuming tasks name those interfaces, and time base precedes sample/sweep consumers.
- [x] Known-bad controls reach the semantic assertion and have restored valid twins; roundtrips/model mirrors alone are not truth.
- [x] Five review-focus risks have explicit tests in their owning tasks; JSON/native byte limits and reservation limits have distinct owners.
- [x] Package qualification uses actual independent standalone consumers; product migrations and producer/live evidence stay later/separate.
- [x] No code, product test, live environment, commit or release was executed to write this plan.

This task delivers the requested specification and plan only. Implementation requires the selected execution workflow and the reviewed contract; this document does not request or imply a new approval flow for documentation already authorized.
