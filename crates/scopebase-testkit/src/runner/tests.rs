// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};
#[path = "../../tests/fixtures/harness/support.rs"]
mod support;
use support::instrumented as ins;
struct Deterministic {
    base: Instant,
    ns: Rc<Cell<u64>>,
    charges: Rc<RefCell<VecDeque<u64>>>,
}
impl Deterministic {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            ns: Rc::new(Cell::new(0)),
            charges: Rc::new(RefCell::new(VecDeque::new())),
        }
    }
}
impl Clock for Deterministic {
    fn now(&self) -> Instant {
        let delta = self.charges.borrow_mut().pop_front().unwrap_or(1);
        self.ns.set(self.ns.get() + delta);
        self.base + Duration::from_nanos(self.ns.get())
    }
}
struct TimedSession<'a> {
    inner: ins::Session<'a>,
    clock: Rc<Cell<u64>>,
    contract_ns: u64,
    acquire_ns: u64,
    retire_requests: Vec<(u64, Instant, Duration)>,
}
impl FixtureSession for TimedSession<'_> {
    fn contract(&self) -> &RunContract {
        self.clock.set(self.clock.get() + self.contract_ns);
        self.inner.contract()
    }
    fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static> {
        self.clock.set(self.clock.get() + self.acquire_ns);
        self.inner.cancellation_probe()
    }
    fn prepare(&mut self, i: &CaseInvocation) -> Result<FixtureAccess<'_>, FixtureError> {
        self.inner.prepare(i)
    }
    fn collect(&mut self, i: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError> {
        self.inner.collect(i)
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        self.retire_requests
            .push((r.call_id(), r.deadline(), r.remaining()));
        self.inner.retire(r)
    }
}
struct TimedAdapter {
    inner: ins::Adapter,
    clock: Rc<Cell<u64>>,
    retire_ns: u64,
    bookkeeping: Option<Rc<RefCell<VecDeque<u64>>>>,
    requests: Vec<(u64, Instant, Duration)>,
}
impl ConformanceAdapter for TimedAdapter {
    fn subject(&self) -> SubjectBinding {
        self.inner.subject()
    }
    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        self.inner.execute(i, f)
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        self.requests
            .push((r.call_id(), r.deadline(), r.remaining()));
        self.clock.set(self.clock.get() + self.retire_ns);
        let result = self.inner.retire(r);
        if let Some(q) = &self.bookkeeping {
            q.borrow_mut().extend([1, 2_000_000]);
        }
        result
    }
}
fn setup(
    clock: &Deterministic,
) -> (
    ProfilePlan,
    TimedSession<'static>,
    TimedAdapter,
    support::oracle::ArithmeticOracle,
) {
    let (_, p, _) = support::load();
    let mut v = support::contract_value();
    v["limits"]["retirement_ms"] = "1".into();
    v["case_rules"][0]["max_effects"] = 2.into();
    let c = support::changed_contract(&v);
    let inner = ins::Session::new(c.clone());
    let adapter = ins::adapter(&inner);
    (
        p,
        TimedSession {
            inner,
            clock: clock.ns.clone(),
            contract_ns: 0,
            acquire_ns: 0,
            retire_requests: vec![],
        },
        TimedAdapter {
            inner: adapter,
            clock: clock.ns.clone(),
            retire_ns: 0,
            bookkeeping: None,
            requests: vec![],
        },
        support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        },
    )
}
#[test]
fn retirement_budget_is_cumulative() {
    let clock = Deterministic::new();
    let (p, mut s, mut a, o) = setup(&clock);
    a.retire_ns = 100_000;
    let r = run_with_clock(&p, &mut a, &mut s, &o, &clock).unwrap();
    assert_eq!(r.qualification(), Qualification::Qualified);
    assert_eq!(a.requests[0].1, s.retire_requests[0].1);
    assert!(a.requests[1].2 < a.requests[0].2);
    let clock = Deterministic::new();
    let (p, mut s, mut a, o) = setup(&clock);
    s.inner.effect = true;
    s.inner.mode = ins::Retirement::Pending;
    a.retire_ns = 2_000_000;
    let r = run_with_clock(&p, &mut a, &mut s, &o, &clock).unwrap();
    assert_eq!(r.qualification(), Qualification::Incomplete);
    assert_eq!(a.requests.len(), 1);
    assert!(s.retire_requests.is_empty());
    assert_eq!(
        *r.cleanup_records()[0].status(),
        CleanupCallStatus::CalledOverBudget
    );
    assert_eq!(
        *r.cleanup_records()[1].status(),
        CleanupCallStatus::UncalledBudgetExhausted
    );
    assert_eq!(
        *r.cleanup_records()[3].status(),
        CleanupCallStatus::UncalledBudgetExhausted
    );
    assert_eq!(
        *r.cleanup_records()[1].state_at_run_end(),
        CleanupState::Unresolved
    );
    let clock = Deterministic::new();
    let (p, mut s, mut a, o) = setup(&clock);
    a.bookkeeping = Some(clock.charges.clone());
    let r = run_with_clock(&p, &mut a, &mut s, &o, &clock).unwrap();
    assert_eq!(*r.cleanup_records()[0].status(), CleanupCallStatus::Called);
    assert_eq!(
        *r.cleanup_records()[1].status(),
        CleanupCallStatus::UncalledBudgetExhausted
    );
    assert_eq!(r.qualification(), Qualification::Incomplete);
}
#[test]
fn review_b4_request_preparation_uses_the_actual_hook_entry() {
    struct Delayed {
        inner: TimedAdapter,
        charges: Rc<RefCell<VecDeque<u64>>>,
        delay: u64,
    }
    impl ConformanceAdapter for Delayed {
        fn subject(&self) -> SubjectBinding {
            self.inner.subject()
        }
        fn execute(
            &mut self,
            i: &CaseInvocation,
            f: &FixtureAccess<'_>,
        ) -> Result<Observation, CaseError> {
            let o = self.inner.execute(i, f)?;
            let result = Observation::new(
                ObservationValues {
                    key: o.key().clone(),
                    schema_id: o.schema_id().clone(),
                    schema_revision: *o.schema_revision(),
                    completed_steps: o.completed_steps().clone(),
                    bytes: o.bytes().clone(),
                    effects: EffectBatch::new(
                        EffectBatchValues {
                            registrations: vec![EffectRegistration::new(
                                EffectRegistrationValues {
                                    resource_id: ins::label("adapter.R"),
                                    owner: Owner::Adapter,
                                    origin: i.key().clone(),
                                    kind: ins::label("state"),
                                    identity_sha256: Digest256::of_bytes(b"adapter resource"),
                                    recovery_evidence_id: None,
                                },
                                i.limits(),
                            )
                            .unwrap()],
                            complete: true,
                        },
                        i.limits(),
                    )
                    .unwrap(),
                },
                i.limits(),
            )
            .unwrap();
            self.charges
                .borrow_mut()
                .extend(std::iter::repeat(1).take(12).chain([self.delay]));
            Ok(result)
        }
        fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
            self.inner.retire(r)
        }
    }
    for late in [true, false] {
        let clock = Deterministic::new();
        let (p, mut s, mut inner, o) = setup(&clock);
        let c = s.inner.c.clone();
        s.inner.effect = true;
        s.inner.mode = if late {
            ins::Retirement::Pending
        } else {
            ins::Retirement::Now
        };
        inner.inner.mode = ins::Retirement::Now;
        inner.retire_ns = if late { 600_000 } else { 100_000 };
        let mut a = Delayed {
            inner,
            charges: clock.charges.clone(),
            delay: if late { 500_000 } else { 1 },
        };
        let r = run_with_clock(&p, &mut a, &mut s, &o, &clock)
            .expect("honest preparation delay must not produce an impossible hook interval");
        assert!(
            !r.cleanup_records()[0].transition_ids().is_empty(),
            "returned transition survives deadline"
        );
        if late {
            assert_eq!(r.qualification(), Qualification::Incomplete);
            assert_eq!(
                *r.cleanup_records()[0].status(),
                CleanupCallStatus::CalledOverBudget
            );
            assert_eq!(
                *r.cleanup_records()[1].status(),
                CleanupCallStatus::UncalledBudgetExhausted
            );
            assert_eq!(
                *r.cleanup_records()[1].state_at_run_end(),
                CleanupState::Unresolved
            );
            assert!(
                r.cleanup_records()[0].hook_elapsed_ns()
                    > r.cleanup_records()[0].remaining_before_ns()
            );
        } else {
            assert_eq!(r.qualification(), Qualification::Qualified);
        }
        let bytes = r.to_json(c.limits().clone()).unwrap();
        assert_eq!(
            RunReport::from_json(&c, &bytes, c.limits().clone())
                .unwrap()
                .qualification(),
            r.qualification()
        );
    }
}
#[test]
fn review_b5_prepare_mirror_reserves_before_copy_and_retains_custody() {
    let clock = Deterministic::new();
    let (_, s, _, _) = setup(&clock);
    let c = s.inner.c.clone();
    let key = c.schedule()[0].clone();
    let batch = EffectBatch::new(
        EffectBatchValues {
            registrations: vec![EffectRegistration::new(
                EffectRegistrationValues {
                    resource_id: ins::label("fixture.R"),
                    owner: Owner::Fixture,
                    origin: key.clone(),
                    kind: ins::label("state"),
                    identity_sha256: Digest256::of_bytes(b"known resource"),
                    recovery_evidence_id: None,
                },
                c.limits(),
            )
            .unwrap()],
            complete: true,
        },
        c.limits(),
    )
    .unwrap();
    for full in [true, false] {
        let used = if full {
            c.limits().retained_bytes() - 1
        } else {
            c.0.reservation
        };
        let probe = || false;
        let mut e = Engine {
            c: c.clone(),
            entry: clock.base,
            clock: &clock,
            probe: &probe,
            stopped: false,
            invalid: None,
            ledger: Ledger::default(),
            closed: Duration::ZERO,
            records: vec![],
            used,
            last_elapsed: 0,
        };
        e.ledger.participants.insert((Owner::Fixture, key.clone()));
        let mirror = e.capture_batch(&key, EnteredStage::Prepare, &batch);
        assert_eq!(
            e.ledger
                .pending(Owner::Fixture, &CleanupScope::Case(key.clone()))
                .len(),
            1,
            "known custody survives copy refusal"
        );
        if full {
            assert!(
                mirror.is_none(),
                "prepare mirror must reserve before cloning"
            );
            assert_eq!(e.used, used);
            assert!(e.invalid.is_some());
            assert!(!e
                .ledger
                .uncertainty(Owner::Fixture, &CleanupScope::Case(key.clone()))
                .is_empty());
        } else {
            assert_eq!(mirror.as_ref(), Some(&batch));
            assert!(e.used > used);
            assert!(e.invalid.is_none());
        }
    }
}
#[test]
fn probe_acquisition_time_is_in_after_contract() {
    for contract_late in [true, false] {
        let clock = Deterministic::new();
        let (p, mut s, mut a, o) = setup(&clock);
        if contract_late {
            s.contract_ns = 30_000_000_000
        } else {
            s.acquire_ns = 30_000_000_000
        }
        let c = s.inner.c.clone();
        let r = run_with_clock(&p, &mut a, &mut s, &o, &clock).unwrap();
        assert_eq!(s.inner.acquisitions, usize::from(!contract_late));
        assert_eq!(s.inner.polls.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(r.qualification(), Qualification::Incomplete);
        assert!(
            matches!(r.runner_observations().after_contract(),CheckpointSlot::Sampled{sample}if *sample.cancelled()==None&&sample.poll_started_elapsed_ns()==sample.poll_finished_elapsed_ns())
        );
        let b = r.to_json(c.limits().clone()).unwrap();
        assert_eq!(
            RunReport::from_json(&c, &b, c.limits().clone())
                .unwrap()
                .qualification(),
            Qualification::Incomplete
        );
    }
}

#[test]
fn elapsed_overflow_preserves_returned_outcome_without_timestamp() {
    struct JumpClock {
        base: Instant,
        jumped: Rc<Cell<bool>>,
    }
    impl Clock for JumpClock {
        fn now(&self) -> Instant {
            self.base
                + if self.jumped.get() {
                    Duration::from_secs(u64::MAX / 1_000_000_000 + 1)
                } else {
                    Duration::ZERO
                }
        }
    }
    struct JumpAdapter {
        inner: ins::Adapter,
        jumped: Rc<Cell<bool>>,
    }
    impl ConformanceAdapter for JumpAdapter {
        fn subject(&self) -> SubjectBinding {
            self.inner.subject()
        }
        fn execute(
            &mut self,
            i: &CaseInvocation,
            f: &FixtureAccess<'_>,
        ) -> Result<Observation, CaseError> {
            let outcome = self.inner.execute(i, f);
            self.jumped.set(true);
            outcome
        }
        fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
            self.inner.retire(r)
        }
    }
    let (_, p, c) = support::load();
    let mut s = ins::Session::new(c.clone());
    let jumped = Rc::new(Cell::new(false));
    let clock = JumpClock {
        base: Instant::now(),
        jumped: jumped.clone(),
    };
    let mut a = JumpAdapter {
        inner: ins::adapter(&s),
        jumped,
    };
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let error = run_with_clock(&p, &mut a, &mut s, &o, &clock).unwrap_err();
    assert_eq!(error.kind(), HarnessErrorKind::LimitExceeded);
    let partial = error.partial_report().expect("retained error report");
    assert_ne!(partial.qualification(), Qualification::Qualified);
    assert!(partial.case_results()[0].outcome().is_some());
    assert!(matches!(
        partial.case_results()[0]
            .execution_checkpoints()
            .execute()
            .after(),
        CheckpointSlot::NotRecorded
    ));
    assert!(
        partial
            .cleanup_records()
            .iter()
            .filter(|r| matches!(r.status(), CleanupCallStatus::Called))
            .count()
            >= 2
    );
    let json = partial.to_json(c.limits().clone()).unwrap();
    assert!(
        !String::from_utf8(json)
            .unwrap()
            .contains("18446744073709551615"),
        "no fabricated saturated timestamp"
    );
}

#[test]
fn review_b5_retirement_raw_response_obeys_remaining_payload() {
    struct Verbose(ins::Adapter);
    impl ConformanceAdapter for Verbose {
        fn subject(&self) -> SubjectBinding {
            self.0.subject()
        }
        fn execute(
            &mut self,
            i: &CaseInvocation,
            f: &FixtureAccess<'_>,
        ) -> Result<Observation, CaseError> {
            self.0.execute(i, f)
        }
        fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
            RetirementReport::new(
                RetirementReportValues {
                    call_id: r.call_id(),
                    owner: r.owner(),
                    scope: r.scope().clone(),
                    discovered: vec![],
                    transitions: vec![],
                    pending_snapshot: vec![],
                    complete: true,
                    diagnostic: Some("d".repeat(65_536)),
                },
                &RunLimits::default(),
            )
            .unwrap()
        }
    }
    let clock = Deterministic::new();
    let (_, mut s, a, _) = setup(&clock);
    let c = s.inner.c.clone();
    let key = c.schedule()[0].clone();
    let mut a = Verbose(a.inner);
    for full in [true, false] {
        let used = if full {
            c.limits().retained_bytes() - 1
        } else {
            c.0.reservation
        };
        let probe = || false;
        let mut e = Engine {
            c: c.clone(),
            entry: clock.base,
            clock: &clock,
            probe: &probe,
            stopped: false,
            invalid: None,
            ledger: Ledger::default(),
            closed: Duration::ZERO,
            records: vec![],
            used,
            last_elapsed: 0,
        };
        e.ledger.participants.insert((Owner::Adapter, key.clone()));
        e.phase(0, &mut LegacyRoute(&mut a), &mut s);
        if full {
            assert!(
                e.records[0].response.is_none(),
                "unretained retirement diagnostic must not remain owned in the partial wire"
            );
            assert!(e.invalid.is_some());
            assert!(!e
                .ledger
                .uncertainty(Owner::Adapter, &CleanupScope::Case(key.clone()))
                .is_empty());
        } else {
            assert!(e.records[0].response.is_some());
            assert!(e.invalid.is_none());
        }
    }
}

#[test]
fn review_a1_retirement_error_diagnostic_fits_selected_limit() {
    struct Verbose(ins::Adapter);
    impl ConformanceAdapter for Verbose {
        fn subject(&self) -> SubjectBinding {
            self.0.subject()
        }
        fn execute(
            &mut self,
            i: &CaseInvocation,
            f: &FixtureAccess<'_>,
        ) -> Result<Observation, CaseError> {
            self.0.execute(i, f)
        }
        fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
            RetirementReport::new(
                RetirementReportValues {
                    call_id: r.call_id(),
                    owner: r.owner(),
                    scope: r.scope().clone(),
                    discovered: vec![],
                    transitions: vec![],
                    pending_snapshot: vec![],
                    complete: true,
                    diagnostic: Some("d".repeat(65_536)),
                },
                &RunLimits::default(),
            )
            .unwrap()
        }
    }
    let clock = Deterministic::new();
    let (_, mut s, a, _) = setup(&clock);
    let mut cv = support::contract_value();
    cv["limits"]["diagnostic_bytes"] = "41".into();
    let c = support::changed_contract(&cv);
    s.inner.c = c.clone();
    let key = c.schedule()[0].clone();
    let mut a = Verbose(a.inner);
    let probe = || false;
    let mut e = Engine {
        c: c.clone(),
        entry: clock.base,
        clock: &clock,
        probe: &probe,
        stopped: false,
        invalid: None,
        ledger: Ledger::default(),
        closed: Duration::ZERO,
        records: vec![],
        used: c.0.reservation,
        last_elapsed: 0,
    };
    e.ledger.participants.insert((Owner::Adapter, key.clone()));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.phase(0, &mut LegacyRoute(&mut a), &mut s)
    }));
    assert!(
        result.is_ok(),
        "selected retirement diagnostics must be representable without a panic"
    );
    assert!(e.invalid.is_some());
    assert!(e.records[0].error.as_ref().unwrap().diagnostic().len() <= 41);
}

#[test]
fn prp01_response_budget_counts_spare_and_checked_overflow() {
    use crate::prepared::{
        ResponseBudget, ResponsePreparationComponent as Part,
        ResponsePreparationFailureKind as Kind,
    };
    let mut b = ResponseBudget::new(64, 100).unwrap();
    b.reserve_minimum(16, Part::CellId).unwrap();
    let error = b.observe_capacity(16, 48, Part::CellId).unwrap_err();
    assert_eq!(error.kind, Kind::CapacityExceeded);
    assert_eq!(error.component, Part::CellId);
    assert_eq!(error.requested_bytes, Some(16));
    assert_eq!(error.observed_bytes, Some(112));
    let mut b = ResponseBudget::new(64, 112).unwrap();
    b.reserve_minimum(16, Part::CellId).unwrap();
    b.observe_capacity(16, 48, Part::CellId).unwrap();
    assert_eq!(b.used(), 112);
    let mut b = ResponseBudget::new(usize::MAX - 1, usize::MAX).unwrap();
    let error = b.reserve_minimum(2, Part::Total).unwrap_err();
    assert_eq!(error.kind, Kind::Overflow);
    assert_eq!(error.component, Part::Total);
    assert_eq!(error.requested_bytes, Some(2));
    assert_eq!(error.observed_bytes, None);
}

#[test]
fn prp02_owned_key_real_overgrant_has_no_fallback() {
    use crate::prepared::ResponseBudget;
    use crate::{ResponsePreparationComponent as Part, ResponsePreparationFailureKind as Kind};
    let (_, _, c) = support::load();
    let source = &c.schedule()[0];
    for (excess_at, component) in [(0, Part::RunId), (1, Part::CaseId), (2, Part::CellId)] {
        let mut attempts = 0;
        let mut capacities = vec![];
        let mut allocate = |minimum: usize| {
            let mut text = String::new();
            let request = if attempts == excess_at {
                minimum + 128
            } else {
                minimum
            };
            text.try_reserve_exact(request).map_err(|_| ())?;
            capacities.push(text.capacity());
            attempts += 1;
            Ok(text)
        };
        let mut b = ResponseBudget::new(0, 64).unwrap();
        let error =
            crate::ids::rsp01_copy_key_with(source, c.limits(), &mut b, &mut allocate).unwrap_err();
        assert_eq!(error.kind, Kind::CapacityExceeded);
        assert_eq!(error.component, component);
        assert_eq!(error.observed_bytes, Some(capacities.iter().sum()));
        assert_eq!(
            attempts,
            excess_at + 1,
            "capacity refusal must never attempt a fresh fallback key"
        );
    }
    let mut b = ResponseBudget::new(0, 4096).unwrap();
    assert_eq!(
        crate::ids::rsp01_copy_key(source, c.limits(), &mut b).unwrap(),
        *source
    );
}
#[test]
fn prp03_copy_allocation_refusal_and_original_cell_grammar() {
    use crate::prepared::ResponseBudget;
    use crate::{ResponsePreparationComponent as Part, ResponsePreparationFailureKind as Kind};
    let (_, _, c) = support::load();
    let source = &c.schedule()[0];
    let mut budget = ResponseBudget::new(0, 4096).unwrap();
    let error = crate::ids::rsp01_copy_key_with(source, c.limits(), &mut budget, &mut |_| Err(()))
        .unwrap_err();
    assert_eq!(error.kind, Kind::Allocation);
    assert_eq!(error.component, Part::RunId);
    assert_eq!(error.requested_bytes, Some(32));
    assert_eq!(error.observed_bytes, None);
    let key = InvocationKey::new(
        InvocationKeyValues {
            run_id: source.run_id().clone(),
            case_key: CaseKey::new(
                CaseKeyValues {
                    case_id: source.case_key().case_id().clone(),
                    case_version: 1,
                    cell_id: "cell / λ".into(),
                },
                c.limits(),
            )
            .unwrap(),
            attempt: 1,
            operation_id: 2,
        },
        c.limits(),
    )
    .unwrap();
    let mut budget = ResponseBudget::new(0, 4096).unwrap();
    let copy = crate::ids::rsp01_copy_key(&key, c.limits(), &mut budget).unwrap();
    assert_eq!(copy, key);
    assert_eq!(copy.case_key().cell_id(), "cell / λ");
}

#[test]
fn prp07_cross_context_output_obeys_receiving_limit() {
    use crate::observation::{
        OneStepDiagnostic, OneStepOutputFailure, OneStepResponse, OneStepResponseStage,
    };
    let (_, _, c) = support::load();
    let i = invocation(&c, &c.schedule()[0]);
    let mut values = c.limits().values();
    values.observation_bytes = 256;
    let high = RunLimits::new(values).unwrap();
    let mut values = high.values();
    values.observation_bytes = 128;
    let low = RunLimits::new(values).unwrap();
    let prepare = |limits: &RunLimits| {
        OneStepResponse::prepare(
            i.key(),
            i.observation_schema(),
            i.script().steps()[0].step_id(),
            limits,
            8192,
            std::mem::size_of::<OneStepResponse>(),
        )
        .unwrap()
    };
    let admitting = prepare(&high);
    let receiving = prepare(&low);
    let output = admitting
        .admit_output(Vec::from([b'x'; 129]), 4096)
        .unwrap();
    let (receiving, failure) = match receiving.finish_observation(output, 4096) {
        Err(refusal) => refusal,
        Ok(_) => panic!("finishing context must not publish 129 bytes under its 128-byte limit"),
    };
    assert_eq!(failure, OneStepOutputFailure::Length { required: 129 });
    let error = receiving.finish_error(
        CaseErrorCategory::InvalidOutput,
        OneStepResponseStage::Execute,
        OneStepDiagnostic::new(b"bpf:limit_exceeded/execute;required=129").unwrap(),
        true,
        None,
    );
    assert_eq!(error.key(), i.key(), "refusal retains the receiving key");
    assert!(error.check_bounds(&low).is_ok());
}

#[test]
fn prp07_same_context_length_boundary_preserves_response_custody() {
    use crate::observation::{
        OneStepDiagnostic, OneStepOutputFailure, OneStepResponse, OneStepResponseStage,
    };
    let (_, _, c) = support::load();
    let i = invocation(&c, &c.schedule()[0]);
    let mut values = c.limits().values();
    values.observation_bytes = 128;
    let limits = RunLimits::new(values).unwrap();
    let prepare = || {
        OneStepResponse::prepare(
            i.key(),
            i.observation_schema(),
            i.script().steps()[0].step_id(),
            &limits,
            8192,
            std::mem::size_of::<OneStepResponse>(),
        )
        .unwrap()
    };
    let response = prepare();
    let bytes = Vec::from([b'x'; 128]);
    let pointer = bytes.as_ptr();
    let joint = std::mem::size_of::<Vec<u8>>() + bytes.capacity();
    let output = response.admit_output(bytes, joint).unwrap();
    let observation = response
        .finish_observation(output, joint)
        .unwrap_or_else(|_| panic!("exact length and joint boundaries must finish"));
    assert_eq!(observation.bytes(), &[b'x'; 128]);
    assert_eq!(observation.bytes().as_ptr(), pointer);
    assert_eq!(observation.key(), i.key());
    assert!(observation.check_bounds(&limits).is_ok());

    let response = prepare();
    assert_eq!(
        response.admit_output(Vec::from([b'x'; 129]), 4096).err(),
        Some(OneStepOutputFailure::Length { required: 129 })
    );
    let error = response.finish_error(
        CaseErrorCategory::InvalidOutput,
        OneStepResponseStage::Execute,
        OneStepDiagnostic::new(b"bpf:limit_exceeded/execute;required=129").unwrap(),
        true,
        None,
    );
    assert_eq!(error.key(), i.key());
    assert!(error.check_bounds(&limits).is_ok());
}

#[test]
fn prp07_finish_rechecks_current_joint_capacity() {
    use crate::observation::{
        OneStepDiagnostic, OneStepOutputFailure, OneStepResponse, OneStepResponseStage,
    };
    let (_, _, c) = support::load();
    let i = invocation(&c, &c.schedule()[0]);
    let prepare = || {
        OneStepResponse::prepare(
            i.key(),
            i.observation_schema(),
            i.script().steps()[0].step_id(),
            c.limits(),
            8192,
            std::mem::size_of::<OneStepResponse>(),
        )
        .unwrap()
    };
    for fits in [true, false] {
        let response = prepare();
        let mut bytes = Vec::with_capacity(256);
        bytes.push(b'x');
        let pointer = bytes.as_ptr();
        let required = std::mem::size_of::<Vec<u8>>() + bytes.capacity();
        let output = response.admit_output(bytes, 4096).unwrap();
        let result = response.finish_observation(output, required - usize::from(!fits));
        if fits {
            let observation =
                result.unwrap_or_else(|_| panic!("exact actual capacity must fit current J"));
            assert_eq!(observation.bytes(), b"x");
            assert_eq!(observation.bytes().as_ptr(), pointer);
            assert!(observation.check_bounds(c.limits()).is_ok());
        } else {
            let (response, failure) = match result {
                Err(refusal) => refusal,
                Ok(_) => panic!("minus-one current J must refuse actual spare capacity"),
            };
            assert_eq!(failure, OneStepOutputFailure::Capacity { required });
            let error = response.finish_error(
                CaseErrorCategory::InvalidOutput,
                OneStepResponseStage::Execute,
                OneStepDiagnostic::new(b"bpf:limit_exceeded/execute").unwrap(),
                true,
                None,
            );
            assert_eq!(error.key(), i.key(), "joint refusal retains the same key");
            assert!(error.check_bounds(c.limits()).is_ok());
        }
    }
}

#[test]
fn prp01_finish_result_fits_existing_admitted_inline_basis() {
    use crate::observation::{OneStepOutputFailure, OneStepResponse};
    let response = std::mem::size_of::<OneStepResponse>();
    let observation = std::mem::size_of::<Observation>();
    let error = std::mem::size_of::<CaseError>();
    let result =
        std::mem::size_of::<Result<Observation, (OneStepResponse, OneStepOutputFailure)>>();
    let basis = response.max(observation).max(error);
    println!("finish inline: response={response} observation={observation} error={error} result={result} basis={basis}");
    assert!(
        result <= basis,
        "consuming result carrier must fit the actual admitted inline basis"
    );
}

#[test]
fn prp07_narrow_finish_moves_exact_fields_and_rejects_unadmitted_output() {
    use crate::observation::{OneStepDiagnostic, OneStepResponse, OneStepResponseStage};
    let (_, _, c) = support::load();
    let i = invocation(&c, &c.schedule()[0]);
    let response = OneStepResponse::prepare(
        i.key(),
        i.observation_schema(),
        i.script().steps()[0].step_id(),
        c.limits(),
        8192,
        std::mem::size_of::<OneStepResponse>(),
    )
    .unwrap();
    let charge = response.admitted_bytes();
    assert!(charge <= 8192);
    let bytes = Vec::from(b"fixed-output".as_slice());
    let pointer = bytes.as_ptr();
    let output = response.admit_output(bytes, 4096).unwrap();
    let observation = response
        .finish_observation(output, 4096)
        .unwrap_or_else(|_| panic!("same-context admitted output must finish"));
    assert_eq!(observation.key(), i.key());
    assert_eq!(observation.schema_id(), i.observation_schema().id());
    assert_eq!(*observation.schema_revision(), 1);
    assert_eq!(
        observation.completed_steps(),
        &vec![Label::parse("sum").unwrap()]
    );
    assert_eq!(observation.bytes(), b"fixed-output");
    assert_eq!(
        observation.bytes().as_ptr(),
        pointer,
        "output buffer must move once"
    );
    assert!(observation.effects().registrations().is_empty());
    assert!(*observation.effects().complete());
    let mut oversized = Vec::new();
    oversized.reserve_exact(4096);
    oversized.extend_from_slice(b"x");
    assert!(
        OneStepResponse::prepare(
            i.key(),
            i.observation_schema(),
            i.script().steps()[0].step_id(),
            c.limits(),
            8192,
            std::mem::size_of::<OneStepResponse>()
        )
        .unwrap()
        .admit_output(oversized, 64)
        .is_err(),
        "spare output capacity must fit joint J"
    );
    let response = OneStepResponse::prepare(
        i.key(),
        i.observation_schema(),
        i.script().steps()[0].step_id(),
        c.limits(),
        8192,
        std::mem::size_of::<OneStepResponse>(),
    )
    .unwrap();
    let error = response.finish_error(
        CaseErrorCategory::Refused,
        OneStepResponseStage::Read,
        OneStepDiagnostic::new(b"bpf:denied/read;required=32").unwrap(),
        true,
        Some(13),
    );
    assert_eq!(error.key(), i.key());
    assert_eq!(error.step_id().as_ref().unwrap().as_str(), "sum");
    assert_eq!(error.stage().as_str(), "read");
    assert_eq!(*error.category(), CaseErrorCategory::Refused);
    assert_eq!(*error.errno(), Some(13));
    assert_eq!(error.diagnostic_bytes(), b"bpf:denied/read;required=32");
    assert_eq!(*error.cause().cause(), RefusalCause::Unknown);
    assert_eq!(error.cause().method().as_str(), "bp03-model");
    assert_eq!(*error.cause().tier(), EvidenceTier::T0);
    assert!(error.completed_steps().is_empty());
    assert!(error.partial_observation().is_none());
    assert!(error.effects().registrations().is_empty());
}

struct PreparationDelay {
    inner: TimedAdapter,
    prepare_ns: u64,
    calls: usize,
    drops: Rc<Cell<usize>>,
}
struct DelayedPreparedCall<'a> {
    adapter: &'a mut PreparationDelay,
    invocation: &'a CaseInvocation,
}
impl Drop for DelayedPreparedCall<'_> {
    fn drop(&mut self) {
        self.adapter.drops.set(self.adapter.drops.get() + 1);
    }
}
impl PreparedExecution for DelayedPreparedCall<'_> {
    fn execute(self, access: &FixtureAccess<'_>) -> Result<Observation, CaseError> {
        self.adapter.inner.execute(self.invocation, access)
    }
}
impl ResponsePreparedAdapter for PreparationDelay {
    fn subject(&self) -> SubjectBinding {
        self.inner.subject()
    }
    type Prepared<'a>
        = DelayedPreparedCall<'a>
    where
        Self: 'a;
    fn prepare_response<'a>(
        &'a mut self,
        invocation: &'a CaseInvocation,
    ) -> Result<Self::Prepared<'a>, ResponsePreparationFailure> {
        self.calls += 1;
        self.inner
            .clock
            .set(self.inner.clock.get() + self.prepare_ns);
        Ok(DelayedPreparedCall {
            adapter: self,
            invocation,
        })
    }
    fn retire(&mut self, request: &RetireRequest) -> RetirementReport {
        self.inner.retire(request)
    }
}
#[test]
fn prp09_existing_gate_charges_preparation_time_without_new_poll() {
    let clock = Deterministic::new();
    let (plan, mut session, inner, oracle) = setup(&clock);
    let c = session.inner.c.clone();
    let mut adapter = PreparationDelay {
        inner,
        prepare_ns: 30_000_000_000,
        calls: 0,
        drops: Rc::new(Cell::new(0)),
    };
    let report =
        run_prepared_with_clock(&plan, &mut adapter, &mut session, &oracle, &clock).unwrap();
    assert_eq!(adapter.calls, 1);
    assert_eq!(adapter.drops.get(), 1);
    assert_eq!(adapter.inner.inner.inner.calls, 0);
    assert!(!session.inner.events.borrow().iter().any(|e| e == "prepare"));
    assert!(
        matches!(report.case_results()[0].execution_checkpoints().prepare().before(),
        CheckpointSlot::Sampled { sample } if sample.cancelled().is_none() && *sample.poll_started_elapsed_ns() >= 30_000_000_000)
    );
    assert_eq!(
        session
            .inner
            .polls
            .load(std::sync::atomic::Ordering::Acquire),
        5,
        "preparation adds no poll; expired before gate skips cancellation"
    );
    assert_eq!(report.qualification(), Qualification::Incomplete);
    let bytes = report.to_json(c.limits().clone()).unwrap();
    assert_eq!(
        RunReport::from_json(&c, &bytes, c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Incomplete
    );
}

#[test]
fn prp01_all_simultaneous_context_capacities_and_header_fit() {
    use crate::observation::{rsp01_test_support, OneStepResponse};
    let (_, _, c) = support::load();
    let i = invocation(&c, &c.schedule()[0]);
    let context = OneStepResponse::prepare(
        i.key(),
        i.observation_schema(),
        i.script().steps()[0].step_id(),
        c.limits(),
        8192,
        std::mem::size_of::<OneStepResponse>(),
    )
    .unwrap();
    let actual = rsp01_test_support::context_bytes(&context);
    assert_eq!(
        context.admitted_bytes(),
        actual,
        "every owned capacity and inline shape counts exactly once"
    );
    assert!(
        OneStepResponse::prepare(
            i.key(),
            i.observation_schema(),
            i.script().steps()[0].step_id(),
            c.limits(),
            actual - 1,
            std::mem::size_of::<OneStepResponse>()
        )
        .is_err(),
        "minus-one rejects actual context"
    );
    let context = OneStepResponse::prepare(
        i.key(),
        i.observation_schema(),
        i.script().steps()[0].step_id(),
        c.limits(),
        actual,
        std::mem::size_of::<OneStepResponse>(),
    )
    .unwrap();
    let output = context
        .admit_output(Vec::from(b"x".as_slice()), 4096)
        .unwrap();
    let response = context
        .finish_observation(output, 4096)
        .unwrap_or_else(|_| panic!("same-context admitted output must finish"));
    assert!(
        rsp01_test_support::observation_bytes(&response) <= actual,
        "returned header Q <= admitted R <= F"
    );
}

#[test]
fn prp07_error_only_finish_and_decimal_are_finite() {
    use crate::observation::{OneStepDiagnostic, OneStepErrorResponse, OneStepResponseStage};
    let (_, _, c) = support::load();
    let key = &c.schedule()[0];
    let mut diagnostic = OneStepDiagnostic::new(b"bpf:limit_exceeded/read;required=").unwrap();
    diagnostic.decimal(usize::MAX).unwrap();
    let response = OneStepErrorResponse::prepare(
        key,
        c.limits(),
        8192,
        std::mem::size_of::<OneStepErrorResponse>(),
    )
    .unwrap();
    assert!(response.admitted_bytes() <= 8192);
    let error = response.finish_error(
        CaseErrorCategory::UnsupportedSchema,
        OneStepResponseStage::Preflight,
        diagnostic,
    );
    assert_eq!(error.key(), key);
    assert!(error.step_id().is_none());
    assert!(error.errno().is_none());
    assert!(error.completed_steps().is_empty());
    assert!(error.partial_observation().is_none());
    assert_eq!(
        error.diagnostic_bytes(),
        format!("bpf:limit_exceeded/read;required={}", usize::MAX).as_bytes()
    );
    assert!(OneStepDiagnostic::new(&[0; 129]).is_err());
    let mut full = OneStepDiagnostic::new(&[b'a'; 128]).unwrap();
    assert!(
        full.extend(b"b").is_err(),
        "overflow must refuse rather than grow or truncate"
    );
}

#[test]
fn prp01_full_outer_inline_is_counted_once() {
    use crate::observation::{rsp01_test_support, OneStepResponse};
    let (_, _, c) = support::load();
    let i = invocation(&c, &c.schedule()[0]);
    let base_inline = std::mem::size_of::<OneStepResponse>()
        .max(std::mem::size_of::<Observation>())
        .max(std::mem::size_of::<CaseError>());
    // This is a synthetic outer shape, not an actual BP03 call measurement.
    let outer_inline = base_inline + 64;
    let context = OneStepResponse::prepare(
        i.key(),
        i.observation_schema(),
        i.script().steps()[0].step_id(),
        c.limits(),
        8192,
        outer_inline,
    )
    .unwrap();
    let independently_measured = rsp01_test_support::context_bytes(&context) + 64;
    assert_eq!(
        context.admitted_bytes(),
        independently_measured,
        "outer inline storage replaces the component inline once"
    );
    assert!(OneStepResponse::prepare(
        i.key(),
        i.observation_schema(),
        i.script().steps()[0].step_id(),
        c.limits(),
        independently_measured - 1,
        outer_inline
    )
    .is_err());
}

#[test]
fn prp01_error_only_outer_inline_is_counted_once() {
    use crate::observation::OneStepErrorResponse;
    let (_, _, c) = support::load();
    let inline = std::mem::size_of::<OneStepErrorResponse>()
        .max(std::mem::size_of::<Observation>())
        .max(std::mem::size_of::<CaseError>());
    let component =
        OneStepErrorResponse::prepare(&c.schedule()[0], c.limits(), 8192, inline).unwrap();
    let outer =
        OneStepErrorResponse::prepare(&c.schedule()[0], c.limits(), 8192, inline + 64).unwrap();
    assert_eq!(outer.admitted_bytes(), component.admitted_bytes() + 64);
    assert!(OneStepErrorResponse::prepare(
        &c.schedule()[0],
        c.limits(),
        outer.admitted_bytes() - 1,
        inline + 64
    )
    .is_err());
}
