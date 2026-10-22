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
        e.phase(0, &mut a, &mut s);
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
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.phase(0, &mut a, &mut s)));
    assert!(
        result.is_ok(),
        "selected retirement diagnostics must be representable without a panic"
    );
    assert!(e.invalid.is_some());
    assert!(e.records[0].error.as_ref().unwrap().diagnostic().len() <= 41);
}
