// SPDX-License-Identifier: Apache-2.0
//! Focused prepared-only API/runner controls. These do not qualify BP03 F/J.
use scopebase_testkit::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
#[path = "fixtures/harness/support.rs"]
mod support;
use support::instrumented as ins;

const FAILURE: ResponsePreparationFailure = ResponsePreparationFailure {
    kind: ResponsePreparationFailureKind::CapacityExceeded,
    component: ResponsePreparationComponent::CellId,
    requested_bytes: Some(64),
    observed_bytes: Some(128),
};

struct CountingOracle {
    inner: support::oracle::ArithmeticOracle,
    evaluations: Cell<usize>,
}
impl CaseOracle for CountingOracle {
    fn identity(&self) -> OracleBinding {
        self.inner.identity()
    }
    fn evaluate(
        &self,
        case: &CaseSpec,
        expected: &ExpectedEvidence,
        outcome: &CaseOutcome,
    ) -> AssertionVerdict {
        self.evaluations.set(self.evaluations.get() + 1);
        self.inner.evaluate(case, expected, outcome)
    }
}
fn counted_oracle(c: &RunContract) -> CountingOracle {
    CountingOracle {
        inner: support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        },
        evaluations: Cell::new(0),
    }
}

struct PreparedOnly {
    inner: ins::Adapter,
    preparations: usize,
    fail_at: Option<usize>,
    live: Rc<Cell<bool>>,
    cancelled: Arc<AtomicBool>,
    cancel_prepare: bool,
    events: Rc<RefCell<Vec<String>>>,
    malformed_run_cleanup: bool,
}
struct Call<'a> {
    adapter: &'a mut PreparedOnly,
    invocation: &'a CaseInvocation,
    executed: bool,
}
impl Drop for Call<'_> {
    fn drop(&mut self) {
        assert!(self.adapter.live.replace(false));
        self.adapter.events.borrow_mut().push(
            if self.executed {
                "consumed"
            } else {
                "drop-ready"
            }
            .into(),
        );
    }
}
impl PreparedExecution for Call<'_> {
    fn execute(mut self, fixture: &FixtureAccess<'_>) -> Result<Observation, CaseError> {
        self.executed = true;
        self.adapter.inner.execute(self.invocation, fixture)
    }
}
impl ResponsePreparedAdapter for PreparedOnly {
    fn subject(&self) -> SubjectBinding {
        assert!(!self.live.get(), "subject must not reborrow a live call");
        self.inner.subject()
    }
    type Prepared<'a>
        = Call<'a>
    where
        Self: 'a;
    fn prepare_response<'a>(
        &'a mut self,
        invocation: &'a CaseInvocation,
    ) -> Result<Self::Prepared<'a>, ResponsePreparationFailure> {
        assert!(!self.live.get());
        let index = self.preparations;
        self.preparations += 1;
        self.events.borrow_mut().push(format!("admit-{index}"));
        if self.fail_at == Some(index) {
            return Err(FAILURE);
        }
        if self.cancel_prepare {
            self.cancelled.store(true, Ordering::Release);
        }
        self.live.set(true);
        Ok(Call {
            adapter: self,
            invocation,
            executed: false,
        })
    }
    fn retire(&mut self, request: &RetireRequest) -> RetirementReport {
        assert!(!self.live.get(), "cleanup must follow call drop/consume");
        let response = self.inner.retire(request);
        if self.malformed_run_cleanup && matches!(request.scope(), CleanupScope::Run(_)) {
            RetirementReport::new(
                RetirementReportValues {
                    call_id: request.call_id() + 1,
                    owner: request.owner(),
                    scope: request.scope().clone(),
                    discovered: vec![],
                    transitions: vec![],
                    pending_snapshot: request.known_pending().to_vec(),
                    complete: true,
                    diagnostic: None,
                },
                &RunLimits::default(),
            )
            .unwrap()
        } else {
            response
        }
    }
}
fn adapter(s: &ins::Session<'_>) -> PreparedOnly {
    PreparedOnly {
        inner: ins::adapter(s),
        preparations: 0,
        fail_at: None,
        live: Rc::new(Cell::new(false)),
        cancelled: s.flag.clone(),
        cancel_prepare: false,
        events: s.events.clone(),
        malformed_run_cleanup: false,
    }
}
fn multi() -> (ProfilePlan, RunContract) {
    let (_, plan, _) = support::load();
    let mut v = support::contract_value();
    v["case_rules"][0]["attempts"] = 3.into();
    v["case_rules"][0]["operation_ids"] = serde_json::json!(["1", "2", "3"]);
    v["case_rules"][0]["max_effects"] = 2.into();
    (plan, support::with_model_ledgers(v))
}
fn replay(c: &RunContract, report: &RunReport) -> RunReport {
    RunReport::from_json(
        c,
        &report.to_json(c.limits().clone()).unwrap(),
        c.limits().clone(),
    )
    .unwrap()
}
fn events(s: &ins::Session<'_>, name: &str) -> usize {
    s.events
        .borrow()
        .iter()
        .filter(|s| s.as_str() == name)
        .count()
}
#[test]
fn prp05_linear_prepared_call() {
    let (_, plan, c) = support::load();
    let mut s = ins::Session::new(c.clone());
    let mut a = adapter(&s);
    let oracle = counted_oracle(&c);
    let report = run_profile_prepared(&plan, &mut a, &mut s, &oracle).unwrap();
    assert_eq!(
        oracle.evaluations.get(),
        1,
        "only actually judged earlier outcomes may reach the oracle"
    );
    assert_eq!(a.preparations, 1);
    assert_eq!(a.inner.inner.calls, 1);
    assert_eq!(events(&s, "consumed"), 1);
    assert_eq!(events(&s, "drop-ready"), 0);
    assert_eq!(report.case_results()[0].key(), &c.schedule()[0]);
    assert_eq!(report.qualification(), Qualification::Qualified);
    assert_eq!(
        replay(&c, &report).qualification(),
        Qualification::Qualified
    );
}
#[test]
fn prp09_prepare_before_existing_gate() {
    let (_, plan, c) = support::load();
    let mut s = ins::Session::new(c.clone());
    let mut a = adapter(&s);
    a.cancel_prepare = true;
    let oracle = counted_oracle(&c);
    let report = run_profile_prepared(&plan, &mut a, &mut s, &oracle).unwrap();
    assert_eq!(
        oracle.evaluations.get(),
        0,
        "only actually judged earlier outcomes may reach the oracle"
    );
    assert_eq!(a.preparations, 1);
    assert_eq!(
        events(&s, "prepare"),
        0,
        "fresh gate must stop fixture effects"
    );
    assert_eq!(events(&s, "execute"), 0);
    assert_eq!(events(&s, "drop-ready"), 1);
    assert!(report
        .cleanup_records()
        .iter()
        .all(|r| *r.status() == CleanupCallStatus::UncalledNoParticipation));
    assert_eq!(
        replay(&c, &report).qualification(),
        Qualification::Incomplete
    );
    assert_eq!(s.acquisitions, 1);
    assert_eq!(
        s.polls.load(Ordering::Acquire),
        7,
        "no extra checkpoint or cancellation poll"
    );
}
#[test]
fn prp09_each_ready_early_branch_drops_before_cleanup() {
    for branch in 0..4 {
        let (_, plan, c) = support::load();
        let mut s = ins::Session::new(c.clone());
        let mut a = adapter(&s);
        match branch {
            0 => s.prepare_error = Some(FixtureErrorCategory::Unavailable),
            1 => s.cancel_prepare = true,
            2 => s.cancel_at = 8, // after Prepare.after, at Execute.before
            _ => s.collect_error = Some(FixtureErrorCategory::Unavailable),
        }
        let oracle = counted_oracle(&c);
        let report = run_profile_prepared(&plan, &mut a, &mut s, &oracle).unwrap();
        assert!(!a.live.get());
        assert_eq!(a.preparations, 1);
        assert_eq!(events(&s, "drop-ready"), usize::from(branch != 3));
        assert_eq!(events(&s, "consumed"), usize::from(branch == 3));
        assert_eq!(events(&s, "execute"), usize::from(branch == 3));
        assert_eq!(
            replay(&c, &report).qualification(),
            Qualification::Incomplete
        );
    }
}
#[test]
fn prp09_prior_stop_never_prepares() {
    let (_, plan, c) = support::load();
    let mut s = ins::Session::new(c.clone());
    s.flag.store(true, Ordering::Release);
    let mut a = adapter(&s);
    let oracle = counted_oracle(&c);
    let r = run_profile_prepared(&plan, &mut a, &mut s, &oracle).unwrap();
    assert_eq!(
        oracle.evaluations.get(),
        0,
        "only actually judged earlier outcomes may reach the oracle"
    );
    assert_eq!(a.preparations, 0);
    assert_eq!(events(&s, "prepare"), 0);
    assert_eq!(replay(&c, &r).qualification(), Qualification::Incomplete);
}
#[test]
fn prp10_late_failure_retains_custody() {
    let (plan, c) = multi();
    let mut s = ins::Session::new(c.clone());
    s.effect = true;
    s.mode = ins::Retirement::Pending;
    let mut a = adapter(&s);
    a.fail_at = Some(1);
    let oracle = counted_oracle(&c);
    let error = run_profile_prepared(&plan, &mut a, &mut s, &oracle).unwrap_err();
    assert_eq!(
        oracle.evaluations.get(),
        1,
        "only actually judged earlier outcomes may reach the oracle"
    );
    assert_eq!(error.schedule_index(), Some(1));
    assert_eq!(error.preparation_failure(), Some(&FAILURE));
    assert!(error.followup_harness_error().is_none());
    let partial = error.partial_report().unwrap();
    assert_eq!(
        partial.case_results().len(),
        2,
        "only actual prefix through failure"
    );
    assert_eq!(
        partial.cleanup_records().len(),
        8,
        "all fixed slots including later unentered cases/run"
    );
    assert_eq!(a.preparations, 2);
    assert_eq!(events(&s, "execute"), 1);
    assert_eq!(events(&s, "prepare"), 1);
    assert_eq!(events(&s, "collect"), 1);
    let failure = &partial.case_results()[1];
    assert_eq!(*failure.execution(), ExecutionState::NotRun);
    assert!(failure.terminal().is_none());
    assert!(failure.entered_stages().is_empty());
    assert!(failure.outcome().is_none());
    assert!(failure.expected_evidence().is_none());
    assert!(failure.oracle_verdict().is_none());
    assert!(failure.effect_batches().is_empty());
    for cleanup in &partial.cleanup_records()[2..6] {
        assert_eq!(
            *cleanup.status(),
            CleanupCallStatus::UncalledNoParticipation
        );
    }
    assert_eq!(
        partial.cleanup_records()[1].pending_ids(),
        &vec![Label::parse("fixture.1").unwrap()]
    );
    assert_eq!(
        partial.cleanup_records()[7].pending_ids(),
        &vec![Label::parse("fixture.1").unwrap()]
    );
    assert_eq!(
        *partial.cleanup_records()[7].state_at_run_end(),
        CleanupState::Unresolved
    );
    assert!(serde_json::from_slice::<serde_json::Value>(
        &partial.to_json(c.limits().clone()).unwrap()
    )
    .unwrap()["run_terminal"]
        .is_null());
    assert!(matches!(
        partial.runner_observations().completion(),
        CheckpointSlot::NotRecorded
    ));
    assert_eq!(
        replay(&c, partial).qualification(),
        Qualification::Incomplete
    );
}
#[test]
fn prp11_scalar_first_single_partial() {
    let (plan, c) = multi();
    let mut s = ins::Session::new(c.clone());
    let mut a = adapter(&s);
    a.fail_at = Some(1);
    a.malformed_run_cleanup = true;
    let oracle = counted_oracle(&c);
    let error = run_profile_prepared(&plan, &mut a, &mut s, &oracle).unwrap_err();
    assert_eq!(
        oracle.evaluations.get(),
        1,
        "only actually judged earlier outcomes may reach the oracle"
    );
    assert_eq!(error.schedule_index(), Some(1));
    assert_eq!(error.preparation_failure(), Some(&FAILURE));
    let followup = error.followup_harness_error().unwrap();
    assert_eq!(followup.kind(), HarnessErrorKind::InvalidProtocol);
    assert_eq!(
        followup.diagnostic(),
        "retirement response identity",
        "first follow-up error survives later reconstruction failure"
    );
    assert!(
        followup.partial_report().is_none(),
        "raw partial moves once to outer variant"
    );
    let raw = error.partial_report().unwrap();
    assert_eq!(raw.qualification(), Qualification::Invalid);
    assert_eq!(
        *raw.cleanup_records()[6]
            .response()
            .as_ref()
            .unwrap()
            .call_id(),
        8
    );
    let bytes = raw.to_json(c.limits().clone()).unwrap();
    assert!(
        RunReport::from_json(&c, &bytes, c.limits().clone()).is_err(),
        "malformed raw wire must keep strict rejection"
    );
    match error {
        PreparedRunError::ResponsePreparation {
            schedule_index,
            failure,
            followup_harness_error: Some(followup),
            partial_report: Some(raw),
        } => {
            assert_eq!(schedule_index, 1);
            assert_eq!(failure, FAILURE);
            assert!(followup.partial_report().is_none());
            assert_eq!(raw.qualification(), Qualification::Invalid);
        }
        other => panic!("wrong error {other:?}"),
    }
}
#[test]
fn prp11_clean_failure_is_nonterminal_strict_v1() {
    let (_, plan, c) = support::load();
    let mut s = ins::Session::new(c.clone());
    let mut a = adapter(&s);
    a.fail_at = Some(0);
    let oracle = counted_oracle(&c);
    let error = run_profile_prepared(&plan, &mut a, &mut s, &oracle).unwrap_err();
    assert_eq!(
        oracle.evaluations.get(),
        0,
        "only actually judged earlier outcomes may reach the oracle"
    );
    let raw = error.partial_report().unwrap();
    assert_eq!(error.schedule_index(), Some(0));
    assert_eq!(raw.qualification(), Qualification::Incomplete);
    assert_eq!(replay(&c, raw).qualification(), Qualification::Incomplete);
    assert_eq!(events(&s, "prepare"), 0);
    assert_eq!(events(&s, "execute"), 0);
    let row = &raw.case_results()[0];
    let mut value: serde_json::Value =
        serde_json::from_slice(&raw.to_json(c.limits().clone()).unwrap()).unwrap();
    for mutation in 0..5 {
        let mut bad = value.clone();
        match mutation {
            0 => bad["run_terminal"] = support::literal()["run_terminal"].clone(),
            1 => {
                bad["case_results"][0]["execution_checkpoints"]["prepare"]["before"] =
                    serde_json::json!({"kind":"omitted","cause":"prior_stop"})
            }
            2 => {
                bad["runner_observations"]["completion"] =
                    support::literal()["runner_observations"]["completion"].clone()
            }
            3 => {
                bad["case_results"][0]["outcome"] =
                    support::literal()["case_results"][0]["outcome"].clone()
            }
            _ => bad["cleanup_records"][0]["owner"] = "fixture".into(),
        }
        assert!(
            RunReport::from_json(&c, &serde_json::to_vec(&bad).unwrap(), c.limits().clone())
                .is_err(),
            "forgery {mutation}"
        );
    }
    assert!(row.terminal().is_none());
    value["schema_version"] = 2.into();
    assert!(
        RunReport::from_json(&c, &serde_json::to_vec(&value).unwrap(), c.limits().clone()).is_err()
    );
}
#[test]
fn prp11_earlier_functional_failure_keeps_precedence() {
    let (plan, c) = multi();
    let mut s = ins::Session::new(c.clone());
    let mut a = adapter(&s);
    a.fail_at = Some(1);
    a.inner.inner.wrong = true;
    let oracle = counted_oracle(&c);
    let error = run_profile_prepared(&plan, &mut a, &mut s, &oracle).unwrap_err();
    assert_eq!(
        oracle.evaluations.get(),
        1,
        "only actually judged earlier outcomes may reach the oracle"
    );
    let raw = error.partial_report().unwrap();
    assert_eq!(raw.qualification(), Qualification::Failed);
    assert_eq!(replay(&c, raw).qualification(), Qualification::Failed);
}
#[test]
fn prp12_legacy_route_unchanged() {
    let (_, plan, c) = support::load();
    let mut old_session = ins::Session::new(c.clone());
    let mut legacy = ins::adapter(&old_session);
    let mut new_session = ins::Session::new(c.clone());
    let mut prepared = adapter(&new_session);
    let oracle = counted_oracle(&c);
    let old = run_profile(&plan, &mut legacy, &mut old_session, &oracle).unwrap();
    let new = run_profile_prepared(&plan, &mut prepared, &mut new_session, &oracle).unwrap();
    assert_eq!(
        new.case_results()[0].outcome(),
        old.case_results()[0].outcome()
    );
    assert_eq!(new.qualification(), old.qualification());
    assert_eq!(
        old_session.polls.load(Ordering::Acquire),
        new_session.polls.load(Ordering::Acquire)
    );
    assert_eq!(old_session.acquisitions, new_session.acquisitions);
    assert_eq!(replay(&c, &old).qualification(), Qualification::Qualified);
}

#[test]
fn prp09_observation_allowance_releases_ready_before_cleanup() {
    let (_, plan, _) = support::load();
    let mut value = support::contract_value();
    value["limits"]["retained_bytes"] = "8388608".into();
    let c = support::changed_contract(&value);
    let mut session = ins::Session::new(c.clone());
    let mut adapter = adapter(&session);
    let oracle = counted_oracle(&c);
    let error = run_profile_prepared(&plan, &mut adapter, &mut session, &oracle).unwrap_err();
    assert_eq!(
        oracle.evaluations.get(),
        0,
        "only actually judged earlier outcomes may reach the oracle"
    );
    let PreparedRunError::Harness(harness) = error else {
        panic!("allowance failure is unrelated to response preparation")
    };
    assert_eq!(harness.kind(), HarnessErrorKind::LimitExceeded);
    assert_eq!(harness.diagnostic(), "next observation allowance");
    assert_eq!(events(&session, "prepare"), 1);
    assert_eq!(events(&session, "execute"), 0);
    assert_eq!(events(&session, "drop-ready"), 1);
    assert!(!adapter.live.get());
    let partial = harness.partial_report().unwrap();
    assert_eq!(
        *partial.cleanup_records()[0].status(),
        CleanupCallStatus::UncalledNoParticipation
    );
    assert_eq!(
        *partial.cleanup_records()[1].status(),
        CleanupCallStatus::Called
    );
}
#[test]
fn prp09_unimplemented_never_prepares() {
    let (plan, c) = support::unimplemented();
    let mut session = ins::Session::new(c.clone());
    let mut adapter = adapter(&session);
    let oracle = counted_oracle(&c);
    let report = run_profile_prepared(&plan, &mut adapter, &mut session, &oracle).unwrap();
    assert_eq!(
        oracle.evaluations.get(),
        0,
        "only actually judged earlier outcomes may reach the oracle"
    );
    assert_eq!(adapter.preparations, 0);
    assert_eq!(events(&session, "prepare"), 0);
    assert_eq!(
        replay(&c, &report).qualification(),
        Qualification::Incomplete
    );
}
#[test]
fn prp05_prepared_execute_keeps_actual_borrowed_nonclone_owner() {
    let (_, plan, c) = support::load();
    let owner = ins::NonClone(123);
    let mut session = ins::Session::new(c.clone());
    session
        .resources
        .push(FixtureResource::new(ins::label("actual-owner"), &owner));
    let mut adapter = adapter(&session);
    adapter.inner.require_resource = true;
    let oracle = counted_oracle(&c);
    let report = run_profile_prepared(&plan, &mut adapter, &mut session, &oracle).unwrap();
    assert_eq!(
        oracle.evaluations.get(),
        1,
        "only actually judged earlier outcomes may reach the oracle"
    );
    assert_eq!(report.qualification(), Qualification::Qualified);
    assert_eq!(adapter.inner.inner.calls, 1);
    assert_eq!(
        replay(&c, &report).qualification(),
        Qualification::Qualified
    );
}

#[test]
fn prp10_late_failure_retains_earlier_uncertainty() {
    let (plan, c) = multi();
    let mut session = ins::Session::new(c.clone());
    session.effect = true;
    session.mode = ins::Retirement::Unknown;
    let mut adapter = adapter(&session);
    adapter.fail_at = Some(1);
    let oracle = counted_oracle(&c);
    let error = run_profile_prepared(&plan, &mut adapter, &mut session, &oracle).unwrap_err();
    assert_eq!(
        oracle.evaluations.get(),
        1,
        "only actually judged earlier outcomes may reach the oracle"
    );
    let raw = error.partial_report().unwrap();
    let early = raw.cleanup_records()[1].uncertainty_ids();
    assert!(!early.is_empty());
    let final_uncertainty = raw.cleanup_records()[7].uncertainty_ids();
    assert!(
        early.iter().all(|id| final_uncertainty.contains(id)),
        "earlier uncertain custody must survive response failure/run cleanup"
    );
    assert_eq!(
        *raw.cleanup_records()[7].state_at_run_end(),
        CleanupState::Unresolved
    );
    assert!(raw.cleanup_records()[2..6]
        .iter()
        .all(|r| *r.status() == CleanupCallStatus::UncalledNoParticipation));
    assert_eq!(replay(&c, raw).qualification(), Qualification::Incomplete);
}
