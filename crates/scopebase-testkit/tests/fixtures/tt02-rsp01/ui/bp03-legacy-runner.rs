// SPDX-License-Identifier: Apache-2.0
//! UI fixture: legacy runner rejects the strict adapter. EXPECT: FAIL.
//!
//! `BpfHostAdapter` implements only `ResponsePreparedAdapter`. Passing it to
//! the old `run_profile` (which takes `&mut dyn ConformanceAdapter`) must
//! fail: no `ConformanceAdapter` implementation exists, so legacy total
//! execution cannot accidentally bypass strict response admission.

use scopebase_testkit::bpf::BpfHostAdapter;
use scopebase_testkit::{
    AssertionVerdict, CaseOutcome, CaseSpec, ExpectedEvidence, FixtureAccess, FixtureError,
    OracleBinding,
};

struct StubSession;
impl scopebase_testkit::FixtureSession for StubSession {
    fn contract(&self) -> &scopebase_testkit::RunContract {
        unimplemented!()
    }
    fn cancellation_probe(
        &mut self,
    ) -> Box<dyn scopebase_testkit::CancellationProbe + 'static> {
        unimplemented!()
    }
    fn prepare(
        &mut self,
        _invocation: &scopebase_testkit::CaseInvocation,
    ) -> Result<FixtureAccess<'_>, FixtureError> {
        unimplemented!()
    }
    fn collect(
        &mut self,
        _invocation: &scopebase_testkit::CaseInvocation,
    ) -> Result<ExpectedEvidence, FixtureError> {
        unimplemented!()
    }
    fn retire(
        &mut self,
        _request: &scopebase_testkit::RetireRequest,
    ) -> scopebase_testkit::RetirementReport {
        unimplemented!()
    }
}

struct StubOracle;
impl scopebase_testkit::CaseOracle for StubOracle {
    fn identity(&self) -> OracleBinding {
        unimplemented!()
    }
    fn evaluate(
        &self,
        _case: &CaseSpec,
        _expected: &ExpectedEvidence,
        _outcome: &CaseOutcome,
    ) -> AssertionVerdict {
        unimplemented!()
    }
}

fn unimplemented<T>() -> T {
    panic!("fixture")
}

fn main() {
    let mut adapter = unimplemented::<BpfHostAdapter>();
    let plan = unimplemented::<scopebase_testkit::ProfilePlan>();
    let mut session = StubSession;
    let oracle = StubOracle;
    // ERROR: the trait bound `BpfHostAdapter: ConformanceAdapter` is not met.
    let _ = scopebase_testkit::run_profile(&plan, &mut adapter, &mut session, &oracle);
}
