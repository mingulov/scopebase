// SPDX-License-Identifier: Apache-2.0
//! Narrow adapter seam; expected evidence is deliberately inaccessible.
use crate::*;
pub trait ConformanceAdapter {
    fn subject(&self) -> SubjectBinding;
    fn execute(
        &mut self,
        invocation: &CaseInvocation,
        fixture: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError>;
    fn retire(&mut self, request: &RetireRequest) -> RetirementReport;
}
