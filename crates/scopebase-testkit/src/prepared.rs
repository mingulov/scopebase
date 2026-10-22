// SPDX-License-Identifier: Apache-2.0
//! Opt-in, consuming response admission. Implementing this seam alone certifies no
//! allocation bound; each adapter must qualify its own admitted context/finish.
use crate::{
    CaseError, CaseInvocation, FixtureAccess, HarnessError, Observation, RetireRequest,
    RetirementReport, RunReport, SubjectBinding,
};

/// A response-admitted call tied to its actual adapter and immutable invocation.
/// Execution consumes the call; dropping it must release pure metadata only.
pub trait PreparedExecution {
    fn execute(self, fixture: &FixtureAccess<'_>) -> Result<Observation, CaseError>;
}

/// Independent prepared-only route. Legacy `ConformanceAdapter` stays unchanged.
pub trait ResponsePreparedAdapter {
    fn subject(&self) -> SubjectBinding;
    type Prepared<'a>: PreparedExecution
    where
        Self: 'a;
    fn prepare_response<'a>(
        &'a mut self,
        invocation: &'a CaseInvocation,
    ) -> Result<Self::Prepared<'a>, ResponsePreparationFailure>;
    fn retire(&mut self, request: &RetireRequest) -> RetirementReport;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponsePreparationFailureKind {
    Allocation,
    CapacityExceeded,
    Overflow,
    InvalidInvocation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponsePreparationComponent {
    RunId,
    CaseId,
    CellId,
    Schema,
    Step,
    Stage,
    Method,
    Diagnostic,
    CompletionStorage,
    Total,
}
/// Allocation-free admission failure, with no owned key or source diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponsePreparationFailure {
    pub kind: ResponsePreparationFailureKind,
    pub component: ResponsePreparationComponent,
    pub requested_bytes: Option<usize>,
    pub observed_bytes: Option<usize>,
}
impl std::fmt::Display for ResponsePreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "response preparation {:?} at {:?}",
            self.kind, self.component
        )
    }
}
impl std::error::Error for ResponsePreparationFailure {}

/// Preparation remains the primary cause even if later cleanup/replay fails.
/// A nested HarnessError partial is moved into the outer report exactly once.
#[derive(Debug)]
pub enum PreparedRunError {
    Harness(HarnessError),
    ResponsePreparation {
        schedule_index: usize,
        failure: ResponsePreparationFailure,
        followup_harness_error: Option<HarnessError>,
        partial_report: Option<RunReport>,
    },
}
impl PreparedRunError {
    pub fn schedule_index(&self) -> Option<usize> {
        match self {
            Self::Harness(_) => None,
            Self::ResponsePreparation { schedule_index, .. } => Some(*schedule_index),
        }
    }
    pub fn preparation_failure(&self) -> Option<&ResponsePreparationFailure> {
        match self {
            Self::Harness(_) => None,
            Self::ResponsePreparation { failure, .. } => Some(failure),
        }
    }
    pub fn followup_harness_error(&self) -> Option<&HarnessError> {
        match self {
            Self::Harness(_) => None,
            Self::ResponsePreparation {
                followup_harness_error,
                ..
            } => followup_harness_error.as_ref(),
        }
    }
    pub fn partial_report(&self) -> Option<&RunReport> {
        match self {
            Self::Harness(error) => error.partial_report(),
            Self::ResponsePreparation { partial_report, .. } => partial_report.as_ref(),
        }
    }
    pub(crate) fn from_engine(
        result: Result<RunReport, HarnessError>,
        preparation: Option<(usize, ResponsePreparationFailure)>,
    ) -> Result<RunReport, Self> {
        let Some((schedule_index, failure)) = preparation else {
            return result.map_err(Self::Harness);
        };
        let (followup_harness_error, partial_report) = match result {
            Ok(report) => (None, Some(report)),
            Err(mut error) => {
                let partial = error.partial.take().map(|report| *report);
                (Some(error), partial)
            }
        };
        Err(Self::ResponsePreparation {
            schedule_index,
            failure,
            followup_harness_error,
            partial_report,
        })
    }
}
impl From<HarnessError> for PreparedRunError {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}
impl std::fmt::Display for PreparedRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Harness(error) => error.fmt(f),
            Self::ResponsePreparation {
                schedule_index,
                failure,
                ..
            } => write!(f, "schedule index {schedule_index}: {failure}"),
        }
    }
}
impl std::error::Error for PreparedRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Harness(error) => Some(error),
            Self::ResponsePreparation { failure, .. } => Some(failure),
        }
    }
}

// Narrow internal accounting for the one-step, empty-effects response shape.
// Each allocator request is prepaid; actual returned capacity replaces that
// minimum before any buffer can be returned to an admitted context.
#[allow(dead_code)]
pub(crate) struct ResponseBudget {
    used: usize,
    limit: usize,
}
#[allow(dead_code)]
impl ResponseBudget {
    pub(crate) fn new(inline: usize, limit: usize) -> Result<Self, ResponsePreparationFailure> {
        let mut value = Self { used: 0, limit };
        value.reserve_minimum(inline, ResponsePreparationComponent::Total)?;
        Ok(value)
    }
    pub(crate) fn used(&self) -> usize {
        self.used
    }
    pub(crate) fn reserve_minimum(
        &mut self,
        requested: usize,
        component: ResponsePreparationComponent,
    ) -> Result<(), ResponsePreparationFailure> {
        let total = self
            .used
            .checked_add(requested)
            .ok_or(ResponsePreparationFailure {
                kind: ResponsePreparationFailureKind::Overflow,
                component,
                requested_bytes: Some(requested),
                observed_bytes: None,
            })?;
        if total > self.limit {
            return Err(ResponsePreparationFailure {
                kind: ResponsePreparationFailureKind::CapacityExceeded,
                component,
                requested_bytes: Some(requested),
                observed_bytes: Some(total),
            });
        }
        self.used = total;
        Ok(())
    }
    pub(crate) fn observe_capacity(
        &mut self,
        requested: usize,
        actual: usize,
        component: ResponsePreparationComponent,
    ) -> Result<(), ResponsePreparationFailure> {
        let total = self
            .used
            .checked_sub(requested)
            .and_then(|n| n.checked_add(actual))
            .ok_or(ResponsePreparationFailure {
                kind: ResponsePreparationFailureKind::Overflow,
                component,
                requested_bytes: Some(requested),
                observed_bytes: None,
            })?;
        if actual < requested {
            return Err(ResponsePreparationFailure {
                kind: ResponsePreparationFailureKind::Allocation,
                component,
                requested_bytes: Some(requested),
                observed_bytes: Some(actual),
            });
        }
        if total > self.limit {
            return Err(ResponsePreparationFailure {
                kind: ResponsePreparationFailureKind::CapacityExceeded,
                component,
                requested_bytes: Some(requested),
                observed_bytes: Some(total),
            });
        }
        self.used = total;
        Ok(())
    }
    pub(crate) fn copy_string(
        &mut self,
        text: &str,
        component: ResponsePreparationComponent,
    ) -> Result<String, ResponsePreparationFailure> {
        self.copy_string_with(text, component, &mut response_string_storage)
    }
    pub(crate) fn copy_string_with<F>(
        &mut self,
        text: &str,
        component: ResponsePreparationComponent,
        allocate: &mut F,
    ) -> Result<String, ResponsePreparationFailure>
    where
        F: FnMut(usize) -> Result<String, ()>,
    {
        self.reserve_minimum(text.len(), component)?;
        let mut copy = allocate(text.len()).map_err(|_| ResponsePreparationFailure {
            kind: ResponsePreparationFailureKind::Allocation,
            component,
            requested_bytes: Some(text.len()),
            observed_bytes: None,
        })?;
        // Even the private real-overgrant seam supplies an actual empty buffer.
        // Never trust a claimed capacity or allow push_str to replenish storage.
        if !copy.is_empty() {
            return Err(ResponsePreparationFailure {
                kind: ResponsePreparationFailureKind::InvalidInvocation,
                component,
                requested_bytes: Some(text.len()),
                observed_bytes: Some(copy.capacity()),
            });
        }
        self.observe_capacity(text.len(), copy.capacity(), component)?;
        copy.push_str(text);
        Ok(copy)
    }
}
pub(crate) fn response_string_storage(requested: usize) -> Result<String, ()> {
    let mut text = String::new();
    text.try_reserve_exact(requested).map_err(|_| ())?;
    Ok(text)
}
