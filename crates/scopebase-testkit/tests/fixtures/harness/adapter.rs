// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::*;
pub struct ArithmeticAdapter {
    pub subject: SubjectBinding,
    pub wrong: bool,
    pub calls: usize,
}
fn label(s: &str) -> Label {
    Label::parse(s).unwrap()
}
fn decimal(b: &[u8]) -> Option<u64> {
    if b.is_empty()
        || b.len() > 20
        || b.len() > 1 && b[0] == b'0'
        || !b.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}
pub fn preflight_error(i: &CaseInvocation) -> CaseError {
    operation_error(
        i,
        CaseErrorCategory::UnsupportedSchema,
        None,
        vec![],
        None,
        b"unsupported adapter dialect",
    )
}
pub fn operation_error(
    i: &CaseInvocation,
    category: CaseErrorCategory,
    step_id: Option<Label>,
    completed_steps: Vec<Label>,
    partial_observation: Option<PartialObservation>,
    diagnostic: &[u8],
) -> CaseError {
    let l = i.limits();
    let dialect = category == CaseErrorCategory::UnsupportedSchema;
    CaseError::new(
        CaseErrorValues {
            key: i.key().clone(),
            step_id,
            stage: label(if dialect {
                "adapter-schema"
            } else {
                "operation"
            }),
            category,
            errno: None,
            diagnostic_bytes: diagnostic[..diagnostic.len().min(l.diagnostic_bytes() as usize)]
                .to_vec(),
            cause: RefusalEvidence::new(
                RefusalEvidenceValues {
                    cause: RefusalCause::Unknown,
                    method: label(if dialect {
                        "adapter-dialect"
                    } else {
                        "checked-operation"
                    }),
                    evidence_ids: vec![],
                    tier: EvidenceTier::T0,
                },
                l,
            )
            .unwrap(),
            completed_steps,
            partial_observation,
            effects: EffectBatch::empty(l),
        },
        l,
    )
    .unwrap()
}
impl ArithmeticAdapter {
    pub fn execute_with<'b>(
        &mut self,
        i: &CaseInvocation,
        mut input: impl FnMut(&Label) -> Option<&'b [u8]>,
    ) -> Result<Observation, CaseError> {
        self.calls += 1;
        let l = i.limits();
        // This is the single body used by execute and counted acceptance tests.
        if i.script().schema_id().as_str() != "tt02-u64-v1"
            || i.script().steps().iter().any(|s| {
                s.inputs().len() != 1
                    || !s.parameters().is_empty()
                    || !matches!(s.operation().as_str(), "checked-add" | "decimal-length")
            })
        {
            return Err(preflight_error(i));
        }
        let mut values = vec![];
        let mut completed = vec![];
        for step in i.script().steps() {
            let b = input(&step.inputs()[0]).unwrap_or(b"");
            let lines = b
                .strip_suffix(b"\n")
                .map(|b| b.split(|b| *b == b'\n').collect::<Vec<_>>())
                .unwrap_or_default();
            let mut category = CaseErrorCategory::InvalidOutput;
            let result = match step.operation().as_str() {
                "checked-add" if lines.len() == 2 => match (decimal(lines[0]), decimal(lines[1])) {
                    (Some(a), Some(b)) => {
                        let n = a.checked_add(b);
                        if n.is_none() {
                            category = CaseErrorCategory::Refused;
                        }
                        n
                    }
                    _ => None,
                },
                "decimal-length" if lines.len() == 1 && decimal(lines[0]).is_some() => {
                    Some(lines[0].len() as u64)
                }
                _ => None,
            };
            if let Some(value) = result {
                let value = if self.wrong { 6 } else { value };
                values
                    .push(serde_json::json!({"step_id":step.step_id(),"value":value.to_string()}));
                completed.push(step.step_id().clone());
            } else {
                let partial=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"tt02-u64-observation","steps":values})).unwrap();
                return Err(operation_error(
                    i,
                    category,
                    Some(step.step_id().clone()),
                    completed,
                    PartialObservation::new(
                        PartialObservationValues {
                            schema_id: i.observation_schema().id().clone(),
                            schema_revision: *i.observation_schema().revision(),
                            bytes: partial,
                        },
                        l,
                    )
                    .ok(),
                    b"arithmetic refused",
                ));
            }
        }
        let bytes = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"kind":"tt02-u64-observation","steps":values}),
        )
        .unwrap();
        let progress = completed.clone();
        Observation::new(
            ObservationValues {
                key: i.key().clone(),
                schema_id: i.observation_schema().id().clone(),
                schema_revision: *i.observation_schema().revision(),
                completed_steps: completed,
                bytes,
                effects: EffectBatch::empty(l),
            },
            l,
        )
        .map_err(|_| {
            operation_error(
                i,
                CaseErrorCategory::InvalidOutput,
                None,
                progress,
                None,
                b"observation exceeds bound",
            )
        })
    }
}
impl ConformanceAdapter for ArithmeticAdapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }
    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        self.execute_with(i, |id| f.input(id))
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        RetirementReport::new(
            RetirementReportValues {
                call_id: r.call_id(),
                owner: r.owner(),
                scope: r.scope().clone(),
                discovered: vec![],
                transitions: vec![],
                pending_snapshot: r.known_pending().to_vec(),
                complete: true,
                diagnostic: None,
            },
            &RunLimits::default(),
        )
        .unwrap()
    }
}
