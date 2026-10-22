// SPDX-License-Identifier: Apache-2.0
//! Literal expected evidence only. No subject operation determines expected truth.
use scopebase_testkit::*;
pub struct LiteralOracle {
    pub binding: OracleBinding,
    pub rules: Vec<CaseRule>,
    pub limits: RunLimits,
}
fn actual(outcome: &CaseOutcome) -> Vec<u8> {
    match outcome {
        CaseOutcome::Observed(v) => {
            let mut bytes = b"observed\n".to_vec();
            bytes.extend_from_slice(v.bytes());
            bytes
        }
        CaseOutcome::OperationError(e) => {
            let category = match e.category() {
                CaseErrorCategory::Refused => "refused",
                CaseErrorCategory::InvalidOutput => "invalid_output",
                CaseErrorCategory::UnsupportedSchema => "unsupported_schema",
                _ => "unexpected",
            };
            let mut bytes = format!("error\n{category}\n{}\n", e.stage().as_str()).into_bytes();
            bytes.extend_from_slice(e.diagnostic_bytes());
            if *e.errno() != None
                || *e.cause().cause() != RefusalCause::Unknown
                || e.cause().method().as_str() != "bp03-model"
                || !e.completed_steps().is_empty()
                || e.partial_observation().is_some()
                || !e.effects().registrations().is_empty()
                || !*e.effects().complete()
            {
                bytes.extend_from_slice(b"\ninvalid-response-shape");
            }
            bytes
        }
    }
}
impl CaseOracle for LiteralOracle {
    fn identity(&self) -> OracleBinding {
        self.binding.clone()
    }
    fn evaluate(
        &self,
        case: &CaseSpec,
        expected: &ExpectedEvidence,
        outcome: &CaseOutcome,
    ) -> AssertionVerdict {
        let rule = self
            .rules
            .iter()
            .find(|r| r.case_key().case_id() == case.id())
            .unwrap();
        let pass = actual(outcome) == *expected.expected_bytes()
            && expected.coverage().is_empty()
            && *expected.truth_kind() == TruthKind::FixedBeforeExecute;
        let checks = rule
            .assertions()
            .iter()
            .map(|a| {
                AssertionCheck::new(
                    AssertionCheckValues {
                        id: a.id().clone(),
                        status: if pass {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Fail
                        },
                        reason: None,
                    },
                    &self.limits,
                )
                .unwrap()
            })
            .collect();
        AssertionVerdict::new(
            AssertionVerdictValues {
                harness: HarnessValidity::Valid,
                checks,
                capability: CapabilityEvidence::new(
                    CapabilityEvidenceValues {
                        state: CapabilityState::Unknown,
                        method: Label::parse("literal-model-oracle").unwrap(),
                        context: "T0 supplied descriptive facts; actual environment unknown".into(),
                        evidence_ids: vec![],
                    },
                    &self.limits,
                )
                .unwrap(),
            },
            &self.limits,
        )
        .unwrap()
    }
}
