// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::*;
pub struct ArithmeticOracle {
    pub binding: OracleBinding,
}
impl CaseOracle for ArithmeticOracle {
    fn identity(&self) -> OracleBinding {
        self.binding.clone()
    }
    fn evaluate(&self, _: &CaseSpec, e: &ExpectedEvidence, o: &CaseOutcome) -> AssertionVerdict {
        let l = RunLimits::default();
        let expected: serde_json::Value = serde_json::from_slice(e.expected_bytes()).unwrap();
        let actual = match o {
            CaseOutcome::Observed(x) => serde_json::from_slice::<serde_json::Value>(x.bytes()).ok(),
            _ => None,
        };
        let preflight = matches!(o,CaseOutcome::OperationError(error)if *error.category()==CaseErrorCategory::UnsupportedSchema);
        let pass = actual.as_ref().is_some_and(|a| {
            a["kind"] == "tt02-u64-observation"
                && expected["kind"] == "tt02-u64-expected"
                && a["steps"] == expected["steps"]
        });
        AssertionVerdict::new(
            AssertionVerdictValues {
                harness: HarnessValidity::Valid,
                checks: vec![AssertionCheck::new(
                    AssertionCheckValues {
                        id: Label::parse("value.equal").unwrap(),
                        status: if preflight {
                            CheckStatus::NotJudged
                        } else if pass {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Fail
                        },
                        reason: None,
                    },
                    &l,
                )
                .unwrap()],
                capability: CapabilityEvidence::new(
                    CapabilityEvidenceValues {
                        state: if preflight {
                            CapabilityState::Unknown
                        } else {
                            CapabilityState::Supported
                        },
                        method: Label::parse("independent-literal").unwrap(),
                        context: "T0 arithmetic model".into(),
                        evidence_ids: vec![Label::parse("expected").unwrap()],
                    },
                    &l,
                )
                .unwrap(),
            },
            &l,
        )
        .unwrap()
    }
}
