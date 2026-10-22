// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::*;
pub struct ModelOracle {
    pub arithmetic: super::oracle::ArithmeticOracle,
    pub rules: Vec<CaseRule>,
    pub source_terms: Vec<u8>,
    pub elf_license: Vec<u8>,
    pub loader_license: Vec<u8>,
    pub context: Vec<u8>,
    pub objects: Vec<ArtifactBinding>,
}
impl CaseOracle for ModelOracle {
    fn identity(&self) -> OracleBinding {
        self.arithmetic.identity()
    }
    fn evaluate(&self, case: &CaseSpec, e: &ExpectedEvidence, o: &CaseOutcome) -> AssertionVerdict {
        let r = self
            .rules
            .iter()
            .find(|r| r.case_key().case_id() == case.id())
            .unwrap();
        if r.script().schema_id().as_str() != "tt02-refusal-v1" {
            return self.arithmetic.evaluate(case, e, o);
        }
        let expected = super::model_adapter::expected_value(e.expected_bytes());
        let expected_valid = expected.is_some();
        let want = expected.unwrap_or(serde_json::Value::Null);
        let preflight = matches!(o,CaseOutcome::OperationError(error)if *error.category()==CaseErrorCategory::UnsupportedSchema);
        let l = RunLimits::default();
        let status = match o {
            CaseOutcome::OperationError(err) => {
                if preflight
                    || *err.cause().cause() == RefusalCause::Unknown
                        && !matches!(r.intent(), ClaimIntent::AssertionOnly)
                {
                    CheckStatus::NotJudged
                } else {
                    let cause = serde_json::to_value(err.cause().cause()).unwrap();
                    let diagnostic = err
                        .diagnostic_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>();
                    if want["kind"] == "error"
                        && want["stage"] == err.stage().as_str()
                        && want["cause"] == cause
                        && want["errno"] == serde_json::to_value(err.errno()).unwrap()
                        && want["category"] == serde_json::to_value(err.category()).unwrap()
                        && want["diagnostic_hex"] == diagnostic
                    {
                        CheckStatus::Pass
                    } else {
                        CheckStatus::Fail
                    }
                }
            }
            CaseOutcome::Observed(observed) => {
                let bytes = observed
                    .bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                if want["kind"] == "observed"
                    && want["schema_id"] == observed.schema_id().as_str()
                    && want["schema_revision"] == *observed.schema_revision()
                    && want["bytes_hex"] == bytes
                {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                }
            }
        };
        let cap = if preflight {
            CapabilityState::Unknown
        } else {
            match o {
                CaseOutcome::OperationError(err) => match err.cause().cause() {
                    RefusalCause::Permission => CapabilityState::Denied,
                    RefusalCause::Verifier | RefusalCause::License => CapabilityState::Incompatible,
                    RefusalCause::UnsupportedOperation => CapabilityState::Unsupported,
                    RefusalCause::Unknown => CapabilityState::Unknown,
                },
                _ => CapabilityState::Supported,
            }
        };
        let context: serde_json::Value = serde_json::from_slice(&self.context).unwrap();
        let equivalent = if let ClaimIntent::ExpectedRefusal { positive_twin, .. } = r.intent() {
            context["positive_twin"] == serde_json::to_value(positive_twin).unwrap()
                && context["negative_case"] == serde_json::to_value(r.case_key()).unwrap()
                && context["operation"] == "emit-model-outcome"
                && context["positive_context"] == "owned-model-context"
                && context["negative_context"] == "owned-model-context"
                && context["helper"] == "GPL-only-helper-model"
                && [
                    ("positive-object", "positive_object_sha256"),
                    ("negative-object", "negative_object_sha256"),
                    ("positive-license", "positive_license_sha256"),
                ]
                .into_iter()
                .all(|(id, key)| {
                    self.objects
                        .iter()
                        .find(|a| a.id().as_str() == id)
                        .is_some_and(|a| context[key] == a.sha256().as_str())
                })
        } else {
            true
        };
        let checks = r
            .assertions()
            .iter()
            .map(|a| {
                AssertionCheck::new(
                    AssertionCheckValues {
                        id: a.id().clone(),
                        status: if a.id().as_str() == "input.license-bytes" {
                            if self.source_terms != b"Apache-2.0 OR GPL-2.0-only\n"
                                || self.elf_license != b"Proprietary\0"
                                || self.loader_license != b"Proprietary\0"
                            {
                                CheckStatus::Fail
                            } else {
                                CheckStatus::Pass
                            }
                        } else if a.id().as_str() == "twin.equivalent" {
                            if equivalent {
                                CheckStatus::Pass
                            } else {
                                CheckStatus::Fail
                            }
                        } else {
                            status
                        },
                        reason: None,
                    },
                    &l,
                )
                .unwrap()
            })
            .collect();
        AssertionVerdict::new(
            AssertionVerdictValues {
                harness: if expected_valid {
                    HarnessValidity::Valid
                } else {
                    HarnessValidity::Invalid {
                        reason: "invalid independent model expectation".into(),
                    }
                },
                checks,
                capability: CapabilityEvidence::new(
                    CapabilityEvidenceValues {
                        state: cap,
                        method: Label::parse("independent-model-witness").unwrap(),
                        context: "T0 literal transcript; no kernel or legal inference".into(),
                        evidence_ids: [
                            "elf-license",
                            "equivalence-model",
                            "expected-model",
                            "loader-license",
                            "negative-object",
                            "positive-license",
                            "positive-object",
                            "source-terms",
                        ]
                        .into_iter()
                        .map(|s| Label::parse(s).unwrap())
                        .collect(),
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
