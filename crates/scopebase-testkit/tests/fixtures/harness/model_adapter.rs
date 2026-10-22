// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::*;
use serde::{Deserialize, Serialize};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    kind: String,
    outcome: Raw,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    schema_version: u32,
    kind: String,
    expected_outcome: Raw,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Raw {
    Observed {
        schema_id: String,
        schema_revision: u32,
        bytes_hex: String,
    },
    Error {
        stage: String,
        category: Category,
        #[serde(deserialize_with = "required_errno")]
        errno: Option<i32>,
        cause: String,
        diagnostic_hex: String,
    },
}
// Deliberately excludes the adapter's own UnsupportedSchema category.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Category {
    Unavailable,
    Refused,
    InvalidOutput,
    Cancelled,
    TimedOut,
    Io,
    Other,
}
impl Category {
    fn typed(&self) -> CaseErrorCategory {
        match self {
            Self::Unavailable => CaseErrorCategory::Unavailable,
            Self::Refused => CaseErrorCategory::Refused,
            Self::InvalidOutput => CaseErrorCategory::InvalidOutput,
            Self::Cancelled => CaseErrorCategory::Cancelled,
            Self::TimedOut => CaseErrorCategory::TimedOut,
            Self::Io => CaseErrorCategory::Io,
            Self::Other => CaseErrorCategory::Other,
        }
    }
}
fn required_errno<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i32>, D::Error> {
    Option::<i32>::deserialize(d)
}
fn bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).ok()?, 16).ok())
        .collect()
}
fn cause(s: &str) -> Option<RefusalCause> {
    Some(match s {
        "permission" => RefusalCause::Permission,
        "verifier" => RefusalCause::Verifier,
        "license" => RefusalCause::License,
        "unsupported_operation" => RefusalCause::UnsupportedOperation,
        "unknown" => RefusalCause::Unknown,
        _ => return None,
    })
}
fn valid(raw: &Raw) -> bool {
    match raw {
        Raw::Observed {
            schema_id,
            schema_revision,
            bytes_hex,
        } => Label::parse(schema_id).is_ok() && *schema_revision > 0 && bytes(bytes_hex).is_some(),
        Raw::Error {
            stage,
            cause: c,
            diagnostic_hex,
            ..
        } => Label::parse(stage).is_ok() && cause(c).is_some() && bytes(diagnostic_hex).is_some(),
    }
}
pub fn expected_value(b: &[u8]) -> Option<serde_json::Value> {
    let raw: Expected = serde_json::from_slice(b).ok()?;
    if raw.schema_version != 1 || raw.kind != "tt02-model-expected" || !valid(&raw.expected_outcome)
    {
        return None;
    }
    serde_json::to_value(raw.expected_outcome).ok()
}
pub struct ModelAdapter {
    pub arithmetic: super::adapter::ArithmeticAdapter,
}
impl ModelAdapter {
    pub fn execute_with<'b>(
        &mut self,
        i: &CaseInvocation,
        mut input: impl FnMut(&Label) -> Option<&'b [u8]>,
    ) -> Result<Observation, CaseError> {
        if i.script().schema_id().as_str() != "tt02-refusal-v1" {
            return self.arithmetic.execute_with(i, input);
        }
        if i.script().steps().len() != 1
            || i.script().steps().iter().any(|s| {
                s.operation().as_str() != "emit-model-outcome"
                    || s.inputs().len() != 1
                    || !s.parameters().is_empty()
            })
        {
            return Err(super::adapter::preflight_error(i));
        }
        let step = &i.script().steps()[0];
        let l = i.limits();
        let invalid = || {
            super::adapter::operation_error(
                i,
                CaseErrorCategory::InvalidOutput,
                Some(step.step_id().clone()),
                vec![],
                None,
                b"invalid model operation transcript",
            )
        };
        let raw: Envelope = serde_json::from_slice(input(&step.inputs()[0]).unwrap_or(b""))
            .map_err(|_| invalid())?;
        if raw.schema_version != 1 || raw.kind != "tt02-model-outcome" || !valid(&raw.outcome) {
            return Err(invalid());
        }
        match raw.outcome {
            Raw::Observed {
                schema_id,
                schema_revision,
                bytes_hex,
            } => Observation::new(
                ObservationValues {
                    key: i.key().clone(),
                    schema_id: Label::parse(&schema_id).map_err(|_| invalid())?,
                    schema_revision,
                    completed_steps: vec![step.step_id().clone()],
                    bytes: bytes(&bytes_hex).ok_or_else(invalid)?,
                    effects: EffectBatch::empty(l),
                },
                l,
            )
            .map_err(|_| invalid()),
            Raw::Error {
                stage,
                category,
                errno,
                cause: c,
                diagnostic_hex,
            } => Err(CaseError::new(
                CaseErrorValues {
                    key: i.key().clone(),
                    step_id: Some(step.step_id().clone()),
                    stage: Label::parse(&stage).map_err(|_| invalid())?,
                    category: category.typed(),
                    errno,
                    diagnostic_bytes: bytes(&diagnostic_hex).ok_or_else(invalid)?,
                    cause: RefusalEvidence::new(
                        RefusalEvidenceValues {
                            cause: cause(&c).ok_or_else(invalid)?,
                            method: Label::parse("literal-model-transcript").unwrap(),
                            evidence_ids: vec![Label::parse("model-input").unwrap()],
                            tier: EvidenceTier::T0,
                        },
                        l,
                    )
                    .map_err(|_| invalid())?,
                    completed_steps: vec![],
                    partial_observation: None,
                    effects: EffectBatch::empty(l),
                },
                l,
            )
            .map_err(|_| invalid())?),
        }
    }
}
impl ConformanceAdapter for ModelAdapter {
    fn subject(&self) -> SubjectBinding {
        self.arithmetic.subject()
    }
    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        self.execute_with(i, |id| f.input(id))
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        self.arithmetic.retire(r)
    }
}
