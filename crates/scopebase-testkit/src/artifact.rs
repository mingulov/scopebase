// SPDX-License-Identifier: Apache-2.0
//! Checked descriptive bindings and bounded positional byte measurement.
use crate::*;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, error::Error, fmt, fs::File, os::unix::fs::FileExt};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingErrorKind {
    InvalidField,
    InvalidDigest,
    Duplicate,
    Unsorted,
    LengthMismatch,
    DigestMismatch,
    SubjectMismatch,
    MissingArtifact,
    NotRegular,
    LimitExceeded,
    Io,
}
#[derive(Clone, Debug)]
pub struct BindingError {
    pub(crate) kind: BindingErrorKind,
    pub(crate) field: String,
    pub(crate) progress: Option<InputReadProgress>,
    pub(crate) diagnostic: String,
}
impl BindingError {
    pub fn kind(&self) -> BindingErrorKind {
        self.kind
    }
    pub fn field(&self) -> &str {
        &self.field
    }
    pub fn progress(&self) -> Option<&InputReadProgress> {
        self.progress.as_ref()
    }
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}
impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "binding {:?}: {}", self.kind, self.field)
    }
}
impl Error for BindingError {}
pub(crate) fn be(kind: BindingErrorKind, field: &str) -> BindingError {
    BindingError {
        kind,
        field: field.into(),
        progress: None,
        diagnostic: String::new(),
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessErrorKind {
    InvalidInput,
    InvalidBinding,
    InvalidSelection,
    InvalidProtocol,
    UnsupportedSchema,
    LimitExceeded,
    Io,
}
#[derive(Debug)]
pub struct HarnessError {
    pub(crate) kind: HarnessErrorKind,
    pub(crate) diagnostic: String,
    pub(crate) partial: Option<Box<RunReport>>,
}
impl HarnessError {
    pub fn kind(&self) -> HarnessErrorKind {
        self.kind
    }
    pub fn partial_report(&self) -> Option<&RunReport> {
        self.partial.as_deref()
    }
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}
impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "harness {:?}: {}", self.kind, self.diagnostic)
    }
}
impl Error for HarnessError {}
pub(crate) fn he(kind: HarnessErrorKind, s: &str) -> HarnessError {
    HarnessError {
        kind,
        diagnostic: s.chars().take(65536).collect(),
        partial: None,
    }
}
impl From<BindingError> for HarnessError {
    fn from(e: BindingError) -> Self {
        he(HarnessErrorKind::InvalidBinding, &e.to_string())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitErrorKind {
    Zero,
    AboveMaximum,
    NotLower,
    CrossField,
    PlatformOverflow,
}
#[derive(Clone, Debug)]
pub struct LimitError {
    field: &'static str,
    requested: u64,
    maximum: u64,
    kind: LimitErrorKind,
}
impl LimitError {
    pub fn kind(&self) -> LimitErrorKind {
        self.kind
    }
    pub fn field(&self) -> &str {
        self.field
    }
    pub fn requested(&self) -> u64 {
        self.requested
    }
    pub fn maximum(&self) -> u64 {
        self.maximum
    }
}
impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "limit {} {:?}: {} (max {})",
            self.field, self.kind, self.requested, self.maximum
        )
    }
}
impl Error for LimitError {}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunLimitValues {
    #[serde(with = "decimal")]
    pub input_bytes: u64,
    #[serde(with = "decimal")]
    pub observation_bytes: u64,
    #[serde(with = "decimal")]
    pub vector_bytes: u64,
    #[serde(with = "decimal")]
    pub receipt_bytes: u64,
    #[serde(with = "decimal")]
    pub retained_bytes: u64,
    #[serde(with = "decimal")]
    pub diagnostic_bytes: u64,
    #[serde(with = "decimal")]
    pub name_bytes: u64,
    #[serde(with = "decimal")]
    pub label_bytes: u64,
    #[serde(with = "decimal")]
    pub measure_file_bytes: u64,
    #[serde(with = "decimal")]
    pub measure_total_bytes: u64,
    #[serde(with = "decimal")]
    pub read_calls: u64,
    #[serde(with = "decimal")]
    pub measurement_attempts: u64,
    #[serde(with = "decimal")]
    pub case_attempts: u64,
    #[serde(with = "decimal")]
    pub steps_per_invocation: u64,
    #[serde(with = "decimal")]
    pub steps_total: u64,
    #[serde(with = "decimal")]
    pub attempts_per_case: u64,
    #[serde(with = "decimal")]
    pub assertions_per_case: u64,
    #[serde(with = "decimal")]
    pub coverage_per_case: u64,
    #[serde(with = "decimal")]
    pub effects_per_case: u64,
    #[serde(with = "decimal")]
    pub assertion_records: u64,
    #[serde(with = "decimal")]
    pub coverage_records: u64,
    #[serde(with = "decimal")]
    pub effects_total: u64,
    #[serde(with = "decimal")]
    pub features: u64,
    #[serde(with = "decimal")]
    pub artifacts: u64,
    #[serde(with = "decimal")]
    pub input_slots: u64,
    #[serde(with = "decimal")]
    pub script_parameters: u64,
    #[serde(with = "decimal")]
    pub resource_views: u64,
    #[serde(with = "decimal")]
    pub scalar_bytes: u64,
    #[serde(with = "decimal")]
    pub json_depth: u64,
    #[serde(with = "decimal")]
    pub json_edges: u64,
    #[serde(with = "decimal")]
    pub execution_ms: u64,
    #[serde(with = "decimal")]
    pub retirement_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RunLimits(pub(crate) RunLimitValues);
impl Default for RunLimits {
    fn default() -> Self {
        Self(RunLimitValues {
            input_bytes: 8388608,
            observation_bytes: 8388608,
            vector_bytes: 8388608,
            receipt_bytes: 8388608,
            retained_bytes: 67108864,
            diagnostic_bytes: 65536,
            name_bytes: 256,
            label_bytes: 96,
            measure_file_bytes: 268435456,
            measure_total_bytes: 1073741824,
            read_calls: 65536,
            measurement_attempts: 4096,
            case_attempts: 4096,
            steps_per_invocation: 64,
            steps_total: 65536,
            attempts_per_case: 16,
            assertions_per_case: 64,
            coverage_per_case: 64,
            effects_per_case: 64,
            assertion_records: 65536,
            coverage_records: 65536,
            effects_total: 4096,
            features: 256,
            artifacts: 4096,
            input_slots: 16,
            script_parameters: 16,
            resource_views: 64,
            scalar_bytes: 4096,
            json_depth: 32,
            json_edges: 262144,
            execution_ms: 30000,
            retirement_ms: 5000,
        })
    }
}
impl RunLimits {
    pub fn values(&self) -> RunLimitValues {
        self.0.clone()
    }
    pub fn maxima() -> RunLimitValues {
        RunLimitValues {
            input_bytes: 8388608,
            observation_bytes: 8388608,
            vector_bytes: 8388608,
            receipt_bytes: 8388608,
            retained_bytes: 67108864,
            diagnostic_bytes: 65536,
            name_bytes: 256,
            label_bytes: 96,
            measure_file_bytes: 1073741824,
            measure_total_bytes: 4294967296,
            read_calls: 262144,
            measurement_attempts: 4096,
            case_attempts: 4096,
            steps_per_invocation: 64,
            steps_total: 65536,
            attempts_per_case: 16,
            assertions_per_case: 64,
            coverage_per_case: 64,
            effects_per_case: 64,
            assertion_records: 65536,
            coverage_records: 65536,
            effects_total: 4096,
            features: 256,
            artifacts: 4096,
            input_slots: 16,
            script_parameters: 16,
            resource_views: 64,
            scalar_bytes: 4096,
            json_depth: 32,
            json_edges: 262144,
            execution_ms: 600000,
            retirement_ms: 30000,
        }
    }
    pub fn new(v: RunLimitValues) -> Result<Self, LimitError> {
        let m = Self::maxima();
        if v.input_bytes == 0 || v.input_bytes > m.input_bytes {
            return Err(LimitError {
                field: "input_bytes",
                requested: v.input_bytes,
                maximum: m.input_bytes,
                kind: if v.input_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.input_bytes).is_err() {
            return Err(LimitError {
                field: "input_bytes",
                requested: v.input_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.observation_bytes == 0 || v.observation_bytes > m.observation_bytes {
            return Err(LimitError {
                field: "observation_bytes",
                requested: v.observation_bytes,
                maximum: m.observation_bytes,
                kind: if v.observation_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.observation_bytes).is_err() {
            return Err(LimitError {
                field: "observation_bytes",
                requested: v.observation_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.vector_bytes == 0 || v.vector_bytes > m.vector_bytes {
            return Err(LimitError {
                field: "vector_bytes",
                requested: v.vector_bytes,
                maximum: m.vector_bytes,
                kind: if v.vector_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.vector_bytes).is_err() {
            return Err(LimitError {
                field: "vector_bytes",
                requested: v.vector_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.receipt_bytes == 0 || v.receipt_bytes > m.receipt_bytes {
            return Err(LimitError {
                field: "receipt_bytes",
                requested: v.receipt_bytes,
                maximum: m.receipt_bytes,
                kind: if v.receipt_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.receipt_bytes).is_err() {
            return Err(LimitError {
                field: "receipt_bytes",
                requested: v.receipt_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.retained_bytes == 0 || v.retained_bytes > m.retained_bytes {
            return Err(LimitError {
                field: "retained_bytes",
                requested: v.retained_bytes,
                maximum: m.retained_bytes,
                kind: if v.retained_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.retained_bytes).is_err() {
            return Err(LimitError {
                field: "retained_bytes",
                requested: v.retained_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.diagnostic_bytes == 0 || v.diagnostic_bytes > m.diagnostic_bytes {
            return Err(LimitError {
                field: "diagnostic_bytes",
                requested: v.diagnostic_bytes,
                maximum: m.diagnostic_bytes,
                kind: if v.diagnostic_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.diagnostic_bytes).is_err() {
            return Err(LimitError {
                field: "diagnostic_bytes",
                requested: v.diagnostic_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.name_bytes == 0 || v.name_bytes > m.name_bytes {
            return Err(LimitError {
                field: "name_bytes",
                requested: v.name_bytes,
                maximum: m.name_bytes,
                kind: if v.name_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.name_bytes).is_err() {
            return Err(LimitError {
                field: "name_bytes",
                requested: v.name_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.label_bytes == 0 || v.label_bytes > m.label_bytes {
            return Err(LimitError {
                field: "label_bytes",
                requested: v.label_bytes,
                maximum: m.label_bytes,
                kind: if v.label_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.label_bytes).is_err() {
            return Err(LimitError {
                field: "label_bytes",
                requested: v.label_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.measure_file_bytes == 0 || v.measure_file_bytes > m.measure_file_bytes {
            return Err(LimitError {
                field: "measure_file_bytes",
                requested: v.measure_file_bytes,
                maximum: m.measure_file_bytes,
                kind: if v.measure_file_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.measure_file_bytes).is_err() {
            return Err(LimitError {
                field: "measure_file_bytes",
                requested: v.measure_file_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.measure_total_bytes == 0 || v.measure_total_bytes > m.measure_total_bytes {
            return Err(LimitError {
                field: "measure_total_bytes",
                requested: v.measure_total_bytes,
                maximum: m.measure_total_bytes,
                kind: if v.measure_total_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.measure_total_bytes).is_err() {
            return Err(LimitError {
                field: "measure_total_bytes",
                requested: v.measure_total_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.read_calls == 0 || v.read_calls > m.read_calls {
            return Err(LimitError {
                field: "read_calls",
                requested: v.read_calls,
                maximum: m.read_calls,
                kind: if v.read_calls == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.read_calls).is_err() {
            return Err(LimitError {
                field: "read_calls",
                requested: v.read_calls,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.measurement_attempts == 0 || v.measurement_attempts > m.measurement_attempts {
            return Err(LimitError {
                field: "measurement_attempts",
                requested: v.measurement_attempts,
                maximum: m.measurement_attempts,
                kind: if v.measurement_attempts == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.measurement_attempts).is_err() {
            return Err(LimitError {
                field: "measurement_attempts",
                requested: v.measurement_attempts,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.case_attempts == 0 || v.case_attempts > m.case_attempts {
            return Err(LimitError {
                field: "case_attempts",
                requested: v.case_attempts,
                maximum: m.case_attempts,
                kind: if v.case_attempts == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.case_attempts).is_err() {
            return Err(LimitError {
                field: "case_attempts",
                requested: v.case_attempts,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.steps_per_invocation == 0 || v.steps_per_invocation > m.steps_per_invocation {
            return Err(LimitError {
                field: "steps_per_invocation",
                requested: v.steps_per_invocation,
                maximum: m.steps_per_invocation,
                kind: if v.steps_per_invocation == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.steps_per_invocation).is_err() {
            return Err(LimitError {
                field: "steps_per_invocation",
                requested: v.steps_per_invocation,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.steps_total == 0 || v.steps_total > m.steps_total {
            return Err(LimitError {
                field: "steps_total",
                requested: v.steps_total,
                maximum: m.steps_total,
                kind: if v.steps_total == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.steps_total).is_err() {
            return Err(LimitError {
                field: "steps_total",
                requested: v.steps_total,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.attempts_per_case == 0 || v.attempts_per_case > m.attempts_per_case {
            return Err(LimitError {
                field: "attempts_per_case",
                requested: v.attempts_per_case,
                maximum: m.attempts_per_case,
                kind: if v.attempts_per_case == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.attempts_per_case).is_err() {
            return Err(LimitError {
                field: "attempts_per_case",
                requested: v.attempts_per_case,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.assertions_per_case == 0 || v.assertions_per_case > m.assertions_per_case {
            return Err(LimitError {
                field: "assertions_per_case",
                requested: v.assertions_per_case,
                maximum: m.assertions_per_case,
                kind: if v.assertions_per_case == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.assertions_per_case).is_err() {
            return Err(LimitError {
                field: "assertions_per_case",
                requested: v.assertions_per_case,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.coverage_per_case == 0 || v.coverage_per_case > m.coverage_per_case {
            return Err(LimitError {
                field: "coverage_per_case",
                requested: v.coverage_per_case,
                maximum: m.coverage_per_case,
                kind: if v.coverage_per_case == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.coverage_per_case).is_err() {
            return Err(LimitError {
                field: "coverage_per_case",
                requested: v.coverage_per_case,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.effects_per_case == 0 || v.effects_per_case > m.effects_per_case {
            return Err(LimitError {
                field: "effects_per_case",
                requested: v.effects_per_case,
                maximum: m.effects_per_case,
                kind: if v.effects_per_case == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.effects_per_case).is_err() {
            return Err(LimitError {
                field: "effects_per_case",
                requested: v.effects_per_case,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.assertion_records == 0 || v.assertion_records > m.assertion_records {
            return Err(LimitError {
                field: "assertion_records",
                requested: v.assertion_records,
                maximum: m.assertion_records,
                kind: if v.assertion_records == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.assertion_records).is_err() {
            return Err(LimitError {
                field: "assertion_records",
                requested: v.assertion_records,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.coverage_records == 0 || v.coverage_records > m.coverage_records {
            return Err(LimitError {
                field: "coverage_records",
                requested: v.coverage_records,
                maximum: m.coverage_records,
                kind: if v.coverage_records == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.coverage_records).is_err() {
            return Err(LimitError {
                field: "coverage_records",
                requested: v.coverage_records,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.effects_total == 0 || v.effects_total > m.effects_total {
            return Err(LimitError {
                field: "effects_total",
                requested: v.effects_total,
                maximum: m.effects_total,
                kind: if v.effects_total == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.effects_total).is_err() {
            return Err(LimitError {
                field: "effects_total",
                requested: v.effects_total,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.features == 0 || v.features > m.features {
            return Err(LimitError {
                field: "features",
                requested: v.features,
                maximum: m.features,
                kind: if v.features == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.features).is_err() {
            return Err(LimitError {
                field: "features",
                requested: v.features,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.artifacts == 0 || v.artifacts > m.artifacts {
            return Err(LimitError {
                field: "artifacts",
                requested: v.artifacts,
                maximum: m.artifacts,
                kind: if v.artifacts == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.artifacts).is_err() {
            return Err(LimitError {
                field: "artifacts",
                requested: v.artifacts,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.input_slots == 0 || v.input_slots > m.input_slots {
            return Err(LimitError {
                field: "input_slots",
                requested: v.input_slots,
                maximum: m.input_slots,
                kind: if v.input_slots == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.input_slots).is_err() {
            return Err(LimitError {
                field: "input_slots",
                requested: v.input_slots,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.script_parameters == 0 || v.script_parameters > m.script_parameters {
            return Err(LimitError {
                field: "script_parameters",
                requested: v.script_parameters,
                maximum: m.script_parameters,
                kind: if v.script_parameters == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.script_parameters).is_err() {
            return Err(LimitError {
                field: "script_parameters",
                requested: v.script_parameters,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.resource_views == 0 || v.resource_views > m.resource_views {
            return Err(LimitError {
                field: "resource_views",
                requested: v.resource_views,
                maximum: m.resource_views,
                kind: if v.resource_views == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.resource_views).is_err() {
            return Err(LimitError {
                field: "resource_views",
                requested: v.resource_views,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.scalar_bytes == 0 || v.scalar_bytes > m.scalar_bytes {
            return Err(LimitError {
                field: "scalar_bytes",
                requested: v.scalar_bytes,
                maximum: m.scalar_bytes,
                kind: if v.scalar_bytes == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.scalar_bytes).is_err() {
            return Err(LimitError {
                field: "scalar_bytes",
                requested: v.scalar_bytes,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.json_depth == 0 || v.json_depth > m.json_depth {
            return Err(LimitError {
                field: "json_depth",
                requested: v.json_depth,
                maximum: m.json_depth,
                kind: if v.json_depth == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.json_depth).is_err() {
            return Err(LimitError {
                field: "json_depth",
                requested: v.json_depth,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.json_edges == 0 || v.json_edges > m.json_edges {
            return Err(LimitError {
                field: "json_edges",
                requested: v.json_edges,
                maximum: m.json_edges,
                kind: if v.json_edges == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.json_edges).is_err() {
            return Err(LimitError {
                field: "json_edges",
                requested: v.json_edges,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.execution_ms == 0 || v.execution_ms > m.execution_ms {
            return Err(LimitError {
                field: "execution_ms",
                requested: v.execution_ms,
                maximum: m.execution_ms,
                kind: if v.execution_ms == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.execution_ms).is_err() {
            return Err(LimitError {
                field: "execution_ms",
                requested: v.execution_ms,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        if v.retirement_ms == 0 || v.retirement_ms > m.retirement_ms {
            return Err(LimitError {
                field: "retirement_ms",
                requested: v.retirement_ms,
                maximum: m.retirement_ms,
                kind: if v.retirement_ms == 0 {
                    LimitErrorKind::Zero
                } else {
                    LimitErrorKind::AboveMaximum
                },
            });
        }
        if usize::try_from(v.retirement_ms).is_err() {
            return Err(LimitError {
                field: "retirement_ms",
                requested: v.retirement_ms,
                maximum: usize::MAX as u64,
                kind: LimitErrorKind::PlatformOverflow,
            });
        }
        let cross = v.steps_total < v.steps_per_invocation
            || v.assertion_records < v.assertions_per_case
            || v.coverage_records < v.coverage_per_case
            || v.effects_total < v.effects_per_case
            || v.case_attempts < v.attempts_per_case
            || v.measure_file_bytes
                .checked_add(1)
                .is_none_or(|x| x > v.measure_total_bytes)
            || v.retained_bytes < 65536
            || [
                v.input_bytes,
                v.observation_bytes,
                v.vector_bytes,
                v.receipt_bytes,
                v.diagnostic_bytes,
            ]
            .iter()
            .any(|x| *x > v.retained_bytes);
        if cross {
            return Err(LimitError {
                field: "cross_field",
                requested: 0,
                maximum: 0,
                kind: LimitErrorKind::CrossField,
            });
        }
        Ok(Self(v))
    }
    pub fn lowered(&self, v: RunLimitValues) -> Result<Self, LimitError> {
        let admitted = Self::new(v.clone())?;
        if v.input_bytes > self.0.input_bytes {
            return Err(LimitError {
                field: "input_bytes",
                requested: v.input_bytes,
                maximum: self.0.input_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.observation_bytes > self.0.observation_bytes {
            return Err(LimitError {
                field: "observation_bytes",
                requested: v.observation_bytes,
                maximum: self.0.observation_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.vector_bytes > self.0.vector_bytes {
            return Err(LimitError {
                field: "vector_bytes",
                requested: v.vector_bytes,
                maximum: self.0.vector_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.receipt_bytes > self.0.receipt_bytes {
            return Err(LimitError {
                field: "receipt_bytes",
                requested: v.receipt_bytes,
                maximum: self.0.receipt_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.retained_bytes > self.0.retained_bytes {
            return Err(LimitError {
                field: "retained_bytes",
                requested: v.retained_bytes,
                maximum: self.0.retained_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.diagnostic_bytes > self.0.diagnostic_bytes {
            return Err(LimitError {
                field: "diagnostic_bytes",
                requested: v.diagnostic_bytes,
                maximum: self.0.diagnostic_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.name_bytes > self.0.name_bytes {
            return Err(LimitError {
                field: "name_bytes",
                requested: v.name_bytes,
                maximum: self.0.name_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.label_bytes > self.0.label_bytes {
            return Err(LimitError {
                field: "label_bytes",
                requested: v.label_bytes,
                maximum: self.0.label_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.measure_file_bytes > self.0.measure_file_bytes {
            return Err(LimitError {
                field: "measure_file_bytes",
                requested: v.measure_file_bytes,
                maximum: self.0.measure_file_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.measure_total_bytes > self.0.measure_total_bytes {
            return Err(LimitError {
                field: "measure_total_bytes",
                requested: v.measure_total_bytes,
                maximum: self.0.measure_total_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.read_calls > self.0.read_calls {
            return Err(LimitError {
                field: "read_calls",
                requested: v.read_calls,
                maximum: self.0.read_calls,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.measurement_attempts > self.0.measurement_attempts {
            return Err(LimitError {
                field: "measurement_attempts",
                requested: v.measurement_attempts,
                maximum: self.0.measurement_attempts,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.case_attempts > self.0.case_attempts {
            return Err(LimitError {
                field: "case_attempts",
                requested: v.case_attempts,
                maximum: self.0.case_attempts,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.steps_per_invocation > self.0.steps_per_invocation {
            return Err(LimitError {
                field: "steps_per_invocation",
                requested: v.steps_per_invocation,
                maximum: self.0.steps_per_invocation,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.steps_total > self.0.steps_total {
            return Err(LimitError {
                field: "steps_total",
                requested: v.steps_total,
                maximum: self.0.steps_total,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.attempts_per_case > self.0.attempts_per_case {
            return Err(LimitError {
                field: "attempts_per_case",
                requested: v.attempts_per_case,
                maximum: self.0.attempts_per_case,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.assertions_per_case > self.0.assertions_per_case {
            return Err(LimitError {
                field: "assertions_per_case",
                requested: v.assertions_per_case,
                maximum: self.0.assertions_per_case,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.coverage_per_case > self.0.coverage_per_case {
            return Err(LimitError {
                field: "coverage_per_case",
                requested: v.coverage_per_case,
                maximum: self.0.coverage_per_case,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.effects_per_case > self.0.effects_per_case {
            return Err(LimitError {
                field: "effects_per_case",
                requested: v.effects_per_case,
                maximum: self.0.effects_per_case,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.assertion_records > self.0.assertion_records {
            return Err(LimitError {
                field: "assertion_records",
                requested: v.assertion_records,
                maximum: self.0.assertion_records,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.coverage_records > self.0.coverage_records {
            return Err(LimitError {
                field: "coverage_records",
                requested: v.coverage_records,
                maximum: self.0.coverage_records,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.effects_total > self.0.effects_total {
            return Err(LimitError {
                field: "effects_total",
                requested: v.effects_total,
                maximum: self.0.effects_total,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.features > self.0.features {
            return Err(LimitError {
                field: "features",
                requested: v.features,
                maximum: self.0.features,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.artifacts > self.0.artifacts {
            return Err(LimitError {
                field: "artifacts",
                requested: v.artifacts,
                maximum: self.0.artifacts,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.input_slots > self.0.input_slots {
            return Err(LimitError {
                field: "input_slots",
                requested: v.input_slots,
                maximum: self.0.input_slots,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.script_parameters > self.0.script_parameters {
            return Err(LimitError {
                field: "script_parameters",
                requested: v.script_parameters,
                maximum: self.0.script_parameters,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.resource_views > self.0.resource_views {
            return Err(LimitError {
                field: "resource_views",
                requested: v.resource_views,
                maximum: self.0.resource_views,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.scalar_bytes > self.0.scalar_bytes {
            return Err(LimitError {
                field: "scalar_bytes",
                requested: v.scalar_bytes,
                maximum: self.0.scalar_bytes,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.json_depth > self.0.json_depth {
            return Err(LimitError {
                field: "json_depth",
                requested: v.json_depth,
                maximum: self.0.json_depth,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.json_edges > self.0.json_edges {
            return Err(LimitError {
                field: "json_edges",
                requested: v.json_edges,
                maximum: self.0.json_edges,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.execution_ms > self.0.execution_ms {
            return Err(LimitError {
                field: "execution_ms",
                requested: v.execution_ms,
                maximum: self.0.execution_ms,
                kind: LimitErrorKind::NotLower,
            });
        }
        if v.retirement_ms > self.0.retirement_ms {
            return Err(LimitError {
                field: "retirement_ms",
                requested: v.retirement_ms,
                maximum: self.0.retirement_ms,
                kind: LimitErrorKind::NotLower,
            });
        }
        Ok(admitted)
    }
    pub fn input_bytes(&self) -> u64 {
        self.0.input_bytes
    }
    pub fn observation_bytes(&self) -> u64 {
        self.0.observation_bytes
    }
    pub fn vector_bytes(&self) -> u64 {
        self.0.vector_bytes
    }
    pub fn receipt_bytes(&self) -> u64 {
        self.0.receipt_bytes
    }
    pub fn retained_bytes(&self) -> u64 {
        self.0.retained_bytes
    }
    pub fn diagnostic_bytes(&self) -> u64 {
        self.0.diagnostic_bytes
    }
    pub fn name_bytes(&self) -> u64 {
        self.0.name_bytes
    }
    pub fn label_bytes(&self) -> u64 {
        self.0.label_bytes
    }
    pub fn measure_file_bytes(&self) -> u64 {
        self.0.measure_file_bytes
    }
    pub fn measure_total_bytes(&self) -> u64 {
        self.0.measure_total_bytes
    }
    pub fn read_calls(&self) -> u64 {
        self.0.read_calls
    }
    pub fn measurement_attempts(&self) -> u64 {
        self.0.measurement_attempts
    }
    pub fn case_attempts(&self) -> u64 {
        self.0.case_attempts
    }
    pub fn steps_per_invocation(&self) -> u64 {
        self.0.steps_per_invocation
    }
    pub fn steps_total(&self) -> u64 {
        self.0.steps_total
    }
    pub fn attempts_per_case(&self) -> u64 {
        self.0.attempts_per_case
    }
    pub fn assertions_per_case(&self) -> u64 {
        self.0.assertions_per_case
    }
    pub fn coverage_per_case(&self) -> u64 {
        self.0.coverage_per_case
    }
    pub fn effects_per_case(&self) -> u64 {
        self.0.effects_per_case
    }
    pub fn assertion_records(&self) -> u64 {
        self.0.assertion_records
    }
    pub fn coverage_records(&self) -> u64 {
        self.0.coverage_records
    }
    pub fn effects_total(&self) -> u64 {
        self.0.effects_total
    }
    pub fn features(&self) -> u64 {
        self.0.features
    }
    pub fn artifacts(&self) -> u64 {
        self.0.artifacts
    }
    pub fn input_slots(&self) -> u64 {
        self.0.input_slots
    }
    pub fn script_parameters(&self) -> u64 {
        self.0.script_parameters
    }
    pub fn resource_views(&self) -> u64 {
        self.0.resource_views
    }
    pub fn scalar_bytes(&self) -> u64 {
        self.0.scalar_bytes
    }
    pub fn json_depth(&self) -> u64 {
        self.0.json_depth
    }
    pub fn json_edges(&self) -> u64 {
        self.0.json_edges
    }
    pub fn execution_ms(&self) -> u64 {
        self.0.execution_ms
    }
    pub fn retirement_ms(&self) -> u64 {
        self.0.retirement_ms
    }
}
impl Decode for RunLimitValues {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        let mut o = Obj::new(
            v,
            &[
                "input_bytes",
                "observation_bytes",
                "vector_bytes",
                "receipt_bytes",
                "retained_bytes",
                "diagnostic_bytes",
                "name_bytes",
                "label_bytes",
                "measure_file_bytes",
                "measure_total_bytes",
                "read_calls",
                "measurement_attempts",
                "case_attempts",
                "steps_per_invocation",
                "steps_total",
                "attempts_per_case",
                "assertions_per_case",
                "coverage_per_case",
                "effects_per_case",
                "assertion_records",
                "coverage_records",
                "effects_total",
                "features",
                "artifacts",
                "input_slots",
                "script_parameters",
                "resource_views",
                "scalar_bytes",
                "json_depth",
                "json_edges",
                "execution_ms",
                "retirement_ms",
            ],
        )?;
        Ok(Self {
            input_bytes: o.get("input_bytes", l)?,
            observation_bytes: o.get("observation_bytes", l)?,
            vector_bytes: o.get("vector_bytes", l)?,
            receipt_bytes: o.get("receipt_bytes", l)?,
            retained_bytes: o.get("retained_bytes", l)?,
            diagnostic_bytes: o.get("diagnostic_bytes", l)?,
            name_bytes: o.get("name_bytes", l)?,
            label_bytes: o.get("label_bytes", l)?,
            measure_file_bytes: o.get("measure_file_bytes", l)?,
            measure_total_bytes: o.get("measure_total_bytes", l)?,
            read_calls: o.get("read_calls", l)?,
            measurement_attempts: o.get("measurement_attempts", l)?,
            case_attempts: o.get("case_attempts", l)?,
            steps_per_invocation: o.get("steps_per_invocation", l)?,
            steps_total: o.get("steps_total", l)?,
            attempts_per_case: o.get("attempts_per_case", l)?,
            assertions_per_case: o.get("assertions_per_case", l)?,
            coverage_per_case: o.get("coverage_per_case", l)?,
            effects_per_case: o.get("effects_per_case", l)?,
            assertion_records: o.get("assertion_records", l)?,
            coverage_records: o.get("coverage_records", l)?,
            effects_total: o.get("effects_total", l)?,
            features: o.get("features", l)?,
            artifacts: o.get("artifacts", l)?,
            input_slots: o.get("input_slots", l)?,
            script_parameters: o.get("script_parameters", l)?,
            resource_views: o.get("resource_views", l)?,
            scalar_bytes: o.get("scalar_bytes", l)?,
            json_depth: o.get("json_depth", l)?,
            json_edges: o.get("json_edges", l)?,
            execution_ms: o.get("execution_ms", l)?,
            retirement_ms: o.get("retirement_ms", l)?,
        })
    }
}
// Only this private decoder may construct records from untrusted wire values.
pub(crate) trait Decode: Sized {
    const BYTE: bool = false;
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError>;
    /// S177: direct byte decode for `BYTE` types, bypassing per-byte
    /// `Value` materialization. Only `BYTE` types implement this.
    fn decode_byte(byte: u8) -> Result<Self, HarnessError> {
        let _ = byte;
        Err(he(HarnessErrorKind::InvalidInput, "not a byte-decodable type"))
    }
}
pub(crate) struct Obj(Map<String, Value>);
impl Obj {
    pub fn new(v: Value, fields: &[&str]) -> Result<Self, HarnessError> {
        let Value::Object(o) = v else {
            return Err(he(HarnessErrorKind::InvalidInput, "expected object"));
        };
        if o.len() != fields.len() || fields.iter().any(|f| !o.contains_key(*f)) {
            return Err(he(
                HarnessErrorKind::InvalidInput,
                "unknown or missing field",
            ));
        }
        Ok(Self(o))
    }
    pub fn get<T: Decode>(&mut self, k: &str, l: &RunLimits) -> Result<T, HarnessError> {
        T::decode(
            self.0
                .remove(k)
                .ok_or_else(|| he(HarnessErrorKind::InvalidInput, k))?,
            l,
        )
    }
}
impl Decode for String {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        let Value::String(s) = v else {
            return Err(he(HarnessErrorKind::InvalidInput, "string required"));
        };
        if s.len() as u64 > l.retained_bytes() {
            return Err(he(HarnessErrorKind::LimitExceeded, "string"));
        }
        Ok(s)
    }
}
impl Decode for bool {
    fn decode(v: Value, _: &RunLimits) -> Result<Self, HarnessError> {
        v.as_bool()
            .ok_or_else(|| he(HarnessErrorKind::InvalidInput, "bool required"))
    }
}
impl Decode for u32 {
    fn decode(v: Value, _: &RunLimits) -> Result<Self, HarnessError> {
        v.as_u64()
            .and_then(|x| u32::try_from(x).ok())
            .ok_or_else(|| he(HarnessErrorKind::InvalidInput, "u32 required"))
    }
}
impl Decode for i32 {
    fn decode(v: Value, _: &RunLimits) -> Result<Self, HarnessError> {
        v.as_i64()
            .and_then(|x| i32::try_from(x).ok())
            .ok_or_else(|| he(HarnessErrorKind::InvalidInput, "i32 required"))
    }
}
impl Decode for u64 {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        let s = String::decode(v, l)?;
        if s.is_empty()
            || !s.bytes().all(|x| x.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return Err(he(HarnessErrorKind::InvalidInput, "canonical decimal u64"));
        }
        s.parse()
            .map_err(|_| he(HarnessErrorKind::InvalidInput, "u64 overflow"))
    }
}
impl<T: Decode> Decode for Option<T> {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        if v.is_null() {
            Ok(None)
        } else {
            Ok(Some(T::decode(v, l)?))
        }
    }
}
impl<T: Decode> Decode for Vec<T> {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        if T::BYTE {
            // S177: bytes decode directly, never via per-byte Values.
            let Value::String(s) = v else {
                return Err(he(HarnessErrorKind::InvalidInput, "hex string required"));
            };
            return unhex(
                Value::String(s),
                l,
                l.observation_bytes().max(l.vector_bytes()),
            )?
            .into_iter()
            .map(T::decode_byte)
            .collect();
        }
        let Value::Array(a) = v else {
            return Err(he(HarnessErrorKind::InvalidInput, "array required"));
        };
        a.into_iter().map(|v| T::decode(v, l)).collect()
    }
}
pub(crate) fn name(s: &str, l: &RunLimits) -> Result<(), HarnessError> {
    if s.is_empty() || s.len() as u64 > l.name_bytes() || s.chars().any(char::is_control) {
        Err(he(HarnessErrorKind::InvalidInput, "name"))
    } else {
        Ok(())
    }
}
pub(crate) fn bound(n: usize, m: u64, s: &str) -> Result<(), HarnessError> {
    if n as u64 > m {
        Err(he(HarnessErrorKind::LimitExceeded, s))
    } else {
        Ok(())
    }
}
pub(crate) fn sorted<T: Ord>(s: &[T]) -> Result<(), HarnessError> {
    if s.windows(2).any(|p| p[0] >= p[1]) {
        Err(he(HarnessErrorKind::InvalidInput, "duplicate or unsorted"))
    } else {
        Ok(())
    }
}
pub(crate) fn unique<T: Ord>(s: &[T]) -> Result<(), HarnessError> {
    if s.iter().collect::<BTreeSet<_>>().len() != s.len() {
        Err(he(HarnessErrorKind::InvalidInput, "duplicate"))
    } else {
        Ok(())
    }
}
pub(crate) mod decimal {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
}
pub(crate) mod optional_decimal {
    use serde::{Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        v.map(|x| x.to_string()).serialize(s)
    }
}
pub(crate) mod hex_bytes {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        struct Hex<'a>(&'a [u8]);
        impl std::fmt::Display for Hex<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                const DIGITS: &[u8] = b"0123456789abcdef";
                for chunk in self.0.chunks(32) {
                    let mut out = [0u8; 64];
                    for (i, b) in chunk.iter().enumerate() {
                        out[2 * i] = DIGITS[(b >> 4) as usize];
                        out[2 * i + 1] = DIGITS[(b & 15) as usize];
                    }
                    f.write_str(std::str::from_utf8(&out[..2 * chunk.len()]).expect("ASCII hex"))?;
                }
                Ok(())
            }
        }
        // serde_json streams collect_str into its writer; no payload-sized
        // intermediate hexadecimal String is allocated during sizing/encoding.
        s.collect_str(&Hex(v))
    }
}
pub(crate) fn hex(v: &[u8]) -> String {
    const D: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(v.len() * 2);
    for b in v {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char)
    }
    s
}
pub(crate) fn unhex(v: Value, l: &RunLimits, cap: u64) -> Result<Vec<u8>, HarnessError> {
    let s = String::decode(v, l)?;
    if s.len() % 2 != 0
        || s.len() as u64 / 2 > cap
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(he(HarnessErrorKind::InvalidInput, "hex bytes"));
    }
    Ok(s.as_bytes()
        .chunks_exact(2)
        .map(|c| {
            let h = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            h(c[0]) * 16 + h(c[1])
        })
        .collect())
}
// Strict JSON tree: duplicates are rejected before serde_json::Value can overwrite them.
pub(crate) fn parse(bytes: &[u8], cap: u64, l: &RunLimits) -> Result<Value, HarnessError> {
    bound(bytes.len(), cap, "document bytes")?;
    use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
    struct Seed<'a> {
        l: &'a RunLimits,
        depth: u64,
        edges: &'a mut u64,
    }
    struct V<'a>(Seed<'a>);
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = Value;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            if self.depth > self.l.json_depth() {
                return Err(D::Error::custom("depth"));
            }
            d.deserialize_any(V(self))
        }
    }
    impl<'de> Visitor<'de> for V<'_> {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "strict JSON")
        }
        fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Value, E> {
            Err(E::custom("float forbidden"))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            if self.0.depth >= self.0.l.json_depth() {
                return Err(A::Error::custom("depth"));
            }
            let mut o = Map::new();
            while let Some(k) = a.next_key::<String>()? {
                *self.0.edges += 1;
                if *self.0.edges > self.0.l.json_edges() {
                    return Err(A::Error::custom("edges"));
                }
                if o.contains_key(&k) {
                    return Err(A::Error::custom("duplicate"));
                }
                let v = a.next_value_seed(Seed {
                    l: self.0.l,
                    depth: self.0.depth + 1,
                    edges: self.0.edges,
                })?;
                o.insert(k, v);
            }
            Ok(Value::Object(o))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            if self.0.depth >= self.0.l.json_depth() {
                return Err(A::Error::custom("depth"));
            }
            let mut o = Vec::new();
            loop {
                let v = a.next_element_seed(Seed {
                    l: self.0.l,
                    depth: self.0.depth + 1,
                    edges: self.0.edges,
                })?;
                let Some(v) = v else { break };
                *self.0.edges += 1;
                if *self.0.edges > self.0.l.json_edges() {
                    return Err(A::Error::custom("edges"));
                }
                o.push(v);
            }
            Ok(Value::Array(o))
        }
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let mut edges = 0;
    let v = Seed {
        l,
        depth: 0,
        edges: &mut edges,
    }
    .deserialize(&mut d)
    .map_err(|e| {
        let diagnostic = e.to_string();
        let kind = if diagnostic.starts_with("depth at ") || diagnostic.starts_with("edges at ") {
            HarnessErrorKind::LimitExceeded
        } else {
            HarnessErrorKind::InvalidInput
        };
        he(kind, &diagnostic)
    })?;
    d.end()
        .map_err(|_| he(HarnessErrorKind::InvalidInput, "trailing input"))?;
    Ok(v)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Digest256([u8; 32]);
impl Digest256 {
    pub fn parse(s: &str) -> Result<Self, BindingError> {
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(be(BindingErrorKind::InvalidDigest, "digest"));
        }
        let b = unhex(Value::String(s.into()), &RunLimits::default(), 32)
            .map_err(|_| be(BindingErrorKind::InvalidDigest, "digest"))?;
        Ok(Self(b.try_into().unwrap()))
    }
    pub fn of_bytes(b: &[u8]) -> Self {
        Self(Sha256::digest(b).into())
    }
    pub fn as_str(&self) -> String {
        hex(&self.0)
    }
}
impl Serialize for Digest256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_str())
    }
}
impl Decode for Digest256 {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        Self::parse(&String::decode(v, l)?).map_err(Into::into)
    }
}
macro_rules! wire_enum {($n:ident{$($v:ident=>$s:literal),+$(,)?})=>{#[derive(Clone,Copy,Debug,Eq,PartialEq,Ord,PartialOrd,Serialize)] pub enum $n{$(#[serde(rename=$s)]$v),+} impl BoundValue for $n{fn check_bounds(&self,_:&RunLimits)->Result<(),HarnessError>{Ok(())}} impl Decode for $n{fn decode(v:Value,l:&RunLimits)->Result<Self,HarnessError>{match String::decode(v,l)?.as_str(){$($s=>Ok(Self::$v),)+_=>Err(he(HarnessErrorKind::InvalidInput,stringify!($n)))}}}}}
pub(crate) use wire_enum;
macro_rules! record {($n:ident,$values:ident{$($(#[$attr:meta])* $field:ident:$ty:ty),*$(,)?},$validate:expr)=>{
 #[derive(Clone,Debug,Eq,PartialEq,Serialize)]pub struct $values{$($(#[$attr])*pub $field:$ty),*}
 #[derive(Clone,Debug,Eq,PartialEq,Serialize)]#[serde(transparent)]pub struct $n(pub(crate) $values);
 impl $n{pub fn new(v:$values,l:&RunLimits)->Result<Self,HarnessError>{let x=Self(v);x.check_bounds(l)?;Ok(x)}$(pub fn $field(&self)->&$ty{&self.0.$field})*}
 impl BoundValue for $n{fn check_bounds(&self,l:&RunLimits)->Result<(),HarnessError>{$(self.0.$field.check_bounds(l)?;)*let checked:Result<(),HarnessError>=($validate)(&self.0,l);checked}}
 impl Decode for $n{fn decode(v:Value,l:&RunLimits)->Result<Self,HarnessError>{let mut o=Obj::new(v,&[$(stringify!($field)),*])?;Self::new($values{$($field:o.get(stringify!($field),l)?),*},l)}}
};}
pub(crate) use record;
wire_enum!(ArtifactRole{SubjectArchive=>"subject_archive",ConsumerExecutable=>"consumer_executable",CaseSource=>"case_source",OracleSource=>"oracle_source",ControlSource=>"control_source",FixtureManifest=>"fixture_manifest",FixtureInput=>"fixture_input",ExpectedVector=>"expected_vector",FixtureLedger=>"fixture_ledger",WorkerExecutable=>"worker_executable",FinalObject=>"final_object",SourceTerms=>"source_terms",ElfLicenseBytes=>"elf_license_bytes",LoaderLicenseBytes=>"loader_license_bytes"});
record!(
    ArtifactBinding,
    ArtifactBindingValues {
        id: Label,
        revision: u32,
        role: ArtifactRole,
        #[serde(with = "decimal")]
        length: u64,
        sha256: Digest256
    },
    |v: &ArtifactBindingValues, l: &RunLimits| {
        if v.revision == 0 {
            return Err(he(HarnessErrorKind::InvalidInput, "artifact revision"));
        }
        if v.length > l.measure_file_bytes() {
            return Err(he(HarnessErrorKind::LimitExceeded, "artifact length"));
        }
        if matches!(
            v.role,
            ArtifactRole::FixtureInput | ArtifactRole::ExpectedVector | ArtifactRole::FixtureLedger
        ) && v.length > l.vector_bytes()
        {
            return Err(he(HarnessErrorKind::LimitExceeded, "vector length"));
        }
        bound(v.id.as_str().len(), l.label_bytes(), "artifact label")
    }
);
record!(
    BackendBinding,
    BackendBindingValues {
        name: String,
        version: String,
        source_sha256: Digest256
    },
    |v: &BackendBindingValues, l: &RunLimits| {
        name(&v.name, l)?;
        name(&v.version, l)
    }
);
record!(
    ConsumerBinding,
    ConsumerBindingValues {
        name: String,
        build_inputs_sha256: Digest256,
        executable_sha256: Digest256
    },
    |v: &ConsumerBindingValues, l: &RunLimits| name(&v.name, l)
);
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BindingProvenance {
    GeneratedBuild {
        manifest_sha256: Digest256,
        measurement_sha256: Digest256,
    },
    SelfReported {
        reason: String,
    },
}
impl Decode for BindingProvenance {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        match v.get("kind").and_then(Value::as_str) {
            Some("generated_build") => {
                let mut o = Obj::new(v, &["kind", "manifest_sha256", "measurement_sha256"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::GeneratedBuild {
                    manifest_sha256: o.get("manifest_sha256", l)?,
                    measurement_sha256: o.get("measurement_sha256", l)?,
                })
            }
            Some("self_reported") => {
                let mut o = Obj::new(v, &["kind", "reason"])?;
                let _: String = o.get("kind", l)?;
                let reason: String = o.get("reason", l)?;
                name(&reason, l)?;
                Ok(Self::SelfReported { reason })
            }
            _ => Err(he(HarnessErrorKind::InvalidInput, "provenance")),
        }
    }
}
record!(SubjectBinding,SubjectBindingValues{package_name:String,package_version:String,source_sha256:Digest256,build_inputs_sha256:Digest256,features:Vec<String>,backend:Option<BackendBinding>,host:String,target:String,consumer:ConsumerBinding,objects:Vec<ArtifactBinding>,provenance:BindingProvenance},|v:&SubjectBindingValues,l:&RunLimits|{for s in [&v.package_name,&v.package_version,&v.host,&v.target]{name(s,l)?}for s in &v.features{name(s,l)?}bound(v.features.len(),l.features(),"features")?;sorted(&v.features)?;bound(v.objects.len(),l.artifacts(),"objects")?;sorted(&v.objects.iter().map(|a|a.id()).collect::<Vec<_>>())?;if let BindingProvenance::SelfReported{reason}=&v.provenance{name(reason,l)?}Ok(())});
impl SubjectBinding {
    /// Admit a subject binding from an already-parsed JSON envelope
    /// value under caller limits.
    ///
    /// S41: the receipt verifier's shallow subject gate reuses this
    /// exact typed admission — the same `Decode` plus bounds check
    /// the engine uses — so a resealed envelope with a sparse or
    /// malformed `subject` object fails here instead of passing an
    /// `is_object` shape check.
    pub fn from_json(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        Self::decode(v, l)
    }
}

record!(
    OracleBinding,
    OracleBindingValues {
        id: Label,
        revision: u32,
        schema_id: Label,
        source_sha256: Digest256,
        artifact_id: Label,
        provenance: BindingProvenance
    },
    |v: &OracleBindingValues, _: &RunLimits| {
        if v.revision == 0 {
            Err(he(HarnessErrorKind::InvalidInput, "oracle revision"))
        } else {
            Ok(())
        }
    }
);
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InputReadProgress {
    pub(crate) file_id: Label,
    #[serde(with = "decimal")]
    pub(crate) expected_length: u64,
    #[serde(with = "decimal")]
    pub(crate) bytes_returned: u64,
    #[serde(with = "decimal")]
    pub(crate) read_calls: u64,
}
impl InputReadProgress {
    pub fn file_id(&self) -> &Label {
        &self.file_id
    }
    pub fn expected_length(&self) -> u64 {
        self.expected_length
    }
    pub fn bytes_returned(&self) -> u64 {
        self.bytes_returned
    }
    pub fn read_calls(&self) -> u64 {
        self.read_calls
    }
}
impl Decode for InputReadProgress {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        let mut o = Obj::new(
            v,
            &["file_id", "expected_length", "bytes_returned", "read_calls"],
        )?;
        Ok(Self {
            file_id: o.get("file_id", l)?,
            expected_length: o.get("expected_length", l)?,
            bytes_returned: o.get("bytes_returned", l)?,
            read_calls: o.get("read_calls", l)?,
        })
    }
}
#[derive(Clone, Debug, Default)]
pub struct MeasurementUsage {
    pub attempts: u64,
    pub reserved_bytes: u64,
    pub bytes_returned: u64,
    pub bytes_hashed: u64,
    pub read_calls: u64,
    pub last: Option<InputReadProgress>,
}
#[derive(Debug)]
pub struct MeasuredArtifact {
    binding: ArtifactBinding,
    run_id: RunId,
    index: u64,
}
impl MeasuredArtifact {
    pub fn binding(&self) -> &ArtifactBinding {
        &self.binding
    }
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }
    pub fn measurement_attempt_index(&self) -> u64 {
        self.index
    }
}
#[derive(Debug)]
pub struct ArtifactMeasurer {
    pub(crate) run_id: RunId,
    pub(crate) limits: RunLimits,
    usage: MeasurementUsage,
    successful: BTreeSet<Label>,
    buffer: Box<[u8; 65536]>,
}
impl ArtifactMeasurer {
    pub fn new(run_id: RunId, limits: RunLimits) -> Result<Self, BindingError> {
        Ok(Self {
            run_id,
            limits,
            usage: MeasurementUsage::default(),
            successful: BTreeSet::new(),
            buffer: Box::new([0; 65536]),
        })
    }
    pub fn usage(&self) -> MeasurementUsage {
        self.usage.clone()
    }
    pub fn measure(
        &mut self,
        expected: &ArtifactBinding,
        file: &File,
    ) -> Result<MeasuredArtifact, BindingError> {
        self.read(expected, file, false)?;
        Ok(MeasuredArtifact {
            binding: expected.clone(),
            run_id: self.run_id.clone(),
            index: self.usage.attempts,
        })
    }
    pub(crate) fn read(
        &mut self,
        e: &ArtifactBinding,
        file: &File,
        retain: bool,
    ) -> Result<Vec<u8>, BindingError> {
        self.read_with(e, file, retain, |f, b, o| f.read_at(b, o))
    }
    fn read_with(
        &mut self,
        e: &ArtifactBinding,
        file: &File,
        retain: bool,
        mut read: impl FnMut(&File, &mut [u8], u64) -> std::io::Result<usize>,
    ) -> Result<Vec<u8>, BindingError> {
        e.check_bounds(&self.limits)
            .map_err(|_| be(BindingErrorKind::LimitExceeded, "selected artifact binding"))?;
        let id = e.id().clone();
        let len = *e.length();
        let mut p = InputReadProgress {
            file_id: id.clone(),
            expected_length: len,
            bytes_returned: 0,
            read_calls: 0,
        };
        macro_rules! fail {
            ($kind:expr) => {{
                self.usage.last = Some(p.clone());
                let mut e = be($kind, id.as_str());
                e.progress = Some(p.clone());
                return Err(e);
            }};
        }
        if self.successful.contains(&id) {
            fail!(BindingErrorKind::Duplicate)
        }
        self.usage.attempts = self
            .usage
            .attempts
            .checked_add(1)
            .ok_or_else(|| be(BindingErrorKind::LimitExceeded, "attempts"))?;
        if self.usage.attempts > self.limits.measurement_attempts() {
            fail!(BindingErrorKind::LimitExceeded)
        }
        let reserve = len
            .checked_add(1)
            .ok_or_else(|| be(BindingErrorKind::LimitExceeded, "length overflow"))?;
        let total = self
            .usage
            .reserved_bytes
            .checked_add(reserve)
            .ok_or_else(|| be(BindingErrorKind::LimitExceeded, "total overflow"))?;
        if total > self.limits.measure_total_bytes() {
            fail!(BindingErrorKind::LimitExceeded)
        }
        self.usage.reserved_bytes = total;
        if len > self.limits.measure_file_bytes() || (retain && len > self.limits.vector_bytes()) {
            fail!(BindingErrorKind::LimitExceeded)
        }
        let md = match file.metadata() {
            Ok(m) => m,
            Err(_) => fail!(BindingErrorKind::Io),
        };
        if !md.is_file() {
            fail!(BindingErrorKind::NotRegular)
        }
        if md.len() != len {
            fail!(BindingErrorKind::LengthMismatch)
        }
        let mut bytes = Vec::new();
        if retain {
            bytes
                .try_reserve_exact(len as usize)
                .map_err(|_| be(BindingErrorKind::LimitExceeded, "vector allocation"))?
        }
        let mut hash = Sha256::new();
        let mut offset = 0;
        loop {
            if self.usage.read_calls >= self.limits.read_calls() {
                fail!(BindingErrorKind::LimitExceeded)
            }
            self.usage.read_calls += 1;
            p.read_calls += 1;
            let want = if offset == len {
                1
            } else {
                (len - offset).min(65536) as usize
            };
            let n = match read(file, &mut self.buffer[..want], offset) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => fail!(BindingErrorKind::Io),
            };
            p.bytes_returned += n as u64;
            self.usage.bytes_returned += n as u64;
            if offset == len {
                if n != 0 {
                    fail!(BindingErrorKind::LengthMismatch)
                }
                break;
            }
            if n == 0 {
                fail!(BindingErrorKind::LengthMismatch)
            }
            hash.update(&self.buffer[..n]);
            self.usage.bytes_hashed += n as u64;
            if retain {
                bytes.extend_from_slice(&self.buffer[..n]);
            }
            offset += n as u64;
        }
        let md = match file.metadata() {
            Ok(m) => m,
            Err(_) => fail!(BindingErrorKind::Io),
        };
        if !md.is_file() {
            fail!(BindingErrorKind::NotRegular)
        }
        if md.len() != len {
            fail!(BindingErrorKind::LengthMismatch)
        }
        let digest = Digest256(hash.finalize().into());
        if digest != *e.sha256() {
            fail!(BindingErrorKind::DigestMismatch)
        }
        self.successful.insert(id);
        self.usage.last = Some(p);
        Ok(bytes)
    }
}
impl Decode for u8 {
    const BYTE: bool = true;
    fn decode(v: Value, _: &RunLimits) -> Result<Self, HarnessError> {
        v.as_u64()
            .and_then(|x| u8::try_from(x).ok())
            .ok_or_else(|| he(HarnessErrorKind::InvalidInput, "byte"))
    }
    fn decode_byte(byte: u8) -> Result<Self, HarnessError> {
        Ok(byte)
    }
}
pub(crate) mod decimal_list {
    use serde::{Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[u64], s: S) -> Result<S::Ok, S::Error> {
        v.iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .serialize(s)
    }
}
macro_rules! old_enum{($t:ty{$($v:ident=>$s:literal),+})=>{impl Serialize for $t{fn serialize<S:Serializer>(&self,s:S)->Result<S::Ok,S::Error>{s.serialize_str(match self{$(Self::$v=>$s),+})}}impl Decode for $t{fn decode(v:Value,l:&RunLimits)->Result<Self,HarnessError>{match String::decode(v,l)?.as_str(){$($s=>Ok(Self::$v),)+_=>Err(he(HarnessErrorKind::InvalidInput,stringify!($t)))}}}}}
old_enum!(EvidenceTier{T0=>"T0",T1=>"T1",T2=>"T2",T3=>"T3",T4=>"T4",T5=>"T5"});
old_enum!(ImplementationStatus{Unimplemented=>"UNIMPLEMENTED",RegisteredExecutable=>"REGISTERED_EXECUTABLE"});
/// Structural validation is rerun at the selected (possibly lowered) limits.
pub(crate) trait BoundValue {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError>;
}
macro_rules! trivial_bounds{($($t:ty),+)=>{$(impl BoundValue for $t{fn check_bounds(&self,_:&RunLimits)->Result<(),HarnessError>{Ok(())}})+};}
trivial_bounds!(
    u8,
    u32,
    u64,
    i32,
    bool,
    Digest256,
    CaseId,
    ProfileId,
    RunId,
    EvidenceTier,
    ImplementationStatus
);
impl BoundValue for Label {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        bound(self.as_str().len(), l.label_bytes(), "label")
    }
}
impl BoundValue for String {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        bound(self.len(), l.retained_bytes(), "string")
    }
}
impl<T: BoundValue> BoundValue for Vec<T> {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        for x in self {
            x.check_bounds(l)?
        }
        Ok(())
    }
}
impl<T: BoundValue> BoundValue for Option<T> {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        if let Some(x) = self {
            x.check_bounds(l)?
        }
        Ok(())
    }
}
impl BoundValue for RunLimits {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        l.lowered(self.values())
            .map_err(|e| he(HarnessErrorKind::LimitExceeded, &e.to_string()))?;
        Ok(())
    }
}
impl BoundValue for BindingProvenance {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        if let Self::SelfReported { reason } = self {
            name(reason, l)?
        }
        Ok(())
    }
}
impl BoundValue for InputReadProgress {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        self.file_id.check_bounds(l)
    }
}
pub(crate) fn encoded_size<T: Serialize>(v: &T, cap: u64) -> Result<u64, HarnessError> {
    struct Counter {
        n: u64,
        cap: u64,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.n = self
                .n
                .checked_add(b.len() as u64)
                .ok_or_else(|| std::io::Error::other("overflow"))?;
            if self.n > self.cap {
                return Err(std::io::Error::other("limit"));
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Counter { n: 0, cap };
    serde_json::to_writer(&mut c, v)
        .map_err(|_| he(HarnessErrorKind::LimitExceeded, "encoded payload"))?;
    Ok(c.n)
}
pub(crate) struct RetainedPayload {
    pub(crate) used: u64,
    limit: u64,
}
impl RetainedPayload {
    pub(crate) fn new(used: u64, limit: u64) -> Result<Self, HarnessError> {
        let mut budget = Self { used: 0, limit };
        budget.reserve(used)?;
        Ok(budget)
    }
    pub(crate) fn reserve(&mut self, bytes: u64) -> Result<(), HarnessError> {
        let next = self
            .used
            .checked_add(bytes)
            .ok_or_else(|| he(HarnessErrorKind::LimitExceeded, "retained payload overflow"))?;
        if next > self.limit {
            return Err(he(HarnessErrorKind::LimitExceeded, "retained owned copy"));
        }
        self.used = next;
        Ok(())
    }
    pub(crate) fn cloned<T: Serialize + Clone>(&mut self, value: &T) -> Result<T, HarnessError> {
        self.reserve(encoded_size(value, self.limit)?)?;
        Ok(value.clone())
    }
}
#[cfg(test)]
mod tests;
