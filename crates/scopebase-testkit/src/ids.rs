// SPDX-License-Identifier: Apache-2.0
use std::{error::Error, fmt};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    Empty,
    TooLong,
    InvalidCharacter,
    InvalidStart,
}
impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid identifier: {self:?}")
    }
}
impl Error for IdError {}
fn check(s: &str, cap: usize) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > cap {
        return Err(IdError::TooLong);
    }
    if !s.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(IdError::InvalidStart);
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(IdError::InvalidCharacter);
    }
    Ok(())
}
macro_rules! identifier {
    ($name:ident,$cap:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: &str) -> Result<Self, IdError> {
                check(value, $cap)?;
                Ok(Self(value.to_owned()))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
identifier!(CaseId, 96);
identifier!(ProfileId, 64);

// A bounded semantic label; distinct from catalog case/profile identifiers.
identifier!(Label, 96);

impl Label {
    /// R02: truncate to an invocation label ceiling. Labels are ASCII
    /// with an alphanumeric start, so any non-empty byte prefix parses;
    /// ceilings validate to >= 1 byte, and `max(1)` pins even a raw 0.
    /// Adapter-invented metadata (stage, method) fits this way; caller
    /// echoes are admitted, and observation bodies must refuse (R07).
    pub fn truncate(&self, max_bytes: u64) -> Label {
        let max = (max_bytes.max(1) as usize).min(self.as_str().len());
        Label::parse(&self.as_str()[..max]).expect("R02: label prefix parses")
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RunId(String);
impl RunId {
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if s.len() != 32 {
            return Err(IdError::TooLong);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IdError::InvalidCharacter);
        }
        Ok(Self(s.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
macro_rules! wire_id {
    ($t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }
        impl crate::artifact::Decode for $t {
            fn decode(
                v: serde_json::Value,
                l: &crate::RunLimits,
            ) -> Result<Self, crate::HarnessError> {
                let id = Self::parse(&<String as crate::artifact::Decode>::decode(v, l)?).map_err(
                    |_| crate::artifact::he(crate::HarnessErrorKind::InvalidInput, "identifier"),
                )?;
                crate::artifact::BoundValue::check_bounds(&id, l)?;
                Ok(id)
            }
        }
    };
}
wire_id!(CaseId);
wire_id!(ProfileId);
wire_id!(Label);
wire_id!(RunId);
use crate::artifact::*;
use crate::{HarnessError, HarnessErrorKind, RunLimits};
use serde::Serialize;
use serde_json::Value;
record!(
    CaseKey,
    CaseKeyValues {
        case_id: CaseId,
        case_version: u32,
        cell_id: String
    },
    |v: &CaseKeyValues, l: &RunLimits| {
        bound(v.cell_id.len(), l.name_bytes(), "cell name")?;
        if v.case_version == 0 || v.cell_id.is_empty() || v.cell_id.len() > 65536 {
            Err(he(HarnessErrorKind::InvalidInput, "case key"))
        } else {
            Ok(())
        }
    }
);
impl Ord for CaseKey {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (&self.0.case_id, self.0.case_version, &self.0.cell_id).cmp(&(
            &o.0.case_id,
            o.0.case_version,
            &o.0.cell_id,
        ))
    }
}
impl PartialOrd for CaseKey {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
record!(
    InvocationKey,
    InvocationKeyValues {
        run_id: RunId,
        case_key: CaseKey,
        attempt: u32,
        #[serde(with = "crate::artifact::decimal")]
        operation_id: u64
    },
    |v: &InvocationKeyValues, _: &RunLimits| {
        if v.attempt == 0 || v.operation_id == 0 {
            Err(he(HarnessErrorKind::InvalidInput, "invocation"))
        } else {
            Ok(())
        }
    }
);
impl Ord for InvocationKey {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (
            &self.0.run_id,
            &self.0.case_key,
            self.0.attempt,
            self.0.operation_id,
        )
            .cmp(&(&o.0.run_id, &o.0.case_key, o.0.attempt, o.0.operation_id))
    }
}
impl PartialOrd for InvocationKey {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

// BP03 adapter accounting inspects only the existing private String capacity.
#[cfg(feature = "bpf-host")]
pub(crate) fn bp03_profile_capacity(value: &ProfileId) -> usize {
    value.0.capacity()
}

#[cfg(feature = "bpf-host")]
pub(crate) fn bp03_label_capacity(value: &Label) -> usize {
    value.0.capacity()
}

#[cfg(feature = "bpf-host")]
pub(crate) fn bp03_case_id_capacity(value: &CaseId) -> usize {
    value.0.capacity()
}

#[cfg(feature = "bpf-host")]
pub(crate) fn bp03_run_id_capacity(value: &RunId) -> usize {
    value.0.capacity()
}

// Fallible prepared-response copies stay inside the private String-owning module.
// Public parsers/Clone/serde and accepted cell-name validity are unchanged.
#[allow(dead_code)]
pub(crate) fn rsp01_copy_key(
    key: &InvocationKey,
    limits: &RunLimits,
    budget: &mut crate::prepared::ResponseBudget,
) -> Result<InvocationKey, crate::ResponsePreparationFailure> {
    rsp01_copy_key_with(key, limits, budget, &mut crate::prepared::response_string_storage)
}
#[allow(dead_code)]
pub(crate) fn rsp01_copy_key_with<F>(
    key: &InvocationKey,
    limits: &RunLimits,
    budget: &mut crate::prepared::ResponseBudget,
    allocate: &mut F,
) -> Result<InvocationKey, crate::ResponsePreparationFailure>
where F: FnMut(usize) -> Result<String, ()> {
    use crate::{ResponsePreparationComponent as Part, ResponsePreparationFailure as Failure,
        ResponsePreparationFailureKind as Kind};
    let invalid = |component| Failure { kind: Kind::InvalidInvocation, component,
        requested_bytes: None, observed_bytes: None };
    let run = key.run_id().as_str();
    if run.len() != 32 || !run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(invalid(Part::RunId));
    }
    let case = key.case_key();
    if check(case.case_id().as_str(), 96).is_err() || *case.case_version() == 0 {
        return Err(invalid(Part::CaseId));
    }
    // CaseKey::new accepts arbitrary nonempty cell bytes up to both ceilings.
    // In particular slash, spaces and non-ASCII must not acquire ID grammar.
    if case.cell_id().is_empty() || case.cell_id().len() > 65536
        || case.cell_id().len() as u64 > limits.name_bytes()
        || case.cell_id().len() as u64 > limits.retained_bytes() {
        return Err(invalid(Part::CellId));
    }
    if *key.attempt() == 0 || *key.operation_id() == 0 {
        return Err(invalid(Part::Total));
    }
    let run_id = RunId(budget.copy_string_with(run, Part::RunId, allocate)?);
    let case_id = CaseId(budget.copy_string_with(case.case_id().as_str(), Part::CaseId, allocate)?);
    let cell_id = budget.copy_string_with(case.cell_id(), Part::CellId, allocate)?;
    Ok(InvocationKey(InvocationKeyValues {
        run_id,
        case_key: CaseKey(CaseKeyValues { case_id, case_version: *case.case_version(), cell_id }),
        attempt: *key.attempt(), operation_id: *key.operation_id(),
    }))
}
#[allow(dead_code)]
pub(crate) fn rsp01_copy_label(
    text: &str,
    limits: &RunLimits,
    budget: &mut crate::prepared::ResponseBudget,
    component: crate::ResponsePreparationComponent,
) -> Result<Label, crate::ResponsePreparationFailure> {
    if check(text, 96).is_err() || text.len() as u64 > limits.label_bytes() {
        return Err(crate::ResponsePreparationFailure {
            kind: crate::ResponsePreparationFailureKind::InvalidInvocation,
            component, requested_bytes: None, observed_bytes: None,
        });
    }
    Ok(Label(budget.copy_string(text, component)?))
}

// Actual recursively owned capacities for independent finite-header accounting.
#[allow(dead_code)]
pub(crate) fn rsp01_key_capacities(key: &InvocationKey) -> [usize; 3] {
    [key.0.run_id.0.capacity(), key.0.case_key.0.case_id.0.capacity(),
        key.0.case_key.0.cell_id.capacity()]
}
#[allow(dead_code)]
pub(crate) fn rsp01_label_capacity(label: &Label) -> usize { label.0.capacity() }

#[cfg(test)]
mod tests {
    use super::*;

    /// R02: truncation fits every ceiling, pins a raw 0 to one byte,
    /// and always parses (ASCII alnum-start prefixes). Every ceiling
    /// from 0..=96 is exercised, not just sampled.
    #[test]
    fn label_truncate_fits_every_ceiling() {
        for text in [
            "adapter-dialect",
            "delivery-operation",
            "execute",
            "x",
            "a.b_c-d9",
        ] {
            let label = Label::parse(text).unwrap();
            for ceiling in 0..=96u64 {
                let fitted = label.truncate(ceiling);
                let expect = (ceiling.max(1) as usize).min(text.len());
                assert_eq!(fitted.as_str(), &text[..expect], "{text} @ {ceiling}");
                assert!(Label::parse(fitted.as_str()).is_ok());
            }
        }
    }
}
