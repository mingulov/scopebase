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
