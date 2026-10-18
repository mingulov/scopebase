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
