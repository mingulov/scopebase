// SPDX-License-Identifier: Apache-2.0
//! Same-unit exact arithmetic and optional upper bounds.
// ADAPT: MemVeil 8307a17 model/validate.mojo:84–88 overflow-refusing addition.
// ADAPT: OSSLscope 4bcb24c evidence.rs:145–152 unknown versus known bounds.
use crate::ContractError;
use std::{fmt, marker::PhantomData};
// CP06-D9: crate-private erasure only; no public unit/wire discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnitTag {
    Events,
    Records,
    Bytes,
    Objects,
    Attempts,
    Nonexecutions,
    DiagnosticSignals,
}
pub(crate) struct UnitTagAccess(());
mod private {
    pub trait Sealed {
        #[allow(private_interfaces)]
        fn unit_tag(_: super::UnitTagAccess) -> super::UnitTag
        where
            Self: Sized;
    }
}
pub(crate) fn unit_tag<U: Unit>() -> UnitTag {
    <U as private::Sealed>::unit_tag(UnitTagAccess(()))
}
/// A sealed unit. Counts with different units cannot be mixed implicitly.
#[allow(private_bounds)]
pub trait Unit: private::Sealed {}
macro_rules! units {
    ($($name:ident => $doc:literal),+ $(,)?) => {$ (
        #[doc = $doc]
        pub enum $name {}
        impl private::Sealed for $name {
            #[allow(private_interfaces)]
            fn unit_tag(_: UnitTagAccess) -> UnitTag { UnitTag::$name }
        }
        impl Unit for $name {}
    )+};
}
units! {
    Events => "Event counts.", Records => "Record counts.", Bytes => "Byte counts.",
    Objects => "Object counts.", Attempts => "Attempt counts.",
    Nonexecutions => "Nonexecution counts.", DiagnosticSignals => "Diagnostic signal counts."
}
/// An exact value in one sealed unit, including zero and `u64::MAX`.
pub struct Count<U: Unit> {
    value: u64,
    unit: PhantomData<U>,
}
impl<U: Unit> Count<U> {
    /// Construct an exact count; no sentinel or saturation semantics are inferred.
    pub fn new(value: u64) -> Self {
        Self {
            value,
            unit: PhantomData,
        }
    }
    /// The exact value.
    pub fn get(&self) -> u64 {
        self.value
    }
    /// Add in the same unit, refusing overflow rather than saturation or wrapping.
    pub fn checked_add(self, rhs: Self) -> Result<Self, ContractError> {
        self.value
            .checked_add(rhs.value)
            .map(Self::new)
            .ok_or(ContractError::ArithmeticOverflow)
    }
    /// Subtract in the same unit, refusing underflow.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, ContractError> {
        self.value
            .checked_sub(rhs.value)
            .map(Self::new)
            .ok_or(ContractError::ArithmeticOverflow)
    }
}
// Manual implementations avoid imposing marker traits on generic U: Unit callers.
impl<U: Unit> Copy for Count<U> {}
impl<U: Unit> Clone for Count<U> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<U: Unit> PartialEq for Count<U> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl<U: Unit> Eq for Count<U> {}
impl<U: Unit> fmt::Debug for Count<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Count").field(&self.value).finish()
    }
}
/// A lower bound and optional upper bound. `None` remains unknown, including at zero.
pub struct CountBounds<U: Unit> {
    lower: Count<U>,
    upper: Option<Count<U>>,
}
impl<U: Unit> CountBounds<U> {
    /// Validate known ordering without replacing unknown with zero.
    pub fn new(lower: Count<U>, upper: Option<Count<U>>) -> Result<Self, ContractError> {
        if upper.is_some_and(|value| value.get() < lower.get()) {
            return Err(ContractError::ReversedBounds);
        }
        Ok(Self { lower, upper })
    }
    /// The supplied lower bound.
    pub fn lower(&self) -> Count<U> {
        self.lower
    }
    /// The supplied upper bound, preserving absence.
    pub fn upper(&self) -> Option<Count<U>> {
        self.upper
    }
}
impl<U: Unit> Clone for CountBounds<U> {
    fn clone(&self) -> Self {
        Self {
            lower: self.lower,
            upper: self.upper,
        }
    }
}
impl<U: Unit> PartialEq for CountBounds<U> {
    fn eq(&self, other: &Self) -> bool {
        self.lower == other.lower && self.upper == other.upper
    }
}
impl<U: Unit> Eq for CountBounds<U> {}
impl<U: Unit> fmt::Debug for CountBounds<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CountBounds")
            .field("lower", &self.lower)
            .field("upper", &self.upper)
            .finish()
    }
}

#[cfg(test)]
mod cp06_tests {
    use super::*;
    #[test]
    fn seven_private_unit_tags() {
        assert_eq!(unit_tag::<Events>(), UnitTag::Events, "CP06:Events tag");
        assert_eq!(unit_tag::<Records>(), UnitTag::Records, "CP06:Records tag");
        assert_eq!(unit_tag::<Bytes>(), UnitTag::Bytes, "CP06:Bytes tag");
        assert_eq!(unit_tag::<Objects>(), UnitTag::Objects, "CP06:Objects tag");
        assert_eq!(
            unit_tag::<Attempts>(),
            UnitTag::Attempts,
            "CP06:Attempts tag"
        );
        assert_eq!(
            unit_tag::<Nonexecutions>(),
            UnitTag::Nonexecutions,
            "CP06:Nonexecutions tag"
        );
        assert_eq!(
            unit_tag::<DiagnosticSignals>(),
            UnitTag::DiagnosticSignals,
            "CP06:DiagnosticSignals tag"
        );
    }
}
