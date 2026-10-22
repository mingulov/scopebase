// SPDX-License-Identifier: Apache-2.0
//! Explicit resource configuration (SDK02).
//!
//! A [`Limits`] value separates input bytes, retained bytes, visited work,
//! live owners, diagnostics and elapsed wait into independent units.
//! [`Limits::validate`] refuses zero fields and any count/byte value that is
//! not representable as `usize` on the build target, before any context or
//! component effect. The wait is an observation deadline, not guaranteed
//! syscall interruption or cleanup.
//!
//! Validation order is field declaration order: the first failing field in
//! [`LimitField`] order wins, so callers see a stable refusal.

use std::error::Error;
use std::fmt;
use std::time::Duration;

/// Explicit resource configuration. The context enforces what it owns --
/// binding payload against `retained_bytes` and diagnostics against
/// `diagnostic_count`/`diagnostic_bytes` -- and carries the remaining units
/// as explicit configuration for the selected component, not as proof that
/// the context controls external resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    pub input_bytes: u64,
    pub retained_bytes: u64,
    pub work_items: u64,
    pub live_owners: u32,
    pub diagnostic_count: u32,
    pub diagnostic_bytes: u64,
    pub wait: Duration,
}

/// The limit field a [`LimitsError`] blames, in validation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitField {
    InputBytes,
    RetainedBytes,
    WorkItems,
    LiveOwners,
    DiagnosticCount,
    DiagnosticBytes,
    Wait,
}

impl LimitField {
    fn name(self) -> &'static str {
        match self {
            LimitField::InputBytes => "input_bytes",
            LimitField::RetainedBytes => "retained_bytes",
            LimitField::WorkItems => "work_items",
            LimitField::LiveOwners => "live_owners",
            LimitField::DiagnosticCount => "diagnostic_count",
            LimitField::DiagnosticBytes => "diagnostic_bytes",
            LimitField::Wait => "wait",
        }
    }
}

/// Limit validation failure. Variants stay structured and carry no caller
/// values beyond the blamed field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitsError {
    Zero(LimitField),
    OutOfRange(LimitField),
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitsError::Zero(field) => {
                write!(f, "limit field must be nonzero: {}", field.name())
            }
            LimitsError::OutOfRange(field) => {
                write!(
                    f,
                    "limit field not representable on this target: {}",
                    field.name()
                )
            }
        }
    }
}

impl Error for LimitsError {}

impl Limits {
    /// Check every unit independently: each field must be nonzero, and each
    /// `u64` count/byte value must fit `usize` on the build target. The
    /// `u32` count fields are representable on every supported target and
    /// carry only the nonzero check. Borrows only; performs no effects.
    pub fn validate(&self) -> Result<(), LimitsError> {
        if self.input_bytes == 0 {
            return Err(LimitsError::Zero(LimitField::InputBytes));
        }
        if usize::try_from(self.input_bytes).is_err() {
            return Err(LimitsError::OutOfRange(LimitField::InputBytes));
        }
        if self.retained_bytes == 0 {
            return Err(LimitsError::Zero(LimitField::RetainedBytes));
        }
        if usize::try_from(self.retained_bytes).is_err() {
            return Err(LimitsError::OutOfRange(LimitField::RetainedBytes));
        }
        if self.work_items == 0 {
            return Err(LimitsError::Zero(LimitField::WorkItems));
        }
        if usize::try_from(self.work_items).is_err() {
            return Err(LimitsError::OutOfRange(LimitField::WorkItems));
        }
        if self.live_owners == 0 {
            return Err(LimitsError::Zero(LimitField::LiveOwners));
        }
        if self.diagnostic_count == 0 {
            return Err(LimitsError::Zero(LimitField::DiagnosticCount));
        }
        if self.diagnostic_bytes == 0 {
            return Err(LimitsError::Zero(LimitField::DiagnosticBytes));
        }
        if usize::try_from(self.diagnostic_bytes).is_err() {
            return Err(LimitsError::OutOfRange(LimitField::DiagnosticBytes));
        }
        if self.wait.is_zero() {
            return Err(LimitsError::Zero(LimitField::Wait));
        }
        Ok(())
    }
}
