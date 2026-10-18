// SPDX-License-Identifier: Apache-2.0
//! Explicit caller-clock nanoseconds and checked half-open intervals.
// ADAPT invariant: KryProbe d153f3a workload/evidence.rs:85–125. Its intervals
// are inclusive and defer reversal refusal to evidence validation; these do not.
use crate::{domain::ClockDomain, ContractError};

/// Nanoseconds supplied by the caller in its named clock domain.
/// No physical clock, conversion, suspend policy or time namespace is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    clock: ClockDomain,
    ticks: u64,
}
impl Timestamp {
    /// Retain the caller's nanoseconds, including zero and `u64::MAX`.
    pub fn new(clock: ClockDomain, ticks: u64) -> Self {
        Self { clock, ticks }
    }
    /// The caller's clock domain.
    pub fn clock(&self) -> ClockDomain {
        self.clock
    }
    /// The exact nanoseconds supplied.
    pub fn ticks(&self) -> u64 {
        self.ticks
    }
}
/// A half-open `[start, end)` interval. Equal endpoints have zero duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeInterval {
    start: Timestamp,
    end: Timestamp,
}
impl TimeInterval {
    /// Refuse clock mismatch before checking endpoint order.
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, ContractError> {
        if start.clock != end.clock {
            return Err(ContractError::DomainMismatch);
        }
        if end.ticks < start.ticks {
            return Err(ContractError::InvalidInterval);
        }
        Ok(Self { start, end })
    }
    /// Exact duration in the caller's nanoseconds; construction proved subtraction safe.
    pub fn duration_ns(&self) -> u64 {
        self.end.ticks - self.start.ticks
    }
    /// The retained start, inclusive.
    pub fn start(&self) -> &Timestamp {
        &self.start
    }
    /// The retained end, exclusive.
    pub fn end(&self) -> &Timestamp {
        &self.end
    }
}
