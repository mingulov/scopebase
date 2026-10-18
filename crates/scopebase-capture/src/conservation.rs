// SPDX-License-Identifier: Apache-2.0
//! Checked arithmetic over caller-asserted disjoint parts; no physical identity proof.
// ADAPT: KryProbe d153f3a workload/scope.rs:32–36,59–97 checked private triple.
use crate::{
    quantity::{Count, Unit},
    ContractError,
};
use std::fmt;

/// Matched, nonmatched and unknown parts with an independently supplied total.
pub struct ScopePartition<U: Unit> {
    total: Count<U>,
    matched: Count<U>,
    nonmatched: Count<U>,
    unknown: Count<U>,
}
impl<U: Unit> ScopePartition<U> {
    /// Refuse arithmetic overflow first, then a representable total mismatch.
    pub fn new(
        total: Count<U>,
        matched: Count<U>,
        nonmatched: Count<U>,
        unknown: Count<U>,
    ) -> Result<Self, ContractError> {
        let observed = matched.checked_add(nonmatched)?.checked_add(unknown)?;
        if observed != total {
            return Err(ContractError::ConservationMismatch);
        }
        Ok(Self {
            total,
            matched,
            nonmatched,
            unknown,
        })
    }
    /// The supplied total.
    pub fn total(&self) -> Count<U> {
        self.total
    }
    /// The matched part.
    pub fn matched(&self) -> Count<U> {
        self.matched
    }
    /// The nonmatched part.
    pub fn nonmatched(&self) -> Count<U> {
        self.nonmatched
    }
    /// The unknown part; never a confirmed match.
    pub fn unknown(&self) -> Count<U> {
        self.unknown
    }
}
impl<U: Unit> Clone for ScopePartition<U> {
    fn clone(&self) -> Self {
        Self {
            total: self.total,
            matched: self.matched,
            nonmatched: self.nonmatched,
            unknown: self.unknown,
        }
    }
}
impl<U: Unit> PartialEq for ScopePartition<U> {
    fn eq(&self, other: &Self) -> bool {
        self.total == other.total
            && self.matched == other.matched
            && self.nonmatched == other.nonmatched
            && self.unknown == other.unknown
    }
}
impl<U: Unit> Eq for ScopePartition<U> {}
impl<U: Unit> fmt::Debug for ScopePartition<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopePartition")
            .field("total", &self.total)
            .field("matched", &self.matched)
            .field("nonmatched", &self.nonmatched)
            .field("unknown", &self.unknown)
            .finish()
    }
}
/// Sum explicit parts with checked arithmetic, then compare the supplied total.
///
/// The caller asserts disjointness, completeness and shared provenance. Empty
/// parts conserve exactly total zero. Runs in O(n) work and O(1) extra storage;
/// there is no absolute time, memory, cancellation or cleanup guarantee.
pub fn check_conservation<U: Unit>(
    total: Count<U>,
    disjoint_parts: &[Count<U>],
) -> Result<(), ContractError> {
    let mut observed = Count::new(0);
    for part in disjoint_parts {
        observed = observed.checked_add(*part)?;
    }
    if observed != total {
        return Err(ContractError::ConservationMismatch);
    }
    Ok(())
}
