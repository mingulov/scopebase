// SPDX-License-Identifier: Apache-2.0
//! Insertion-frozen identity, with exact counts distinct from saturation.
//!
//! ADAPT: KryProbe d153f3aa kcrypto_agg.rs:825-837,842-846,857-861:
//! owner cardinality precedes ordered count validation and winner selection.
//! Generic wrappers and typed saturation are NEW under CP04 P1-P5.
//!
//! Folding reads at most twice, O(n) work/O(1) storage excluding caller Clone.
//! Clone runs once after validation and may allocate, block, mutate interior
//! state or panic. Such caller effects cannot be rolled back. The library does
//! not mutate the borrowed slice, marker fields or count states. Folding never
//! invokes payload Eq; explicit equality operations have caller-defined costs.
//! No lane/byte/time bound, live insertion premise or kernel authority is added.
use crate::{
    quantity::{Count, Unit},
    ContractError,
};
use std::fmt;
/// Why an identity observation remains unknown; no default identity is invented.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityUnknown {
    NotObserved,
    Ambiguous,
    Exhausted,
}
/// An observation is descriptive and confers no process or object authority.
#[non_exhaustive]
pub enum ObservedIdentity<I> {
    Known(I),
    Unknown(IdentityUnknown),
}
/// Only the successful inserter owns identity; secondary counts still contribute.
pub enum LaneIdentity<I> {
    InsertionOwner(I),
    Secondary,
}
/// A lane's count is exact (including MAX) or explicitly nonexact/saturated.
pub struct ProvenanceLane<I, U: Unit> {
    identity: LaneIdentity<I>,
    count: Option<Count<U>>,
}
/// A unique insertion identity and exact checked total, with no partial output.
pub struct InsertionFold<I, U: Unit> {
    identity: I,
    total: Count<U>,
}
impl<I, U: Unit> ProvenanceLane<I, U> {
    /// Declare an exact count. Moves its arguments without cloning.
    pub fn new(identity: LaneIdentity<I>, count: Count<U>) -> Self {
        Self {
            identity,
            count: Some(count),
        }
    }
    /// Declare nonexact saturation, retaining its owner/secondary marker.
    pub fn saturated(identity: LaneIdentity<I>) -> Self {
        Self {
            identity,
            count: None,
        }
    }
}
impl<I, U: Unit> InsertionFold<I, U> {
    /// The successful inserter's observation, including genuine numeric zero.
    pub fn identity(&self) -> &I {
        &self.identity
    }
    /// The exact total in the caller's unit.
    pub fn total(&self) -> Count<U> {
        self.total
    }
}
/// Validate marker cardinality, then counts in order, then clone the owner once.
///
/// Missing/conflicting ownership precedes every count error. The first count
/// refusal wins: an overflowing exact prefix can precede a later saturation.
/// No payload Clone or Eq runs on any Result refusal; caller Clone effects on
/// success/unwind remain caller-owned, including interior mutation and panic.
pub fn fold_insertion_identity<I: Eq + Clone, U: Unit>(
    lanes: &[ProvenanceLane<I, U>],
) -> Result<InsertionFold<I, U>, ContractError> {
    let mut owner: Option<usize> = None;
    for (index, lane) in lanes.iter().enumerate() {
        if let LaneIdentity::InsertionOwner(_) = &lane.identity {
            if owner.is_some() {
                return Err(ContractError::ConflictingProvenance);
            }
            owner = Some(index);
        }
    }
    let owner = owner.ok_or(ContractError::MissingProvenance)?;
    let mut total = Count::new(0);
    for lane in lanes {
        let count = lane.count.ok_or(ContractError::SaturatedCount)?;
        total = total.checked_add(count)?;
    }
    let identity = match &lanes[owner].identity {
        LaneIdentity::InsertionOwner(identity) => identity,
        LaneIdentity::Secondary => return Err(ContractError::MissingProvenance),
    };
    Ok(InsertionFold {
        identity: identity.clone(),
        total,
    })
}
impl<I: Clone> Clone for ObservedIdentity<I> {
    fn clone(&self) -> Self {
        match self {
            Self::Known(i) => Self::Known(i.clone()),
            Self::Unknown(r) => Self::Unknown(*r),
        }
    }
}
impl<I: PartialEq> PartialEq for ObservedIdentity<I> {
    fn eq(&self, o: &Self) -> bool {
        match (self, o) {
            (Self::Known(a), Self::Known(b)) => a == b,
            (Self::Unknown(a), Self::Unknown(b)) => a == b,
            _ => false,
        }
    }
}
impl<I: Eq> Eq for ObservedIdentity<I> {}
impl<I> fmt::Debug for ObservedIdentity<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(_) => f.write_str("Known(<redacted>)"),
            Self::Unknown(r) => f.debug_tuple("Unknown").field(r).finish(),
        }
    }
}
impl<I: Clone> Clone for LaneIdentity<I> {
    fn clone(&self) -> Self {
        match self {
            Self::InsertionOwner(i) => Self::InsertionOwner(i.clone()),
            Self::Secondary => Self::Secondary,
        }
    }
}
impl<I: PartialEq> PartialEq for LaneIdentity<I> {
    fn eq(&self, o: &Self) -> bool {
        match (self, o) {
            (Self::InsertionOwner(a), Self::InsertionOwner(b)) => a == b,
            (Self::Secondary, Self::Secondary) => true,
            _ => false,
        }
    }
}
impl<I: Eq> Eq for LaneIdentity<I> {}
impl<I> fmt::Debug for LaneIdentity<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsertionOwner(_) => f.write_str("InsertionOwner(<redacted>)"),
            Self::Secondary => f.write_str("Secondary"),
        }
    }
}
impl<I: Clone, U: Unit> Clone for ProvenanceLane<I, U> {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            count: self.count,
        }
    }
}
impl<I: PartialEq, U: Unit> PartialEq for ProvenanceLane<I, U> {
    fn eq(&self, o: &Self) -> bool {
        self.identity == o.identity && self.count == o.count
    }
}
impl<I: Eq, U: Unit> Eq for ProvenanceLane<I, U> {}
impl<I, U: Unit> fmt::Debug for ProvenanceLane<I, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvenanceLane")
            .field("identity", &self.identity)
            .field("count", &self.count)
            .finish()
    }
}
impl<I: Clone, U: Unit> Clone for InsertionFold<I, U> {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            total: self.total,
        }
    }
}
impl<I: PartialEq, U: Unit> PartialEq for InsertionFold<I, U> {
    fn eq(&self, o: &Self) -> bool {
        self.identity == o.identity && self.total == o.total
    }
}
impl<I: Eq, U: Unit> Eq for InsertionFold<I, U> {}
impl<I, U: Unit> fmt::Debug for InsertionFold<I, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InsertionFold")
            .field("identity", &"<redacted>")
            .field("total", &self.total)
            .finish()
    }
}
