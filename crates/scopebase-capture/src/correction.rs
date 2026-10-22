// SPDX-License-Identifier: Apache-2.0
//! Checked complete replacement of a caller-associated value. Epoch/revision
//! are metadata, not a target key or a delivery/broadcast protocol.
// ADAPT O 4bcb24c scan/oracle.rs:690-700,1594-1608; capture.rs:7490-7503.
use crate::{domain::Epoch, ContractError};
/// An exact revision, including zero and MAX. No sentinel or wrapping semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision(u64);
impl Revision {
    /// Retain an exact value.
    pub fn new(value: u64) -> Self {
        Self(value)
    }
}
/// One complete value, starting at revision zero. Automatic Send/Sync follows
/// its actual fields; metadata operations impose no Eq/Clone/Debug bounds.
pub struct Versioned<T> {
    epoch: Epoch,
    revision: Revision,
    value: T,
}
/// A checked next-revision envelope. The caller routes its complete target key.
pub struct Correction<T> {
    epoch: Epoch,
    from: Revision,
    to: Revision,
    replacement: T,
}
impl<T> Versioned<T> {
    /// Start one caller-owned value at revision zero.
    pub fn new(epoch: Epoch, value: T) -> Self {
        Self {
            epoch,
            revision: Revision::new(0),
            value,
        }
    }
    /// Current exact revision.
    pub fn revision(&self) -> Revision {
        self.revision
    }
    /// Borrow the whole current value.
    pub fn value(&self) -> &T {
        &self.value
    }
    /// Check complete epoch before exact current revision, then replace the whole
    /// value. A normally returned refusal returns the unchanged original owner;
    /// the rejected replacement is consumed and dropped. On success old T drops.
    /// Ordinary payload Drop effects/panics propagate: no catch, rollback or normal
    /// return is promised if destruction panics. Same metadata cannot detect a
    /// caller's wrong target key, and this does not distribute to other holders.
    pub fn apply(self, correction: Correction<T>) -> Result<Self, (Self, ContractError)> {
        if self.epoch != correction.epoch {
            return Err((self, ContractError::DomainMismatch));
        }
        if self.revision != correction.from {
            return Err((self, ContractError::StaleRevision));
        }
        Ok(Self {
            epoch: correction.epoch,
            revision: correction.to,
            value: correction.replacement,
        })
    }
}
impl<T> Correction<T> {
    /// Construct exactly from+1, refusing MAX with ArithmeticOverflow. On refusal
    /// the replacement is dropped with ordinary caller-defined Drop behavior.
    pub fn new(epoch: Epoch, from: Revision, replacement: T) -> Result<Self, ContractError> {
        let to = from
            .0
            .checked_add(1)
            .ok_or(ContractError::ArithmeticOverflow)?;
        Ok(Self {
            epoch,
            from,
            to: Revision::new(to),
            replacement,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CaptureId, ProducerId};
    #[test]
    fn max_minus_one_reaches_max() {
        let e = Epoch::new(
            CaptureId::new([1; 16]).unwrap(),
            ProducerId::new([2; 16]).unwrap(),
            0,
        );
        let v = Versioned {
            epoch: e.clone(),
            revision: Revision::new(u64::MAX - 1),
            value: "A",
        };
        let v = match v.apply(Correction::new(e, Revision::new(u64::MAX - 1), "B").unwrap()) {
            Ok(v) => v,
            Err(_) => panic!("CP06:MAX edge"),
        };
        assert_eq!(
            v.revision(),
            Revision::new(u64::MAX),
            "CP06:no revision wrap"
        );
        assert_eq!(*v.value(), "B");
    }
}
