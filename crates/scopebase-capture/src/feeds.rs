// SPDX-License-Identifier: Apache-2.0
//! Explicit required-feed presence, independent of numeric loss totals.
// ADAPT K d153f3a driver.rs:252-255,259-281,349-359,419-442.
use crate::{
    domain::{ChannelId, Epoch},
    loss::LossFact,
    quantity::Unit,
    ContractError,
};
/// One required-channel inventory in a complete epoch. Presence of Unknown
/// loss satisfies cardinality without establishing absence of loss.
pub struct FeedRegistry {
    epoch: Epoch,
    required: Vec<ChannelId>,
    received: Vec<bool>,
}
impl FeedRegistry {
    /// Admit length and pairwise duplicates before checked owned allocation.
    /// Duplicate preflight O(n²); sorted copy O(n log n), O(n) cardinality.
    pub fn new(
        epoch: Epoch,
        required: &[ChannelId],
        max_feeds: usize,
    ) -> Result<Self, ContractError> {
        Self::new_attempt(epoch, required, max_feeds, &mut Attempt::default())
    }
    fn new_attempt(
        epoch: Epoch,
        ids: &[ChannelId],
        max: usize,
        a: &mut Attempt,
    ) -> Result<Self, ContractError> {
        if ids.len() > max {
            return Err(ContractError::CapacityExceeded);
        }
        for i in 0..ids.len() {
            if ids[..i].contains(&ids[i]) {
                return Err(ContractError::DuplicateKey);
            }
        }
        let mut required = Vec::new();
        a.reserve(&mut required, ids.len(), "feed_required_ids")?;
        required.extend_from_slice(ids);
        required.sort_unstable();
        let mut received = Vec::new();
        a.reserve(&mut received, ids.len(), "feed_received_bits")?;
        received.resize(ids.len(), false);
        Ok(Self {
            epoch,
            required,
            received,
        })
    }
    /// Check full epoch, declared membership, then duplicate presence; commit
    /// exactly one bit. O(log n), no allocation, no fact conversion or accrual.
    pub fn feed<U: Unit>(&mut self, fact: &LossFact<U>) -> Result<(), ContractError> {
        if fact.source().epoch() != &self.epoch {
            return Err(ContractError::DomainMismatch);
        }
        let index = self
            .required
            .binary_search(&fact.channel())
            .map_err(|_| ContractError::InvalidId)?;
        if self.received[index] {
            return Err(ContractError::DuplicateFeed);
        }
        self.received[index] = true;
        Ok(())
    }
    /// O(n) observational, idempotent presence check. A refusal does not seal
    /// the registry: the missing declared feed can still be supplied later.
    pub fn finish(&self) -> Result<(), ContractError> {
        if self.received.iter().all(|&x| x) {
            Ok(())
        } else {
            Err(ContractError::MissingFeed)
        }
    }
}
#[derive(Default)]
struct Attempt {
    #[cfg(test)]
    fail: Option<&'static str>,
    #[cfg(test)]
    visited: Vec<&'static str>,
}
impl Attempt {
    fn reserve<T>(
        &mut self,
        v: &mut Vec<T>,
        n: usize,
        _site: &'static str,
    ) -> Result<(), ContractError> {
        n.checked_mul(std::mem::size_of::<T>())
            .ok_or(ContractError::CapacityExceeded)?;
        #[cfg(test)]
        let result = {
            self.visited.push(_site);
            if self.fail == Some(_site) {
                Vec::<u8>::new().try_reserve_exact(usize::MAX)
            } else {
                v.try_reserve_exact(n)
            }
        };
        #[cfg(not(test))]
        let result = v.try_reserve_exact(n);
        // The injected and ordinary reserve results use this identical mapping.
        result.map_err(|_| ContractError::CapacityExceeded)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{BindingId, CaptureId, Origin, ProducerId, SourceRef},
        loss::{LossKind, LossMagnitude},
        quantity::Events,
    };
    fn epoch() -> Epoch {
        Epoch::new(
            CaptureId::new([1; 16]).unwrap(),
            ProducerId::new([2; 16]).unwrap(),
            0,
        )
    }
    fn id(n: u32) -> ChannelId {
        ChannelId::new(n)
    }
    fn fact(n: u32) -> LossFact<Events> {
        LossFact::new(
            SourceRef::new(epoch(), BindingId::new([3; 32]).unwrap(), Origin::Synthetic),
            id(n),
            LossKind::Transport,
            LossMagnitude::Unknown,
        )
        .unwrap()
    }
    #[test]
    fn constructor_reserves_and_sorted_bit_association() {
        for site in ["feed_required_ids", "feed_received_bits"] {
            let input = [id(1), id(0)];
            let mut a = Attempt {
                fail: Some(site),
                ..Attempt::default()
            };
            assert!(
                matches!(
                    FeedRegistry::new_attempt(epoch(), &input, 2, &mut a),
                    Err(ContractError::CapacityExceeded)
                ),
                "CP06:feed reserve maps capacity"
            );
            assert_eq!(
                a.visited,
                if site == "feed_required_ids" {
                    vec!["feed_required_ids"]
                } else {
                    vec!["feed_required_ids", "feed_received_bits"]
                },
                "CP06:feed constructor visits"
            );
            assert_eq!(input, [id(1), id(0)]);
            for (input, want) in [
                (vec![id(1), id(0), id(2)], ContractError::CapacityExceeded),
                (vec![id(1), id(1), id(0)], ContractError::CapacityExceeded),
                (vec![id(1), id(1)], ContractError::DuplicateKey),
            ] {
                let mut a = Attempt {
                    fail: Some(site),
                    ..Attempt::default()
                };
                match FeedRegistry::new_attempt(epoch(), &input, 2, &mut a) {
                    Err(e) => assert_eq!(e, want, "CP06:feed preflight error"),
                    Ok(_) => panic!("CP06:invalid declaration admitted"),
                };
                assert!(
                    a.visited.is_empty(),
                    "CP06:no feed reserve before validation"
                );
            }
            let mut r = FeedRegistry::new(epoch(), &input, 2).unwrap();
            assert_eq!(r.required, [id(0), id(1)]);
            assert_eq!(r.received, [false, false]);
            r.feed(&fact(1)).unwrap();
            assert_eq!(
                r.received,
                [false, true],
                "CP06:sorted id-to-bit association"
            );
            assert_eq!(r.finish(), Err(ContractError::MissingFeed));
            assert_eq!(r.feed(&fact(1)), Err(ContractError::DuplicateFeed));
            assert_eq!(r.received, [false, true]);
            r.feed(&fact(0)).unwrap();
            assert_eq!(r.received, [true, true]);
            assert_eq!(r.finish(), Ok(()));
        }
    }
    #[test]
    fn ordinary_reserve_error_uses_the_same_capacity_mapping() {
        let mut values = Vec::<u8>::new();
        let mut a = Attempt::default();
        // Deterministic capacity overflow, without allocating usize::MAX bytes.
        assert_eq!(
            a.reserve(&mut values, usize::MAX, "normal_capacity_error"),
            Err(ContractError::CapacityExceeded),
            "CP06:normal reserve maps capacity"
        );
        assert!(values.is_empty());
        assert_eq!(a.visited, ["normal_capacity_error"]);
    }
}
