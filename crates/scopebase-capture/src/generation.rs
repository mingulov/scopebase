// SPDX-License-Identifier: Apache-2.0
//! Immutable, caller-supplied object generations within a complete capture epoch.
//!
//! A raw handle alone does not establish continuity. The caller supplies its
//! complete identity domain as `K`, and keeps unknown observations separate
//! rather than turning them into a shared sentinel key. This module issues no
//! identities and performs no lifecycle, clock, syscall or logging effects.
use crate::{domain::Epoch, ContractError};
use std::fmt;

/// A caller-asserted raw identity and generation, scoped to a complete epoch.
///
/// Zero and `u64::MAX` are valid supplied generations. There is no layout,
/// serialization, uniqueness or runtime-authority promise.
pub struct ObjectKey<K> {
    epoch: Epoch,
    raw: K,
    generation: u64,
}

impl<K> ObjectKey<K> {
    /// Move the supplied fields without inferring identity or requiring traits.
    pub fn new(epoch: Epoch, raw: K, generation: u64) -> Self {
        Self {
            epoch,
            raw,
            generation,
        }
    }
    /// The complete caller-supplied capture and producer epoch.
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// The caller's complete raw identity domain, without formatting it.
    pub fn raw(&self) -> &K {
        &self.raw
    }
    /// The exact supplied object generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Advance without wrapping, checking overflow before cloning the payload.
    ///
    /// Success invokes `K::clone` exactly once and stores its result without
    /// equivalence validation. Caller callbacks can allocate, block, panic or
    /// mutate shared interior state; their effects are not rolled back.
    pub fn next_generation(&self) -> Result<Self, ContractError>
    where
        K: Clone,
    {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(ContractError::ArithmeticOverflow)?;
        let raw = self.raw.clone();
        Ok(Self::new(self.epoch.clone(), raw, generation))
    }

    /// Compare the full epoch, then generation, then raw equality exactly once.
    ///
    /// Metadata refusal performs no payload comparison. A payload comparison
    /// has the caller's own costs, effects and panic behavior.
    pub fn matches(&self, other: &Self) -> bool
    where
        K: Eq,
    {
        self == other
    }
}
impl<K: Clone> Clone for ObjectKey<K> {
    fn clone(&self) -> Self {
        Self::new(self.epoch.clone(), self.raw.clone(), self.generation)
    }
}
impl<K: PartialEq> PartialEq for ObjectKey<K> {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch && self.generation == other.generation && self.raw == other.raw
    }
}
impl<K: Eq> Eq for ObjectKey<K> {}
impl<K> fmt::Debug for ObjectKey<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectKey")
            .field("epoch", &self.epoch)
            .field("generation", &self.generation)
            .field("raw", &"<redacted>")
            .finish()
    }
}

/// Require the same complete relation as [`ObjectKey::matches`].
///
/// Every false relation, including a different raw identity or epoch, returns
/// `GenerationMismatch`. This invokes at most one payload equality operation.
pub fn require_generation<K: Eq>(
    submitted: &ObjectKey<K>,
    current: &ObjectKey<K>,
) -> Result<(), ContractError> {
    if submitted.matches(current) {
        Ok(())
    } else {
        Err(ContractError::GenerationMismatch)
    }
}
