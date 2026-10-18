// SPDX-License-Identifier: Apache-2.0
//! Structured contract failures with no raw observation or identity payloads.

/// The shared capture contract vocabulary. Compare variants, not formatted text.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// An opaque ID was the absent all-zero marker.
    InvalidId,
    /// Values name different domains.
    DomainMismatch,
    /// Exact arithmetic exceeds the representable range.
    ArithmeticOverflow,
    /// A known upper bound is below its lower bound.
    ReversedBounds,
    /// Representable explicit parts do not equal the supplied total.
    ConservationMismatch,
    /// Required provenance is absent.
    MissingProvenance,
    /// Provenance claims conflict.
    ConflictingProvenance,
    /// A key is duplicated.
    DuplicateKey,
    /// The epoch ordinal cannot advance.
    EpochExhausted,
    /// Generations do not match.
    GenerationMismatch,
    /// An explicit capacity was exceeded.
    CapacityExceeded,
    /// A required feed is absent.
    MissingFeed,
    /// A feed is duplicated.
    DuplicateFeed,
    /// A revision is stale.
    StaleRevision,
    /// An interval is reversed or otherwise invalid.
    InvalidInterval,
    /// A sample violates its contract.
    InvalidSample,
    /// A profile violates its contract.
    InvalidProfile,
    /// A version is incompatible.
    IncompatibleVersion,
    /// Replay violates its contract.
    InvalidReplay,
    /// An encountered count was explicitly nonexact due to saturation.
    SaturatedCount,
}
