// SPDX-License-Identifier: Apache-2.0
//! Caller-asserted domains and provenance, without live authority or ID generation.
use crate::ContractError;
use std::fmt;

macro_rules! opaque_id {
    ($name:ident, $len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);
        impl $name {
            /// Reject the all-zero absent marker; other bytes are caller assertions.
            pub fn new(value: [u8; $len]) -> Result<Self, ContractError> {
                if value.iter().all(|byte| *byte == 0) {
                    return Err(ContractError::InvalidId);
                }
                Ok(Self(value))
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}
opaque_id!(
    CaptureId,
    16,
    "A caller-named capture domain, not identity authority."
);
opaque_id!(ProducerId, 16, "A caller-named producer domain.");
opaque_id!(
    BindingId,
    32,
    "A caller-asserted artifact binding; not proof of loaded bytes."
);
opaque_id!(
    ClockDomain,
    16,
    "A caller-named nanosecond clock domain; no conversion is inferred."
);

macro_rules! numeric_id {
    ($name:ident, $number:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($number);
        impl $name {
            /// Construct an identifier; zero is an ordinary valid value.
            pub fn new(value: $number) -> Self {
                Self(value)
            }
        }
    };
}
numeric_id!(ChannelId, u32, "A channel identifier scoped by its caller.");
numeric_id!(ClaimId, u32, "A claim identifier scoped by its caller.");
numeric_id!(
    PhysicalSiteId,
    u64,
    "A physical-site label, not a universal object identity."
);

/// A producer's ordinal within one capture. Ordinal zero is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epoch {
    capture: CaptureId,
    producer: ProducerId,
    ordinal: u64,
}
impl Epoch {
    /// Retain the supplied domains and ordinal without acquiring authority.
    pub fn new(capture: CaptureId, producer: ProducerId, ordinal: u64) -> Self {
        Self {
            capture,
            producer,
            ordinal,
        }
    }
    /// Advance without wrapping or changing either domain.
    pub fn successor(&self) -> Result<Self, ContractError> {
        let ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or(ContractError::EpochExhausted)?;
        Ok(Self::new(self.capture, self.producer, ordinal))
    }
    /// The caller's capture domain.
    pub fn capture(&self) -> CaptureId {
        self.capture
    }
    /// The caller's producer domain.
    pub fn producer(&self) -> ProducerId {
        self.producer
    }
    /// The exact ordinal, including zero.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

/// How an adapter labels its observation; no variant proves live provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Reported by an adapter.
    AdapterReported,
    /// Generated as synthetic input.
    Synthetic,
    /// Replayed from a prior record.
    Replayed,
}

/// Explicit observation provenance; descriptive values cannot reconstruct authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    epoch: Epoch,
    binding: BindingId,
    origin: Origin,
}
impl SourceRef {
    /// Retain all supplied provenance without promoting its origin.
    pub fn new(epoch: Epoch, binding: BindingId, origin: Origin) -> Self {
        Self {
            epoch,
            binding,
            origin,
        }
    }
    /// The exact epoch.
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// The supplied origin.
    pub fn origin(&self) -> Origin {
        self.origin
    }
    /// The supplied binding.
    pub fn binding(&self) -> BindingId {
        self.binding
    }
}
