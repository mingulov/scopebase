// SPDX-License-Identifier: Apache-2.0
//! Typed loss facts and separately capped diagnostic signals.
// ADAPT: OSSLscope 4bcb24c evidence.rs:300–348 source/unit/loss distinction.
// ADAPT: KryProbe d153f3a kcrypto_agg.rs:133–161 independent capped lane fold.
//! Classification is explicit caller policy; no loss total or activity conversion.
use crate::{
    domain::{ChannelId, SourceRef},
    quantity::{Count, Unit},
    ContractError,
};
use std::fmt;

/// Caller-selected loss classification; it does not prescribe or convert units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossKind {
    /// Discovery omissions.
    Discovery,
    /// Transport omissions.
    Transport,
    /// Producer nonexecution.
    KernelNonexecution,
    /// Attribution failure.
    Attribution,
    /// Queue overflow.
    QueueOverflow,
    /// Malformed input.
    MalformedInput,
    /// Diagnostic truncation.
    DiagnosticTruncation,
}
/// Same-unit magnitude with explicit uncertainty; unknown is never exact zero.
#[non_exhaustive]
pub enum LossMagnitude<U: Unit> {
    /// An exact count, including zero.
    Exact(Count<U>),
    /// A lower bound, including zero.
    AtLeast(Count<U>),
    /// No numerical magnitude is known.
    Unknown,
}
/// One explicit loss observation, retaining source, channel, kind and unit.
pub struct LossFact<U: Unit> {
    source: SourceRef,
    channel: ChannelId,
    kind: LossKind,
    magnitude: LossMagnitude<U>,
}
impl<U: Unit> LossFact<U> {
    /// All checked arguments are admitted. Kind does not imply a unit or a sum.
    pub fn new(
        source: SourceRef,
        channel: ChannelId,
        kind: LossKind,
        magnitude: LossMagnitude<U>,
    ) -> Result<Self, ContractError> {
        Ok(Self {
            source,
            channel,
            kind,
            magnitude,
        })
    }
    /// Full source metadata; this does not acquire authority.
    pub fn source(&self) -> &SourceRef {
        &self.source
    }
    /// The retained channel.
    pub fn channel(&self) -> ChannelId {
        self.channel
    }
    /// The caller's classification.
    pub fn kind(&self) -> LossKind {
        self.kind
    }
    /// The retained magnitude, preserving zero/lower-bound/unknown distinctions.
    pub fn magnitude(&self) -> &LossMagnitude<U> {
        &self.magnitude
    }
}
/// A capped diagnostic byte, never an exact omitted-event magnitude.
///
/// ```compile_fail
/// use scopebase_capture::loss::CappedLossSignal;
/// fn forge(s: CappedLossSignal) -> CappedLossSignal {
///     CappedLossSignal { source: s.source().clone(), channel: s.channel(), observed: 1, cap: 0 }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CappedLossSignal {
    source: SourceRef,
    channel: ChannelId,
    observed: u8,
    cap: u8,
}
impl CappedLossSignal {
    /// Refuse cap zero and observations beyond the cap; zero itself is valid.
    pub fn new(
        source: SourceRef,
        channel: ChannelId,
        observed: u8,
        cap: u8,
    ) -> Result<Self, ContractError> {
        if cap == 0 || observed > cap {
            return Err(ContractError::InvalidSample);
        }
        Ok(Self {
            source,
            channel,
            observed,
            cap,
        })
    }
    /// Full source metadata.
    pub fn source(&self) -> &SourceRef {
        &self.source
    }
    /// The retained channel.
    pub fn channel(&self) -> ChannelId {
        self.channel
    }
    /// The capped byte, with no exact event-count conversion.
    pub fn observed(&self) -> u8 {
        self.observed
    }
    /// The nonzero cap.
    pub fn cap(&self) -> u8 {
        self.cap
    }
}
/// Fold independent pre-capped lanes without wrapping; inspect every lane even
/// after reaching the cap. An empty slice with a valid cap yields zero.
///
/// ADAPT K's capped CPU/program sum; the byte protocol additionally refuses
/// invalid lanes instead of clamping arbitrary u64 inputs. O(n) work and O(1)
/// extra memory, no allocation. The caller owns input-length admission.
pub fn fold_capped_signals(values: &[u8], cap: u8) -> Result<u8, ContractError> {
    if cap == 0 {
        return Err(ContractError::InvalidSample);
    }
    let mut total = 0u16;
    for &value in values {
        if value > cap {
            return Err(ContractError::InvalidSample);
        }
        total = (total + u16::from(value)).min(u16::from(cap));
    }
    Ok(total as u8)
}
impl<U: Unit> Clone for LossMagnitude<U> {
    fn clone(&self) -> Self {
        match self {
            Self::Exact(n) => Self::Exact(*n),
            Self::AtLeast(n) => Self::AtLeast(*n),
            Self::Unknown => Self::Unknown,
        }
    }
}
impl<U: Unit> PartialEq for LossMagnitude<U> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(a), Self::Exact(b)) | (Self::AtLeast(a), Self::AtLeast(b)) => a == b,
            (Self::Unknown, Self::Unknown) => true,
            _ => false,
        }
    }
}
impl<U: Unit> Eq for LossMagnitude<U> {}
impl<U: Unit> fmt::Debug for LossMagnitude<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(n) => f.debug_tuple("Exact").field(n).finish(),
            Self::AtLeast(n) => f.debug_tuple("AtLeast").field(n).finish(),
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}
impl<U: Unit> Clone for LossFact<U> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            channel: self.channel,
            kind: self.kind,
            magnitude: self.magnitude.clone(),
        }
    }
}
impl<U: Unit> PartialEq for LossFact<U> {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
            && self.channel == other.channel
            && self.kind == other.kind
            && self.magnitude == other.magnitude
    }
}
impl<U: Unit> Eq for LossFact<U> {}
impl<U: Unit> fmt::Debug for LossFact<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LossFact")
            .field("source", &self.source)
            .field("channel", &self.channel)
            .field("kind", &self.kind)
            .field("magnitude", &self.magnitude)
            .finish()
    }
}
