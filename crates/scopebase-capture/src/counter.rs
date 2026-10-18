// SPDX-License-Identifier: Apache-2.0
//! Checked counter observations and exact-pair caller assertions.
//!
//! NEW: the width-generic protocol follows CP03 C1–C4. ADAPT: OSSLscope
//! 4bcb24c capture.rs:1504–1515 retains missing-baseline blindness; a decrease
//! is now explicitly unknown rather than the donor's saturating subtraction.
//! This module performs no acquisition, clock read, allocation or reset inference.
use crate::{
    domain::{ChannelId, SourceRef},
    quantity::{Count, Unit},
    time::TimeInterval,
    ContractError,
};
use std::fmt;

/// The producer's declared arithmetic, not proof of continuity or absence of reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterPolicy {
    /// Increases exactly; a decrease cannot establish an unsigned delta.
    Monotonic,
    /// Stops increasing at the nonzero maximum.
    Saturating { maximum: u64 },
    /// Wraps at `2^width`, with width in `1..=64`.
    Modulo { width: u8 },
}
/// A valid observed value and its complete read interval, with caller provenance.
/// Missing observations/clocks must stay missing in the acquiring adapter.
///
/// Private fields prevent bypassing validation:
/// ```compile_fail
/// use scopebase_capture::{counter::Sample, quantity::{Count, Events}};
/// fn forge(s: Sample<Events>) -> Sample<Events> {
///     Sample { source: s.source().clone(), channel: s.channel(), policy: s.policy(),
///         interval: s.interval().clone(), value: Count::new(0) }
/// }
/// ```
pub struct Sample<U: Unit> {
    source: SourceRef,
    channel: ChannelId,
    policy: CounterPolicy,
    interval: TimeInterval,
    value: Count<U>,
}
impl<U: Unit> Sample<U> {
    /// Validate policy configuration before the value's range. Metadata is descriptive.
    pub fn new(
        source: SourceRef,
        channel: ChannelId,
        policy: CounterPolicy,
        interval: TimeInterval,
        value: Count<U>,
    ) -> Result<Self, ContractError> {
        match policy {
            CounterPolicy::Saturating { maximum: 0 } => return Err(ContractError::InvalidSample),
            CounterPolicy::Modulo { width } if !(1..=64).contains(&width) => {
                return Err(ContractError::InvalidSample)
            }
            _ => {}
        }
        let valid = match policy {
            CounterPolicy::Monotonic => true,
            CounterPolicy::Saturating { maximum } => value.get() <= maximum,
            CounterPolicy::Modulo { width } => u128::from(value.get()) < (1u128 << width),
        };
        if !valid {
            return Err(ContractError::InvalidSample);
        }
        Ok(Self {
            source,
            channel,
            policy,
            interval,
            value,
        })
    }
    /// Complete caller-provided source, including origin.
    pub fn source(&self) -> &SourceRef {
        &self.source
    }
    /// The retained channel.
    pub fn channel(&self) -> ChannelId {
        self.channel
    }
    /// The declared policy, including its parameters.
    pub fn policy(&self) -> CounterPolicy {
        self.policy
    }
    /// The complete read window, not an invented atomic timestamp.
    pub fn interval(&self) -> &TimeInterval {
        &self.interval
    }
    /// The observed value, in its original unit.
    pub fn value(&self) -> Count<U> {
        self.value
    }
}
/// An explicit caller assertion: this exact pair spans no reset and the producer
/// advanced by at most `maximum`. The library cannot verify that assertion.
///
/// Supply independently justified evidence; never derive the maximum from the
/// observed residue, this library's delta, or elapsed time alone. Equal-by-value
/// reconstructed pairs may reuse it. Different observations need a new assertion.
/// This owns two fixed-size samples, with no heap allocation or retained borrow.
pub struct AdvanceBound<U: Unit> {
    baseline: Sample<U>,
    current: Sample<U>,
    maximum: Count<U>,
}
impl<U: Unit> AdvanceBound<U> {
    /// Check context, modulo policy, then start ordering. Forward overlap and any
    /// maximum are admitted here; comparison decides partialness/contradiction.
    pub fn new(
        baseline: &Sample<U>,
        current: &Sample<U>,
        maximum: Count<U>,
    ) -> Result<Self, ContractError> {
        if !same_context(baseline, current) {
            return Err(ContractError::DomainMismatch);
        }
        if !matches!(current.policy, CounterPolicy::Modulo { .. }) {
            return Err(ContractError::InvalidSample);
        }
        if current.interval.start().ticks() < baseline.interval.start().ticks() {
            return Err(ContractError::InvalidSample);
        }
        Ok(Self {
            baseline: baseline.clone(),
            current: current.clone(),
            maximum,
        })
    }
    /// Exact retained baseline; this never supplies an absent explicit baseline.
    pub fn baseline(&self) -> &Sample<U> {
        &self.baseline
    }
    /// Exact retained current observation.
    pub fn current(&self) -> &Sample<U> {
        &self.current
    }
    /// The independently supplied maximum, unchanged.
    pub fn maximum(&self) -> Count<U> {
        self.maximum
    }
}
/// A policy-qualified change; it is not automatically a loss fact.
#[non_exhaustive]
pub enum Delta<U: Unit> {
    /// An exact same-unit change.
    Exact(Count<U>),
    /// Saturation permits only this lower bound.
    AtLeast(Count<U>),
    /// Evidence does not establish a numerical change.
    Unknown(DeltaUnknown),
}
/// Why no numerical delta can be established.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaUnknown {
    /// No explicit initial observation.
    MissingBaseline,
    /// A decrease without established continuity.
    ResetOrWrap,
    /// The valid read windows overlap.
    PartialRead,
    /// Both observations are already at the saturation maximum.
    Saturated,
    /// No independent strict-less-than-modulus advance bound.
    UnboundedWrap,
}
fn same_context<U: Unit>(baseline: &Sample<U>, current: &Sample<U>) -> bool {
    baseline.source.epoch().capture() == current.source.epoch().capture()
        && baseline.source.epoch().producer() == current.source.epoch().producer()
        && baseline.source.epoch().ordinal() == current.source.epoch().ordinal()
        && baseline.source.binding() == current.source.binding()
        && baseline.source.origin() == current.source.origin()
        && baseline.channel == current.channel
        && baseline.policy == current.policy
        && baseline.interval.start().clock() == current.interval.start().clock()
}
/// Compare immutable samples, preserving CP03's refusal precedence.
///
/// Supplied current-bound matching precedes missing baseline; baseline context
/// precedes its exact-pair matching; reversed/overlapping reads precede arithmetic.
/// A bound never replaces `None`. O(1) work/storage, no allocation or I/O.
pub fn sample_delta<U: Unit>(
    baseline: Option<&Sample<U>>,
    current: &Sample<U>,
    bound: Option<&AdvanceBound<U>>,
) -> Result<Delta<U>, ContractError> {
    if let Some(bound) = bound {
        if !same_context(&bound.current, current) {
            return Err(ContractError::DomainMismatch);
        }
        if current.interval.start().ticks() != bound.current.interval.start().ticks()
            || current.interval.end().ticks() != bound.current.interval.end().ticks()
            || current.value != bound.current.value
        {
            return Err(ContractError::InvalidSample);
        }
    }
    let Some(baseline) = baseline else {
        return Ok(Delta::Unknown(DeltaUnknown::MissingBaseline));
    };
    if !same_context(baseline, current) {
        return Err(ContractError::DomainMismatch);
    }
    if let Some(bound) = bound {
        if baseline.interval.start().ticks() != bound.baseline.interval.start().ticks()
            || baseline.interval.end().ticks() != bound.baseline.interval.end().ticks()
            || baseline.value != bound.baseline.value
        {
            return Err(ContractError::InvalidSample);
        }
    }
    if current.interval.start().ticks() < baseline.interval.start().ticks() {
        return Err(ContractError::InvalidSample);
    }
    if current.interval.start().ticks() < baseline.interval.end().ticks() {
        return Ok(Delta::Unknown(DeltaUnknown::PartialRead));
    }
    let b = baseline.value.get();
    let c = current.value.get();
    match current.policy {
        CounterPolicy::Monotonic => {
            if c < b {
                return Ok(Delta::Unknown(DeltaUnknown::ResetOrWrap));
            }
            Ok(Delta::Exact(Count::new(c - b)))
        }
        CounterPolicy::Saturating { maximum } => {
            if c < b {
                return Ok(Delta::Unknown(DeltaUnknown::ResetOrWrap));
            }
            if b == maximum {
                return Ok(Delta::Unknown(DeltaUnknown::Saturated));
            }
            if c == maximum {
                return Ok(Delta::AtLeast(Count::new(c - b)));
            }
            Ok(Delta::Exact(Count::new(c - b)))
        }
        CounterPolicy::Modulo { width } => {
            let Some(bound) = bound else {
                return Ok(Delta::Unknown(DeltaUnknown::UnboundedWrap));
            };
            let modulus = 1u128 << width;
            if u128::from(bound.maximum.get()) >= modulus {
                return Ok(Delta::Unknown(DeltaUnknown::UnboundedWrap));
            }
            let difference = (u128::from(c) + modulus - u128::from(b)) % modulus;
            if difference > u128::from(bound.maximum.get()) {
                return Err(ContractError::InvalidSample);
            }
            Ok(Delta::Exact(Count::new(difference as u64)))
        }
    }
}
// Manual traits preserve the accepted sealed markers' lack of Debug/Clone/Eq.
impl<U: Unit> Clone for Sample<U> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            channel: self.channel,
            policy: self.policy,
            interval: self.interval.clone(),
            value: self.value,
        }
    }
}
impl<U: Unit> PartialEq for Sample<U> {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
            && self.channel == other.channel
            && self.policy == other.policy
            && self.interval == other.interval
            && self.value == other.value
    }
}
impl<U: Unit> Eq for Sample<U> {}
impl<U: Unit> fmt::Debug for Sample<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sample")
            .field("source", &self.source)
            .field("channel", &self.channel)
            .field("policy", &self.policy)
            .field("interval", &self.interval)
            .field("value", &self.value)
            .finish()
    }
}
impl<U: Unit> Clone for AdvanceBound<U> {
    fn clone(&self) -> Self {
        Self {
            baseline: self.baseline.clone(),
            current: self.current.clone(),
            maximum: self.maximum,
        }
    }
}
impl<U: Unit> PartialEq for AdvanceBound<U> {
    fn eq(&self, other: &Self) -> bool {
        self.baseline == other.baseline
            && self.current == other.current
            && self.maximum == other.maximum
    }
}
impl<U: Unit> Eq for AdvanceBound<U> {}
impl<U: Unit> fmt::Debug for AdvanceBound<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdvanceBound")
            .field("baseline", &self.baseline)
            .field("current", &self.current)
            .field("maximum", &self.maximum)
            .finish()
    }
}
impl<U: Unit> Clone for Delta<U> {
    fn clone(&self) -> Self {
        match self {
            Self::Exact(n) => Self::Exact(*n),
            Self::AtLeast(n) => Self::AtLeast(*n),
            Self::Unknown(r) => Self::Unknown(*r),
        }
    }
}
impl<U: Unit> PartialEq for Delta<U> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(a), Self::Exact(b)) | (Self::AtLeast(a), Self::AtLeast(b)) => a == b,
            (Self::Unknown(a), Self::Unknown(b)) => a == b,
            _ => false,
        }
    }
}
impl<U: Unit> Eq for Delta<U> {}
impl<U: Unit> fmt::Debug for Delta<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(n) => f.debug_tuple("Exact").field(n).finish(),
            Self::AtLeast(n) => f.debug_tuple("AtLeast").field(n).finish(),
            Self::Unknown(r) => f.debug_tuple("Unknown").field(r).finish(),
        }
    }
}
