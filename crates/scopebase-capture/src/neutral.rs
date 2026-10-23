// SPDX-License-Identifier: Apache-2.0
//! Canonical neutral observation validation (v1 semantic seam).
//!
//! ADAPT: MemVeil 8307a17 `src/memveil/model/validate.mojo:19-50`
//! (`parse_u64` canonical grammar: no sign, no leading zeros, checked
//! accumulation refusing overflow). This port keeps the grammar and maps
//! every refusal to [`ContractError::InvalidSample`].
//! ADAPT: KryProbe d153f3a
//! `scripts/kcrypto_perf/successorvalidity.py:81-96` (`_unsigned_counter`:
//! bools are never counters, digit strings or u64-range ints only).
//! DELTA: bare JSON integers are refused too; v1 counts are canonical
//! decimal strings only, so no float or bare-int coercion exists.
//! CONCEPT: KryProbe d153f3a
//! `crates/kryprobe-core/src/workload/evidence.rs:34-42,260`
//! (closed method vocabulary refusing at decode; assertions cannot
//! self-promote) and `observation.rs:32-56` (coherence validation;
//! cgroup-zero carries no resolved identity). V1 keeps closed origin,
//! unit, kind and reason vocabularies and preserves origins exactly.
//! VECTORS: KryProbe d153f3a `tests/kcrypto_perf/test_successor.py`
//! `:316,:335,:386,:393,:570` strict receipt vectors; MemVeil 8307a17
//! `tests/unit/test_reader.mojo:330,339` canonical-u64 vectors.
//!
//! [`validate_v1`] is the sole neutral semantic validator: every record
//! kind is checked by calling the existing public constructors, so direct
//! construction and replay agree on both acceptance and refusal. V1
//! validates one single-epoch snapshot: channels are unique within their
//! class, claims and reasons are unique, and corrections are single steps
//! from a genesis revision. Refusal precedence is: limits, source
//! identity, duplicates, unit coherence, then per-item constructor checks
//! in input order. Limit checks precede every clone and allocation.
use crate::{
    conservation::check_conservation,
    correction::{Correction, Revision, Versioned},
    counter::{CounterPolicy, Sample},
    domain::{BindingId, CaptureId, ChannelId, ClockDomain, Epoch, Origin, ProducerId, SourceRef},
    loss::{CappedLossSignal, LossFact, LossKind, LossMagnitude},
    quantity::{Count, Unit},
    time::{TimeInterval, Timestamp},
    ContractError,
};
use std::fmt;

/// Hard maxima. [`NeutralLimits::default`] equals these values.
pub const NEUTRAL_MAX_COUNTERS: usize = 4096;
/// Hard maxima. [`NeutralLimits::default`] equals these values.
pub const NEUTRAL_MAX_CLAIMS: usize = 4096;
/// Hard maxima. [`NeutralLimits::default`] equals these values.
pub const NEUTRAL_MAX_REASONS_PER_CLAIM: usize = 16;

/// Cardinality limits. Every value at or below the hard maxima is valid;
/// anything above refuses with [`ContractError::CapacityExceeded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeutralLimits {
    /// Maximum counters.
    pub counters: usize,
    /// Maximum claims.
    pub claims: usize,
    /// Maximum reasons per claim.
    pub reasons_per_claim: usize,
}

impl Default for NeutralLimits {
    /// The hard maxima: counters 4,096, claims 4,096, reasons 16.
    fn default() -> Self {
        Self {
            counters: NEUTRAL_MAX_COUNTERS,
            claims: NEUTRAL_MAX_CLAIMS,
            reasons_per_claim: NEUTRAL_MAX_REASONS_PER_CLAIM,
        }
    }
}

/// Raw asserted origin. Validation preserves it exactly, never promoting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeutralOrigin {
    /// Reported by an adapter.
    AdapterReported,
    /// Generated as synthetic input.
    Synthetic,
    /// Replayed from a prior record.
    Replayed,
}

/// Raw asserted unit. Counters, losses and partitions must name the
/// document unit; signals must name [`NeutralUnit::DiagnosticSignals`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeutralUnit {
    /// Event counts.
    Events,
    /// Record counts.
    Records,
    /// Byte counts.
    Bytes,
    /// Object counts.
    Objects,
    /// Attempt counts.
    Attempts,
    /// Nonexecution counts.
    Nonexecutions,
    /// Diagnostic signal counts.
    DiagnosticSignals,
}

/// Raw asserted counter policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeutralPolicy {
    /// Increases exactly.
    Monotonic,
    /// Stops increasing at the nonzero maximum.
    Saturating {
        /// The declared maximum.
        maximum: u64,
    },
    /// Wraps at `2^width`, with width in `1..=64`.
    Modulo {
        /// The declared width.
        width: u8,
    },
}

/// Raw asserted loss classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeutralLossKind {
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

/// Raw asserted loss magnitude. Known zero and unknown stay distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeutralMagnitude {
    /// An exact count, including zero.
    Exact(u64),
    /// A lower bound, including zero.
    AtLeast(u64),
    /// No numerical magnitude is known.
    Unknown,
}

/// Raw asserted quality reason vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeutralReason {
    /// Accepted damaging consumed evidence affects this claim.
    ConsumedLoss,
    /// Required evidence is absent.
    MissingEvidence,
    /// This particular query selected a partial view.
    QueryPartial,
    /// Caller evidence is ambiguous.
    Ambiguous,
    /// Caller capacity affected evidence.
    Capacity,
}

/// Raw asserted source. Byte arrays are caller assertions, not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeutralSource {
    /// Caller-named capture domain bytes.
    pub capture: [u8; 16],
    /// Caller-named producer domain bytes.
    pub producer: [u8; 16],
    /// Exact epoch ordinal, including zero.
    pub ordinal: u64,
    /// Caller-asserted artifact binding bytes.
    pub binding: [u8; 32],
    /// Asserted origin, preserved exactly.
    pub origin: NeutralOrigin,
}

/// Raw asserted counter observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeutralCounter {
    /// Channel, unique within the counters of one observation.
    pub channel: u32,
    /// Declared policy.
    pub policy: NeutralPolicy,
    /// Caller-named clock domain bytes.
    pub clock: [u8; 16],
    /// Read-window start ticks.
    pub start: u64,
    /// Read-window end ticks.
    pub end: u64,
    /// Observed value.
    pub value: u64,
    /// Asserted unit, must equal the document unit.
    pub unit: NeutralUnit,
}

/// Raw asserted loss observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeutralLoss {
    /// Channel, unique within the losses of one observation.
    pub channel: u32,
    /// Caller classification.
    pub kind: NeutralLossKind,
    /// Asserted magnitude.
    pub magnitude: NeutralMagnitude,
    /// Asserted unit, must equal the document unit.
    pub unit: NeutralUnit,
}

/// Raw asserted diagnostic signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeutralSignal {
    /// Channel, unique within the signals of one observation.
    pub channel: u32,
    /// Capped observed byte.
    pub observed: u8,
    /// Nonzero cap.
    pub cap: u8,
    /// Asserted unit, must be [`NeutralUnit::DiagnosticSignals`].
    pub unit: NeutralUnit,
}

/// Raw asserted claim with its reason vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeutralClaim {
    /// Claim identifier, unique within one observation.
    pub claim: u32,
    /// Distinct asserted reasons.
    pub reasons: Vec<NeutralReason>,
}

/// Raw asserted conserved partition: `total` must equal the part sum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeutralPartition {
    /// Independently supplied total.
    pub total: u64,
    /// Caller-asserted disjoint parts.
    pub parts: Vec<u64>,
    /// Asserted unit, must equal the document unit.
    pub unit: NeutralUnit,
}

/// Raw asserted single-step correction from a genesis revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeutralCorrection {
    /// Asserted current revision; must be zero in v1.
    pub from: u64,
    /// Asserted next revision; must be exactly one in v1.
    pub to: u64,
}

/// Raw v1 observation. Public fields are the exact input spec; use
/// [`validate_v1`] to check them. Cloning is caller-owned and unbounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeutralObservationV1 {
    /// Asserted source.
    pub source: NeutralSource,
    /// The single unit for counters, losses and partitions.
    pub unit: NeutralUnit,
    /// Raw counter rows.
    pub counters: Vec<NeutralCounter>,
    /// Raw loss rows.
    pub losses: Vec<NeutralLoss>,
    /// Raw signal rows.
    pub signals: Vec<NeutralSignal>,
    /// Raw claim rows.
    pub claims: Vec<NeutralClaim>,
    /// Raw partition rows.
    pub partitions: Vec<NeutralPartition>,
    /// Raw correction rows.
    pub corrections: Vec<NeutralCorrection>,
}

/// Parse a canonical u64 decimal string: `0` or a nonzero digit followed
/// by up to 19 more digits, then range-checked to `u64::MAX`. Signs,
/// leading zeros, non-digits, overlong runs and overflow refuse with
/// [`ContractError::InvalidSample`]. No float coercion exists.
pub fn parse_count_u64(text: &str) -> Result<u64, ContractError> {
    let raw = text.as_bytes();
    let n = raw.len();
    if n == 0 || n > 20 {
        return Err(ContractError::InvalidSample);
    }
    if n > 1 && raw[0] == b'0' {
        return Err(ContractError::InvalidSample);
    }
    let mut acc: u64 = 0;
    for byte in raw {
        if !byte.is_ascii_digit() {
            return Err(ContractError::InvalidSample);
        }
        let digit = u64::from(byte - b'0');
        if acc > (u64::MAX - digit) / 10 {
            return Err(ContractError::InvalidSample);
        }
        acc = acc * 10 + digit;
    }
    Ok(acc)
}

/// Parse the closed unit vocabulary.
pub fn parse_unit_name(name: &str) -> Result<NeutralUnit, ContractError> {
    match name {
        "events" => Ok(NeutralUnit::Events),
        "records" => Ok(NeutralUnit::Records),
        "bytes" => Ok(NeutralUnit::Bytes),
        "objects" => Ok(NeutralUnit::Objects),
        "attempts" => Ok(NeutralUnit::Attempts),
        "nonexecutions" => Ok(NeutralUnit::Nonexecutions),
        "diagnostic-signals" => Ok(NeutralUnit::DiagnosticSignals),
        _ => Err(ContractError::InvalidSample),
    }
}

/// Parse the closed origin vocabulary.
pub fn parse_origin_name(name: &str) -> Result<NeutralOrigin, ContractError> {
    match name {
        "adapter-reported" => Ok(NeutralOrigin::AdapterReported),
        "synthetic" => Ok(NeutralOrigin::Synthetic),
        "replayed" => Ok(NeutralOrigin::Replayed),
        _ => Err(ContractError::InvalidSample),
    }
}

/// Parse the closed loss-kind vocabulary.
pub fn parse_loss_kind(name: &str) -> Result<NeutralLossKind, ContractError> {
    match name {
        "discovery" => Ok(NeutralLossKind::Discovery),
        "transport" => Ok(NeutralLossKind::Transport),
        "kernel-nonexecution" => Ok(NeutralLossKind::KernelNonexecution),
        "attribution" => Ok(NeutralLossKind::Attribution),
        "queue-overflow" => Ok(NeutralLossKind::QueueOverflow),
        "malformed-input" => Ok(NeutralLossKind::MalformedInput),
        "diagnostic-truncation" => Ok(NeutralLossKind::DiagnosticTruncation),
        _ => Err(ContractError::InvalidSample),
    }
}

/// Parse the closed reason vocabulary.
pub fn parse_reason_name(name: &str) -> Result<NeutralReason, ContractError> {
    match name {
        "consumed-loss" => Ok(NeutralReason::ConsumedLoss),
        "missing-evidence" => Ok(NeutralReason::MissingEvidence),
        "query-partial" => Ok(NeutralReason::QueryPartial),
        "ambiguous" => Ok(NeutralReason::Ambiguous),
        "capacity" => Ok(NeutralReason::Capacity),
        _ => Err(ContractError::InvalidSample),
    }
}

/// One validated counter. Immutable SDK metadata only:
///
/// ```compile_fail
/// use scopebase_capture::neutral::ValidatedCounter;
/// fn forge(c: ValidatedCounter) -> ValidatedCounter {
///     ValidatedCounter { channel: c.channel(), value: c.value() }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCounter {
    channel: u32,
    unit: NeutralUnit,
    policy: NeutralPolicy,
    start: u64,
    end: u64,
    value: u64,
}

impl ValidatedCounter {
    /// The admitted channel.
    pub fn channel(&self) -> u32 {
        self.channel
    }
    /// The admitted unit.
    pub fn unit(&self) -> NeutralUnit {
        self.unit
    }
    /// The admitted policy.
    pub fn policy(&self) -> NeutralPolicy {
        self.policy
    }
    /// Read-window start ticks.
    pub fn start(&self) -> u64 {
        self.start
    }
    /// Read-window end ticks.
    pub fn end(&self) -> u64 {
        self.end
    }
    /// The exact observed value.
    pub fn value(&self) -> u64 {
        self.value
    }
}

/// One validated loss. Immutable SDK metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedLoss {
    channel: u32,
    kind: NeutralLossKind,
    magnitude: NeutralMagnitude,
    unit: NeutralUnit,
}

impl ValidatedLoss {
    /// The admitted channel.
    pub fn channel(&self) -> u32 {
        self.channel
    }
    /// The admitted classification.
    pub fn kind(&self) -> NeutralLossKind {
        self.kind
    }
    /// The admitted magnitude, preserving zero/unknown distinctions.
    pub fn magnitude(&self) -> NeutralMagnitude {
        self.magnitude
    }
    /// The admitted unit.
    pub fn unit(&self) -> NeutralUnit {
        self.unit
    }
}

/// One validated signal. Immutable SDK metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSignal {
    channel: u32,
    observed: u8,
    cap: u8,
}

impl ValidatedSignal {
    /// The admitted channel.
    pub fn channel(&self) -> u32 {
        self.channel
    }
    /// The capped observed byte.
    pub fn observed(&self) -> u8 {
        self.observed
    }
    /// The nonzero cap.
    pub fn cap(&self) -> u8 {
        self.cap
    }
}

/// One validated claim. Immutable SDK metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedClaim {
    claim: u32,
    reasons: Vec<NeutralReason>,
}

impl ValidatedClaim {
    /// The admitted claim.
    pub fn claim(&self) -> u32 {
        self.claim
    }
    /// The admitted distinct reasons.
    pub fn reasons(&self) -> &[NeutralReason] {
        &self.reasons
    }
}

/// A validated v1 observation. Immutable SDK metadata only:
///
/// ```compile_fail
/// use scopebase_capture::neutral::ValidatedNeutralV1;
/// fn forge(v: ValidatedNeutralV1) -> ValidatedNeutralV1 {
///     ValidatedNeutralV1 { partition_count: v.partition_count() }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedNeutralV1 {
    source: SourceRef,
    unit: NeutralUnit,
    counters: Vec<ValidatedCounter>,
    losses: Vec<ValidatedLoss>,
    signals: Vec<ValidatedSignal>,
    claims: Vec<ValidatedClaim>,
    partitions: usize,
    corrections: usize,
}

impl ValidatedNeutralV1 {
    /// The validated source, with its preserved origin.
    pub fn source(&self) -> &SourceRef {
        &self.source
    }
    /// The validated document unit.
    pub fn unit(&self) -> NeutralUnit {
        self.unit
    }
    /// The validated counters in input order.
    pub fn counters(&self) -> &[ValidatedCounter] {
        &self.counters
    }
    /// The validated losses in input order.
    pub fn losses(&self) -> &[ValidatedLoss] {
        &self.losses
    }
    /// The validated signals in input order.
    pub fn signals(&self) -> &[ValidatedSignal] {
        &self.signals
    }
    /// The validated claims in input order.
    pub fn claims(&self) -> &[ValidatedClaim] {
        &self.claims
    }
    /// The number of validated partitions.
    pub fn partition_count(&self) -> usize {
        self.partitions
    }
    /// The number of validated corrections.
    pub fn correction_count(&self) -> usize {
        self.corrections
    }
}

fn neutral_policy(policy: NeutralPolicy) -> CounterPolicy {
    match policy {
        NeutralPolicy::Monotonic => CounterPolicy::Monotonic,
        NeutralPolicy::Saturating { maximum } => CounterPolicy::Saturating { maximum },
        NeutralPolicy::Modulo { width } => CounterPolicy::Modulo { width },
    }
}

fn neutral_loss_kind(kind: NeutralLossKind) -> LossKind {
    match kind {
        NeutralLossKind::Discovery => LossKind::Discovery,
        NeutralLossKind::Transport => LossKind::Transport,
        NeutralLossKind::KernelNonexecution => LossKind::KernelNonexecution,
        NeutralLossKind::Attribution => LossKind::Attribution,
        NeutralLossKind::QueueOverflow => LossKind::QueueOverflow,
        NeutralLossKind::MalformedInput => LossKind::MalformedInput,
        NeutralLossKind::DiagnosticTruncation => LossKind::DiagnosticTruncation,
    }
}

fn check_counter<U: Unit>(
    counter: &NeutralCounter,
    source: &SourceRef,
) -> Result<ValidatedCounter, ContractError> {
    let clock = ClockDomain::new(counter.clock)?;
    let interval = TimeInterval::new(
        Timestamp::new(clock, counter.start),
        Timestamp::new(clock, counter.end),
    )?;
    let _sample = Sample::new(
        source.clone(),
        ChannelId::new(counter.channel),
        neutral_policy(counter.policy),
        interval,
        Count::<U>::new(counter.value),
    )?;
    Ok(ValidatedCounter {
        channel: counter.channel,
        unit: counter.unit,
        policy: counter.policy,
        start: counter.start,
        end: counter.end,
        value: counter.value,
    })
}

fn check_loss<U: Unit>(
    loss: &NeutralLoss,
    source: &SourceRef,
) -> Result<ValidatedLoss, ContractError> {
    let magnitude = match loss.magnitude {
        NeutralMagnitude::Exact(n) => LossMagnitude::Exact(Count::<U>::new(n)),
        NeutralMagnitude::AtLeast(n) => LossMagnitude::AtLeast(Count::<U>::new(n)),
        NeutralMagnitude::Unknown => LossMagnitude::Unknown,
    };
    let _fact = LossFact::new(
        source.clone(),
        ChannelId::new(loss.channel),
        neutral_loss_kind(loss.kind),
        magnitude,
    )?;
    Ok(ValidatedLoss {
        channel: loss.channel,
        kind: loss.kind,
        magnitude: loss.magnitude,
        unit: loss.unit,
    })
}

fn check_partition<U: Unit>(partition: &NeutralPartition) -> Result<(), ContractError> {
    let mut parts = Vec::new();
    parts
        .try_reserve_exact(partition.parts.len())
        .map_err(|_| ContractError::CapacityExceeded)?;
    for part in &partition.parts {
        parts.push(Count::<U>::new(*part));
    }
    check_conservation(Count::<U>::new(partition.total), &parts)
}

fn check_correction(epoch: &Epoch, correction: &NeutralCorrection) -> Result<(), ContractError> {
    let current = Versioned::new(epoch.clone(), ());
    let envelope = Correction::new(epoch.clone(), Revision::new(correction.from), ())?;
    let next = current.apply(envelope).map_err(|(_, refused)| refused)?;
    if next.revision() != Revision::new(correction.to) {
        return Err(ContractError::StaleRevision);
    }
    Ok(())
}

fn check_typed<U: Unit>(
    obs: &NeutralObservationV1,
    source: &SourceRef,
    counters: &mut Vec<ValidatedCounter>,
    losses: &mut Vec<ValidatedLoss>,
) -> Result<(), ContractError> {
    for counter in &obs.counters {
        counters.push(check_counter::<U>(counter, source)?);
    }
    for loss in &obs.losses {
        losses.push(check_loss::<U>(loss, source)?);
    }
    for partition in &obs.partitions {
        check_partition::<U>(partition)?;
    }
    Ok(())
}

/// Validate one v1 observation by calling the existing constructors.
///
/// Limit checks precede every clone and allocation: cardinality and hard
/// maxima refuse before source, duplicate, unit or per-item checks run,
/// and the borrowed input is never mutated. On success the returned
/// value carries immutable validated metadata only.
pub fn validate_v1(
    obs: &NeutralObservationV1,
    limits: NeutralLimits,
) -> Result<ValidatedNeutralV1, ContractError> {
    if limits.counters > NEUTRAL_MAX_COUNTERS
        || limits.claims > NEUTRAL_MAX_CLAIMS
        || limits.reasons_per_claim > NEUTRAL_MAX_REASONS_PER_CLAIM
    {
        return Err(ContractError::CapacityExceeded);
    }
    if obs.counters.len() > limits.counters || obs.claims.len() > limits.claims {
        return Err(ContractError::CapacityExceeded);
    }
    let source = SourceRef::new(
        Epoch::new(
            CaptureId::new(obs.source.capture)?,
            ProducerId::new(obs.source.producer)?,
            obs.source.ordinal,
        ),
        BindingId::new(obs.source.binding)?,
        match obs.source.origin {
            NeutralOrigin::AdapterReported => Origin::AdapterReported,
            NeutralOrigin::Synthetic => Origin::Synthetic,
            NeutralOrigin::Replayed => Origin::Replayed,
        },
    );
    for (index, counter) in obs.counters.iter().enumerate() {
        if obs.counters[..index]
            .iter()
            .any(|prior| prior.channel == counter.channel)
        {
            return Err(ContractError::DuplicateKey);
        }
    }
    for (index, loss) in obs.losses.iter().enumerate() {
        if obs.losses[..index]
            .iter()
            .any(|prior| prior.channel == loss.channel)
        {
            return Err(ContractError::DuplicateKey);
        }
    }
    for (index, signal) in obs.signals.iter().enumerate() {
        if obs.signals[..index]
            .iter()
            .any(|prior| prior.channel == signal.channel)
        {
            return Err(ContractError::DuplicateKey);
        }
    }
    for (index, claim) in obs.claims.iter().enumerate() {
        if obs.claims[..index]
            .iter()
            .any(|prior| prior.claim == claim.claim)
        {
            return Err(ContractError::DuplicateKey);
        }
        if claim.reasons.len() > limits.reasons_per_claim {
            return Err(ContractError::CapacityExceeded);
        }
        for (position, reason) in claim.reasons.iter().enumerate() {
            if claim.reasons[..position].contains(reason) {
                return Err(ContractError::DuplicateKey);
            }
        }
    }
    for counter in &obs.counters {
        if counter.unit != obs.unit {
            return Err(ContractError::DomainMismatch);
        }
    }
    for loss in &obs.losses {
        if loss.unit != obs.unit {
            return Err(ContractError::DomainMismatch);
        }
    }
    for partition in &obs.partitions {
        if partition.unit != obs.unit {
            return Err(ContractError::DomainMismatch);
        }
    }
    for signal in &obs.signals {
        if signal.unit != NeutralUnit::DiagnosticSignals {
            return Err(ContractError::DomainMismatch);
        }
    }
    let mut counters = Vec::new();
    let mut losses = Vec::new();
    {
        use crate::quantity::{
            Attempts, Bytes, DiagnosticSignals, Events, Nonexecutions, Objects, Records,
        };
        match obs.unit {
            NeutralUnit::Events => check_typed::<Events>(obs, &source, &mut counters, &mut losses)?,
            NeutralUnit::Records => {
                check_typed::<Records>(obs, &source, &mut counters, &mut losses)?;
            }
            NeutralUnit::Bytes => check_typed::<Bytes>(obs, &source, &mut counters, &mut losses)?,
            NeutralUnit::Objects => {
                check_typed::<Objects>(obs, &source, &mut counters, &mut losses)?;
            }
            NeutralUnit::Attempts => {
                check_typed::<Attempts>(obs, &source, &mut counters, &mut losses)?;
            }
            NeutralUnit::Nonexecutions => {
                check_typed::<Nonexecutions>(obs, &source, &mut counters, &mut losses)?;
            }
            NeutralUnit::DiagnosticSignals => {
                check_typed::<DiagnosticSignals>(obs, &source, &mut counters, &mut losses)?;
            }
        }
    }
    let mut signals = Vec::new();
    for signal in &obs.signals {
        let _fact = CappedLossSignal::new(
            source.clone(),
            ChannelId::new(signal.channel),
            signal.observed,
            signal.cap,
        )?;
        signals.push(ValidatedSignal {
            channel: signal.channel,
            observed: signal.observed,
            cap: signal.cap,
        });
    }
    for correction in &obs.corrections {
        check_correction(source.epoch(), correction)?;
    }
    let claims = obs
        .claims
        .iter()
        .map(|claim| ValidatedClaim {
            claim: claim.claim,
            reasons: claim.reasons.clone(),
        })
        .collect();
    Ok(ValidatedNeutralV1 {
        source,
        unit: obs.unit,
        counters,
        losses,
        signals,
        claims,
        partitions: obs.partitions.len(),
        corrections: obs.corrections.len(),
    })
}

impl fmt::Display for NeutralUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Events => "events",
            Self::Records => "records",
            Self::Bytes => "bytes",
            Self::Objects => "objects",
            Self::Attempts => "attempts",
            Self::Nonexecutions => "nonexecutions",
            Self::DiagnosticSignals => "diagnostic-signals",
        })
    }
}

impl fmt::Display for NeutralOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AdapterReported => "adapter-reported",
            Self::Synthetic => "synthetic",
            Self::Replayed => "replayed",
        })
    }
}
