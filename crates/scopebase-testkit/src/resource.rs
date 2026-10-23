// SPDX-License-Identifier: Apache-2.0
//! TT09 resource, performance and concurrent-consumer qualification core.
//!
//! NEW (no donor slice): none of the four donor projects carries a
//! cross-domain resource/performance qualification harness with per-domain
//! byte/work/memory/time bounds plus N-consumer isolation accounting, so this
//! module freezes that contract here instead of inventing a donor source.
//! Per-domain baselines are measured on the executor machine and recorded in
//! `profiles/performance-v1.json`; cells that cannot be measured there stay
//! UNBUILT with an exact reason, never fabricated.
//!
//! [`ResourceSample`] names one epoch of observed resource use with explicit
//! units; sampler failures stay failures ([`SampleError`]), never synthesized
//! samples. [`DomainBounds`] + [`check_bounds`]/[`violations`] assert the four
//! bound dimensions separately per domain: bytes (current retained + working),
//! work (cumulative attempts), memory (peak bytes) and time (caller-supplied
//! elapsed ms). A time overrun is not a byte/work/memory verdict and overlapping
//! memory metrics are never claimed additive.
//!
//! [`Ledger`] qualifies N parallel consumers sharing one accounting domain:
//! per-consumer reservation tickets with settle/charge/refund lifecycle,
//! exact reservation transfer, bounded failed-cleanup quarantine and typed
//! interference detection (foreign retirement, double charge/refund, early
//! refund). Conservation is auditable ([`LedgerAudit::is_conservative`]).
//!
//! All arithmetic is checked: overflow fails typed, never wraps silent.

use std::collections::BTreeMap;
use std::{error::Error, fmt, sync::Mutex};

// ---------------------------------------------------------------------------
// Resource samples
// ---------------------------------------------------------------------------

/// Opaque observation epoch. Units: one monotonically increasing executor
/// tick per collection round; epochs order samples, they are not timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SampleEpoch(u64);

impl SampleEpoch {
    pub fn new(epoch: u64) -> Self {
        Self(epoch)
    }
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleErrorKind {
    /// A peak counter is below its current counter: the sampler is broken.
    InconsistentPeak,
    /// The sampler could not observe (I/O, denial, missing source).
    Io,
}

#[derive(Clone, Debug)]
pub struct SampleError {
    kind: SampleErrorKind,
    detail: String,
}

impl SampleError {
    pub fn kind(&self) -> SampleErrorKind {
        self.kind
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
    pub fn io(detail: impl Into<String>) -> Self {
        Self {
            kind: SampleErrorKind::Io,
            detail: detail.into(),
        }
    }
    fn peak(detail: impl Into<String>) -> Self {
        Self {
            kind: SampleErrorKind::InconsistentPeak,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sample {:?}: {}", self.kind, self.detail)
    }
}

impl Error for SampleError {}

/// Raw sampler output. Units: counts for fds/workers/mappings/links/attempts,
/// bytes for retained/working/peak. Peaks must dominate their current counter.
#[derive(Clone, Debug, Default)]
pub struct ResourceSampleValues {
    pub epoch: u64,
    pub current_fds: u64,
    pub peak_fds: u64,
    pub current_workers: u64,
    pub peak_workers: u64,
    pub current_mappings: u64,
    pub peak_mappings: u64,
    pub current_links: u64,
    pub peak_links: u64,
    pub retained_bytes: u64,
    pub working_bytes: u64,
    pub peak_bytes: u64,
    pub attempts: u64,
}

/// One validated epoch of resource observations.
#[derive(Clone, Debug)]
pub struct ResourceSample {
    values: ResourceSampleValues,
}

impl ResourceSample {
    pub fn new(v: ResourceSampleValues) -> Result<Self, SampleError> {
        for (name, current, peak) in [
            ("fds", v.current_fds, v.peak_fds),
            ("workers", v.current_workers, v.peak_workers),
            ("mappings", v.current_mappings, v.peak_mappings),
            ("links", v.current_links, v.peak_links),
        ] {
            if peak < current {
                return Err(SampleError::peak(format!(
                    "{name} peak {peak} below current {current}"
                )));
            }
        }
        Ok(Self { values: v })
    }

    pub fn epoch(&self) -> SampleEpoch {
        SampleEpoch(self.values.epoch)
    }
    pub fn current_fds(&self) -> u64 {
        self.values.current_fds
    }
    pub fn peak_fds(&self) -> u64 {
        self.values.peak_fds
    }
    pub fn current_workers(&self) -> u64 {
        self.values.current_workers
    }
    pub fn peak_workers(&self) -> u64 {
        self.values.peak_workers
    }
    pub fn current_mappings(&self) -> u64 {
        self.values.current_mappings
    }
    pub fn peak_mappings(&self) -> u64 {
        self.values.peak_mappings
    }
    pub fn current_links(&self) -> u64 {
        self.values.current_links
    }
    pub fn peak_links(&self) -> u64 {
        self.values.peak_links
    }
    pub fn retained_bytes(&self) -> u64 {
        self.values.retained_bytes
    }
    pub fn working_bytes(&self) -> u64 {
        self.values.working_bytes
    }
    pub fn peak_bytes(&self) -> u64 {
        self.values.peak_bytes
    }
    pub fn attempts(&self) -> u64 {
        self.values.attempts
    }
}

/// Run `sampler` for `epoch` and validate its output. Sampler errors propagate
/// unchanged: a failed observation is an error, never a synthesized sample.
pub fn collect_sample(
    epoch: u64,
    sampler: impl FnOnce(u64) -> Result<ResourceSampleValues, SampleError>,
) -> Result<ResourceSample, SampleError> {
    let values = sampler(epoch)?;
    ResourceSample::new(values)
}

// ---------------------------------------------------------------------------
// Per-domain bounds
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainErrorKind {
    Empty,
    TooLong,
    InvalidChar,
}

#[derive(Clone, Debug)]
pub struct DomainError {
    kind: DomainErrorKind,
    detail: String,
}

impl DomainError {
    pub fn kind(&self) -> DomainErrorKind {
        self.kind
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "domain {:?}: {}", self.kind, self.detail)
    }
}

impl Error for DomainError {}

/// Bound-domain identity: `1..=64` chars over `[a-z0-9_.-]`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DomainId(String);

impl DomainId {
    pub fn new(name: &str) -> Result<Self, DomainError> {
        if name.is_empty() {
            return Err(DomainError {
                kind: DomainErrorKind::Empty,
                detail: "domain is empty".to_string(),
            });
        }
        if name.len() > 64 {
            return Err(DomainError {
                kind: DomainErrorKind::TooLong,
                detail: format!("domain is {} bytes, max 64", name.len()),
            });
        }
        if !name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.'
        }) {
            return Err(DomainError {
                kind: DomainErrorKind::InvalidChar,
                detail: "domain must match [a-z0-9_.-]+".to_string(),
            });
        }
        Ok(Self(name.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Independent per-domain caps. Every representable configuration is valid,
/// including zero (permits no positive use) and `u64::MAX` (finite: checked
/// arithmetic still applies). No cross-dimension relationship is implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainBounds {
    domain: DomainId,
    byte_cap: u64,
    work_cap: u64,
    memory_cap: u64,
    time_ms_cap: u64,
}

impl DomainBounds {
    pub fn new(
        domain: DomainId,
        byte_cap: u64,
        work_cap: u64,
        memory_cap: u64,
        time_ms_cap: u64,
    ) -> Self {
        Self {
            domain,
            byte_cap,
            work_cap,
            memory_cap,
            time_ms_cap,
        }
    }
    pub fn domain(&self) -> &DomainId {
        &self.domain
    }
    pub fn byte_cap(&self) -> u64 {
        self.byte_cap
    }
    pub fn work_cap(&self) -> u64 {
        self.work_cap
    }
    pub fn memory_cap(&self) -> u64 {
        self.memory_cap
    }
    pub fn time_ms_cap(&self) -> u64 {
        self.time_ms_cap
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundKind {
    Bytes,
    Work,
    Memory,
    Time,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundOverrun {
    domain: DomainId,
    kind: BoundKind,
    observed: u64,
    cap: u64,
}

impl BoundOverrun {
    pub fn domain(&self) -> &DomainId {
        &self.domain
    }
    pub fn kind(&self) -> BoundKind {
        self.kind
    }
    pub fn observed(&self) -> u64 {
        self.observed
    }
    pub fn cap(&self) -> u64 {
        self.cap
    }
}

impl fmt::Display for BoundOverrun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "domain {} overran {:?} bound: observed {} > cap {}",
            self.domain.as_str(),
            self.kind,
            self.observed,
            self.cap
        )
    }
}

impl Error for BoundOverrun {}

/// Every violated dimension, in fixed Bytes/Work/Memory/Time order. Each
/// dimension is asserted independently: a violation list names exactly the
/// dimensions whose own cap failed, so a time overrun never implies (or masks)
/// a byte/work/memory verdict.
pub fn violations(
    sample: &ResourceSample,
    bounds: &DomainBounds,
    elapsed_ms: u64,
) -> Vec<BoundOverrun> {
    let mut out = Vec::new();
    // Bytes: current retained + working with checked addition. An overflowing
    // sum is itself an overrun (the true sum exceeds every representable cap),
    // reported saturated; a wrapping add would report a small value and pass.
    match sample.retained_bytes().checked_add(sample.working_bytes()) {
        Some(current) if current <= bounds.byte_cap() => {}
        Some(current) => out.push(BoundOverrun {
            domain: bounds.domain().clone(),
            kind: BoundKind::Bytes,
            observed: current,
            cap: bounds.byte_cap(),
        }),
        None => out.push(BoundOverrun {
            domain: bounds.domain().clone(),
            kind: BoundKind::Bytes,
            observed: u64::MAX,
            cap: bounds.byte_cap(),
        }),
    }
    if sample.attempts() > bounds.work_cap() {
        out.push(BoundOverrun {
            domain: bounds.domain().clone(),
            kind: BoundKind::Work,
            observed: sample.attempts(),
            cap: bounds.work_cap(),
        });
    }
    if sample.peak_bytes() > bounds.memory_cap() {
        out.push(BoundOverrun {
            domain: bounds.domain().clone(),
            kind: BoundKind::Memory,
            observed: sample.peak_bytes(),
            cap: bounds.memory_cap(),
        });
    }
    if elapsed_ms > bounds.time_ms_cap() {
        out.push(BoundOverrun {
            domain: bounds.domain().clone(),
            kind: BoundKind::Time,
            observed: elapsed_ms,
            cap: bounds.time_ms_cap(),
        });
    }
    out
}

/// First violated dimension in Bytes/Work/Memory/Time order, or `Ok` when every
/// dimension holds. Use [`violations`] when each failing dimension matters.
pub fn check_bounds(
    sample: &ResourceSample,
    bounds: &DomainBounds,
    elapsed_ms: u64,
) -> Result<(), BoundOverrun> {
    if let Some(first) = violations(sample, bounds, elapsed_ms).into_iter().next() {
        return Err(first);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Peak tracker
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeakErrorKind {
    Overflow,
}

#[derive(Clone, Debug)]
pub struct PeakError {
    kind: PeakErrorKind,
    detail: String,
}

impl PeakError {
    pub fn kind(&self) -> PeakErrorKind {
        self.kind
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for PeakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peak {:?}: {}", self.kind, self.detail)
    }
}

impl Error for PeakError {}

/// Monotonic high-water mark with explicit transient accounting. Reallocation
/// transiently holds old + new; cloning transiently doubles. Both use checked
/// arithmetic: overflow fails typed and leaves the peak unchanged.
#[derive(Clone, Debug, Default)]
pub struct PeakTracker {
    peak: u64,
}

impl PeakTracker {
    pub fn new() -> Self {
        Self { peak: 0 }
    }
    pub fn peak(&self) -> u64 {
        self.peak
    }
    pub fn observe(&mut self, current: u64) {
        self.peak = self.peak.max(current);
    }
    pub fn realloc(&mut self, old_size: u64, new_size: u64) -> Result<(), PeakError> {
        let transient = old_size.checked_add(new_size).ok_or_else(|| PeakError {
            kind: PeakErrorKind::Overflow,
            detail: format!("realloc transient {old_size} + {new_size} overflows"),
        })?;
        self.observe(transient);
        self.observe(new_size);
        Ok(())
    }
    pub fn clone_from(&mut self, size: u64) -> Result<(), PeakError> {
        let transient = size.checked_mul(2).ok_or_else(|| PeakError {
            kind: PeakErrorKind::Overflow,
            detail: format!("clone transient 2 * {size} overflows"),
        })?;
        self.observe(transient);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Concurrent-consumer ledger
// ---------------------------------------------------------------------------

/// Admitted consumer identity. Ids are never reused, including after retire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConsumerId(u32);

impl ConsumerId {
    pub fn get(self) -> u32 {
        self.0
    }
}

/// One reservation: `bytes` held for `consumer` under ledger sequence `seq`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ticket {
    consumer: ConsumerId,
    seq: u64,
    bytes: u64,
}

impl Ticket {
    pub fn consumer(&self) -> ConsumerId {
        self.consumer
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerErrorKind {
    /// Register beyond `max_consumers`, or id/sequence exhaustion.
    ConsumerCap,
    /// Unknown or retired consumer.
    UnknownConsumer,
    /// Ticket never issued (or tombstone pruned at retire).
    UnknownTicket,
    /// Non-owner attempted refund, quarantine or retire-custody of a ticket.
    ForeignRetirement,
    /// Non-owner attempted settle, work charge or transfer of a ticket.
    ForeignTicket,
    /// Refund, quarantine or transfer before settle.
    EarlyRefund,
    /// Second refund of one ticket (no double credit).
    DoubleRefund,
    /// Second work charge against one ticket (no double debit).
    DoubleCharge,
    /// Refund/charge/quarantine/transfer of a closed ticket (refunded or
    /// quarantined) that is not a double refund.
    NotOutstanding,
    /// Retire with live (unsettled or outstanding) tickets.
    OutstandingAtRetire,
    /// Failed-cleanup quarantine would exceed its byte cap.
    QuarantineOverflow,
}

#[derive(Clone, Debug)]
pub struct LedgerError {
    kind: LedgerErrorKind,
    detail: String,
}

impl LedgerError {
    pub fn kind(&self) -> LedgerErrorKind {
        self.kind
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
    fn new(kind: LedgerErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ledger {:?}: {}", self.kind, self.detail)
    }
}

impl Error for LedgerError {}

#[derive(Clone, Debug)]
struct TicketState {
    owner: ConsumerId,
    bytes: u64,
    settled: bool,
    charged: bool,
    refunded: bool,
    quarantined: bool,
}

#[derive(Clone, Debug)]
struct ConsumerState {
    work: u64,
    retired: bool,
}

#[derive(Debug)]
struct LedgerState {
    max_consumers: u32,
    quarantine_cap: u64,
    next_consumer: u32,
    next_seq: u64,
    consumers: BTreeMap<u32, ConsumerState>,
    tickets: BTreeMap<u64, TicketState>,
    /// Refunded ticket seqs by owning consumer at refund time. Tombstones keep
    /// double refunds typed (rather than unknown) and are dropped when their
    /// consumer retires, so retention stays observable, not hidden.
    tombstones: BTreeMap<u64, u32>,
    settled_total: u64,
    refunded_total: u64,
    quarantined_total: u64,
    transferred_total: u64,
    work_total: u64,
}

fn counter_add(counter: &mut u64, amount: u64, what: &str) {
    // u64 exhaustion is unreachable in any bounded qualification run; a loud
    // panic beats silent saturation if it ever happens.
    *counter = counter.checked_add(amount).expect(what);
}

/// N-consumer reservation ledger with exact isolation accounting.
///
/// Lifecycle per ticket: `reserve` (pending) -> `settle` (outstanding) ->
/// `refund` (closed, bytes credited back) or `quarantine` (closed, bytes parked
/// in the bounded failed-cleanup quarantine). Work is charged at most once per
/// ticket ([`LedgerErrorKind::DoubleCharge`]). Settle is idempotent; every
/// other transition is once-only and owner-only. Retirement paths
/// (refund/quarantine) by a non-owner report [`LedgerErrorKind::ForeignRetirement`];
/// observation paths (settle/charge/transfer) by a non-owner report
/// [`LedgerErrorKind::ForeignTicket`]. No consumer can clean up another's
/// tickets, and failed operations leave all totals unchanged.
///
/// Locking: one mutex guards exact accounting. A poisoned mutex panics loudly
/// (poisoning implies a worker thread already panicked mid-operation, which
/// fails the run on its own); it never synthesizes accounting.
#[derive(Debug)]
pub struct Ledger {
    state: Mutex<LedgerState>,
}

impl Ledger {
    pub fn new(max_consumers: u32, quarantine_cap_bytes: u64) -> Self {
        Self {
            state: Mutex::new(LedgerState {
                max_consumers,
                quarantine_cap: quarantine_cap_bytes,
                next_consumer: 0,
                next_seq: 0,
                consumers: BTreeMap::new(),
                tickets: BTreeMap::new(),
                tombstones: BTreeMap::new(),
                settled_total: 0,
                refunded_total: 0,
                quarantined_total: 0,
                transferred_total: 0,
                work_total: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        self.state
            .lock()
            .expect("ledger mutex poisoned: a worker panicked mid-operation")
    }

    fn active_consumer(state: &LedgerState, id: ConsumerId) -> Result<(), LedgerError> {
        match state.consumers.get(&id.0) {
            Some(c) if !c.retired => Ok(()),
            _ => Err(LedgerError::new(
                LedgerErrorKind::UnknownConsumer,
                format!("consumer {} unknown or retired", id.0),
            )),
        }
    }

    /// Admit one consumer. The N+1st registration fails typed.
    pub fn register(&self) -> Result<ConsumerId, LedgerError> {
        let mut state = self.lock();
        let live = state.consumers.values().filter(|c| !c.retired).count() as u64;
        if live >= state.max_consumers as u64 {
            return Err(LedgerError::new(
                LedgerErrorKind::ConsumerCap,
                format!("{} live consumers reach cap {}", live, state.max_consumers),
            ));
        }
        let id = state.next_consumer;
        state.next_consumer = state.next_consumer.checked_add(1).ok_or_else(|| {
            LedgerError::new(LedgerErrorKind::ConsumerCap, "consumer id space exhausted")
        })?;
        state.consumers.insert(
            id,
            ConsumerState {
                work: 0,
                retired: false,
            },
        );
        Ok(ConsumerId(id))
    }

    /// Reserve `bytes` for `id`. The ticket is pending until settled.
    pub fn reserve(&self, id: ConsumerId, bytes: u64) -> Result<Ticket, LedgerError> {
        let mut state = self.lock();
        Self::active_consumer(&state, id)?;
        let seq = state.next_seq;
        state.next_seq = state.next_seq.checked_add(1).ok_or_else(|| {
            LedgerError::new(LedgerErrorKind::ConsumerCap, "ticket sequence exhausted")
        })?;
        state.tickets.insert(
            seq,
            TicketState {
                owner: id,
                bytes,
                settled: false,
                charged: false,
                refunded: false,
                quarantined: false,
            },
        );
        Ok(Ticket {
            consumer: id,
            seq,
            bytes,
        })
    }

    fn ticket_owner(state: &LedgerState, ticket: &Ticket) -> Result<ConsumerId, LedgerError> {
        match state.tickets.get(&ticket.seq) {
            Some(t) if t.bytes == ticket.bytes => Ok(t.owner),
            Some(_) => Err(LedgerError::new(
                LedgerErrorKind::UnknownTicket,
                format!("ticket {} byte mismatch: not the issued ticket", ticket.seq),
            )),
            None if state.tombstones.contains_key(&ticket.seq) => Err(LedgerError::new(
                LedgerErrorKind::UnknownTicket,
                format!("ticket {} refunded and tombstoned", ticket.seq),
            )),
            None => Err(LedgerError::new(
                LedgerErrorKind::UnknownTicket,
                format!("ticket {} never issued", ticket.seq),
            )),
        }
    }

    /// Mark a pending ticket outstanding. Idempotent: re-settling a settled
    /// ticket succeeds, since settlement is a state, not a countable event.
    pub fn settle(&self, requester: ConsumerId, ticket: &Ticket) -> Result<(), LedgerError> {
        let mut state = self.lock();
        Self::active_consumer(&state, requester)?;
        let owner = Self::ticket_owner(&state, ticket)?;
        if owner != requester {
            return Err(LedgerError::new(
                LedgerErrorKind::ForeignTicket,
                format!(
                    "consumer {} cannot settle consumer {} ticket {}",
                    requester.0, owner.0, ticket.seq
                ),
            ));
        }
        let entry = state.tickets.get_mut(&ticket.seq).expect("checked above");
        if entry.refunded || entry.quarantined {
            return Err(LedgerError::new(
                LedgerErrorKind::NotOutstanding,
                format!("ticket {} is closed", ticket.seq),
            ));
        }
        if !entry.settled {
            entry.settled = true;
            let bytes = entry.bytes;
            counter_add(
                &mut state.settled_total,
                bytes,
                "settled byte counter overflow",
            );
        }
        Ok(())
    }

    /// Charge `units` of work against a ticket, at most once per ticket.
    /// Charging is orthogonal to settlement; it is owner-only and once-only.
    pub fn charge_work(
        &self,
        requester: ConsumerId,
        ticket: &Ticket,
        units: u64,
    ) -> Result<(), LedgerError> {
        let mut state = self.lock();
        Self::active_consumer(&state, requester)?;
        let owner = Self::ticket_owner(&state, ticket)?;
        if owner != requester {
            return Err(LedgerError::new(
                LedgerErrorKind::ForeignTicket,
                format!(
                    "consumer {} cannot charge consumer {} ticket {}",
                    requester.0, owner.0, ticket.seq
                ),
            ));
        }
        let entry = state.tickets.get_mut(&ticket.seq).expect("checked above");
        if entry.refunded || entry.quarantined {
            return Err(LedgerError::new(
                LedgerErrorKind::NotOutstanding,
                format!("ticket {} is closed", ticket.seq),
            ));
        }
        if entry.charged {
            return Err(LedgerError::new(
                LedgerErrorKind::DoubleCharge,
                format!("ticket {} already charged", ticket.seq),
            ));
        }
        entry.charged = true;
        let consumer = state.consumers.get_mut(&requester.0).expect("active above");
        counter_add(
            &mut consumer.work,
            units,
            "per-consumer work counter overflow",
        );
        counter_add(&mut state.work_total, units, "total work counter overflow");
        Ok(())
    }

    /// Credit a settled ticket's bytes back. Requires the owner and a settled,
    /// open ticket; anything else fails typed with totals unchanged.
    pub fn refund(&self, requester: ConsumerId, ticket: &Ticket) -> Result<(), LedgerError> {
        let mut state = self.lock();
        Self::active_consumer(&state, requester)?;
        if state.tombstones.contains_key(&ticket.seq) {
            return Err(LedgerError::new(
                LedgerErrorKind::DoubleRefund,
                format!("ticket {} already refunded", ticket.seq),
            ));
        }
        let owner = Self::ticket_owner(&state, ticket)?;
        if owner != requester {
            return Err(LedgerError::new(
                LedgerErrorKind::ForeignRetirement,
                format!(
                    "consumer {} cannot refund consumer {} ticket {}",
                    requester.0, owner.0, ticket.seq
                ),
            ));
        }
        let entry = state.tickets.get(&ticket.seq).expect("checked above");
        if entry.quarantined {
            return Err(LedgerError::new(
                LedgerErrorKind::NotOutstanding,
                format!("ticket {} is quarantined", ticket.seq),
            ));
        }
        if !entry.settled {
            return Err(LedgerError::new(
                LedgerErrorKind::EarlyRefund,
                format!("ticket {} refunded before settle", ticket.seq),
            ));
        }
        let bytes = entry.bytes;
        state.tickets.remove(&ticket.seq);
        state.tombstones.insert(ticket.seq, owner.0);
        counter_add(
            &mut state.refunded_total,
            bytes,
            "refunded byte counter overflow",
        );
        Ok(())
    }

    /// Move one settled, open ticket from `from` to `to`, conserving bytes
    /// exactly. Only the current owner side (`from`) may initiate.
    pub fn transfer(
        &self,
        from: ConsumerId,
        to: ConsumerId,
        ticket: &Ticket,
    ) -> Result<(), LedgerError> {
        let mut state = self.lock();
        Self::active_consumer(&state, from)?;
        Self::active_consumer(&state, to)?;
        if state.tombstones.contains_key(&ticket.seq) {
            return Err(LedgerError::new(
                LedgerErrorKind::DoubleRefund,
                format!("ticket {} already refunded", ticket.seq),
            ));
        }
        let owner = Self::ticket_owner(&state, ticket)?;
        if owner != from {
            return Err(LedgerError::new(
                LedgerErrorKind::ForeignTicket,
                format!(
                    "consumer {} cannot transfer consumer {} ticket {}",
                    from.0, owner.0, ticket.seq
                ),
            ));
        }
        let entry = state.tickets.get_mut(&ticket.seq).expect("checked above");
        if entry.quarantined {
            return Err(LedgerError::new(
                LedgerErrorKind::NotOutstanding,
                format!("ticket {} is quarantined", ticket.seq),
            ));
        }
        if !entry.settled {
            return Err(LedgerError::new(
                LedgerErrorKind::EarlyRefund,
                format!("ticket {} transferred before settle", ticket.seq),
            ));
        }
        entry.owner = to;
        let bytes = entry.bytes;
        counter_add(
            &mut state.transferred_total,
            bytes,
            "transferred byte counter overflow",
        );
        Ok(())
    }

    /// Park a settled, open ticket's bytes in the bounded failed-cleanup
    /// quarantine. Quarantine overflow fails typed with all totals unchanged;
    /// there is no hidden unbounded spillover.
    pub fn quarantine(&self, requester: ConsumerId, ticket: &Ticket) -> Result<(), LedgerError> {
        let mut state = self.lock();
        Self::active_consumer(&state, requester)?;
        if state.tombstones.contains_key(&ticket.seq) {
            return Err(LedgerError::new(
                LedgerErrorKind::DoubleRefund,
                format!("ticket {} already refunded", ticket.seq),
            ));
        }
        let owner = Self::ticket_owner(&state, ticket)?;
        if owner != requester {
            return Err(LedgerError::new(
                LedgerErrorKind::ForeignRetirement,
                format!(
                    "consumer {} cannot quarantine consumer {} ticket {}",
                    requester.0, owner.0, ticket.seq
                ),
            ));
        }
        let entry = state.tickets.get(&ticket.seq).expect("checked above");
        if entry.quarantined {
            return Err(LedgerError::new(
                LedgerErrorKind::NotOutstanding,
                format!("ticket {} already quarantined", ticket.seq),
            ));
        }
        if !entry.settled {
            return Err(LedgerError::new(
                LedgerErrorKind::EarlyRefund,
                format!("ticket {} quarantined before settle", ticket.seq),
            ));
        }
        let bytes = entry.bytes;
        let next = state.quarantined_total.checked_add(bytes).ok_or_else(|| {
            LedgerError::new(
                LedgerErrorKind::QuarantineOverflow,
                "quarantine counter overflow",
            )
        })?;
        if next > state.quarantine_cap {
            return Err(LedgerError::new(
                LedgerErrorKind::QuarantineOverflow,
                format!(
                    "quarantine {} + {bytes} exceeds cap {}",
                    state.quarantined_total, state.quarantine_cap
                ),
            ));
        }
        let entry = state.tickets.get_mut(&ticket.seq).expect("checked above");
        entry.quarantined = true;
        state.quarantined_total = next;
        Ok(())
    }

    /// Retire a consumer with no live tickets. Any live (pending or
    /// outstanding) ticket blocks retirement with [`LedgerErrorKind::OutstandingAtRetire`]
    /// and no partial effect; repeat attempts fail identically. Retire drops
    /// that consumer's refund tombstones, bounding retention.
    pub fn retire_consumer(&self, id: ConsumerId) -> Result<(), LedgerError> {
        let mut state = self.lock();
        Self::active_consumer(&state, id)?;
        let live = state
            .tickets
            .values()
            .filter(|t| t.owner == id && !t.refunded && !t.quarantined)
            .count();
        if live > 0 {
            let bytes: u64 = state
                .tickets
                .values()
                .filter(|t| t.owner == id && !t.refunded && !t.quarantined)
                .map(|t| t.bytes)
                .fold(0, |a, b| a.saturating_add(b));
            return Err(LedgerError::new(
                LedgerErrorKind::OutstandingAtRetire,
                format!(
                    "consumer {} holds {live} live tickets ({bytes} bytes)",
                    id.0
                ),
            ));
        }
        let consumer = state.consumers.get_mut(&id.0).expect("active above");
        consumer.retired = true;
        state.tombstones.retain(|_, owner| *owner != id.0);
        Ok(())
    }

    /// Settled-but-open bytes currently owned by `id`.
    pub fn consumer_outstanding(&self, id: ConsumerId) -> Result<u64, LedgerError> {
        let state = self.lock();
        Self::active_consumer(&state, id)?;
        Ok(state
            .tickets
            .values()
            .filter(|t| t.owner == id && t.settled && !t.refunded && !t.quarantined)
            .map(|t| t.bytes)
            .fold(0, |a: u64, b| a.saturating_add(b)))
    }

    /// Cumulative work units charged by `id`.
    pub fn consumer_work(&self, id: ConsumerId) -> Result<u64, LedgerError> {
        let state = self.lock();
        Self::active_consumer(&state, id)?;
        Ok(state.consumers.get(&id.0).map(|c| c.work).unwrap_or(0))
    }

    pub fn quarantined_bytes(&self) -> u64 {
        self.lock().quarantined_total
    }

    /// Live ticket records plus tombstones: ledger working-set size, exposed
    /// so retention is observable rather than hidden.
    pub fn live_records(&self) -> usize {
        let state = self.lock();
        state.tickets.len() + state.tombstones.len()
    }

    /// Conservation audit folded from live ticket states plus exact counters.
    pub fn audit(&self) -> LedgerAudit {
        let state = self.lock();
        let outstanding: u64 = state
            .tickets
            .values()
            .filter(|t| t.settled && !t.refunded && !t.quarantined)
            .map(|t| t.bytes)
            .fold(0, |a: u64, b| a.saturating_add(b));
        LedgerAudit {
            settled: state.settled_total,
            refunded: state.refunded_total,
            outstanding,
            quarantined: state.quarantined_total,
            transferred: state.transferred_total,
            work_charged: state.work_total,
        }
    }
}

/// Conservation snapshot: `settled == refunded + outstanding + quarantined`
/// always holds; `transferred` is cumulative moved bytes (conserved by
/// construction, tracked separately, never double-counted).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerAudit {
    settled: u64,
    refunded: u64,
    outstanding: u64,
    quarantined: u64,
    transferred: u64,
    work_charged: u64,
}

impl LedgerAudit {
    pub fn settled(&self) -> u64 {
        self.settled
    }
    pub fn refunded(&self) -> u64 {
        self.refunded
    }
    pub fn outstanding(&self) -> u64 {
        self.outstanding
    }
    pub fn quarantined(&self) -> u64 {
        self.quarantined
    }
    pub fn transferred(&self) -> u64 {
        self.transferred
    }
    pub fn work_charged(&self) -> u64 {
        self.work_charged
    }
    pub fn is_conservative(&self) -> bool {
        self.refunded
            .checked_add(self.outstanding)
            .and_then(|s| s.checked_add(self.quarantined))
            == Some(self.settled)
    }
}
