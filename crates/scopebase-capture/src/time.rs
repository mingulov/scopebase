// SPDX-License-Identifier: Apache-2.0
//! Explicit caller-clock nanoseconds and checked half-open intervals.
// ADAPT invariant: KryProbe d153f3a workload/evidence.rs:85–125. Its intervals
// are inclusive and defer reversal refusal to evidence validation; these do not.
use crate::{domain::ClockDomain, ContractError};

/// Nanoseconds supplied by the caller in its named clock domain.
/// No physical clock, conversion, suspend policy or time namespace is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    clock: ClockDomain,
    ticks: u64,
}
impl Timestamp {
    /// Retain the caller's nanoseconds, including zero and `u64::MAX`.
    pub fn new(clock: ClockDomain, ticks: u64) -> Self {
        Self { clock, ticks }
    }
    /// The caller's clock domain.
    pub fn clock(&self) -> ClockDomain {
        self.clock
    }
    /// The exact nanoseconds supplied.
    pub fn ticks(&self) -> u64 {
        self.ticks
    }
}
/// A half-open `[start, end)` interval. Equal endpoints have zero duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeInterval {
    start: Timestamp,
    end: Timestamp,
}
impl TimeInterval {
    /// Refuse clock mismatch before checking endpoint order.
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, ContractError> {
        if start.clock != end.clock {
            return Err(ContractError::DomainMismatch);
        }
        if end.ticks < start.ticks {
            return Err(ContractError::InvalidInterval);
        }
        Ok(Self { start, end })
    }
    /// Exact duration in the caller's nanoseconds; construction proved subtraction safe.
    pub fn duration_ns(&self) -> u64 {
        self.end.ticks - self.start.ticks
    }
    /// The retained start, inclusive.
    pub fn start(&self) -> &Timestamp {
        &self.start
    }
    /// The retained end, exclusive.
    pub fn end(&self) -> &Timestamp {
        &self.end
    }
}

// CP08 sweep section. ADAPT: MemVeil fix 6ea5ffc via
// tests/unit/test_mappings.mojo:302-501 (release-before-acquire
// half-open ties, explicit ordering proof for peak, per-generation
// durations independent of sweep refusal). MappingTracker and
// _note_peak_order are concept references only: this section proves
// submitted order and exports no metric reducer.
/// A state edge kind in a submitted sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Release,
    Acquire,
}
/// One submitted state edge: a timestamp, kind and sweep-unique event ID.
///
/// The ID is unique within the submitted sweep. It is not a
/// generation-local ordinal or a universal object identity; the adapter
/// maps each source `(ObjectKey, generation-local ordinal)` injectively
/// and stably to these IDs and never passes a local ordinal directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateEdge {
    at: Timestamp,
    kind: EdgeKind,
    sweep_event_id: u64,
}
impl StateEdge {
    /// Retain the submitted edge without validating order or uniqueness.
    pub fn new(at: Timestamp, kind: EdgeKind, sweep_event_id: u64) -> Self {
        Self { at, kind, sweep_event_id }
    }
}
/// Proof that a submitted sweep was ordered in one clock domain.
///
/// Ordering only: not a peak, occupancy, activity or causal claim.
/// Empty input yields a valid empty proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepProof {
    clock: Option<ClockDomain>,
    edges: usize,
}
/// Validate one submitted sweep without reordering or sorting it.
///
/// Requires one clock domain (`DomainMismatch`), sweep-unique event
/// IDs (`DuplicateKey`), nondecreasing timestamps and Release before
/// Acquire at ties (`InvalidInterval`). O(n log n) work, O(n) extra
/// storage for the duplicate set; refusals change no caller state.
pub fn validate_sweep_order(edges: &[StateEdge]) -> Result<SweepProof, ContractError> {
    if let Some(first) = edges.first() {
        for edge in &edges[1..] {
            if edge.at.clock() != first.at.clock() {
                return Err(ContractError::DomainMismatch);
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for edge in edges {
        if !seen.insert(edge.sweep_event_id) {
            return Err(ContractError::DuplicateKey);
        }
    }
    for pair in edges.windows(2) {
        let (prior, next) = (&pair[0], &pair[1]);
        if next.at.ticks() < prior.at.ticks() {
            return Err(ContractError::InvalidInterval);
        }
        if next.at.ticks() == prior.at.ticks()
            && prior.kind == EdgeKind::Acquire
            && next.kind == EdgeKind::Release
        {
            return Err(ContractError::InvalidInterval);
        }
    }
    Ok(SweepProof {
        clock: edges.first().map(|edge| edge.at.clock()),
        edges: edges.len(),
    })
}
