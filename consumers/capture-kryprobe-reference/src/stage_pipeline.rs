// SPDX-License-Identifier: Apache-2.0
//! CP12 experiment-local stage pipeline (KryProbe-shaped): event records
//! flow ingest -> fold -> report against one shared count/byte budget.
//! NEW (CP12): no donor lines copied. The rules mirror the gated pilot in
//! `scopebase-capture`'s `tests/support/reservation_pilot.rs`; this module
//! exists only to run the two-consumer fit experiment and must not be
//! mistaken for a stable reservation API. Verdict lives in
//! `docs/issues/capture/reservation-evaluation.md`.
use scopebase_capture::ContractError;
use std::collections::BTreeMap;
use std::rc::Rc;

/// Pipeline stages. Location rides on the handle, as in the pilot.
pub const INGEST: u8 = 0;
/// Fold stage: per-event reduction holds the same charge.
pub const FOLD: u8 = 1;
/// Report stage: the last holder before retirement.
pub const REPORT: u8 = 2;

/// A move-only stage reservation over one real heap payload box.
#[derive(Debug)]
pub struct StageReservation {
    ticket: u64,
    count: u64,
    bytes: u64,
    stage: u8,
    payload: Rc<()>,
}

impl StageReservation {
    /// Ledger ticket this handle draws against.
    pub fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Stage currently holding this handle.
    pub fn stage(&self) -> u8 {
        self.stage
    }

    /// The count units charged for this reservation.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The bytes charged for this reservation.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Consuming move to another stage; same-stage moves refuse and return
    /// the same handle with its charge intact.
    pub fn transfer(self, stage: u8) -> Result<Self, (Self, ContractError)> {
        if stage == self.stage {
            return Err((self, ContractError::DuplicateKey));
        }
        Ok(Self { stage, ..self })
    }
}

/// One shared budget across the three KryProbe-shaped stages.
#[derive(Debug)]
pub struct StagePipeline {
    count_limit: u64,
    byte_limit: Option<u64>,
    live: BTreeMap<u64, (u64, u64)>,
    counts: u64,
    bytes: u64,
    peak: u64,
    next: u64,
}

impl StagePipeline {
    /// A fresh pipeline sharing one budget across all stages.
    pub fn new(count_limit: u64, byte_limit: Option<u64>) -> Self {
        StagePipeline {
            count_limit,
            byte_limit,
            live: BTreeMap::new(),
            counts: 0,
            bytes: 0,
            peak: 0,
            next: 0,
        }
    }

    /// Reserve count/byte charge; refusals preserve state and mint nothing.
    pub fn reserve(&mut self, count: u64, bytes: u64) -> Result<StageReservation, ContractError> {
        if count > self.count_limit.saturating_sub(self.counts) {
            return Err(ContractError::CapacityExceeded);
        }
        if self
            .byte_limit
            .is_some_and(|limit| bytes > limit.saturating_sub(self.bytes))
        {
            return Err(ContractError::CapacityExceeded);
        }
        let ticket = self
            .next
            .checked_add(1)
            .ok_or(ContractError::CapacityExceeded)?;
        self.next = ticket;
        self.live.insert(ticket, (count, bytes));
        self.counts += count;
        self.bytes += bytes;
        self.peak = self.peak.max(self.bytes);
        Ok(StageReservation {
            ticket,
            count,
            bytes,
            stage: INGEST,
            payload: Rc::new(()),
        })
    }

    /// Retire one handle; the charge releases with its last owner.
    pub fn retire(&mut self, reservation: StageReservation) {
        if Rc::strong_count(&reservation.payload) > 1 {
            drop(reservation);
            return;
        }
        let ticket = reservation.ticket;
        drop(reservation);
        if let Some((count, bytes)) = self.live.remove(&ticket) {
            self.counts -= count;
            self.bytes -= bytes;
        }
    }

    /// Currently charged counts across all stages.
    pub fn charged_counts(&self) -> u64 {
        self.counts
    }

    /// Currently charged bytes across all stages.
    pub fn charged_bytes(&self) -> u64 {
        self.bytes
    }

    /// Highest charged-byte total ever observed.
    pub fn peak_bytes(&self) -> u64 {
        self.peak
    }
}
