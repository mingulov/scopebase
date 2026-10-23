// SPDX-License-Identifier: Apache-2.0
//! CP12 experiment-local stage pipeline (MemVeil-shaped): observations flow
//! observe -> view under pool pressure; shared views alias one payload,
//! independent copies charge anew, and cancellation retains the charge
//! until the last owner retires. NEW (CP12): no donor lines copied. The
//! rules mirror the gated pilot in `scopebase-capture`'s
//! `tests/support/reservation_pilot.rs`; this module exists only to run the
//! two-consumer fit experiment and must not be mistaken for a stable
//! reservation API. Verdict lives in
//! `docs/issues/capture/reservation-evaluation.md`.
use scopebase_capture::ContractError;
use std::collections::BTreeMap;
use std::rc::Rc;

/// Observe stage: admission charges the shared pool.
pub const OBSERVE: u8 = 0;
/// View stage: shared or independent holders of one observation.
pub const VIEW: u8 = 1;

/// A move-only observation handle over one real heap payload box.
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

    /// Alias the same payload allocation without a new charge.
    pub fn shared_clone(&self) -> StageReservation {
        StageReservation {
            ticket: self.ticket,
            count: self.count,
            bytes: self.bytes,
            stage: self.stage,
            payload: Rc::clone(&self.payload),
        }
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

/// One shared pool across the MemVeil-shaped observe/view stages.
#[derive(Debug)]
pub struct StagePipeline {
    count_limit: u64,
    byte_limit: Option<u64>,
    live: BTreeMap<u64, (u64, u64, bool)>,
    counts: u64,
    bytes: u64,
    next: u64,
}

impl StagePipeline {
    /// A fresh pool sharing one budget across both stages.
    pub fn new(count_limit: u64, byte_limit: Option<u64>) -> Self {
        StagePipeline {
            count_limit,
            byte_limit,
            live: BTreeMap::new(),
            counts: 0,
            bytes: 0,
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
        self.live.insert(ticket, (count, bytes, false));
        self.counts += count;
        self.bytes += bytes;
        Ok(StageReservation {
            ticket,
            count,
            bytes,
            stage: OBSERVE,
            payload: Rc::new(()),
        })
    }

    /// Mark a live ticket cancelled without releasing its charge.
    pub fn cancel(&mut self, ticket: u64) -> bool {
        match self.live.get_mut(&ticket) {
            Some(entry) if !entry.2 => {
                entry.2 = true;
                true
            }
            _ => false,
        }
    }

    /// Retire one handle; the charge releases with its last owner.
    pub fn retire(&mut self, reservation: StageReservation) {
        if Rc::strong_count(&reservation.payload) > 1 {
            drop(reservation);
            return;
        }
        let ticket = reservation.ticket;
        drop(reservation);
        if let Some((count, bytes, _)) = self.live.remove(&ticket) {
            self.counts -= count;
            self.bytes -= bytes;
        }
    }

    /// Currently charged counts across both stages.
    pub fn charged_counts(&self) -> u64 {
        self.counts
    }

    /// Currently charged bytes across both stages.
    pub fn charged_bytes(&self) -> u64 {
        self.bytes
    }

    /// Live tickets in the custody record.
    pub fn live_tickets(&self) -> usize {
        self.live.len()
    }

    /// The byte bound this pool may quote, or `None` when unknown.
    pub fn byte_guarantee(&self) -> Option<u64> {
        self.byte_limit
    }
}
