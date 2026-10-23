// SPDX-License-Identifier: Apache-2.0
//! CP12 gated internal pilot: one shared cross-stage reservation ledger.
//!
//! ADAPT of the p11scope shared-ledger successor (user-owned application
//! code; grant `OWNER-2026-10-23`):
//! `p11scope-ws/.worktrees/v040-integration/src/semantics_objects/journal.rs`
//! at commit `2c2713e66292b0d2688508a25f79e813ae823d81` (branch
//! `v040-h7-object-wire`, clean frozen checkout):
//! one-ledger census `:291-310`/`:329-335`, byte-fit admission `:337-341`,
//! charge order ceiling-then-replay-then-bytes with rollback `:347-360`,
//! idempotent release `:362-367`, checked monotone mint `:429-443`, and
//! reviewed-limit freeze `:465-470`. Original regression threads one
//! `StagingLedger` through begin/complete/settle at N/N+1 scale in
//! `src/s2s3_tests.rs:2943`
//! (`s2s3_bounded_state_and_redaction_policy_scale_n_and_n_plus_one`).
//! No third-party/upstream lines are copied.
//!
//! Pilot scope (NOT a stable API): [`PilotBudget`] owns the one shared
//! ledger; [`Reservation`] is a move-only handle whose `Rc` payload proves
//! aliasing and last-owner release. Stage location rides on the handle —
//! [`Reservation::transfer`] takes no ledger, exactly as the plan pins it —
//! so cross-stage custody of a shared handle is a documented evaluation
//! limit, not a proven property. Charged bytes are accounting like the
//! donor's structural bytes; each reservation additionally owns one real
//! heap payload box, never a bytes-sized buffer (a bytes-sized buffer
//! would make the count-only case unrepresentable).
#![allow(dead_code)]

use scopebase_capture::ContractError;
use std::collections::BTreeMap;
use std::rc::Rc;

/// One pipeline stage in the evaluation. Handles, not the ledger, record
/// which stage currently holds a reservation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StageId(pub u8);

/// One real heap payload box. Distinct reservations own distinct boxes;
/// [`Reservation::shared_clone`] aliases one box. The charged byte count is
/// accounting (donor: structural bytes), not the box size.
#[derive(Debug)]
struct PayloadAlloc {
    charged: u64,
}

/// A move-only reservation handle. Ownership proves single retirement: a
/// retired handle cannot be retired again because it no longer exists.
#[derive(Debug)]
pub struct Reservation {
    ticket: u64,
    count: u64,
    bytes: u64,
    stage: StageId,
    payload: Rc<PayloadAlloc>,
}

impl Reservation {
    /// The ledger ticket this handle draws against.
    pub fn ticket(&self) -> u64 {
        self.ticket
    }

    /// The stage currently holding this handle.
    pub fn stage(&self) -> StageId {
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

    /// Alias the same payload allocation: same ticket, no new charge.
    /// The ledger is untouched; the `Rc` proves the sharing.
    pub fn shared_clone(&self) -> Reservation {
        Reservation {
            ticket: self.ticket,
            count: self.count,
            bytes: self.bytes,
            stage: self.stage,
            payload: Rc::clone(&self.payload),
        }
    }

    /// Consuming move to another stage. Moving a ticket into the stage it
    /// already occupies refuses with [`ContractError::DuplicateKey`] and
    /// returns the same handle: same ticket, same charge, ledger untouched.
    pub fn transfer(self, stage: StageId) -> Result<Reservation, (Reservation, ContractError)> {
        if stage == self.stage {
            return Err((self, ContractError::DuplicateKey));
        }
        Ok(Reservation { stage, ..self })
    }
}

/// One live ledger charge: the custody record for a ticket.
#[derive(Debug)]
struct LiveCharge {
    count: u64,
    bytes: u64,
    cancelled: bool,
}

/// The one shared reservation owner for the evaluation. Single-threaded by
/// construction: no `Arc`, no `Mutex`, no `Send`/`Sync` promise.
#[derive(Debug)]
pub struct PilotBudget {
    count_limit: u64,
    byte_limit: Option<u64>,
    live: BTreeMap<u64, LiveCharge>,
    charged_counts: u64,
    charged_bytes: u64,
    peak_bytes: u64,
    next_ticket: u64,
}

impl PilotBudget {
    /// A fresh shared budget. `byte_limit = None` admits any byte size and
    /// reports no byte guarantee until a reviewed limit freezes one.
    pub fn new(count_limit: u64, byte_limit: Option<u64>) -> Result<Self, ContractError> {
        Ok(PilotBudget {
            count_limit,
            byte_limit,
            live: BTreeMap::new(),
            charged_counts: 0,
            charged_bytes: 0,
            peak_bytes: 0,
            next_ticket: 0,
        })
    }

    /// Reserve `count` units and `count`ed `bytes` against the shared pool.
    /// Admission order is count ceiling, then byte fit, then ticket mint;
    /// every refusal preserves prior state and mints no ticket. Tickets are
    /// minted monotone and never recycled, so replay is impossible by
    /// construction rather than by check.
    pub fn reserve(&mut self, count: u64, bytes: u64) -> Result<Reservation, ContractError> {
        // Ceiling first, via remaining budget: any refusal names the policy
        // limit, and an accepted addition can never overflow the running
        // total (checked_add below is unreachable-failure defense).
        if count > self.count_limit.saturating_sub(self.charged_counts) {
            return Err(ContractError::CapacityExceeded);
        }
        if self.byte_limit.is_some_and(|limit| bytes > limit.saturating_sub(self.charged_bytes)) {
            return Err(ContractError::CapacityExceeded);
        }
        let total_counts = self
            .charged_counts
            .checked_add(count)
            .ok_or(ContractError::ArithmeticOverflow)?;
        let total_bytes = self
            .charged_bytes
            .checked_add(bytes)
            .ok_or(ContractError::ArithmeticOverflow)?;
        let ticket = self.next_ticket.checked_add(1).ok_or(ContractError::CapacityExceeded)?;
        self.next_ticket = ticket;
        self.live.insert(
            ticket,
            LiveCharge {
                count,
                bytes,
                cancelled: false,
            },
        );
        self.charged_counts = total_counts;
        self.charged_bytes = total_bytes;
        self.peak_bytes = self.peak_bytes.max(total_bytes);
        Ok(Reservation {
            ticket,
            count,
            bytes,
            stage: StageId(0),
            payload: Rc::new(PayloadAlloc { charged: bytes }),
        })
    }

    /// Mark a live ticket cancelled. Cancellation is custody, not release:
    /// the charge stays until the last payload owner retires. Unknown or
    /// already-cancelled tickets mark nothing and change no total.
    pub fn cancel(&mut self, ticket: u64) -> bool {
        match self.live.get_mut(&ticket) {
            Some(charge) if !charge.cancelled => {
                charge.cancelled = true;
                true
            }
            _ => false,
        }
    }

    /// Retire one handle. The ticket charge releases only when the last
    /// payload owner retires; earlier retirements just drop their handle.
    pub fn retire(&mut self, reservation: Reservation) {
        if Rc::strong_count(&reservation.payload) > 1 {
            drop(reservation);
            return;
        }
        let ticket = reservation.ticket;
        drop(reservation);
        if let Some(charge) = self.live.remove(&ticket) {
            self.charged_counts -= charge.count;
            self.charged_bytes -= charge.bytes;
        }
    }

    /// Freeze the byte pool with a reviewed limit. Tests use it for refusal
    /// twins; it never retroactively bounds the count-only phase.
    pub fn set_byte_limit(&mut self, limit: u64) {
        self.byte_limit = Some(limit);
    }

    /// Currently charged count units across all stages.
    pub fn charged_counts(&self) -> u64 {
        self.charged_counts
    }

    /// Currently charged bytes across all stages.
    pub fn charged_bytes(&self) -> u64 {
        self.charged_bytes
    }

    /// Highest charged-byte total ever observed, including retired overlap.
    pub fn peak_bytes(&self) -> u64 {
        self.peak_bytes
    }

    /// Live tickets in the custody record.
    pub fn live_tickets(&self) -> usize {
        self.live.len()
    }

    /// The byte bound this pilot may quote, or `None` when unknown. A
    /// count-only pilot reports unknown however large its charges grow.
    pub fn byte_guarantee(&self) -> Option<u64> {
        self.byte_limit
    }
}

/// Independent oracle: enumerates live payload allocations from its own
/// call log and computes expected totals itself. It compares against the
/// pilot only in [`ReservationOracle::check`], never to derive truth.
#[derive(Debug)]
pub struct ReservationOracle {
    count_limit: u64,
    byte_limit: Option<u64>,
    live: BTreeMap<u64, OracleRecord>,
    charged_counts: u64,
    charged_bytes: u64,
    peak_bytes: u64,
    next_id: u64,
}

#[derive(Debug)]
struct OracleRecord {
    count: u64,
    bytes: u64,
}

impl ReservationOracle {
    /// A fresh oracle over the same stated limits as its pilot.
    pub fn new(count_limit: u64, byte_limit: Option<u64>) -> Self {
        ReservationOracle {
            count_limit,
            byte_limit,
            live: BTreeMap::new(),
            charged_counts: 0,
            charged_bytes: 0,
            peak_bytes: 0,
            next_id: 0,
        }
    }

    /// Mirror one accepted reservation from the test script. Admission is
    /// recomputed from the oracle's own totals; a scripted reservation the
    /// oracle itself would refuse returns `None`.
    pub fn reserve(&mut self, count: u64, bytes: u64) -> Option<u64> {
        if count > self.count_limit.saturating_sub(self.charged_counts) {
            return None;
        }
        if self.byte_limit.is_some_and(|limit| bytes > limit.saturating_sub(self.charged_bytes)) {
            return None;
        }
        let total_counts = self.charged_counts.checked_add(count)?;
        let total_bytes = self.charged_bytes.checked_add(bytes)?;
        let id = self.next_id.checked_add(1)?;
        self.next_id = id;
        self.live.insert(id, OracleRecord { count, bytes });
        self.charged_counts = total_counts;
        self.charged_bytes = total_bytes;
        self.peak_bytes = self.peak_bytes.max(total_bytes);
        Some(id)
    }

    /// Mirror one accepted stage move. The oracle records the move in its
    /// own log; stage location assertions stay on the pilot handle.
    pub fn transfer(&mut self, _id: u64, _stage: StageId) {}

    /// Mirror one cancellation. Cancellation never changes oracle totals:
    /// only retirement releases a charge.
    pub fn cancel(&mut self, _id: u64) {}

    /// Mirror one last-owner retirement, releasing the oracle's charge.
    pub fn retire(&mut self, id: u64) {
        if let Some(record) = self.live.remove(&id) {
            self.charged_counts -= record.count;
            self.charged_bytes -= record.bytes;
        }
    }

    /// The oracle's own peak, computed without reading the pilot.
    pub fn peak_bytes(&self) -> u64 {
        self.peak_bytes
    }

    /// Compare independently computed totals against the pilot. This is the
    /// only point where the oracle looks at pilot state.
    pub fn check(&self, pilot: &PilotBudget) {
        assert_eq!(
            pilot.charged_counts(),
            self.charged_counts,
            "CP12:oracle counts agree"
        );
        assert_eq!(
            pilot.charged_bytes(),
            self.charged_bytes,
            "CP12:oracle bytes agree"
        );
        assert_eq!(pilot.peak_bytes(), self.peak_bytes, "CP12:oracle peak agrees");
        assert_eq!(
            pilot.live_tickets(),
            self.live.len(),
            "CP12:oracle census agrees"
        );
    }
}
