// SPDX-License-Identifier: Apache-2.0
//! Fixed-boundary drain contract: budgets, boundary states, source trait.
//!
//! The [`BoundedRingSource`] contract mirrors the adapted
//! `aya-ring-reader.patch` reader shape (`snapshot_positions` plus a
//! stop-bounded read) without any mapping: native adapters implement this
//! trait in BP10, and the test suite drives it through scripted sources.
//! Bounded results never contain quiescence or settlement claims.

use crate::ring::RingPositions;
use crate::OperationError;

/// Per-drain consumption caps. Records (emitted or discarded) charge one
/// record unit and their full header-plus-aligned-payload bytes; a record
/// that does not fit the remaining budget stays unconsumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainBudget {
    pub max_records: usize,
    pub max_bytes: usize,
}

/// Why a bounded drain stopped. `Reached` means only that the captured
/// boundary was consumed; it makes no closure or settlement statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryState {
    Reached,
    Pending,
    BudgetExhausted,
}

/// One bounded drain's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainResult {
    pub boundary: BoundaryState,
    pub records: usize,
    pub bytes: usize,
    pub discarded: usize,
}

/// Sole-consumer source drained up to a fixed producer boundary.
///
/// The trait is non-cloneable with exclusive `&mut self` operations: one
/// source has exactly one reader, and a snapshot's `stop` is valid only
/// for the source that produced it while it remains the sole reader.
/// `consume_before` consumes records with cursors strictly before `stop`,
/// honoring `budget`; a later producer never extends the captured stop.
/// Discards advance exactly once and charge both budgets. Errors preserve
/// already-consumed tails: consumed records stay consumed.
pub trait BoundedRingSource {
    /// Snapshot the owned consumer cursor, a fresh producer cursor and the
    /// ring capacity's owning positions.
    fn snapshot(&mut self) -> Result<RingPositions, OperationError>;
    /// Consume records before `stop`, visiting each emitted payload.
    fn consume_before(
        &mut self,
        stop: u64,
        budget: DrainBudget,
        visit: &mut dyn FnMut(&[u8]),
    ) -> Result<DrainResult, OperationError>;
}
