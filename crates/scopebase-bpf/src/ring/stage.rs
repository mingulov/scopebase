// SPDX-License-Identifier: Apache-2.0
//! Owned single-slot staging with conservation accounting.
//!
//! ADAPT of the libbpf-mojo staging semantics (`src/libbpf_mojo/buffer.mojo`
//! `BufferStats { received, delivered, staged, malformed, dropped }` and the
//! `tests/native/ring_conformance.c` short/single/mutation vectors): borrowed
//! callback bytes are copied into one owned bounded slot, short destinations
//! keep the record across retries, and the counters conserve every record.
//! `held` is the current slot occupancy (0 or 1); all other counters are
//! cumulative per staging period.

use crate::{ErrorKind, OperationError, Stage};
use std::cell::Cell;
use std::marker::PhantomData;

/// Staged-frame envelope version, stored little-endian after the length.
pub const STAGE_FRAMING_VERSION: u32 = 1;
/// Staged-frame header: payload length plus framing version.
pub const STAGE_HEADER_BYTES: usize = 8;

/// Transport counters for one staging slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageStats {
    pub received: u64,
    pub delivered: u64,
    pub held: u64,
    pub malformed: u64,
    pub dropped: u64,
}

impl StageStats {
    /// Per-period conservation: every received record is delivered, held,
    /// malformed or dropped, computed with checked arithmetic.
    pub fn balanced(&self) -> bool {
        self.delivered
            .checked_add(self.held)
            .and_then(|sum| sum.checked_add(self.malformed))
            .and_then(|sum| sum.checked_add(self.dropped))
            == Some(self.received)
    }
}

/// One owned bounded staging slot; sole-owner and `!Sync`.
#[derive(Debug)]
pub struct StagedRecord {
    max_record_bytes: usize,
    slot: Vec<u8>,
    stats: StageStats,
    _sole_owner: PhantomData<Cell<()>>,
}

impl StagedRecord {
    /// Create an empty slot admitting payloads up to `max_record_bytes`.
    ///
    /// A zero bound admits nothing and refuses. Allocation is lazy: the
    /// bound is stored, and offers reserve exactly the framed record.
    pub fn new(max_record_bytes: usize) -> Result<Self, OperationError> {
        if max_record_bytes == 0 {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Drain,
                None,
                None,
            ));
        }
        Ok(Self {
            max_record_bytes,
            slot: Vec::new(),
            stats: StageStats {
                received: 0,
                delivered: 0,
                held: 0,
                malformed: 0,
                dropped: 0,
            },
            _sole_owner: PhantomData,
        })
    }

    /// Copy borrowed source bytes into the owned slot.
    ///
    /// Empty and over-bound records reject as malformed (counted, with the
    /// payload length reported for oversize). An occupied slot drops the
    /// newly offered record and preserves the previous bytes. Allocation
    /// failure refuses before staging without touching the counters.
    pub fn offer(&mut self, source: &[u8]) -> Result<(), OperationError> {
        if source.is_empty()
            || source.len() > self.max_record_bytes
            || source.len() > u32::MAX as usize
        {
            self.stats.received = bump(self.stats.received)?;
            self.stats.malformed = bump(self.stats.malformed)?;
            let mut err = OperationError::new(ErrorKind::Malformed, Stage::Drain, None, None);
            if !source.is_empty() {
                err = err.with_required_size(source.len());
            }
            return Err(err);
        }
        if !self.slot.is_empty() {
            self.stats.received = bump(self.stats.received)?;
            self.stats.dropped = bump(self.stats.dropped)?;
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Drain,
                None,
                None,
            ));
        }
        let mut framed = Vec::new();
        framed
            .try_reserve_exact(STAGE_HEADER_BYTES + source.len())
            .map_err(|_| {
                OperationError::new(ErrorKind::LimitExceeded, Stage::Drain, None, None)
                    .with_required_size(STAGE_HEADER_BYTES + source.len())
            })?;
        framed.extend_from_slice(&(source.len() as u32).to_le_bytes());
        framed.extend_from_slice(&STAGE_FRAMING_VERSION.to_le_bytes());
        framed.extend_from_slice(source);
        // Bump before store: counter exhaustion refuses with the slot and
        // every counter untouched, never a stored record with stale stats.
        let received = bump(self.stats.received)?;
        self.slot = framed;
        self.stats.received = received;
        self.stats.held = 1;
        Ok(())
    }

    /// Copy the held framed record into the destination.
    ///
    /// An empty slot copies zero bytes. A short destination refuses with
    /// the framed length required, leaves the destination completely
    /// unchanged and retains the record for retries. A sufficient
    /// destination receives exactly one frame and consumes the slot.
    pub fn copy_into(&mut self, destination: &mut [u8]) -> Result<usize, OperationError> {
        if self.slot.is_empty() {
            return Ok(0);
        }
        if destination.len() < self.slot.len() {
            return Err(
                OperationError::new(ErrorKind::LimitExceeded, Stage::Drain, None, None)
                    .with_required_size(self.slot.len()),
            );
        }
        destination[..self.slot.len()].copy_from_slice(&self.slot);
        let delivered = self.slot.len();
        self.slot.clear();
        self.stats.delivered = bump(self.stats.delivered)?;
        self.stats.held = 0;
        Ok(delivered)
    }

    /// Borrow the current transport counters.
    pub fn stats(&self) -> &StageStats {
        &self.stats
    }
}

fn bump(counter: u64) -> Result<u64, OperationError> {
    counter
        .checked_add(1)
        .ok_or_else(|| OperationError::new(ErrorKind::Overflow, Stage::Drain, None, None))
}
