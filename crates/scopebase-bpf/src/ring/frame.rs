// SPDX-License-Identifier: Apache-2.0
//! Checked ring frame step: one header plus cursors, one decision.
//!
//! ADAPT of KryProbe `kryprobe-privilege/src/drain/frame.rs` (`frame_step`:
//! 8-byte header, BUSY stop, discard skip, torn-tail stop, top-of-range
//! handling) under the fixed-stop discipline of the p11scope
//! `aya-ring-reader.patch` (`validate_stop`: aligned cursors, power-of-two
//! capacity, bounded distance; `RecordCrossesBoundary` refusal). All
//! cursor distances are wrapping modular distances; the capacity bound
//! below half the u64 modulus keeps them unambiguous.

use crate::{ErrorKind, OperationError, Stage};

/// Record header size: length word plus kernel-internal word.
pub const HEADER_BYTES: usize = 8;
/// Cursor and record alignment.
pub const ALIGN_BYTES: u64 = 8;
/// Data-length bits of the header word; higher bits are reserved.
pub const MAX_PAYLOAD_LEN: u32 = 0x3fff_ffff;

/// Absolute consumer/producer cursors of one ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingPositions {
    pub consumer: u64,
    pub producer: u64,
}

/// One decoded record header: payload length plus commit flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub payload_len: u32,
    pub busy: bool,
    pub discard: bool,
}

/// One header word's framing decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStep {
    /// Nothing consumable now (busy writer, torn tail, empty): retry later
    /// with the consumer unchanged.
    Pending,
    /// Copy `payload_len` bytes, then advance to `next`.
    Emit { payload_len: usize, next: u64 },
    /// Advance to `next` without emitting.
    Discard { next: u64 },
    /// The consumer reached the captured stop exactly.
    ReachedBoundary,
}

/// Decide one record from its header and the ring cursors.
///
/// All cursors are absolute wrapping positions. The capacity must be a
/// power of two with `8 <= capacity < 2^63`; consumer and stop must be
/// 8-aligned; the modular stop distance must be below capacity; and the
/// modular available distance (`producer - consumer`) must not exceed
/// capacity. A stop at the consumer means [`FrameStep::ReachedBoundary`]
/// regardless of the header. A missing header refuses; a busy header is
/// [`FrameStep::Pending`]. Reserved length bits and lengths over capacity
/// are malformed. A frame crossing the stop refuses before payload access;
/// a frame overrunning the producer snapshot is a torn tail
/// ([`FrameStep::Pending`]). A stop beyond the producer snapshot yields
/// [`FrameStep::Pending`] (await producer), not refusal; see the torn-tail
/// vector (consumer 0/producer 15/stop 64). A later producer never extends
/// the captured stop. The successor cursor wraps modulo 2^64.
pub fn frame_step(
    positions: RingPositions,
    stop: u64,
    capacity: usize,
    header: Option<RecordHeader>,
) -> Result<FrameStep, OperationError> {
    let invalid = |()| OperationError::new(ErrorKind::InvalidInput, Stage::Drain, None, None);
    let capacity_u64 = capacity as u64;
    if capacity < HEADER_BYTES || !capacity.is_power_of_two() || capacity_u64 >= (1u64 << 63) {
        return Err(invalid(()));
    }
    if positions.consumer % ALIGN_BYTES != 0 || stop % ALIGN_BYTES != 0 {
        return Err(invalid(()));
    }
    let remaining = stop.wrapping_sub(positions.consumer);
    if remaining >= capacity_u64 {
        return Err(invalid(()));
    }
    let available = positions.producer.wrapping_sub(positions.consumer);
    if available > capacity_u64 {
        return Err(invalid(()));
    }
    if positions.consumer == stop {
        return Ok(FrameStep::ReachedBoundary);
    }
    let Some(header) = header else {
        return Err(invalid(()));
    };
    if header.busy {
        return Ok(FrameStep::Pending);
    }
    if header.payload_len > MAX_PAYLOAD_LEN {
        return Err(OperationError::new(
            ErrorKind::Malformed,
            Stage::Drain,
            None,
            None,
        ));
    }
    if u64::from(header.payload_len) > capacity_u64 {
        return Err(OperationError::new(
            ErrorKind::Malformed,
            Stage::Drain,
            None,
            None,
        ));
    }
    // payload_len < 2^30: 8 + 8-aligned length cannot overflow u64.
    let total = HEADER_BYTES as u64 + ((u64::from(header.payload_len) + 7) & !7);
    if total > remaining {
        return Err(OperationError::new(
            ErrorKind::Incompatible,
            Stage::Drain,
            None,
            None,
        ));
    }
    if total > available {
        return Ok(FrameStep::Pending);
    }
    let next = positions.consumer.wrapping_add(total);
    if header.discard {
        Ok(FrameStep::Discard { next })
    } else {
        Ok(FrameStep::Emit {
            payload_len: header.payload_len as usize,
            next,
        })
    }
}
