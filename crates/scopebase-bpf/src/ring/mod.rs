// SPDX-License-Identifier: Apache-2.0
//! Bounded ring consumption: checked frame arithmetic, fixed-boundary
//! source contract and one owned staging slot. Pure and host-only; no
//! raw mmap reader lives here.

mod bounded;
mod frame;
mod stage;

pub use bounded::{BoundaryState, BoundedRingSource, DrainBudget, DrainResult};
pub use frame::{frame_step, FrameStep, RecordHeader, RingPositions};
pub use stage::{StageStats, StagedRecord, STAGE_FRAMING_VERSION};
