// SPDX-License-Identifier: Apache-2.0
//! Finite attachment planning, pool-backed effectful execution and
//! explicit retirement. The pure planner validates sites and splits
//! ranges; the executor owns every backend, authority, link and
//! uncertain acquisition in a caller-owned persistent pool from before
//! the first effect until positive retirement.

mod execute;
mod plan;
mod pool;
mod retire;

pub use execute::execute_plan;
pub use plan::{
    adjudicate_split, is_terminal_error, AttachBackend, AttachMode, AttachPlan, CustodyCharge,
    ErrorAction, ErrorPolicy, NativeAttach, NativeRetire, Site,
};
pub use pool::{
    PoolClose, PoolReconcile, PoolUsage, RetirementBudget, RetirementCapacity, RetirementPool,
};
pub use retire::{AttachOutcome, AttachSummary, AttachmentSet, Retirement, UnresolvedAttachments};
