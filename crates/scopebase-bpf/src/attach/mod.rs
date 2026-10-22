// SPDX-License-Identifier: Apache-2.0
//! Finite attachment planning: validated sites, deterministic midpoint
//! splitting and caller error policy. Pure and host-only; the effectful
//! pool-backed executor is BP05 work.

mod plan;

pub use plan::{
    adjudicate_split, is_terminal_error, AttachBackend, AttachMode, AttachPlan, CustodyCharge,
    ErrorAction, ErrorPolicy, NativeAttach, NativeRetire, Site,
};
