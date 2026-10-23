// SPDX-License-Identifier: Apache-2.0
//! TT03 owned Linux fixture first increment: worker, wire codec, session
//! admission/finalizer and ported donor oracle facets.
//!
//! Binding authority: `docs/superpowers/specs/2026-10-22-scopebase-tt03-linux-fixture.md`.
//! Covers the ordinary-host worker core (boot/resume Hello, ready,
//! capture_raw, set_tricky_comm, blob upload, file create/offer, close, real
//! exec round-trip/failure/nonleader exec, real sibling spawn plus
//! leader-only exit with handover), the exact public
//! session/custody/finalizer API with native TT02 prepare/collect wiring,
//! third-slot descriptor inventory, the runner-deadline hold and worker-death
//! outage injection (real mid-protocol death, orphaned retirement with
//! retained evidence, partial-file detection), plus ported donor facets.
//! Snapshot full-schema conformance, F rows, the strict materializer and
//! final-index joint compatibility are documented follow-ups, not claimed
//! here.
pub mod audit;
mod creator;
mod driver;
pub(crate) mod fork;
mod manifest;
mod oracle;
mod phase;
pub mod seccomp;
mod session;
pub mod target;
pub mod wire;

pub use driver::{
    launch_pair, CleanupProof, DeadlineHoldReport, DrainedRecord, DriverError, DriverErrorKind,
    InventoryRecord, LaunchConfig, LivePair, ReapedExit, Scenario, ScenarioStep, ShutdownReport,
};
pub use manifest::{control_pairing_applies, Control};
pub use wire::{Action, Actor};
pub use oracle::{
    clean_shutdown_gate, exited_unreaped_owned, generation_of, gone_from_result,
    parse_stat_comm_state_starttime, stat_is_zombie, verify_retirement_exactly_once,
    verify_unknown_sticky, CustodyClaim, GenerationState, OracleError, TRICKY_COMM,
    TRICKY_COMM_HEX,
};
pub use phase::{LinuxPhaseError, LinuxProcessFixture};
pub use session::{
    LinuxFixtureAdmissionCleanupReport, LinuxFixtureAdmissionCustody,
    LinuxFixtureAdmissionFailure, LinuxFixtureFiles, LinuxFixtureSession,
    LinuxOuterCleanupAdmissionError, LinuxOuterCleanupAdmissionErrorKind,
    LinuxOuterCleanupBudget, LinuxOuterCleanupReport,
};
