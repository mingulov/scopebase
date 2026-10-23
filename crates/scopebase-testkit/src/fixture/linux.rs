// SPDX-License-Identifier: Apache-2.0
//! TT03 owned Linux fixture first increment: worker, wire codec, session
//! admission/finalizer and ported donor oracle facets.
//!
//! Binding authority: `docs/superpowers/specs/2026-10-22-scopebase-tt03-linux-fixture.md`.
//! First increment covers the ordinary-host worker core (boot Hello, ready,
//! capture_raw, set_tricky_comm, blob upload, file create/offer, close), the
//! exact public session/custody/finalizer API, and six ported donor facets.
//! Exec handover, sibling threads, descriptor inventory, TT02 prepare/collect
//! native wiring, Snapshot full-schema conformance and the strict materializer
//! are documented follow-ups, not claimed here.
mod creator;
mod driver;
mod manifest;
mod oracle;
mod phase;
mod session;
pub mod wire;

pub use driver::{
    launch_pair, CleanupProof, DrainedRecord, DriverError, DriverErrorKind, LaunchConfig,
    LivePair, ReapedExit, Scenario, ScenarioStep, ShutdownReport,
};
pub use wire::{Action, Actor};
pub use oracle::{
    exited_unreaped_owned, generation_of, gone_from_result, parse_stat_comm_state_starttime,
    stat_is_zombie, GenerationState, OracleError, TRICKY_COMM, TRICKY_COMM_HEX,
};
pub use phase::{LinuxPhaseError, LinuxProcessFixture};
pub use session::{
    LinuxFixtureAdmissionCleanupReport, LinuxFixtureAdmissionCustody,
    LinuxFixtureAdmissionFailure, LinuxFixtureFiles, LinuxFixtureSession,
    LinuxOuterCleanupAdmissionError, LinuxOuterCleanupAdmissionErrorKind,
    LinuxOuterCleanupBudget, LinuxOuterCleanupReport,
};
