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
// S78-round4: under the seccomp-only feature the linux surface is
// just `seccomp` (libc-only, no scopebase-linux edge); everything
// else stays behind `linux-fixtures`.
#[cfg(feature = "linux-fixtures")]
pub mod audit;
#[cfg(feature = "linux-fixtures")]
mod creator;
#[cfg(feature = "linux-fixtures")]
mod driver;
#[cfg(feature = "linux-fixtures")]
pub(crate) mod fork;
#[cfg(feature = "linux-fixtures")]
mod manifest;
#[cfg(feature = "linux-fixtures")]
mod oracle;
#[cfg(feature = "linux-fixtures")]
mod phase;
pub mod seccomp;
#[cfg(feature = "linux-fixtures")]
mod session;
#[cfg(feature = "linux-fixtures")]
pub mod target;
#[cfg(feature = "linux-fixtures")]
pub mod wire;

#[cfg(feature = "linux-fixtures")]
pub use driver::{
    launch_pair, CleanupProof, DeadlineHoldReport, DrainedRecord, DriverError, DriverErrorKind,
    InventoryRecord, LaunchConfig, LivePair, ReapedExit, Scenario, ScenarioStep, ShutdownReport,
};
#[cfg(feature = "linux-fixtures")]
pub use manifest::{control_pairing_applies, Control};
#[cfg(feature = "linux-fixtures")]
pub use oracle::{
    clean_shutdown_gate, exited_unreaped_owned, generation_of, gone_from_result,
    parse_stat_comm_state_starttime, stat_is_zombie, verify_retirement_exactly_once,
    verify_unknown_sticky, CustodyClaim, GenerationState, OracleError, TRICKY_COMM,
    TRICKY_COMM_HEX,
};
#[cfg(feature = "linux-fixtures")]
pub use phase::{LinuxPhaseError, LinuxProcessFixture};
#[cfg(feature = "linux-fixtures")]
pub use session::{
    LinuxFixtureAdmissionCleanupReport, LinuxFixtureAdmissionCustody, LinuxFixtureAdmissionFailure,
    LinuxFixtureFiles, LinuxFixtureSession, LinuxOuterCleanupAdmissionError,
    LinuxOuterCleanupAdmissionErrorKind, LinuxOuterCleanupBudget, LinuxOuterCleanupReport,
};
#[cfg(feature = "linux-fixtures")]
pub use wire::{Action, Actor};
