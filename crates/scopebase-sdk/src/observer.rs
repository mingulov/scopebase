// SPDX-License-Identifier: Apache-2.0
//! Independently useful owned-workload host observer (SDK04).
//!
//! NEW glue over the accepted LX02 held-file, LX03 bounded-read and LX04
//! cooperative-control surfaces; no donor lines are copied here. A
//! [`WorkloadObserver`] spawns its OWN workload via a caller-supplied
//! [`Command`] and observes only that child: every observation names the
//! owned PID, and any other PID is refused with
//! [`ObserverError::ForeignPid`] before any acquisition effect. The observer
//! never attaches to, signals, or reads on behalf of a foreign process.
//!
//! Observations are bounded twice: at most `max_observations` retained
//! records holding at most `max_retained_bytes` of file bytes, and every
//! read honors its own LX03 [`ReadLimits`] plus the caller's LX04
//! [`OperationControl`]. Each retained observation also records one bounded
//! SDK diagnostic; diagnostics never move admission.
//!
//! Shutdown is explicit: [`WorkloadObserver::shutdown`] reaps the owned
//! child -- killing it first when still running -- and reports which
//! happened. [`Drop`] is last-resort cleanup of the owned child only (kill
//! plus reap, best effort, never panicking); it never touches another
//! process.
//!
//! ```rust,no_run
//! use scopebase_linux::control::OperationControl;
//! use scopebase_sdk::limits::Limits;
//! use scopebase_sdk::observer::{ObserverLimits, WorkloadObserver};
//! use scopebase_sdk::profile::Profile;
//! use std::process::Command;
//! use std::time::Duration;
//!
//! let profile = Profile::new("sdk04-demo", Vec::new(), Vec::new()).unwrap();
//! let limits = Limits {
//!     input_bytes: 65_536,
//!     retained_bytes: 65_536,
//!     work_items: 64,
//!     live_owners: 8,
//!     diagnostic_count: 32,
//!     diagnostic_bytes: 65_536,
//!     wait: Duration::from_secs(2),
//! };
//! let observer_limits = ObserverLimits {
//!     max_observations: 16,
//!     max_retained_bytes: 8_192,
//!     read: scopebase_linux::file::ReadLimits {
//!         max_bytes: 65_536,
//!         max_read_calls: 64,
//!         max_buffer_capacity: 65_537,
//!     },
//! };
//! let mut workload = Command::new("sh");
//! workload.arg("-c").arg("printf '%s' ok > /tmp/sdk04-demo.bin");
//! let mut observer =
//!     WorkloadObserver::spawn(profile, limits, observer_limits, &mut workload).unwrap();
//! let pid = observer.pid();
//! observer.wait_for_exit(Duration::from_secs(10)).unwrap();
//! let observation = observer
//!     .observe_file(pid, "/tmp/sdk04-demo.bin".as_ref(), &OperationControl::unlimited())
//!     .unwrap();
//! assert_eq!(observation.bytes, b"ok");
//! let shutdown = observer.shutdown().unwrap();
//! assert!(shutdown.exited_cleanly());
//! ```

use std::error::Error;
use std::fmt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use scopebase_linux::control::OperationControl;
use scopebase_linux::error::LinuxError;
use scopebase_linux::file::{HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy};
use scopebase_linux::identity::StatObservation;

use crate::context::{AppContext, ContextError};
use crate::diagnostic::{Diagnostic, EffectState, Severity, Stage as DiagnosticStage};
use crate::limits::Limits;
use crate::profile::Profile;

/// Spec default: bounded operations per observer.
pub const DEFAULT_OPERATIONS: u64 = 16;
/// Spec default: fixture pattern size in bytes.
pub const DEFAULT_PATTERN_BYTES: usize = 4_096;
/// Spec default: input byte ceiling.
pub const DEFAULT_INPUT_BYTES: u64 = 65_536;
/// Spec default: retained byte ceiling.
pub const DEFAULT_RETAINED_BYTES: u64 = 8_192;
/// Spec default: live owner ceiling.
pub const DEFAULT_LIVE_OWNERS: u32 = 8;

/// Diagnostic code recorded once per retained observation.
const OBSERVE_CODE: &str = "sdk04_observe";

/// Observer-local bounds. Every field must be nonzero and `usize`
/// representable; validated in [`WorkloadObserver::spawn`] before any spawn
/// or acquisition effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserverLimits {
    /// Maximum retained observation records.
    pub max_observations: u64,
    /// Maximum retained file bytes across all observations.
    pub max_retained_bytes: u64,
    /// Per-read LX03 ceilings applied to every observation read.
    pub read: ReadLimits,
}

impl ObserverLimits {
    fn validate(&self) -> Result<(), ObserverError> {
        if self.max_observations == 0 || self.max_retained_bytes == 0 {
            return Err(ObserverError::InvalidLimits);
        }
        if usize::try_from(self.max_observations).is_err()
            || usize::try_from(self.max_retained_bytes).is_err()
        {
            return Err(ObserverError::InvalidLimits);
        }
        if self.read.max_bytes == 0
            || self.read.max_read_calls == 0
            || self.read.max_buffer_capacity == 0
        {
            return Err(ObserverError::InvalidLimits);
        }
        Ok(())
    }
}

/// Typed observer failure. Unit variants carry no caller payloads; wrapped
/// errors preserve their own evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum ObserverError {
    /// Observer bounds failed validation; nothing was spawned or acquired.
    InvalidLimits,
    /// The presented PID is not the owned workload PID; refused before any
    /// acquisition, read, or retention effect.
    ForeignPid,
    /// Observation-count or retained-byte bound exhausted; prior retained
    /// observations are unchanged.
    Capacity,
    /// The observer is shut down; the owned child is already reaped.
    ShutDown,
    /// The owned workload failed to spawn; no child exists.
    Spawn(std::io::Error),
    /// Reaping or signalling the owned child failed; custody is unresolved.
    ReapFailed,
    /// Application context construction failed.
    Context(ContextError),
    /// Held-file acquisition or bounded read failed; carries LX evidence.
    Linux(LinuxError),
}

impl fmt::Display for ObserverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObserverError::InvalidLimits => write!(f, "invalid observer limits"),
            ObserverError::ForeignPid => {
                write!(f, "refused: PID is not the owned workload")
            }
            ObserverError::Capacity => write!(f, "observer capacity exceeded"),
            ObserverError::ShutDown => write!(f, "observer is shut down"),
            ObserverError::Spawn(error) => {
                write!(f, "owned workload spawn failed: {error}")
            }
            ObserverError::ReapFailed => {
                write!(f, "owned workload reap failed")
            }
            ObserverError::Context(error) => write!(f, "observer context failed: {error}"),
            ObserverError::Linux(error) => write!(f, "observer Linux operation failed: {error}"),
        }
    }
}

impl Error for ObserverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ObserverError::Spawn(error) => Some(error),
            ObserverError::Context(error) => Some(error),
            ObserverError::Linux(error) => Some(error),
            _ => None,
        }
    }
}

/// One retained owned-workload file observation. `bytes` is a bounded copy
/// of what one LX03 read returned; before/after metadata is observation
/// evidence, never a content-snapshot proof.
#[derive(Clone)]
pub struct FileObservation {
    /// Zero-based retain order within this observer.
    pub sequence: u64,
    /// Always the owned workload PID.
    pub pid: u32,
    /// Descriptor metadata before the read.
    pub before: StatObservation,
    /// Descriptor metadata after the read.
    pub after: StatObservation,
    /// Retained file bytes, charged against `max_retained_bytes`.
    pub bytes: Vec<u8>,
    /// Charged read calls for this observation.
    pub read_calls: u64,
}

impl fmt::Debug for FileObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileObservation")
            .field("sequence", &self.sequence)
            .field("pid", &self.pid)
            .field("bytes_len", &self.bytes.len())
            .field("read_calls", &self.read_calls)
            .finish()
    }
}

/// Cooperative exit wait outcome. `Timeout` is an observation deadline, not
/// retirement: the owned child keeps running under observer custody.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum WaitOutcome {
    Exited(ExitStatus),
    Timeout,
}

impl WaitOutcome {
    /// Whether the owned child exited (and was reaped) within the wait.
    pub fn exited(&self) -> bool {
        matches!(self, WaitOutcome::Exited(_))
    }

    /// The reap status when the child exited.
    pub fn status(&self) -> Option<ExitStatus> {
        match self {
            WaitOutcome::Exited(status) => Some(*status),
            WaitOutcome::Timeout => None,
        }
    }
}

/// How shutdown disposed of the owned child. A kill is reported as a kill,
/// never as a clean exit.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ShutdownOutcome {
    /// The child had already exited; shutdown reaped it.
    Exited(ExitStatus),
    /// The child was still running; shutdown killed then reaped it.
    Killed(ExitStatus),
}

/// Bounded shutdown report. Carries counts, never retained bytes.
#[derive(Clone, Copy, Debug)]
pub struct ShutdownReport {
    /// The owned workload PID.
    pub pid: u32,
    /// How the owned child was disposed.
    pub outcome: ShutdownOutcome,
    /// Retained observations at shutdown.
    pub observations: u64,
    /// Retained file bytes at shutdown.
    pub retained_bytes: u64,
}

impl ShutdownReport {
    /// Whether the child exited on its own with a success status.
    pub fn exited_cleanly(&self) -> bool {
        match self.outcome {
            ShutdownOutcome::Exited(status) => status.success(),
            ShutdownOutcome::Killed(_) => false,
        }
    }

    /// Whether shutdown killed a still-running child before reaping it.
    pub fn was_killed(&self) -> bool {
        matches!(self.outcome, ShutdownOutcome::Killed(_))
    }

    /// The reap status of the owned child.
    pub fn status(&self) -> ExitStatus {
        match self.outcome {
            ShutdownOutcome::Exited(status) | ShutdownOutcome::Killed(status) => status,
        }
    }
}

/// Poll granularity for cooperative exit waits.
const WAIT_POLL: Duration = Duration::from_millis(1);

/// S213: classify a shutdown reap by the kill result AND the
/// status. `Killed` requires both a delivered signal and signal
/// death: a failed kill delivered nothing (ESRCH is the common
/// case — the child exited between our `try_wait` and the kill),
/// and a delivered SIGTERM that loses to `exit(0)` is still a
/// clean exit, never a kill. (`Killed(0)` is unrepresentable by
/// construction.)
fn classify_shutdown_kill(kill: std::io::Result<()>, status: ExitStatus) -> ShutdownOutcome {
    use std::os::unix::process::ExitStatusExt;
    match kill {
        Ok(()) if status.signal().is_some() => ShutdownOutcome::Killed(status),
        _ => ShutdownOutcome::Exited(status),
    }
}

/// S218: reap-failure mapping shared by every wait site
/// (`wait_for_exit`, both shutdown waits). Reachable only under OS
/// fault — a wait syscall failing on our owned live handle (ECHILD
/// after an external reap, a trapped or seccomp-denied waitpid);
/// normal exits, kills and timeouts never take this path, so no
/// deterministic live-child test can reach it.
fn map_reap_error(_: std::io::Error) -> ObserverError {
    ObserverError::ReapFailed
}

/// Owned-workload host observer. Spawn-only custody: the observer records
/// the PID of the child it spawned and refuses every other PID. Not
/// [`Clone`]: custody of one child cannot be duplicated.
#[derive(Debug)]
pub struct WorkloadObserver {
    resolver: ProcFdResolver,
    child: Option<Child>,
    pid: u32,
    last_exit: Option<ExitStatus>,
    limits: ObserverLimits,
    observations: Vec<FileObservation>,
    retained_bytes: u64,
    context: AppContext,
    shut_down: bool,
}

impl WorkloadObserver {
    /// Spawn the owned workload and build its observer. Validation order is
    /// observer bounds, then application context and limits, then the LX02
    /// resolver, and only then the spawn itself: any refusal precedes the
    /// child and leaves no process behind. The caller owns the spawn effects
    /// configured on `workload` (program, arguments, environment, stdio);
    /// the observer records only the resulting child.
    pub fn spawn(
        profile: Profile,
        limits: Limits,
        observer_limits: ObserverLimits,
        workload: &mut Command,
    ) -> Result<Self, ObserverError> {
        observer_limits.validate()?;
        let context = AppContext::new(profile, limits).map_err(ObserverError::Context)?;
        let resolver = ProcFdResolver::open_self().map_err(ObserverError::Linux)?;
        let child = workload.spawn().map_err(ObserverError::Spawn)?;
        let pid = child.id();
        Ok(WorkloadObserver {
            resolver,
            child: Some(child),
            pid,
            last_exit: None,
            limits: observer_limits,
            observations: Vec::new(),
            retained_bytes: 0,
            context,
            shut_down: false,
        })
    }

    /// The owned workload PID recorded at spawn.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Retained observation count.
    pub fn observation_count(&self) -> u64 {
        self.observations.len() as u64
    }

    /// Retained file bytes across all observations.
    pub fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Borrow the retained observations in sequence order.
    pub fn observations(&self) -> &[FileObservation] {
        &self.observations
    }

    /// Borrow the bounded application context (diagnostics, admission).
    pub fn context(&self) -> &AppContext {
        &self.context
    }

    /// Observe one owned-workload file through LX02 acquisition plus one
    /// LX03 bounded read under the caller's LX04 `control`.
    ///
    /// Refusal order is shutdown, then PID ownership, then observation-count
    /// capacity, then the Linux acquisition/read, and finally the retained
    /// byte budget before cloning: a refused observation retains nothing and
    /// leaves prior observations unchanged. A foreign PID is refused before
    /// any file effect; the observer never reads on behalf of another
    /// process. Cancellation or deadline in `control` surfaces as the
    /// underlying typed [`LinuxError`].
    pub fn observe_file(
        &mut self,
        pid: u32,
        path: &Path,
        control: &OperationControl,
    ) -> Result<&FileObservation, ObserverError> {
        if self.shut_down {
            return Err(ObserverError::ShutDown);
        }
        if pid != self.pid {
            return Err(ObserverError::ForeignPid);
        }
        if (self.observations.len() as u64) >= self.limits.max_observations {
            return Err(ObserverError::Capacity);
        }
        let held =
            HeldFile::open(path, &self.resolver, SymlinkPolicy::RejectFinal)
                .map_err(ObserverError::Linux)?;
        let read = held
            .read_all(self.limits.read, control)
            .map_err(ObserverError::Linux)?;
        let len = read.bytes().len() as u64;
        let total = self
            .retained_bytes
            .checked_add(len)
            .ok_or(ObserverError::Capacity)?;
        if total > self.limits.max_retained_bytes {
            return Err(ObserverError::Capacity);
        }
        let sequence = self.observations.len() as u64;
        let observations = read.observations();
        self.observations.push(FileObservation {
            sequence,
            pid: self.pid,
            before: observations.before(),
            after: observations.after(),
            bytes: read.bytes().to_vec(),
            read_calls: read.charges().read_calls(),
        });
        self.retained_bytes = total;
        let text = format!("obs {sequence} pid {} bytes {len}", self.pid);
        self.context.diagnostic(Diagnostic {
            code: OBSERVE_CODE,
            severity: Severity::Note,
            stage: DiagnosticStage::Observation,
            effect: EffectState::None,
            text: &text,
            path: Some(path.as_os_str().as_encoded_bytes()),
        });
        Ok(&self.observations[sequence as usize])
    }

    /// Cooperatively wait up to `timeout` for the owned child to exit,
    /// reaping it on success. Polls the owned handle only; a foreign PID
    /// can never be waited here because only the spawned handle is stored.
    /// A timeout leaves the child running under observer custody.
    pub fn wait_for_exit(&mut self, timeout: Duration) -> Result<WaitOutcome, ObserverError> {
        if self.shut_down {
            return Err(ObserverError::ShutDown);
        }
        if let Some(status) = self.last_exit {
            return Ok(WaitOutcome::Exited(status));
        }
        let child = self.child.as_mut().ok_or(ObserverError::ReapFailed)?;
        let deadline = Instant::now().checked_add(timeout);
        loop {
            match child.try_wait().map_err(map_reap_error)? {
                Some(status) => {
                    self.child = None;
                    self.last_exit = Some(status);
                    return Ok(WaitOutcome::Exited(status));
                }
                None => {
                    // S212: an overflowing deadline (`None`) saturates
                    // to "never expires" — it must not time out
                    // immediately.
                    let expired = deadline.is_some_and(|at| Instant::now() >= at);
                    if expired {
                        return Ok(WaitOutcome::Timeout);
                    }
                    std::thread::sleep(WAIT_POLL);
                }
            }
        }
    }

    /// Shut the observer down and reap the owned child exactly once. A
    /// still-running child is killed first and reported as
    /// [`ShutdownOutcome::Killed`]; an already-exited child is reaped and
    /// reported as [`ShutdownOutcome::Exited`]. A child that exits
    /// between the running check and the kill (kill finds no
    /// process) reports [`ShutdownOutcome::Exited`], never a kill —
    /// as does a delivered kill that loses to a clean exit status.
    /// Blocks until the owned child is reaped. A second shutdown is
    /// refused with [`ObserverError::ShutDown`].
    pub fn shutdown(&mut self) -> Result<ShutdownReport, ObserverError> {
        if self.shut_down {
            return Err(ObserverError::ShutDown);
        }
        let outcome = if let Some(mut child) = self.child.take() {
            match child.try_wait().map_err(map_reap_error)? {
                Some(status) => ShutdownOutcome::Exited(status),
                None => {
                    let kill = child.kill();
                    match child.wait() {
                        Ok(status) => classify_shutdown_kill(kill, status),
                        Err(e) => return Err(map_reap_error(e)),
                    }
                }
            }
        } else if let Some(status) = self.last_exit {
            ShutdownOutcome::Exited(status)
        } else {
            return Err(ObserverError::ReapFailed);
        };
        self.last_exit = Some(match outcome {
            ShutdownOutcome::Exited(status) | ShutdownOutcome::Killed(status) => status,
        });
        self.shut_down = true;
        Ok(ShutdownReport {
            pid: self.pid,
            outcome,
            observations: self.observations.len() as u64,
            retained_bytes: self.retained_bytes,
        })
    }
}

impl Drop for WorkloadObserver {
    /// Last-resort cleanup of the OWNED child only: kill plus reap, best
    /// effort. Never panics, never touches another process, and never runs
    /// twice: after [`WorkloadObserver::shutdown`] or a reaping wait there
    /// is no handle left to dispose.
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    /// S213: `Killed` requires a delivered signal AND signal
    /// death. A failed kill delivered nothing (ESRCH: the child
    /// exited first); a delivered SIGTERM losing to `exit(0)` is
    /// still clean — `Killed(0)` is unrepresentable.
    #[test]
    fn shutdown_kill_race_maps_esrch_to_exited() {
        let clean = ExitStatus::from_raw(0);
        let signaled = ExitStatus::from_raw(9);
        assert!(!signaled.success());
        // Delivered + signaled: the genuine kill.
        assert!(matches!(
            classify_shutdown_kill(Ok(()), signaled),
            ShutdownOutcome::Killed(_)
        ));
        // Delivered but exited clean anyway: not a kill.
        assert!(matches!(
            classify_shutdown_kill(Ok(()), clean),
            ShutdownOutcome::Exited(s) if s.success()
        ));
        // Failed kill + clean reap: natural exit.
        assert!(matches!(
            classify_shutdown_kill(
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "esrch")),
                clean
            ),
            ShutdownOutcome::Exited(s) if s.success()
        ));
        // Failed kill + signaled status: still not OUR kill (no
        // signal delivered — e.g. an external killer).
        assert!(matches!(
            classify_shutdown_kill(
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "esrch")),
                signaled
            ),
            ShutdownOutcome::Exited(_)
        ));
        // Other kill failures also delivered nothing.
        assert!(matches!(
            classify_shutdown_kill(
                Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "eperm")),
                clean
            ),
            ShutdownOutcome::Exited(s) if s.success()
        ));
    }

    /// S218: every wait-site OS failure maps to `ReapFailed`,
    /// whatever the errno. (The live path needs an OS fault no
    /// deterministic test can stage; this pins the shared mapping
    /// all three wait sites use.)
    #[test]
    fn wait_os_failures_map_to_reap_failed() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other,
        ] {
            assert!(matches!(
                map_reap_error(std::io::Error::new(kind, "os fault")),
                ObserverError::ReapFailed
            ));
        }
    }
}
