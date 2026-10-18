// SPDX-License-Identifier: Apache-2.0
//! Cooperative, process-local control for synchronous operation owners.
//!
//! A checkpoint observes cancellation before the absolute monotonic deadline.
//! It cannot interrupt a blocking call. Owners record incurred work and effects
//! before checking again, preserve failed syscall errors, and retain resource
//! custody until their own cleanup protocol completes. These primitives do not
//! add control parameters to the acquisition APIs.
//!
//! ```
//! use scopebase_linux::control::{CancelToken, MonotonicDeadline, OperationControl};
//! use std::time::Duration;
//! let token = CancelToken::new();
//! let deadline = MonotonicDeadline::after(Duration::from_secs(1))?;
//! let control = OperationControl::new(Some(deadline), token.clone());
//! token.cancel();
//! # Ok::<(), scopebase_linux::error::LinuxError>(())
//! ```
use crate::error::{
    CleanupDisposition, DescriptorFlagEffect, EffectSummary, LinuxError, Reason, ResourceCharges,
    Stage,
};
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// Explicit, shared cancellation authority. Clone shares the same token.
///
/// Signaling is idempotent and irreversible. It is not a publication protocol
/// for arbitrary application data and promises no notification latency/fairness.
#[derive(Clone)]
pub struct CancelToken {
    cancelled: Arc<AtomicBool>,
}
impl CancelToken {
    /// Allocate a fresh, independent token which has not been cancelled.
    /// Allocation has ordinary allocator failure/abort limitations.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    /// Signal cancellation through every clone; dropping a clone does not reset it.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// An opaque absolute deadline in this process's `Instant` domain.
///
/// No wall-clock/kernel timestamp conversion is supported. Platform suspension
/// behavior follows `Instant`, rather than promising CLOCK_BOOTTIME semantics.
#[derive(Copy, Clone)]
pub struct MonotonicDeadline {
    at: Instant,
}
impl MonotonicDeadline {
    /// Read the monotonic clock once and add `duration` with checked arithmetic.
    /// Zero is valid and expires at equality. Overflow returns ConfigureControl /
    /// InvalidInput with no source, effects, or operational resource charges.
    pub fn after(duration: Duration) -> Result<Self, LinuxError> {
        deadline_after_at(Instant::now(), duration)
    }
}
fn deadline_after_at(start: Instant, duration: Duration) -> Result<MonotonicDeadline, LinuxError> {
    start
        .checked_add(duration)
        .map(|at| MonotonicDeadline { at })
        .ok_or_else(|| LinuxError {
            stage: Stage::ConfigureControl,
            reason: Reason::InvalidInput,
            source: None,
            effect: EffectSummary {
                attempted: 0,
                completed: 0,
                cleanup: CleanupDisposition::NotNeeded,
                flags: DescriptorFlagEffect::NotAttempted,
            },
            charges: ResourceCharges {
                syscalls: 0,
                acquired: 0,
                peak: 0,
                read: None,
            },
        })
}

/// Shared cancellation and a copied absolute deadline, without a stop latch.
///
/// Cloning never restarts the deadline. Independent invocations observe the
/// current stop reason and own their effects/custody. Collection-wide first-stop
/// policy belongs to the collection adapter. Cancellation after the final token
/// load may coexist with success; a later checkpoint observes it.
#[derive(Clone)]
pub struct OperationControl {
    deadline: Option<MonotonicDeadline>,
    cancel: CancelToken,
}
impl OperationControl {
    /// Create a fresh token and no deadline. Numeric operation limits still apply.
    pub fn unlimited() -> Self {
        Self::new(None, CancelToken::new())
    }
    /// Consume this token handle; clone it first to retain cancellation authority.
    pub fn new(deadline: Option<MonotonicDeadline>, cancel: CancelToken) -> Self {
        Self { deadline, cancel }
    }
    // Consumed by subsequent operation owners. No public checkpoint/clock seam.
    pub(crate) fn checkpoint(&self) -> Result<(), ControlStop> {
        self.checkpoint_using(Instant::now)
    }
    #[cfg(test)]
    pub(crate) fn with_test_deadline(at: Instant, cancel: CancelToken) -> Self {
        Self::new(Some(MonotonicDeadline { at }), cancel)
    }
    #[cfg(test)]
    pub(crate) fn checkpoint_at(&self, now: Instant) -> Result<(), ControlStop> {
        self.checkpoint_using(|| now)
    }
    fn checkpoint_using(&self, now: impl FnOnce() -> Instant) -> Result<(), ControlStop> {
        if self.cancel.cancelled.load(Ordering::Acquire) {
            return Err(ControlStop::Cancelled);
        }
        if self.deadline.is_some_and(|deadline| now() >= deadline.at) {
            return Err(ControlStop::Deadline);
        }
        Ok(())
    }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControlStop {
    Cancelled,
    Deadline,
}
impl ControlStop {
    // Caller transfers its actual metadata; no refund, cleanup, or Drop action.
    pub(crate) fn into_error(
        self,
        stage: Stage,
        effect: EffectSummary,
        charges: ResourceCharges,
    ) -> LinuxError {
        LinuxError {
            stage,
            reason: match self {
                Self::Cancelled => Reason::Cancelled,
                Self::Deadline => Reason::Deadline,
            },
            source: None,
            effect,
            charges,
        }
    }
}
impl fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CancelToken")
    }
}
impl fmt::Debug for MonotonicDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MonotonicDeadline")
    }
}
impl fmt::Debug for OperationControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationControl")
    }
}

#[cfg(test)]
mod tests;
