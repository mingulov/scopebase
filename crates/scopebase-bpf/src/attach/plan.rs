// SPDX-License-Identifier: Apache-2.0
//! Neutral pure planner: site validation, production split primitive,
//! backend custody contracts and the pinned split/terminal decision model.
//!
//! ADAPT of the donor bisection discipline: p11scope
//! `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//! `bisect_attach_counted` (bounded `<= 2n-1` attempts at log-n depth,
//! permission fail-fast, halt on exhaustion/unsupported with closed-leaf
//! accounting) and osslscope `osslscope/src/plan.rs` `bisect_attach`
//! (salvage: split every non-permission failure so one poison offset
//! cannot sink good siblings). The donors differ on which failures are
//! terminal; this module stays neutral and keeps that difference in the
//! caller [`ErrorPolicy`]. Library-terminal permission/resource failures
//! ([`is_terminal_error`]) cannot split even when the policy votes to
//! isolate. No native effects occur here; BP05 owns the pool-backed
//! executor that consumes [`AttachBackend`] and [`adjudicate_split`].

use crate::{ErrorKind, Limits, OperationError, Stage};
use std::collections::HashSet;
use std::ops::Range;

/// One attach site: the offset and its cookie travel as one record so
/// parallel vectors cannot diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Site {
    pub offset: u64,
    pub cookie: u64,
}

/// Selected attach direction and arity for one plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachMode {
    EntrySingle,
    ReturnSingle,
    EntryMulti,
    ReturnMulti,
}

/// Validated nonempty site batch with unique offsets and cookies.
///
/// Duplicate offsets or cookies are refused for this first profile rather
/// than relying on backend-specific duplicate semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachPlan {
    sites: Vec<Site>,
    mode: AttachMode,
}

impl AttachPlan {
    /// Admit a site batch against explicit caps.
    ///
    /// Refuses empty batches, batches over `limits.sites`, batches whose
    /// worst-case `2n-1` split attempts exceed `limits.work_steps`, and
    /// batches with a repeated offset or cookie. The attempt reservation
    /// uses checked arithmetic: an overflowing `2n-1` refuses before any
    /// admission. Success reserves the worst case; it starts no work.
    pub fn checked(
        sites: Vec<Site>,
        mode: AttachMode,
        limits: &Limits,
    ) -> Result<Self, OperationError> {
        if sites.is_empty() {
            return Err(OperationError::new(
                ErrorKind::InvalidInput,
                Stage::Attach,
                None,
                None,
            ));
        }
        if sites.len() > limits.sites {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Attach,
                None,
                None,
            ));
        }
        let attempts = sites
            .len()
            .checked_mul(2)
            .and_then(|doubled| doubled.checked_sub(1))
            .ok_or_else(|| OperationError::new(ErrorKind::Overflow, Stage::Attach, None, None))?;
        let attempts = u64::try_from(attempts)
            .map_err(|_| OperationError::new(ErrorKind::Overflow, Stage::Attach, None, None))?;
        if attempts > limits.work_steps {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Attach,
                None,
                None,
            ));
        }
        let mut offsets = HashSet::with_capacity(sites.len());
        let mut cookies = HashSet::with_capacity(sites.len());
        for site in &sites {
            if !offsets.insert(site.offset) || !cookies.insert(site.cookie) {
                return Err(OperationError::new(
                    ErrorKind::InvalidInput,
                    Stage::Attach,
                    None,
                    None,
                ));
            }
        }
        Ok(Self { sites, mode })
    }

    /// Borrow the admitted sites in plan order.
    pub fn sites(&self) -> &[Site] {
        &self.sites
    }

    /// Return the selected attach mode for this plan.
    pub fn mode(&self) -> AttachMode {
        self.mode
    }

    /// Split a site range into deterministic disjoint halves.
    ///
    /// The batch must be a nonempty in-bounds range of this plan. A
    /// singleton returns `None` (it cannot split); anything else returns
    /// the left/right halves divided at `start + len/2`, which stay
    /// disjoint and cover the original exactly. Empty, reversed and
    /// out-of-bounds ranges refuse. Pure: no backend is consulted.
    pub fn split_sites(
        &self,
        batch: Range<usize>,
    ) -> Result<Option<(Range<usize>, Range<usize>)>, OperationError> {
        if batch.start >= batch.end || batch.end > self.sites.len() {
            return Err(OperationError::new(
                ErrorKind::InvalidInput,
                Stage::Attach,
                None,
                None,
            ));
        }
        let len = batch.end - batch.start;
        if len == 1 {
            return Ok(None);
        }
        let mid = batch.start + len / 2;
        Ok(Some((batch.start..mid, mid..batch.end)))
    }
}

/// Caller vote on a failed attach node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorAction {
    /// Split an isolatable multi-site failure and keep salvaging siblings.
    IsolateSites,
    /// Stop splitting; the executor rolls back and reports the failure.
    AbortAndRollback,
}

/// Caller error policy: preserves the donor difference between salvage
/// (split isolatable failures, osslscope) and fail-fast (abort, p11scope
/// permission path) handling. Called once per failed node; the library
/// terminal rules in [`adjudicate_split`] may override the vote.
pub trait ErrorPolicy {
    fn classify(&mut self, error: &OperationError, batch_len: usize) -> ErrorAction;
}

/// Native retirement outcome for one link or uncertain acquisition.
#[derive(Debug)]
pub enum NativeRetire {
    Retired,
    Pending,
    Failed(OperationError),
}

/// Native attach outcome: an owned link, a proven no-effect failure, or an
/// uncertain acquisition whose custody travels with the result. There is
/// no ownerless error branch: ambiguous effects always carry recovery
/// ownership.
#[derive(Debug)]
pub enum NativeAttach<L, U> {
    Attached(L),
    NoEffect(OperationError),
    Uncertain { custody: U, cause: OperationError },
}

/// Audited upper bound for one plan: admitted native link/uncertain slots
/// and library-owned host custody bytes. Pre-existing caller-owned
/// program/map allocation is identified separately, never through these
/// two counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyCharge {
    pub link_slots: usize,
    pub retained_bytes: usize,
}

/// Backend contract for the BP05 executor.
///
/// # Safety
///
/// False no-effect, custody-charge or retirement statements can discard
/// kernel-active resources or exceed the declared resource bound:
/// - `custody_charge` returns an audited upper bound for one entire plan,
///   including backend/authority/program references, all split leaves and
///   one terminal uncertain attempt. It is never a caller estimate.
/// - `attach` returns `NoEffect` only when it proves no surviving native
///   effect and no retained asynchronous operation; unknown errno without
///   effect proof cannot become `NoEffect`.
/// - Ambiguous acquisitions return `Uncertain` with recoverable custody;
///   `retire_uncertain` reconciles every partial link and returns
///   `Retired` only after confirming no surviving effects.
/// - `retire` reports the true native outcome; only confirmed retirement
///   releases custody.
#[allow(unsafe_code)]
pub unsafe trait AttachBackend {
    type Authority;
    type Link;
    type Uncertain;

    fn custody_charge(
        &self,
        authority: &Self::Authority,
        sites: &[Site],
    ) -> Result<CustodyCharge, OperationError>;

    fn attach(
        &mut self,
        authority: &Self::Authority,
        sites: &[Site],
        mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain>;

    fn retire(&mut self, link: &mut Self::Link) -> NativeRetire;

    fn retire_uncertain(&mut self, custody: &mut Self::Uncertain) -> NativeRetire;
}

/// Library-terminal failures: permission denial and resource exhaustion.
///
/// Classified by [`ErrorKind`] only, never by errno: a [`ErrorKind::Backend`]
/// error carrying EPERM/EACCES (for example a verifier or license refusal)
/// is policy-decided, not terminal.
pub fn is_terminal_error(error: &OperationError) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Denied | ErrorKind::LimitExceeded | ErrorKind::Overflow
    )
}

/// Pin the decision model: attempt each node once, split only
/// side-effect-free isolatable multi nodes.
///
/// The caller policy is consulted exactly once per failed node; then
/// library-terminal errors and batches shorter than two sites are forced
/// to [`ErrorAction::AbortAndRollback`]. Singleton refusal, uncertain
/// native outcomes and terminal denial therefore roll back the eventual
/// effectful operation in BP05.
pub fn adjudicate_split<P: ErrorPolicy>(
    policy: &mut P,
    error: &OperationError,
    batch_len: usize,
) -> ErrorAction {
    let vote = policy.classify(error, batch_len);
    if batch_len < 2 || is_terminal_error(error) {
        ErrorAction::AbortAndRollback
    } else {
        vote
    }
}
