// SPDX-License-Identifier: Apache-2.0
//! TC02: persistent compiler executor with output-root leases.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree; whole
//! user-authored files):
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/run.py`
//! (lines 27-36: lock files opened `O_CLOEXEC | O_NOFOLLOW` and taken
//! `LOCK_EX | LOCK_NB`, released by close; lines 56-57: whole-matrix
//! wall-clock budget; lines 59-78: nonzero returncode gates admission,
//! only `returncode == 0` plus positive evidence passes) and
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py`
//! (lines 127-132: exit-zero gate before object extraction and hashing).
//! ADAPT to Rust: exclusive output-root leases with held identity,
//! deadline-bound waits that return custody instead of booleans, and
//! emission only on positive zero-exit plus validated outputs. Ticket and
//! orphan discipline mirrors the in-repo BP05 retirement pool. No upstream
//! lines copied. Grant: OWNER-2026-10-23.
//!
//! The executor owns every scope and output lease for one accounting
//! domain. [`CompileJob`] and [`CompileOutput`] are move-only,
//! non-serializable custody tickets; dropping a job marks its entry
//! orphaned without releasing anything, and only [`CompilerExecutor::reconcile`]
//! reaps orphans after positive proof. Dropping an output abandons its
//! lease: the reservation is never auto-released. `close` returns the
//! executor while any entry remains; dropping a live executor leaks the
//! charged state as a documented last resort instead of pretending a
//! clean completion.
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use std::cell::Cell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::object::invalid;
use crate::toolchain::invoke::{has_nul, is_proxy_key};
use crate::toolchain::scope::{
    BuildExit, BuildRequest, BuildScopeBackend, ScopePoll, ScopeStart, SelectedClosure, ToolRole,
};

/// Per-domain bound for one persistent executor: concurrent job entries,
/// aggregate reserved artifact bytes and aggregate retained diagnostic
/// bytes. The bound covers the lifetime of this accounting domain, not one
/// call and not the whole process; a fresh executor is a separate domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorLimits {
    pub max_jobs: usize,
    pub max_reserved_output_bytes: usize,
    pub max_retained_diagnostic_bytes: usize,
}

/// Live accounting snapshot: entries holding reservations plus their full
/// artifact and diagnostic charges. Entries stay fully charged until
/// reaped after positive proof; partial proof releases no credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorUsage {
    pub jobs: usize,
    pub reserved_output_bytes: usize,
    pub retained_diagnostic_bytes: usize,
}

/// Explicit scope-call budget for one [`CompilerExecutor::reconcile`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorBudget {
    pub max_scope_calls: usize,
}

/// Post-pass census: entries reaped by this call, plus every remaining
/// entry split into pending and failed. Caller-active entries (a live
/// job ticket on a running scope with no failure) appear in neither
/// count; leased outputs awaiting explicit release count as pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorReport {
    pub settled_jobs: usize,
    pub pending_jobs: usize,
    pub failed_jobs: usize,
    pub usage: ExecutorUsage,
}

/// One reserved entry: scope/output state, held root identity and charges.
/// The `live` flag is shared with the outstanding job ticket, if any;
/// dropping the ticket clears it, which marks the entry orphaned without
/// touching native state.
struct Entry<S: BuildScopeBackend> {
    state: EntryState<S>,
    root: PathBuf,
    canonical_root: PathBuf,
    /// Open handle on the owned root: held identity, never read. Keeping
    /// the descriptor open pins the directory while the entry lives.
    #[allow(dead_code)]
    held: Option<std::fs::File>,
    charge_artifact: usize,
    charge_diagnostic: usize,
    live: Rc<Cell<bool>>,
    failed: bool,
    /// NoEffect cause kept for output-only entries; surfaced when the
    /// root cleanup finally resolves.
    cause: Option<OperationError>,
}

enum EntryState<S: BuildScopeBackend> {
    Running {
        job: S::Job,
    },
    /// No live scope; the root reservation survives (start had no effect
    /// and cleanup failed, the start panicked before returning, or an
    /// orphaned scope settled and only cleanup remains).
    SettledUnreleased,
    /// Terminal build; the sealed output lease awaits explicit release.
    Leased,
}

/// Session counter. Mints unique executor identities only; it retains no
/// executor state, so it is not a registry.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// Persistent owner of scopes and output leases for one accounting and
/// session domain. Created once per domain and reused across builds.
/// `!Send + !Sync`, with serialized `&mut self` operations.
pub struct CompilerExecutor<S: BuildScopeBackend> {
    session: u64,
    creating_pid: u32,
    limits: ExecutorLimits,
    next_entry: u64,
    backend: S,
    entries: HashMap<u64, Entry<S>>,
}

impl<S: BuildScopeBackend> std::fmt::Debug for CompilerExecutor<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompilerExecutor")
            .field("session", &self.session)
            .field("limits", &self.limits)
            .field("jobs", &self.entries.len())
            .field("usage", &self.usage())
            .finish()
    }
}

impl<S: BuildScopeBackend> CompilerExecutor<S> {
    /// Create an empty executor over one backend and accounting domain.
    /// Every representable limit is constructible, including an all-zero
    /// limit (which admits nothing); the `Result` reserves refusal for
    /// future admission profiles.
    pub fn new(backend: S, limits: ExecutorLimits) -> Result<Self, OperationError> {
        Ok(Self {
            session: NEXT_SESSION.fetch_add(1, Ordering::SeqCst),
            creating_pid: std::process::id(),
            limits,
            next_entry: 0,
            backend,
            entries: HashMap::new(),
        })
    }

    /// Snapshot live accounting: entries plus their full charges.
    pub fn usage(&self) -> ExecutorUsage {
        let mut reserved_output_bytes = 0usize;
        let mut retained_diagnostic_bytes = 0usize;
        for entry in self.entries.values() {
            // Admission keeps both sums within capacity, so this is
            // exact; saturating keeps the snapshot total regardless.
            reserved_output_bytes = reserved_output_bytes.saturating_add(entry.charge_artifact);
            retained_diagnostic_bytes =
                retained_diagnostic_bytes.saturating_add(entry.charge_diagnostic);
        }
        ExecutorUsage {
            jobs: self.entries.len(),
            reserved_output_bytes,
            retained_diagnostic_bytes,
        }
    }

    /// Reconcile orphaned entries (tickets dropped or never issued) within
    /// an explicit scope-call budget. Entries with live caller-held job
    /// tickets are never disturbed, even with spare budget; leased
    /// outputs need explicit release and are never touched either.
    /// Settled orphans clean only their owned outputs. In a
    /// forked-but-not-exec'd child this is a no-op returning a zero
    /// report with a truthful usage snapshot.
    pub fn reconcile(&mut self, budget: ExecutorBudget) -> ExecutorReport {
        if self.check_process(Stage::Execute).is_err() {
            return ExecutorReport {
                settled_jobs: 0,
                pending_jobs: 0,
                failed_jobs: 0,
                usage: self.usage(),
            };
        }
        let mut ids: Vec<u64> = self.entries.keys().copied().collect();
        ids.sort_unstable();
        let mut settled_jobs = 0usize;
        // Free pass: unreleased orphans need filesystem cleanup only, no
        // scope calls.
        for id in &ids {
            let orphan_unreleased = matches!(
                self.entries.get(id),
                Some(entry) if !entry.live.get() && matches!(entry.state, EntryState::SettledUnreleased)
            );
            if !orphan_unreleased {
                continue;
            }
            match self.cleanup_root(*id) {
                Ok(()) => {
                    self.entries.remove(id);
                    settled_jobs += 1;
                }
                Err(_) => {
                    if let Some(entry) = self.entries.get_mut(id) {
                        entry.failed = true;
                    }
                }
            }
        }
        // Budgeted pass: one poll per orphaned running entry.
        let mut calls = 0usize;
        for id in &ids {
            if calls >= budget.max_scope_calls {
                break;
            }
            let orphan_running = matches!(
                self.entries.get(id),
                Some(entry) if !entry.live.get() && matches!(entry.state, EntryState::Running { .. })
            );
            if !orphan_running {
                continue;
            }
            calls += 1;
            let poll = {
                let entry = self.entries.get_mut(id).expect("live orphan");
                let EntryState::Running { job } = &mut entry.state else {
                    continue;
                };
                self.backend.poll(job)
            };
            match poll {
                ScopePoll::Running => {
                    if let Some(entry) = self.entries.get_mut(id) {
                        entry.failed = false;
                    }
                }
                ScopePoll::Unresolved(_) => {
                    // The error has no ticket to travel to; the entry
                    // reports failed until a later poll clears it.
                    if let Some(entry) = self.entries.get_mut(id) {
                        entry.failed = true;
                    }
                }
                ScopePoll::Settled { .. } => {
                    if let Some(entry) = self.entries.get_mut(id) {
                        entry.state = EntryState::SettledUnreleased;
                        entry.cause = None;
                    }
                    match self.cleanup_root(*id) {
                        Ok(()) => {
                            self.entries.remove(id);
                            settled_jobs += 1;
                        }
                        Err(_) => {
                            if let Some(entry) = self.entries.get_mut(id) {
                                entry.failed = true;
                            }
                        }
                    }
                }
            }
        }
        let mut pending_jobs = 0usize;
        let mut failed_jobs = 0usize;
        for entry in self.entries.values() {
            if entry.failed {
                failed_jobs += 1;
            } else if !(entry.live.get() && matches!(entry.state, EntryState::Running { .. })) {
                pending_jobs += 1;
            }
        }
        ExecutorReport {
            settled_jobs,
            pending_jobs,
            failed_jobs,
            usage: self.usage(),
        }
    }

    /// Attempt to close the executor. `Closed` means no entry remains;
    /// otherwise the executor itself is returned with recovery intact,
    /// and no scope call was made.
    pub fn close(self) -> ExecutorClose<S> {
        if self.entries.is_empty() {
            ExecutorClose::Closed
        } else {
            ExecutorClose::Unresolved(self)
        }
    }

    /// Refuse fork-without-exec reuse: native owners belong to the
    /// creating process until an exec boundary re-acquires them.
    fn check_process(&self, stage: Stage) -> Result<(), OperationError> {
        if std::process::id() != self.creating_pid {
            Err(OperationError::new(ErrorKind::Changed, stage, None, None))
        } else {
            Ok(())
        }
    }

    /// Reserve one job slot plus artifact and diagnostic charges before
    /// any effect. Overflow in the reservation calculation refuses.
    fn reserve_charges(&self, request: &BuildRequest) -> Result<(), OperationError> {
        if self.entries.len() >= self.limits.max_jobs {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Admission,
                None,
                None,
            ));
        }
        let overflow = || OperationError::new(ErrorKind::Overflow, Stage::Admission, None, None);
        let mut reserved = 0usize;
        let mut retained = 0usize;
        for entry in self.entries.values() {
            reserved = reserved
                .checked_add(entry.charge_artifact)
                .ok_or_else(overflow)?;
            retained = retained
                .checked_add(entry.charge_diagnostic)
                .ok_or_else(overflow)?;
        }
        let reserved = reserved
            .checked_add(request.max_artifact_bytes)
            .ok_or_else(overflow)?;
        let retained = retained
            .checked_add(request.max_output_bytes)
            .ok_or_else(overflow)?;
        if reserved > self.limits.max_reserved_output_bytes
            || retained > self.limits.max_retained_diagnostic_bytes
        {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Admission,
                None,
                None,
            ));
        }
        Ok(())
    }

    /// Create and hold one owned isolated output root. The root must not
    /// exist, and neither it nor any alias of it may sit inside a
    /// reserved root; lexical differences cannot bypass the reservation
    /// because parents resolve canonically. The directory the executor
    /// creates is exactly what cleanup later removes.
    fn reserve_root(&self, output_root: &std::path::Path) -> Result<ReservedRoot, OperationError> {
        let parent = output_root.parent().ok_or_else(|| invalid("output root"))?;
        if !parent.is_dir() {
            return Err(invalid("output root parent missing"));
        }
        let canonical_parent = parent.canonicalize().map_err(|error| {
            OperationError::new(
                ErrorKind::Backend,
                Stage::Admission,
                error.raw_os_error(),
                Some(Box::new(RetireDetail("root parent unresolvable"))),
            )
        })?;
        if std::fs::symlink_metadata(output_root).is_ok() {
            return Err(invalid("output root exists"));
        }
        for entry in self.entries.values() {
            if canonical_parent == entry.canonical_root
                || canonical_parent.starts_with(&entry.canonical_root)
            {
                return Err(invalid("output root inside reserved root"));
            }
        }
        match std::fs::create_dir(output_root) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotFound
                ) =>
            {
                return Err(invalid("output root exists"));
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(OperationError::new(
                    ErrorKind::Denied,
                    Stage::Allocate,
                    error.raw_os_error(),
                    Some(Box::new(RetireDetail("output root denied"))),
                ));
            }
            Err(error) => {
                return Err(OperationError::new(
                    ErrorKind::Backend,
                    Stage::Allocate,
                    error.raw_os_error(),
                    Some(Box::new(RetireDetail("output root backend failure"))),
                ));
            }
        }
        let created = (|| -> std::io::Result<ReservedRoot> {
            let canonical = output_root.canonicalize()?;
            let held = std::fs::File::open(&canonical)?;
            Ok(ReservedRoot {
                path: output_root.to_path_buf(),
                canonical,
                held,
            })
        })();
        match created {
            Ok(root) => Ok(root),
            Err(error) => {
                let _ = std::fs::remove_dir_all(output_root);
                Err(OperationError::new(
                    ErrorKind::Backend,
                    Stage::Allocate,
                    error.raw_os_error(),
                    Some(Box::new(RetireDetail("output root backend failure"))),
                ))
            }
        }
    }

    /// Insert a live entry before starting any native scope. Orphaned
    /// until a ticket is issued: a panic before the outcome leaves a
    /// recoverable orphan, never a skipped live entry. Entry ids are
    /// never reused, so a ticket for a reaped entry is recognizably stale.
    fn insert_entry(&mut self, root: ReservedRoot, request: &BuildRequest) -> u64 {
        let id = self.next_entry;
        self.next_entry = self.next_entry.wrapping_add(1);
        self.entries.insert(
            id,
            Entry {
                state: EntryState::SettledUnreleased,
                root: root.path,
                canonical_root: root.canonical,
                held: Some(root.held),
                charge_artifact: request.max_artifact_bytes,
                charge_diagnostic: request.max_output_bytes,
                live: Rc::new(Cell::new(false)),
                failed: false,
                cause: None,
            },
        );
        id
    }

    /// Mark an entry ticket-held and share its liveness flag with the
    /// newly issued ticket. Called only for live entries.
    fn issue(&mut self, id: u64) -> Rc<Cell<bool>> {
        let entry = self
            .entries
            .get(&id)
            .expect("ticket issued only for a live entry");
        entry.live.set(true);
        Rc::clone(&entry.live)
    }

    /// Remove one owned output root made by [`CompilerExecutor::reserve_root`].
    /// An already-absent root cleans vacuously. Any other failure retains
    /// the reservation for retry; cleanup never touches paths outside the
    /// owned root.
    fn cleanup_root(&mut self, id: u64) -> Result<(), OperationError> {
        let root = self
            .entries
            .get(&id)
            .expect("cleanup runs only on a live entry")
            .root
            .clone();
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(OperationError::new(
                    ErrorKind::Denied,
                    Stage::Retire,
                    error.raw_os_error(),
                    Some(Box::new(RetireDetail("output root cleanup denied"))),
                ));
            }
            Err(error) => {
                return Err(OperationError::new(
                    ErrorKind::Backend,
                    Stage::Retire,
                    error.raw_os_error(),
                    Some(Box::new(RetireDetail("output root cleanup failed"))),
                ));
            }
        }
        if std::fs::symlink_metadata(&root).is_ok() {
            return Err(OperationError::new(
                ErrorKind::Backend,
                Stage::Retire,
                None,
                Some(Box::new(RetireDetail("output root survived cleanup"))),
            ));
        }
        Ok(())
    }
}

impl<S: BuildScopeBackend> Drop for CompilerExecutor<S> {
    /// Last resort: with entries remaining, retain the whole charged
    /// state by leaking it. Native destructors must not run here:
    /// running them would settle without proof and pretend a clean
    /// close. Never panics; never calls native code.
    fn drop(&mut self) {
        if !self.entries.is_empty() {
            let entries = std::mem::take(&mut self.entries);
            std::mem::forget(entries);
        }
    }
}

/// Executor close outcome: clean close, or the executor itself with
/// recovery intact. `close` makes no scope calls.
pub enum ExecutorClose<S: BuildScopeBackend> {
    Closed,
    Unresolved(CompilerExecutor<S>),
}

impl<S: BuildScopeBackend> std::fmt::Debug for ExecutorClose<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutorClose::Closed => write!(f, "Closed"),
            ExecutorClose::Unresolved(executor) => {
                f.debug_tuple("Unresolved").field(executor).finish()
            }
        }
    }
}

struct ReservedRoot {
    path: PathBuf,
    canonical: PathBuf,
    held: std::fs::File,
}

#[derive(Debug)]
struct RetireDetail(&'static str);

impl std::fmt::Display for RetireDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc02 custody: {}", self.0)
    }
}

impl std::error::Error for RetireDetail {}

// ---------------------------------------------------------------------------
// Custody tickets and outcomes.
// ---------------------------------------------------------------------------

/// Move-only ticket for one live build. There is exactly one ticket per
/// entry; it cannot be cloned, serialized or forged. Consumed by
/// [`CompileJob::reconcile`] and [`CompileJob::request_stop`]; dropping it
/// marks the entry orphaned without releasing anything. `!Send + !Sync`.
pub struct CompileJob<S: BuildScopeBackend> {
    session: u64,
    entry: u64,
    live: Option<Rc<Cell<bool>>>,
    scope: PhantomData<S>,
}

impl<S: BuildScopeBackend> std::fmt::Debug for CompileJob<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompileJob")
            .field("session", &self.session)
            .field("entry", &self.entry)
            .finish()
    }
}

impl<S: BuildScopeBackend> Drop for CompileJob<S> {
    /// Mark the entry orphaned. Releases no scope, root, credit or
    /// charge, and calls no native code. Never panics.
    fn drop(&mut self) {
        if let Some(live) = self.live.as_ref() {
            live.set(false);
        }
    }
}

impl<S: BuildScopeBackend> CompileJob<S> {
    fn issued(session: u64, entry: u64, live: Rc<Cell<bool>>) -> Self {
        Self {
            session,
            entry,
            live: Some(live),
            scope: PhantomData,
        }
    }

    fn rehome(session: u64, entry: u64, live: Option<Rc<Cell<bool>>>) -> Self {
        Self {
            session,
            entry,
            live,
            scope: PhantomData,
        }
    }

    /// Poll a live build until it settles or `deadline` passes. Consumes
    /// the ticket and returns custody on anything but a terminal result.
    /// Wrong-executor, wrong-process and stale-entry tickets are refused
    /// with their original custody and no scope call.
    pub fn reconcile(
        mut self,
        executor: &mut CompilerExecutor<S>,
        deadline: Instant,
    ) -> CompileOutcome<S> {
        let live = self.live.take();
        if let Err(error) = executor.check_process(Stage::Execute) {
            return CompileOutcome::Unresolved {
                job: Self::rehome(self.session, self.entry, live),
                error,
            };
        }
        if executor.session != self.session {
            return CompileOutcome::Unresolved {
                job: Self::rehome(self.session, self.entry, live),
                error: invalid("wrong executor"),
            };
        }
        match executor.entries.get(&self.entry) {
            Some(entry) if matches!(entry.state, EntryState::Running { .. }) => {
                drive_running(executor, self.session, self.entry, live, deadline, false)
            }
            Some(entry) if matches!(entry.state, EntryState::SettledUnreleased) => {
                resolve_unreleased(executor, self.session, self.entry, live)
            }
            _ => CompileOutcome::Unresolved {
                job: Self::rehome(self.session, self.entry, live),
                error: invalid("stale job"),
            },
        }
    }

    /// Request a cooperative stop through the actually owned scope, then
    /// poll until it settles or `deadline` passes. Same custody contract
    /// as [`CompileJob::reconcile`]; never signals a guessed pid.
    pub fn request_stop(
        mut self,
        executor: &mut CompilerExecutor<S>,
        deadline: Instant,
    ) -> CompileOutcome<S> {
        let live = self.live.take();
        if let Err(error) = executor.check_process(Stage::Execute) {
            return CompileOutcome::Unresolved {
                job: Self::rehome(self.session, self.entry, live),
                error,
            };
        }
        if executor.session != self.session {
            return CompileOutcome::Unresolved {
                job: Self::rehome(self.session, self.entry, live),
                error: invalid("wrong executor"),
            };
        }
        match executor.entries.get(&self.entry) {
            Some(entry) if matches!(entry.state, EntryState::Running { .. }) => {
                drive_running(executor, self.session, self.entry, live, deadline, true)
            }
            // No scope to stop; retry the pending root cleanup instead.
            Some(entry) if matches!(entry.state, EntryState::SettledUnreleased) => {
                resolve_unreleased(executor, self.session, self.entry, live)
            }
            _ => CompileOutcome::Unresolved {
                job: Self::rehome(self.session, self.entry, live),
                error: invalid("stale job"),
            },
        }
    }
}

/// Move-only sealed output-root lease. Issued only with a terminal
/// [`CompileOutcome::Emitted`] or [`CompileOutcome::Refused`]; the sealed
/// object paths are inspectable through [`CompileOutput::objects`], but a
/// refusal lease is not a valid object claim. The lease ends only through
/// checked [`CompileOutput::release`]; dropping the ticket abandons the
/// lease without releasing anything. `!Send + !Sync`.
pub struct CompileOutput<S: BuildScopeBackend> {
    session: u64,
    entry: u64,
    live: Option<Rc<Cell<bool>>>,
    objects: Vec<PathBuf>,
    scope: PhantomData<S>,
}

impl<S: BuildScopeBackend> std::fmt::Debug for CompileOutput<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompileOutput")
            .field("session", &self.session)
            .field("entry", &self.entry)
            .field("objects", &self.objects)
            .finish()
    }
}

impl<S: BuildScopeBackend> Drop for CompileOutput<S> {
    /// Abandon the lease. Releases nothing and calls no native code;
    /// only explicit release ends a lease. Never panics.
    fn drop(&mut self) {
        if let Some(live) = self.live.as_ref() {
            live.set(false);
        }
    }
}

impl<S: BuildScopeBackend> CompileOutput<S> {
    /// Sealed object paths. Inspectable on refusal leases too, but only
    /// an [`CompileOutcome::Emitted`] lease claims valid objects.
    pub fn objects(&self) -> &[PathBuf] {
        &self.objects
    }

    /// Checked release: remove the owned output root and free the lease.
    /// A failed cleanup returns the original ticket with custody intact
    /// for retry. Wrong-executor, wrong-process and stale tickets fail
    /// without native action.
    pub fn release(self, executor: &mut CompilerExecutor<S>) -> Result<(), OutputReleaseError<S>> {
        if let Err(error) = executor.check_process(Stage::Retire) {
            return Err(OutputReleaseError {
                output: self,
                error,
            });
        }
        if executor.session != self.session {
            return Err(OutputReleaseError {
                output: self,
                error: invalid("wrong executor"),
            });
        }
        match executor.entries.get(&self.entry) {
            Some(entry) if matches!(entry.state, EntryState::Leased) => {}
            _ => {
                return Err(OutputReleaseError {
                    output: self,
                    error: invalid("stale output"),
                })
            }
        }
        match executor.cleanup_root(self.entry) {
            Ok(()) => {
                executor.entries.remove(&self.entry);
                Ok(())
            }
            Err(error) => {
                if let Some(entry) = executor.entries.get_mut(&self.entry) {
                    entry.failed = true;
                }
                Err(OutputReleaseError {
                    output: self,
                    error,
                })
            }
        }
    }
}

/// Failed release: the original output ticket plus the typed cause, with
/// the lease and its reservation fully retained.
pub struct OutputReleaseError<S: BuildScopeBackend> {
    pub output: CompileOutput<S>,
    pub error: OperationError,
}

impl<S: BuildScopeBackend> std::fmt::Debug for OutputReleaseError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputReleaseError")
            .field("output", &self.output)
            .field("error", &self.error)
            .finish()
    }
}

/// Terminal or custody-bearing build outcome. `ToolMissing` and `Rejected`
/// carry no scope or output-root ownership; every other variant either
/// seals an output lease or returns a live job ticket, never an unowned
/// summary.
pub enum CompileOutcome<S: BuildScopeBackend> {
    Emitted {
        output: CompileOutput<S>,
    },
    Refused {
        diagnostic: Vec<u8>,
        output: CompileOutput<S>,
    },
    ToolMissing {
        name: String,
    },
    Rejected(OperationError),
    TimedOut {
        job: CompileJob<S>,
    },
    Unresolved {
        job: CompileJob<S>,
        error: OperationError,
    },
}

impl<S: BuildScopeBackend> std::fmt::Debug for CompileOutcome<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileOutcome::Emitted { output } => {
                f.debug_struct("Emitted").field("output", output).finish()
            }
            CompileOutcome::Refused { diagnostic, output } => f
                .debug_struct("Refused")
                .field("diagnostic_bytes", &diagnostic.len())
                .field("output", output)
                .finish(),
            CompileOutcome::ToolMissing { name } => {
                f.debug_struct("ToolMissing").field("name", name).finish()
            }
            CompileOutcome::Rejected(error) => f.debug_tuple("Rejected").field(error).finish(),
            CompileOutcome::TimedOut { job } => {
                f.debug_struct("TimedOut").field("job", job).finish()
            }
            CompileOutcome::Unresolved { job, error } => f
                .debug_struct("Unresolved")
                .field("job", job)
                .field("error", error)
                .finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// Admission and drive.
// ---------------------------------------------------------------------------

/// Environment keys that refuse: compiler, target and CPU selection
/// belongs to the closure and the request fields, never the environment.
const FORBIDDEN_ENV_KEYS: &[&str] = &["RUSTC", "CARGO", "TARGET", "CPU"];

/// Validate request shape without effects: non-empty NUL-free paths and
/// target, NUL-free features, and an explicit environment with no NUL,
/// `=`, proxy or offline-override keys.
fn validate_request(request: &BuildRequest) -> Result<(), OperationError> {
    if request.source_root.as_os_str().is_empty()
        || request.output_root.as_os_str().is_empty()
        || has_nul(request.source_root.as_os_str())
        || has_nul(request.output_root.as_os_str())
    {
        return Err(invalid("request paths"));
    }
    if request.target.is_empty() || request.target.bytes().any(|byte| byte == 0) {
        return Err(invalid("target"));
    }
    if request
        .features
        .iter()
        .any(|feature| feature.bytes().any(|byte| byte == 0))
    {
        return Err(invalid("features"));
    }
    for (key, value) in &request.environment {
        if key.is_empty() || has_nul(key) || has_nul(value) {
            return Err(invalid("environment bytes"));
        }
        if key.to_string_lossy().contains('=') {
            return Err(invalid("environment key"));
        }
        if is_proxy_key(key) {
            return Err(invalid("network proxy environment refused"));
        }
        if key == "CARGO_NET_OFFLINE" && value != "true" {
            return Err(invalid("offline environment refused"));
        }
        if FORBIDDEN_ENV_KEYS.iter().any(|banned| key == *banned) {
            return Err(invalid("compiler selection environment refused"));
        }
    }
    Ok(())
}

/// Verify the Cargo/rustc/sysroot selected pair: all three or nothing,
/// matching toolchain versions, rustc beneath the sysroot, and a sysroot
/// carrying `lib/rustlib`.
fn check_pair(tools: &SelectedClosure) -> Result<(), OperationError> {
    let selected = tools.cargo().is_some() as u8
        + tools.rustc().is_some() as u8
        + tools.rust_sysroot().is_some() as u8;
    if selected == 0 {
        return Ok(());
    }
    if selected < 3 {
        return Err(invalid("cargo/rustc/sysroot must be selected together"));
    }
    let manifest = tools.manifest();
    let cargo_version = tools
        .role_pin(ToolRole::Cargo)
        .and_then(|pin| manifest.find(pin))
        .map(|tool| tool.version());
    let rustc_version = tools
        .role_pin(ToolRole::Rustc)
        .and_then(|pin| manifest.find(pin))
        .map(|tool| tool.version());
    if cargo_version.is_none() || cargo_version != rustc_version {
        return Err(invalid("cargo/rustc version mismatch"));
    }
    let (rustc, sysroot) = (
        tools.rustc().expect("selected"),
        tools.rust_sysroot().expect("selected"),
    );
    if !rustc.executable.starts_with(sysroot) {
        return Err(invalid("rustc outside sysroot"));
    }
    if !sysroot.join("lib/rustlib").is_dir() {
        return Err(invalid("sysroot lacks lib/rustlib"));
    }
    Ok(())
}

/// First selected tool whose path is absent, in role order. Sysroot and
/// loaded-library paths count: every bound path must resolve.
fn missing_tool(tools: &SelectedClosure) -> Option<String> {
    let mut bound: Vec<(ToolRole, &std::path::Path)> = Vec::new();
    if let Some(tool) = tools.cargo() {
        bound.push((ToolRole::Cargo, &tool.executable));
    }
    if let Some(tool) = tools.rustc() {
        bound.push((ToolRole::Rustc, &tool.executable));
    }
    if let Some(sysroot) = tools.rust_sysroot() {
        bound.push((ToolRole::RustSysroot, sysroot));
    }
    if let Some(tool) = tools.clang() {
        bound.push((ToolRole::Clang, &tool.executable));
    }
    if let Some(tool) = tools.llc() {
        bound.push((ToolRole::Llc, &tool.executable));
    }
    if let Some(tool) = tools.linker() {
        bound.push((ToolRole::Linker, &tool.executable));
    }
    bound.push((ToolRole::LoadedLlvm, &tools.loaded_llvm().executable));
    bound
        .into_iter()
        .find(|(_, path)| std::fs::symlink_metadata(path).is_err())
        .map(|(role, _)| role.name().to_owned())
}

/// Drive one running entry: optionally request a cooperative stop first,
/// then poll until settlement, backend trouble or `deadline`.
fn drive_running<S: BuildScopeBackend>(
    executor: &mut CompilerExecutor<S>,
    session: u64,
    id: u64,
    live: Option<Rc<Cell<bool>>>,
    deadline: Instant,
    stop: bool,
) -> CompileOutcome<S> {
    if stop {
        let poll = {
            let entry = executor.entries.get_mut(&id).expect("live entry");
            let EntryState::Running { job } = &mut entry.state else {
                return CompileOutcome::Unresolved {
                    job: CompileJob::rehome(session, id, live),
                    error: invalid("stale job"),
                };
            };
            executor.backend.request_stop(job)
        };
        if let ScopePoll::Settled {
            exit,
            objects,
            diagnostic,
        } = poll
        {
            return seal(executor, session, id, live, exit, objects, diagnostic);
        }
    }
    loop {
        let poll = {
            let entry = executor.entries.get_mut(&id).expect("live entry");
            let EntryState::Running { job } = &mut entry.state else {
                return CompileOutcome::Unresolved {
                    job: CompileJob::rehome(session, id, live),
                    error: invalid("stale job"),
                };
            };
            executor.backend.poll(job)
        };
        match poll {
            ScopePoll::Running => {
                if let Some(entry) = executor.entries.get_mut(&id) {
                    entry.failed = false;
                }
                if Instant::now() >= deadline {
                    return CompileOutcome::TimedOut {
                        job: CompileJob::rehome(session, id, live),
                    };
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            ScopePoll::Settled {
                exit,
                objects,
                diagnostic,
            } => {
                return seal(executor, session, id, live, exit, objects, diagnostic);
            }
            ScopePoll::Unresolved(error) => {
                if let Some(entry) = executor.entries.get_mut(&id) {
                    entry.failed = true;
                }
                return CompileOutcome::Unresolved {
                    job: CompileJob::rehome(session, id, live),
                    error,
                };
            }
        }
    }
}

/// Retry the pending root cleanup of an output-only entry. Success frees
/// the entry and surfaces the stored NoEffect cause as a rejection with
/// no surviving ownership; failure keeps custody for retry.
fn resolve_unreleased<S: BuildScopeBackend>(
    executor: &mut CompilerExecutor<S>,
    session: u64,
    id: u64,
    live: Option<Rc<Cell<bool>>>,
) -> CompileOutcome<S> {
    match executor.cleanup_root(id) {
        Ok(()) => {
            let entry = executor.entries.remove(&id).expect("live entry");
            if let Some(live) = live.as_ref() {
                live.set(false);
            }
            match entry.cause {
                Some(cause) => CompileOutcome::Rejected(cause),
                // Defensive: live-ticketed unreleased entries always carry
                // the NoEffect cause; ticketless ones never reach this path.
                None => CompileOutcome::Rejected(OperationError::new(
                    ErrorKind::Backend,
                    Stage::Execute,
                    None,
                    Some(Box::new(RetireDetail("settled without cause"))),
                )),
            }
        }
        Err(error) => {
            if let Some(entry) = executor.entries.get_mut(&id) {
                entry.failed = true;
            }
            CompileOutcome::Unresolved {
                job: CompileJob::rehome(session, id, live),
                error,
            }
        }
    }
}

/// Seal a settled scope into a leased output. `Emitted` additionally
/// requires `Exited(0)` and valid admitted outputs: a nonempty object
/// list, every object a regular file inside the held root, and a total
/// within the artifact reservation. Anything else seals as `Refused`.
fn seal<S: BuildScopeBackend>(
    executor: &mut CompilerExecutor<S>,
    session: u64,
    id: u64,
    live: Option<Rc<Cell<bool>>>,
    exit: BuildExit,
    objects: Vec<PathBuf>,
    diagnostic: Vec<u8>,
) -> CompileOutcome<S> {
    let entry = executor.entries.get_mut(&id).expect("live entry");
    entry.state = EntryState::Leased;
    entry.failed = false;
    let canonical_root = entry.canonical_root.clone();
    let allowance = entry.charge_artifact;
    if let Some(live) = live.as_ref() {
        live.set(false);
    }
    let admitted = matches!(exit, BuildExit::Exited(0)) && !objects.is_empty() && {
        let mut total = 0usize;
        let mut ok = true;
        for object in &objects {
            let valid = object
                .canonicalize()
                .ok()
                .filter(|resolved| resolved.starts_with(&canonical_root))
                .and_then(|resolved| resolved.metadata().ok())
                .filter(|meta| meta.is_file())
                .map(|meta| meta.len())
                .and_then(|len| usize::try_from(len).ok())
                .and_then(|len| {
                    total.checked_add(len).map(|sum| {
                        total = sum;
                    })
                })
                .is_some();
            if !valid {
                ok = false;
                break;
            }
        }
        ok && total <= allowance
    };
    let output = CompileOutput {
        session,
        entry: id,
        live,
        objects,
        scope: PhantomData,
    };
    if admitted {
        CompileOutcome::Emitted { output }
    } else {
        CompileOutcome::Refused { diagnostic, output }
    }
}

/// Build one fixture under an explicit closure with persistent custody.
///
/// Admission order is fixed and side-effect free until the root is
/// reserved: request shape, capacity and charges, pair coherence, tool
/// existence (`ToolMissing`), then root reservation and backend start.
/// The initial poll loop runs to `request.deadline`; anything unsettled
/// returns a live [`CompileJob`] ticket, never an unowned summary.
pub fn compile_fixture<S: BuildScopeBackend>(
    executor: &mut CompilerExecutor<S>,
    tools: &SelectedClosure,
    request: &BuildRequest,
) -> CompileOutcome<S> {
    if let Err(error) = executor.check_process(Stage::Execute) {
        return CompileOutcome::Rejected(error);
    }
    if let Err(error) = validate_request(request) {
        return CompileOutcome::Rejected(error);
    }
    if let Err(error) = executor.reserve_charges(request) {
        return CompileOutcome::Rejected(error);
    }
    if let Err(error) = check_pair(tools) {
        return CompileOutcome::Rejected(error);
    }
    if let Some(name) = missing_tool(tools) {
        return CompileOutcome::ToolMissing { name };
    }
    let root = match executor.reserve_root(&request.output_root) {
        Ok(root) => root,
        Err(error) => return CompileOutcome::Rejected(error),
    };
    // The entry is live before the native scope starts: a backend panic
    // unwinds with a recoverable orphan, exactly like the BP05 pool.
    let id = executor.insert_entry(root, request);
    let session = executor.session;
    match executor.backend.start(tools, request) {
        ScopeStart::Started(job) => {
            if let Some(entry) = executor.entries.get_mut(&id) {
                entry.state = EntryState::Running { job };
            }
            let live = executor.issue(id);
            drive_running(executor, session, id, Some(live), request.deadline, false)
        }
        ScopeStart::NoEffect(cause) => match executor.cleanup_root(id) {
            Ok(()) => {
                executor.entries.remove(&id);
                CompileOutcome::Rejected(cause)
            }
            Err(error) => {
                if let Some(entry) = executor.entries.get_mut(&id) {
                    entry.failed = true;
                    entry.cause = Some(cause);
                }
                let live = executor.issue(id);
                CompileOutcome::Unresolved {
                    job: CompileJob::issued(session, id, live),
                    error,
                }
            }
        },
        ScopeStart::Uncertain { custody, cause } => {
            if let Some(entry) = executor.entries.get_mut(&id) {
                entry.state = EntryState::Running { job: custody };
                entry.failed = true;
            }
            let live = executor.issue(id);
            CompileOutcome::Unresolved {
                job: CompileJob::issued(session, id, live),
                error: cause,
            }
        }
    }
}
