// SPDX-License-Identifier: Apache-2.0
//! Persistent attachment custody pool: capacity accounting, orphan
//! reconciliation and explicit close.
//!
//! ADAPT of the donor halt/ownership discipline: p11scope
//! `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//! @ `2c2713e66292b0d2688508a25f79e813ae823d81` (`BisectHalt` with
//! `closed_leaves`, lines 338-348; the halt closure that closes
//! already-created leaves and counts them, lines 411-421) and KryProbe
//! `crates/kryprobe-core/src/attach.rs` @ `d153f3aa`
//! (`d153f3aaf9a3931337b47c9e1b046c692da55083`, issuance-only
//! `LinkGroup` generation, lines 12-80; `GenerationGuard` stale
//! refusal, lines 260-274). The donor drop-with-count becomes explicit
//! per-object retirement against a persistent charge: active, pending,
//! failed, uncertain and orphaned entries stay fully charged until
//! positive native retirement, and dropped tickets only mark entries
//! orphaned. All user-owned donor slices under blanket `OWNER-2026-10-23`;
//! third-party/upstream lines never copied.

use crate::attach::plan::{AttachBackend, CustodyCharge, NativeRetire};
use crate::{ErrorKind, OperationError, Stage};
use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-domain bound for one persistent pool: concurrent plan entries,
/// audited native link/uncertain slots and library-owned retained bytes.
///
/// The bound covers the lifetime of this accounting domain, not one
/// function call and not the whole process. Callers and the SDK must
/// count every live pool; constructing a fresh pool creates a separate
/// domain and never resets an application-wide bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetirementCapacity {
    pub max_groups: usize,
    pub max_links: usize,
    pub max_retained_bytes: usize,
}

/// Live accounting snapshot: entries, outstanding native objects and
/// retained charge bytes.
///
/// `links` counts unconfirmed link/uncertain objects, not reserved
/// slots; `retained_bytes` sums the full audited charge of every live
/// entry. Entries stay fully charged until reaped after positive
/// retirement; partial proof releases no credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolUsage {
    pub groups: usize,
    pub links: usize,
    pub retained_bytes: usize,
}

/// Explicit native-call budget for one `reconcile` pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetirementBudget {
    pub max_native_calls: usize,
}

/// Post-call entry census: groups reaped by this call, plus every
/// remaining entry with outstanding custody split into pending-only
/// and failed. Pure-active entries with live caller-held tickets are
/// active, not pending, and appear in neither count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolReconcile {
    pub retired_groups: usize,
    pub pending_groups: usize,
    pub failed_groups: usize,
    pub usage: PoolUsage,
}

/// One attached link and its retirement state.
#[derive(Debug)]
pub(crate) struct LinkSlot<L> {
    pub state: LinkState<L>,
}

/// Retirement state of one link. `Failed` marks custody that reported
/// a typed error; the error itself travels in the caller's
/// [`Retirement`](crate::attach::Retirement) value, and the first
/// failure in retire order is the reported one.
#[derive(Debug)]
pub(crate) enum LinkState<L> {
    Active(L),
    Pending(L),
    Failed(L),
}

impl<L> LinkState<L> {
    pub fn link_mut(&mut self) -> &mut L {
        match self {
            LinkState::Active(link) | LinkState::Pending(link) | LinkState::Failed(link) => link,
        }
    }

    pub fn into_link(self) -> L {
        match self {
            LinkState::Active(link) | LinkState::Pending(link) | LinkState::Failed(link) => link,
        }
    }
}

/// One uncertain acquisition and its reconciliation state.
#[derive(Debug)]
pub(crate) struct UncertainSlot<U> {
    pub state: UncertainState<U>,
}

/// Reconciliation state of one uncertain acquisition. Same reporting
/// rule as [`LinkState`]: the first failure in retire order is reported.
#[derive(Debug)]
pub(crate) enum UncertainState<U> {
    Open(U),
    Pending(U),
    Failed(U),
}

impl<U> UncertainState<U> {
    pub fn custody_mut(&mut self) -> &mut U {
        match self {
            UncertainState::Open(custody)
            | UncertainState::Pending(custody)
            | UncertainState::Failed(custody) => custody,
        }
    }

    pub fn into_custody(self) -> U {
        match self {
            UncertainState::Open(custody)
            | UncertainState::Pending(custody)
            | UncertainState::Failed(custody) => custody,
        }
    }
}

/// One reserved plan entry: the pool-owned backend, authority, links,
/// uncertain acquisitions and audited charge. The `live` flag is shared
/// with the outstanding ticket (if any); dropping the ticket clears it,
/// which marks the entry orphaned without touching native state. Slot
/// vectors stay in attach order (push-only on attach, position-preserving
/// updates on retire), so reverse iteration is reverse attach order.
pub(crate) struct Entry<B: AttachBackend> {
    pub backend: B,
    pub authority: B::Authority,
    pub links: Vec<LinkSlot<B::Link>>,
    pub uncertain: Vec<UncertainSlot<B::Uncertain>>,
    pub charge: CustodyCharge,
    pub live: Rc<Cell<bool>>,
}

impl<B: AttachBackend> std::fmt::Debug for Entry<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("links", &self.links.len())
            .field("uncertain", &self.uncertain.len())
            .field("charge", &self.charge)
            .field("live", &self.live.get())
            .finish()
    }
}

impl<B: AttachBackend> Entry<B> {
    fn outstanding(&self) -> usize {
        self.links.len() + self.uncertain.len()
    }

    fn has_failed(&self) -> bool {
        self.links
            .iter()
            .any(|slot| matches!(slot.state, LinkState::Failed(_)))
            || self
                .uncertain
                .iter()
                .any(|slot| matches!(slot.state, UncertainState::Failed(_)))
    }

    fn is_pure_active(&self) -> bool {
        self.live.get()
            && self
                .links
                .iter()
                .all(|slot| matches!(slot.state, LinkState::Active(_)))
            && self
                .uncertain
                .iter()
                .all(|slot| matches!(slot.state, UncertainState::Open(_)))
    }
}

/// Session counter. This mints unique pool identities only; it retains
/// no pool state, so it is not a registry.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// Persistent owner of backends, authorities, links and uncertain
/// acquisitions for one accounting/session domain.
///
/// The pool is created once per domain and reused across attach
/// attempts. It is `!Send + !Sync` with serialized `&mut self`
/// operations; movable/concurrent native factories need a separate
/// qualified profile.
pub struct RetirementPool<B: AttachBackend> {
    session: u64,
    creating_pid: u32,
    capacity: RetirementCapacity,
    next_entry: u64,
    entries: HashMap<u64, Entry<B>>,
}

impl<B: AttachBackend> std::fmt::Debug for RetirementPool<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetirementPool")
            .field("session", &self.session)
            .field("capacity", &self.capacity)
            .field("groups", &self.entries.len())
            .field("usage", &self.usage())
            .finish()
    }
}

impl<B: AttachBackend> RetirementPool<B> {
    /// Create an empty pool over one accounting domain.
    ///
    /// Every representable capacity is constructible, including an
    /// all-zero capacity (which admits nothing); the `Result` reserves
    /// refusal for future admission profiles.
    pub fn new(capacity: RetirementCapacity) -> Result<Self, OperationError> {
        Ok(Self {
            session: NEXT_SESSION.fetch_add(1, Ordering::SeqCst),
            creating_pid: std::process::id(),
            capacity,
            next_entry: 0,
            entries: HashMap::new(),
        })
    }

    /// Snapshot live accounting: entries, outstanding native objects
    /// and retained charge bytes.
    pub fn usage(&self) -> PoolUsage {
        let mut links = 0usize;
        let mut retained_bytes = 0usize;
        for entry in self.entries.values() {
            // Admission keeps both sums within capacity, so this is
            // exact; saturating keeps the snapshot total regardless.
            links = links.saturating_add(entry.outstanding());
            retained_bytes = retained_bytes.saturating_add(entry.charge.retained_bytes);
        }
        PoolUsage {
            groups: self.entries.len(),
            links,
            retained_bytes,
        }
    }

    /// Reconcile orphaned entries (tickets dropped or never issued)
    /// within an explicit native-call budget.
    ///
    /// Entries with live caller-held tickets are never disturbed, even
    /// with spare budget. Effect-free orphans (entries that never
    /// produced a native object, e.g. after a policy panic) reap
    /// without consuming budget. No links are created; only `retire`
    /// and `retire_uncertain` are called, in reverse attach sequence.
    /// In a forked-but-not-exec'd child this is a no-op returning a
    /// zero report with a truthful usage snapshot.
    pub fn reconcile(&mut self, budget: RetirementBudget) -> PoolReconcile {
        if self.check_process(Stage::Execute).is_err() {
            return PoolReconcile {
                retired_groups: 0,
                pending_groups: 0,
                failed_groups: 0,
                usage: self.usage(),
            };
        }
        let mut ids: Vec<u64> = self.entries.keys().copied().collect();
        ids.sort_unstable();
        let mut retired_groups = 0usize;
        // Free pass: reap effect-free orphans (no native calls needed).
        for id in ids.clone() {
            let reaps = self
                .entries
                .get(&id)
                .map(|entry| !entry.live.get() && entry.outstanding() == 0)
                .unwrap_or(false);
            if reaps {
                self.entries.remove(&id);
                retired_groups += 1;
            }
        }
        // Budgeted native pass over orphaned entries with custody.
        let mut calls = 0usize;
        for id in ids {
            if calls >= budget.max_native_calls {
                break;
            }
            let orphaned = self
                .entries
                .get(&id)
                .map(|entry| !entry.live.get() && entry.outstanding() > 0)
                .unwrap_or(false);
            if !orphaned {
                continue;
            }
            let remaining = budget.max_native_calls.saturating_sub(calls);
            let (made, done) = self.reconcile_entry(id, remaining);
            calls += made;
            if done {
                self.entries.remove(&id);
                retired_groups += 1;
            }
        }
        let mut pending_groups = 0usize;
        let mut failed_groups = 0usize;
        for entry in self.entries.values() {
            if entry.outstanding() == 0 {
                continue;
            }
            if entry.has_failed() {
                failed_groups += 1;
            } else if !entry.is_pure_active() {
                pending_groups += 1;
            }
        }
        PoolReconcile {
            retired_groups,
            pending_groups,
            failed_groups,
            usage: self.usage(),
        }
    }

    /// Attempt to close the pool. `Closed` means no entry remains;
    /// otherwise the pool itself is returned with recovery intact, and
    /// no native call was made.
    pub fn close(self) -> PoolClose<B> {
        if self.entries.is_empty() {
            PoolClose::Closed
        } else {
            PoolClose::Unresolved(self)
        }
    }

    /// Refuse fork-without-exec reuse: native owners belong to the
    /// creating process until an exec boundary re-acquires them.
    pub(crate) fn check_process(&self, stage: Stage) -> Result<(), OperationError> {
        if std::process::id() != self.creating_pid {
            Err(OperationError::new(ErrorKind::Changed, stage, None, None))
        } else {
            Ok(())
        }
    }

    pub(crate) fn session(&self) -> u64 {
        self.session
    }

    pub(crate) fn entry(&self, id: u64) -> Option<&Entry<B>> {
        self.entries.get(&id)
    }

    pub(crate) fn entry_mut(&mut self, id: u64) -> Option<&mut Entry<B>> {
        self.entries.get_mut(&id)
    }

    pub(crate) fn has_group_slot(&self) -> bool {
        self.entries.len() < self.capacity.max_groups
    }

    /// Reserve one group plus the full audited charge before effects.
    /// Overflow in the reservation calculation refuses before effects.
    pub(crate) fn reserve(
        &mut self,
        backend: B,
        authority: B::Authority,
        charge: CustodyCharge,
    ) -> Result<u64, OperationError> {
        if !self.has_group_slot() {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Attach,
                None,
                None,
            ));
        }
        let mut used_links = 0usize;
        let mut used_bytes = 0usize;
        for entry in self.entries.values() {
            used_links = used_links
                .checked_add(entry.charge.link_slots)
                .ok_or_else(|| {
                    OperationError::new(ErrorKind::Overflow, Stage::Attach, None, None)
                })?;
            used_bytes = used_bytes
                .checked_add(entry.charge.retained_bytes)
                .ok_or_else(|| {
                    OperationError::new(ErrorKind::Overflow, Stage::Attach, None, None)
                })?;
        }
        let total_links = used_links
            .checked_add(charge.link_slots)
            .ok_or_else(|| OperationError::new(ErrorKind::Overflow, Stage::Attach, None, None))?;
        let total_bytes = used_bytes
            .checked_add(charge.retained_bytes)
            .ok_or_else(|| OperationError::new(ErrorKind::Overflow, Stage::Attach, None, None))?;
        if total_links > self.capacity.max_links || total_bytes > self.capacity.max_retained_bytes {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Attach,
                None,
                None,
            ));
        }
        let id = self.next_entry;
        self.next_entry = self.next_entry.wrapping_add(1);
        // Orphaned until a ticket is issued: a panic before the outcome
        // leaves a recoverable orphan, never a skipped live entry.
        // Entry ids are never reused, so a ticket for a reaped entry is
        // recognizably stale.
        self.entries.insert(
            id,
            Entry {
                backend,
                authority,
                links: Vec::new(),
                uncertain: Vec::new(),
                charge,
                live: Rc::new(Cell::new(false)),
            },
        );
        Ok(id)
    }

    /// Mark an entry ticket-held and share its liveness flag with the
    /// newly issued ticket. Called only for live entries.
    pub(crate) fn issue_ticket(&mut self, id: u64) -> Rc<Cell<bool>> {
        let entry = self
            .entries
            .get(&id)
            .expect("ticket issued only for a live entry");
        entry.live.set(true);
        Rc::clone(&entry.live)
    }

    /// Retire every outstanding link of one entry in reverse attach
    /// order, leaving uncertain acquisitions open for ticket-driven
    /// recovery. Used by the executor's first-profile rollback: an
    /// uncertain result is terminal retained custody, never something
    /// the walk itself reconciles away.
    pub(crate) fn rollback_links(&mut self, id: u64) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        let Entry { backend, links, .. } = entry;
        for index in (0..links.len()).rev() {
            let mut slot = links.remove(index);
            match backend.retire(slot.state.link_mut()) {
                NativeRetire::Retired => {}
                NativeRetire::Pending => {
                    let link = slot.state.into_link();
                    links.insert(
                        index,
                        LinkSlot {
                            state: LinkState::Pending(link),
                        },
                    );
                }
                NativeRetire::Failed(_) => {
                    let link = slot.state.into_link();
                    links.insert(
                        index,
                        LinkSlot {
                            state: LinkState::Failed(link),
                        },
                    );
                }
            }
        }
    }

    /// Retire every outstanding object of one entry in reverse attach
    /// sequence (links, then uncertain acquisitions), with no call
    /// budget: an explicit caller-driven full pass. Returns the first
    /// failure in retire order, if any. Creates no links.
    pub(crate) fn retire_all(&mut self, id: u64) -> Option<OperationError> {
        let entry = self
            .entries
            .get_mut(&id)
            .expect("retire pass runs only on a live entry");
        let Entry {
            backend,
            links,
            uncertain,
            ..
        } = entry;
        let mut first_error = None;
        for index in (0..links.len()).rev() {
            let mut slot = links.remove(index);
            match backend.retire(slot.state.link_mut()) {
                NativeRetire::Retired => {}
                NativeRetire::Pending => {
                    let link = slot.state.into_link();
                    links.insert(
                        index,
                        LinkSlot {
                            state: LinkState::Pending(link),
                        },
                    );
                }
                NativeRetire::Failed(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    let link = slot.state.into_link();
                    links.insert(
                        index,
                        LinkSlot {
                            state: LinkState::Failed(link),
                        },
                    );
                }
            }
        }
        for index in (0..uncertain.len()).rev() {
            let mut slot = uncertain.remove(index);
            match backend.retire_uncertain(slot.state.custody_mut()) {
                NativeRetire::Retired => {}
                NativeRetire::Pending => {
                    let custody = slot.state.into_custody();
                    uncertain.insert(
                        index,
                        UncertainSlot {
                            state: UncertainState::Pending(custody),
                        },
                    );
                }
                NativeRetire::Failed(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    let custody = slot.state.into_custody();
                    uncertain.insert(
                        index,
                        UncertainSlot {
                            state: UncertainState::Failed(custody),
                        },
                    );
                }
            }
        }
        first_error
    }

    /// Reap an entry whose every object is confirmed retired, releasing
    /// its backend, authority and full charge. Returns whether the
    /// entry was reaped.
    pub(crate) fn reap_if_empty(&mut self, id: u64) -> bool {
        let empty = self
            .entries
            .get(&id)
            .map(|entry| entry.outstanding() == 0)
            .unwrap_or(false);
        if empty {
            self.entries.remove(&id);
        }
        empty
    }

    /// Retire one orphaned entry within a remaining call budget, in
    /// reverse attach sequence. Returns (calls made, fully confirmed).
    fn reconcile_entry(&mut self, id: u64, remaining: usize) -> (usize, bool) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return (0, true);
        };
        let Entry {
            backend,
            links,
            uncertain,
            ..
        } = entry;
        let mut calls = 0usize;
        let mut index = links.len();
        while index > 0 && calls < remaining {
            index -= 1;
            let mut slot = links.remove(index);
            calls += 1;
            match backend.retire(slot.state.link_mut()) {
                NativeRetire::Retired => {}
                NativeRetire::Pending => {
                    let link = slot.state.into_link();
                    links.insert(
                        index,
                        LinkSlot {
                            state: LinkState::Pending(link),
                        },
                    );
                }
                NativeRetire::Failed(_) => {
                    let link = slot.state.into_link();
                    links.insert(
                        index,
                        LinkSlot {
                            state: LinkState::Failed(link),
                        },
                    );
                }
            }
        }
        let mut index = uncertain.len();
        while index > 0 && calls < remaining {
            index -= 1;
            let mut slot = uncertain.remove(index);
            calls += 1;
            match backend.retire_uncertain(slot.state.custody_mut()) {
                NativeRetire::Retired => {}
                NativeRetire::Pending => {
                    let custody = slot.state.into_custody();
                    uncertain.insert(
                        index,
                        UncertainSlot {
                            state: UncertainState::Pending(custody),
                        },
                    );
                }
                NativeRetire::Failed(_) => {
                    let custody = slot.state.into_custody();
                    uncertain.insert(
                        index,
                        UncertainSlot {
                            state: UncertainState::Failed(custody),
                        },
                    );
                }
            }
        }
        (calls, links.is_empty() && uncertain.is_empty())
    }
}

impl<B: AttachBackend> Drop for RetirementPool<B> {
    /// Last resort: with entries remaining, retain the whole charged
    /// state by leaking it. Native destructors must not run here:
    /// running them would detach without proof and pretend a clean
    /// close. Never panics; never calls native code.
    fn drop(&mut self) {
        if !self.entries.is_empty() {
            let entries = std::mem::take(&mut self.entries);
            std::mem::forget(entries);
        }
    }
}

/// Pool close outcome: clean close, or the pool itself with recovery
/// intact. `close` makes no native calls.
pub enum PoolClose<B: AttachBackend> {
    Closed,
    Unresolved(RetirementPool<B>),
}

impl<B: AttachBackend> std::fmt::Debug for PoolClose<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolClose::Closed => write!(f, "Closed"),
            PoolClose::Unresolved(pool) => f.debug_tuple("Unresolved").field(pool).finish(),
        }
    }
}
