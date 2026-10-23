// SPDX-License-Identifier: Apache-2.0
//! Consuming retirement tickets and executor outcome values.
//!
//! ADAPT of the donor ownership discipline: p11scope
//! `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//! @ `2c2713e66292b0d2688508a25f79e813ae823d81` (halt-after-linked-leaf
//! vector, lines 980-1014: the halt closes what it created and counts
//! it) and KryProbe `crates/kryprobe-core/src/attach.rs` @ `d153f3aa`
//! (`d153f3aaf9a3931337b47c9e1b046c692da55083`, issuance-only
//! `LinkGroup` construction, lines 38-80). Tickets here are likewise
//! issuance-only and move-only, but retirement is explicit and
//! per-object: only confirmed native retirement releases custody, and a
//! failed cleanup is a typed error, never inferred success. All
//! user-owned donor slices under blanket `OWNER-2026-10-23`;
//! third-party/upstream lines never copied.

use crate::attach::plan::{AttachBackend, Site};
use crate::attach::pool::RetirementPool;
use crate::{ErrorKind, OperationError, Stage};
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;

/// Effectful walk summary: backend attempts, attached site count and
/// refused sites in plan order. Pure and `Send + Sync`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachSummary {
    pub attempts: usize,
    pub attached_sites: usize,
    pub refused_sites: Vec<Site>,
}

/// Move-only ticket for one fully attached plan entry. There is exactly
/// one ticket per entry; it cannot be cloned, serialized or forged.
/// Consumed by [`AttachmentSet::retire`]; dropping it marks the entry
/// orphaned without releasing anything. `!Send + !Sync`.
pub struct AttachmentSet<B: AttachBackend> {
    session: u64,
    entry: u64,
    live: Option<Rc<Cell<bool>>>,
    backend: PhantomData<B>,
}

impl<B: AttachBackend> std::fmt::Debug for AttachmentSet<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentSet")
            .field("session", &self.session)
            .field("entry", &self.entry)
            .finish()
    }
}

impl<B: AttachBackend> Drop for AttachmentSet<B> {
    /// Mark the entry orphaned. Releases no native object, credit,
    /// authority or charge, and calls no native code. Never panics.
    fn drop(&mut self) {
        if let Some(live) = self.live.as_ref() {
            live.set(false);
        }
    }
}

/// Move-only ticket for retained unresolved custody (pending, failed or
/// uncertain objects). Same single-handle, non-serializable rules as
/// [`AttachmentSet`]. `!Send + !Sync`.
pub struct UnresolvedAttachments<B: AttachBackend> {
    session: u64,
    entry: u64,
    live: Option<Rc<Cell<bool>>>,
    backend: PhantomData<B>,
}

impl<B: AttachBackend> std::fmt::Debug for UnresolvedAttachments<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnresolvedAttachments")
            .field("session", &self.session)
            .field("entry", &self.entry)
            .finish()
    }
}

impl<B: AttachBackend> Drop for UnresolvedAttachments<B> {
    /// Mark the entry orphaned. Releases nothing and calls no native
    /// code. Never panics.
    fn drop(&mut self) {
        if let Some(live) = self.live.as_ref() {
            live.set(false);
        }
    }
}

/// Executor outcome: full success with an active ticket, a proven
/// rollback, or retained unresolved custody with its cause. Uncertain
/// is terminal retained custody, never an ownerless error.
pub enum AttachOutcome<B: AttachBackend> {
    Active {
        owner: AttachmentSet<B>,
        summary: AttachSummary,
    },
    RolledBack {
        summary: AttachSummary,
        cause: OperationError,
    },
    Unresolved {
        custody: UnresolvedAttachments<B>,
        summary: AttachSummary,
        cause: OperationError,
    },
}

impl<B: AttachBackend> std::fmt::Debug for AttachOutcome<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachOutcome::Active { owner, summary } => f
                .debug_struct("Active")
                .field("owner", owner)
                .field("summary", summary)
                .finish(),
            AttachOutcome::RolledBack { summary, cause } => f
                .debug_struct("RolledBack")
                .field("summary", summary)
                .field("cause", cause)
                .finish(),
            AttachOutcome::Unresolved {
                custody,
                summary,
                cause,
            } => f
                .debug_struct("Unresolved")
                .field("custody", custody)
                .field("summary", summary)
                .field("cause", cause)
                .finish(),
        }
    }
}

/// Retirement outcome: proven `Retired`, still-`Pending` custody, or a
/// typed `Failed` error with custody for retry. Pending and Failed
/// release no credit and destroy no link value.
pub enum Retirement<B: AttachBackend> {
    Retired,
    Pending(UnresolvedAttachments<B>),
    Failed {
        custody: UnresolvedAttachments<B>,
        error: OperationError,
    },
}

impl<B: AttachBackend> std::fmt::Debug for Retirement<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Retirement::Retired => write!(f, "Retired"),
            Retirement::Pending(custody) => f.debug_tuple("Pending").field(custody).finish(),
            Retirement::Failed { custody, error } => f
                .debug_struct("Failed")
                .field("custody", custody)
                .field("error", error)
                .finish(),
        }
    }
}

impl<B: AttachBackend> AttachmentSet<B> {
    pub(crate) fn issued(session: u64, entry: u64, live: Rc<Cell<bool>>) -> Self {
        Self {
            session,
            entry,
            live: Some(live),
            backend: PhantomData,
        }
    }

    /// Retire every object of this entry through its home pool.
    ///
    /// Consumes the ticket and runs one full reverse-sequence retire
    /// pass with no call budget. `Retired` releases the original
    /// authority and the full charge only after every object is
    /// confirmed gone. `Pending`/`Failed` return custody with charges
    /// intact; `Failed` carries the first failure in retire order.
    /// Foreign-pool, wrong-process and stale-entry refusals return the
    /// ticket as custody without any native call. Creates no links.
    pub fn retire(mut self, pool: &mut RetirementPool<B>) -> Retirement<B> {
        // Take the flag so Drop does not mark; it is re-homed below.
        let live = self.live.take();
        if let Err(error) = pool.check_process(Stage::Retire) {
            return Retirement::Failed {
                custody: UnresolvedAttachments {
                    session: self.session,
                    entry: self.entry,
                    live,
                    backend: PhantomData,
                },
                error,
            };
        }
        if pool.session() != self.session {
            return Retirement::Failed {
                custody: UnresolvedAttachments {
                    session: self.session,
                    entry: self.entry,
                    live,
                    backend: PhantomData,
                },
                error: OperationError::new(ErrorKind::InvalidInput, Stage::Retire, None, None),
            };
        }
        if pool.entry(self.entry).is_none() {
            // Defensive: the single-handle ticket discipline makes this
            // unreachable through public API (reaping consumes or
            // outlives the only handle), but a stale handle must refuse
            // safely rather than touch a stranger entry.
            return Retirement::Failed {
                custody: UnresolvedAttachments {
                    session: self.session,
                    entry: self.entry,
                    live,
                    backend: PhantomData,
                },
                error: OperationError::new(ErrorKind::InvalidInput, Stage::Retire, None, None),
            };
        }
        retire_entry(pool, self.entry, self.session, live)
    }
}

impl<B: AttachBackend> UnresolvedAttachments<B> {
    pub(crate) fn issued(session: u64, entry: u64, live: Rc<Cell<bool>>) -> Self {
        Self {
            session,
            entry,
            live: Some(live),
            backend: PhantomData,
        }
    }

    /// Retry one full reverse-sequence retire pass through the home
    /// pool. Same outcome contract as [`AttachmentSet::retire`]:
    /// consumes this handle, creates no links, and returns custody on
    /// anything but proven retirement.
    pub fn retry_retire(mut self, pool: &mut RetirementPool<B>) -> Retirement<B> {
        let live = self.live.take();
        if let Err(error) = pool.check_process(Stage::Retire) {
            return Retirement::Failed {
                custody: UnresolvedAttachments {
                    session: self.session,
                    entry: self.entry,
                    live,
                    backend: PhantomData,
                },
                error,
            };
        }
        if pool.session() != self.session {
            return Retirement::Failed {
                custody: UnresolvedAttachments {
                    session: self.session,
                    entry: self.entry,
                    live,
                    backend: PhantomData,
                },
                error: OperationError::new(ErrorKind::InvalidInput, Stage::Retire, None, None),
            };
        }
        if pool.entry(self.entry).is_none() {
            return Retirement::Failed {
                custody: UnresolvedAttachments {
                    session: self.session,
                    entry: self.entry,
                    live,
                    backend: PhantomData,
                },
                error: OperationError::new(ErrorKind::InvalidInput, Stage::Retire, None, None),
            };
        }
        retire_entry(pool, self.entry, self.session, live)
    }

    /// Count outstanding unconfirmed objects (links plus uncertain
    /// acquisitions) in the home pool. Borrows the ticket; makes no
    /// native calls. Foreign-pool, wrong-process and stale-entry
    /// handles refuse with a typed error.
    pub fn remaining_links(&self, pool: &RetirementPool<B>) -> Result<usize, OperationError> {
        pool.check_process(Stage::Retire)?;
        if pool.session() != self.session {
            return Err(OperationError::new(
                ErrorKind::InvalidInput,
                Stage::Retire,
                None,
                None,
            ));
        }
        match pool.entry(self.entry) {
            Some(entry) => Ok(entry.links.len() + entry.uncertain.len()),
            None => Err(OperationError::new(
                ErrorKind::InvalidInput,
                Stage::Retire,
                None,
                None,
            )),
        }
    }
}

/// Shared retire/retry body: one full pass, then reap-and-report or
/// return custody. `live` is the ticket's flag, already detached from
/// its `Drop`; it is cleared on `Retired` and re-homed otherwise.
fn retire_entry<B: AttachBackend>(
    pool: &mut RetirementPool<B>,
    id: u64,
    session: u64,
    live: Option<Rc<Cell<bool>>>,
) -> Retirement<B> {
    let first_error = pool.retire_all(id);
    if pool.reap_if_empty(id) {
        if let Some(live) = live {
            live.set(false);
        }
        return Retirement::Retired;
    }
    let custody = UnresolvedAttachments {
        session,
        entry: id,
        live,
        backend: PhantomData,
    };
    match first_error {
        Some(error) => Retirement::Failed { custody, error },
        None => Retirement::Pending(custody),
    }
}
