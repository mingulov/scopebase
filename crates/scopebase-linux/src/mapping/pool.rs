// SPDX-License-Identifier: Apache-2.0
// LX06 caller-owned mapping accounting domains, reservation and retirement.
//
// NEW (frozen LX06 contract, 2026-10-17 linux design "Mapping evidence and
// calibration"): no donor slice implements a shared calibration accounting
// domain with preallocated unresolved custody, Retiring exclusivity, terminal
// retention or the Open/Closing/Closed admission protocol. The donor
// calibration (P src/attach/instance.rs `calibrate` @2c2713e6) maps and
// unmaps inline with no pool; reservation-before-effect and the drain/close
// state machine are new vocabulary the contract requires. D03 scoped grant
// (2026-10-23) covers GPL-source to Apache-2.0 destination inside this
// library; donor files/terms untouched.
//
// Design: one `MappingPool` clone family shares one `Shared` domain behind a
// short mutex that is never held across mmap/munmap, proc reads or user code.
// Every calibration reserves its slot, page-rounded byte charge and held
// owner BEFORE mmap; a pre-effect failure returns the reservation, a
// successful mmap transfers it to active custody, and only a successful
// checked munmap releases the charge. A failed Drop-time munmap transfers the
// complete record into the preallocated unresolved queue without allocation,
// and a private self-anchor retains the queue when the last public handle
// disappears (terminal unresolved retention, not cleanup).
use crate::{
    control::OperationControl,
    error::{
        CleanupDisposition, DescriptorFlagEffect, EffectSummary, LimitKind, LinuxError, Reason,
        ResourceCharges, Stage,
    },
    file::HeldFile,
};
use std::{
    ffi::c_void,
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

/// Preallocated unresolved records per domain. Queued Drop-transfers within
/// this bound never allocate; beyond it a bounded `try_reserve` runs before
/// the push, and a failed reserve deliberately leaks that one record's charge
/// (documented below) rather than aborting the process from Drop.
const PREALLOC_UNRESOLVED: usize = 65_536;

static NEXT_DOMAIN: AtomicU64 = AtomicU64::new(1);

/// Explicit domain ceilings. `(0, 0)` together is the valid no-new domain;
/// otherwise both are nonzero.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MappingPoolLimits {
    pub max_mappings: usize,
    pub max_mapped_bytes: usize,
}

/// Admission phase of the shared domain. `Closing`/`Closed` block admission
/// across every clone; a closed domain never reopens.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Phase {
    Open,
    Closing,
    Closed,
}

/// One unretired mapping owned by the domain queue: the exact address/length
/// to munmap, the original held owner (charge retained) and its byte charge.
/// `retiring` gives per-slot exclusive reconciliation: at most one retry or
/// drain holds a record outside the lock.
///
/// R10: `id` is the record's identity for claim/commit/cancel. Address
/// tokens do NOT identify records: after a successful unmap the kernel
/// may hand the same range to a later mapping, so two queued records can
/// share `(addr, len)` and a first-match removal can drop the live one.
struct UnresolvedRecord {
    id: u64,
    addr: *mut c_void,
    len: usize,
    // Retained owner: keeps the file authority and its charge alive with the
    // unretired mapping, never re-queried after queueing.
    #[allow(dead_code)]
    held: Arc<HeldFile>,
    bytes: usize,
    retiring: bool,
}

// The address is an opaque munmap token, touched only under the Retiring
// transition that guarantees single ownership outside the state lock; the
// length/bytes are plain data and HeldFile is Send+Sync.
unsafe impl Send for UnresolvedRecord {}
unsafe impl Sync for UnresolvedRecord {}

/// Domain counters. Invariant: `active_mappings + reserved_mappings +
/// unresolved.len() <= max_mappings` (and the byte analogue), so a queued
/// Drop-transfer within the preallocation never grows the queue.
pub(crate) struct Inner {
    phase: Phase,
    active_ops: usize,
    active_mappings: usize,
    active_bytes: usize,
    reserved_mappings: usize,
    reserved_bytes: usize,
    unresolved: Vec<UnresolvedRecord>,
    /// R10: next queued-record id. Assigned under the state lock, starts
    /// at 1 so 0 never names a record.
    next_unresolved_id: u64,
}

impl Inner {
    fn occupied_mappings(&self) -> usize {
        self.active_mappings + self.reserved_mappings + self.unresolved.len()
    }
    fn occupied_bytes(&self) -> usize {
        self.active_bytes
            + self.reserved_bytes
            + self
                .unresolved
                .iter()
                .map(|record| record.bytes)
                .sum::<usize>()
    }
    fn occupied(&self) -> bool {
        self.occupied_mappings() > 0
    }
}

pub(crate) struct Shared {
    id: u64,
    limits: MappingPoolLimits,
    state: Mutex<Inner>,
    /// Terminal-retention self-anchor: set when a pool handle drops with
    /// occupied records, released after the last occupied record retires with
    /// no active work.
    ///
    /// R44: lock order is state-then-anchor. Both install (`Drop`) and
    /// release (`release_anchor_if_empty`) hold the state lock across the
    /// anchor lock, so a retirement cannot erase an anchor installed for
    /// newly acquired custody between the two steps. (An earlier revision
    /// of this doc forbade nesting; the F07 order requires it.)
    anchor: Mutex<Option<Arc<Shared>>>,
    /// R43: forced-interleaving hooks. Test-only; production builds carry
    /// no hook state and no hook calls.
    #[cfg(test)]
    test_hooks: TestHooks,
}

/// R43: forced-interleaving hooks for drain/permit/anchor tests. Each
/// hook runs OUTSIDE the state lock at a documented quiescent point. A
/// hook must not call back into pool operations that take the state
/// lock; blocking on test channels is the intended use. Hooks are
/// reference-counted so concurrent drains can each hold one while
/// blocked: firing clones the Arc under the slot lock and invokes it
/// after release, never holding the slot across the call.
#[cfg(test)]
type ClaimHook = Arc<dyn Fn(u64) + Send + Sync>;
#[cfg(test)]
type UnitHook = Arc<dyn Fn() + Send + Sync>;

#[cfg(test)]
pub(crate) struct TestHooks {
    /// After a drain claims a record (`retiring` set, claim recorded),
    /// before the cancel checkpoint and unmap. Receives the record id.
    pub(crate) after_claim: Mutex<Option<ClaimHook>>,
    /// S46: after a drain's unmap succeeds, before the commit lock
    /// removes the record by id. Receives the record id. Lets the
    /// R10 recycle test force the true post-unmap/precommit
    /// interleaving: the replacement maps and queues while the
    /// stale claim is still open.
    pub(crate) before_commit: Mutex<Option<ClaimHook>>,
    /// In `ActivePermit::retire` after the counters update, before the
    /// anchor release check.
    pub(crate) after_retire_counters: Mutex<Option<UnitHook>>,
    /// In `release_anchor_if_empty` when the anchor is actually released.
    pub(crate) anchor_releasing: Mutex<Option<UnitHook>>,
}

#[cfg(test)]
impl TestHooks {
    fn new() -> Self {
        Self {
            after_claim: Mutex::new(None),
            before_commit: Mutex::new(None),
            after_retire_counters: Mutex::new(None),
            anchor_releasing: Mutex::new(None),
        }
    }
}

#[cfg(test)]
fn fire_after_claim(shared: &Shared, id: u64) {
    let hook = shared.test_hooks.after_claim.lock().unwrap().clone();
    if let Some(hook) = hook {
        hook(id);
    }
}

#[cfg(test)]
fn fire_before_commit(shared: &Shared, id: u64) {
    let hook = shared.test_hooks.before_commit.lock().unwrap().clone();
    if let Some(hook) = hook {
        hook(id);
    }
}

#[cfg(test)]
fn fire_after_retire_counters(shared: &Shared) {
    let hook = shared
        .test_hooks
        .after_retire_counters
        .lock()
        .unwrap()
        .clone();
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn fire_anchor_releasing(shared: &Shared) {
    let hook = shared.test_hooks.anchor_releasing.lock().unwrap().clone();
    if let Some(hook) = hook {
        hook();
    }
}

/// Caller-owned mapping accounting domain. Clones share one domain: charges
/// are never reset by a fresh operation or a reconstructed handle, and a
/// `Closing`/`Closed` transition binds every clone. Limits are domain-scoped;
/// a separately constructed pool is an explicit additional budget.
pub struct MappingPool {
    pub(crate) shared: Arc<Shared>,
}

impl Clone for MappingPool {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl fmt::Debug for MappingPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MappingPool")
    }
}

/// Domain identity plus active/unresolved/reserved mapping and byte counts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MappingPoolStatus {
    domain: u64,
    active_mappings: usize,
    active_bytes: usize,
    unresolved_mappings: usize,
    unresolved_bytes: usize,
    reserved_mappings: usize,
    reserved_bytes: usize,
}

impl MappingPoolStatus {
    pub fn domain(&self) -> u64 {
        self.domain
    }
    pub fn active_mappings(&self) -> usize {
        self.active_mappings
    }
    pub fn active_bytes(&self) -> usize {
        self.active_bytes
    }
    pub fn unresolved_mappings(&self) -> usize {
        self.unresolved_mappings
    }
    pub fn unresolved_bytes(&self) -> usize {
        self.unresolved_bytes
    }
    pub fn reserved_mappings(&self) -> usize {
        self.reserved_mappings
    }
    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }
}

/// One drain pass over this domain's queued records: attempted/retired counts,
/// the remaining unresolved count and one error per failed record. Records
/// owned by another domain, and live `MappingCustody` handles outside the
/// queue, are never touched.
#[derive(Debug)]
pub struct MappingDrainReport {
    attempted: usize,
    retired: usize,
    unresolved: usize,
    errors: Vec<LinuxError>,
}

impl MappingDrainReport {
    pub fn attempted(&self) -> usize {
        self.attempted
    }
    pub fn retired(&self) -> usize {
        self.retired
    }
    pub fn unresolved(&self) -> usize {
        self.unresolved
    }
    pub fn errors(&self) -> &[LinuxError] {
        &self.errors
    }
}

/// Proof that one domain reached `Closed` with zero occupied records and no
/// active operation. Proves closure only for that domain.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MappingPoolClosed {
    domain: u64,
}

impl MappingPoolClosed {
    pub fn domain(&self) -> u64 {
        self.domain
    }
}

/// Failed close: the still-live `Closing` domain for drain/close retry, the
/// reconciliation report and the blocking error.
#[derive(Debug)]
pub struct MappingPoolCloseFailure {
    pool: MappingPool,
    report: MappingDrainReport,
    error: LinuxError,
}

impl MappingPoolCloseFailure {
    pub fn into_pool(self) -> MappingPool {
        self.pool
    }
    pub fn report(&self) -> &MappingDrainReport {
        &self.report
    }
    pub fn error(&self) -> &LinuxError {
        &self.error
    }
}

pub(crate) fn zero_charges() -> ResourceCharges {
    ResourceCharges {
        syscalls: 0,
        acquired: 0,
        peak: 0,
        read: None,
        parse: None,
        #[cfg(feature = "process")]
        process: None,
    }
}

pub(crate) fn pool_error(stage: Stage, reason: Reason, cleanup: CleanupDisposition) -> LinuxError {
    LinuxError {
        parse_line: None,
        stage,
        reason,
        source: None,
        effect: EffectSummary {
            attempted: 0,
            completed: 0,
            cleanup,
            flags: DescriptorFlagEffect::NotAttempted,
        },
        charges: zero_charges(),
        #[cfg(feature = "process")]
        process: None,
    }
}

/// Observer-side syscall error with its actual errno preserved.
pub(crate) fn pool_error_with_source(stage: Stage, errno: rustix::io::Errno) -> LinuxError {
    LinuxError {
        parse_line: None,
        stage,
        reason: crate::process::map_errno(errno),
        source: Some(errno.into()),
        effect: EffectSummary {
            attempted: 1,
            completed: 0,
            cleanup: CleanupDisposition::Complete,
            flags: DescriptorFlagEffect::NotAttempted,
        },
        charges: zero_charges(),
        #[cfg(feature = "process")]
        process: None,
    }
}

impl MappingPool {
    pub fn new(limits: MappingPoolLimits) -> Result<Self, LinuxError> {
        let coherent = (limits.max_mappings == 0 && limits.max_mapped_bytes == 0)
            || (limits.max_mappings > 0 && limits.max_mapped_bytes > 0);
        if !coherent {
            return Err(pool_error(
                Stage::ConfigureMapping,
                Reason::InvalidInput,
                CleanupDisposition::NotNeeded,
            ));
        }
        Ok(Self {
            shared: Arc::new(Shared {
                id: NEXT_DOMAIN.fetch_add(1, Ordering::SeqCst),
                limits,
                state: Mutex::new(Inner {
                    phase: Phase::Open,
                    active_ops: 0,
                    active_mappings: 0,
                    active_bytes: 0,
                    reserved_mappings: 0,
                    reserved_bytes: 0,
                    unresolved: Vec::with_capacity(limits.max_mappings.min(PREALLOC_UNRESOLVED)),
                    next_unresolved_id: 1,
                }),
                anchor: Mutex::new(None),
                #[cfg(test)]
                test_hooks: TestHooks::new(),
            }),
        })
    }

    pub fn status(&self) -> MappingPoolStatus {
        let state = lock_report(&self.shared);
        MappingPoolStatus {
            domain: self.shared.id,
            active_mappings: state.active_mappings,
            active_bytes: state.active_bytes,
            unresolved_mappings: state.unresolved.len(),
            unresolved_bytes: state.unresolved.iter().map(|record| record.bytes).sum(),
            reserved_mappings: state.reserved_mappings,
            reserved_bytes: state.reserved_bytes,
        }
    }

    /// Attempt every queued record owned by this domain. Failed records stay
    /// queued with their charges; records already under retry elsewhere are
    /// skipped, never double-driven.
    pub fn retry_unresolved(&self, control: &OperationControl) -> MappingDrainReport {
        drain_shared(&self.shared, control)
    }

    /// R10/R43: test-only queue introspection: `(id, addr, len, retiring)`
    /// per queued record in queue order. Lets forced-interleaving tests
    /// assert WHICH record a commit removed, not just the count.
    #[cfg(test)]
    pub(crate) fn queue_snapshot(&self) -> Vec<(u64, *mut c_void, usize, bool)> {
        let state = lock_report(&self.shared);
        state
            .unresolved
            .iter()
            .map(|record| (record.id, record.addr, record.len, record.retiring))
            .collect()
    }

    /// Admission-stop commit then reconciliation. Cancellation before the
    /// state transition returns the unchanged `Open` pool. Otherwise the
    /// shared domain moves `Open -> Closing` (blocking new admissions through
    /// every clone) before any munmap runs; `Closed` requires zero occupied
    /// records and no active operation.
    pub fn close(
        self,
        control: &OperationControl,
    ) -> Result<MappingPoolClosed, MappingPoolCloseFailure> {
        if let Err(stop) = control.checkpoint() {
            let report = self.empty_drain_report();
            return Err(MappingPoolCloseFailure {
                pool: self,
                report,
                error: pool_error(
                    Stage::ObserveMapping,
                    stop_reason(stop),
                    CleanupDisposition::Complete,
                ),
            });
        }
        {
            let mut state = lock_report(&self.shared);
            match state.phase {
                Phase::Closed => {
                    return Ok(MappingPoolClosed {
                        domain: self.shared.id,
                    });
                }
                Phase::Open => {
                    state.phase = Phase::Closing;
                }
                Phase::Closing => {}
            }
        }
        let report = drain_shared(&self.shared, control);
        let blocked = {
            let mut state = lock_report(&self.shared);
            if !state.occupied() && state.active_ops == 0 {
                state.phase = Phase::Closed;
                None
            } else if state.active_ops > 0 {
                Some(pool_error(
                    Stage::ObserveMapping,
                    Reason::Unavailable,
                    CleanupDisposition::Complete,
                ))
            } else {
                Some(pool_error(
                    Stage::RetireMapping,
                    Reason::Unavailable,
                    CleanupDisposition::Unresolved,
                ))
            }
        };
        match blocked {
            None => {
                release_anchor_if_empty(&self.shared);
                Ok(MappingPoolClosed {
                    domain: self.shared.id,
                })
            }
            Some(mut error) => {
                // A concrete drain error describes the block better than the
                // synthesized one; either way the domain stays Closing.
                if let Some(first) = report.errors.first() {
                    error = clone_error(first);
                }
                Err(MappingPoolCloseFailure {
                    pool: self,
                    report,
                    error,
                })
            }
        }
    }

    fn empty_drain_report(&self) -> MappingDrainReport {
        let state = lock_report(&self.shared);
        MappingDrainReport {
            attempted: 0,
            retired: 0,
            unresolved: state.unresolved.len(),
            errors: Vec::new(),
        }
    }
}

impl Drop for MappingPool {
    fn drop(&mut self) {
        // Any drop with occupied records anchors the queue: if this was the
        // last public handle the state, file owners and charges stay retained
        // indefinitely (terminal unresolved retention). The anchor releases
        // when the last record retires with no active work. F07: the check
        // and the install hold the state lock across the anchor lock
        // (state-then-anchor, matching `release_anchor_if_empty`).
        let state = lock_report(&self.shared);
        if state.occupied() {
            *lock_anchor(&self.shared) = Some(Arc::clone(&self.shared));
        }
    }
}

fn clone_error(error: &LinuxError) -> LinuxError {
    LinuxError {
        parse_line: error.parse_line(),
        stage: error.stage(),
        reason: error.reason(),
        source: error
            .source()
            .map(|source| std::io::Error::from_raw_os_error(source.raw_os_error().unwrap_or(0))),
        effect: error.effect().clone(),
        charges: error.charges().clone(),
        #[cfg(feature = "process")]
        process: error.process_context().copied(),
    }
}

/// Admission-path lock: a poisoned mutex refuses new work with Unavailable.
/// Queued records stay anchored for explicit unresolved reporting.
pub(crate) fn lock_admission(shared: &Shared) -> Result<MutexGuard<'_, Inner>, LinuxError> {
    shared.state.lock().map_err(|_| {
        pool_error(
            Stage::ObserveMapping,
            Reason::Unavailable,
            CleanupDisposition::Complete,
        )
    })
}

/// Reporting-path lock: status, drain, close reconciliation and Drop-time
/// transfers proceed through the poisoned guard's contents instead of losing
/// anchored custody.
pub(crate) fn lock_report(shared: &Shared) -> MutexGuard<'_, Inner> {
    shared
        .state
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn lock_anchor(shared: &Shared) -> MutexGuard<'_, Option<Arc<Shared>>> {
    shared
        .anchor
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Release the terminal-retention anchor once the domain holds nothing and no
/// operation is in flight. F07: the occupancy check and the anchor
/// mutation hold the state lock across the anchor lock (order
/// state-then-anchor, matching `Drop`), so a retirement cannot erase an
/// anchor installed for newly acquired custody between the two steps.
pub(crate) fn release_anchor_if_empty(shared: &Shared) {
    let state = lock_report(shared);
    if !state.occupied() && state.active_ops == 0 {
        lock_anchor(shared).take();
        drop(state);
        #[cfg(test)]
        fire_anchor_releasing(shared);
    }
}

/// RAII active-operation registration: `close` cannot report clean shutdown
/// while an admitted operation runs on any clone.
pub(crate) struct OpGuard {
    shared: Arc<Shared>,
}

impl OpGuard {
    pub(crate) fn admit(pool: &MappingPool) -> Result<Self, LinuxError> {
        let mut state = lock_admission(&pool.shared)?;
        if state.phase != Phase::Open {
            return Err(pool_error(
                Stage::ObserveMapping,
                Reason::WrongContext,
                CleanupDisposition::Complete,
            ));
        }
        state.active_ops += 1;
        Ok(Self {
            shared: Arc::clone(&pool.shared),
        })
    }

    pub(crate) fn domain(&self) -> &Arc<Shared> {
        &self.shared
    }
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        {
            let mut state = lock_report(&self.shared);
            state.active_ops = state.active_ops.saturating_sub(1);
        }
        release_anchor_if_empty(&self.shared);
    }
}

impl fmt::Debug for OpGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpGuard")
    }
}

/// Pre-effect reservation: one slot plus page-rounded bytes, held from before
/// mmap until the mapping either activates or the attempt fails. Drop without
/// activation returns the reservation; activation consumes it.
pub(crate) struct Reservation {
    shared: Arc<Shared>,
    bytes: usize,
    consumed: bool,
}

impl Reservation {
    pub(crate) fn reserve(shared: &Arc<Shared>, bytes: usize) -> Result<Self, LinuxError> {
        let mut state = lock_admission(shared)?;
        if state.phase != Phase::Open {
            return Err(pool_error(
                Stage::ObserveMapping,
                Reason::WrongContext,
                CleanupDisposition::Complete,
            ));
        }
        if state.occupied_mappings() + 1 > shared.limits.max_mappings {
            return Err(pool_error(
                Stage::MapCalibration,
                Reason::LimitExceeded(LimitKind::Mappings),
                CleanupDisposition::Complete,
            ));
        }
        if state.occupied_bytes().saturating_add(bytes) > shared.limits.max_mapped_bytes {
            return Err(pool_error(
                Stage::MapCalibration,
                Reason::LimitExceeded(LimitKind::MappedBytes),
                CleanupDisposition::Complete,
            ));
        }
        state.reserved_mappings += 1;
        state.reserved_bytes = state.reserved_bytes.saturating_add(bytes);
        Ok(Self {
            shared: Arc::clone(shared),
            bytes,
            consumed: false,
        })
    }

    pub(crate) fn activate(
        mut self,
        addr: *mut c_void,
        len: usize,
        held: Arc<HeldFile>,
    ) -> ActivePermit {
        {
            let mut state = lock_report(&self.shared);
            state.reserved_mappings = state.reserved_mappings.saturating_sub(1);
            state.reserved_bytes = state.reserved_bytes.saturating_sub(self.bytes);
            state.active_mappings += 1;
            state.active_bytes = state.active_bytes.saturating_add(self.bytes);
        }
        self.consumed = true;
        ActivePermit {
            shared: Arc::clone(&self.shared),
            addr,
            len,
            held,
            bytes: self.bytes,
            settled: false,
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        {
            let mut state = lock_report(&self.shared);
            state.reserved_mappings = state.reserved_mappings.saturating_sub(1);
            state.reserved_bytes = state.reserved_bytes.saturating_sub(self.bytes);
        }
        release_anchor_if_empty(&self.shared);
    }
}

impl fmt::Debug for Reservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Reservation")
    }
}

/// Nonforgeable live-mapping permit: the pool charge for one successful mmap.
/// `retire` (after a checked munmap) and `unresolved` (after a failed one)
/// consume it; a stray drop leaks the charge rather than freeing it early.
pub(crate) struct ActivePermit {
    shared: Arc<Shared>,
    addr: *mut c_void,
    len: usize,
    held: Arc<HeldFile>,
    bytes: usize,
    settled: bool,
}

impl ActivePermit {
    pub(crate) fn addr(&self) -> *mut c_void {
        self.addr
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Release the mapping/byte/owner charge after a successful checked
    /// munmap. The only path that frees capacity.
    pub(crate) fn retire(mut self) {
        let shared = Arc::clone(&self.shared);
        {
            let mut state = lock_report(&self.shared);
            state.active_mappings = state.active_mappings.saturating_sub(1);
            state.active_bytes = state.active_bytes.saturating_sub(self.bytes);
        }
        #[cfg(test)]
        fire_after_retire_counters(&shared);
        self.settled = true;
        drop(self);
        release_anchor_if_empty(&shared);
    }

    /// Transfer the complete still-charged record into the preallocated
    /// unresolved queue. Within the preallocation this never allocates; past
    /// it a bounded `try_reserve` runs first, and only a failed reserve under
    /// memory pressure deliberately leaks the one record's charge instead of
    /// aborting from Drop.
    pub(crate) fn unresolved(mut self) {
        let (addr, len, bytes) = (self.addr, self.len, self.bytes);
        {
            let mut state = lock_report(&self.shared);
            state.active_mappings = state.active_mappings.saturating_sub(1);
            state.active_bytes = state.active_bytes.saturating_sub(self.bytes);
            // R10: the id is assigned under the lock with the queue push,
            // so queue order and id order agree. The counter skips 0, so 0
            // never names a record.
            let id = state.next_unresolved_id;
            state.next_unresolved_id = state.next_unresolved_id.wrapping_add(1).max(1);
            let record = UnresolvedRecord {
                id,
                addr,
                len,
                held: Arc::clone(&self.held),
                bytes,
                retiring: false,
            };
            if state.unresolved.len() == state.unresolved.capacity()
                && state.unresolved.try_reserve(1).is_err()
            {
                // Out of queue memory in the one place that must not fail:
                // leak this record's charge deliberately. The mapping stays
                // mapped and the owner stays owned; capacity is conservatively
                // retained by never accounting the loss. Reachable only past
                // 65,536 queued records under allocation failure.
                std::mem::forget(record);
                state.active_mappings += 1;
                state.active_bytes = state.active_bytes.saturating_add(self.bytes);
                self.settled = true;
                return;
            }
            state.unresolved.push(record);
        }
        self.settled = true;
    }
}

// Single-owned munmap token plus a Send+Sync owner: transfers are
// consume-only (`retire`/`unresolved`), so no aliasing crosses threads.
unsafe impl Send for ActivePermit {}
unsafe impl Sync for ActivePermit {}

impl Drop for ActivePermit {
    fn drop(&mut self) {
        // `retire`/`unresolved` consume the permit; reaching Drop unsettled
        // is a logic bug. Leak the charge (never free it early) and flag it
        // in tests.
        debug_assert!(
            self.settled,
            "ActivePermit dropped without retire/unresolved"
        );
    }
}

impl fmt::Debug for ActivePermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActivePermit")
    }
}

/// One drain pass: claim each idle queued record under its Retiring flag, run
/// the munmap with no lock held, then commit or requeue under the lock.
/// Cancellation stops the pass with the remaining records still queued. Each
/// record present at pass start is attempted at most once; records queued
/// concurrently wait for the next pass, so a persistently failing record can
/// never spin the pass forever.
fn drain_shared(shared: &Arc<Shared>, control: &OperationControl) -> MappingDrainReport {
    let mut attempted = 0usize;
    let mut retired = 0usize;
    let mut errors = Vec::new();
    if let Err(stop) = control.checkpoint() {
        let unresolved = lock_report(shared).unresolved.len();
        return MappingDrainReport {
            attempted,
            retired,
            unresolved,
            errors: vec![pool_error(
                Stage::RetireMapping,
                stop_reason(stop),
                CleanupDisposition::Unresolved,
            )],
        };
    }
    let budget = lock_report(shared).unresolved.len();
    // R10: claim/commit/cancel match by record id, never by (addr, len).
    // Address ranges recycle across unmap/remap, so two queued records
    // can share a token; the id names the claimed record exactly even
    // when a concurrent drain reorders the queue under us.
    let mut tried: Vec<u64> = Vec::new();
    for _ in 0..budget {
        let claim = {
            let mut state = lock_report(shared);
            let index = state
                .unresolved
                .iter()
                .position(|record| !record.retiring && !tried.contains(&record.id));
            match index {
                None => None,
                Some(index) => {
                    state.unresolved[index].retiring = true;
                    let record = &state.unresolved[index];
                    Some((record.id, record.addr, record.len))
                }
            }
        };
        let Some((id, addr, len)) = claim else {
            break;
        };
        tried.push(id);
        #[cfg(test)]
        fire_after_claim(shared, id);
        // No pool lock is held across the unmap attempt.
        if let Err(stop) = control.checkpoint() {
            let mut state = lock_report(shared);
            // F06/R10: restore by id, not by the claim-time index: a
            // concurrent drain may have shifted the queue under us.
            if let Some(record) = state.unresolved.iter_mut().find(|record| record.id == id) {
                record.retiring = false;
            }
            errors.push(pool_error(
                Stage::RetireMapping,
                stop_reason(stop),
                CleanupDisposition::Unresolved,
            ));
            break;
        }
        attempted += 1;
        match super::custody::unmap_raw(addr, len) {
            Ok(()) => {
                #[cfg(test)]
                fire_before_commit(shared, id);
                let mut state = lock_report(shared);
                // The queue may have shifted under a concurrent drain, and
                // the range may have been recycled into a second queued
                // record; remove the claimed id, never the first token
                // match (which could be the live record).
                if let Some(position) = state.unresolved.iter().position(|record| record.id == id) {
                    state.unresolved.swap_remove(position);
                }
                retired += 1;
            }
            Err(error) => {
                let mut state = lock_report(shared);
                if let Some(record) = state.unresolved.iter_mut().find(|record| record.id == id) {
                    record.retiring = false;
                }
                errors.push(error);
            }
        }
    }
    let unresolved = lock_report(shared).unresolved.len();
    release_anchor_if_empty(shared);
    MappingDrainReport {
        attempted,
        retired,
        unresolved,
        errors,
    }
}

fn stop_reason(stop: crate::control::ControlStop) -> Reason {
    match stop {
        crate::control::ControlStop::Cancelled => Reason::Cancelled,
        crate::control::ControlStop::Deadline => Reason::Deadline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{CancelToken, OperationControl};
    use crate::file::{ProcFdResolver, SymlinkPolicy};
    use std::os::fd::AsFd;

    fn test_pool(max_mappings: usize, max_bytes: usize) -> MappingPool {
        MappingPool::new(MappingPoolLimits {
            max_mappings,
            max_mapped_bytes: max_bytes,
        })
        .unwrap()
    }

    fn test_held(name: &str) -> (std::path::PathBuf, Arc<HeldFile>) {
        let path =
            std::env::temp_dir().join(format!("lx06-pool-{}-{name}.dat", std::process::id()));
        std::fs::write(&path, vec![9u8; 8192]).unwrap();
        let resolver = ProcFdResolver::open_self().unwrap();
        let held = Arc::new(HeldFile::open(&path, &resolver, SymlinkPolicy::Follow).unwrap());
        (path, held)
    }

    fn test_mmap(held: &HeldFile, len: usize) -> *mut c_void {
        unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                len,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE,
                held.as_fd(),
                0,
            )
        }
        .unwrap()
    }

    /// R10: remap `len` bytes at the exact address `addr` (which must be
    /// currently unmapped). Deterministic address reuse for the recycle
    /// regression; a floating mmap would only usually reuse the range.
    /// S46: non-clobbering fixed placement. `FIXED_NOREPLACE`
    /// refuses with `EEXIST` when any page of the range is occupied
    /// instead of silently destroying whatever a competitor mapped
    /// there after our unmap; the returned address is validated to
    /// be exactly the requested range. An `EEXIST` here is a loud
    /// test-assumption violation (a competitor stole the hole),
    /// never silent corruption. Callers hold `FD_TABLE`, which
    /// serializes every in-tree direct mmap; out-of-tree occupants
    /// (allocator arenas, thread stacks) never reuse a hole freed
    /// by our direct munmap, so a refusal names a real regression
    /// in that discipline.
    fn test_mmap_fixed(held: &HeldFile, addr: *mut c_void, len: usize) -> *mut c_void {
        let placed = unsafe {
            rustix::mm::mmap(
                addr,
                len,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE
                    | rustix::mm::MapFlags::FIXED
                    | rustix::mm::MapFlags::FIXED_NOREPLACE,
                held.as_fd(),
                0,
            )
        };
        let placed = placed.unwrap_or_else(|errno| {
            panic!("fixed placement collided (EEXIST expected only here): {errno}")
        });
        assert_eq!(placed, addr, "fixed remap must reuse the range");
        placed
    }

    /// S46: crash-free liveness probe for a range the test owns. A
    /// same-protection `mprotect` succeeds exactly when every page
    /// is mapped — unlike a read, it reports `ENOMEM` instead of
    /// delivering `SIGSEGV` when the range is gone.
    fn assert_range_live(addr: *mut c_void, len: usize, what: &str) {
        let result = unsafe { rustix::mm::mprotect(addr, len, rustix::mm::MprotectFlags::READ) };
        assert!(result.is_ok(), "{what} is no longer mapped: {result:?}");
    }

    fn page() -> usize {
        rustix::param::page_size()
    }

    /// Reserve, map and activate one live permit on `pool`.
    fn activate_one(pool: &MappingPool, held: &Arc<HeldFile>) -> (ActivePermit, *mut c_void) {
        let reservation = Reservation::reserve(&pool.shared, page()).unwrap();
        let addr = test_mmap(held, page());
        let permit = reservation.activate(addr, page(), Arc::clone(held));
        (permit, addr)
    }

    #[test]
    fn failed_unmap_drop_keeps_owner_and_charge() {
        let _table = crate::FD_TABLE.lock().unwrap();
        super::super::custody::inject_unmap_failures(0);
        let pool = test_pool(1, page());
        let (path, held) = test_held("drop-queue");
        let (permit, addr) = activate_one(&pool, &held);
        let mut guard = super::super::custody::TestCleanupGuard::new(addr, page());
        let custody = super::super::MappingCustody::new(permit);
        super::super::custody::inject_unmap_failures(1);
        drop(custody);
        // The failed Drop queued the complete record: owner and charge stay.
        let status = pool.status();
        assert_eq!(status.active_mappings(), 0);
        assert_eq!(status.unresolved_mappings(), 1);
        assert_eq!(status.unresolved_bytes(), page());
        assert!(Arc::strong_count(&held) >= 2, "queue retains the owner");
        // Only a successful retry frees capacity; the mapping is genuinely
        // still live (the injected failure never touched the kernel).
        let report = pool.retry_unresolved(&OperationControl::unlimited());
        assert_eq!(
            (report.attempted(), report.retired(), report.unresolved()),
            (1, 1, 0)
        );
        assert!(report.errors().is_empty());
        guard.disarm();
        let status = pool.status();
        assert_eq!(status.unresolved_mappings(), 0);
        assert_eq!(status.active_mappings(), 0);
        assert_eq!(Arc::strong_count(&held), 1);
        pool.close(&OperationControl::unlimited()).unwrap();
        std::fs::remove_file(path).unwrap();
        super::super::custody::inject_unmap_failures(0);
    }

    #[test]
    fn same_pool_reconstruction_cannot_reset_capacity() {
        // S46: direct mmaps serialize on FD_TABLE with the fixed-hole
        // tests, so no floating placement can steal a hole window.
        let _table = crate::FD_TABLE.lock().unwrap();
        let pool = test_pool(1, page());
        let (path, held) = test_held("reconstruct");
        let (permit, addr) = activate_one(&pool, &held);
        // A reconstructed handle observes the same occupied domain, and
        // dropping the original handle resets nothing.
        let rebuilt = pool.clone();
        drop(pool);
        assert_eq!(rebuilt.status().active_mappings(), 1);
        let refused = Reservation::reserve(&rebuilt.shared, page()).unwrap_err();
        assert_eq!(refused.reason(), Reason::LimitExceeded(LimitKind::Mappings));
        // Successful checked munmap alone frees capacity.
        unsafe { rustix::mm::munmap(addr, page()) }.unwrap();
        permit.retire();
        assert_eq!(rebuilt.status().active_mappings(), 0);
        // An outstanding reservation blocks clean close until released.
        let outstanding = Reservation::reserve(&rebuilt.shared, page()).unwrap();
        let failure = rebuilt.close(&OperationControl::unlimited()).unwrap_err();
        drop(outstanding);
        failure
            .into_pool()
            .close(&OperationControl::unlimited())
            .unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn byte_exhaustion_refuses_with_mapped_bytes() {
        // Mappings headroom remains but the byte budget is spent: the
        // pool.rs:570 path refuses with LimitKind::MappedBytes, and a
        // checked retire reopens admission.
        // S46: direct mmaps serialize on FD_TABLE (see above).
        let _table = crate::FD_TABLE.lock().unwrap();
        let pool = test_pool(8, page());
        let (path, held) = test_held("mapped-bytes");
        let (permit, addr) = activate_one(&pool, &held);
        let refused = Reservation::reserve(&pool.shared, page()).unwrap_err();
        assert_eq!(refused.stage(), Stage::MapCalibration);
        assert_eq!(
            refused.reason(),
            Reason::LimitExceeded(LimitKind::MappedBytes)
        );
        unsafe { rustix::mm::munmap(addr, page()) }.unwrap();
        permit.retire();
        // The refusal was capacity, not terminal: admission reopens.
        let reopened = Reservation::reserve(&pool.shared, page()).unwrap();
        drop(reopened);
        pool.close(&OperationControl::unlimited()).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn repeated_unmap_fail_drop_then_admit_refuses() {
        let _table = crate::FD_TABLE.lock().unwrap();
        super::super::custody::inject_unmap_failures(0);
        let pool = test_pool(1, page());
        let (path, held) = test_held("repeat-fail");
        let (permit, addr) = activate_one(&pool, &held);
        let mut guard = super::super::custody::TestCleanupGuard::new(addr, page());
        super::super::custody::inject_unmap_failures(1);
        drop(super::super::MappingCustody::new(permit));
        // Occupied by the queued record: new admission refuses.
        let refused = Reservation::reserve(&pool.shared, page()).unwrap_err();
        assert_eq!(refused.reason(), Reason::LimitExceeded(LimitKind::Mappings));
        // A repeated failure keeps the record queued with its error.
        super::super::custody::inject_unmap_failures(1);
        let report = pool.retry_unresolved(&OperationControl::unlimited());
        assert_eq!(
            (report.attempted(), report.retired(), report.unresolved()),
            (1, 0, 1)
        );
        assert_eq!(report.errors().len(), 1);
        assert_eq!(pool.status().unresolved_mappings(), 1);
        // A clean retry retires and reopens admission.
        let report = pool.retry_unresolved(&OperationControl::unlimited());
        assert_eq!(
            (report.attempted(), report.retired(), report.unresolved()),
            (1, 1, 0)
        );
        guard.disarm();
        let outstanding = Reservation::reserve(&pool.shared, page()).unwrap();
        let failure = pool.close(&OperationControl::unlimited()).unwrap_err();
        drop(outstanding);
        failure
            .into_pool()
            .close(&OperationControl::unlimited())
            .unwrap();
        std::fs::remove_file(path).unwrap();
        super::super::custody::inject_unmap_failures(0);
    }

    #[test]
    fn cancelled_drain_unwinds_by_id_under_forced_shift() {
        // F06/R43: forced replacement for the old 3000-round racy unwind
        // test (which never forced the schedule it needed). X claims R0
        // and pauses in the after-claim hook; the victim claims R1 (index
        // 1) and pauses; X commits R0, shifting R1 to index 0; the victim
        // cancels and must unwind R1 by id. An index unwind would address
        // index 1 of a 1-record queue; the id unwind always lands, and a
        // final clean retry reaches unresolved 0.
        let _table = crate::FD_TABLE.lock().unwrap();
        super::super::custody::inject_unmap_failures(0);
        let pool = test_pool(2, 2 * page());
        let (path, held) = test_held("f06-forced");
        let (permit0, addr0) = activate_one(&pool, &held);
        let (permit1, addr1) = activate_one(&pool, &held);
        let mut guard0 = super::super::custody::TestCleanupGuard::new(addr0, page());
        let mut guard1 = super::super::custody::TestCleanupGuard::new(addr1, page());
        super::super::custody::inject_unmap_failures(2);
        drop(super::super::MappingCustody::new(permit0));
        drop(super::super::MappingCustody::new(permit1));
        super::super::custody::inject_unmap_failures(0);
        assert_eq!(
            pool.queue_snapshot()
                .iter()
                .map(|(id, _, _, _)| *id)
                .collect::<Vec<_>>(),
            vec![1, 2],
            "queue holds R0 then R1"
        );
        let (x_claimed_tx, x_claimed_rx) = std::sync::mpsc::channel();
        let (x_release_tx, x_release_rx) = std::sync::mpsc::channel::<()>();
        let (v_claimed_tx, v_claimed_rx) = std::sync::mpsc::channel();
        let (v_release_tx, v_release_rx) = std::sync::mpsc::channel::<()>();
        // Receivers ride a mutex: only one drain waits on each by design,
        // but the closure type must be Sync.
        let x_release_rx = Mutex::new(x_release_rx);
        let v_release_rx = Mutex::new(v_release_rx);
        *pool.shared.test_hooks.after_claim.lock().unwrap() = Some(Arc::new(move |id| {
            if id == 1 {
                x_claimed_tx.send(()).unwrap();
                x_release_rx.lock().unwrap().recv().unwrap();
            } else if id == 2 {
                v_claimed_tx.send(()).unwrap();
                v_release_rx.lock().unwrap().recv().unwrap();
            } else {
                panic!("unexpected claim of record {id}");
            }
        }));
        let token = CancelToken::new();
        let control = OperationControl::new(None, token.clone());
        std::thread::scope(|scope| {
            let x = scope.spawn(|| pool.retry_unresolved(&OperationControl::unlimited()));
            x_claimed_rx.recv().unwrap();
            let victim = scope.spawn(|| pool.retry_unresolved(&control));
            v_claimed_rx.recv().unwrap();
            // X commits R0 while the victim holds R1: the commit shifts
            // R1 from index 1 to index 0 under the victim's claim.
            x_release_tx.send(()).unwrap();
            let x_report = x.join().unwrap();
            assert_eq!((x_report.attempted(), x_report.retired()), (1, 1));
            assert_eq!(
                pool.queue_snapshot(),
                vec![(2, addr1, page(), true)],
                "R1 shifted to index 0, still retiring"
            );
            token.cancel();
            v_release_tx.send(()).unwrap();
            let victim_report = victim.join().unwrap();
            assert_eq!(victim_report.attempted(), 0, "cancel precedes the unmap");
            assert_eq!(victim_report.errors().len(), 1);
        });
        assert_eq!(
            pool.queue_snapshot(),
            vec![(2, addr1, page(), false)],
            "cancel unwinds the shifted claim by id"
        );
        // The rendezvous is over: uninstall the hook so the cleanup drain
        // cannot block in it.
        *pool.shared.test_hooks.after_claim.lock().unwrap() = None;
        let report = pool.retry_unresolved(&OperationControl::unlimited());
        assert_eq!(
            (report.attempted(), report.retired(), report.unresolved()),
            (1, 1, 0),
            "no record strands Retiring"
        );
        guard0.disarm();
        guard1.disarm();
        pool.close(&OperationControl::unlimited()).unwrap();
        std::fs::remove_file(path).unwrap();
        super::super::custody::inject_unmap_failures(0);
    }

    /// S46: fixed placement REFUSES an occupied range instead of
    /// destroying it. The old `FIXED`-only helper silently clobbered
    /// whatever a competitor mapped in the hole; the `NOREPLACE`
    /// placement fails loudly. (A `should_panic`: the refusal IS the
    /// asserted behavior, and the occupant below survives it.)
    #[test]
    #[should_panic(expected = "fixed placement collided")]
    fn fixed_placement_refuses_occupied_range() {
        // The setup mapping serializes on FD_TABLE; the lock is
        // released before the asserting call, because this test
        // passes BY PANICKING and a panic while holding the mutex
        // would poison every other table test. The refusing call is
        // a single failing syscall (no mapping, no window), so it
        // needs no serialization; the occupant outlives it via the
        // guard's unwind cleanup.
        let (_path, held, addr) = {
            let _table = crate::FD_TABLE.lock().unwrap();
            let (_path, held) = test_held("noreplace");
            let addr = test_mmap(&held, page());
            (_path, held, addr)
        };
        let _guard = super::super::custody::TestCleanupGuard::new(addr, page());
        // The backing file must go even on the asserting panic (this
        // test passes by panicking, so no tail cleanup runs).
        struct FileGuard(std::path::PathBuf);
        impl Drop for FileGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _file = FileGuard(_path);
        // Occupied by our own live mapping: must refuse, never replace.
        let _ = test_mmap_fixed(&held, addr, page());
    }

    #[test]
    fn commit_removes_claimed_id_after_recycle_reorder() {
        // R10: post-unmap address reuse plus a reorder. A claims R1
        // (range X) and pauses; A then unmaps M1's still-live range
        // (the CORRECT occupant) and pauses again pre-commit; X is
        // remapped at the same address and queued as R2 (same token,
        // new id) while A's stale claim is still open; a decoy commit
        // then moves R2 ahead of R1. A's commit must remove R1 (its
        // claim), not the first token match (the live R2). First-match
        // code strands R1 Retiring and drops R2 instead.
        // S46: the old flow released A before its unmap, so A
        // destroyed the M2 replacement instead of testing a live
        // post-unmap/precommit interleaving. The replacement's
        // mapping must REMAIN LIVE across A's commit, and its queue
        // record must be retained.
        let _table = crate::FD_TABLE.lock().unwrap();
        super::super::custody::inject_unmap_failures(0);
        let pool = test_pool(4, 4 * page());
        let (path, held) = test_held("r10-recycle");
        let (permit_d, addr_d) = activate_one(&pool, &held);
        let (permit1, addr_x) = activate_one(&pool, &held);
        let mut guard_d = super::super::custody::TestCleanupGuard::new(addr_d, page());
        let mut guard1 = super::super::custody::TestCleanupGuard::new(addr_x, page());
        super::super::custody::inject_unmap_failures(2);
        drop(super::super::MappingCustody::new(permit_d));
        drop(super::super::MappingCustody::new(permit1));
        super::super::custody::inject_unmap_failures(0);
        assert_eq!(pool.queue_snapshot().len(), 2, "D1 then R1 queued");
        let (x_claimed_tx, x_claimed_rx) = std::sync::mpsc::channel();
        let (x_release_tx, x_release_rx) = std::sync::mpsc::channel::<()>();
        let (a_claimed_tx, a_claimed_rx) = std::sync::mpsc::channel();
        let (a_release_tx, a_release_rx) = std::sync::mpsc::channel::<()>();
        let (x2_claimed_tx, x2_claimed_rx) = std::sync::mpsc::channel();
        let (x2_release_tx, x2_release_rx) = std::sync::mpsc::channel::<()>();
        // S46: A's second pause — after its unmap, before its commit.
        let (a_unmapped_tx, a_unmapped_rx) = std::sync::mpsc::channel();
        let (a_commit_tx, a_commit_rx) = std::sync::mpsc::channel::<()>();
        // Receivers ride a mutex: only one drain waits on each by design,
        // but the closure type must be Sync.
        let x_release_rx = Mutex::new(x_release_rx);
        let a_release_rx = Mutex::new(a_release_rx);
        let x2_release_rx = Mutex::new(x2_release_rx);
        let a_commit_rx = Mutex::new(a_commit_rx);
        *pool.shared.test_hooks.after_claim.lock().unwrap() = Some(Arc::new(move |id| {
            if id == 1 {
                x_claimed_tx.send(()).unwrap();
                x_release_rx.lock().unwrap().recv().unwrap();
            } else if id == 2 {
                a_claimed_tx.send(()).unwrap();
                a_release_rx.lock().unwrap().recv().unwrap();
            } else if id == 3 {
                // X's second claim (A skips R2 while X holds it): pause so
                // the reorder is asserted before either drain proceeds.
                x2_claimed_tx.send(()).unwrap();
                x2_release_rx.lock().unwrap().recv().unwrap();
            } else {
                panic!("unexpected claim of record {id}");
            }
        }));
        // S46: A pauses a second time after its unmap, before its
        // commit. Other records' commits pass through immediately.
        *pool.shared.test_hooks.before_commit.lock().unwrap() = Some(Arc::new(move |id| {
            if id == 2 {
                a_unmapped_tx.send(()).unwrap();
                a_commit_rx.lock().unwrap().recv().unwrap();
            }
        }));
        // X runs under a cancellable control: after A commits, X is
        // cancelled out of its second claim (a real second unmap would
        // succeed even on the gone range — Linux munmap never fails for
        // unmapped pages — and retire R2 out from under the assertion).
        let x_token = CancelToken::new();
        let x_control = OperationControl::new(None, x_token.clone());
        std::thread::scope(|scope| {
            // X holds the decoy so A is forced to claim R1 at index 1.
            let x = scope.spawn(|| pool.retry_unresolved(&x_control));
            x_claimed_rx.recv().unwrap();
            let a = scope.spawn(|| pool.retry_unresolved(&OperationControl::unlimited()));
            a_claimed_rx.recv().unwrap();
            // S46: A unmaps FIRST, while M1's range is still the live
            // occupant (the injected failure never touched the kernel,
            // so this unmap is correct and complete), then pauses
            // pre-commit. Only then is X recycled: the hole is
            // genuinely free, the NOREPLACE remap cannot clobber, and
            // R2 queues while A's stale claim is still open.
            a_release_tx.send(()).unwrap();
            a_unmapped_rx.recv().unwrap();
            let reservation = Reservation::reserve(&pool.shared, page()).unwrap();
            let addr_m2 = test_mmap_fixed(&held, addr_x, page());
            let permit2 = reservation.activate(addr_m2, page(), Arc::clone(&held));
            let mut guard2 = super::super::custody::TestCleanupGuard::new(addr_m2, page());
            super::super::custody::inject_unmap_failures(1);
            drop(super::super::MappingCustody::new(permit2));
            super::super::custody::inject_unmap_failures(0);
            assert_eq!(
                pool.queue_snapshot(),
                vec![
                    (1, addr_d, page(), true),
                    (2, addr_x, page(), true),
                    (3, addr_x, page(), false),
                ],
                "R2 shares R1's token with a new id"
            );
            // X commits the decoy: swap_remove moves R2 (last) to index 0,
            // ahead of A's still-held R1. X's pass then claims R2 and
            // pauses, so the reorder is asserted before A commits.
            x_release_tx.send(()).unwrap();
            x2_claimed_rx.recv().unwrap();
            assert_eq!(
                pool.queue_snapshot(),
                vec![(3, addr_x, page(), true), (2, addr_x, page(), true)],
                "reorder puts the live same-token record first"
            );
            // A commits R1 by id (its unmap long done, before the
            // recycle — M2's live range is untouched); A then finds
            // R2 held by X and ends its pass. X is cancelled out of
            // its R2 claim and unwinds it by id, leaving R2 queued
            // and unretiring.
            a_commit_tx.send(()).unwrap();
            let a_report = a.join().unwrap();
            assert_eq!((a_report.attempted(), a_report.retired()), (1, 1));
            x_token.cancel();
            x2_release_tx.send(()).unwrap();
            let x_report = x.join().unwrap();
            assert_eq!((x_report.attempted(), x_report.retired()), (1, 1));
            assert_eq!(x_report.errors().len(), 1);
            assert_eq!(
                pool.queue_snapshot(),
                vec![(3, addr_x, page(), false)],
                "commit removed the claimed R1, not the live R2"
            );
            // S46: the replacement mapping REMAINS LIVE across A's
            // commit of the stale token, and its queue record is
            // retained (asserted above).
            assert_range_live(addr_m2, page(), "M2 replacement");
            // M2 stays mapped past the scope: the cleanup drain below
            // unmaps it live through R2's token.
            guard2.disarm();
        });
        // The rendezvous is over: uninstall the hooks so the cleanup
        // drain cannot block in them.
        *pool.shared.test_hooks.after_claim.lock().unwrap() = None;
        *pool.shared.test_hooks.before_commit.lock().unwrap() = None;
        // Retire the surviving R2 through its live occupant: the drain
        // unmaps M2's range through R2's token and retires the record,
        // then the pool closes. M2 still occupies addr_x (asserted
        // live above), so the re-guard covers the drain window.
        let mut guard2 = super::super::custody::TestCleanupGuard::new(addr_x, page());
        let report = pool.retry_unresolved(&OperationControl::unlimited());
        assert_eq!(
            (report.attempted(), report.retired(), report.unresolved()),
            (1, 1, 0)
        );
        guard2.disarm();
        guard_d.disarm();
        guard1.disarm();
        pool.close(&OperationControl::unlimited()).unwrap();
        std::fs::remove_file(path).unwrap();
        super::super::custody::inject_unmap_failures(0);
    }

    #[test]
    fn retire_counters_precede_anchor_release() {
        // R43: forced order assertion for the F07 terminal-retention
        // release. The pool drops with one live mapping (anchor
        // installs); retiring the permit must update the counters BEFORE
        // the anchor release check, or the release would still see the
        // mapping occupied and skip, leaking the anchor. The hooks log
        // the order; any future reorder flips the log and fails.
        let _table = crate::FD_TABLE.lock().unwrap();
        super::super::custody::inject_unmap_failures(0);
        let pool = test_pool(1, page());
        let (path, held) = test_held("retire-order");
        let (permit, addr) = activate_one(&pool, &held);
        let mut guard = super::super::custody::TestCleanupGuard::new(addr, page());
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_counters = Arc::clone(&log);
        let log_release = Arc::clone(&log);
        *pool.shared.test_hooks.after_retire_counters.lock().unwrap() = Some(Arc::new(move || {
            log_counters.lock().unwrap().push("counters")
        }));
        *pool.shared.test_hooks.anchor_releasing.lock().unwrap() = Some(Arc::new(move || {
            log_release.lock().unwrap().push("release")
        }));
        let weak = Arc::downgrade(&pool.shared);
        drop(pool);
        assert!(
            weak.upgrade().is_some(),
            "occupied drop installs the anchor"
        );
        unsafe { rustix::mm::munmap(addr, page()) }.unwrap();
        guard.disarm();
        permit.retire();
        assert_eq!(
            *log.lock().unwrap(),
            vec!["counters", "release"],
            "counters update before the anchor release check"
        );
        assert!(weak.upgrade().is_none(), "empty domain releases its anchor");
        assert_eq!(Arc::strong_count(&held), 1);
        std::fs::remove_file(path).unwrap();
        super::super::custody::inject_unmap_failures(0);
    }

    #[test]
    fn retire_empty_observation_overlaps_acquisition_and_install() {
        // S12: the serial order test cannot see the concurrent
        // check/install window. Retirement's empty observation MUST
        // overlap a new custody acquisition plus its anchor install,
        // and the install must be OBSERVED (anchor kept), not erased.
        // The after_retire_counters hook runs with no locks held,
        // after R1's counters hit zero and before the release check:
        // the racer acquires R2 and drops its handle (installing
        // R2's anchor) exactly in that window, every run.
        let _table = crate::FD_TABLE.lock().unwrap();
        super::super::custody::inject_unmap_failures(0);
        let pool = test_pool(2, 2 * page());
        let (path, held) = test_held("overlap-install");
        let (permit1, addr1) = activate_one(&pool, &held);
        let mut guard1 = super::super::custody::TestCleanupGuard::new(addr1, page());
        // Second handle for the racer's install; the main handle
        // drops now (R1 occupied -> anchor installed).
        let racer_pool = pool.clone();
        let weak = Arc::downgrade(&pool.shared);
        drop(pool);
        assert!(
            weak.upgrade().is_some(),
            "occupied drop installs the anchor"
        );
        // Synchronous racer inside the hook: all pool locks are down
        // at the hook point, so reserve/activate/drop take them freely.
        // R2's address is an opaque never-mapped token, not a real
        // mapping: the race under test is over pool state
        // (locks/counters/anchor/queue), and `retire` never touches
        // the mapping — the caller unmaps. Real placement is S46's
        // separately covered subject; no guard is needed for a token
        // that is never unmapped.
        const R2_TOKEN: *mut c_void = 0x4000 as *mut c_void;
        let racer = Arc::new(Mutex::new(Some(racer_pool)));
        let racer_hook = Arc::clone(&racer);
        let held_hook = Arc::clone(&held);
        let permit2_holder: Arc<Mutex<Option<ActivePermit>>> = Arc::new(Mutex::new(None));
        let permit2_hook = Arc::clone(&permit2_holder);
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_counters = Arc::clone(&log);
        let log_release = Arc::clone(&log);
        let shared = weak.upgrade().unwrap();
        *shared.test_hooks.after_retire_counters.lock().unwrap() = Some(Arc::new(move || {
            log_counters.lock().unwrap().push("counters");
            // First (only) firing does the racing install; later
            // firings (cleanup retires) find nothing and pass through.
            let Some(racer_pool) = racer_hook.lock().unwrap().take() else {
                return;
            };
            let reservation = Reservation::reserve(&racer_pool.shared, page()).unwrap();
            let permit2 = reservation.activate(R2_TOKEN, page(), Arc::clone(&held_hook));
            *permit2_hook.lock().unwrap() = Some(permit2);
            drop(racer_pool);
        }));
        *shared.test_hooks.anchor_releasing.lock().unwrap() = Some(Arc::new(move || {
            log_release.lock().unwrap().push("release");
        }));
        drop(shared);
        unsafe { rustix::mm::munmap(addr1, page()) }.unwrap();
        guard1.disarm();
        permit1.retire();
        // The racing install landed before the release check: the
        // check observed R2 occupied and KEPT the anchor (no
        // "release" in the log), and the new custody is retained.
        assert_eq!(
            *log.lock().unwrap(),
            vec!["counters"],
            "release check kept the anchor over the racing install"
        );
        let shared = weak.upgrade().expect("anchor survives the overlap");
        assert!(
            shared.anchor.lock().unwrap().is_some(),
            "anchor slot still holds the domain"
        );
        assert_eq!(
            lock_report(&shared).active_mappings,
            1,
            "R2 custody retained"
        );
        assert_eq!(
            permit2_holder.lock().unwrap().as_ref().unwrap().addr(),
            R2_TOKEN,
            "R2 token carried through"
        );
        drop(shared);
        // Cleanup: uninstall the hooks, retire R2 (no unmap: the
        // token was never mapped), and prove the anchor releases
        // once the domain is truly empty.
        let shared = weak.upgrade().unwrap();
        *shared.test_hooks.after_retire_counters.lock().unwrap() = None;
        *shared.test_hooks.anchor_releasing.lock().unwrap() = None;
        drop(shared);
        let permit2 = permit2_holder.lock().unwrap().take().unwrap();
        permit2.retire();
        assert!(weak.upgrade().is_none(), "empty domain releases its anchor");
        std::fs::remove_file(path).unwrap();
        super::super::custody::inject_unmap_failures(0);
    }

    #[test]
    fn retire_acquire_race_retains_unresolved() {
        // S12: hammer the retire-vs-acquire race with real threads.
        // R1 retires while a racer acquires R2, installs its anchor
        // (second-handle drop), and queues R2 unresolved: every
        // serialization must retain R2's anchor and record. All
        // addresses are opaque never-mapped tokens (see the overlap
        // test): the race is over pool state, the injected failure
        // never touches the kernel, and the drain's token unmap is a
        // no-op success on Linux. Protected code passes every round
        // by mutual exclusion; a check-then-unlock-then-take release
        // loses the anchor (RED-verified with a widened window).
        const ROUNDS: usize = 200;
        const R_TOKEN: *mut c_void = 0x5000 as *mut c_void;
        let _table = crate::FD_TABLE.lock().unwrap();
        super::super::custody::inject_unmap_failures(0);
        // One backing file for all rounds: permits hold owner Arcs,
        // and no round maps anything real.
        let (path, held) = test_held("race-retain");
        for _ in 0..ROUNDS {
            let pool = test_pool(2, 2 * page());
            let reservation = Reservation::reserve(&pool.shared, page()).unwrap();
            let permit1 = reservation.activate(R_TOKEN, page(), Arc::clone(&held));
            let racer_pool = pool.clone();
            let weak = Arc::downgrade(&pool.shared);
            drop(pool);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let barrier_main = Arc::clone(&barrier);
            std::thread::scope(|scope| {
                let racer = scope.spawn({
                    let barrier = Arc::clone(&barrier);
                    let held = Arc::clone(&held);
                    move || {
                        barrier.wait();
                        let reservation = Reservation::reserve(&racer_pool.shared, page()).unwrap();
                        let permit2 = reservation.activate(R_TOKEN, page(), held);
                        drop(racer_pool);
                        // R2 retires unresolved: the injected failure
                        // queues the record without touching the kernel.
                        super::super::custody::inject_unmap_failures(1);
                        drop(super::super::MappingCustody::new(permit2));
                        super::super::custody::inject_unmap_failures(0);
                    }
                });
                barrier_main.wait();
                permit1.retire();
                racer.join().unwrap();
            });
            let shared = weak.upgrade().expect("anchor survives the race");
            assert_eq!(
                lock_report(&shared).unresolved.len(),
                1,
                "R2 record retained"
            );
            // Drain the survivor through the shared domain directly
            // (no handles remain by design) and prove the anchor
            // releases once truly empty.
            let report = drain_shared(&shared, &OperationControl::unlimited());
            assert_eq!(
                (report.attempted(), report.retired(), report.unresolved()),
                (1, 1, 0)
            );
            drop(shared);
            assert!(
                weak.upgrade().is_none(),
                "drained domain releases its anchor"
            );
        }
        std::fs::remove_file(path).unwrap();
        super::super::custody::inject_unmap_failures(0);
    }

    #[test]
    fn last_pool_handle_retains_terminal_custody() {
        let _table = crate::FD_TABLE.lock().unwrap();
        super::super::custody::inject_unmap_failures(0);
        let pool = test_pool(1, page());
        let (path, held) = test_held("terminal");
        let (permit, addr) = activate_one(&pool, &held);
        let mut guard = super::super::custody::TestCleanupGuard::new(addr, page());
        super::super::custody::inject_unmap_failures(1);
        drop(super::super::MappingCustody::new(permit));
        // No public handle remains, yet the queue, owner and charge survive.
        let weak = Arc::downgrade(&pool.shared);
        drop(pool);
        let retained = weak
            .upgrade()
            .expect("terminal retention anchors the queue");
        assert!(Arc::strong_count(&held) >= 2, "owner survives its pool");
        // Test-only recovery through the weak anchor (production has no such
        // route: callers retain a pool clone and drain/close explicitly).
        let report = drain_shared(&retained, &OperationControl::unlimited());
        assert_eq!(
            (report.attempted(), report.retired(), report.unresolved()),
            (1, 1, 0)
        );
        guard.disarm();
        drop(retained);
        assert!(weak.upgrade().is_none(), "empty domain releases its anchor");
        assert_eq!(Arc::strong_count(&held), 1);
        std::fs::remove_file(path).unwrap();
        super::super::custody::inject_unmap_failures(0);
    }

    #[test]
    fn close_reconciles_live_custody_before_shutting_down() {
        // Scripted admit/retire/close history: close fails Closing while a
        // live custody is out, then succeeds after its checked retire.
        // S46: direct mmaps serialize on FD_TABLE (see above).
        let _table = crate::FD_TABLE.lock().unwrap();
        let pool = test_pool(1, page());
        let (path, held) = test_held("close-retry");
        let (permit, addr) = activate_one(&pool, &held);
        let failure = pool.close(&OperationControl::unlimited()).unwrap_err();
        assert_eq!(failure.report().unresolved(), 0);
        assert_eq!(failure.error().reason(), Reason::Unavailable);
        let pool = failure.into_pool();
        // Closing blocks admission across the recovered handle.
        assert!(OpGuard::admit(&pool).is_err());
        unsafe { rustix::mm::munmap(addr, page()) }.unwrap();
        permit.retire();
        pool.close(&OperationControl::unlimited()).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn close_waits_out_active_operations() {
        let pool = test_pool(1, page());
        let other = pool.clone();
        let _op = OpGuard::admit(&pool).unwrap();
        // An operation in flight on any clone blocks clean shutdown.
        let failure = other.close(&OperationControl::unlimited()).unwrap_err();
        assert_eq!(failure.error().stage(), Stage::ObserveMapping);
        let pool = failure.into_pool();
        drop(_op);
        pool.close(&OperationControl::unlimited()).unwrap();
    }
}
