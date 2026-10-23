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
struct UnresolvedRecord {
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
    /// no active work. Never locked while `state` is held.
    anchor: Mutex<Option<Arc<Shared>>>,
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
                }),
                anchor: Mutex::new(None),
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
        // when the last record retires with no active work.
        let occupied = lock_report(&self.shared).occupied();
        if occupied {
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
/// operation is in flight. The state lock is never held while taking this.
pub(crate) fn release_anchor_if_empty(shared: &Shared) {
    let empty = {
        let state = lock_report(shared);
        !state.occupied() && state.active_ops == 0
    };
    if empty {
        lock_anchor(shared).take();
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
        let record = UnresolvedRecord {
            addr: self.addr,
            len: self.len,
            held: Arc::clone(&self.held),
            bytes: self.bytes,
            retiring: false,
        };
        {
            let mut state = lock_report(&self.shared);
            state.active_mappings = state.active_mappings.saturating_sub(1);
            state.active_bytes = state.active_bytes.saturating_sub(self.bytes);
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
    let mut tried: Vec<(*mut c_void, usize)> = Vec::new();
    for _ in 0..budget {
        let claim = {
            let mut state = lock_report(shared);
            let index = state.unresolved.iter().position(|record| {
                !record.retiring
                    && !tried
                        .iter()
                        .any(|(addr, len)| *addr == record.addr && *len == record.len)
            });
            match index {
                None => None,
                Some(index) => {
                    state.unresolved[index].retiring = true;
                    let record = &state.unresolved[index];
                    Some((index, record.addr, record.len))
                }
            }
        };
        let Some((index, addr, len)) = claim else {
            break;
        };
        tried.push((addr, len));
        // No pool lock is held across the unmap attempt.
        if let Err(stop) = control.checkpoint() {
            let mut state = lock_report(shared);
            if let Some(record) = state.unresolved.get_mut(index) {
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
                let mut state = lock_report(shared);
                // The queue may have shifted under a concurrent drain; remove
                // by identity (address tokens are unique per live mapping).
                if let Some(position) = state
                    .unresolved
                    .iter()
                    .position(|record| record.addr == addr && record.len == len)
                {
                    state.unresolved.swap_remove(position);
                }
                retired += 1;
            }
            Err(error) => {
                let mut state = lock_report(shared);
                if let Some(record) = state
                    .unresolved
                    .iter_mut()
                    .find(|record| record.addr == addr && record.len == len)
                {
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
