// SPDX-License-Identifier: Apache-2.0
//! LX06 mapping relations over /proc: exact association, key compatibility,
//! explicit calibration and retained custody.
//!
//! `observe_mapping` relates one retained [`HeldFile`](crate::file::HeldFile)
//! to one virtual range of one retained
//! [`ProcessObservation`](crate::process::ProcessObservation) through the
//! frozen LX05 maps/mountinfo parsers. Raw-key equality can at most yield
//! [`MappingOutcome::KeyCompatible`]; [`MappingOutcome::ExactRange`]
//! additionally requires the independent per-range map_files association with
//! both descriptors alive through the comparison. `NoNewTargetMappings`
//! never calls mmap on the requested target in any branch; calibration mode
//! permits at most one page-aligned private `PROT_READ` mapping whose key
//! alone is established, never target association.
//!
//! Error routing: target-side states (exit, disappearance, denial, view or
//! birth change) are [`MappingOutcome::Mismatch`]/[`MappingOutcome::Inconclusive`]
//! verdicts, never path reopens; observer-side failures (invalid limits,
//! closed pool, control stops, caller budgets, own-fd faults) are
//! [`MappingFailure`] errors. A failed unmap keeps its live
//! [`MappingCustody`] beside whatever was observed: observation and failed
//! cleanup stay separately inspectable.
//!
//! Donor lineage: P @2c2713e6 `ranges_for`/non-unique-key doctrine
//! (src/discovery/instances.rs), `MapFilesDir::identity` plus
//! `write_map_files_name` (src/discovery/identity.rs), the one-page
//! `PROT_READ`/`MAP_PRIVATE` calibration shape (src/attach/instance.rs
//! `calibrate`) and the re-read-once mount rule (`reread_on_missing_mount`).
//! Pool/custody/proof-reuse vocabulary is new per the frozen contract. D03
//! scoped grant (2026-10-23) covers GPL-source to Apache-2.0 destination
//! inside this library; donor files/terms untouched.
mod calibration;
mod custody;
pub mod pool;
mod proof;

pub use custody::MappingCustody;
pub use pool::{
    MappingDrainReport, MappingPool, MappingPoolCloseFailure, MappingPoolClosed, MappingPoolLimits,
    MappingPoolStatus,
};
pub use proof::{
    FsClass, InconclusiveKind, InconclusiveReason, MapRangeProof, MappingProof, MismatchEvidence,
    MismatchKind, ProofMethod,
};

use pool::OpGuard;
use proof::{key_verdict, shape_of, shape_retained, KeyVerdict, LineShape};
use std::{ffi::CStr, fmt, os::fd::AsFd, sync::Arc, time::Instant};

use crate::{
    control::OperationControl,
    error::{CleanupDisposition, LimitKind, LinuxError, Reason, ResourceCharges, Stage},
    file::HeldFile,
    identity::{MapsFileKey, ObservationInterval, StatObservation},
    process::{BirthStatus, ProcLimits, ProcessObservation},
};

/// Checked nonempty half-open virtual range with page-offset and length
/// validation: `start < end`, page-aligned start, page-multiple length.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct MapRange {
    start: u64,
    end: u64,
}

impl MapRange {
    pub fn new(start: u64, end: u64) -> Result<Self, LinuxError> {
        let page = rustix::param::page_size() as u64;
        if page > 0 && start < end && start % page == 0 && (end - start) % page == 0 {
            Ok(Self { start, end })
        } else {
            Err(pool::pool_error(
                Stage::ConfigureMapping,
                Reason::InvalidInput,
                CleanupDisposition::NotNeeded,
            ))
        }
    }
    pub fn start(&self) -> u64 {
        self.start
    }
    pub fn end(&self) -> u64 {
        self.end
    }
    pub fn len(&self) -> u64 {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for MapRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapRange(<private>)")
    }
}

/// Whether the caller authorizes the one explicit calibration mapping.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MappingPolicy {
    NoNewTargetMappings,
    AllowPrivateCalibration { max_mapped_bytes: usize },
}

/// Operation ceilings: bounded proc reads, at most one mount-table refresh,
/// a ceiling on additionally acquired FDs and the policy's live-mapping
/// count (0 for `NoNew`, 1 for calibration). No deadline is implied for a
/// blocked mmap or proc read.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MappingLimits {
    pub proc: ProcLimits,
    pub max_mount_refreshes: u8,
    pub max_open_fds: usize,
    pub max_live_mappings: usize,
}

/// One mapping observation request: the caller-owned pool domain, the held
/// object, the retained target observation, the requested range, the
/// calibration policy, an optional retained proof for key reuse and the
/// operation ceilings.
#[derive(Debug)]
pub struct MappingRequest<'a> {
    pub pool: &'a MappingPool,
    pub held: Arc<HeldFile>,
    pub process: &'a ProcessObservation,
    pub range: MapRange,
    pub policy: MappingPolicy,
    pub retained: Option<&'a MappingProof>,
    pub limits: MappingLimits,
}

/// The mapping relation verdict. Proofs are opaque retained values; refusal
/// carriers retain their reached stage charges.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum MappingOutcome {
    ExactRange(MapRangeProof),
    KeyCompatible(MappingProof),
    Mismatch(MismatchEvidence),
    Inconclusive(InconclusiveReason),
}

/// Failed observation: the optionally reached outcome, the blocking error and
/// the optional still-charged unmap custody, each separately inspectable,
/// plus the reached stage charges.
#[derive(Debug)]
pub struct MappingFailure {
    pub(crate) observation: Option<MappingOutcome>,
    pub(crate) error: LinuxError,
    pub(crate) unresolved: Option<MappingCustody>,
    pub(crate) charges: Vec<ResourceCharges>,
}

impl MappingFailure {
    pub fn observation(&self) -> Option<&MappingOutcome> {
        self.observation.as_ref()
    }
    pub fn error(&self) -> &LinuxError {
        &self.error
    }
    pub fn unresolved(&self) -> Option<&MappingCustody> {
        self.unresolved.as_ref()
    }
    pub fn into_unresolved(self) -> Option<MappingCustody> {
        self.unresolved
    }
    pub fn stage_charges(&self) -> &[ResourceCharges] {
        &self.charges
    }
}

pub(crate) fn stop_reason(stop: crate::control::ControlStop) -> Reason {
    match stop {
        crate::control::ControlStop::Cancelled => Reason::Cancelled,
        crate::control::ControlStop::Deadline => Reason::Deadline,
    }
}

/// Pure policy/limits coherence: refreshes are 0 or 1, and the live-mapping
/// ceiling is 0 for `NoNew` and 1 for calibration. A `NoNew` request with a
/// nonzero ceiling asks for calibration effects without calibration
/// authority and refuses.
fn validate_policy(policy: MappingPolicy, limits: &MappingLimits) -> Result<(), LinuxError> {
    let coherent = limits.max_mount_refreshes <= 1
        && matches!(
            (policy, limits.max_live_mappings),
            (MappingPolicy::NoNewTargetMappings, 0)
                | (MappingPolicy::AllowPrivateCalibration { .. }, 1)
        );
    if coherent {
        Ok(())
    } else {
        Err(pool::pool_error(
            Stage::ConfigureMapping,
            Reason::InvalidInput,
            CleanupDisposition::NotNeeded,
        ))
    }
}

/// Per-invocation FD accounting plus reached stage charges.
struct OpCtx<'a> {
    control: &'a OperationControl,
    max_open_fds: usize,
    fd_spent: u64,
    charges: Vec<ResourceCharges>,
}

impl OpCtx<'_> {
    fn spend(&mut self, charges: &ResourceCharges) -> Result<(), LinuxError> {
        self.charges.push(charges.clone());
        self.fd_spent += charges.fd_acquisitions();
        if self.fd_spent > self.max_open_fds as u64 {
            return Err(pool::pool_error(
                Stage::ObserveMapping,
                Reason::LimitExceeded(LimitKind::OpenFds),
                CleanupDisposition::Complete,
            ));
        }
        Ok(())
    }

    /// Record charges that already happened, without a ceiling check.
    /// Failure paths use this so an over-ceiling ledger never replaces
    /// the real error with a second ceiling refusal.
    fn record(&mut self, charges: &ResourceCharges) {
        self.charges.push(charges.clone());
        self.fd_spent += charges.fd_acquisitions();
    }

    /// Absorb whole sub-operation charge lists (calibration, mount lookup).
    /// R12: record-all-then-first-error. Every batch member is recorded
    /// (the acquisitions happened); the ceiling is then reported once,
    /// for the first breach. The old fail-fast loop dropped the
    /// post-breach members from the ledger.
    fn absorb(&mut self, charges: &[ResourceCharges]) -> Result<(), LinuxError> {
        let mut first_breach = None;
        for charges in charges {
            self.charges.push(charges.clone());
            self.fd_spent += charges.fd_acquisitions();
            if first_breach.is_none() && self.fd_spent > self.max_open_fds as u64 {
                first_breach = Some(pool::pool_error(
                    Stage::ObserveMapping,
                    Reason::LimitExceeded(LimitKind::OpenFds),
                    CleanupDisposition::Complete,
                ));
            }
        }
        match first_breach {
            None => Ok(()),
            Some(error) => Err(error),
        }
    }

    /// Honest mini-charges without a ceiling check (see `record`).
    /// R12: fdinfo pre-admits its single FD up front, so every path
    /// records; the old checked post-success spend is gone with it.
    fn record_direct(&mut self, syscalls: u64, acquired: u64) {
        self.record(&ResourceCharges {
            syscalls,
            acquired,
            peak: acquired,
            read: None,
            parse: None,
            #[cfg(feature = "process")]
            process: None,
        });
    }

    fn take_charges(&mut self) -> Vec<ResourceCharges> {
        std::mem::take(&mut self.charges)
    }

    fn mismatch(&mut self, kind: MismatchKind) -> MappingOutcome {
        MappingOutcome::Mismatch(MismatchEvidence::new(kind, self.take_charges()))
    }

    fn inconclusive(&mut self, kind: InconclusiveKind) -> MappingOutcome {
        MappingOutcome::Inconclusive(InconclusiveReason::new(kind, self.take_charges()))
    }

    fn failure(&mut self, error: LinuxError) -> MappingFailure {
        MappingFailure {
            observation: None,
            error,
            unresolved: None,
            charges: self.take_charges(),
        }
    }

    fn failure_full(
        &mut self,
        observation: Option<MappingOutcome>,
        error: LinuxError,
        unresolved: Option<MappingCustody>,
    ) -> MappingFailure {
        MappingFailure {
            observation,
            error,
            unresolved,
            charges: self.take_charges(),
        }
    }
}

/// Record one sub-operation's charges against the FD ceiling. A breached
/// ceiling replaces the sub-operation's own result: the operation is over
/// budget regardless of what the sub-operation reports.
///
/// R11: worst-case FD acquisitions per tracked sub-operation, counted
/// from the success path (every open on it; error paths return early
/// and acquire fewer). Locked by exact-acquisition tests; update
/// deliberately if a sub-operation gains an open.
const BIRTH_WORST_FDS: u64 = 5;
const MAPS_WORST_FDS: u64 = 15;
const MAP_FILES_WORST_FDS: u64 = 11;
const MOUNTINFO_WORST_FDS: u64 = 15;
/// S10: a full strict acquisition's success cost (six steps: creator
/// guard, pre-sample, pidfd, retained directory, namespace capture,
/// view guard — NOT the 5-FD birth re-verification). Locked at 21 by
/// the `process_observation` acquisition-inventory test; update
/// deliberately if acquisition gains an open.
const ACQUIRE_WORST_FDS: u64 = 21;
/// S10: calibration's worst case is its three acquiring sub-operations
/// on their success paths — a fresh strict self acquisition, its maps
/// read, and the calibration mapping's own map_files identity
/// (stat/mmap/unmap open no FDs; the reservation is a pool slot, not
/// a descriptor). Compositional so a deliberately updated
/// sub-operation constant propagates here by construction.
const CALIBRATION_WORST_FDS: u64 = ACQUIRE_WORST_FDS + MAPS_WORST_FDS + MAP_FILES_WORST_FDS;

/// R11: refuse before running unless the sub-operation's whole worst
/// case fits the remaining budget. Acquisitions happen inside `run`,
/// so the check must cover all of them, not just the first.
fn preadmit_fds(ctx: &OpCtx, worst_case_fds: u64) -> Result<(), LinuxError> {
    if ctx.fd_spent.saturating_add(worst_case_fds) > ctx.max_open_fds as u64 {
        return Err(pool::pool_error(
            Stage::ObserveMapping,
            Reason::LimitExceeded(LimitKind::OpenFds),
            CleanupDisposition::Complete,
        ));
    }
    Ok(())
}

/// F13: the sub-operation runs as a thunk behind an exhausted-budget
/// preflight. R11 strengthens it to worst-case pre-admission: a
/// positive-but-insufficient budget used to run a multi-FD sub-op and
/// over-acquire transiently before rejecting; now the whole worst case
/// must fit, so a refused sub-operation performs zero acquisitions.
fn tracked<T>(
    ctx: &mut OpCtx,
    worst_case_fds: u64,
    run: impl FnOnce() -> Result<T, LinuxError>,
    project: fn(&T) -> &ResourceCharges,
) -> Result<T, LinuxError> {
    preadmit_fds(ctx, worst_case_fds)?;
    match run() {
        Ok(value) => {
            let charges = project(&value).clone();
            match ctx.spend(&charges) {
                Ok(()) => Ok(value),
                Err(ceiling) => Err(ceiling),
            }
        }
        Err(error) => {
            let charges = error.charges().clone();
            match ctx.spend(&charges) {
                Ok(()) => Err(error),
                Err(ceiling) => Err(ceiling),
            }
        }
    }
}

/// Target-side verdicts routable from a sub-operation error.
pub(crate) enum TargetVerdict {
    Mismatch(MismatchKind),
    Inconclusive(InconclusiveKind),
}

/// S11: members of the process error context whose failure breaks
/// OUR view or authentication (observer ambient, observer directory
/// lineage, creator liveness) rather than the target. No target work
/// is meaningfully observed past such a failure, so it is an
/// observer-side `MappingFailure`, never a target verdict — even
/// when its `Reason` is verdict-shaped.
#[cfg(feature = "process")]
fn is_observer_member(member: crate::error::ProcMember) -> bool {
    use crate::error::ProcMember::*;
    matches!(
        member,
        Root | SelfLink | ObserverDirectory | ObserverStatus | ObserverPidNamespace | CreatorPidfd
    )
}

/// S11: true when the error carries an observer-side origin member
/// (our view or authentication broke; the target was never
/// observed). Member-less errors are not observer-origin: they keep
/// the historical `Reason`-only routing.
#[cfg(feature = "process")]
fn is_observer_origin(error: &LinuxError) -> bool {
    error
        .process_context()
        .and_then(crate::error::ProcessErrorContext::member)
        .is_some_and(is_observer_member)
}

/// Non-process builds have no origin members at all.
#[cfg(not(feature = "process"))]
fn is_observer_origin(_error: &LinuxError) -> bool {
    false
}

/// Route a target sub-operation error: disappearance, denial, birth/view
/// change and unclear liveness become verdicts; control stops, caller
/// budgets, config faults and environmental or unreadable failures pass
/// through as errors.
///
/// S11: the route consults the error's operation/member origin as well
/// as its `Reason`. An observer-side member (our view broke; the
/// target was never observed) passes through as an observer-side
/// failure however verdict-shaped its `Reason` is. Member-less errors
/// keep the historical `Reason`-only routing.
fn route_target_error(error: &LinuxError) -> Result<TargetVerdict, ()> {
    if is_observer_origin(error) {
        return Err(());
    }
    match error.reason() {
        Reason::Denied => Ok(TargetVerdict::Inconclusive(InconclusiveKind::TargetDenied)),
        Reason::Disappeared => Ok(TargetVerdict::Inconclusive(
            InconclusiveKind::TargetDisappeared,
        )),
        Reason::ChangedSource => Ok(TargetVerdict::Mismatch(MismatchKind::SourceChanged)),
        Reason::WrongContext => Ok(TargetVerdict::Mismatch(MismatchKind::ViewChanged)),
        Reason::Inconclusive => Ok(TargetVerdict::Inconclusive(InconclusiveKind::BirthUnclear)),
        _ => Err(()),
    }
}

fn route_or_fail(ctx: &mut OpCtx, error: LinuxError) -> Result<MappingOutcome, MappingFailure> {
    match route_target_error(&error) {
        Ok(TargetVerdict::Mismatch(kind)) => Ok(ctx.mismatch(kind)),
        Ok(TargetVerdict::Inconclusive(kind)) => Ok(ctx.inconclusive(kind)),
        Err(()) => Err(ctx.failure(error)),
    }
}

/// Observe the relation between one held object and one target range.
///
/// Flow: pre-effect validation (limits, policy coherence, retained-proof
/// recheck, empty file), pool admission, birth bracket, before/after bounded
/// maps reads retaining the named range/offset/permissions, one independent
/// map_files association attempt, then the key path (retained, calibrated or
/// mount-resolved) when exact association is denied. Requests for
/// atomic-current-image authority are refused by construction: every proof
/// documents its observation interval, never uninterrupted mapping.
pub fn observe_mapping(
    request: MappingRequest<'_>,
    control: &OperationControl,
) -> Result<MappingOutcome, MappingFailure> {
    let started = Instant::now();
    let failed = |error: LinuxError| MappingFailure {
        observation: None,
        error,
        unresolved: None,
        charges: Vec::new(),
    };
    // Pre-effect validation: no target work, no calibration, no admission.
    if let Err(error) = validate_policy(request.policy, &request.limits) {
        return Err(failed(error));
    }
    if let Err(error) = crate::process::validate_limits(request.limits.proc) {
        return Err(failed(error));
    }
    let held_stat = match request.held.stat() {
        Ok(stat) => stat,
        Err(error) => return Err(failed(error)),
    };
    let fs = classify_filesystem(request.held.as_fd());
    if let Some(retained) = request.retained {
        if let Err(error) = proof::recheck_retained(
            retained,
            &request.held,
            &held_stat,
            request.process,
            request.range,
        ) {
            return Err(failed(error));
        }
    }
    // Empty files are inconclusive without mapping, before admission.
    if held_stat.len() == 0 {
        return Ok(MappingOutcome::Inconclusive(InconclusiveReason::new(
            InconclusiveKind::EmptyFile,
            Vec::new(),
        )));
    }
    let guard = match OpGuard::admit(request.pool) {
        Ok(guard) => guard,
        Err(error) => return Err(failed(error)),
    };
    let mut ctx = OpCtx {
        control,
        max_open_fds: request.limits.max_open_fds,
        fd_spent: 0,
        charges: Vec::new(),
    };
    run_observation(&request, &held_stat, fs, &guard, &mut ctx, started)
}

/// Map_files association evidence for the requested range.
enum AssocEvidence {
    /// The VMA's own file is the held object.
    Exact((u64, u64)),
    /// The VMA's own file contradicts the held object.
    Contradictory,
    /// Association is denied: the key path decides.
    KeyPath,
}

/// Outcome of classifying a failed map_files association: either the
/// observation continues down the key path, or it is decided here.
enum AssocFailure {
    KeyPath,
    Done(Result<MappingOutcome, MappingFailure>),
}

/// S11: classify a failed map_files association. Origin first: an
/// observer-side failure (our view or authentication broke — e.g.
/// the observer-directory guard denied mid-call) routes through the
/// origin-aware router as an observer `MappingFailure`, never into
/// target evidence — even when its `Reason` matches a fallback below.
/// A target-side denial proceeds down the key path; a target-side
/// disappearance splits by inode (a missing entry for a file-backed
/// line means the VMA changed under the read; an anonymous line never
/// had one and simply names no file).
fn classify_assoc_error(
    ctx: &mut OpCtx,
    error: LinuxError,
    anon_inode_zero: bool,
) -> AssocFailure {
    if !is_observer_origin(&error) {
        if error.reason() == Reason::Denied {
            return AssocFailure::KeyPath;
        }
        if error.reason() == Reason::Disappeared {
            return AssocFailure::Done(Ok(if anon_inode_zero {
                ctx.mismatch(MismatchKind::KeyMismatch)
            } else {
                ctx.mismatch(MismatchKind::RangeChanged)
            }));
        }
    }
    AssocFailure::Done(route_or_fail(ctx, error))
}

fn run_observation(
    request: &MappingRequest<'_>,
    held_stat: &StatObservation,
    fs: FsClass,
    guard: &OpGuard,
    ctx: &mut OpCtx,
    started: Instant,
) -> Result<MappingOutcome, MappingFailure> {
    let control = ctx.control;
    let proc = request.limits.proc;
    let range = request.range;

    // Birth bracket: only a live same-birth target proceeds.
    let birth = match tracked(
        ctx,
        BIRTH_WORST_FDS,
        || request.process.verify_birth(control),
        crate::process::BirthVerification::charges,
    ) {
        Ok(birth) => birth,
        Err(error) => return route_or_fail(ctx, error),
    };
    let current_birth = birth
        .sampled_birth()
        .cloned()
        .unwrap_or_else(|| request.process.birth().clone());
    match birth.status() {
        BirthStatus::AliveSameBirth => {}
        BirthStatus::Exited => return Ok(ctx.inconclusive(InconclusiveKind::TargetExited)),
        BirthStatus::Changed => return Ok(ctx.mismatch(MismatchKind::BirthChanged)),
        BirthStatus::Inconclusive => return Ok(ctx.inconclusive(InconclusiveKind::BirthUnclear)),
    }

    // Before maps read: the named range must render.
    let maps_before = match tracked(
        ctx,
        MAPS_WORST_FDS,
        || request.process.read_maps(proc, control),
        crate::process::MapsObservation::charges,
    ) {
        Ok(maps) => maps,
        Err(error) => return route_or_fail(ctx, error),
    };
    let before = maps_before
        .snapshot()
        .entries()
        .find(|entry| entry.start() == range.start() && entry.end() == range.end());
    let Some(before) = before else {
        return Ok(ctx.mismatch(MismatchKind::RangeUnmapped));
    };
    let shape_before: LineShape = shape_of(&before);

    // Independent per-range association with both descriptors alive.
    let assoc = match tracked(
        ctx,
        MAP_FILES_WORST_FDS,
        || {
            request
                .process
                .read_map_files_identity(range.start(), range.end(), proc, control)
        },
        crate::process::MapFilesObservation::charges,
    ) {
        Ok(observation) => {
            let identity = observation.identity();
            let key = held_stat.key();
            if identity.device() == key.device_raw() && identity.inode() == key.inode() {
                AssocEvidence::Exact((identity.device(), identity.inode()))
            } else {
                AssocEvidence::Contradictory
            }
        }
        Err(error) => match classify_assoc_error(ctx, error, shape_before.key.inode() == 0) {
            AssocFailure::KeyPath => AssocEvidence::KeyPath,
            AssocFailure::Done(outcome) => return outcome,
        },
    };

    // Key path when exact association is denied: retained, calibrated or
    // mount-resolved, in that order of reuse.
    let mut pending_cleanup: Option<(LinuxError, MappingCustody)> = None;
    let (held_key, method) = match assoc {
        AssocEvidence::Exact(_) | AssocEvidence::Contradictory => {
            (shape_before.key, ProofMethod::MapFiles)
        }
        AssocEvidence::KeyPath => {
            if let Some(retained) = request.retained {
                (retained.maps_key(), ProofMethod::Retained)
            } else if let MappingPolicy::AllowPrivateCalibration { max_mapped_bytes } =
                request.policy
            {
                // S10: MappingLimits is an admission ceiling, not
                // post-effect accounting. Calibration's whole worst
                // case must fit the REMAINING budget before any of it
                // runs; a refused calibration performs zero
                // acquisitions (no mapping, no observation, no reads).
                if let Err(ceiling) = preadmit_fds(ctx, CALIBRATION_WORST_FDS) {
                    return Err(ctx.failure_full(None, ceiling, None));
                }
                match calibration::calibrate(
                    &request.held,
                    guard.domain(),
                    request.process.epoch(),
                    proc,
                    max_mapped_bytes,
                    control,
                ) {
                    Ok(completed) => {
                        if let Err(ceiling) = ctx.absorb(&completed.charges) {
                            let custody = completed.cleanup.map(|(_, custody)| custody);
                            return Err(ctx.failure_full(None, ceiling, custody));
                        }
                        pending_cleanup = completed.cleanup;
                        (completed.key.key, ProofMethod::Calibrated)
                    }
                    Err(calibration::CalibrationAbort::Inconclusive(kind)) => {
                        return Ok(ctx.inconclusive(kind));
                    }
                    Err(calibration::CalibrationAbort::Failed(failure)) => {
                        let custody = failure.unresolved;
                        if let Err(ceiling) = ctx.absorb(&failure.charges) {
                            return Err(ctx.failure_full(failure.observation, ceiling, custody));
                        }
                        return Err(ctx.failure_full(failure.observation, failure.error, custody));
                    }
                }
            } else {
                match mount_resolve_key(
                    request.held.as_fd(),
                    held_stat,
                    request.process,
                    request.limits.max_mount_refreshes,
                    proc,
                    ctx,
                ) {
                    MountKey::Key(key) => (key, ProofMethod::MountResolved),
                    MountKey::Unresolved => {
                        return Ok(ctx.inconclusive(InconclusiveKind::MountUnresolved));
                    }
                    MountKey::Verdict(TargetVerdict::Mismatch(kind)) => {
                        return Ok(ctx.mismatch(kind));
                    }
                    MountKey::Verdict(TargetVerdict::Inconclusive(kind)) => {
                        return Ok(ctx.inconclusive(kind));
                    }
                    MountKey::Failed(error) => return Err(ctx.failure(error)),
                }
            }
        }
    };

    // After maps read: the named range, offset and permissions must retain.
    let maps_after = match tracked(
        ctx,
        MAPS_WORST_FDS,
        || request.process.read_maps(proc, control),
        crate::process::MapsObservation::charges,
    ) {
        Ok(maps) => maps,
        Err(error) => {
            let outcome = route_or_fail(ctx, error);
            return finish(ctx, outcome, pending_cleanup);
        }
    };
    let after = maps_after
        .snapshot()
        .entries()
        .find(|entry| entry.start() == range.start() && entry.end() == range.end());
    let after_retained = after
        .map(|entry| shape_retained(&shape_before, &shape_of(&entry)))
        .unwrap_or(false);
    if !after_retained {
        let outcome = Ok(ctx.mismatch(MismatchKind::RangeChanged));
        return finish(ctx, outcome, pending_cleanup);
    }
    let after_key = after
        .map(|entry| entry.file_key())
        .unwrap_or(shape_before.key);

    // Verdict: exact association needs the map_files route; raw-key equality
    // can at most yield the key relation.
    let outcome = match assoc {
        AssocEvidence::Exact(identity) => {
            let proof = build_proof(
                request,
                held_stat,
                after_key,
                fs,
                &current_birth,
                ProofMethod::MapFiles,
                ctx,
                started,
            );
            MappingOutcome::ExactRange(MapRangeProof::new(proof, identity))
        }
        AssocEvidence::Contradictory => ctx.mismatch(MismatchKind::KeyMismatch),
        AssocEvidence::KeyPath => match key_verdict(after_key, held_key) {
            KeyVerdict::Compatible => {
                let proof = build_proof(
                    request,
                    held_stat,
                    after_key,
                    fs,
                    &current_birth,
                    method,
                    ctx,
                    started,
                );
                MappingOutcome::KeyCompatible(proof)
            }
            KeyVerdict::Mismatch => ctx.mismatch(MismatchKind::KeyMismatch),
        },
    };
    finish(ctx, Ok(outcome), pending_cleanup)
}

/// Attach a pending calibration cleanup to the determined outcome: success
/// stays success, and failed cleanup keeps the observation separately
/// inspectable beside the live custody.
fn finish(
    ctx: &mut OpCtx,
    outcome: Result<MappingOutcome, MappingFailure>,
    pending_cleanup: Option<(LinuxError, MappingCustody)>,
) -> Result<MappingOutcome, MappingFailure> {
    let Some((error, custody)) = pending_cleanup else {
        return outcome;
    };
    match outcome {
        Ok(determined) => Err(MappingFailure {
            observation: Some(determined),
            error,
            unresolved: Some(custody),
            charges: ctx.take_charges(),
        }),
        Err(mut failure) => {
            // Both the observation path and calibration cleanup failed: the
            // observation error stands, and calibration custody must not be
            // silently dropped, so prefer the live custody. The calibration
            // error is superseded but its custody survives.
            let _ = error;
            if failure.unresolved.is_none() {
                failure.unresolved = Some(custody);
            } else {
                // Two live custodies cannot merge into one failure slot; queue
                // the calibration record explicitly by dropping it (failed
                // Drop-time unmaps queue; successful ones retire).
                drop(custody);
            }
            Err(failure)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_proof(
    request: &MappingRequest<'_>,
    held_stat: &StatObservation,
    key: MapsFileKey,
    fs: FsClass,
    birth: &crate::identity::TaskBirthObservation,
    method: ProofMethod,
    ctx: &mut OpCtx,
    started: Instant,
) -> MappingProof {
    MappingProof::new(
        Arc::clone(&request.held),
        *held_stat,
        key,
        fs,
        birth.clone(),
        request.process.mount_view().clone(),
        method,
        request.range,
        request.process.epoch().clone(),
        ObservationInterval::new(started, Instant::now()),
        ctx.take_charges(),
    )
}

/// Mount-resolution result: the held maps-domain key, an unresolved mount
/// (after the allowed refresh), a routed target verdict or an observer-side
/// failure.
enum MountKey {
    Key(MapsFileKey),
    Unresolved,
    Verdict(TargetVerdict),
    Failed(LinuxError),
}

/// Resolve the held object's maps-comparable key: its fdinfo mount ID through
/// the target mount table (ADAPT P `mapping_file_key_in_mountinfo` doctrine:
/// `st_dev` is never substituted), re-reading the table once when the row is
/// missing (ADAPT P `reread_on_missing_mount` @2c2713e6). The held FD stays
/// open across the retry so its mount cannot detach underneath.
fn mount_resolve_key(
    held_fd: std::os::fd::BorrowedFd<'_>,
    held_stat: &StatObservation,
    process: &ProcessObservation,
    max_refreshes: u8,
    proc: ProcLimits,
    ctx: &mut OpCtx,
) -> MountKey {
    // R12/R13: the fdinfo read charges itself on every path (open,
    // each read attempt, close, cross-check stat) against the caller's
    // own read ceiling; the old fixed post-success (3, 1) undercounted
    // the stat and dropped failure-path charges.
    let control = ctx.control;
    let mnt_id = match read_fdinfo_mnt_id(held_fd, held_stat, ctx, control, proc.max_read_calls) {
        Ok(id) => id,
        Err(error) => return MountKey::Failed(error),
    };
    let mut used = 0u8;
    loop {
        let table = match tracked(
            ctx,
            MOUNTINFO_WORST_FDS,
            || process.read_mountinfo(proc, ctx.control),
            crate::process::MountObservation::charges,
        ) {
            Ok(table) => table,
            Err(error) => match route_target_error(&error) {
                Ok(verdict) => return MountKey::Verdict(verdict),
                Err(()) => return MountKey::Failed(error),
            },
        };
        if let Some(key) = lookup_mount_key(table.snapshot(), mnt_id, held_stat.key().inode()) {
            return MountKey::Key(key);
        }
        if used >= max_refreshes {
            return MountKey::Unresolved;
        }
        used += 1;
    }
}

/// Look up one fdinfo mount ID in a target mount table, returning the
/// maps-comparable `(major, minor, st_ino)` key. A missing row is `None`:
/// incomparable, never a substituted `st_dev`.
fn lookup_mount_key(
    table: &crate::procfs::MountTableSnapshot,
    mnt_id: u64,
    ino: u64,
) -> Option<MapsFileKey> {
    table.entry_by_number(mnt_id).map(|row| MapsFileKey {
        major: row.device().major(),
        minor: row.device().minor(),
        inode: ino,
    })
}

/// Read this held FD's mount ID from its own fdinfo, cross-checked against
/// the held stat key so a recycled descriptor number can never resolve a
/// foreign mount. One bounded single read: fdinfo never fills 4 KiB.
///
/// R12: charges are recorded on every path that issues syscalls,
/// including failures after the open. The old code only charged
/// success: a later failure dropped the successful open's charge, and
/// the cross-check stat was never counted at all. R13: every read
/// attempt checkpoints control and counts against `max_read_attempts`
/// (the caller's own read ceiling), so an INTR storm cannot spin past
/// cancel/deadline or past the budget.
fn read_fdinfo_mnt_id(
    fd: std::os::fd::BorrowedFd<'_>,
    held: &StatObservation,
    ctx: &mut OpCtx,
    control: &OperationControl,
    max_read_attempts: u64,
) -> Result<u64, LinuxError> {
    use std::os::fd::AsRawFd;
    let raw = fd.as_raw_fd();
    if raw < 0 {
        return Err(pool::pool_error(
            Stage::ObserveMapping,
            Reason::InvalidInput,
            CleanupDisposition::NotNeeded,
        ));
    }
    let raw = raw as u32;
    let mut info_storage = [0u8; 64];
    let mut fd_storage = [0u8; 64];
    let info_path = render_proc_path("/proc/self/fdinfo/", raw, &mut info_storage)?;
    let fd_path = render_proc_path("/proc/self/fd/", raw, &mut fd_storage)?;
    let map_err =
        |errno: rustix::io::Errno| pool::pool_error_with_source(Stage::ObserveMapping, errno);
    // R11: pre-admit the one fdinfo FD before opening: a spent budget
    // refuses without touching the kernel. Every path below records
    // (never spends), so failure charges can never mask the real error.
    preadmit_fds(ctx, 1)?;
    let mut syscalls = 0u64;
    let file = match rustix::fs::open(
        info_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Err(errno) => {
            ctx.record_direct(1, 0);
            return Err(map_err(errno));
        }
        Ok(file) => {
            syscalls += 1;
            file
        }
    };
    let mut buf = [0u8; 4096];
    let mut attempts = 0u64;
    let count = loop {
        if attempts >= max_read_attempts {
            ctx.record_direct(syscalls, 1);
            return Err(pool::pool_error(
                Stage::ObserveMapping,
                Reason::LimitExceeded(LimitKind::ReadCalls),
                CleanupDisposition::Complete,
            ));
        }
        if let Err(stop) = control.checkpoint() {
            ctx.record_direct(syscalls, 1);
            return Err(pool::pool_error(
                Stage::ObserveMapping,
                match stop {
                    crate::control::ControlStop::Cancelled => Reason::Cancelled,
                    crate::control::ControlStop::Deadline => Reason::Deadline,
                },
                CleanupDisposition::Complete,
            ));
        }
        attempts += 1;
        syscalls += 1;
        match rustix::io::read(&file, &mut buf) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(errno) => {
                ctx.record_direct(syscalls, 1);
                return Err(map_err(errno));
            }
            Ok(count) => break count,
        }
    };
    // S45: no charge for the RAII close — ResourceCharges counts
    // explicit syscall attempts only (see error.rs).
    drop(file);
    if count == buf.len() {
        ctx.record_direct(syscalls, 1);
        return Err(pool::pool_error(
            Stage::ObserveMapping,
            Reason::Malformed,
            CleanupDisposition::Complete,
        ));
    }
    let mnt_id = match parse_fdinfo_mnt_id(&buf[..count]) {
        Some(id) => id,
        None => {
            ctx.record_direct(syscalls, 1);
            return Err(pool::pool_error(
                Stage::ObserveMapping,
                Reason::Malformed,
                CleanupDisposition::Complete,
            ));
        }
    };
    // Cross-check: the numbered FD still names the held object.
    syscalls += 1; // statat
    let stat = match rustix::fs::statat(rustix::fs::CWD, fd_path, rustix::fs::AtFlags::empty()) {
        Err(errno) => {
            ctx.record_direct(syscalls, 1);
            return Err(map_err(errno));
        }
        Ok(stat) => stat,
    };
    let device = u64::try_from(stat.st_dev as i128).unwrap_or(u64::MAX);
    let inode = u64::try_from(stat.st_ino as i128).unwrap_or(u64::MAX);
    if device != held.key().device_raw() || inode != held.key().inode() {
        ctx.record_direct(syscalls, 1);
        return Err(pool::pool_error(
            Stage::ObserveMapping,
            Reason::WrongContext,
            CleanupDisposition::Complete,
        ));
    }
    ctx.record_direct(syscalls, 1);
    Ok(mnt_id)
}

/// Render `<prefix><decimal>` plus NUL into caller storage.
fn render_proc_path<'a>(
    prefix: &str,
    raw: u32,
    storage: &'a mut [u8; 64],
) -> Result<&'a CStr, LinuxError> {
    let bytes = prefix.as_bytes();
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    let mut rest = raw;
    loop {
        digits[count] = b'0' + (rest % 10) as u8;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if bytes.len() + count + 1 > storage.len() {
        return Err(pool::pool_error(
            Stage::ObserveMapping,
            Reason::InvalidInput,
            CleanupDisposition::NotNeeded,
        ));
    }
    storage[..bytes.len()].copy_from_slice(bytes);
    for (index, digit) in digits[..count].iter().rev().enumerate() {
        storage[bytes.len() + index] = *digit;
    }
    let len = bytes.len() + count;
    storage[len] = 0;
    CStr::from_bytes_with_nul(&storage[..len + 1]).map_err(|_| {
        pool::pool_error(
            Stage::ObserveMapping,
            Reason::Malformed,
            CleanupDisposition::NotNeeded,
        )
    })
}

/// Parse one fdinfo `mnt_id:` line: exactly decimal digits, `u64`-checked.
fn parse_fdinfo_mnt_id(input: &[u8]) -> Option<u64> {
    for line in input.split(|byte| *byte == b'\n') {
        let Some(rest) = line.strip_prefix(b"mnt_id:") else {
            continue;
        };
        let digits = rest
            .iter()
            .skip_while(|byte| **byte == b' ' || **byte == b'\t')
            .copied()
            .collect::<Vec<u8>>();
        if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let text = core::str::from_utf8(&digits).ok()?;
        if let Ok(id) = text.parse::<u64>() {
            return Some(id);
        }
    }
    None
}

/// Error-bearing filesystem classification: a failed fstatfs is `Unknown`,
/// never an observation failure and never ordinary.
fn classify_filesystem(fd: std::os::fd::BorrowedFd<'_>) -> FsClass {
    match rustix::fs::fstatfs(fd) {
        Ok(fs) => FsClass::from_magic(fs.f_type as u64),
        Err(_) => FsClass::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::{parse_mountinfo, ParseLimits};

    fn error_with(reason: Reason) -> LinuxError {
        pool::pool_error(Stage::ObserveMapping, reason, CleanupDisposition::Complete)
    }

    #[test]
    fn target_error_routing_covers_every_reason() {
        // Verdicts: target-side states become outcomes.
        assert!(matches!(
            route_target_error(&error_with(Reason::Denied)).unwrap(),
            TargetVerdict::Inconclusive(InconclusiveKind::TargetDenied)
        ));
        assert!(matches!(
            route_target_error(&error_with(Reason::Disappeared)).unwrap(),
            TargetVerdict::Inconclusive(InconclusiveKind::TargetDisappeared)
        ));
        assert!(matches!(
            route_target_error(&error_with(Reason::ChangedSource)).unwrap(),
            TargetVerdict::Mismatch(MismatchKind::SourceChanged)
        ));
        assert!(matches!(
            route_target_error(&error_with(Reason::WrongContext)).unwrap(),
            TargetVerdict::Mismatch(MismatchKind::ViewChanged)
        ));
        assert!(matches!(
            route_target_error(&error_with(Reason::Inconclusive)).unwrap(),
            TargetVerdict::Inconclusive(InconclusiveKind::BirthUnclear)
        ));
        // Passthrough: control, budgets, config and environment stay errors.
        for reason in [
            Reason::InvalidInput,
            Reason::NonRegular,
            Reason::Unreadable,
            Reason::Unavailable,
            Reason::Malformed,
            Reason::Cancelled,
            Reason::Deadline,
            Reason::Allocation,
            Reason::LimitExceeded(LimitKind::OpenFds),
        ] {
            assert!(
                route_target_error(&error_with(reason)).is_err(),
                "{reason:?} must pass through"
            );
        }
    }

    #[cfg(feature = "process")]
    fn error_with_member(reason: Reason, member: crate::error::ProcMember) -> LinuxError {
        use crate::error::{ProcOperation, ProcessErrorContext};
        let mut error = error_with(reason);
        error.process = Some(ProcessErrorContext::new(
            ProcOperation::ReadMaps,
            Some(member),
        ));
        error
    }

    /// S11 observer-guard denial control: a verdict-shaped `Reason`
    /// on an observer-side member (our view broke — e.g. the
    /// post-acquisition observer-directory open denied) passes
    /// through as an observer-side failure, never a target verdict.
    /// Target-side members keep `Reason` routing, and member-less
    /// errors keep the historical behavior.
    #[test]
    #[cfg(feature = "process")]
    fn observer_origin_errors_pass_through_as_failures() {
        use crate::error::ProcMember::*;
        let verdict_shaped = [
            Reason::Denied,
            Reason::Disappeared,
            Reason::ChangedSource,
            Reason::WrongContext,
            Reason::Inconclusive,
        ];
        for member in [
            Root,
            SelfLink,
            ObserverDirectory,
            ObserverStatus,
            ObserverPidNamespace,
            CreatorPidfd,
        ] {
            for reason in verdict_shaped {
                assert!(
                    route_target_error(&error_with_member(reason, member)).is_err(),
                    "{member:?}/{reason:?} must pass through as an observer-side failure"
                );
            }
        }
        // Target-side members: Reason routing unchanged.
        for member in [
            TargetDirectory,
            TargetStatus,
            TargetStat,
            TargetPidNamespace,
            TargetMountNamespace,
            Maps,
            Mountinfo,
            MapFiles,
            Pidfd,
        ] {
            assert!(
                matches!(
                    route_target_error(&error_with_member(Reason::Denied, member)).unwrap(),
                    TargetVerdict::Inconclusive(InconclusiveKind::TargetDenied)
                ),
                "{member:?}/Denied must stay a target verdict"
            );
            assert!(
                matches!(
                    route_target_error(&error_with_member(Reason::WrongContext, member)).unwrap(),
                    TargetVerdict::Mismatch(MismatchKind::ViewChanged)
                ),
                "{member:?}/WrongContext must stay a target verdict"
            );
        }
        // Member-less context: historical Reason routing preserved.
        let mut bare = error_with(Reason::Denied);
        bare.process = Some(crate::error::ProcessErrorContext::new(
            crate::error::ProcOperation::ReadMaps,
            None,
        ));
        assert!(
            matches!(
                route_target_error(&bare).unwrap(),
                TargetVerdict::Inconclusive(InconclusiveKind::TargetDenied)
            ),
            "member-less Denied must stay a target verdict"
        );
    }

    /// S11-round3: origin gates every assoc fallback. A verdict-shaped
    /// `Reason` on an observer-side member (e.g. the
    /// observer-directory guard denied mid-call) routes as an
    /// observer failure through the production classifier — never
    /// into key-path evidence or an inode-split verdict. Target-side
    /// and member-less errors keep the historical fallbacks.
    #[test]
    #[cfg(feature = "process")]
    fn assoc_fallbacks_refuse_observer_origin() {
        use crate::error::ProcMember::*;
        let control = OperationControl::unlimited();
        // Target-side denial proceeds down the key path.
        let mut ctx = op_ctx(&control, 1024);
        assert!(
            matches!(
                classify_assoc_error(
                    &mut ctx,
                    error_with_member(Reason::Denied, MapFiles),
                    false
                ),
                AssocFailure::KeyPath
            ),
            "target-side Denied must stay key-path evidence"
        );
        // Member-less denial keeps the historical key path.
        let mut ctx = op_ctx(&control, 1024);
        assert!(
            matches!(
                classify_assoc_error(&mut ctx, error_with(Reason::Denied), false),
                AssocFailure::KeyPath
            ),
            "member-less Denied must stay key-path evidence"
        );
        // Observer-guard denial is an observer failure, never
        // key-path evidence.
        for member in [ObserverDirectory, ObserverStatus, Root, CreatorPidfd] {
            let mut ctx = op_ctx(&control, 1024);
            match classify_assoc_error(
                &mut ctx,
                error_with_member(Reason::Denied, member),
                false,
            ) {
                AssocFailure::Done(Err(failure)) => assert_eq!(
                    failure.error().reason(),
                    Reason::Denied,
                    "{member:?}/Denied must surface its own reason"
                ),
                AssocFailure::KeyPath => {
                    panic!("{member:?}/Denied must not reach the key path")
                }
                AssocFailure::Done(Ok(_)) => {
                    panic!("{member:?}/Denied must not become a verdict")
                }
            }
        }
        // Target-side disappearance keeps the inode split.
        let mut ctx = op_ctx(&control, 1024);
        match classify_assoc_error(
            &mut ctx,
            error_with_member(Reason::Disappeared, MapFiles),
            true,
        ) {
            AssocFailure::Done(Ok(MappingOutcome::Mismatch(evidence))) => assert_eq!(
                evidence.kind(),
                MismatchKind::KeyMismatch,
                "anonymous disappearance stays KeyMismatch"
            ),
            _ => panic!("target-side anonymous disappearance must stay KeyMismatch"),
        }
        let mut ctx = op_ctx(&control, 1024);
        match classify_assoc_error(
            &mut ctx,
            error_with_member(Reason::Disappeared, MapFiles),
            false,
        ) {
            AssocFailure::Done(Ok(MappingOutcome::Mismatch(evidence))) => assert_eq!(
                evidence.kind(),
                MismatchKind::RangeChanged,
                "file-backed disappearance stays RangeChanged"
            ),
            _ => panic!("target-side file disappearance must stay RangeChanged"),
        }
        // Observer-side disappearance is a failure, not a verdict.
        let mut ctx = op_ctx(&control, 1024);
        match classify_assoc_error(
            &mut ctx,
            error_with_member(Reason::Disappeared, ObserverDirectory),
            false,
        ) {
            AssocFailure::Done(Err(failure)) => assert_eq!(
                failure.error().reason(),
                Reason::Disappeared
            ),
            _ => panic!("observer-side disappearance must not become a verdict"),
        }
        // Post-fork shape (WrongContext/CreatorPidfd) is a failure.
        let mut ctx = op_ctx(&control, 1024);
        match classify_assoc_error(
            &mut ctx,
            error_with_member(Reason::WrongContext, CreatorPidfd),
            false,
        ) {
            AssocFailure::Done(Err(failure)) => assert_eq!(
                failure.error().reason(),
                Reason::WrongContext
            ),
            _ => panic!("post-fork WrongContext must not become a verdict"),
        }
        // Member-less WrongContext keeps the historical ViewChanged.
        let mut ctx = op_ctx(&control, 1024);
        match classify_assoc_error(&mut ctx, error_with(Reason::WrongContext), false) {
            AssocFailure::Done(Ok(MappingOutcome::Mismatch(evidence))) => assert_eq!(
                evidence.kind(),
                MismatchKind::ViewChanged
            ),
            _ => panic!("member-less WrongContext must stay ViewChanged"),
        }
    }

    /// S11-round3: a post-fork observation through the production
    /// `observe_mapping` path is an observer-side `MappingFailure`,
    /// never a target `ViewChanged` mismatch. The forged creator is
    /// our own parent pid — the exact pid pair a forked child would
    /// present — and the failure must carry the CreatorPidfd origin.
    /// The member-less former shape routed Ok(ViewChanged) here.
    #[test]
    #[cfg(feature = "process")]
    fn post_fork_observe_mapping_is_observer_failure() {
        use crate::process::{ObserverEpoch, Pid};
        let control = OperationControl::unlimited();
        let epoch = ObserverEpoch::new(proc_limits(), &control).expect("epoch on own process");
        let pid = Pid::new(std::process::id() as i32).expect("own pid");
        let mut process =
            crate::process::ProcessObservation::acquire(pid, &epoch, proc_limits(), &control)
                .expect("acquire self");
        // Post-fork state: creator (parent) != current (self).
        let parent = Pid::new(
            rustix::process::getppid()
                .expect("parent pid")
                .as_raw_nonzero()
                .get(),
        )
        .expect("positive parent pid");
        assert_ne!(parent, pid, "test must not be its own parent");
        process.forge_post_fork_epoch(epoch.forge_post_fork_creator(parent));
        let (path, held) = fdinfo_held("postfork");
        let pool = pool::MappingPool::new(pool::MappingPoolLimits {
            max_mappings: 0,
            max_mapped_bytes: 0,
        })
        .expect("no-new pool");
        let page = rustix::param::page_size() as u64;
        let failure = observe_mapping(
            MappingRequest {
                pool: &pool,
                held,
                process: &process,
                range: MapRange::new(page, 2 * page).expect("page range"),
                policy: MappingPolicy::NoNewTargetMappings,
                retained: None,
                limits: MappingLimits {
                    proc: proc_limits(),
                    max_mount_refreshes: 1,
                    max_open_fds: 1024,
                    max_live_mappings: 0,
                },
            },
            &control,
        )
        .expect_err("post-fork observation must fail, not mismatch");
        assert_eq!(failure.error().reason(), Reason::WrongContext);
        assert_eq!(
            failure
                .error()
                .process_context()
                .and_then(crate::error::ProcessErrorContext::member),
            Some(crate::error::ProcMember::CreatorPidfd),
            "creator mismatch must keep its observer origin"
        );
        pool.close(&control).expect("pool closes");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn policy_coherence_matrix() {
        let base = MappingLimits {
            proc: ProcLimits {
                parse: ParseLimits {
                    max_bytes: 1,
                    max_entries: 1,
                    max_line_bytes: 1,
                },
                max_read_calls: 1,
                max_metadata_bytes: 1,
            },
            max_mount_refreshes: 1,
            max_open_fds: 1,
            max_live_mappings: 0,
        };
        assert!(validate_policy(MappingPolicy::NoNewTargetMappings, &base).is_ok());
        let calibration = MappingLimits {
            max_live_mappings: 1,
            ..base
        };
        assert!(validate_policy(
            MappingPolicy::AllowPrivateCalibration {
                max_mapped_bytes: 4096
            },
            &calibration
        )
        .is_ok());
        // Uncalibrated live request refuses.
        assert!(validate_policy(MappingPolicy::NoNewTargetMappings, &calibration).is_err());
        // Calibration-shaped ceiling without calibration refuses.
        assert!(validate_policy(
            MappingPolicy::AllowPrivateCalibration {
                max_mapped_bytes: 4096
            },
            &base
        )
        .is_err());
        // Refresh counts above one refuse.
        let churn = MappingLimits {
            max_mount_refreshes: 2,
            ..base
        };
        assert!(validate_policy(MappingPolicy::NoNewTargetMappings, &churn).is_err());
        let churn = MappingLimits {
            max_mount_refreshes: 0,
            ..base
        };
        assert!(validate_policy(MappingPolicy::NoNewTargetMappings, &churn).is_ok());
    }

    #[test]
    fn fdinfo_mnt_id_parsing_is_strict() {
        let good = b"pos:\t0\nflags:\t0100000\nmnt_id:\t45\nino:\t123\n";
        assert_eq!(parse_fdinfo_mnt_id(good), Some(45));
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id: 7\n"), Some(7));
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id:\t0\n"), Some(0));
        // Missing, empty, signed, hex or trailing-garbage values refuse.
        assert_eq!(parse_fdinfo_mnt_id(b"pos:\t0\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id:\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id: -1\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id: 0x2d\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id: 45x\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id: 4 5\n"), None);
        // Overflow refuses rather than wrapping.
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id: 18446744073709551616\n"), None);
        assert_eq!(
            parse_fdinfo_mnt_id(b"mnt_id: 18446744073709551615\n"),
            Some(u64::MAX)
        );
    }

    #[test]
    fn mount_lookup_resolves_or_reports_missing() {
        let limits = ParseLimits {
            max_bytes: 1 << 20,
            max_entries: 1 << 16,
            max_line_bytes: 1 << 16,
        };
        let table = parse_mountinfo(
            b"34 45 0:29 / /run rw,nosuid,nodev shared:13 - tmpfs tmpfs rw\n45 1 0:35 /@ / rw,noatime shared:1 - btrfs /dev/sda3 rw\n",
            limits,
        )
        .unwrap();
        let key = lookup_mount_key(&table, 45, 101192187).unwrap();
        assert_eq!(
            (key.device_major(), key.device_minor(), key.inode()),
            (0, 35, 101192187)
        );
        // A missing mount row is incomparable, never a substituted st_dev.
        assert!(lookup_mount_key(&table, 999, 101192187).is_none());
    }

    #[test]
    fn fstatfs_failure_is_unknown_never_ordinary() {
        // An out-of-range descriptor fails fstatfs with EBADF however the
        // test process races FD allocation: the classification is Unknown
        // (refuses reuse), never a silent ordinary filesystem.
        let bad = unsafe { std::os::fd::BorrowedFd::borrow_raw(i32::MAX - 1) };
        assert_eq!(classify_filesystem(bad), FsClass::Unknown);
        // A valid descriptor classifies by its real magic.
        let file = std::fs::File::open("/proc/self/mountinfo").unwrap();
        assert_ne!(
            classify_filesystem(std::os::fd::AsFd::as_fd(&file)),
            FsClass::Unknown
        );
    }

    #[test]
    fn fd_ceiling_counts_cumulative_acquisitions() {
        let control = OperationControl::unlimited();
        let mut ctx = OpCtx {
            control: &control,
            max_open_fds: 2,
            fd_spent: 0,
            charges: Vec::new(),
        };
        let one = ResourceCharges {
            syscalls: 1,
            acquired: 1,
            peak: 1,
            read: None,
            parse: None,
            #[cfg(feature = "process")]
            process: None,
        };
        assert!(ctx.spend(&one).is_ok());
        assert!(ctx.spend(&one).is_ok());
        let err = ctx.spend(&one).unwrap_err();
        assert_eq!(err.reason(), Reason::LimitExceeded(LimitKind::OpenFds));
        // Reached charges stay recorded on the refusal path.
        assert_eq!(ctx.charges.len(), 3);
    }

    fn proc_limits() -> ProcLimits {
        ProcLimits {
            parse: ParseLimits {
                max_bytes: 1 << 20,
                max_entries: 1 << 16,
                max_line_bytes: 1 << 16,
            },
            max_read_calls: 4096,
            max_metadata_bytes: 1 << 20,
        }
    }

    fn self_observation(control: &OperationControl) -> ProcessObservation {
        use crate::process::{ObserverEpoch, Pid};
        let epoch = ObserverEpoch::new(proc_limits(), control).expect("epoch on own process");
        let pid = Pid::new(std::process::id() as i32).expect("own pid");
        ProcessObservation::acquire(pid, &epoch, proc_limits(), control).expect("acquire self")
    }

    /// R11: the worst-case constants match the success path exactly, so a
    /// sub-operation that gains an open fails here until its constant is
    /// deliberately updated. Error paths return early and acquire fewer.
    #[test]
    fn worst_case_constants_match_success_acquisitions() {
        // S46: the probe mapping serializes on FD_TABLE with the
        // fixed-hole tests, so no floating placement can steal a
        // hole window. The mutex takes no fd; charge counts below
        // are unaffected.
        let _table = crate::FD_TABLE.lock().unwrap();
        let control = OperationControl::unlimited();
        let process = self_observation(&control);
        // S10: the strict acquisition behind calibration's worst case
        // (six steps, not the 5-FD re-verification below).
        assert_eq!(
            process.acquisition_charges().fd_acquisitions(),
            ACQUIRE_WORST_FDS,
            "guard + pre-sample + pidfd + dir + namespaces + view"
        );
        let birth = process.verify_birth(&control).expect("birth on live self");
        assert_eq!(
            birth.charges().fd_acquisitions(),
            BIRTH_WORST_FDS,
            "guard 4 + stat 1"
        );
        let maps = process.read_maps(proc_limits(), &control).expect("maps");
        assert_eq!(
            maps.charges().fd_acquisitions(),
            MAPS_WORST_FDS,
            "guard 4 + view 5 + member 1 + view 5"
        );
        let mounts = process
            .read_mountinfo(proc_limits(), &control)
            .expect("mountinfo");
        assert_eq!(
            mounts.charges().fd_acquisitions(),
            MOUNTINFO_WORST_FDS,
            "same shape as maps"
        );
        // map_files needs a live mapped range; environments that deny its
        // stat (EPERM even for self here) take the denial path instead.
        use std::os::fd::AsFd;
        let (map_path, map_held) = fdinfo_held("mapfiles");
        let page = rustix::param::page_size();
        let addr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                page,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE,
                map_held.as_fd(),
                0,
            )
        }
        .expect("probe mapping");
        let start = addr as u64;
        let observed =
            process.read_map_files_identity(start, start + page as u64, proc_limits(), &control);
        unsafe { rustix::mm::munmap(addr, page) }.expect("unmap probe page");
        std::fs::remove_file(map_path).unwrap();
        match observed {
            Ok(assoc) => assert_eq!(
                assoc.charges().fd_acquisitions(),
                MAP_FILES_WORST_FDS,
                "guard 4 + view 5 + dir 1 + object 1"
            ),
            Err(error) if error.reason() == Reason::Denied => assert_eq!(
                error.charges().fd_acquisitions(),
                MAP_FILES_WORST_FDS - 1,
                "denied object open: all but the last acquisition"
            ),
            Err(error) => panic!("unexpected map_files outcome: {:?}", error.reason()),
        }
    }

    fn identity_charges(charges: &ResourceCharges) -> &ResourceCharges {
        charges
    }

    /// R11: a positive-but-insufficient budget refuses WITHOUT executing
    /// the thunk (the executed flag is the hook counter: zero runs, zero
    /// acquisitions), while an exact fit runs. The old fully-spent-only
    /// preflight ran the first case and over-acquired transiently.
    #[test]
    fn tracked_preflight_refuses_without_executing() {
        use std::cell::Cell;
        let control = OperationControl::unlimited();
        let mut ctx = OpCtx {
            control: &control,
            max_open_fds: 10,
            fd_spent: 6,
            charges: Vec::new(),
        };
        let executed = Cell::new(false);
        let err = tracked(
            &mut ctx,
            5,
            || {
                executed.set(true);
                Ok(pool::zero_charges())
            },
            identity_charges,
        )
        .unwrap_err();
        assert_eq!(err.reason(), Reason::LimitExceeded(LimitKind::OpenFds));
        assert!(!executed.get(), "refused thunk must not execute");
        assert!(ctx.charges.is_empty(), "zero runs, zero charges");
        // Exact-fit twin: spent 5 + worst 5 fits 10, so the thunk runs.
        ctx.fd_spent = 5;
        let value = tracked(
            &mut ctx,
            5,
            || {
                executed.set(true);
                Ok(pool::zero_charges())
            },
            identity_charges,
        )
        .expect("exact fit runs");
        assert!(executed.get());
        assert_eq!(value.fd_acquisitions(), 0);
        assert_eq!(ctx.charges.len(), 1);
    }

    /// R12: absorb records every batch member, then reports the first
    /// breach once. Post-breach members used to vanish from the ledger.
    #[test]
    fn absorb_records_all_before_first_breach() {
        let control = OperationControl::unlimited();
        let mut ctx = OpCtx {
            control: &control,
            max_open_fds: 2,
            fd_spent: 0,
            charges: Vec::new(),
        };
        let one = ResourceCharges {
            syscalls: 1,
            acquired: 1,
            peak: 1,
            read: None,
            parse: None,
            #[cfg(feature = "process")]
            process: None,
        };
        let err = ctx
            .absorb(&[one.clone(), one.clone(), one.clone()])
            .unwrap_err();
        assert_eq!(err.reason(), Reason::LimitExceeded(LimitKind::OpenFds));
        assert_eq!(ctx.charges.len(), 3, "all members recorded");
        assert_eq!(ctx.fd_spent, 3, "honest over-ceiling total");
        // All-fit batches still succeed.
        let mut ctx = OpCtx {
            control: &control,
            max_open_fds: 2,
            fd_spent: 0,
            charges: Vec::new(),
        };
        assert!(ctx.absorb(&[one.clone(), one]).is_ok());
        assert_eq!(ctx.charges.len(), 2);
    }

    static FDINFO_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn fdinfo_held(tag: &str) -> (std::path::PathBuf, std::sync::Arc<HeldFile>) {
        use crate::file::{ProcFdResolver, SymlinkPolicy};
        use std::sync::atomic::Ordering;
        let id = FDINFO_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "r12-fdinfo-{}-{}-{}.dat",
            std::process::id(),
            id,
            tag
        ));
        std::fs::write(&path, b"fdinfo probe").expect("write probe file");
        let resolver = ProcFdResolver::open_self().expect("resolver");
        let held = std::sync::Arc::new(
            HeldFile::open(&path, &resolver, SymlinkPolicy::Follow).expect("hold probe file"),
        );
        (path, held)
    }

    fn op_ctx(control: &OperationControl, max_open_fds: usize) -> OpCtx<'_> {
        OpCtx {
            control,
            max_open_fds,
            fd_spent: 0,
            charges: Vec::new(),
        }
    }

    /// R12: a successful fdinfo read charges open + read +
    /// cross-check statat (3 syscalls, 1 acquisition); the RAII
    /// close is uncharged (S45). The old fixed post-success
    /// (3, 1) never counted the stat.
    #[test]
    fn fdinfo_success_charges_every_syscall() {
        use std::os::fd::AsFd;
        let control = OperationControl::unlimited();
        let mut ctx = op_ctx(&control, 1024);
        let (path, held) = fdinfo_held("ok");
        let stat = held.stat().expect("stat probe file");
        let _mnt_id = read_fdinfo_mnt_id(held.as_fd(), &stat, &mut ctx, &control, 4096)
            .expect("fdinfo resolves");
        assert_eq!(ctx.charges.len(), 1);
        assert_eq!(ctx.charges[0].syscalls, 3, "open + read + statat (S45: RAII close uncharged)");
        assert_eq!(ctx.charges[0].fd_acquisitions(), 1);
        assert_eq!(ctx.fd_spent, 1);
        std::fs::remove_file(path).unwrap();
    }

    /// R12: a cross-check failure still records the successful open and
    /// every syscall (the old code charged nothing on this path).
    #[test]
    fn fdinfo_mismatch_records_open_before_refusing() {
        use std::os::fd::AsFd;
        let control = OperationControl::unlimited();
        let mut ctx = op_ctx(&control, 1024);
        let (path_a, held_a) = fdinfo_held("a");
        let (path_b, held_b) = fdinfo_held("b");
        let stat_b = held_b.stat().expect("stat other file");
        let err = read_fdinfo_mnt_id(held_a.as_fd(), &stat_b, &mut ctx, &control, 4096)
            .expect_err("foreign stat must refuse");
        assert_eq!(err.reason(), Reason::WrongContext);
        assert_eq!(ctx.charges.len(), 1);
        assert_eq!(ctx.charges[0].syscalls, 3, "open + read + statat (S45: RAII close uncharged)");
        assert_eq!(ctx.charges[0].fd_acquisitions(), 1, "the open is kept");
        assert_eq!(ctx.fd_spent, 1);
        std::fs::remove_file(path_a).unwrap();
        std::fs::remove_file(path_b).unwrap();
    }

    /// R11: a spent FD budget refuses the fdinfo read before opening:
    /// zero new charges, zero acquisitions.
    #[test]
    fn fdinfo_preadmits_before_opening() {
        use std::os::fd::AsFd;
        let control = OperationControl::unlimited();
        let mut ctx = op_ctx(&control, 0);
        let (path, held) = fdinfo_held("spent");
        let stat = held.stat().expect("stat probe file");
        let err = read_fdinfo_mnt_id(held.as_fd(), &stat, &mut ctx, &control, 4096)
            .expect_err("spent budget refuses");
        assert_eq!(err.reason(), Reason::LimitExceeded(LimitKind::OpenFds));
        assert!(ctx.charges.is_empty(), "refused before any syscall");
        assert_eq!(ctx.fd_spent, 0);
        std::fs::remove_file(path).unwrap();
    }

    /// R13: a zero read-attempt budget refuses before the first read
    /// (the open issued, the read never did), and a cancelled control
    /// refuses at the checkpoint with the open's charges recorded.
    #[test]
    fn fdinfo_read_cap_and_cancel_gate_issuance() {
        use crate::control::CancelToken;
        use std::os::fd::AsFd;
        let control = OperationControl::unlimited();
        let (path, held) = fdinfo_held("cap");
        let stat = held.stat().expect("stat probe file");
        let mut ctx = op_ctx(&control, 1024);
        let err = read_fdinfo_mnt_id(held.as_fd(), &stat, &mut ctx, &control, 0)
            .expect_err("zero attempts refuses");
        assert_eq!(err.reason(), Reason::LimitExceeded(LimitKind::ReadCalls));
        assert_eq!(ctx.charges.len(), 1);
        assert_eq!(ctx.charges[0].syscalls, 1, "open issued, read never");
        assert_eq!(ctx.charges[0].fd_acquisitions(), 1);
        let token = CancelToken::new();
        token.cancel();
        let cancelled = OperationControl::new(None, token);
        let mut ctx = op_ctx(&cancelled, 1024);
        let err = read_fdinfo_mnt_id(held.as_fd(), &stat, &mut ctx, &cancelled, 4096)
            .expect_err("cancelled control refuses");
        assert_eq!(err.reason(), Reason::Cancelled);
        assert_eq!(ctx.charges.len(), 1);
        assert_eq!(ctx.charges[0].fd_acquisitions(), 1, "open recorded");
        std::fs::remove_file(path).unwrap();
    }
}
