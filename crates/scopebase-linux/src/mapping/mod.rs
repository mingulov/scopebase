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

    /// Absorb whole sub-operation charge lists (calibration, mount lookup).
    fn absorb(&mut self, charges: &[ResourceCharges]) -> Result<(), LinuxError> {
        for charges in charges {
            self.spend(charges)?;
        }
        Ok(())
    }

    /// Honest mini-charges for direct syscalls outside a sub-operation.
    fn spend_direct(&mut self, syscalls: u64, acquired: u64) -> Result<(), LinuxError> {
        self.spend(&ResourceCharges {
            syscalls,
            acquired,
            peak: acquired,
            read: None,
            parse: None,
            #[cfg(feature = "process")]
            process: None,
        })
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
fn tracked<T>(
    ctx: &mut OpCtx,
    result: Result<T, LinuxError>,
    project: fn(&T) -> &ResourceCharges,
) -> Result<T, LinuxError> {
    match result {
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

/// Route a target sub-operation error: disappearance, denial, birth/view
/// change and unclear liveness become verdicts; control stops, caller
/// budgets, config faults and environmental or unreadable failures pass
/// through as errors.
fn route_target_error(error: &LinuxError) -> Result<TargetVerdict, ()> {
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
        request.process.verify_birth(control),
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
        request.process.read_maps(proc, control),
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
        request
            .process
            .read_map_files_identity(range.start(), range.end(), proc, control),
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
        Err(error) if error.reason() == Reason::Denied => AssocEvidence::KeyPath,
        Err(error) if error.reason() == Reason::Disappeared => {
            // A missing entry for a file-backed line means the VMA changed
            // under the read; an anonymous line never had one and simply
            // names no file.
            if shape_before.key.inode() == 0 {
                return Ok(ctx.mismatch(MismatchKind::KeyMismatch));
            }
            return Ok(ctx.mismatch(MismatchKind::RangeChanged));
        }
        Err(error) => return route_or_fail(ctx, error),
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
        request.process.read_maps(proc, control),
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
    let mnt_id = match read_fdinfo_mnt_id(held_fd, held_stat) {
        Ok(id) => id,
        Err(error) => return MountKey::Failed(error),
    };
    if let Err(error) = ctx.spend_direct(3, 1) {
        return MountKey::Failed(error);
    }
    let mut used = 0u8;
    loop {
        let table = match tracked(
            ctx,
            process.read_mountinfo(proc, ctx.control),
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
fn read_fdinfo_mnt_id(
    fd: std::os::fd::BorrowedFd<'_>,
    held: &StatObservation,
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
    let file = rustix::fs::open(
        info_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(map_err)?;
    let mut buf = [0u8; 4096];
    let count = loop {
        match rustix::io::read(&file, &mut buf) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(errno) => return Err(map_err(errno)),
            Ok(count) => break count,
        }
    };
    drop(file);
    if count == buf.len() {
        return Err(pool::pool_error(
            Stage::ObserveMapping,
            Reason::Malformed,
            CleanupDisposition::NotNeeded,
        ));
    }
    let mnt_id = parse_fdinfo_mnt_id(&buf[..count]).ok_or_else(|| {
        pool::pool_error(
            Stage::ObserveMapping,
            Reason::Malformed,
            CleanupDisposition::NotNeeded,
        )
    })?;
    // Cross-check: the numbered FD still names the held object.
    let stat = rustix::fs::statat(rustix::fs::CWD, fd_path, rustix::fs::AtFlags::empty())
        .map_err(map_err)?;
    let device = u64::try_from(stat.st_dev as i128).unwrap_or(u64::MAX);
    let inode = u64::try_from(stat.st_ino as i128).unwrap_or(u64::MAX);
    if device != held.key().device_raw() || inode != held.key().inode() {
        return Err(pool::pool_error(
            Stage::ObserveMapping,
            Reason::WrongContext,
            CleanupDisposition::NotNeeded,
        ));
    }
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
}
