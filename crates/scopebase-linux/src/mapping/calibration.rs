// SPDX-License-Identifier: Apache-2.0
// LX06 explicit one-page private calibration of a held object.
//
// ADAPT P src/attach/instance.rs `calibrate` @2c2713e6 (lines 640-700): map
// one page of the pinned fd `PROT_READ`/`MAP_PRIVATE`, read that mapping's
// kernel identity back through `/proc/self`, then unmap. The donor arms a BPF
// hook and records the hook's `{s_dev, i_ino}`; without that hook this port
// reads the kernel-rendered maps line plus the calibration mapping's own
// map_files stat instead, and the custody/pool/error vocabulary around it is
// new per the frozen LX06 contract. D03 scoped grant (2026-10-23) covers
// GPL-source to Apache-2.0 destination inside this library; donor files/terms
// untouched.
//
// Calibration establishes the held object's kernel-rendered key only — never
// uniqueness across files and never target association. It runs only in
// `AllowPrivateCalibration` mode, only when exact association is unavailable,
// at most one page-aligned private read-only mapping, never executable or
// shared. Empty files and a sub-page cap are inconclusive without mapping.
use super::{pool::Reservation, proof::InconclusiveKind, MappingFailure};
use crate::{
    control::OperationControl,
    error::{LinuxError, Reason, ResourceCharges, Stage},
    file::HeldFile,
    identity::MapsFileKey,
    process::{MapFilesIdentity, ObserverEpoch, Pid, ProcLimits, ProcessObservation},
};
use std::{os::fd::AsFd, sync::Arc};

/// The held object's kernel-rendered key: its maps-domain key from the
/// calibration mapping's own observed line.
pub(crate) struct CalibratedKey {
    pub(crate) key: MapsFileKey,
}

/// A completed calibration: the key, an optional failed-cleanup attachment
/// (the unmap failed after the key was established) and the sub-operation
/// stage charges.
pub(crate) struct Calibration {
    pub(crate) key: CalibratedKey,
    pub(crate) cleanup: Option<(LinuxError, super::MappingCustody)>,
    pub(crate) charges: Vec<ResourceCharges>,
}

/// Calibration refusal before any key: either inconclusive (empty object or
/// sub-page cap, both without mapping) or a failed operation.
pub(crate) enum CalibrationAbort {
    Inconclusive(InconclusiveKind),
    Failed(MappingFailure),
}

/// Mapping length selection: `min(file_size, page_size)`. `None` for empty
/// files, which never map. The kernel rounds the single page; the charged
/// bytes are always the full page.
pub(crate) fn calibration_len(file_size: u64, page: usize) -> Option<usize> {
    if file_size == 0 {
        return None;
    }
    Some((file_size.min(page as u64)) as usize)
}

/// Run one explicit calibration of `held` under `epoch`, reserving one slot
/// plus a page of bytes from `domain` before mmap. Reads the observer's own
/// maps through a fresh self observation (never ambient paths), requires the
/// address-containing line without the executable bit, stats the calibration
/// mapping's own map_files entry when obtainable, then retires the mapping.
pub(crate) fn calibrate(
    held: &Arc<HeldFile>,
    domain: &Arc<super::pool::Shared>,
    epoch: &ObserverEpoch,
    proc: ProcLimits,
    max_mapped_bytes: usize,
    control: &OperationControl,
) -> Result<Calibration, CalibrationAbort> {
    let stat = held.stat().map_err(|error| {
        CalibrationAbort::Failed(MappingFailure {
            observation: None,
            error,
            unresolved: None,
            charges: Vec::new(),
        })
    })?;
    let page = rustix::param::page_size();
    let Some(map_len) = calibration_len(stat.len(), page) else {
        return Err(CalibrationAbort::Inconclusive(InconclusiveKind::EmptyFile));
    };
    if max_mapped_bytes < page {
        return Err(CalibrationAbort::Inconclusive(
            InconclusiveKind::CapBelowPage,
        ));
    }
    let reservation = Reservation::reserve(domain, page).map_err(|error| {
        CalibrationAbort::Failed(MappingFailure {
            observation: None,
            error,
            unresolved: None,
            charges: Vec::new(),
        })
    })?;
    if let Err(stop) = control.checkpoint() {
        return Err(CalibrationAbort::Failed(MappingFailure {
            observation: None,
            error: super::pool::pool_error(
                Stage::MapCalibration,
                super::stop_reason(stop),
                crate::error::CleanupDisposition::Complete,
            ),
            unresolved: None,
            charges: Vec::new(),
        }));
    }
    // SAFETY: a fresh private read-only mapping of an open regular file at
    // offset 0 with `0 < map_len <= page`; it is unmapped on every path below
    // and never dereferenced.
    let addr = match unsafe {
        rustix::mm::mmap(
            std::ptr::null_mut(),
            map_len,
            rustix::mm::ProtFlags::READ,
            rustix::mm::MapFlags::PRIVATE,
            held.as_fd(),
            0,
        )
    } {
        Ok(addr) => addr,
        Err(errno) => {
            drop(reservation);
            return Err(CalibrationAbort::Failed(MappingFailure {
                observation: None,
                error: mmap_error(errno),
                unresolved: None,
                charges: Vec::new(),
            }));
        }
    };
    let permit = reservation.activate(addr, map_len, Arc::clone(held));
    let mut charges = Vec::new();
    // The observer's own maps through a retained self observation under the
    // caller's epoch: bracketed, bounded, no ambient /proc/self/maps read.
    let me = Pid::new(std::process::id() as i32).expect("positive self pid");
    let this = match ProcessObservation::acquire(me, epoch, proc, control) {
        Ok(this) => this,
        Err(error) => return abort_calibration(permit, failed(error, charges)),
    };
    charges.push(this.acquisition_charges().clone());
    let maps = match this.read_maps(proc, control) {
        Ok(maps) => maps,
        Err(error) => return abort_calibration(permit, failed(error, charges)),
    };
    charges.push(maps.charges().clone());
    let address = addr as u64;
    let line = match maps.snapshot().containing(address) {
        Some(line) if line.end().saturating_sub(address) >= map_len as u64 => line,
        _ => {
            return abort_calibration(
                permit,
                failed(
                    super::pool::pool_error(
                        Stage::MapCalibration,
                        Reason::WrongContext,
                        crate::error::CleanupDisposition::Complete,
                    ),
                    charges,
                ),
            );
        }
    };
    if line.permissions()[2] == b'x' {
        // Our own calibration mapping must never render executable.
        return abort_calibration(
            permit,
            failed(
                super::pool::pool_error(
                    Stage::MapCalibration,
                    Reason::WrongContext,
                    crate::error::CleanupDisposition::Complete,
                ),
                charges,
            ),
        );
    }
    let key = line.file_key();
    // Consistency-check the calibration mapping's own map_files identity when
    // obtainable; denial or disappearance yields key-only calibration, never
    // failure. When obtained it must name the held object itself (like-for-
    // like with the held fstat): our own fresh mapping contradicting our own
    // file is a wrong-context abort, never a key.
    match this.read_map_files_identity(line.start(), line.end(), proc, control) {
        Ok(observation) => {
            charges.push(observation.charges().clone());
            let identity: MapFilesIdentity = observation.identity();
            let held_key = stat.key();
            if identity.device() != held_key.device_raw() || identity.inode() != held_key.inode() {
                return abort_calibration(
                    permit,
                    failed(
                        super::pool::pool_error(
                            Stage::MapCalibration,
                            Reason::WrongContext,
                            crate::error::CleanupDisposition::Complete,
                        ),
                        charges,
                    ),
                );
            }
        }
        Err(error) => {
            if !admit_key_only(&error) {
                return abort_calibration(permit, failed(error, charges));
            }
            // F13: tolerated, but the attempt's spend still counts: the
            // read ran and acquired before it was denied or vanished.
            charges.push(error.charges().clone());
        }
    }
    drop(this);
    match super::custody::unmap_raw(addr, map_len) {
        Ok(()) => {
            permit.retire();
            Ok(Calibration {
                key: CalibratedKey { key },
                cleanup: None,
                charges,
            })
        }
        Err(error) => {
            // The key stands but cleanup failed: the caller attaches this to
            // its outcome as separately inspectable unresolved custody.
            let custody = super::MappingCustody::new(permit);
            Ok(Calibration {
                key: CalibratedKey { key },
                cleanup: Some((error, custody)),
                charges,
            })
        }
    }
}

/// S11-round4: admit a failed map_files identity read into key-only
/// calibration. Same origin-aware admission as the outer assoc
/// classifier: an observer-side failure (our view or authentication
/// broke mid-call — e.g. the observer-directory guard denied before
/// the target entry was ever touched) aborts calibration instead of
/// degrading to a key, however verdict-shaped its `Reason` is. Only
/// target-side or member-less denial/disappearance/inconclusive keep
/// the historical key-only fallback.
fn admit_key_only(error: &LinuxError) -> bool {
    if super::is_observer_origin(error) {
        return false;
    }
    matches!(
        error.reason(),
        Reason::Denied | Reason::Disappeared | Reason::Inconclusive
    )
}

fn failed(error: LinuxError, mut charges: Vec<ResourceCharges>) -> MappingFailure {
    // F13: the failing step's own spend joins the carried charges, so the
    // caller absorbs every acquisition including the one that failed.
    charges.push(error.charges().clone());
    MappingFailure {
        observation: None,
        error,
        unresolved: None,
        charges,
    }
}

/// Abort after the mapping exists: one checked munmap, retire on success and
/// return the operation failure clean; on unmap failure keep the live custody
/// beside the operation failure.
fn abort_calibration(
    permit: super::pool::ActivePermit,
    mut failure: MappingFailure,
) -> Result<Calibration, CalibrationAbort> {
    let addr = permit.addr();
    let len = permit.len();
    match super::custody::unmap_raw(addr, len) {
        Ok(()) => {
            permit.retire();
            Err(CalibrationAbort::Failed(failure))
        }
        Err(_) => {
            failure.unresolved = Some(super::MappingCustody::new(permit));
            Err(CalibrationAbort::Failed(failure))
        }
    }
}

fn mmap_error(errno: rustix::io::Errno) -> LinuxError {
    use crate::error::{CleanupDisposition, DescriptorFlagEffect, EffectSummary};
    LinuxError {
        parse_line: None,
        stage: Stage::MapCalibration,
        reason: crate::process::map_errno(errno),
        source: Some(errno.into()),
        effect: EffectSummary {
            attempted: 1,
            completed: 0,
            cleanup: CleanupDisposition::Complete,
            flags: DescriptorFlagEffect::NotAttempted,
        },
        charges: super::pool::zero_charges(),
        #[cfg(feature = "process")]
        process: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_length_is_capped_at_one_page() {
        assert_eq!(calibration_len(0, 4096), None);
        assert_eq!(calibration_len(1, 4096), Some(1));
        assert_eq!(calibration_len(4095, 4096), Some(4095));
        assert_eq!(calibration_len(4096, 4096), Some(4096));
        assert_eq!(calibration_len(1 << 30, 4096), Some(4096));
    }

    /// S11-round4: calibration's map_files association fallback uses the
    /// same origin-aware admission as the outer assoc classifier. Every
    /// tolerated `Reason` on an observer-side member (our view broke
    /// mid-call — e.g. the observer-directory guard denied before the
    /// target entry was touched) refuses key-only calibration; only
    /// target-side or member-less failures keep the historical
    /// fallback. Drives the real admission branch (no
    /// self-observation trigger produces a tolerated reason on an
    /// observer member today — LSM/remount transients could — so the
    /// branch is covered here and the production abort path below).
    #[test]
    #[cfg(feature = "process")]
    fn key_only_admission_refuses_observer_origin() {
        use crate::error::{CleanupDisposition, ProcMember, ProcOperation, ProcessErrorContext};
        fn error_with_member(reason: Reason, member: ProcMember) -> LinuxError {
            let mut error = super::super::pool::pool_error(
                Stage::MapCalibration,
                reason,
                CleanupDisposition::Complete,
            );
            error.process = Some(ProcessErrorContext::new(
                ProcOperation::ReadMapFiles,
                Some(member),
            ));
            error
        }
        fn bare(reason: Reason) -> LinuxError {
            super::super::pool::pool_error(Stage::MapCalibration, reason, CleanupDisposition::Complete)
        }
        use ProcMember::*;
        let tolerated = [Reason::Denied, Reason::Disappeared, Reason::Inconclusive];
        // Observer-side members: never key-only evidence.
        for member in [
            Root,
            SelfLink,
            ObserverDirectory,
            ObserverStatus,
            ObserverPidNamespace,
            CreatorPidfd,
        ] {
            for reason in tolerated {
                assert!(
                    !admit_key_only(&error_with_member(reason, member)),
                    "{member:?}/{reason:?} must abort calibration, not degrade to a key"
                );
            }
        }
        // Target-side members: the historical key-only fallback stays.
        for member in [TargetDirectory, TargetStatus, TargetStat, Maps, MapFiles, Pidfd] {
            for reason in tolerated {
                assert!(
                    admit_key_only(&error_with_member(reason, member)),
                    "{member:?}/{reason:?} must stay key-only evidence"
                );
            }
        }
        // Member-less errors: historical reason-only routing preserved.
        for reason in tolerated {
            assert!(
                admit_key_only(&bare(reason)),
                "member-less {reason:?} must stay key-only evidence"
            );
        }
        // Untolerated reasons refuse regardless of origin.
        for reason in [
            Reason::WrongContext,
            Reason::ChangedSource,
            Reason::Unreadable,
            Reason::Unavailable,
            Reason::Malformed,
            Reason::InvalidInput,
        ] {
            assert!(
                !admit_key_only(&bare(reason)),
                "member-less {reason:?} must abort calibration"
            );
            assert!(
                !admit_key_only(&error_with_member(reason, MapFiles)),
                "MapFiles/{reason:?} must abort calibration"
            );
        }
    }

    /// S11-round4: production-path observer-failure control for
    /// calibration. A forged post-fork epoch (creator = our own parent
    /// pid, the exact pair a forked child presents) aborts the real
    /// `calibrate` as a `Failed` operation — never `Ok` key-only
    /// evidence and never `Inconclusive` — with the CreatorPidfd
    /// observer origin preserved on the failure, and the mapping
    /// retired (no active mapping left behind).
    /// S94-round5: private staging for the observer probe. Exclusive
    /// by construction (the S14 discipline): we create the root
    /// (exclusive `create_dir`, skipping stale names — never
    /// removing anything we did not just create), we own it, mode
    /// 0700, so no other uid can plant or replace names inside.
    fn staging(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        for _ in 0..1024 {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "lx06-cal-observer-{}-{tag}-{n}",
                std::process::id()
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                        .expect("staging mode");
                    return dir;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("staging: {error}"),
            }
        }
        panic!("staging names exhausted");
    }

    #[test]
    #[cfg(feature = "process")]
    fn post_fork_calibrate_aborts_with_observer_origin() {
        use crate::file::HeldFile;
        use crate::procfs::ParseLimits;
        use std::io::Write;
        use std::sync::Arc;
        // S88-round5: serialize on FD_TABLE with the
        // unmap-injection tests: calibrate/abort reaches
        // unmap_raw, which consumes the process-global
        // injected-failure counter.
        let _table = crate::FD_TABLE.lock().unwrap();
        let control = OperationControl::unlimited();
        let proc = ProcLimits {
            parse: ParseLimits {
                max_bytes: 1 << 20,
                max_entries: 1 << 16,
                max_line_bytes: 1 << 16,
            },
            max_read_calls: 4096,
            max_metadata_bytes: 1 << 20,
        };
        let epoch = ObserverEpoch::new(proc, &control).expect("epoch on own process");
        let parent = Pid::new(
            rustix::process::getppid()
                .expect("parent pid")
                .as_raw_nonzero()
                .get(),
        )
        .expect("positive parent pid");
        let me = Pid::new(std::process::id() as i32).expect("own pid");
        assert_ne!(parent, me, "test must not be its own parent");
        let forged = epoch.forge_post_fork_creator(parent);
        // S94-round5: the probe is exclusively created inside the
        // private root and its creation descriptor is adopted
        // directly — no shared-temp pathname is ever re-resolved,
        // so a preplanted symlink has nothing to redirect.
        let root = staging("probe");
        let path = root.join("probe.dat");
        let mut created = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("exclusive probe");
        created
            .write_all(b"calibration observer probe")
            .expect("write probe file");
        let held = Arc::new(HeldFile::from_file(created).expect("adopt probe"));
        let page = rustix::param::page_size();
        let pool = super::super::pool::MappingPool::new(super::super::pool::MappingPoolLimits {
            max_mappings: 1,
            max_mapped_bytes: page,
        })
        .expect("calibration pool");
        let guard = super::super::pool::OpGuard::admit(&pool).expect("admit op");
        match calibrate(&held, guard.domain(), &forged, proc, page, &control) {
            Err(CalibrationAbort::Failed(failure)) => {
                assert_eq!(failure.error().reason(), Reason::WrongContext);
                assert_eq!(
                    failure
                        .error()
                        .process_context()
                        .and_then(crate::error::ProcessErrorContext::member),
                    Some(crate::error::ProcMember::CreatorPidfd),
                    "creator mismatch must keep its observer origin"
                );
            }
            Err(CalibrationAbort::Inconclusive(_)) => {
                panic!("post-fork calibration must fail, not go inconclusive")
            }
            Ok(_) => panic!("post-fork calibration must fail, not publish a key"),
        }
        assert_eq!(
            pool.status().active_mappings(),
            0,
            "aborted calibration must retire its mapping"
        );
        drop(guard);
        pool.close(&control).expect("pool closes");
        drop(held);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
