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
        Err(error) => match error.reason() {
            // F13: tolerated, but the attempt's spend still counts: the
            // read ran and acquired before it was denied or vanished.
            Reason::Denied | Reason::Disappeared | Reason::Inconclusive => {
                charges.push(error.charges().clone());
            }
            _ => return abort_calibration(permit, failed(error, charges)),
        },
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
}
