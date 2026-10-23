// SPDX-License-Identifier: Apache-2.0
// LX06 retained unmap custody: the still-charged owner of one live mapping.
//
// NEW (frozen LX06 contract): no donor slice retains a failed-munmap owner.
// The donor calibration (P src/attach/instance.rs `calibrate` @2c2713e6)
// unmaps inline and ignores the return; explicit unresolved ownership with
// consuming retry and Drop-time queue transfer is new vocabulary the contract
// requires. D03 scoped grant (2026-10-23) covers GPL-source to Apache-2.0
// destination inside this library; donor files/terms untouched.
//
// A `MappingCustody` keeps the mapped range, the original `Arc<HeldFile>` and
// the nonforgeable pool permit until a successful checked munmap. Only that
// success releases the domain charge; every other path keeps the owner and
// the charge together.
use super::pool::{pool_error, ActivePermit};
use crate::{
    control::OperationControl,
    error::{CleanupDisposition, DescriptorFlagEffect, EffectSummary, LinuxError, Reason, Stage},
};
use std::{ffi::c_void, fmt};

/// Still-charged owner of one live calibration mapping. `retry_unmap` is the
/// explicit reconciliation route; dropping without it attempts one final
/// munmap and queues the complete record on failure. Last-public-handle loss
/// anchors terminal unresolved state in the domain; it never releases the
/// owner or pretends cleanup happened.
pub struct MappingCustody {
    // ManuallyDrop: the permit moves out exactly once (retry success or Drop
    // transfer). A plain field would run the permit's field drops after this
    // Drop impl, double-dropping the domain/owner Arcs.
    permit: std::mem::ManuallyDrop<ActivePermit>,
}

impl MappingCustody {
    pub(crate) fn new(permit: ActivePermit) -> Self {
        Self {
            permit: std::mem::ManuallyDrop::new(permit),
        }
    }

    /// Consuming unmap retry: checkpoint, one checked munmap with no pool lock
    /// held, then charge release on success. Failure returns this same custody
    /// inside the failure with the charge intact.
    pub fn retry_unmap(self, control: &OperationControl) -> Result<(), super::MappingFailure> {
        if let Err(stop) = control.checkpoint() {
            let reason = match stop {
                crate::control::ControlStop::Cancelled => Reason::Cancelled,
                crate::control::ControlStop::Deadline => Reason::Deadline,
            };
            return Err(super::MappingFailure {
                observation: None,
                error: pool_error(Stage::RetireMapping, reason, CleanupDisposition::Unresolved),
                unresolved: Some(self),
                charges: Vec::new(),
            });
        }
        let addr = self.permit.addr();
        let len = self.permit.len();
        match unmap_raw(addr, len) {
            Ok(()) => {
                // Owned `self` with a live Drop: suppress the destructor and
                // take the consume-only permit out exactly once.
                let mut this = std::mem::ManuallyDrop::new(self);
                let permit = unsafe { std::mem::ManuallyDrop::take(&mut this.permit) };
                permit.retire();
                Ok(())
            }
            Err(error) => Err(super::MappingFailure {
                observation: None,
                error,
                unresolved: Some(self),
                charges: Vec::new(),
            }),
        }
    }
}

impl fmt::Debug for MappingCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MappingCustody")
    }
}

impl Drop for MappingCustody {
    fn drop(&mut self) {
        // One munmap attempt without a hard wait bound, then queue transfer
        // of the complete still-charged record on failure. The take moves the
        // consume-only permit out of the borrowed value exactly once; the
        // ManuallyDrop field runs no further drops afterwards, so the
        // domain/owner Arcs drop exactly once inside the transfer.
        let permit = unsafe { std::mem::ManuallyDrop::take(&mut self.permit) };
        drop_transfer(permit);
    }
}

/// Consume a dropped custody's permit: one munmap, retire on success, queue
/// the complete record on failure. Separated from `Drop` so the consume-only
/// permit moves by value.
fn drop_transfer(permit: ActivePermit) {
    let addr = permit.addr();
    let len = permit.len();
    match unmap_raw(addr, len) {
        Ok(()) => permit.retire(),
        Err(_) => permit.unresolved(),
    }
}

/// One checked munmap. Success is `Ok`; failure keeps the mapping live and
/// reports the actual errno at `RetireMapping` with `Unresolved` cleanup.
pub(crate) fn unmap_raw(addr: *mut c_void, len: usize) -> Result<(), LinuxError> {
    #[cfg(test)]
    if consume_injected_failure() {
        return Err(LinuxError {
            parse_line: None,
            stage: Stage::RetireMapping,
            reason: Reason::Unreadable,
            source: Some(std::io::Error::from_raw_os_error(
                rustix::io::Errno::IO.raw_os_error(),
            )),
            effect: EffectSummary {
                attempted: 1,
                completed: 0,
                cleanup: CleanupDisposition::Unresolved,
                flags: DescriptorFlagEffect::NotAttempted,
            },
            charges: super::pool::zero_charges(),
            #[cfg(feature = "process")]
            process: None,
        });
    }
    // SAFETY: the address/length pair is exactly a mapping this domain
    // created and has not yet retired; no Rust reference aliases it.
    match unsafe { rustix::mm::munmap(addr, len) } {
        Ok(()) => Ok(()),
        Err(errno) => Err(LinuxError {
            parse_line: None,
            stage: Stage::RetireMapping,
            reason: Reason::Unreadable,
            source: Some(errno.into()),
            effect: EffectSummary {
                attempted: 1,
                completed: 0,
                cleanup: CleanupDisposition::Unresolved,
                flags: DescriptorFlagEffect::NotAttempted,
            },
            charges: super::pool::zero_charges(),
            #[cfg(feature = "process")]
            process: None,
        }),
    }
}

/// Test-only unmap failure injection: the next `count` raw unmaps fail without
/// touching the kernel, so the mapping genuinely stays live under custody.
/// Production has no hook. Tests hold a `TestCleanupGuard` so injected
/// failures cannot leak real test-process mappings.
#[cfg(test)]
static INJECTED_UNMAP_FAILURES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[cfg(test)]
pub(crate) fn inject_unmap_failures(count: u32) {
    INJECTED_UNMAP_FAILURES.store(count, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn consume_injected_failure() -> bool {
    INJECTED_UNMAP_FAILURES
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |current| current.checked_sub(1),
        )
        .is_ok()
}

/// Test-only cleanup guard: really unmaps one address/length pair on drop,
/// ignoring the result. Held across injected-failure scenarios so a failed
/// test still retires the real mapping it created.
#[cfg(test)]
pub(crate) struct TestCleanupGuard {
    addr: *mut c_void,
    len: usize,
    disarm: bool,
}

#[cfg(test)]
impl TestCleanupGuard {
    pub(crate) fn new(addr: *mut c_void, len: usize) -> Self {
        Self {
            addr,
            len,
            disarm: false,
        }
    }
    pub(crate) fn disarm(&mut self) {
        self.disarm = true;
    }
}

#[cfg(test)]
impl Drop for TestCleanupGuard {
    fn drop(&mut self) {
        if !self.disarm {
            // Real munmap, bypassing injection: this is cleanup, not the
            // behavior under test.
            unsafe {
                let _ = rustix::mm::munmap(self.addr, self.len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::pool::{MappingPool, MappingPoolLimits, Reservation};
    use super::*;
    use crate::file::{ProcFdResolver, SymlinkPolicy};
    use std::os::fd::AsFd;
    use std::sync::Arc;

    #[test]
    fn retry_unmap_returns_live_custody_until_success() {
        let _table = crate::FD_TABLE.lock().unwrap();
        inject_unmap_failures(0);
        let pool = MappingPool::new(MappingPoolLimits {
            max_mappings: 1,
            max_mapped_bytes: rustix::param::page_size(),
        })
        .unwrap();
        let path = std::env::temp_dir().join(format!("lx06-retry-{}.dat", std::process::id()));
        std::fs::write(&path, vec![3u8; 8192]).unwrap();
        let resolver = ProcFdResolver::open_self().unwrap();
        let held =
            Arc::new(crate::file::HeldFile::open(&path, &resolver, SymlinkPolicy::Follow).unwrap());
        let page = rustix::param::page_size();
        let reservation = Reservation::reserve(&pool.shared, page).unwrap();
        let addr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                page,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE,
                held.as_fd(),
                0,
            )
        }
        .unwrap();
        let permit = reservation.activate(addr, page, Arc::clone(&held));
        let mut guard = TestCleanupGuard::new(addr, page);
        let custody = MappingCustody::new(permit);
        // A failed retry hands the same live custody back with its charge.
        inject_unmap_failures(1);
        let failure = custody
            .retry_unmap(&OperationControl::unlimited())
            .unwrap_err();
        assert!(failure.unresolved().is_some());
        assert_eq!(pool.status().active_mappings(), 1);
        let custody = failure.into_unresolved().unwrap();
        // A clean retry retires and frees the domain charge.
        custody.retry_unmap(&OperationControl::unlimited()).unwrap();
        guard.disarm();
        assert_eq!(pool.status().active_mappings(), 0);
        pool.close(&OperationControl::unlimited()).unwrap();
        std::fs::remove_file(path).unwrap();
        inject_unmap_failures(0);
    }

    #[test]
    fn cancelled_retry_keeps_custody() {
        use crate::control::{CancelToken, OperationControl};
        // Serialized: retry_unmap reaches the shared injection seam.
        let _table = crate::FD_TABLE.lock().unwrap();
        inject_unmap_failures(0);
        let pool = MappingPool::new(MappingPoolLimits {
            max_mappings: 1,
            max_mapped_bytes: rustix::param::page_size(),
        })
        .unwrap();
        let path = std::env::temp_dir().join(format!("lx06-cancel-{}.dat", std::process::id()));
        std::fs::write(&path, vec![3u8; 8192]).unwrap();
        let resolver = ProcFdResolver::open_self().unwrap();
        let held =
            Arc::new(crate::file::HeldFile::open(&path, &resolver, SymlinkPolicy::Follow).unwrap());
        let page = rustix::param::page_size();
        let reservation = Reservation::reserve(&pool.shared, page).unwrap();
        let addr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                page,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE,
                held.as_fd(),
                0,
            )
        }
        .unwrap();
        let permit = reservation.activate(addr, page, Arc::clone(&held));
        let mut guard = TestCleanupGuard::new(addr, page);
        let custody = MappingCustody::new(permit);
        let cancel = CancelToken::new();
        let control = OperationControl::new(None, cancel.clone());
        cancel.cancel();
        let failure = custody.retry_unmap(&control).unwrap_err();
        assert_eq!(failure.error().reason(), Reason::Cancelled);
        let custody = failure.into_unresolved().expect("cancel keeps custody");
        custody.retry_unmap(&OperationControl::unlimited()).unwrap();
        guard.disarm();
        pool.close(&OperationControl::unlimited()).unwrap();
        std::fs::remove_file(path).unwrap();
        inject_unmap_failures(0);
    }
}
