// SPDX-License-Identifier: Apache-2.0
//! BP10: narrow Aya adapter over the existing loader.
//!
//! [`AyaBackend`] wraps one already-loaded uprobe program behind the
//! narrow [`AyaUprobeShape`] seam and implements
//! [`AttachBackend`](crate::attach::AttachBackend) with
//! `Authority = Arc<HeldFile>`. The shape mirrors the minimal upstream
//! surface the adapter needs (version report, entry/return kind, batch
//! attach, detach); it copies no upstream code. The real binding over
//! upstream `aya =0.14.0` (registry, defaults off) compiles behind the
//! `aya` feature; live attach cells need a privileged kernel and stay
//! NOT_RUN here.
//!
//! The adapter uses the held-FD route only: the shape receives the
//! authority's live FD, never a caller pathname. Mode/shape mismatch,
//! site pairing faults and over-cap batches refuse before the shape is
//! touched, so refusal carries a proven no-effect claim.

use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::sync::Arc;

use scopebase_linux::file::HeldFile;

use crate::attach::{AttachBackend, AttachMode, CustodyCharge, NativeAttach, NativeRetire, Site};
use crate::identity::ProducerDomain;
use crate::{ErrorKind, Limits, OperationError, Stage};

use super::{
    admit_loader, admit_sites, charge_for, AdmittedLoader, LoaderId, LoaderVersion,
    ProgramAdoptError,
};

/// Narrow Aya uprobe surface the adapter needs. Upstream `aya` is adapted
/// through this seam (see the `aya`-feature binding below); scripted
/// doubles prove the adapter logic without a kernel.
pub trait AyaUprobeShape {
    type Link;
    type Uncertain;

    /// Loader version this program was loaded with.
    fn loader_version(&self) -> LoaderVersion;
    /// Whether the loaded program is a return probe.
    fn is_return(&self) -> bool;
    /// Attach one batch against the held target FD. The FD is the
    /// authority's live descriptor; no pathname is supplied.
    fn attach_batch(
        &mut self,
        held_fd: RawFd,
        sites: &[Site],
        mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain>;
    /// Detach one owned link.
    fn detach(&mut self, link: &mut Self::Link) -> NativeRetire;
    /// Reconcile one uncertain acquisition.
    fn retire_uncertain_shape(&mut self, custody: &mut Self::Uncertain) -> NativeRetire;
}

/// Narrow adapter over one loaded Aya uprobe program. Move-only: the
/// program, domain binding and poison flag travel with the backend.
#[derive(Debug)]
pub struct AyaBackend<S> {
    shape: S,
    domain: ProducerDomain,
    admitted: AdmittedLoader,
    limits: Limits,
    poisoned: bool,
}

impl<S: AyaUprobeShape> AyaBackend<S> {
    /// Adopt an already-loaded program into `domain`. The program's
    /// reported loader version must be admitted; on any refusal the
    /// original program travels back in [`ProgramAdoptError`].
    pub fn from_loaded(
        program: S,
        domain: ProducerDomain,
        limits: Limits,
    ) -> Result<Self, ProgramAdoptError<S>> {
        if let Err(cause) = limits.validate() {
            return Err(ProgramAdoptError::new(program, cause));
        }
        let version = program.loader_version();
        let admitted = match admit_loader(LoaderId::Aya, &version) {
            Ok(admitted) => admitted,
            Err(cause) => return Err(ProgramAdoptError::new(program, cause)),
        };
        Ok(Self {
            shape: program,
            domain,
            admitted,
            limits,
            poisoned: false,
        })
    }

    pub fn loader_id(&self) -> LoaderId {
        self.admitted.loader()
    }

    pub fn admitted_version(&self) -> LoaderVersion {
        self.admitted.version()
    }

    pub fn domain(&self) -> ProducerDomain {
        self.domain
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn shape(&self) -> &S {
        &self.shape
    }

    pub fn shape_mut(&mut self) -> &mut S {
        &mut self.shape
    }

    fn mode_matches(&self, mode: AttachMode) -> bool {
        matches!(
            (self.shape.is_return(), mode),
            (false, AttachMode::EntrySingle | AttachMode::EntryMulti)
                | (true, AttachMode::ReturnSingle | AttachMode::ReturnMulti)
        )
    }
}

#[allow(unsafe_code)]
unsafe impl<S: AyaUprobeShape> AttachBackend for AyaBackend<S> {
    type Authority = Arc<HeldFile>;
    type Link = S::Link;
    type Uncertain = S::Uncertain;

    fn custody_charge(
        &self,
        _authority: &Self::Authority,
        sites: &[Site],
    ) -> Result<CustodyCharge, OperationError> {
        if self.poisoned {
            return Err(OperationError::new(
                ErrorKind::Poisoned,
                Stage::Admission,
                None,
                None,
            ));
        }
        charge_for(sites, &self.limits)
    }

    fn attach(
        &mut self,
        authority: &Self::Authority,
        sites: &[Site],
        mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        if self.poisoned {
            return NativeAttach::NoEffect(OperationError::new(
                ErrorKind::Poisoned,
                Stage::Attach,
                None,
                None,
            ));
        }
        if let Err(cause) = admit_sites(sites, &self.limits) {
            return NativeAttach::NoEffect(cause);
        }
        if !self.mode_matches(mode) {
            return NativeAttach::NoEffect(OperationError::new(
                ErrorKind::Incompatible,
                Stage::Attach,
                None,
                None,
            ));
        }
        let held_fd = authority.as_fd().as_raw_fd();
        self.shape.attach_batch(held_fd, sites, mode)
    }

    fn retire(&mut self, link: &mut Self::Link) -> NativeRetire {
        let outcome = self.shape.detach(link);
        if matches!(outcome, NativeRetire::Failed(_)) {
            self.poisoned = true;
        }
        outcome
    }

    fn retire_uncertain(&mut self, custody: &mut Self::Uncertain) -> NativeRetire {
        let outcome = self.shape.retire_uncertain_shape(custody);
        if matches!(outcome, NativeRetire::Failed(_)) {
            self.poisoned = true;
        }
        outcome
    }
}

// ---------------------------------------------------------------------------
// Real binding over upstream aya =0.14.0 (compile-verified; live cells
// need a privileged kernel and stay NOT_RUN here).
// ---------------------------------------------------------------------------

/// Real narrow binding: upstream `aya::programs::UProbe` behind the
/// [`AyaUprobeShape`] seam. This calls upstream APIs; it vendors no
/// upstream code.
///
/// S161: the probe kind is read back via the public
/// [`aya::programs::UProbe::kind`] (aya 0.14 exposes `ProbeKind::Entry`
/// vs `ProbeKind::Return`; e.g. `from_pin` adopts either), so Return*
/// modes route against the adopted kind instead of assuming entry.
#[cfg(feature = "aya")]
fn uprobe_is_return(kind: aya::programs::ProbeKind) -> bool {
    matches!(kind, aya::programs::ProbeKind::Return)
}

/// Render the authority's live FD as the `/proc/self/fd/N` path that
/// upstream aya 0.14 `UProbe::attach` requires (it takes a path, not an
/// FD). This is still the held-FD route — the path derives from the live
/// FD, never a caller pathname — but it needs `/proc` mounted: in a
/// container without `/proc`, attach fails with a mapped upstream
/// `Backend` error even though the FD itself is valid (S183).
#[cfg(feature = "aya")]
fn proc_fd_path(held_fd: RawFd) -> String {
    format!("/proc/self/fd/{held_fd}")
}

#[cfg(feature = "aya")]
impl AyaUprobeShape for aya::programs::UProbe {
    type Link = Option<aya::programs::uprobe::UProbeLinkId>;
    type Uncertain = Option<aya::programs::uprobe::UProbeLinkId>;

    fn loader_version(&self) -> LoaderVersion {
        LoaderVersion::new(0, 14, 0)
    }

    fn is_return(&self) -> bool {
        uprobe_is_return(self.kind())
    }

    fn attach_batch(
        &mut self,
        held_fd: RawFd,
        sites: &[Site],
        _mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        // Upstream aya 0.14 `UProbe::attach` is single-point: multi-site
        // batches refuse honestly instead of fanning out behind one
        // custody record.
        if sites.len() != 1 {
            return NativeAttach::NoEffect(OperationError::new(
                ErrorKind::Unsupported,
                Stage::Attach,
                None,
                None,
            ));
        }
        // Held-FD route: the only path handed to upstream is derived
        // from the authority's live FD, never a caller pathname (see
        // `proc_fd_path` for the `/proc` dependency this implies).
        let target = proc_fd_path(held_fd);
        let point = aya::programs::uprobe::UProbeAttachPoint {
            location: aya::programs::uprobe::UProbeAttachLocation::AbsoluteOffset(sites[0].offset),
            cookie: Some(sites[0].cookie),
        };
        match self.attach(
            point,
            target.as_str(),
            aya::programs::uprobe::UProbeScope::AllProcesses,
        ) {
            Ok(id) => NativeAttach::Attached(Some(id)),
            Err(cause) => NativeAttach::NoEffect(map_program_error(cause, Stage::Attach)),
        }
    }

    fn detach(&mut self, link: &mut Self::Link) -> NativeRetire {
        match link.take() {
            Some(id) => match self.detach(id) {
                Ok(()) => NativeRetire::Retired,
                Err(cause) => NativeRetire::Failed(map_program_error(cause, Stage::Retire)),
            },
            None => NativeRetire::Failed(OperationError::new(
                ErrorKind::Incompatible,
                Stage::Retire,
                None,
                None,
            )),
        }
    }

    fn retire_uncertain_shape(&mut self, custody: &mut Self::Uncertain) -> NativeRetire {
        match custody.take() {
            Some(id) => match self.detach(id) {
                Ok(()) => NativeRetire::Retired,
                Err(cause) => NativeRetire::Failed(map_program_error(cause, Stage::Retire)),
            },
            None => NativeRetire::Pending,
        }
    }
}

/// Map an upstream [`aya::programs::ProgramError`] onto the host error
/// contract: errno captured immediately, kind by the donor
/// classification, no source formatting.
#[cfg(feature = "aya")]
fn map_program_error(cause: aya::programs::ProgramError, stage: Stage) -> OperationError {
    use aya::programs::ProgramError;
    match cause {
        ProgramError::NotLoaded
        | ProgramError::AlreadyLoaded
        | ProgramError::AlreadyAttached
        | ProgramError::NotAttached => {
            OperationError::new(ErrorKind::Incompatible, stage, None, None)
        }
        ProgramError::LoadError { io_error, .. } => {
            let errno = io_error.raw_os_error();
            let kind = errno
                .map(super::classify_loader_errno)
                .unwrap_or(ErrorKind::Backend);
            OperationError::new(kind, stage, errno, None)
        }
        ProgramError::SyscallError(syscall) => {
            let io_error: &std::io::Error = &syscall.io_error;
            let errno = io_error.raw_os_error();
            let kind = errno
                .map(super::classify_loader_errno)
                .unwrap_or(ErrorKind::Backend);
            OperationError::new(kind, stage, errno, None)
        }
        _ => OperationError::new(ErrorKind::Backend, stage, None, None),
    }
}

#[cfg(test)]
mod tests {
    // S161: the real binding must route return uprobes to Return* modes.
    // A live `UProbe` value needs bpffs/kernel (NOT_RUN live cell), so the
    // kind->is_return mapping is pinned here and `is_return` delegates to it.
    #[cfg(feature = "aya")]
    #[test]
    fn uprobe_kind_maps_to_is_return() {
        use aya::programs::ProbeKind;
        use super::uprobe_is_return;
        assert!(!uprobe_is_return(ProbeKind::Entry));
        assert!(uprobe_is_return(ProbeKind::Return));
    }

    // S183: upstream aya 0.14 `attach` takes a path, so the held FD is
    // handed over as `/proc/self/fd/N` — the route needs `/proc` mounted
    // even though the FD itself is the authority. Pin the derivation.
    #[cfg(feature = "aya")]
    #[test]
    fn held_fd_derives_proc_self_fd_path() {
        use super::proc_fd_path;
        assert_eq!(proc_fd_path(3), "/proc/self/fd/3");
    }
}
