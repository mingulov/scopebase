// SPDX-License-Identifier: Apache-2.0
//! BP10: narrow libbpf adapter over the existing loader.
//!
//! [`LibbpfBackend`] wraps one already-loaded object behind the narrow
//! [`LibbpfObjectShape`] seam and implements
//! [`AttachBackend`](crate::attach::AttachBackend) with
//! `Authority = Arc<HeldFile>`. Shape-only in BP10: `libbpf-rs` was
//! unavailable in the offline crate cache, so no real binding is
//! compiled; the real binding is a named follow-up (see
//! `tools/bpf-compat/profiles/libbpf-adapter.json`).
//!
//! Admission binds the program name: `from_loaded` refuses when the
//! object does not carry the expected program. The libbpf backend
//! cannot enforce a fixed tail, so [`LibbpfBackend::admit_profile`]
//! refuses the `fixed-tail` profile with [`ErrorKind::Unsupported`]
//! instead of claiming it. The held-FD route, site admission and
//! poison discipline match the Aya backend.

use std::ffi::CStr;
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

/// Narrow libbpf object surface the adapter needs. No upstream code is
/// copied here; the future real binding will implement this seam over
/// `libbpf_rs::Object` without vendoring it.
pub trait LibbpfObjectShape {
    type Link;
    type Uncertain;

    /// Shape seam version this object binding reports.
    fn loader_version(&self) -> LoaderVersion;
    /// Program name carried by the loaded object.
    fn program_name(&self) -> &CStr;
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

/// Narrow adapter over one loaded libbpf object. Move-only: the object,
/// domain binding and poison flag travel with the backend.
#[derive(Debug)]
pub struct LibbpfBackend<S> {
    shape: S,
    domain: ProducerDomain,
    admitted: AdmittedLoader,
    limits: Limits,
    poisoned: bool,
}

impl<S: LibbpfObjectShape> LibbpfBackend<S> {
    /// Adopt an already-loaded object into `domain`, bound to the
    /// expected program name. Version, limits and name mismatches
    /// refuse with the original object preserved in
    /// [`ProgramAdoptError`].
    pub fn from_loaded(
        program: S,
        program_name: &CStr,
        domain: ProducerDomain,
        limits: Limits,
    ) -> Result<Self, ProgramAdoptError<S>> {
        if let Err(cause) = limits.validate() {
            return Err(ProgramAdoptError::new(program, cause));
        }
        let version = program.loader_version();
        let admitted = match admit_loader(LoaderId::Libbpf, &version) {
            Ok(admitted) => admitted,
            Err(cause) => return Err(ProgramAdoptError::new(program, cause)),
        };
        if program.program_name() != program_name {
            let cause = OperationError::new(ErrorKind::Incompatible, Stage::Admission, None, None);
            return Err(ProgramAdoptError::new(program, cause));
        }
        Ok(Self {
            shape: program,
            domain,
            admitted,
            limits,
            poisoned: false,
        })
    }

    /// Admit one attach profile. `single` and `multi` are supported;
    /// `fixed-tail` refuses [`ErrorKind::Unsupported`] (libbpf cannot
    /// enforce a fixed tail) and anything else refuses
    /// [`ErrorKind::InvalidInput`].
    pub fn admit_profile(&self, profile: &str) -> Result<(), OperationError> {
        match profile {
            "single" | "multi" => Ok(()),
            "fixed-tail" => Err(OperationError::new(
                ErrorKind::Unsupported,
                Stage::Admission,
                None,
                None,
            )),
            _ => Err(OperationError::new(
                ErrorKind::InvalidInput,
                Stage::Admission,
                None,
                None,
            )),
        }
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
}

#[allow(unsafe_code)]
unsafe impl<S: LibbpfObjectShape> AttachBackend for LibbpfBackend<S> {
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
