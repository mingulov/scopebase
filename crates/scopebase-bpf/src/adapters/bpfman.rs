// SPDX-License-Identifier: Apache-2.0
//! BP10: narrow bpfman-shape adapter.
//!
//! [`BpfmanBackend`] wraps one manager-known program behind the narrow
//! [`BpfmanShape`] seam and implements
//! [`AttachBackend`](crate::attach::AttachBackend) with
//! `Authority = Arc<HeldFile>`. Shape-only by design: bpfman is an
//! operator/manager API, not a linked loader, so there is no upstream
//! crate to bind here; an operator binding is later work (see
//! `tools/bpf-compat/profiles/bpfman-adapter.json`).
//!
//! Admission binds the program id. The held-FD route, site admission
//! and poison discipline match the Aya backend.

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

/// Narrow bpfman manager surface the adapter needs: a seam version, a
/// program id and batch attach/detach. No upstream code is copied here.
pub trait BpfmanShape {
    type Link;
    type Uncertain;

    /// Shape seam version this handle reports.
    fn loader_version(&self) -> LoaderVersion;
    /// Manager-known program id.
    fn program_id(&self) -> u32;
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

/// Narrow adapter over one bpfman-known program. Move-only: the handle,
/// domain binding and poison flag travel with the backend.
#[derive(Debug)]
pub struct BpfmanBackend<S> {
    shape: S,
    domain: ProducerDomain,
    admitted: AdmittedLoader,
    limits: Limits,
    poisoned: bool,
}

impl<S: BpfmanShape> BpfmanBackend<S> {
    /// Adopt a manager-known program into `domain`, bound to the
    /// expected program id. Version, limits and id mismatches refuse
    /// with the original handle preserved in [`ProgramAdoptError`].
    pub fn from_loaded(
        program: S,
        program_id: u32,
        domain: ProducerDomain,
        limits: Limits,
    ) -> Result<Self, ProgramAdoptError<S>> {
        if let Err(cause) = limits.validate() {
            return Err(ProgramAdoptError::new(program, cause));
        }
        let version = program.loader_version();
        let admitted = match admit_loader(LoaderId::Bpfman, &version) {
            Ok(admitted) => admitted,
            Err(cause) => return Err(ProgramAdoptError::new(program, cause)),
        };
        if program.program_id() != program_id {
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
unsafe impl<S: BpfmanShape> AttachBackend for BpfmanBackend<S> {
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
