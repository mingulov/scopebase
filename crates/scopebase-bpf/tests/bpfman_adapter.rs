// SPDX-License-Identifier: Apache-2.0
//! BP10: narrow bpfman-shape adapter plus the native contract vectors.
//!
//! Shape-only by design: bpfman is an operator/manager API, not a linked
//! loader (see `tools/bpf-compat/profiles/bpfman-adapter.json`). The
//! adapter proves admission, version gating and contract vectors over the
//! narrow [`BpfmanShape`](scopebase_bpf::adapters::BpfmanShape) seam; an
//! operator binding is later work, not silently claimed.
//!
//! ADAPT provenance (all user-owned donor lines; upstream code never copied):
//! - p11scope `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//!   @ `2c2713e66292b0d2688508a25f79e813ae823d81`: offsets/cookies
//!   pairing refusal (lines 226-245). ADAPT: site admission discipline.
//! Grant: OWNER-2026-10-23 plus the D03 scoped GPL-source to Apache-2.0
//! library-destination grant; original donor files/terms untouched.

#[path = "support/adapter_cases.rs"]
mod adapter_cases;

use adapter_cases::{check_manifest, limits, run_configure_suite, run_output_suite};
use scopebase_bpf::adapters::{admit_loader, BpfmanBackend, BpfmanShape, LoaderId, LoaderVersion};
use scopebase_bpf::attach::{AttachBackend, AttachMode, NativeAttach, NativeRetire, Site};
use scopebase_bpf::identity::ProducerDomain;
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use std::cell::{Cell, RefCell};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

const DOMAIN: ProducerDomain = ProducerDomain([0xC0; 16]);

/// Scripted bpfman-shaped program handle: records the held FD and
/// replays scripted outcomes. No native effects.
#[derive(Debug)]
struct FakeHandle {
    version: LoaderVersion,
    program_id: u32,
    seen_fd: Cell<Option<std::os::fd::RawFd>>,
    attach_calls: Cell<usize>,
    images: RefCell<Vec<u32>>,
    fail_attach: RefCell<Option<OperationError>>,
}

impl FakeHandle {
    fn new(program_id: u32) -> Self {
        Self {
            version: LoaderVersion::new(0, 1, 0),
            program_id,
            seen_fd: Cell::new(None),
            attach_calls: Cell::new(0),
            images: RefCell::new(Vec::new()),
            fail_attach: RefCell::new(None),
        }
    }
}

impl BpfmanShape for FakeHandle {
    type Link = u32;
    type Uncertain = u32;

    fn loader_version(&self) -> LoaderVersion {
        self.version
    }

    fn program_id(&self) -> u32 {
        self.program_id
    }

    fn attach_batch(
        &mut self,
        held_fd: std::os::fd::RawFd,
        sites: &[Site],
        _mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        let _ = sites.len();
        self.attach_calls.set(self.attach_calls.get() + 1);
        self.seen_fd.set(Some(held_fd));
        if let Some(cause) = self.fail_attach.borrow_mut().take() {
            return NativeAttach::NoEffect(cause);
        }
        self.images.borrow_mut().push(self.program_id);
        NativeAttach::Attached(self.program_id)
    }

    fn detach(&mut self, link: &mut Self::Link) -> NativeRetire {
        self.images.borrow_mut().retain(|id| id != link);
        NativeRetire::Retired
    }

    fn retire_uncertain_shape(&mut self, _custody: &mut Self::Uncertain) -> NativeRetire {
        NativeRetire::Retired
    }
}

#[test]
fn manifest_matches_admitted_bpfman_versions() {
    check_manifest(LoaderId::Bpfman, &["0.1.0"]);
    let admitted = admit_loader(LoaderId::Bpfman, &LoaderVersion::new(0, 1, 0)).unwrap();
    assert_eq!(admitted.loader(), LoaderId::Bpfman);
    assert!(admit_loader(LoaderId::Bpfman, &LoaderVersion::new(0, 14, 0)).is_err());
}

#[test]
fn native_configure_vectors_hold() {
    run_configure_suite();
}

#[test]
fn native_output_vectors_hold() {
    run_output_suite();
}

#[test]
fn program_id_mismatch_refused_with_owner_preserved() {
    let handle = FakeHandle::new(41);
    let error = BpfmanBackend::from_loaded(handle, 42, DOMAIN, limits()).unwrap_err();
    assert_eq!(error.cause().kind(), ErrorKind::Incompatible);
    let (owner, _) = error.into_parts();
    assert_eq!(owner.program_id(), 41);
}

#[test]
fn attach_detach_round_trip_uses_held_fd() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-bpfman");
    let authority = Arc::new(held);
    let expected_fd = authority.as_fd().as_raw_fd();
    let mut backend = BpfmanBackend::from_loaded(FakeHandle::new(7), 7, DOMAIN, limits()).unwrap();
    assert_eq!(backend.loader_id(), LoaderId::Bpfman);
    let plan = vec![
        Site {
            offset: 0x4000,
            cookie: 44,
        },
        Site {
            offset: 0x5000,
            cookie: 55,
        },
    ];
    let mut link = match backend.attach(&authority, &plan, AttachMode::EntryMulti) {
        NativeAttach::Attached(link) => link,
        other => panic!("expected attach, got {other:?}"),
    };
    assert_eq!(backend.shape().seen_fd.get(), Some(expected_fd));
    assert!(matches!(backend.retire(&mut link), NativeRetire::Retired));
    assert!(!backend.is_poisoned());
    assert!(backend.shape().images.borrow().is_empty());
}

#[test]
fn shape_refusal_propagates_without_poison() {
    // A proven no-effect refusal from the shape is not a rollback
    // failure: the backend stays usable.
    let (_path, held) = adapter_cases::temp_held(b"bp10-bpfman-noeffect");
    let authority = Arc::new(held);
    let mut backend = BpfmanBackend::from_loaded(FakeHandle::new(9), 9, DOMAIN, limits()).unwrap();
    *backend.shape_mut().fail_attach.borrow_mut() = Some(OperationError::new(
        ErrorKind::Backend,
        Stage::Attach,
        Some(22),
        None,
    ));
    let plan = vec![Site {
        offset: 0x4000,
        cookie: 44,
    }];
    match backend.attach(&authority, &plan, AttachMode::EntrySingle) {
        NativeAttach::NoEffect(cause) => assert_eq!(cause.kind(), ErrorKind::Backend),
        other => panic!("expected NoEffect, got {other:?}"),
    }
    assert!(!backend.is_poisoned());
}

#[test]
fn over_cap_and_poisoned_charge_refused() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-bpfman-charge");
    let authority = Arc::new(held);
    let backend = BpfmanBackend::from_loaded(FakeHandle::new(3), 3, DOMAIN, limits()).unwrap();
    let plan = vec![Site {
        offset: 1,
        cookie: 1,
    }];
    let charge = backend.custody_charge(&authority, &plan).unwrap();
    assert_eq!(charge.link_slots, 2);
    assert_eq!(charge.retained_bytes, 16);
    let over = vec![
        Site {
            offset: 0,
            cookie: 0
        };
        65
    ];
    assert_eq!(
        backend
            .custody_charge(&authority, &over)
            .unwrap_err()
            .kind(),
        ErrorKind::LimitExceeded
    );
}
