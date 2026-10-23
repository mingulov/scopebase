// SPDX-License-Identifier: Apache-2.0
//! BP10: narrow libbpf adapter over the existing loader plus the native
//! contract vectors.
//!
//! Shape-only in BP10: `libbpf-rs` was unavailable in the offline crate
//! cache, so no real binding is compiled (see
//! `tools/bpf-compat/profiles/libbpf-adapter.json`). The adapter logic,
//! version gate and contract vectors are proven over the narrow
//! [`LibbpfObjectShape`](scopebase_bpf::adapters::LibbpfObjectShape) seam;
//! the real `libbpf-rs` binding is a named follow-up, not silently claimed.
//!
//! ADAPT provenance (all user-owned donor lines; upstream libbpf code
//! never copied):
//! - p11scope `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//!   @ `2c2713e66292b0d2688508a25f79e813ae823d81`: offsets/cookies
//!   pairing refusal (lines 226-245) and errno classification
//!   (lines 288-310). ADAPT: same pairing/errno discipline as the Aya
//!   backend, over the libbpf shape.
//! - KryProbe `crates/kryprobe-privilege/src/bpfloader/progload.rs` @
//!   `d153f3aaf9a3931337b47c9e1b046c692da55083`:
//!   `attach_type_for_section` prefix routing (lines 141-160).
//!   ADAPT: program-name admission with unknown-name refusal.
//! Grant: OWNER-2026-10-23 plus the D03 scoped GPL-source to Apache-2.0
//! library-destination grant; original donor files/terms untouched.

#[path = "support/adapter_cases.rs"]
mod adapter_cases;

use adapter_cases::{check_manifest, limits, run_configure_suite, run_output_suite};
use scopebase_bpf::adapters::{
    admit_loader, LibbpfBackend, LibbpfObjectShape, LoaderId, LoaderVersion,
};
use scopebase_bpf::attach::{AttachBackend, AttachMode, NativeAttach, NativeRetire, Site};
use scopebase_bpf::identity::ProducerDomain;
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

const DOMAIN: ProducerDomain = ProducerDomain([0xB0; 16]);

/// Scripted libbpf-shaped object: records the held FD and replays
/// scripted outcomes. No native effects.
#[derive(Debug)]
struct FakeObject {
    version: LoaderVersion,
    name: CString,
    seen_fd: Cell<Option<std::os::fd::RawFd>>,
    attach_calls: Cell<usize>,
    detach_calls: Cell<usize>,
    log: RefCell<Vec<String>>,
    fail_detach: RefCell<Option<OperationError>>,
}

impl FakeObject {
    fn new(name: &str) -> Self {
        Self {
            version: LoaderVersion::new(0, 1, 0),
            name: CString::new(name).unwrap(),
            seen_fd: Cell::new(None),
            attach_calls: Cell::new(0),
            detach_calls: Cell::new(0),
            log: RefCell::new(Vec::new()),
            fail_detach: RefCell::new(None),
        }
    }
}

impl LibbpfObjectShape for FakeObject {
    type Link = u64;
    type Uncertain = u64;

    fn loader_version(&self) -> LoaderVersion {
        self.version
    }

    fn program_name(&self) -> &CStr {
        &self.name
    }

    fn attach_batch(
        &mut self,
        held_fd: std::os::fd::RawFd,
        sites: &[Site],
        _mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        self.attach_calls.set(self.attach_calls.get() + 1);
        self.seen_fd.set(Some(held_fd));
        self.log
            .borrow_mut()
            .push(format!("attach:{}", sites.len()));
        NativeAttach::Attached(7)
    }

    fn detach(&mut self, _link: &mut Self::Link) -> NativeRetire {
        self.detach_calls.set(self.detach_calls.get() + 1);
        match self.fail_detach.borrow_mut().take() {
            Some(cause) => NativeRetire::Failed(cause),
            None => NativeRetire::Retired,
        }
    }

    fn retire_uncertain_shape(&mut self, _custody: &mut Self::Uncertain) -> NativeRetire {
        NativeRetire::Retired
    }
}

fn backend(name: &str) -> LibbpfBackend<FakeObject> {
    let expected = CString::new(name).unwrap();
    LibbpfBackend::from_loaded(FakeObject::new(name), &expected, DOMAIN, limits()).unwrap()
}

#[test]
fn manifest_matches_admitted_libbpf_versions() {
    check_manifest(LoaderId::Libbpf, &["0.1.0"]);
    let admitted = admit_loader(LoaderId::Libbpf, &LoaderVersion::new(0, 1, 0)).unwrap();
    assert_eq!(admitted.loader(), LoaderId::Libbpf);
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
fn program_name_mismatch_refused_with_owner_preserved() {
    let object = FakeObject::new("uprobe_entry");
    let wrong = CString::new("uprobe_other").unwrap();
    let error = LibbpfBackend::from_loaded(object, &wrong, DOMAIN, limits()).unwrap_err();
    assert_eq!(error.cause().kind(), ErrorKind::Incompatible);
    assert_eq!(error.cause().stage(), Stage::Admission);
    let (owner, _) = error.into_parts();
    assert_eq!(
        owner.program_name(),
        CStr::from_bytes_with_nul(b"uprobe_entry\0").unwrap()
    );
}

#[test]
fn unsupported_shape_version_refused() {
    let mut object = FakeObject::new("uprobe_entry");
    object.version = LoaderVersion::new(0, 2, 0);
    let expected = CString::new("uprobe_entry").unwrap();
    let error = LibbpfBackend::from_loaded(object, &expected, DOMAIN, limits()).unwrap_err();
    assert_eq!(error.cause().kind(), ErrorKind::Incompatible);
    // Aya's upstream pin is not valid for the libbpf shape either.
    assert!(admit_loader(LoaderId::Libbpf, &LoaderVersion::new(0, 14, 0)).is_err());
}

#[test]
fn attach_uses_held_fd() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-libbpf");
    let authority = Arc::new(held);
    let expected_fd = authority.as_fd().as_raw_fd();
    let mut backend = backend("uprobe_entry");
    let plan = vec![Site {
        offset: 0x3000,
        cookie: 33,
    }];
    let outcome = backend.attach(&authority, &plan, AttachMode::EntrySingle);
    assert!(matches!(outcome, NativeAttach::Attached(_)));
    assert_eq!(backend.shape().seen_fd.get(), Some(expected_fd));
    assert_eq!(backend.shape().attach_calls.get(), 1);
}

#[test]
fn fixed_tail_profile_refused_unsupported() {
    // Plan-pinned behavior: real libbpf cannot enforce a fixed tail, so
    // the adapter refuses that profile instead of claiming it.
    let backend = backend("uprobe_entry");
    let error = backend.admit_profile("fixed-tail").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert_eq!(error.stage(), Stage::Admission);
    assert!(backend.admit_profile("single").is_ok());
    assert!(backend.admit_profile("multi").is_ok());
}

#[test]
fn retire_failure_poisons_backend() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-libbpf-poison");
    let authority = Arc::new(held);
    let mut backend = backend("uprobe_entry");
    let plan = vec![Site {
        offset: 0x3000,
        cookie: 33,
    }];
    let mut link = match backend.attach(&authority, &plan, AttachMode::EntrySingle) {
        NativeAttach::Attached(link) => link,
        other => panic!("expected attach, got {other:?}"),
    };
    *backend.shape_mut().fail_detach.borrow_mut() = Some(OperationError::new(
        ErrorKind::Backend,
        Stage::Retire,
        Some(5),
        None,
    ));
    assert!(matches!(backend.retire(&mut link), NativeRetire::Failed(_)));
    assert!(backend.is_poisoned());
    assert_eq!(
        backend
            .custody_charge(&authority, &plan)
            .unwrap_err()
            .kind(),
        ErrorKind::Poisoned
    );
}
