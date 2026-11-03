// SPDX-License-Identifier: Apache-2.0
//! BP10: narrow Aya adapter over the existing loader plus the native
//! contract vectors.
//!
//! ADAPT provenance (all user-owned donor lines; upstream Aya code never
//! copied — the real binding calls upstream APIs, it does not vendor them):
//! - p11scope `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//!   @ `2c2713e66292b0d2688508a25f79e813ae823d81`: offsets/cookies
//!   pairing refusal (lines 226-245), errno classification
//!   (lines 288-310) and the `GroupHalt` terminal taxonomy
//!   (lines 312-324). ADAPT: pairing becomes site duplicate/empty/cap
//!   refusal; classification becomes the loader errno mapping.
//! - p11scope `tests/bpf_map_contracts.rs` @ `7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4`
//!   lines 61-107: distinct sentinel FD per map. ADAPT: distinct
//!   sentinel per output span in the native vectors (no `aya_obj` use).
//! - KryProbe `crates/kryprobe-privilege/src/bpfloader/progload.rs` @
//!   `d153f3aaf9a3931337b47c9e1b046c692da55083`:
//!   `attach_type_for_section` prefix routing (lines 141-160) and its
//!   twin test (lines 622-635). ADAPT: entry/return mode routing with
//!   unknown-shape refusal.
//! Grant: OWNER-2026-10-23 plus the D03 scoped GPL-source to Apache-2.0
//! library-destination grant; original donor files/terms untouched.
//!
//! Standalone-seam ratification (explicit): TC05 shipped a standalone
//! graph seam and TC06 recorded the standalone decision; BP10 keeps it.
//! The native vectors below do not extend `inspect_final_object`: the
//! `tc05_tc06_standalone_seam_ratified` test calls TC03 inspect, TC05
//! graph extraction and TC06 rule checks as three independent entry
//! points and pins their independent typed refusals.

#[path = "support/adapter_cases.rs"]
mod adapter_cases;

use adapter_cases::{check_manifest, limits, repo_bytes, run_configure_suite, run_output_suite};
use scopebase_bpf::adapters::{
    admit_loader, AyaBackend, AyaUprobeShape, LoaderId, LoaderVersion, RULE_ATTACH_MODE,
    RULE_ATTACH_PAIRING,
};
use scopebase_bpf::attach::{AttachBackend, AttachMode, NativeAttach, NativeRetire, Site};
use scopebase_bpf::identity::ProducerDomain;
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use std::cell::{Cell, RefCell};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

const DOMAIN: ProducerDomain = ProducerDomain([0xA0; 16]);

/// Scripted Aya-shaped program: records the held FD it was given and
/// replays scripted attach/detach outcomes. No native effects.
#[derive(Debug)]
struct FakeUprobe {
    version: LoaderVersion,
    is_return: bool,
    seen_fd: Cell<Option<std::os::fd::RawFd>>,
    seen_sites: RefCell<Vec<Site>>,
    attach_calls: Cell<usize>,
    detach_calls: Cell<usize>,
    fail_attach: RefCell<Option<OperationError>>,
    fail_detach: RefCell<Option<OperationError>>,
    next_link: Cell<u64>,
}

impl FakeUprobe {
    fn entry() -> Self {
        Self {
            version: LoaderVersion::new(0, 14, 0),
            is_return: false,
            seen_fd: Cell::new(None),
            seen_sites: RefCell::new(Vec::new()),
            attach_calls: Cell::new(0),
            detach_calls: Cell::new(0),
            fail_attach: RefCell::new(None),
            fail_detach: RefCell::new(None),
            next_link: Cell::new(1),
        }
    }

    fn with_version(mut self, version: LoaderVersion) -> Self {
        self.version = version;
        self
    }
}

impl AyaUprobeShape for FakeUprobe {
    type Link = u64;
    type Uncertain = u64;

    fn loader_version(&self) -> LoaderVersion {
        self.version
    }

    fn is_return(&self) -> bool {
        self.is_return
    }

    fn attach_batch(
        &mut self,
        held_fd: std::os::fd::RawFd,
        sites: &[Site],
        _mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        self.attach_calls.set(self.attach_calls.get() + 1);
        self.seen_fd.set(Some(held_fd));
        self.seen_sites.borrow_mut().extend_from_slice(sites);
        if let Some(cause) = self.fail_attach.borrow_mut().take() {
            return NativeAttach::NoEffect(cause);
        }
        let link = self.next_link.get();
        self.next_link.set(link + 1);
        NativeAttach::Attached(link)
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

fn backend(program: FakeUprobe) -> AyaBackend<FakeUprobe> {
    AyaBackend::from_loaded(program, DOMAIN, limits()).unwrap()
}

fn sites() -> Vec<Site> {
    vec![
        Site {
            offset: 0x1000,
            cookie: 11,
        },
        Site {
            offset: 0x2000,
            cookie: 22,
        },
    ]
}

#[test]
fn manifest_matches_admitted_aya_versions() {
    check_manifest(LoaderId::Aya, &["0.14.0"]);
    let admitted = admit_loader(LoaderId::Aya, &LoaderVersion::new(0, 14, 0)).unwrap();
    assert_eq!(admitted.loader(), LoaderId::Aya);
    assert_eq!(admitted.version(), LoaderVersion::new(0, 14, 0));
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
fn from_loaded_binds_domain_and_version() {
    let backend = backend(FakeUprobe::entry());
    assert_eq!(backend.loader_id(), LoaderId::Aya);
    assert_eq!(backend.domain(), DOMAIN);
    assert_eq!(backend.admitted_version(), LoaderVersion::new(0, 14, 0));
    assert!(!backend.is_poisoned());
}

#[test]
fn unsupported_loader_version_refused_with_owner_preserved() {
    for text in ["0.13.0", "0.14.1", "0.15.0", "1.0.0"] {
        let version = LoaderVersion::parse(text).unwrap();
        let program = FakeUprobe::entry().with_version(version);
        let error = AyaBackend::from_loaded(program, DOMAIN, limits()).unwrap_err();
        assert_eq!(error.cause().kind(), ErrorKind::Incompatible);
        assert_eq!(error.cause().stage(), Stage::Admission);
        // The original owner travels back untouched: the program value
        // is recoverable and still reports its version.
        let (owner, cause) = error.into_parts();
        assert_eq!(cause.kind(), ErrorKind::Incompatible);
        assert_eq!(owner.loader_version(), version);
    }
}

#[test]
fn malformed_version_text_refused() {
    for text in [
        "", "0.14", "0.14.0.0", "v0.14.0", "0.14.0\n", "00.14.0", "0.14.0 ",
    ] {
        assert!(
            LoaderVersion::parse(text).is_err(),
            "version text must refuse: {text:?}"
        );
    }
}

#[test]
fn attach_uses_held_fd_with_paired_sites() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-aya");
    let authority = Arc::new(held);
    let expected_fd = authority.as_fd().as_raw_fd();
    let mut backend = backend(FakeUprobe::entry());
    let plan = sites();
    for mode in [AttachMode::EntrySingle, AttachMode::EntryMulti] {
        let outcome = backend.attach(&authority, &plan[..1], mode);
        assert!(matches!(outcome, NativeAttach::Attached(_)), "{mode:?}");
    }
    // The shape saw the held FD itself, never a pathname: the only
    // descriptor it ever observed is the authority's live FD.
    assert_eq!(backend.shape().seen_fd.get(), Some(expected_fd));
    assert_eq!(backend.shape().attach_calls.get(), 2);
    // Paired sites travel as one record each: offsets and cookies match
    // the plan order on every call.
    let seen = backend.shape().seen_sites.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], plan[0]);
    assert_eq!(seen[1], plan[0]);
}

#[test]
fn return_mode_against_entry_program_refused_without_effect() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-aya-mode");
    let authority = Arc::new(held);
    let mut backend = backend(FakeUprobe::entry());
    let outcome = backend.attach(&authority, &sites()[..1], AttachMode::ReturnSingle);
    match outcome {
        NativeAttach::NoEffect(cause) => {
            assert_eq!(cause.kind(), ErrorKind::Incompatible);
            assert_eq!(cause.stage(), Stage::Attach);
        }
        other => panic!("mode mismatch must be NoEffect, got {other:?}"),
    }
    // Proven no-effect: the shape was never invoked.
    assert_eq!(backend.shape().attach_calls.get(), 0);
    assert_eq!(RULE_ATTACH_MODE, "native.attach.mode-mismatch");
}

#[test]
fn duplicate_and_empty_sites_refused_without_effect() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-aya-pair");
    let authority = Arc::new(held);
    let mut backend = backend(FakeUprobe::entry());
    let dupes = vec![
        Site {
            offset: 0x1000,
            cookie: 11,
        },
        Site {
            offset: 0x1000,
            cookie: 22,
        },
    ];
    match backend.attach(&authority, &dupes, AttachMode::EntryMulti) {
        NativeAttach::NoEffect(cause) => assert_eq!(cause.kind(), ErrorKind::InvalidInput),
        other => panic!("duplicate offsets must refuse, got {other:?}"),
    }
    let dupe_cookies = vec![
        Site {
            offset: 0x1000,
            cookie: 11,
        },
        Site {
            offset: 0x2000,
            cookie: 11,
        },
    ];
    match backend.attach(&authority, &dupe_cookies, AttachMode::EntryMulti) {
        NativeAttach::NoEffect(cause) => assert_eq!(cause.kind(), ErrorKind::InvalidInput),
        other => panic!("duplicate cookies must refuse, got {other:?}"),
    }
    match backend.attach(&authority, &[], AttachMode::EntrySingle) {
        NativeAttach::NoEffect(cause) => assert_eq!(cause.kind(), ErrorKind::InvalidInput),
        other => panic!("empty sites must refuse, got {other:?}"),
    }
    assert_eq!(backend.shape().attach_calls.get(), 0);
    assert_eq!(RULE_ATTACH_PAIRING, "native.attach.pairing");
}

#[test]
fn cookie_swap_detected_end_to_end() {
    // Mutant control: if the adapter ever reordered or dropped the
    // cookie pairing, the shape-side expectation fails loudly.
    let (_path, held) = adapter_cases::temp_held(b"bp10-aya-swap");
    let authority = Arc::new(held);
    let mut backend = backend(FakeUprobe::entry());
    let plan = sites();
    let outcome = backend.attach(&authority, &plan, AttachMode::EntryMulti);
    assert!(matches!(outcome, NativeAttach::Attached(_)));
    let seen = backend.shape().seen_sites.borrow();
    assert_eq!(&seen[..], &plan[..], "offset/cookie pairing must survive");
    let swapped = vec![
        Site {
            offset: plan[0].offset,
            cookie: plan[1].cookie,
        },
        Site {
            offset: plan[1].offset,
            cookie: plan[0].cookie,
        },
    ];
    assert_ne!(&seen[..], &swapped[..], "swapped control must differ");
}

#[test]
fn custody_charge_bounds_plan() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-aya-charge");
    let authority = Arc::new(held);
    let backend = backend(FakeUprobe::entry());
    let plan = sites();
    let charge = backend.custody_charge(&authority, &plan).unwrap();
    assert_eq!(charge.link_slots, plan.len() + 1);
    assert_eq!(charge.retained_bytes, plan.len() * 16);
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

#[test]
fn retire_failure_poisons_backend() {
    let (_path, held) = adapter_cases::temp_held(b"bp10-aya-poison");
    let authority = Arc::new(held);
    let mut backend = backend(FakeUprobe::entry());
    let mut link = match backend.attach(&authority, &sites()[..1], AttachMode::EntrySingle) {
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
    // A poisoned backend refuses further attach without touching the shape.
    let calls = backend.shape().attach_calls.get();
    match backend.attach(&authority, &sites()[..1], AttachMode::EntrySingle) {
        NativeAttach::NoEffect(cause) => assert_eq!(cause.kind(), ErrorKind::Poisoned),
        other => panic!("poisoned backend must refuse, got {other:?}"),
    }
    assert_eq!(backend.shape().attach_calls.get(), calls);
}

#[test]
fn loader_errno_classification() {
    use scopebase_bpf::adapters::classify_loader_errno;
    // Donor discipline (p11scope bpf-multi lines 288-310): permission is
    // systemic Denied, exhaustion is LimitExceeded, missing multi
    // support is Unsupported; anything else stays Backend/Unknown.
    assert_eq!(classify_loader_errno(13), ErrorKind::Denied); // EACCES
    assert_eq!(classify_loader_errno(1), ErrorKind::Denied); // EPERM
    assert_eq!(classify_loader_errno(24), ErrorKind::LimitExceeded); // EMFILE
    assert_eq!(classify_loader_errno(95), ErrorKind::Unsupported); // EOPNOTSUPP
    assert_eq!(classify_loader_errno(22), ErrorKind::Backend); // EINVAL: poison, not fallback
}

#[test]
fn tc05_tc06_standalone_seam_ratified() {
    use scopebase_testkit::object::graph::extract_call_graph;
    use scopebase_testkit::object::inspect_final_object;
    use scopebase_testkit::object::prune_dead_code;
    use scopebase_testkit::object::ObjectContract;
    // Minimal contract in the exact TC01/TC03 schema shape.
    let contract_json = serde_json::json!({
        "schema_version": 1,
        "artifact": "bp10-seam-probe",
        "profile": "compiler-object-v1",
        "target": { "triple": "bpfel-unknown-none", "arch": "bpfel", "endian": "little", "pointer_width_bits": 64 },
        "backend": { "kind": "llvm-llc", "name": "llc", "version": "21.1.8", "sha256": "935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382" },
        "features_enabled": [],
        "features_disabled": [],
        "required_cells": ["kernel-6.12-x86_64-verifier"],
        "optional_cells": [],
    });
    let contract_bytes = serde_json::to_vec(&contract_json).unwrap();
    let contract = ObjectContract::from_json(&contract_bytes, &limits()).unwrap();
    // TC03 inspect and TC05 graph extraction are independent entry
    // points over the same bytes: both refuse truncated input typed,
    // neither delegates to the other.
    let truncated = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    let inspect_err = inspect_final_object(&truncated, &contract, &limits()).unwrap_err();
    assert_eq!(inspect_err.kind(), ErrorKind::Malformed);
    let graph_err = extract_call_graph(&truncated, &contract, &limits()).unwrap_err();
    assert_eq!(graph_err.kind(), ErrorKind::Malformed);
    // S168: TC06 keeps its own bounded decode beside them — the leg
    // must call the actual TC06 entry point, not pin a repo file's
    // nonemptiness. Truncated input refuses with the TC06 marker
    // (Malformed/Inspect plus the tc06 source tag: TC03 refuses at
    // Admission, TC05 tags tc05); a valid control object succeeds.
    let prune_err = prune_dead_code(&truncated, &contract, &limits()).unwrap_err();
    assert_eq!(prune_err.kind(), ErrorKind::Malformed);
    assert_eq!(prune_err.stage(), scopebase_bpf::Stage::Inspect);
    let mut tagged = false;
    let mut cursor = std::error::Error::source(&prune_err);
    while let Some(cause) = cursor {
        if cause.to_string().contains("tc06 prune") {
            tagged = true;
        }
        cursor = std::error::Error::source(cause);
    }
    assert!(tagged, "TC06 refusal carries its source tag");
    // Live-only control object: emitted 2026-11-02 by testkit
    // `prune_fixture(Endian::Little, &[("live", 2)], &["live"])`
    // (object_rules.rs); re-emit from that builder if TC06's accepted
    // shape evolves. sha256 d03df6df….
    let valid = repo_bytes("crates/scopebase-bpf/tests/fixtures/tc06-live.o");
    let pruned = prune_dead_code(&valid, &contract, &limits()).expect("valid control prunes");
    assert_eq!(pruned, valid, "dead-empty prune echoes its input");
}

#[cfg(feature = "aya")]
#[test]
fn real_aya_binding_implements_shape() {
    // Compile-time proof that the narrow shape is implementable over
    // the real upstream type (aya =0.14.0). Live attach cells need a
    // privileged kernel and stay NOT_RUN here.
    fn assert_shape<S: AyaUprobeShape>() {}
    assert_shape::<aya::programs::UProbe>();
}

#[test]
fn temp_create_refuses_precreated_target() {
    // S187: `create_new` — a pre-created file at the target (e.g. a
    // planted symlink) refuses instead of truncating through, and the
    // victim contents are unchanged.
    let path = std::env::temp_dir().join(format!("bp10-s187-aya-{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"victim").unwrap();
    let error = adapter_cases::create_temp_file(&path, b"overwritten").expect_err("refuses");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"victim");
    std::fs::remove_file(&path).unwrap();
}
