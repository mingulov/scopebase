// SPDX-License-Identifier: Apache-2.0
//! TT07 operator tests: installed delivery, typed refusals, receipt bounds.
//!
//! NEW (TT07): no donor lines copied. These tests drive the operator library
//! and CLI dispatch against the in-crate delivery closure. The installed
//! outside-checkout route is covered by tools/qualification/test_installed.py.
use scopebase_conformance::{
    commands, cleanup, closure, delivery, describe, plan, receipt, OperatorErrorKind,
    EXIT_BROKEN_PACKAGE, EXIT_FAILURE, EXIT_INCOMPLETE, EXIT_OK, EXIT_USAGE,
};
use scopebase_testkit::{CaseOracle, ConformanceAdapter, Qualification};
use std::path::{Path, PathBuf};

fn delivery_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("delivery")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tt07-{}-{}-{}",
        name,
        std::process::id(),
        // Monotonic disambiguator inside one process.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy_closure(name: &str) -> PathBuf {
    let dst = scratch(name);
    let root = dst.join("fixture-root");
    copy_dir(&delivery_root(), &root);
    root
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

// Plan case: missing fixture input is typed Incomplete, never silent success.
#[test]
fn missing_fixture_is_incomplete() {
    let root = copy_closure("missing-fixture");
    std::fs::remove_file(root.join("vectors").join("closure-input.txt")).unwrap();
    let out = scratch("missing-fixture-out");
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: delivery_root().join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::ClosureIncomplete);
    assert_eq!(err.exit_code(), EXIT_INCOMPLETE);
    assert!(
        !out.join("run").join("receipt.json").exists(),
        "refused run must not emit a receipt"
    );
}

// Plan case: a differently resolved downstream library is not certified.
#[test]
fn different_resolved_library_is_not_certified() {
    struct Renamed {
        inner: delivery::DeliveryAdapter,
        subject: scopebase_testkit::SubjectBinding,
    }
    impl scopebase_testkit::ConformanceAdapter for Renamed {
        fn subject(&self) -> scopebase_testkit::SubjectBinding {
            self.subject.clone()
        }
        fn execute(
            &mut self,
            i: &scopebase_testkit::CaseInvocation,
            f: &scopebase_testkit::FixtureAccess<'_>,
        ) -> Result<scopebase_testkit::Observation, scopebase_testkit::CaseError> {
            self.inner.execute(i, f)
        }
        fn retire(
            &mut self,
            r: &scopebase_testkit::RetireRequest,
        ) -> scopebase_testkit::RetirementReport {
            self.inner.retire(r)
        }
    }
    let root = delivery_root();
    let adapter = delivery::DeliveryAdapter::new().unwrap();
    let values = scopebase_testkit::SubjectBindingValues {
        package_name: "conformance-evil-fork".into(),
        package_version: adapter.subject().package_version().clone(),
        source_sha256: adapter.subject().source_sha256().clone(),
        build_inputs_sha256: adapter.subject().build_inputs_sha256().clone(),
        features: vec![],
        backend: None,
        host: adapter.subject().host().clone(),
        target: adapter.subject().target().clone(),
        consumer: adapter.subject().consumer().clone(),
        objects: vec![],
        provenance: scopebase_testkit::BindingProvenance::SelfReported {
            reason: "tt07 negative control".into(),
        },
    };
    let renamed_subject =
        scopebase_testkit::SubjectBinding::new(values, &scopebase_testkit::RunLimits::default())
            .unwrap();
    let mut renamed = Renamed {
        inner: adapter,
        subject: renamed_subject,
    };
    let out = scratch("evil-fork-out");
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut renamed,
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::SubjectMismatch);
    assert_eq!(err.exit_code(), EXIT_BROKEN_PACKAGE);
    assert!(
        !out.join("run").join("receipt.json").exists(),
        "mismatched subject must not be certified"
    );
}

// Tampered closure bytes are a broken package, not an incomplete run.
#[test]
fn tampered_fixture_is_broken_package() {
    let root = copy_closure("tampered");
    let victim = root.join("vectors").join("closure-input.txt");
    std::fs::write(&victim, b"tampered bytes").unwrap();
    let err = closure::verify_closure(&root, &root.join("fixture-manifest.json")).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage);
    assert_eq!(err.exit_code(), EXIT_BROKEN_PACKAGE);
}

// Missing H33 notices break the installed route.
#[test]
fn missing_notice_is_broken_package() {
    let root = copy_closure("missing-notice");
    std::fs::remove_file(root.join("THIRD-PARTY-NOTICES.md")).unwrap();
    let err = closure::verify_closure(&root, &root.join("fixture-manifest.json")).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage);
}

// Unknown profiles have no bound adapter: typed incomplete.
#[test]
fn unknown_profile_has_no_bound_adapter() {
    let root = delivery_root();
    let out = scratch("unknown-profile-out");
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "capture-core-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert!(
        matches!(
            err.kind(),
            OperatorErrorKind::NoBoundAdapter | OperatorErrorKind::UnknownProfile
        ),
        "unexpected kind: {:?}",
        err.kind()
    );
    assert_eq!(err.exit_code(), EXIT_INCOMPLETE);
}

// Full positive: the delivery profile executes through the real engine.
#[test]
fn delivery_run_is_qualified() {
    let root = delivery_root();
    let out = scratch("delivery-positive");
    let outcome = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap();
    assert_eq!(outcome.qualification, Qualification::Qualified);
    let receipt_path = out.join("run").join("receipt.json");
    assert!(receipt_path.exists());
    let report = receipt::verify_receipt(&receipt_path).unwrap();
    assert_eq!(report.qualification, Qualification::Qualified);
    assert!(!report.runtime_authority);
}

// Plan case: a receipt is evidence, never runtime authority.
#[test]
fn receipt_is_not_runtime_authority() {
    let root = delivery_root();
    let out = scratch("receipt-authority");
    let outcome = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap();
    assert_eq!(outcome.qualification, Qualification::Qualified);
    let envelope = read_json(&out.join("run").join("receipt.json"));
    assert_eq!(envelope["schema"], "operator-receipt-v1");
    assert_eq!(envelope["runtime_authority"], false);
    assert!(
        envelope["runtime_authority_statement"]
            .as_str()
            .unwrap()
            .contains("not"),
        "statement must deny runtime authority"
    );
    // Tampering with the recorded verdict invalidates the receipt.
    let mut tampered = envelope.clone();
    tampered["report"]["run_terminal"]["qualification"] = "failed".into();
    let tampered_path = out.join("tampered-receipt.json");
    std::fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let err = receipt::verify_receipt(&tampered_path).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::ReceiptInvalid);
}

// describe/plan perform no active setup and create no files.
#[test]
fn describe_and_plan_have_no_effects() {
    let before = scratch("purity");
    let catalog = std::fs::read(delivery_root().join("catalog.json")).unwrap();
    let description = describe::describe(&catalog).unwrap();
    assert!(
        description
            .profiles
            .iter()
            .any(|p| p.id == "operator-delivery-v1")
    );
    let doc = plan::plan(
        &catalog,
        "operator-delivery-v1",
        &delivery_root(),
        "no-new-target-mappings",
    )
    .unwrap();
    assert!(doc.closure_complete);
    assert!(doc.effects.is_empty());
    let entries: Vec<_> = std::fs::read_dir(&before).unwrap().collect();
    assert!(entries.is_empty());
    // Plan reports missing closures without performing setup.
    let root = copy_closure("plan-missing");
    std::fs::remove_file(root.join("vectors").join("binding-input.txt")).unwrap();
    let doc = plan::plan(
        &catalog,
        "operator-delivery-v1",
        &root,
        "no-new-target-mappings",
    )
    .unwrap();
    assert!(!doc.closure_complete);
    assert!(!doc.missing.is_empty());
}

// Plan case: CLI refusals carry stable exits and leave no effects.
#[test]
fn cli_refusal_exit_and_effects() {
    let work = scratch("cli-refusal");
    // Usage error: no subcommand.
    assert_eq!(commands::run_argv(&["scopebase-conformance".into()]), EXIT_USAGE);
    // Unknown subcommand.
    assert_eq!(
        commands::run_argv(&["scopebase-conformance".into(), "frobnicate".into()]),
        EXIT_USAGE
    );
    // Missing input file: typed refusal, exit 3, no output created.
    let missing = work.join("no-such-catalog.json");
    let code = commands::run_argv(&[
        "scopebase-conformance".into(),
        "describe".into(),
        "--catalog".into(),
        missing.to_string_lossy().into(),
    ]);
    assert_eq!(code, EXIT_INCOMPLETE);
    assert_eq!(
        commands::exit_for_kind(OperatorErrorKind::MissingInput),
        EXIT_INCOMPLETE
    );
    assert_eq!(
        commands::exit_for_kind(OperatorErrorKind::BrokenPackage),
        EXIT_BROKEN_PACKAGE
    );
    assert_eq!(
        commands::exit_for_kind(OperatorErrorKind::ReceiptInvalid),
        EXIT_FAILURE
    );
    let leftovers: Vec<_> = std::fs::read_dir(&work).unwrap().collect();
    assert!(leftovers.is_empty(), "refusals must not write effects");
}

// Read-only fixture roots still run; writes stay in the output dir.
#[test]
fn offline_read_only_prefix() {
    let root = copy_closure("read-only");
    let out = scratch("read-only-out");
    // Revoke write permission on every closure file (dirs stay traversable).
    set_tree_read_only(&root);
    let outcome = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap();
    assert_eq!(outcome.qualification, Qualification::Qualified);
    restore_tree_writable(&root);
}

fn set_tree_read_only(dir: &Path) {
    for entry in walkdir(dir) {
        let mut perms = std::fs::metadata(&entry).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&entry, perms).unwrap();
    }
}

fn restore_tree_writable(dir: &Path) {
    for entry in walkdir(dir) {
        let mut perms = std::fs::metadata(&entry).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
        }
        #[cfg(not(unix))]
        {
            perms.set_readonly(false);
        }
        std::fs::set_permissions(&entry, perms).unwrap();
    }
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![dir.to_path_buf()];
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walkdir(&path));
        } else {
            out.push(path);
        }
    }
    out
}

// cleanup only removes identity-checked run dirs.
#[test]
fn cleanup_is_identity_checked() {
    let root = delivery_root();
    let out = scratch("cleanup");
    let outcome = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap();
    assert_eq!(outcome.qualification, Qualification::Qualified);
    // Wrong expected run id refuses and keeps the dir.
    let err = cleanup::cleanup_run(&out.join("run"), Some("0".repeat(32).as_str())).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused);
    assert!(out.join("run").exists());
    // Refuses non-run dirs.
    let plain = out.join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    let err = cleanup::cleanup_run(&plain, None).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused);
    assert!(plain.exists());
    // Positive path removes the run dir.
    let report = cleanup::cleanup_run(&out.join("run"), None).unwrap();
    assert!(!out.join("run").exists());
    assert_eq!(report.run_id.len(), 32);
}

// Unknown mapping policies are usage errors, not silent defaults.
#[test]
fn unknown_mapping_policy_is_usage_error() {
    let root = delivery_root();
    let out = scratch("mapping-policy");
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "map-everything".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::Usage);
    assert_eq!(err.exit_code(), EXIT_USAGE);
}

// The shipped template pins exactly the linked delivery coordinates.
#[test]
fn template_pins_delivery_coordinates() {
    let root = delivery_root();
    let template = read_json(&root.join("contract-template.json"));
    let adapter = delivery::DeliveryAdapter::new().unwrap();
    let subject = adapter.subject();
    assert_eq!(
        template["expected_coordinates"]["package_name"].as_str(),
        Some(subject.package_name().as_str())
    );
    assert_eq!(
        template["expected_coordinates"]["package_version"].as_str(),
        Some(subject.package_version().as_str())
    );
    assert_eq!(
        template["expected_coordinates"]["source_sha256"].as_str(),
        Some(subject.source_sha256().as_str().as_str())
    );
    assert_eq!(
        template["expected_coordinates"]["consumer"].as_str(),
        Some(subject.consumer().name().as_str())
    );
    let oracle = delivery::DeliveryOracle::new().unwrap();
    let identity = serde_json::to_value(oracle.identity()).unwrap();
    let pinned = &template["expected_oracle"];
    for field in ["id", "revision", "schema_id", "source_sha256", "artifact_id"] {
        assert_eq!(identity[field], pinned[field], "oracle pin {field}");
    }
    assert_eq!(pinned["provenance"]["kind"], "generated_build");
    assert_eq!(
        identity["provenance"]["manifest_sha256"],
        pinned["provenance"]["manifest_sha256"]
    );
    // The per-build measurement is bound at runtime, never frozen.
    assert_eq!(pinned["provenance"]["measurement_sha256"], "@MEASUREMENT@");
}
