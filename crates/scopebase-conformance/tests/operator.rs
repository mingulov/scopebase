// SPDX-License-Identifier: Apache-2.0
//! TT07 operator tests: installed delivery, typed refusals, receipt bounds.
//!
//! NEW (TT07): no donor lines copied. These tests drive the operator library
//! and CLI dispatch against the in-crate delivery closure. The installed
//! outside-checkout route is covered by tools/qualification/test_installed.py.
use scopebase_conformance::{
    commands, cleanup, closure, delivery, describe, plan, receipt, OperatorErrorKind,
    EXIT_BROKEN_PACKAGE, EXIT_FAILURE, EXIT_INCOMPLETE, EXIT_USAGE,
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

/// An adapter that serves delivery behavior under a substituted subject.
struct Resubjected {
    inner: delivery::DeliveryAdapter,
    subject: scopebase_testkit::SubjectBinding,
}

impl scopebase_testkit::ConformanceAdapter for Resubjected {
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
    let mut renamed = Resubjected {
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

// A mutated source digest is refused even when every name/version matches.
#[test]
fn mutated_source_sha256_is_not_certified() {
    let root = delivery_root();
    let adapter = delivery::DeliveryAdapter::new().unwrap();
    let values = scopebase_testkit::SubjectBindingValues {
        package_name: adapter.subject().package_name().clone(),
        package_version: adapter.subject().package_version().clone(),
        source_sha256: scopebase_testkit::Digest256::of_bytes(b"mutated source bytes"),
        build_inputs_sha256: *adapter.subject().build_inputs_sha256(),
        features: vec![],
        backend: None,
        host: adapter.subject().host().clone(),
        target: adapter.subject().target().clone(),
        consumer: adapter.subject().consumer().clone(),
        objects: vec![],
        provenance: scopebase_testkit::BindingProvenance::SelfReported {
            reason: "tt07 source-hash negative control".into(),
        },
    };
    let mutated_subject =
        scopebase_testkit::SubjectBinding::new(values, &scopebase_testkit::RunLimits::default())
            .unwrap();
    let mut mutated = Resubjected {
        inner: adapter,
        subject: mutated_subject,
    };
    let out = scratch("evil-source-out");
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut mutated,
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::SubjectMismatch);
    assert_eq!(err.exit_code(), EXIT_BROKEN_PACKAGE);
    assert!(
        !out.join("run").join("receipt.json").exists(),
        "mutated source must not be certified"
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

// Box3b: describe/plan emit the no-qualification marker, never a verdict.
#[test]
fn describe_and_plan_report_not_evaluated() {
    let catalog = std::fs::read(delivery_root().join("catalog.json")).unwrap();
    let description = describe::describe(&catalog).unwrap();
    let value = serde_json::to_value(&description).unwrap();
    assert_eq!(
        value.get("qualification").and_then(|q| q.as_str()),
        Some("not_evaluated")
    );
    let doc = plan::plan(
        &catalog,
        "operator-delivery-v1",
        &delivery_root(),
        "no-new-target-mappings",
    )
    .unwrap();
    let value = serde_json::to_value(&doc).unwrap();
    assert_eq!(
        value.get("qualification").and_then(|q| q.as_str()),
        Some("not_evaluated")
    );
}

// Box3b: structural verify-receipt exits 0 reporting the recorded verdict.
#[test]
fn cli_verify_receipt_exits_zero_with_recorded_qualification() {
    let root = delivery_root();
    let out = scratch("cli-verify");
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
    let receipt_path = out.join("run").join("receipt.json");
    let report = receipt::verify_receipt(&receipt_path).unwrap();
    assert_eq!(report.qualification, outcome.qualification);
    let code = commands::run_argv(&[
        "scopebase-conformance".into(),
        "verify-receipt".into(),
        receipt_path.to_string_lossy().into(),
    ]);
    assert_eq!(code, 0);
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

// F33: flag arity is strict. A value-less trailing option and a flag
// followed by another flag are usage errors (exit 2), never a silent
// default or a misread of the next flag; no effects are written.
#[test]
fn cli_flag_arity_is_strict() {
    let work = scratch("cli-arity");
    let argv = |tail: &[&str]| {
        let mut v = vec!["scopebase-conformance".to_string()];
        v.extend(tail.iter().map(|s| s.to_string()));
        v
    };
    // Trailing option without a value.
    assert_eq!(
        commands::run_argv(&argv(&[
            "plan",
            "--catalog",
            "c.json",
            "--profile",
            "p",
            "--fixture-root",
            "r",
            "--mapping-policy"
        ])),
        EXIT_USAGE
    );
    // Required flag followed by another flag: missing value, not "--profile".
    assert_eq!(
        commands::run_argv(&argv(&[
            "plan",
            "--catalog",
            "--profile",
            "p",
            "--fixture-root",
            "r"
        ])),
        EXIT_USAGE
    );
    // Trailing required flag.
    assert_eq!(
        commands::run_argv(&argv(&["cleanup", "--run"])),
        EXIT_USAGE
    );
    // Explicit `--flag=value` still works (flag-like values allowed there).
    let missing = work.join("no-such-catalog.json");
    let code = commands::run_argv(&argv(&[
        "describe",
        &format!("--catalog={}", missing.to_string_lossy()),
    ]));
    assert_eq!(code, EXIT_INCOMPLETE);
    let leftovers: Vec<_> = std::fs::read_dir(&work).unwrap().collect();
    assert!(leftovers.is_empty(), "arity refusals must not write effects");
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

// F10: a ledger file id escaping staging refuses before any write, and no
// file appears outside the staging dir. The override path is used because
// overrides are caller-chosen outside closure pins.
#[test]
fn ledger_file_id_traversal_is_refused() {
    let root = copy_closure("traversal");
    let mut template: serde_json::Value = read_json(&root.join("contract-template.json"));
    // The malicious key reuses a real ledger template (with a run-id slot)
    // so only the file-id guard stands between it and the write.
    template["ledger_templates"]["../escaped"] =
        serde_json::Value::String("vectors/ledger-closure.json.tmpl".into());
    let override_path = root.join("evil-template.json");
    std::fs::write(&override_path, serde_json::to_vec(&template).unwrap()).unwrap();
    let out = scratch("traversal-out");
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: Some(override_path),
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage);
    // staging.join("../escaped.json") would land here without the guard.
    assert!(
        !out.join("run").join("escaped.json").exists(),
        "traversal must not write outside staging"
    );
    assert!(
        !out.join("escaped.json").exists(),
        "traversal must not write anywhere unexpected"
    );
}

// F31: the default template is manifest-pinned; a tampered copy refuses as
// a broken package. (verify_closure pins every file up front; the F31 fix
// additionally re-checks the bytes at use through closure.read, closing
// the verify-then-reopen window.)
#[test]
fn tampered_default_template_is_refused() {
    let root = copy_closure("tampered-template");
    let path = root.join("contract-template.json");
    let mut template: serde_json::Value = read_json(&path);
    template["tampered"] = serde_json::Value::Bool(true);
    std::fs::write(&path, serde_json::to_vec(&template).unwrap()).unwrap();
    let out = scratch("tampered-template-out");
    let err = delivery::run_delivery(delivery::RunRequest {
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
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage);
}

// F11: a second run into an occupied output dir refuses (usage error) and
// leaves the first run's receipt intact.
#[test]
fn second_run_into_occupied_output_dir_refuses() {
    let root = delivery_root();
    let out = scratch("occupied-out");
    let run = || {
        delivery::run_delivery(delivery::RunRequest {
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
    };
    let first = run().unwrap();
    assert_eq!(first.qualification, Qualification::Qualified);
    let before = std::fs::read(out.join("run").join("receipt.json")).unwrap();
    let err = run().unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::Usage);
    let after = std::fs::read(out.join("run").join("receipt.json")).unwrap();
    assert_eq!(before, after, "refused rerun must not touch the first run");
}

// F30: outer bindings are compared against the admitted catalog and staged
// contract; a resealed receipt with a swapped subject still fails, while
// the untouched receipt verifies.
#[test]
fn resealed_subject_swap_fails_catalog_verification() {
    let root = delivery_root();
    let out = scratch("reseal");
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
    let catalog_bytes = std::fs::read(root.join("catalog.json")).unwrap();
    let receipt_path = out.join("run").join("receipt.json");
    let report = receipt::verify_receipt_with_catalog(&receipt_path, &catalog_bytes).unwrap();
    assert_eq!(report.qualification, Qualification::Qualified);
    // Evil twin: same staged contract, subject swapped, seal recomputed.
    let evil = out.join("run-evil");
    copy_dir(&out.join("run"), &evil);
    let evil_receipt = evil.join("receipt.json");
    let mut envelope: serde_json::Value = read_json(&evil_receipt);
    envelope["subject"]["package_name"] =
        serde_json::Value::String("conformance-evil-fork".into());
    envelope.as_object_mut().unwrap().remove("envelope_sha256");
    let digest =
        scopebase_testkit::Digest256::of_bytes(&serde_json::to_vec(&envelope).unwrap()).as_str();
    envelope["envelope_sha256"] = digest.into();
    std::fs::write(&evil_receipt, serde_json::to_vec(&envelope).unwrap()).unwrap();
    let err = receipt::verify_receipt_with_catalog(&evil_receipt, &catalog_bytes).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::ReceiptInvalid);
}

// F03: minimal-but-admitted limits still deliver the schema refusal (no
// panic): the diagnostic is truncated to the caller's own ceiling.
#[test]
fn tiny_limits_still_deliver_schema_refusal() {
    use scopebase_testkit::{
        CaseErrorCategory, CaseId, CaseInvocation, CaseInvocationValues, CaseKey, CaseKeyValues,
        EffectBatch, FixtureAccess, InvocationKey, InvocationKeyValues, Label, OperationScript,
        RunId, RunLimits, SchemaBinding, SchemaBindingValues,
    };
    let mut values = RunLimits::default().values();
    values.diagnostic_bytes = 1;
    values.steps_per_invocation = 1;
    values.observation_bytes = 1;
    let limits = RunLimits::new(values).unwrap();
    let label = |text: &str| Label::parse(text).unwrap();
    let script = serde_json::json!({
        "schema_version": 1,
        "kind": "steps-v1",
        "schema_id": "alien-schema-v9",
        "steps": [{"step_id": "only", "operation": "nope", "inputs": [], "parameters": []}],
    });
    let key = InvocationKey::new(
        InvocationKeyValues {
            run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            case_key: CaseKey::new(
                CaseKeyValues {
                    case_id: CaseId::parse("TT07.tiny-limits").unwrap(),
                    case_version: 1,
                    cell_id: "tiny".into(),
                },
                &limits,
            )
            .unwrap(),
            attempt: 1,
            operation_id: 1,
        },
        &limits,
    )
    .unwrap();
    let binding = |id: &str| {
        SchemaBinding::new(
            SchemaBindingValues { id: label(id), revision: 1 },
            &limits,
        )
        .unwrap()
    };
    let invocation = CaseInvocation::new(
        CaseInvocationValues {
            key,
            observation_schema: binding("tt07-observation"),
            fixture_schema: binding("tt07-fixture"),
            script: OperationScript::load(&serde_json::to_vec(&script).unwrap(), &limits).unwrap(),
            limits: limits.clone(),
        },
        &limits,
    )
    .unwrap();
    let access =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).unwrap();
    let mut adapter = delivery::DeliveryAdapter::new().unwrap();
    let error = adapter
        .execute(&invocation, &access)
        .expect_err("alien schema must refuse");
    assert_eq!(*error.category(), CaseErrorCategory::UnsupportedSchema);
    assert!(
        error.diagnostic_bytes().len() <= 1,
        "diagnostic must fit the caller ceiling"
    );
}

// R03/R04: executable boundary tests over the installed operator
// binary. Dispatch unit tests cannot exercise argv decoding or dead
// stdio; these drive the real binary.

fn operator_bin() -> PathBuf {
    // Compile-time lookup (cargo sets this when the binary target is in
    // the build plan); a filtered run that excludes the binary fails
    // loudly here instead of skipping vacuously.
    PathBuf::from(env!("CARGO_BIN_EXE_scopebase-conformance"))
}

/// R04: output failure is exit 1 (`OutputFailed`), and the kind maps
/// there (in-process mapping check; the dead stream needs a process).
#[test]
fn output_failed_maps_to_exit_1() {
    assert_eq!(
        commands::exit_for_kind(OperatorErrorKind::OutputFailed),
        EXIT_FAILURE
    );
}

/// R03: non-UTF-8 argv refuses with the reason plus usage (exit 2),
/// never panics in `env::args()` (old code exited 101).
#[test]
fn non_utf8_argv_refuses_with_usage() {
    use std::os::unix::ffi::OsStringExt;
    let out = std::process::Command::new(operator_bin())
        .arg(std::ffi::OsString::from_vec(b"describe\xff".to_vec()))
        .output()
        .expect("spawn operator");
    assert_eq!(out.status.code(), Some(EXIT_USAGE));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid Unicode"), "{stderr:?}");
    assert!(stderr.contains("usage:"), "{stderr:?}");
}

/// R04: `--help` with a dead stdout exits 1 with an `OutputFailed`
/// report on stderr, never panics (old `println!` exited 101).
#[test]
fn dead_stdout_help_exits_1_without_panic() {
    let full = std::fs::File::create("/dev/full").expect("/dev/full opens");
    let out = std::process::Command::new(operator_bin())
        .arg("--help")
        .stdout(full)
        .output()
        .expect("spawn operator");
    assert_eq!(out.status.code(), Some(EXIT_FAILURE));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot write report to stdout"),
        "{stderr:?}"
    );
}

/// R04: a dead stderr does not disturb a success: `--help` still
/// exits 0 with the usage on stdout.
#[test]
fn dead_stderr_keeps_help_success() {
    let full = std::fs::File::create("/dev/full").expect("/dev/full opens");
    let out = std::process::Command::new(operator_bin())
        .arg("--help")
        .stderr(full)
        .output()
        .expect("spawn operator");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("usage:"), "{stdout:?}");
}

/// R04: a dead stderr keeps the already-determined usage code (bare
/// argv is a usage error, exit 2), never panics.
#[test]
fn dead_stderr_keeps_usage_code() {
    let full = std::fs::File::create("/dev/full").expect("/dev/full opens");
    let out = std::process::Command::new(operator_bin())
        .stderr(full)
        .output()
        .expect("spawn operator");
    assert_eq!(out.status.code(), Some(EXIT_USAGE));
}
