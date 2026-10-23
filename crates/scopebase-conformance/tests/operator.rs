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
use scopebase_testkit::{CaseOracle, ConformanceAdapter, Digest256, Qualification};
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

// R37: full verification reads the envelope exactly once. A FIFO
// serves its bytes to the first reader only: the old second read
// hung on reopen, so completing with the right report proves the
// seal, bindings and report all came from one read.
#[cfg(unix)]
#[test]
fn receipt_full_verification_reads_once() {
    let root = delivery_root();
    let out = scratch("receipt-once");
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
    let receipt_bytes = std::fs::read(&outcome.receipt_path).unwrap();
    // A verification dir: the real staged contract beside a FIFO receipt.
    let dir = out.join("verify");
    std::fs::create_dir_all(dir.join("staging")).unwrap();
    std::fs::copy(
        out.join("run").join("staging").join("contract.json"),
        dir.join("staging").join("contract.json"),
    )
    .unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        dir.join("receipt.json"),
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    let catalog = std::fs::read(root.join("catalog.json")).unwrap();
    // The writer serves the envelope once, then closes (EOF); a
    // second open would block forever with no writer left.
    let fifo = dir.join("receipt.json");
    let writer = std::thread::spawn(move || {
        std::fs::write(&fifo, &receipt_bytes).unwrap();
    });
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let report = receipt::verify_receipt_with_catalog(&dir.join("receipt.json"), &catalog);
        let _ = tx.send(report.map(|r| (r.run_id, r.qualification)));
    });
    let (run_id, qualification) = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("verification blocked on a second envelope read")
        .unwrap();
    writer.join().unwrap();
    assert_eq!(run_id, outcome.run_id);
    assert_eq!(qualification, outcome.qualification);
}

// R48: a resealed envelope with an unsupported version is refused by
// both shallow and full verification, with the valid report and
// bindings otherwise intact.
#[test]
fn receipt_with_unsupported_version_is_refused() {
    let root = delivery_root();
    let out = scratch("receipt-version");
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
    let mut envelope = read_json(&outcome.receipt_path);
    envelope["schema_version"] = 2.into();
    // Reseal over the altered envelope: the unkeyed seal recomputes,
    // so only the version gate can refuse this.
    let mut canonical = envelope.clone();
    canonical.as_object_mut().unwrap().remove("envelope_sha256");
    let digest = Digest256::of_bytes(&serde_json::to_vec(&canonical).unwrap()).as_str();
    envelope["envelope_sha256"] = digest.into();
    let bad = out.join("run").join("receipt-v2.json");
    std::fs::write(&bad, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
    let err = receipt::verify_receipt(&bad).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::ReceiptInvalid);
    let catalog = std::fs::read(root.join("catalog.json")).unwrap();
    let err = receipt::verify_receipt_with_catalog(&bad, &catalog).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::ReceiptInvalid);
}

// R40: the oracle judges the exact expected/actual kind pair. Steps
// stay byte-identical across every row; only the kinds vary.
#[test]
fn oracle_judges_exact_kind_pairs() {
    use scopebase_testkit::{
        CaseId, CaseKey, CaseKeyValues, CatalogLimits, CheckStatus, EffectBatch, ExpectedEvidence,
        ExpectedEvidenceValues, InvocationKey, InvocationKeyValues, Label, Observation,
        ObservationValues, RunId, RunLimits, SchemaBinding, SchemaBindingValues, TruthKind,
    };
    let catalog_bytes = std::fs::read(delivery_root().join("catalog.json")).unwrap();
    let catalog =
        scopebase_testkit::CaseCatalog::load(&catalog_bytes, CatalogLimits::default()).unwrap();
    let spec = catalog
        .case(&CaseId::parse("TT07.closure").unwrap(), 1)
        .unwrap();
    let oracle = delivery::DeliveryOracle::new().unwrap();
    let limits = RunLimits::default();
    let judge = |expected_kind: Option<&str>, actual_kind: Option<&str>| {
        let key = InvocationKey::new(
            InvocationKeyValues {
                run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                case_key: CaseKey::new(
                    CaseKeyValues {
                        case_id: CaseId::parse("TT07.closure").unwrap(),
                        case_version: 1,
                        cell_id: "installed".to_string(),
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
        let steps = serde_json::json!([{"step_id": "s1", "value": "abc"}]);
        let mut expected_json = serde_json::json!({"schema_version": 1, "steps": steps});
        if let Some(kind) = expected_kind {
            expected_json["kind"] = kind.into();
        }
        let mut actual_json = serde_json::json!({"schema_version": 1, "steps": steps});
        if let Some(kind) = actual_kind {
            actual_json["kind"] = kind.into();
        }
        let expected = ExpectedEvidence::new(
            ExpectedEvidenceValues {
                key: key.clone(),
                oracle: oracle.identity(),
                fixture_schema: SchemaBinding::new(
                    SchemaBindingValues {
                        id: Label::parse("s").unwrap(),
                        revision: 1,
                    },
                    &limits,
                )
                .unwrap(),
                truth_kind: TruthKind::FixedBeforeExecute,
                expected_bytes: serde_json::to_vec(&expected_json).unwrap(),
                ledger_bytes: b"{}".to_vec(),
                coverage: vec![],
                effects: EffectBatch::empty(&limits),
            },
            &limits,
        )
        .unwrap();
        let observation = Observation::new(
            ObservationValues {
                key,
                schema_id: Label::parse("o").unwrap(),
                schema_revision: 1,
                completed_steps: vec![],
                bytes: serde_json::to_vec(&actual_json).unwrap(),
                effects: EffectBatch::empty(&limits),
            },
            &limits,
        )
        .unwrap();
        let verdict = oracle.evaluate(
            spec,
            &expected,
            &scopebase_testkit::CaseOutcome::Observed(observation),
        );
        *verdict.checks()[0].status()
    };
    // Matched pairs pass with identical steps: expected vectors
    // speak `-expected`, observations `-observation`.
    assert_eq!(
        judge(
            Some("tt07-closure-v1-expected"),
            Some("tt07-closure-v1-observation")
        ),
        CheckStatus::Pass
    );
    assert_eq!(
        judge(
            Some("tt07-binding-v1-expected"),
            Some("tt07-binding-v1-observation")
        ),
        CheckStatus::Pass
    );
    // Crossed, missing, same-dialect and unadmitted kinds fail with
    // identical steps.
    assert_eq!(
        judge(
            Some("tt07-closure-v1-expected"),
            Some("tt07-binding-v1-observation")
        ),
        CheckStatus::Fail
    );
    assert_eq!(
        judge(
            Some("tt07-binding-v1-expected"),
            Some("tt07-closure-v1-observation")
        ),
        CheckStatus::Fail
    );
    assert_eq!(
        judge(
            Some("tt07-closure-v1-observation"),
            Some("tt07-closure-v1-observation")
        ),
        CheckStatus::Fail
    );
    assert_eq!(
        judge(Some("tt07-closure-v1-expected"), None),
        CheckStatus::Fail
    );
    assert_eq!(
        judge(None, Some("tt07-closure-v1-observation")),
        CheckStatus::Fail
    );
    assert_eq!(
        judge(Some("tt07-evil-v1"), Some("tt07-evil-v1")),
        CheckStatus::Fail
    );
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

// R38: planning never reads outside the root, unbounded, or
// blocking. Escape entries, pseudo-devices, oversized manifests and
// FIFOs are accounted without ever being opened the old way.
#[test]
fn plan_accounting_is_bounded_and_root_validated() {
    let catalog = std::fs::read(delivery_root().join("catalog.json")).unwrap();
    // (a) Absolute escape and pseudo-device entries land in
    // `mismatched`, never read: the old fallback read them (an EIO
    // pseudo-device even miscategorized as `missing`).
    let root = copy_closure("plan-escape");
    let manifest_path = root.join("fixture-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    for (path, sha) in [
        (
            "/proc/self/mem",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "../../outside.json",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ] {
        manifest["files"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "path": path,
                "length": "8",
                "sha256": sha,
            }));
    }
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let doc = plan::plan(
        &catalog,
        "operator-delivery-v1",
        &root,
        "no-new-target-mappings",
    )
    .unwrap();
    assert!(!doc.closure_complete);
    assert!(doc.mismatched.iter().any(|m| m == "/proc/self/mem"));
    assert!(doc.mismatched.iter().any(|m| m == "../../outside.json"));
    assert!(!doc.missing.iter().any(|m| m == "/proc/self/mem"));

    // (b) An oversized manifest is refused as a unit: the old code
    // read and parsed it, then accounted every entry individually.
    let root = copy_closure("plan-oversized");
    let manifest_path = root.join("fixture-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["padding"] = "x".repeat(2 << 20).into();
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let doc = plan::plan(
        &catalog,
        "operator-delivery-v1",
        &root,
        "no-new-target-mappings",
    )
    .unwrap();
    assert!(!doc.closure_complete);
    assert!(doc.mismatched.iter().any(|m| m == closure::MANIFEST_FILE));

    // (c) A writer-less FIFO member refuses fast instead of hanging
    // verification or the accounting fallback. Completing proves it.
    #[cfg(unix)]
    {
        let root = copy_closure("plan-fifo");
        let manifest_path = root.join("fixture-manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["files"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "path": "stall.bin",
                "length": "4",
                "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            }));
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.join("stall.bin"),
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let doc = plan::plan(
            &catalog,
            "operator-delivery-v1",
            &root,
            "no-new-target-mappings",
        )
        .unwrap();
        assert!(!doc.closure_complete);
        assert!(doc.mismatched.iter().any(|m| m == "stall.bin"));
    }
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

// R47: positional arity is strict. Flags-only commands take no bare
// tokens, and `verify-receipt` takes exactly one: extras refuse with
// usage before any I/O, never execute.
#[test]
fn cli_positional_arity_is_strict() {
    let work = scratch("cli-positional");
    let argv = |tail: &[&str]| {
        let mut v = vec!["scopebase-conformance".to_string()];
        v.extend(tail.iter().map(|s| s.to_string()));
        v
    };
    // Stray tokens on flags-only commands.
    assert_eq!(
        commands::run_argv(&argv(&["cleanup", "--run", "somewhere", "stray"])),
        EXIT_USAGE
    );
    assert_eq!(
        commands::run_argv(&argv(&["describe", "--catalog", "c.json", "stray"])),
        EXIT_USAGE
    );
    assert_eq!(
        commands::run_argv(&argv(&[
            "run",
            "--catalog",
            "c.json",
            "--profile",
            "p",
            "--fixture-root",
            "r",
            "--output",
            "o",
            "stray"
        ])),
        EXIT_USAGE
    );
    // A second positional on verify-receipt.
    assert_eq!(
        commands::run_argv(&argv(&["verify-receipt", "a.json", "b.json"])),
        EXIT_USAGE
    );
    // Flag values that look bare are still values, not positionals:
    // this reaches catalog I/O (exit 3), not a usage refusal.
    let missing = work.join("no-such-catalog.json");
    let code = commands::run_argv(&argv(&[
        "describe",
        "--catalog",
        missing.to_string_lossy().as_ref(),
    ]));
    assert_eq!(code, EXIT_INCOMPLETE);
    let leftovers: Vec<_> = std::fs::read_dir(&work).unwrap().collect();
    assert!(
        leftovers.is_empty(),
        "arity refusals must not write effects"
    );
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

// R36: a manifest reached only through a symlink is an identity spoof:
// the old path-based reader followed it, the pinned reader refuses.
#[test]
fn cleanup_refuses_symlink_manifest() {
    let out = scratch("cleanup-symlink-manifest");
    let elsewhere = out.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(
        elsewhere.join("run-manifest.json"),
        r#"{"schema":"operator-run-manifest-v1","run_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","profile":"p"}"#,
    )
    .unwrap();
    let run = out.join("run");
    std::fs::create_dir_all(&run).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        elsewhere.join("run-manifest.json"),
        run.join("run-manifest.json"),
    )
    .unwrap();
    let err = cleanup::cleanup_run(&run, None).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused);
    assert!(run.exists());
    assert!(elsewhere.join("run-manifest.json").exists());
}

// R36: planted symlinks inside a run dir are unlinked, never followed:
// outside targets survive cleanup.
#[test]
fn cleanup_never_follows_planted_symlinks() {
    let out = scratch("cleanup-planted-links");
    let outside = out.join("outside.txt");
    std::fs::write(&outside, b"precious").unwrap();
    let run = out.join("run");
    let nested = run.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        run.join("run-manifest.json"),
        r#"{"schema":"operator-run-manifest-v1","run_id":"ffffffffffffffffffffffffffffffff","profile":"p"}"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, nested.join("escape")).unwrap();
        std::os::unix::fs::symlink(&out, run.join("loop-back")).unwrap();
    }
    let report = cleanup::cleanup_run(&run, None).unwrap();
    assert_eq!(report.run_id, "ffffffffffffffffffffffffffffffff");
    assert!(!run.exists());
    assert_eq!(std::fs::read(&outside).unwrap(), b"precious");
}

// R36: validation-to-deletion replacement. While a swapper thread
// cycles a victim (non-run) dir and a valid run dir under one name,
// cleanup either removes the run or refuses — the victim's bytes
// always survive. A name-based unlink keeps a residual window that
// can only ever remove an empty attacker-planted dir (and is then
// reported as a refusal); the non-empty victim here proves the
// fd-bound validation rules out the destructive case.
#[test]
fn cleanup_survives_validation_to_deletion_swaps() {
    const RUN_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let out = scratch("cleanup-swaps");
    let victim_src = out.join("victim-src");
    std::fs::create_dir_all(&victim_src).unwrap();
    std::fs::write(victim_src.join("precious.txt"), b"precious").unwrap();
    let run_src = out.join("run-src");
    std::fs::create_dir_all(&run_src).unwrap();
    std::fs::write(
        run_src.join("run-manifest.json"),
        format!(r#"{{"schema":"operator-run-manifest-v1","run_id":"{RUN_ID}","profile":"p"}}"#),
    )
    .unwrap();
    std::fs::write(run_src.join("filler.txt"), b"run-owned").unwrap();
    let slot = out.join("slot");
    let park = out.join("park");
    let tmp = out.join("tmp");
    std::fs::rename(&run_src, &slot).unwrap();
    std::fs::rename(&victim_src, &park).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let swapper = {
        let (slot, park, tmp, stop) = (slot.clone(), park.clone(), tmp.clone(), stop.clone());
        std::thread::spawn(move || {
            // Exchange slot <-> park; cleanup may remove the name
            // mid-exchange, so every rename error is ignored.
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = std::fs::rename(&slot, &tmp);
                let _ = std::fs::rename(&park, &slot);
                let _ = std::fs::rename(&tmp, &park);
                std::thread::yield_now();
            }
        })
    };
    // Replant a fresh valid run whenever the slot is missing, so
    // every round exposes the validation-to-deletion window instead
    // of stopping at the first uncontended success.
    let plant = |dst: &Path| {
        let staging = dst.with_extension("plant");
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(
            staging.join("run-manifest.json"),
            format!(r#"{{"schema":"operator-run-manifest-v1","run_id":"{RUN_ID}","profile":"p"}}"#),
        )
        .unwrap();
        std::fs::write(staging.join("filler.txt"), b"run-owned").unwrap();
        // Fails when the slot holds a non-empty dir (victim or an
        // unprocessed run): the round simply runs against that.
        let _ = std::fs::rename(&staging, dst);
    };
    let mut successes = 0;
    for _ in 0..2000 {
        if std::fs::symlink_metadata(&slot).is_err() {
            plant(&slot);
        }
        match cleanup::cleanup_run(&slot, None) {
            Ok(report) => {
                // Only the validated run is ever removed.
                assert_eq!(report.run_id, RUN_ID);
                successes += 1;
            }
            Err(err) => assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused),
        }
    }
    assert!(successes >= 1, "uncontended rounds must succeed");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    swapper.join().unwrap();
    // The victim's bytes survive wherever the swapper parked them.
    let mut precious = 0;
    for entry in walkdir(&out) {
        if entry
            .file_name()
            .map(|n| n == "precious.txt")
            .unwrap_or(false)
        {
            assert_eq!(std::fs::read(&entry).unwrap(), b"precious");
            precious += 1;
        }
    }
    assert_eq!(precious, 1, "victim bytes must survive exactly once");
    // And cleanup still works once the swapping stops.
    let calm = out.join("calm");
    std::fs::create_dir_all(&calm).unwrap();
    std::fs::write(
        calm.join("run-manifest.json"),
        format!(r#"{{"schema":"operator-run-manifest-v1","run_id":"{RUN_ID}","profile":"p"}}"#),
    )
    .unwrap();
    let report = cleanup::cleanup_run(&calm, None).unwrap();
    assert_eq!(report.run_id, RUN_ID);
    assert!(!calm.exists());
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

// F31/R41: a template tampered before verification refuses as a broken
// package. This pins the pre-verify refusal only — it cannot inject a
// mutation between verification and use (both happen inside one
// `run_delivery`). The verify/use window itself is covered by the
// closure unit test `read_rechecks_pin_after_verify`, with a
// protection-removed control proving it fails without the re-check.
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

// R35: an empty output path refuses before any I/O — the old check
// admitted it (`read_dir("")` is `NotFound`) and wrote run files
// into the current directory. Both the API and the CLI refuse, and
// the current directory stays clean.
#[test]
fn empty_output_dir_refuses_before_io() {
    let root = delivery_root();
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: PathBuf::from(""),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::Usage);
    let code = commands::run_argv(&[
        "scopebase-conformance".to_string(),
        "run".to_string(),
        "--catalog".to_string(),
        root.join("catalog.json").to_string_lossy().into(),
        "--profile".to_string(),
        "operator-delivery-v1".to_string(),
        "--fixture-root".to_string(),
        root.to_string_lossy().into(),
        "--output".to_string(),
        String::new(),
    ]);
    assert_eq!(code, EXIT_USAGE);
    for canary in ["staging", "receipt.json", "run-manifest.json"] {
        assert!(
            !Path::new(canary).exists(),
            "empty output must not write ./{canary}"
        );
    }
}

// R36: two runs racing the same output are exclusive — exactly one
// wins, and the loser refuses before writing anything. (In-process
// this outcome also holds on old code by scheduling luck — the slow
// adapter construction ahead of the check separates the two checks —
// so the old-code-discriminating control is the pre-created-empty
// race below, which old code admits and new code refuses.)
#[test]
fn concurrent_runs_into_same_output_are_exclusive() {
    let root = delivery_root();
    let out = scratch("concurrent-out");
    let target = out.join("run");
    let run = |root: PathBuf, target: PathBuf| {
        delivery::run_delivery(delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: None,
            output_dir: target,
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        })
    };
    let first = {
        let (root, target) = (root.clone(), target.clone());
        std::thread::spawn(move || run(root, target))
    };
    let second = {
        let (root, target) = (root.clone(), target.clone());
        std::thread::spawn(move || run(root, target))
    };
    let (r1, r2) = (first.join().unwrap(), second.join().unwrap());
    let (winner, loser) = match (r1, r2) {
        (Ok(w), Err(l)) => (w, l),
        (Err(l), Ok(w)) => (w, l),
        (Ok(_), Ok(_)) => panic!("both concurrent runs succeeded"),
        (Err(e1), Err(e2)) => panic!("both concurrent runs failed: {e1} / {e2}"),
    };
    assert_eq!(winner.qualification, Qualification::Qualified);
    assert_eq!(loser.kind(), OperatorErrorKind::Usage);
    // The winner's run is complete and sealed: the receipt verifies,
    // and no temp/sealed-write leftovers remain.
    let report = receipt::verify_receipt(&winner.receipt_path).unwrap();
    assert_eq!(report.run_id, winner.run_id);
    for entry in walkdir(&target) {
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(
            !name.starts_with(".tmp-"),
            "sealed-write leftover: {}",
            entry.display()
        );
    }
}

// R36: delivery never inherits another directory — a pre-created
// (even empty) output refuses, so two runs racing it both lose with
// usage errors and the dir stays untouched. Old code admitted empty
// dirs, so at least one old run always proceeded past the check.
#[test]
fn pre_created_output_dir_refuses_both_racers() {
    let root = delivery_root();
    let out = scratch("precreated-out");
    let target = out.join("run");
    std::fs::create_dir_all(&target).unwrap();
    let run = |root: PathBuf, target: PathBuf| {
        delivery::run_delivery(delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: None,
            output_dir: target,
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        })
    };
    let first = {
        let (root, target) = (root.clone(), target.clone());
        std::thread::spawn(move || run(root, target))
    };
    let second = {
        let (root, target) = (root.clone(), target.clone());
        std::thread::spawn(move || run(root, target))
    };
    let (r1, r2) = (first.join().unwrap(), second.join().unwrap());
    for result in [&r1, &r2] {
        let err = result.as_ref().unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::Usage);
    }
    let entries: Vec<_> = std::fs::read_dir(&target).unwrap().collect();
    assert!(entries.is_empty(), "refused runs must not write");
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

// RB4 (R02): a tight-but-legal label ceiling still delivers the refusal
// (no panic): the convenience method/stage tags fit the live ceiling
// while the category and cause stay exact. Nine bytes keeps the two
// fitted tags distinct ("adapter-s" vs "adapter-d").
#[test]
fn tight_label_ceiling_fits_delivery_refusal_tags() {
    use scopebase_testkit::{
        CaseErrorCategory, CaseId, CaseInvocation, CaseInvocationValues, CaseKey, CaseKeyValues,
        EffectBatch, FixtureAccess, InvocationKey, InvocationKeyValues, Label, OperationScript,
        RunId, RunLimits, SchemaBinding, SchemaBindingValues,
    };
    let mut values = RunLimits::default().values();
    values.label_bytes = 9;
    let limits = RunLimits::new(values).unwrap();
    let label = |text: &str| Label::parse(text).unwrap();
    let script = serde_json::json!({
        "schema_version": 1,
        "kind": "steps-v1",
        "schema_id": "s",
        "steps": [{"step_id": "s", "operation": "nope", "inputs": [], "parameters": []}],
    });
    let key = InvocationKey::new(
        InvocationKeyValues {
            run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            case_key: CaseKey::new(
                CaseKeyValues {
                    case_id: CaseId::parse("TT07.tight-labels").unwrap(),
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
            SchemaBindingValues {
                id: label(id),
                revision: 1,
            },
            &limits,
        )
        .unwrap()
    };
    let invocation = CaseInvocation::new(
        CaseInvocationValues {
            key,
            observation_schema: binding("o-v1"),
            fixture_schema: binding("f-v1"),
            script: OperationScript::load(&serde_json::to_vec(&script).unwrap(), &limits).unwrap(),
            limits: limits.clone(),
        },
        &limits,
    )
    .unwrap();
    let access = FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).unwrap();
    let mut adapter = delivery::DeliveryAdapter::new().unwrap();
    let error = adapter
        .execute(&invocation, &access)
        .expect_err("alien schema must refuse");
    assert_eq!(*error.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(error.stage().as_str(), "adapter-s");
    assert_eq!(error.cause().method().as_str(), "adapter-d");
    assert!(error.step_id().is_none(), "dialect rejection names no step");
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
