// SPDX-License-Identifier: Apache-2.0
//! TT07 operator tests: installed delivery, typed refusals, receipt bounds.
//!
//! NEW (TT07): no donor lines copied. These tests drive the operator library
//! and CLI dispatch against the in-crate delivery closure. The installed
//! outside-checkout route is covered by tools/qualification/test_installed.py.
use scopebase_conformance::{
    cleanup, closure, commands, delivery, describe, plan, receipt, OperatorErrorKind,
    EXIT_BROKEN_PACKAGE, EXIT_FAILURE, EXIT_INCOMPLETE, EXIT_USAGE,
};
use scopebase_testkit::{CaseOracle, ConformanceAdapter, Digest256, Qualification};
use scopebase_testkit::{
    CaseErrorCategory, CaseId, CaseInvocation, CaseInvocationValues, CaseKey, CaseKeyValues,
    EffectBatch, FixtureAccess, FixtureInput, InvocationKey, InvocationKeyValues, Label,
    OperationScript, RunId, RunLimits, SchemaBinding, SchemaBindingValues,
};
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
    // S14: scratch parents are 0700 regardless of ambient umask,
    // so run dirs under them pass the exclusivity gate.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

fn copy_closure(name: &str) -> PathBuf {
    let dst = scratch(name);
    let root = dst.join("fixture-root");
    copy_dir(&delivery_root(), &root);
    root
}

/// S13: create one directory level with an explicit exclusive mode,
/// umask-proof. Cleanup refuses shared directories, so every test
/// tree it clears must be exclusive by construction (run dirs 0700
/// like delivery creates; nested levels 0755).
fn mkexclusive(path: &std::path::Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
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

// S41: mandatory v1 bindings gate the seal. A sparse or malformed
// envelope RESEALED over its sparse shape (self-consistent seal)
// still fails on the bindings — never passes shallow admission.
#[test]
fn receipt_rejects_sparse_and_malformed_bindings() {
    let root = delivery_root();
    let out = scratch("receipt-bindings");
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
    // Reseal exactly like the producer: drop the seal, hash the
    // canonical bytes, reattach. Anyone can do this — which is why
    // the bindings must gate admission, not the seal.
    let reseal = |mut sparse: serde_json::Value| {
        sparse.as_object_mut().unwrap().remove("envelope_sha256");
        let digest =
            scopebase_testkit::Digest256::of_bytes(&serde_json::to_vec(&sparse).unwrap()).as_str();
        sparse["envelope_sha256"] = digest.into();
        sparse
    };
    // Control: a resealed UNCHANGED envelope still verifies — the
    // helper is faithful to the producer's seal.
    let control_path = out.join("resealed-control.json");
    std::fs::write(
        &control_path,
        serde_json::to_vec(&reseal(envelope.clone())).unwrap(),
    )
    .unwrap();
    let report = receipt::verify_receipt(&control_path).unwrap();
    assert_eq!(report.qualification, Qualification::Qualified);
    // Removed bindings fail, one at a time.
    for binding in [
        "catalog_sha256",
        "run_contract_sha256",
        "fixture_manifest_sha256",
        "mapping_policy",
        "subject",
    ] {
        let mut sparse = envelope.clone();
        sparse.as_object_mut().unwrap().remove(binding);
        let path = out.join(format!("sparse-{binding}.json"));
        std::fs::write(&path, serde_json::to_vec(&reseal(sparse)).unwrap()).unwrap();
        let err = receipt::verify_receipt(&path).unwrap_err();
        assert_eq!(
            err.kind(),
            OperatorErrorKind::ReceiptInvalid,
            "removed {binding} must fail"
        );
    }
    // Malformed digests fail: short, non-hex, and non-string.
    for (tag, bad) in [
        ("short", serde_json::json!("abc")),
        ("nonhex", serde_json::json!("zz".repeat(32))),
        ("number", serde_json::json!(123)),
    ] {
        let mut sparse = envelope.clone();
        sparse["catalog_sha256"] = bad;
        let path = out.join(format!("malformed-{tag}.json"));
        std::fs::write(&path, serde_json::to_vec(&reseal(sparse)).unwrap()).unwrap();
        let err = receipt::verify_receipt(&path).unwrap_err();
        assert_eq!(
            err.kind(),
            OperatorErrorKind::ReceiptInvalid,
            "malformed digest ({tag}) must fail"
        );
    }
}

// S41: the shallow subject gate admits the TYPED binding, not any
// object. A resealed envelope whose subject is `{}` — or a sparse
// object missing binding fields — fails at the subject gate, never
// by seal mismatch (the reseal keeps the seal valid).
#[test]
fn receipt_rejects_untyped_subject() {
    let root = delivery_root();
    let out = scratch("receipt-subject");
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
    let reseal = |mut sparse: serde_json::Value| {
        sparse.as_object_mut().unwrap().remove("envelope_sha256");
        let digest =
            scopebase_testkit::Digest256::of_bytes(&serde_json::to_vec(&sparse).unwrap()).as_str();
        sparse["envelope_sha256"] = digest.into();
        sparse
    };
    // Control: the resealed genuine envelope still verifies — the
    // producer's subject passes typed admission.
    let control_path = out.join("resealed-subject-control.json");
    std::fs::write(
        &control_path,
        serde_json::to_vec(&reseal(envelope.clone())).unwrap(),
    )
    .unwrap();
    let report = receipt::verify_receipt(&control_path).unwrap();
    assert_eq!(report.qualification, Qualification::Qualified);
    // `{}` and sparse subjects fail at the subject gate.
    let mut probe = envelope["subject"].clone();
    probe.as_object_mut().unwrap().remove("consumer");
    let mut mistyped = envelope["subject"].clone();
    mistyped["package_name"] = serde_json::json!(7);
    mistyped["consumer"] = serde_json::json!("consumer");
    for (tag, bad) in [
        ("empty", serde_json::json!({})),
        ("sparse", probe),
        ("mistyped", mistyped),
        ("scalar", serde_json::json!("subject")),
    ] {
        let mut tampered = envelope.clone();
        tampered["subject"] = bad;
        let path = out.join(format!("untyped-subject-{tag}.json"));
        std::fs::write(&path, serde_json::to_vec(&reseal(tampered)).unwrap()).unwrap();
        let err = receipt::verify_receipt(&path).unwrap_err();
        assert_eq!(
            err.kind(),
            OperatorErrorKind::ReceiptInvalid,
            "untyped subject ({tag}) must fail"
        );
        assert!(
            err.to_string().contains("subject"),
            "untyped subject ({tag}) must fail at the subject gate, got: {err}"
        );
    }
}

// S57: a valid large receipt round-trips. A 512 KiB binding input
// (echoed by DeliveryAdapter, hex-expanded in the report past the
// old 1 MiB cap) still verifies on both routes — writer and reader
// bounds are compatible, including envelope expansion.
#[test]
fn large_valid_receipt_round_trips() {
    let root = copy_closure("s57-large");
    let big = vec![b'a'; 524288];
    std::fs::write(root.join("vectors/binding-input.txt"), &big).unwrap();
    let expected = format!(
        "{{\"schema_version\": 1, \"kind\": \"tt07-binding-v1-expected\", \"steps\": [{{\"step_id\": \"binding\", \"value\": \"{}\"}}]}}",
        "a".repeat(524288)
    );
    std::fs::write(root.join("vectors/binding-expected.json"), &expected).unwrap();
    // Re-pin the full chain: the contract template pins each vector
    // (length + sha256), and the fixture manifest pins the template.
    let template_path = root.join("contract-template.json");
    let mut template = read_json(&template_path);
    for artifact in template["artifacts"].as_array_mut().unwrap() {
        let id = artifact["id"].as_str().unwrap();
        let rel = match id {
            "binding-input" => "vectors/binding-input.txt",
            "binding-expected" => "vectors/binding-expected.json",
            _ => continue,
        };
        let bytes = std::fs::read(root.join(rel)).unwrap();
        artifact["length"] = serde_json::Value::String(bytes.len().to_string());
        artifact["sha256"] =
            serde_json::Value::String(scopebase_testkit::Digest256::of_bytes(&bytes).as_str());
    }
    std::fs::write(&template_path, serde_json::to_vec(&template).unwrap()).unwrap();
    let manifest_path = root.join("fixture-manifest.json");
    let mut manifest = read_json(&manifest_path);
    for file in manifest["files"].as_array_mut().unwrap() {
        let path = file["path"].as_str().unwrap();
        if path == "vectors/binding-input.txt"
            || path == "vectors/binding-expected.json"
            || path == "contract-template.json"
        {
            let bytes = std::fs::read(root.join(path)).unwrap();
            file["length"] = serde_json::Value::String(bytes.len().to_string());
            file["sha256"] =
                serde_json::Value::String(scopebase_testkit::Digest256::of_bytes(&bytes).as_str());
        }
    }
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let out = scratch("s57-large-out");
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
    let receipt_len = std::fs::metadata(&receipt_path).unwrap().len();
    assert!(
        receipt_len > (1 << 20),
        "round trip must exceed the old 1 MiB cap: {receipt_len}"
    );
    let report = receipt::verify_receipt(&receipt_path).unwrap();
    assert_eq!(report.qualification, Qualification::Qualified);
    let catalog_bytes = std::fs::read(root.join("catalog.json")).unwrap();
    let full = receipt::verify_receipt_with_catalog(&receipt_path, &catalog_bytes).unwrap();
    assert_eq!(full.qualification, Qualification::Qualified);
}

// S57: the envelope bound covers the largest engine-admitted
// report body plus overhead — guards the derivation against
// future limit changes on either side.
#[test]
fn receipt_cap_covers_engine_report_ceiling() {
    let body = RunLimits::default().receipt_bytes();
    assert!(
        closure::MAX_RECEIPT_BYTES >= body + (2 << 20),
        "envelope cap {} must cover report ceiling {body} + 2 MiB overhead",
        closure::MAX_RECEIPT_BYTES
    );
    assert!(closure::receipt_envelope_fits(closure::MAX_RECEIPT_BYTES));
    assert!(!closure::receipt_envelope_fits(closure::MAX_RECEIPT_BYTES + 1));
}

// S39: receipt envelopes admit bounded. An oversized envelope
// refuses before JSON admission, and a writer-less FIFO refuses
// promptly instead of blocking the verifier. The FIFO call runs on
// a worker with a join timeout so a regression trips the test
// instead of hanging the suite.
#[test]
fn receipt_envelope_admits_bounded_inputs() {
    let out = scratch("receipt-bounds");
    let huge = out.join("huge-receipt.json");
    let over = usize::try_from(closure::MAX_RECEIPT_BYTES).unwrap() + 1;
    std::fs::write(&huge, vec![b'x'; over]).unwrap();
    let err = receipt::verify_receipt(&huge).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::ReceiptInvalid);
    assert!(
        err.detail().contains("exceeds"),
        "oversized envelope must refuse on the bound, not on parse: {}",
        err.detail()
    );
    let fifo = out.join("fifo-receipt.json");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_bits_truncate(0o644),
    )
    .unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(receipt::verify_receipt(&fifo));
    });
    let outcome = done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("receipt read blocked on a writer-less FIFO");
    let err = outcome.expect_err("FIFO envelope refuses");
    assert_eq!(err.kind(), OperatorErrorKind::ReceiptInvalid);
}

// S39: catalogs admit bounded. The oversized control is a sparse
// file (one byte past the 64MiB cap, ~no disk): the size pre-check
// refuses without reading. Same tripwire discipline as envelopes.
#[test]
fn catalog_admits_bounded_inputs() {
    use std::io::{Seek, SeekFrom, Write};
    let work = scratch("catalog-bounds");
    let sparse = work.join("sparse-catalog.json");
    let mut file = std::fs::File::create(&sparse).unwrap();
    file.seek(SeekFrom::Start((1 << 26) + 1)).unwrap();
    file.write_all(b"x").unwrap();
    drop(file);
    assert_eq!(
        std::fs::metadata(&sparse).unwrap().len(),
        (1 << 26) + 2,
        "sparse control exceeds the cap"
    );
    let argv = |tail: &[&str]| {
        let mut v = vec!["scopebase-conformance".to_string()];
        v.extend(tail.iter().map(|s| s.to_string()));
        v
    };
    assert_eq!(
        commands::run_argv(&argv(&[
            "describe",
            "--catalog",
            sparse.to_string_lossy().as_ref()
        ])),
        EXIT_INCOMPLETE,
        "oversized catalog refuses"
    );
    // The bound itself (not a downstream parse error) must refuse:
    // a delivery run against the sparse catalog fails on the read
    // detail before any effect.
    let mut adapter = delivery::DeliveryAdapter::new().unwrap();
    let mut oracle = delivery::DeliveryOracle::new().unwrap();
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: sparse.clone(),
        profile: "operator-delivery-v1".into(),
        fixture_root: delivery_root(),
        manifest_path: None,
        template_path: None,
        output_dir: work.join("run-sparse"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut adapter,
        oracle: &mut oracle,
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::MissingInput);
    assert!(
        err.detail().contains("exceeds"),
        "oversized catalog must refuse on the bound: {}",
        err.detail()
    );
    assert!(
        !work.join("run-sparse").exists(),
        "oversized catalog fails before effects"
    );
    let fifo = work.join("fifo-catalog.json");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_bits_truncate(0o644),
    )
    .unwrap();
    let args = argv(&["describe", "--catalog", fifo.to_string_lossy().as_ref()]);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(commands::run_argv(&args));
    });
    assert_eq!(
        done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("catalog read blocked on a writer-less FIFO"),
        EXIT_INCOMPLETE,
        "FIFO catalog refuses"
    );
}

// S39: staged run contracts admit bounded. A delivery run stages a
// small contract; the test replaces it with an oversized file (then
// a FIFO) and full verification refuses on the staged read.
#[test]
fn staged_contract_admits_bounded_inputs() {
    let root = delivery_root();
    let out = scratch("staged-bounds");
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
    let catalog = std::fs::read(root.join("catalog.json")).unwrap();
    let receipt_path = out.join("run").join("receipt.json");
    let staged = out.join("run").join("staging").join("contract.json");
    std::fs::write(&staged, vec![b'x'; (1 << 20) + 1]).unwrap();
    let err = receipt::verify_receipt_with_catalog(&receipt_path, &catalog).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::ReceiptInvalid);
    assert!(
        err.detail().contains("exceeds"),
        "oversized staged contract must refuse on the bound: {}",
        err.detail()
    );
    std::fs::remove_file(&staged).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &staged,
        rustix::fs::Mode::from_bits_truncate(0o644),
    )
    .unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(receipt::verify_receipt_with_catalog(
            &receipt_path,
            &catalog,
        ));
    });
    let outcome = done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("staged read blocked on a writer-less FIFO");
    let err = outcome.expect_err("FIFO staged contract refuses");
    assert_eq!(err.kind(), OperatorErrorKind::ReceiptInvalid);
}

// S39: template overrides admit bounded. An oversized override fails
// before any run effect (no output dir appears); a FIFO override
// refuses promptly instead of hanging the run.
#[test]
fn template_override_admits_bounded_inputs() {
    let root = delivery_root();
    let out = scratch("template-bounds");
    let huge = out.join("huge-template.json");
    std::fs::write(&huge, vec![b'x'; (1 << 20) + 1]).unwrap();
    let mut adapter = delivery::DeliveryAdapter::new().unwrap();
    let mut oracle = delivery::DeliveryOracle::new().unwrap();
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: Some(huge),
        output_dir: out.join("run-huge"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut adapter,
        oracle: &mut oracle,
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::MissingInput);
    assert!(
        err.detail().contains("exceeds"),
        "oversized template must refuse on the bound: {}",
        err.detail()
    );
    assert!(
        !out.join("run-huge").exists(),
        "oversized template fails before effects"
    );
    let fifo = out.join("fifo-template.json");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_bits_truncate(0o644),
    )
    .unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The adapter/oracle build inside the worker: the request
        // borrows them, so everything of the run lives here.
        let outcome = delivery::run_delivery(delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: Some(fifo),
            output_dir: out.join("run-fifo"),
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        });
        let _ = done_tx.send(outcome.map(|_| ()));
    });
    let outcome = done_rx
        .recv_timeout(std::time::Duration::from_secs(15))
        .expect("template read blocked on a writer-less FIFO");
    let err = outcome.expect_err("FIFO template refuses");
    assert_eq!(err.kind(), OperatorErrorKind::MissingInput);
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

// S40: step lists validate before comparison. Missing, null, scalar,
// empty, or malformed step fields fail on EITHER side — never pass
// by mutual equality — and a pass proves positive coverage. The
// kinds stay a valid pair throughout; only the steps vary.
#[test]
fn oracle_rejects_malformed_step_shapes() {
    use scopebase_testkit::{
        AssertionVerdict, CaseOutcome, CaseSpec, CatalogLimits, CheckStatus, ExpectedEvidence,
        ExpectedEvidenceValues, InvocationKey, InvocationKeyValues, Label, Observation,
        ObservationValues, RunId, RunLimits, SchemaBinding, SchemaBindingValues, TruthKind,
    };
    let catalog_bytes = std::fs::read(delivery_root().join("catalog.json")).unwrap();
    let catalog =
        scopebase_testkit::CaseCatalog::load(&catalog_bytes, CatalogLimits::default()).unwrap();
    let spec = catalog
        .case(
            &scopebase_testkit::CaseId::parse("TT07.closure").unwrap(),
            1,
        )
        .unwrap();
    let oracle = delivery::DeliveryOracle::new().unwrap();
    let limits = RunLimits::default();
    let judge = |expected_steps: Option<serde_json::Value>,
                 actual_steps: Option<serde_json::Value>| {
        let key = InvocationKey::new(
            InvocationKeyValues {
                run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                case_key: scopebase_testkit::CaseKey::new(
                    scopebase_testkit::CaseKeyValues {
                        case_id: scopebase_testkit::CaseId::parse("TT07.closure").unwrap(),
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
        let mut expected_json = serde_json::json!({
            "schema_version": 1,
            "kind": "tt07-closure-v1-expected",
        });
        if let Some(steps) = expected_steps {
            expected_json["steps"] = steps;
        }
        let mut actual_json = serde_json::json!({
            "schema_version": 1,
            "kind": "tt07-closure-v1-observation",
        });
        if let Some(steps) = actual_steps {
            actual_json["steps"] = steps;
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
                effects: scopebase_testkit::EffectBatch::empty(&limits),
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
                effects: scopebase_testkit::EffectBatch::empty(&limits),
            },
            &limits,
        )
        .unwrap();
        let verdict: AssertionVerdict =
            oracle.evaluate(spec, &expected, &CaseOutcome::Observed(observation));
        *verdict.checks()[0].status()
    };
    let positive = || serde_json::json!([{"step_id": "s1", "value": "abc"}]);
    // Control: identical positive templates pass.
    assert_eq!(judge(Some(positive()), Some(positive())), CheckStatus::Pass);
    // Missing steps on either side (or both) fail — the old
    // `None == None` equality passed the both-missing case.
    assert_eq!(judge(None, Some(positive())), CheckStatus::Fail);
    assert_eq!(judge(Some(positive()), None), CheckStatus::Fail);
    assert_eq!(judge(None, None), CheckStatus::Fail);
    // Null, scalar, and empty step fields fail, even when equal.
    for shape in [
        serde_json::Value::Null,
        serde_json::json!("s1"),
        serde_json::json!([]),
    ] {
        assert_eq!(
            judge(Some(positive()), Some(shape.clone())),
            CheckStatus::Fail,
            "actual shape must fail against a positive template: {shape}"
        );
        assert_eq!(
            judge(Some(shape.clone()), Some(shape.clone())),
            CheckStatus::Fail,
            "mutually equal malformed shapes must fail: {shape}"
        );
    }
    // Malformed records fail: non-string id, missing value, empty id,
    // extra field — against a positive template and mutually equal.
    for record in [
        serde_json::json!([{"step_id": 1, "value": "abc"}]),
        serde_json::json!([{"step_id": "s1"}]),
        serde_json::json!([{"step_id": "", "value": "abc"}]),
        serde_json::json!([{"step_id": "s1", "value": "abc", "extra": 1}]),
        serde_json::json!(["s1"]),
    ] {
        assert_eq!(
            judge(Some(positive()), Some(record.clone())),
            CheckStatus::Fail,
            "malformed actual must fail: {record}"
        );
        assert_eq!(
            judge(Some(record.clone()), Some(record.clone())),
            CheckStatus::Fail,
            "mutually equal malformed records must fail: {record}"
        );
    }
    // Differing positive contents still fail by comparison.
    assert_eq!(
        judge(
            Some(positive()),
            Some(serde_json::json!([{"step_id": "s1", "value": "abd"}]))
        ),
        CheckStatus::Fail
    );
}

// describe/plan perform no active setup and create no files.
#[test]
fn describe_and_plan_have_no_effects() {
    let before = scratch("purity");
    let catalog = std::fs::read(delivery_root().join("catalog.json")).unwrap();
    let description = describe::describe(&catalog).unwrap();
    assert!(description
        .profiles
        .iter()
        .any(|p| p.id == "operator-delivery-v1"));
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

// S38-round3: plan confines every member read to the fixture root —
// a symlinked member refuses through the PUBLIC planning route even
// when its pin matches the outside bytes. The old verification
// pass opened through the link, matched the pin, and reported the
// closure complete (admitting outside bytes into planning).
#[cfg(unix)]
#[test]
fn plan_mismatches_symlinked_member_with_matching_pin() {
    let root = copy_closure("plan-symlink");
    let outside = scratch("plan-symlink-outside");
    std::fs::write(outside.join("canary.txt"), b"canary-bytes").unwrap();
    let member = root.join("vectors").join("binding-input.txt");
    std::fs::remove_file(&member).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.join("canary.txt"), &member).unwrap();
    // Repin the member to the outside bytes (the bypass shape).
    let manifest_path = root.join("fixture-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let mut repinned = false;
    for entry in manifest
        .get_mut("files")
        .and_then(|f| f.as_array_mut())
        .unwrap()
    {
        if entry.get("path").and_then(|p| p.as_str()) == Some("vectors/binding-input.txt") {
            entry["length"] = serde_json::Value::from("12");
            entry["sha256"] =
                serde_json::Value::from(Digest256::of_bytes(b"canary-bytes").as_str());
            repinned = true;
        }
    }
    assert!(repinned, "fixture pins vectors/binding-input.txt");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let catalog = std::fs::read(delivery_root().join("catalog.json")).unwrap();
    let doc = plan::plan(
        &catalog,
        "operator-delivery-v1",
        &root,
        "no-new-target-mappings",
    )
    .unwrap();
    assert!(
        !doc.closure_complete,
        "symlinked member must not verify complete"
    );
    assert!(
        doc.mismatched.iter().any(|m| m == "vectors/binding-input.txt"),
        "symlinked member must land in mismatched: {:?}",
        doc.mismatched
    );
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
    assert_eq!(
        commands::run_argv(&["scopebase-conformance".into()]),
        EXIT_USAGE
    );
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
    assert_eq!(commands::run_argv(&argv(&["cleanup", "--run"])), EXIT_USAGE);
    // Explicit `--flag=value` still works (flag-like values allowed there).
    let missing = work.join("no-such-catalog.json");
    let code = commands::run_argv(&argv(&[
        "describe",
        &format!("--catalog={}", missing.to_string_lossy()),
    ]));
    assert_eq!(code, EXIT_INCOMPLETE);
    let leftovers: Vec<_> = std::fs::read_dir(&work).unwrap().collect();
    assert!(
        leftovers.is_empty(),
        "arity refusals must not write effects"
    );
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
    // S43: option-first ordering still takes exactly one positional:
    // `--catalog C` contributes no positional, so `R` is the one.
    assert_eq!(
        commands::run_argv(&argv(&[
            "verify-receipt",
            "--catalog",
            "c.json",
            "r.json",
            "extra"
        ])),
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

// S43: option-first ordering selects the positional, not the flag
// value. `verify-receipt --catalog C R` verifies R (exit 0); the old
// first-bare-token lookup verified C (a catalog, not a receipt) and
// ignored R.
#[test]
fn cli_verify_receipt_option_first_selects_positional() {
    let root = delivery_root();
    let out = scratch("cli-verify-order");
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
    let receipt = out.join("run").join("receipt.json");
    let catalog = root.join("catalog.json");
    let code = commands::run_argv(&[
        "scopebase-conformance".into(),
        "verify-receipt".into(),
        "--catalog".into(),
        catalog.to_string_lossy().into(),
        receipt.to_string_lossy().into(),
    ]);
    assert_eq!(code, 0, "option-first order must verify the receipt");
    // `=` form behaves the same.
    let code = commands::run_argv(&[
        "scopebase-conformance".into(),
        "verify-receipt".into(),
        format!("--catalog={}", catalog.to_string_lossy()),
        receipt.to_string_lossy().into(),
    ]);
    assert_eq!(code, 0, "equals-form option must verify the receipt");
}

// S43: a missing receipt positional is Usage before any I/O —
// `--catalog C` alone (or bare `verify-receipt`) refuses instead of
// verifying the flag value (or an absent path).
#[test]
fn cli_verify_receipt_missing_positional_is_usage() {
    let root = delivery_root();
    let catalog = root.join("catalog.json");
    assert_eq!(
        commands::run_argv(&[
            "scopebase-conformance".into(),
            "verify-receipt".into(),
            "--catalog".into(),
            catalog.to_string_lossy().into(),
        ]),
        EXIT_USAGE
    );
    assert_eq!(
        commands::run_argv(&["scopebase-conformance".into(), "verify-receipt".into()]),
        EXIT_USAGE
    );
    // A flag value that looks bare is still consumed as the value:
    // `--catalog` with no value is Usage, never a receipt read.
    assert_eq!(
        commands::run_argv(&[
            "scopebase-conformance".into(),
            "verify-receipt".into(),
            "--catalog".into(),
        ]),
        EXIT_USAGE
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
    mkexclusive(&run, 0o700);
    mkexclusive(&nested, 0o755);
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
//
// S13-round3: the residual window above is same-UID self-race
// (caller territory — no mode excludes our own threads, and Linux
// has no atomic verify-and-unlink). Cross-UID swappers are excluded
// by the deletion-time exclusivity re-check: a loosened parent
// refuses before unlinking (see `unlink_window_loosening_refuses_
// before_unlink`), so a foreign swapper can never be inside the
// window.
#[test]
fn cleanup_survives_validation_to_deletion_swaps() {
    const RUN_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let out = scratch("cleanup-swaps");
    let victim_src = out.join("victim-src");
    std::fs::create_dir_all(&victim_src).unwrap();
    std::fs::write(victim_src.join("precious.txt"), b"precious").unwrap();
    let run_src = out.join("run-src");
    mkexclusive(&run_src, 0o700);
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
        // S13: planted runs are exclusive like delivery creates.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
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
    mkexclusive(&calm, 0o700);
    std::fs::write(
        calm.join("run-manifest.json"),
        format!(r#"{{"schema":"operator-run-manifest-v1","run_id":"{RUN_ID}","profile":"p"}}"#),
    )
    .unwrap();
    let report = cleanup::cleanup_run(&calm, None).unwrap();
    assert_eq!(report.run_id, RUN_ID);
    assert!(!calm.exists());
}

// S37: a writer-less FIFO substituted for the run manifest refuses
// promptly instead of blocking the cleanup in `open`. The call runs
// on a worker with a join timeout so a regression trips the test
// instead of hanging the suite (the stranded worker holds no locks
// and dies with the test process).
#[test]
fn cleanup_refuses_fifo_manifest_without_blocking() {
    let out = scratch("cleanup-fifo-manifest");
    let run = out.join("run");
    std::fs::create_dir(&run).unwrap();
    let manifest = run.join("run-manifest.json");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &manifest,
        rustix::fs::Mode::from_bits_truncate(0o644),
    )
    .unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = cleanup::cleanup_run(&run, None);
        let _ = done_tx.send(outcome);
    });
    let outcome = done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("cleanup blocked on a writer-less FIFO manifest");
    let err = outcome.expect_err("FIFO manifest refuses");
    assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused);
    assert!(
        err.detail().contains("not a regular file"),
        "unexpected detail: {}",
        err.detail()
    );
}

// S14: a run dir under a shared (world-writable) parent refuses:
// a foreign swapper could race the verify/unlink window. The run
// is left in place and the remedy names private staging.
#[test]
fn cleanup_refuses_shared_parent() {
    let out = scratch("cleanup-shared-parent");
    let shared = out.join("shared");
    std::fs::create_dir(&shared).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    let run = shared.join("run");
    std::fs::create_dir(&run).unwrap();
    std::fs::write(
        run.join("run-manifest.json"),
        r#"{"schema":"operator-run-manifest-v1","run_id":"cccccccccccccccccccccccccccccccc","profile":"p"}"#,
    )
    .unwrap();
    let err = cleanup::cleanup_run(&run, None).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused);
    assert!(
        err.detail().contains("not exclusive"),
        "remedy unnamed: {}",
        err.detail()
    );
    assert!(
        run.join("run-manifest.json").exists(),
        "refusal removed data"
    );
}

// S13-round3: a loosened nested directory refuses before deleting
// inside it. Another UID could rename under a group/other-writable
// directory, so clearing refuses with the nested content fully
// intact and the run standing. Pre-gate code cleared and removed
// the whole tree here.
#[test]
fn cleanup_refuses_shared_nested_dir() {
    let out = scratch("cleanup-shared-nested");
    let run = out.join("run");
    mkexclusive(&run, 0o700);
    std::fs::write(
        run.join("run-manifest.json"),
        r#"{"schema":"operator-run-manifest-v1","run_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","profile":"p"}"#,
    )
    .unwrap();
    let nested = run.join("nested");
    mkexclusive(&nested, 0o755);
    std::fs::write(nested.join("precious.txt"), b"precious").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    let err = cleanup::cleanup_run(&run, None).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused);
    assert!(
        err.detail().contains("not exclusive"),
        "unexpected detail: {}",
        err.detail()
    );
    assert_eq!(
        std::fs::read(nested.join("precious.txt")).unwrap(),
        b"precious",
        "refused cleanup deleted nested content"
    );
    assert!(run.is_dir(), "refused cleanup unlinked the run");
}

// S13: the nested unlink proof fires on multi-linked entries. A
// hardlink planted inside a run dir would survive any single
// unlink, so cleanup refuses loudly instead of reporting
// "removed" over a surviving inode.
#[test]
fn cleanup_refuses_hardlinked_entry() {
    let out = scratch("cleanup-hardlink");
    let run = out.join("run");
    mkexclusive(&run, 0o700);
    std::fs::write(
        run.join("run-manifest.json"),
        r#"{"schema":"operator-run-manifest-v1","run_id":"dddddddddddddddddddddddddddddddd","profile":"p"}"#,
    )
    .unwrap();
    std::fs::write(run.join("a.txt"), b"linked").unwrap();
    std::fs::hard_link(run.join("a.txt"), run.join("b.txt")).unwrap();
    let err = cleanup::cleanup_run(&run, None).unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused);
    assert!(
        err.detail().contains("replaced during removal"),
        "unexpected detail: {}",
        err.detail()
    );
    // The refused cleanup unlinked at most the first-visited name;
    // the inode itself survives — that survival is exactly what
    // the proof reports.
    let survivor = [run.join("a.txt"), run.join("b.txt")]
        .into_iter()
        .filter_map(|p| std::fs::read(p).ok())
        .find(|bytes| bytes == b"linked");
    assert!(
        survivor.is_some(),
        "refused cleanup destroyed the inode it claimed survived"
    );
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
    for field in [
        "id",
        "revision",
        "schema_id",
        "source_sha256",
        "artifact_id",
    ] {
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

// S58 helpers: whitespace-pad a ledger template to an exact raw
// length (valid JSON, still exactly one run-id slot) and pin it in
// the manifest; add N ledger aliases (artifact + template entry).
fn s58_pad_tmpl(base: &[u8], raw_len: usize) -> Vec<u8> {
    assert_eq!(
        std::str::from_utf8(base)
            .unwrap()
            .matches("@RUN_ID@")
            .count(),
        1,
        "base template must hold exactly one run-id slot"
    );
    assert!(base.starts_with(b"{"));
    let mut out = Vec::with_capacity(raw_len);
    out.push(b'{');
    out.extend(std::iter::repeat(b' ').take(raw_len - base.len()));
    out.extend_from_slice(&base[1..]);
    assert_eq!(out.len(), raw_len);
    out
}

fn s58_pin_file(manifest: &mut serde_json::Value, root: &Path, rel: &str) {
    let bytes = std::fs::read(root.join(rel)).unwrap();
    manifest["files"].as_array_mut().unwrap().push(serde_json::json!({
        "path": rel,
        "length": bytes.len().to_string(),
        "sha256": scopebase_testkit::Digest256::of_bytes(&bytes).as_str(),
    }));
}

fn s58_add_aliases(template: &mut serde_json::Value, n: usize, tmpl_rel: &str) {
    for k in 0..n {
        let id = format!("alias-{k:04}");
        template["ledger_templates"][id.clone()] =
            serde_json::Value::String(tmpl_rel.to_string());
        template["artifacts"].as_array_mut().unwrap().push(serde_json::json!({
            "id": id,
            "revision": 1,
            "role": "fixture_ledger",
            "length": "7",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        }));
    }
    template["artifacts"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
}

// S58: every ledger template must reference a fixture-ledger
// artifact. An unreferenced alias renders unbounded staged waste;
// a mistyped id (naming an expected vector) would overwrite that
// artifact's pins with rendered bytes. Both refuse pre-effect.
#[test]
fn ledger_alias_must_reference_fixture_ledger_artifact() {
    let root = delivery_root();
    for (tag, key) in [
        ("unreferenced", "evil-alias"),
        ("mistyped", "binding-expected"),
    ] {
        let out = scratch(&format!("s58-ref-{tag}"));
        let mut template = read_json(&root.join("contract-template.json"));
        template["ledger_templates"][key] =
            serde_json::Value::String("vectors/ledger-binding.json.tmpl".into());
        let override_path = out.join("override.json");
        std::fs::write(&override_path, serde_json::to_vec(&template).unwrap()).unwrap();
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
        assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage, "{tag}: kind");
        assert!(
            err.detail().contains(key),
            "{tag}: refusal must name the alias: {}",
            err.detail()
        );
        assert!(
            !out.join("run").exists(),
            "{tag}: preflight refusal leaves no run dir"
        );
    }
}

// S58: per-file rendered budget is exact. A ledger rendering to
// exactly the vector ceiling passes preflight (the run acquires
// its directory — the whitespace padding is ledger-inert); one
// byte over refuses before allocation. The exact case may still
// fail downstream (the engine's encoded-payload caps are tighter
// than the vector ceiling); what the boundary proves is
// preflight admission, and a later failure stays cleanable via
// its creating manifest.
#[test]
fn ledger_render_exact_vector_budget() {
    let ceiling = 8 << 20;
    for (tag, raw_len, pass) in [
        ("exact", ceiling - 24, true),
        ("over", ceiling - 24 + 1, false),
    ] {
        let root = copy_closure(&format!("s58-exact-{tag}"));
        let base = std::fs::read(root.join("vectors/ledger-binding.json.tmpl")).unwrap();
        std::fs::write(
            root.join("vectors/pad-exact.json.tmpl"),
            s58_pad_tmpl(&base, raw_len),
        )
        .unwrap();
        let manifest_path = root.join("fixture-manifest.json");
        let mut manifest = read_json(&manifest_path);
        s58_pin_file(&mut manifest, &root, "vectors/pad-exact.json.tmpl");
        std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        let out = scratch(&format!("s58-exact-out-{tag}"));
        let mut template = read_json(&root.join("contract-template.json"));
        template["ledger_templates"]["binding-ledger"] =
            serde_json::Value::String("vectors/pad-exact.json.tmpl".into());
        let override_path = out.join("override.json");
        std::fs::write(&override_path, serde_json::to_vec(&template).unwrap()).unwrap();
        let outcome = delivery::run_delivery(delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: Some(override_path),
            output_dir: out.join("run"),
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        });
        if pass {
            // Preflight admitted: the run acquired its directory.
            // A downstream engine refusal is not a budget refusal.
            if let Err(err) = &outcome {
                assert!(
                    !err.detail().contains("budget"),
                    "{tag}: exact budget must not refuse: {}",
                    err.detail()
                );
            }
            let run = out.join("run");
            assert!(run.exists(), "{tag}: exact budget acquires a run dir");
            let report = cleanup::cleanup_run(&run, None).expect("later failure stays cleanable");
            assert_eq!(report.profile, "operator-delivery-v1");
            assert!(!run.exists(), "{tag}: cleanup removes the run");
        } else {
            let err = outcome.unwrap_err();
            assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage, "{tag}: kind");
            assert!(
                err.detail().contains("vector budget"),
                "{tag}: must cite the vector budget: {}",
                err.detail()
            );
            assert!(
                !out.join("run").exists(),
                "{tag}: budget refusal leaves no run dir"
            );
        }
    }
}

// S58: ledger cardinality admits before rendering. Over four
// thousand aliases refuse on the artifact budget without reading
// a single template.
#[test]
fn ledger_cardinality_admits_before_rendering() {
    let root = delivery_root();
    let out = scratch("s58-cardinality");
    let mut template = read_json(&root.join("contract-template.json"));
    s58_add_aliases(&mut template, 4200, "vectors/ledger-binding.json.tmpl");
    let override_path = out.join("override.json");
    std::fs::write(&override_path, serde_json::to_vec(&template).unwrap()).unwrap();
    let override_len = std::fs::metadata(&override_path).unwrap().len();
    assert!(
        override_len < (1 << 20),
        "override itself stays admittable: {override_len}"
    );
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
    assert!(
        err.detail().contains("artifact budget"),
        "must cite the artifact budget: {}",
        err.detail()
    );
    assert!(
        !out.join("run").exists(),
        "budget refusal leaves no run dir"
    );
}

// S58: alias amplification refuses before allocation. Thirty maxed
// (8 MiB) aliases nominally retain ~500 MB from a ~5 KB override;
// the preflight refuses once the retained peak crosses the budget
// instead of rendering and staging all of it.
#[test]
fn ledger_alias_amplification_refuses_before_allocation() {
    let root = copy_closure("s58-amplify");
    let base = std::fs::read(root.join("vectors/ledger-binding.json.tmpl")).unwrap();
    std::fs::write(
        root.join("vectors/pad-8m.json.tmpl"),
        s58_pad_tmpl(&base, (8 << 20) - 24),
    )
    .unwrap();
    let manifest_path = root.join("fixture-manifest.json");
    let mut manifest = read_json(&manifest_path);
    s58_pin_file(&mut manifest, &root, "vectors/pad-8m.json.tmpl");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let out = scratch("s58-amplify-out");
    let mut template = read_json(&root.join("contract-template.json"));
    s58_add_aliases(&mut template, 30, "vectors/pad-8m.json.tmpl");
    let override_path = out.join("override.json");
    std::fs::write(&override_path, serde_json::to_vec(&template).unwrap()).unwrap();
    let override_len = std::fs::metadata(&override_path).unwrap().len();
    assert!(
        override_len < (1 << 20),
        "override itself stays small: {override_len}"
    );
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
    // S58-round4: the eighth maxed alias still refuses at the
    // retained peak: aliases sort before the base ledgers, so its
    // remaining allowance is exactly 8 MiB and the pinned member
    // fits it — the peak (not the read) is over budget. The
    // pre-read allowance refusal is covered by the rawcap test,
    // whose member exceeds its remainder.
    assert!(
        err.detail().contains("retained budget"),
        "must cite the retained budget: {}",
        err.detail()
    );
    assert!(
        !out.join("run").exists(),
        "budget refusal leaves no run dir"
    );
}

// S58: add N fully wired alias cases (catalog case + profile
// requirement + rule + layout row + ledger artifact + template
// entry), each ledger rendering the shared padded template. The
// aliases echo the binding vectors, so every case is independently
// runnable; the ledgers multiply retained bytes.
fn s58_add_alias_cases(
    catalog: &mut serde_json::Value,
    template: &mut serde_json::Value,
    n: usize,
    tmpl_rel: &str,
) {
    let binding_case = catalog["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "TT07.binding")
        .unwrap()
        .clone();
    let binding_rule = template["case_rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["case_key"]["case_id"] == "TT07.binding")
        .unwrap()
        .clone();
    for k in 0..n {
        let case_id = format!("TT07.alias-{k:02}");
        let ledger_id = format!("alias-ledger-{k:02}");
        let mut case = binding_case.clone();
        case["id"] = serde_json::Value::String(case_id.clone());
        catalog["cases"].as_array_mut().unwrap().push(case);
        catalog["profiles"][0]["required_cases"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "case_id": case_id,
                "case_version": 1,
                "when_extensions": [],
            }));
        let mut rule = binding_rule.clone();
        rule["case_key"]["case_id"] = serde_json::Value::String(case_id.clone());
        // Contract admission requires distinct operation ids per
        // rule (closure/binding already take 1–2).
        rule["operation_ids"] = serde_json::Value::Array(vec![serde_json::Value::String(
            format!("{}", 3 + k),
        )]);
        template["case_rules"].as_array_mut().unwrap().push(rule);
        template["vector_layout"][case_id] = serde_json::json!({
            "inputs": {"binding-input": "binding-input"},
            "expected": "binding-expected",
            "ledger": ledger_id,
        });
        template["artifacts"].as_array_mut().unwrap().push(serde_json::json!({
            "id": ledger_id,
            "revision": 1,
            "role": "fixture_ledger",
            "length": "7",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        }));
        template["ledger_templates"][ledger_id] =
            serde_json::Value::String(tmpl_rel.to_string());
    }
    template["artifacts"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
}

// S58: aggregate budget margins, ±1 maxed file around the
// retained boundary. Seven ~8 MB wired alias ledgers (~59 MB
// retained) pass preflight — the run acquires its directory;
// eight refuse. The under case may still fail downstream of
// preflight (engine encoded caps); what the margin proves is
// admission, and a later failure stays cleanable.
#[test]
fn ledger_aggregate_budget_margins() {
    // Rendered 8 MiB − 1 KiB per alias: seven peak ~8 KB under the
    // retained budget, eight exceed it by megabytes — both margins
    // robust, neither borderline.
    const RAW: usize = (8 << 20) - 24 - 1024;
    for (tag, n, pass) in [("under", 7, true), ("over", 8, false)] {
        let root = copy_closure(&format!("s58-margin-{tag}"));
        let base = std::fs::read(root.join("vectors/ledger-binding.json.tmpl")).unwrap();
        std::fs::write(
            root.join("vectors/pad-margin.json.tmpl"),
            s58_pad_tmpl(&base, RAW),
        )
        .unwrap();
        let catalog_path = root.join("catalog.json");
        let mut catalog = read_json(&catalog_path);
        let mut template = read_json(&root.join("contract-template.json"));
        s58_add_alias_cases(
            &mut catalog,
            &mut template,
            n,
            "vectors/pad-margin.json.tmpl",
        );
        std::fs::write(&catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();
        let manifest_path = root.join("fixture-manifest.json");
        let mut manifest = read_json(&manifest_path);
        s58_pin_file(&mut manifest, &root, "vectors/pad-margin.json.tmpl");
        for file in manifest["files"].as_array_mut().unwrap() {
            if file["path"].as_str() == Some("catalog.json") {
                let bytes = std::fs::read(&catalog_path).unwrap();
                file["length"] = serde_json::Value::String(bytes.len().to_string());
                file["sha256"] = serde_json::Value::String(
                    scopebase_testkit::Digest256::of_bytes(&bytes).as_str(),
                );
            }
        }
        std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        let out = scratch(&format!("s58-margin-out-{tag}"));
        let override_path = out.join("override.json");
        std::fs::write(&override_path, serde_json::to_vec(&template).unwrap()).unwrap();
        let outcome = delivery::run_delivery(delivery::RunRequest {
            catalog_path: catalog_path.clone(),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: Some(override_path),
            output_dir: out.join("run"),
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        });
        if pass {
            if let Err(err) = &outcome {
                assert!(
                    !err.detail().contains("budget"),
                    "{tag}: under-budget aggregate must not refuse: {}",
                    err.detail()
                );
            }
            let run = out.join("run");
            assert!(
                run.exists(),
                "{tag}: under-budget aggregate acquires a run dir; outcome: {outcome:?}"
            );
            let report = cleanup::cleanup_run(&run, None).expect("later failure stays cleanable");
            assert_eq!(report.profile, "operator-delivery-v1");
            assert!(!run.exists(), "{tag}: cleanup removes the run");
        } else {
            let err = outcome.unwrap_err();
            assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage, "{tag}: kind");
            assert!(
                err.detail().contains("retained budget"),
                "{tag}: must cite the retained budget: {}",
                err.detail()
            );
            assert!(
                !out.join("run").exists(),
                "{tag}: budget refusal leaves no run dir"
            );
        }
    }
}

// S58-round4: build a template with exactly `slots` run-id slots at
// exactly `raw_len` bytes (4x rendering amplification: each 8-byte
// slot grows by 24 when the 32-char run id lands).
fn s58_multi_tmpl(slots: usize, raw_len: usize) -> Vec<u8> {
    let body = format!("\"s\":\"{}\"", "@RUN_ID@".repeat(slots));
    assert!(
        1 + body.len() + 1 <= raw_len,
        "slots do not fit the raw length"
    );
    let mut out = Vec::with_capacity(raw_len);
    out.push(b'{');
    out.extend(std::iter::repeat(b' ').take(raw_len - 1 - body.len() - 1));
    out.extend_from_slice(body.as_bytes());
    out.push(b'}');
    assert_eq!(out.len(), raw_len);
    out
}

fn s58_add_ledger_alias(template: &mut serde_json::Value, id: &str, tmpl_rel: &str) {
    template["ledger_templates"][id] = serde_json::Value::String(tmpl_rel.to_string());
    template["artifacts"].as_array_mut().unwrap().push(serde_json::json!({
        "id": id,
        "revision": 1,
        "role": "fixture_ledger",
        "length": "7",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    }));
}

// S58-round4: the raw member read admits against the per-file vector
// budget and the REMAINING aggregate allowance before allocating.
// Seven 8 MiB-rendered predecessors plus one 4 MiB predecessor
// retain ~60 MiB; a final 5 MiB member — under the 8 MiB vector
// budget but over the ~4 MiB remainder — refuses at read admission
// with no allocation and no run dir. Pre-fix it materialized in
// full beside the retained 60 MiB and refused only at the peak
// check ("would exceed retained budget"); the allowance citation is
// the boundary signal. (Templates render sorted by alias id, so the
// final alias sorts last; base closure/binding ledgers render first
// and their kilobytes sit inside every margin below.)
#[test]
fn ledger_raw_member_admits_before_allocation() {
    const VECTOR: usize = 8 << 20;
    // Predecessors render exactly 8 MiB from ~3.4 MiB raw (200k
    // slots × 24 growth); the eighth renders exactly 4 MiB.
    const PRED_SLOTS: usize = 200_000;
    const PRED_RAW: usize = VECTOR - 24 * PRED_SLOTS;
    const PRED8_SLOTS: usize = 100_000;
    const PRED8_RAW: usize = (4 << 20) - 24 * PRED8_SLOTS;
    const FINAL_RAW: usize = 5 << 20;
    assert_eq!(PRED_RAW + 24 * PRED_SLOTS, VECTOR);
    assert_eq!(PRED8_RAW + 24 * PRED8_SLOTS, 4 << 20);
    let root = copy_closure("s58-rawcap");
    let manifest_path = root.join("fixture-manifest.json");
    let mut manifest = read_json(&manifest_path);
    for k in 0..7 {
        let rel = format!("vectors/pred-{k:02}.json.tmpl");
        std::fs::write(root.join(&rel), s58_multi_tmpl(PRED_SLOTS, PRED_RAW)).unwrap();
        s58_pin_file(&mut manifest, &root, &rel);
    }
    std::fs::write(
        root.join("vectors/pred-07.json.tmpl"),
        s58_multi_tmpl(PRED8_SLOTS, PRED8_RAW),
    )
    .unwrap();
    s58_pin_file(&mut manifest, &root, "vectors/pred-07.json.tmpl");
    std::fs::write(
        root.join("vectors/zzz-final.json.tmpl"),
        s58_multi_tmpl(1, FINAL_RAW),
    )
    .unwrap();
    s58_pin_file(&mut manifest, &root, "vectors/zzz-final.json.tmpl");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let out = scratch("s58-rawcap-out");
    let mut template = read_json(&root.join("contract-template.json"));
    for k in 0..8 {
        let id = format!("pred-{k:02}");
        s58_add_ledger_alias(&mut template, &id, &format!("vectors/{id}.json.tmpl"));
    }
    s58_add_ledger_alias(&mut template, "zzz-final", "vectors/zzz-final.json.tmpl");
    template["artifacts"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let override_path = out.join("override.json");
    std::fs::write(&override_path, serde_json::to_vec(&template).unwrap()).unwrap();
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
    assert!(
        err.detail().contains("byte allowance")
            && err.detail().contains("zzz-final.json.tmpl"),
        "must cite the read allowance for the final member: {}",
        err.detail()
    );
    assert!(
        !out.join("run").exists(),
        "read-admission refusal leaves no run dir"
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
    envelope["subject"]["package_name"] = serde_json::Value::String("conformance-evil-fork".into());
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
            observation_schema: binding("tt07-observation"),
            fixture_schema: binding("tt07-fixture"),
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

/// S70-round4: `--fixture-root . --fixture-manifest
/// fixture-manifest.json` admits the same manifest the default
/// spelling does. Runs the real binary with its cwd inside a
/// fixture copy (no in-process chdir): pre-fix the raw
/// `strip_prefix` rejected the equivalent spelling.
#[test]
fn cli_dot_root_with_bare_manifest_matches_default() {
    let root = copy_closure("s70-cli");
    let out = scratch("s70-cli-out");
    let run = out.join("run");
    let child = std::process::Command::new(operator_bin())
        .current_dir(&root)
        .arg("run")
        .arg("--catalog")
        .arg(root.join("catalog.json"))
        .arg("--profile")
        .arg("operator-delivery-v1")
        .arg("--fixture-root")
        .arg(".")
        .arg("--fixture-manifest")
        .arg("fixture-manifest.json")
        .arg("--output")
        .arg(&run)
        .output()
        .expect("spawn operator");
    let stderr = String::from_utf8_lossy(&child.stderr).into_owned();
    assert_eq!(
        child.status.code(),
        Some(0),
        "dot-root run must qualify: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&child.stdout).into_owned();
    assert!(
        stdout.contains("\"qualification\":\"qualified\"")
            || stdout.contains("\"qualification\": \"qualified\""),
        "dot-root run must report qualified: {stdout}"
    );
    assert!(run.exists(), "dot-root run must acquire its run dir");
    let report = cleanup::cleanup_run(&run, None).expect("run stays cleanable");
    assert_eq!(report.profile, "operator-delivery-v1");
    assert!(!run.exists(), "cleanup removes the run");
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

// S42: a pure input failure (bundle assembly from the template
// layout) refuses BEFORE the output dir is acquired: no run dir
// at all, so there is nothing to strand and no cleanup to run.
#[test]
fn preflight_failure_leaves_no_run_dir() {
    let root = copy_closure("s42-preflight");
    let mut template = read_json(&root.join("contract-template.json"));
    // Drop one layout case: bundle_manifest() can no longer assemble.
    template["vector_layout"]
        .as_object_mut()
        .unwrap()
        .remove("TT07.binding");
    let broken = root.join("contract-template-broken.json");
    std::fs::write(&broken, serde_json::to_vec(&template).unwrap()).unwrap();
    let out = scratch("s42-preflight-out");
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: delivery_root().join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: Some(broken),
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage);
    assert!(
        !out.join("run").exists(),
        "pre-effect refusal must not acquire a run dir"
    );
}

// S42: a run stranded mid-flight (creating manifest + partial
// staging, as after a kill between acquisition and seal) is
// cleanable: cleanup accepts the creating shape and removes it.
#[test]
fn creating_run_is_cleanable() {
    let out = scratch("s42-creating");
    let run = out.join("run");
    let staging = run.join("staging");
    // S13: cleanup requires every traversed dir exclusive — pin both
    // levels umask-proof (delivery creates them 0700).
    mkexclusive(&run, 0o700);
    mkexclusive(&staging, 0o700);
    let creating = serde_json::json!({
        "schema": "operator-run-manifest-v1",
        "run_id": "0123456789abcdef0123456789abcdef",
        "profile": "operator-delivery-v1",
        "operator": "scopebase-conformance test",
        "mapping_policy": "no-new-target-mappings",
        "state": "creating",
    });
    std::fs::write(
        run.join("run-manifest.json"),
        serde_json::to_vec_pretty(&creating).unwrap(),
    )
    .unwrap();
    std::fs::write(staging.join("closure-ledger.json"), b"partial").unwrap();
    std::fs::write(staging.join("contract.json"), b"partial").unwrap();
    let report = cleanup::cleanup_run(&run, None).unwrap();
    assert!(!run.exists(), "creating run must be removable");
    assert_eq!(report.run_id, "0123456789abcdef0123456789abcdef");
    assert_eq!(report.profile, "operator-delivery-v1");
}

// S42-round3: each pre-manifest failure window rolls back to
// "nothing happened" — the original error returns, no residue
// remains, and a retry at the same path succeeds. Every injection
// is root-proof (symlink/EEXIST/rename-onto-dir), never raced.
#[test]
fn pre_manifest_failures_leave_no_residue_and_retry() {
    use delivery::DeliveryHookPhase;
    let root = delivery_root();
    for tag in ["acquire-open", "staging-mkdir", "staging-open", "manifest-write"] {
        let out = scratch(&format!("s42-{tag}"));
        let run = out.join("run");
        let decoy = out.join("decoy-target");
        std::fs::write(&decoy, b"decoy").unwrap();
        let hook = |phase: DeliveryHookPhase| {
            let fire = |want: DeliveryHookPhase| phase == want;
            match tag {
                // Fresh dir swapped for a symlink: acquire openat
                // (NOFOLLOW) fails ELOOP as any uid.
                "acquire-open" if fire(DeliveryHookPhase::AfterOutputMkdir) => {
                    std::fs::remove_dir(&run).unwrap();
                    std::os::unix::fs::symlink(&decoy, &run).unwrap();
                }
                // Staging pre-created as a file: staging mkdirat
                // fails EEXIST as any uid.
                "staging-mkdir" if fire(DeliveryHookPhase::AfterAcquire) => {
                    std::fs::write(run.join("staging"), b"blocker").unwrap();
                }
                // Fresh staging swapped for a symlink: staging
                // openat (NOFOLLOW) fails ELOOP as any uid.
                "staging-open" if fire(DeliveryHookPhase::AfterStagingMkdir) => {
                    std::fs::remove_dir(run.join("staging")).unwrap();
                    std::os::unix::fs::symlink(&decoy, run.join("staging")).unwrap();
                }
                // Manifest name planted as a directory: the sealed
                // rename-onto-dir fails as any uid.
                "manifest-write" if fire(DeliveryHookPhase::BeforeManifest) => {
                    std::fs::create_dir(run.join("run-manifest.json")).unwrap();
                }
                _ => {}
            }
        };
        let err = delivery::run_delivery_with_hook(
            delivery::RunRequest {
                catalog_path: root.join("catalog.json"),
                profile: "operator-delivery-v1".into(),
                fixture_root: root.clone(),
                manifest_path: None,
                template_path: None,
                output_dir: run.clone(),
                mapping_policy: "no-new-target-mappings".into(),
                adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
                oracle: &delivery::DeliveryOracle::new().unwrap(),
            },
            Some(&hook),
        )
        .unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::Engine, "{tag}: kind");
        let stage = match tag {
            "acquire-open" => "cannot open fresh output dir",
            "staging-mkdir" => "cannot create run staging",
            "staging-open" => "cannot open run staging",
            _ => "cannot write creating manifest",
        };
        assert!(
            err.detail().contains(stage),
            "{tag}: wrong window failed: {}",
            err.detail()
        );
        // Rollback reclaimed OUR names only: the decoy target is
        // untouched, the run name is gone.
        assert!(decoy.exists(), "{tag}: rollback followed a link");
        assert!(!run.exists(), "{tag}: pre-manifest failure stranded residue");
        // Retry at the same path succeeds — the name is free and no
        // half-state lingers.
        let outcome = delivery::run_delivery(delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: None,
            output_dir: run.clone(),
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        })
        .unwrap();
        assert_eq!(outcome.qualification, Qualification::Qualified, "{tag}: retry");
    }
}

// S42-round3: a rollback that cannot remove reports unresolved
// custody naming the run path — never a silent strand, never a
// foreign deletion. Case A blocks removal with permissions
// (non-root only: root bypasses the mode bits); case B plants a
// foreign entry (any uid) and proves nothing is removed.
#[test]
fn failed_rollback_reports_unresolved_custody() {
    use delivery::DeliveryHookPhase;
    use std::os::unix::fs::PermissionsExt;
    let root = delivery_root();
    // Case A: staging mkdir fails (acquired dir read-only) AND the
    // rollback unlink fails (parent read-only).
    if !rustix::process::geteuid().is_root() {
        let out = scratch("s42-custody-perms");
        let run = out.join("run");
        let hook = |phase: DeliveryHookPhase| {
            if phase != DeliveryHookPhase::AfterAcquire {
                return;
            }
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o500)).unwrap();
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o500)).unwrap();
        };
        let err = delivery::run_delivery_with_hook(
            delivery::RunRequest {
                catalog_path: root.join("catalog.json"),
                profile: "operator-delivery-v1".into(),
                fixture_root: root.clone(),
                manifest_path: None,
                template_path: None,
                output_dir: run.clone(),
                mapping_policy: "no-new-target-mappings".into(),
                adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
                oracle: &delivery::DeliveryOracle::new().unwrap(),
            },
            Some(&hook),
        )
        .unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::UnresolvedCustody);
        assert!(
            err.detail().contains("without cleanup custody"),
            "custody must say so: {}",
            err.detail()
        );
        assert!(
            err.detail().contains(&run.display().to_string()),
            "custody must name the path: {}",
            err.detail()
        );
        // Neither retry (name exists) nor cleanup (no manifest) owns
        // it — the documented premise of the custody report.
        let retry = delivery::run_delivery(delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: None,
            output_dir: run.clone(),
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        })
        .unwrap_err();
        assert_eq!(retry.kind(), OperatorErrorKind::Usage);
        let scrub = cleanup::cleanup_run(&run, None).unwrap_err();
        assert_eq!(scrub.kind(), OperatorErrorKind::CleanupRefused);
        // Restore and hand-remove the stranded run.
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&run).unwrap();
    } else {
        eprintln!("skip s42-custody-perms: needs a non-root uid");
    }
    // Case B: a foreign entry refuses rollback before ANY removal.
    let out = scratch("s42-custody-foreign");
    let run = out.join("run");
    let hook = |phase: DeliveryHookPhase| {
        if phase != DeliveryHookPhase::BeforeManifest {
            return;
        }
        std::fs::create_dir(run.join("run-manifest.json")).unwrap();
        std::fs::write(run.join("evil"), b"foreign").unwrap();
    };
    let err = delivery::run_delivery_with_hook(
        delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: None,
            output_dir: run.clone(),
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        },
        Some(&hook),
    )
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::UnresolvedCustody);
    assert!(
        err.detail().contains("foreign entry"),
        "custody must name the cause: {}",
        err.detail()
    );
    // Inventory-first: nothing was removed, known entries included.
    assert!(run.join("evil").exists(), "foreign entry must survive");
    assert!(
        run.join("staging").exists(),
        "rollback must not partially remove"
    );
    assert!(run.join("run-manifest.json").exists());
    std::fs::remove_dir_all(&run).unwrap();
}

// S56: producer and cleanup agree on the parent policy. A run
// directly under a shared parent (sticky 1777 like /tmp, or plain
// group-writable) refuses BEFORE creating anything; an
// auto-created parent is secured 0700 so the run proceeds; and a
// run under a private parent round-trips through cleanup.
#[test]
fn run_and_cleanup_agree_on_parent_policy() {
    let root = delivery_root();
    let out = scratch("s56-parent");
    for (tag, mode) in [("sticky", 0o1777), ("group-writable", 0o775)] {
        let shared = out.join(tag);
        mkexclusive(&shared, mode);
        let run = shared.join("run");
        let err = delivery::run_delivery(delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: None,
            output_dir: run.clone(),
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        })
        .unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::Usage, "{tag}: kind");
        assert!(
            err.detail().contains("not exclusive"),
            "{tag}: must cite exclusivity: {}",
            err.detail()
        );
        assert!(!run.exists(), "{tag}: refused run must create nothing");
    }
    // Auto-created parents are secured, not refused.
    let nested = out.join("deep").join("nest").join("run");
    let outcome = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: "operator-delivery-v1".into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: nested.clone(),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap();
    assert_eq!(outcome.qualification, Qualification::Qualified);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(nested.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "created parent must be exclusive");
    }
    // Round trip: the delivered cleanup route removes a successful run.
    let report = cleanup::cleanup_run(&nested, None).unwrap();
    assert!(!nested.exists(), "cleanup must remove the run");
    assert!(!report.run_id.is_empty());
    assert_eq!(report.profile, "operator-delivery-v1");
}

// S69-round4: a symlink planted in the check-to-create window (fired
// via BeforeParentMkdir) must NOT receive the new-parent chmod: the
// planted name reports EEXIST (not newly owned), refuses at the
// NOFOLLOW parent open, and the link target's mode and marker
// survive untouched. Pre-fix the path chmod followed the plant and
// flipped the victim to 0700.
#[test]
fn planted_parent_symlink_gets_no_chmod() {
    use delivery::DeliveryHookPhase;
    use std::os::unix::fs::PermissionsExt;
    let root = delivery_root();
    let out = scratch("s69-plant");
    let victim = out.join("victim");
    mkexclusive(&victim, 0o755);
    let marker = victim.join("marker.txt");
    std::fs::write(&marker, b"victim intact").unwrap();
    let parent = out.join("parent");
    let run = parent.join("run");
    let hook = |phase: DeliveryHookPhase| {
        if phase != DeliveryHookPhase::BeforeParentMkdir {
            return;
        }
        std::os::unix::fs::symlink(&victim, &parent).unwrap();
    };
    let err = delivery::run_delivery_with_hook(
        delivery::RunRequest {
            catalog_path: root.join("catalog.json"),
            profile: "operator-delivery-v1".into(),
            fixture_root: root.clone(),
            manifest_path: None,
            template_path: None,
            output_dir: run.clone(),
            mapping_policy: "no-new-target-mappings".into(),
            adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
            oracle: &delivery::DeliveryOracle::new().unwrap(),
        },
        Some(&hook),
    )
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::MissingInput);
    assert!(
        err.detail().contains("cannot open output parent"),
        "planted symlink parent must refuse at open: {}",
        err.detail()
    );
    assert!(!run.exists(), "refused run must create nothing");
    let mode = std::fs::metadata(&victim)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755, "victim mode must survive the plant window");
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"victim intact",
        "victim content must survive the plant window"
    );
}

// S61: DeliveryAdapter preflights the ENTIRE script before its
// first input access (TT02 dialect amendment, like the S34 capture
// adapters). The script below has a valid first step and an
// unsupported second step under the binding dialect, whose first
// input is non-UTF8: the old per-step loop read step 1 first —
// Unavailable with a missing slot, InvalidOutput with a populated
// one — while the preflight rejects pre-read UnsupportedSchema
// with no step and no progress in both cases.
#[test]
fn delivery_adapter_preflights_whole_script_before_reads() {
    fn script(second_op: &str) -> Vec<u8> {
        format!(
            "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"tt07-binding-v1\",\
             \"steps\":[{{\"step_id\":\"first\",\"operation\":\"subject-coords\",\
             \"inputs\":[\"slot-a\"],\"parameters\":[]}},\
             {{\"step_id\":\"second\",\"operation\":\"{second_op}\",\
             \"inputs\":[\"slot-a\"],\"parameters\":[]}}]}}"
        )
        .into_bytes()
    }
    fn invocation(limits: &RunLimits, script_json: &[u8]) -> CaseInvocation {
        let script = OperationScript::load(script_json, limits).expect("test script loads");
        let key = InvocationKey::new(
            InvocationKeyValues {
                run_id: RunId::parse("0123456789abcdef0123456789abcdef").expect("run id"),
                case_key: CaseKey::new(
                    CaseKeyValues {
                        case_id: CaseId::parse("TT07.delivery-contract").expect("case id"),
                        case_version: 1,
                        cell_id: "contract".to_string(),
                    },
                    limits,
                )
                .expect("case key"),
                attempt: 1,
                operation_id: 1,
            },
            limits,
        )
        .expect("invocation key");
        CaseInvocation::new(
            CaseInvocationValues {
                key,
                observation_schema: SchemaBinding::new(
                    SchemaBindingValues {
                        id: Label::parse("tt07-binding-v1-observation").expect("schema"),
                        revision: 1,
                    },
                    limits,
                )
                .expect("observation schema"),
                fixture_schema: SchemaBinding::new(
                    SchemaBindingValues {
                        id: Label::parse("tt07-fixture-v1").expect("schema"),
                        revision: 1,
                    },
                    limits,
                )
                .expect("fixture schema"),
                script,
                limits: limits.clone(),
            },
            limits,
        )
        .expect("invocation")
    }
    let limits = RunLimits::default();
    let inv = invocation(&limits, &script("no-such-op"));
    // Non-UTF8 first input: the old loop consumed it (InvalidOutput)
    // before reaching the unsupported second step.
    let slot_a = Label::parse("slot-a").expect("slot");
    let present = FixtureInput::new(slot_a, b"\xff\xfe");
    let fix_present =
        FixtureAccess::new(std::slice::from_ref(&present), &[], EffectBatch::empty(&limits), &limits)
            .expect("populated fixture");
    let fix_missing =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    for (tag, fix) in [("missing-slot", &fix_missing), ("populated-slot", &fix_present)] {
        let err = delivery::DeliveryAdapter::new()
            .unwrap()
            .execute(&inv, fix)
            .expect_err(&format!("{tag}: second-step dialect rejects pre-read"));
        assert_eq!(
            *err.category(),
            CaseErrorCategory::UnsupportedSchema,
            "{tag}: category"
        );
        assert_eq!(err.stage().as_str(), "adapter-schema", "{tag}: stage");
        assert!(err.step_id().is_none(), "{tag}: dialect names no step");
        assert!(err.completed_steps().is_empty(), "{tag}: no progress");
    }
    // Control: two valid steps still execute.
    let inv_ok = invocation(&limits, &script("subject-coords"));
    let slot_b = Label::parse("slot-a").expect("slot");
    let ok_input = FixtureInput::new(slot_b, b"coords-ok");
    let fix_ok = FixtureAccess::new(
        std::slice::from_ref(&ok_input),
        &[],
        EffectBatch::empty(&limits),
        &limits,
    )
    .expect("control fixture");
    delivery::DeliveryAdapter::new()
        .unwrap()
        .execute(&inv_ok, &fix_ok)
        .expect("valid two-step script executes");
}

// S42: success overwrites the creating manifest with the sealed
// one (receipt bound, no creating state left behind).
#[test]
fn successful_run_seals_manifest() {
    let root = delivery_root();
    let out = scratch("s42-sealed");
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
    let manifest = read_json(&out.join("run").join("run-manifest.json"));
    assert_eq!(manifest["receipt"], "receipt.json");
    assert!(
        manifest.get("state").is_none(),
        "sealed manifest must not carry creating state"
    );
}

// S36: a writer-less FIFO substituted at a staged name — per write
// and after all staging — is invisible: the bundle read consumes
// the descriptors retained at creation, never a reopened name.
// (The old reopen-by-name blocked at open; the worker below turns
// that hang into a tripwire failure instead of stalling the suite.)
#[test]
fn staged_fifo_substitution_is_invisible() {
    let root = copy_closure("s36-staged");
    let out = scratch("s36-staged-out");
    let run_dir = out.join("run");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let hook_dir = run_dir.clone();
        let plant = |dir: &std::path::Path| {
            for ledger in ["closure-ledger.json", "binding-ledger.json"] {
                let staged = dir.join("staging").join(ledger);
                // Only names already staged as regular files: the
                // not-yet-written ledger must keep its name free for
                // the exclusive create, and an earlier FIFO planting
                // stays planted.
                let is_regular = std::fs::symlink_metadata(&staged)
                    .map(|m| m.file_type().is_file())
                    .unwrap_or(false);
                if !is_regular {
                    continue;
                }
                std::fs::remove_file(&staged).unwrap();
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &staged,
                    rustix::fs::Mode::from_bits_truncate(0o600),
                )
                .unwrap();
            }
        };
        let hook = |_phase: delivery::DeliveryHookPhase| plant(&hook_dir);
        let outcome = delivery::run_delivery_with_hook(
            delivery::RunRequest {
                catalog_path: delivery_root().join("catalog.json"),
                profile: "operator-delivery-v1".into(),
                fixture_root: root.clone(),
                manifest_path: None,
                template_path: None,
                output_dir: run_dir.clone(),
                mapping_policy: "no-new-target-mappings".into(),
                adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
                oracle: &delivery::DeliveryOracle::new().unwrap(),
            },
            Some(&hook),
        );
        let _ = done_tx.send(outcome.map(|o| o.qualification));
    });
    let qualification = done_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("run blocked on a substituted staged FIFO")
        .unwrap();
    assert_eq!(qualification, Qualification::Qualified);
}

// S36: a writer-less FIFO substituted at a closure vector after
// verification refuses on the same-descriptor type check instead
// of blocking at open. (The old blocking File::open hung; the
// worker turns that hang into a tripwire failure.)
#[test]
fn closure_fifo_substitution_fails_fast() {
    let root = copy_closure("s36-closure");
    let out = scratch("s36-closure-out");
    let victim = root.join("vectors").join("closure-input.txt");
    assert!(victim.exists());
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let hook = |phase: delivery::DeliveryHookPhase| {
            if phase != delivery::DeliveryHookPhase::AfterStaging {
                return;
            }
            std::fs::remove_file(&victim).unwrap();
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                &victim,
                rustix::fs::Mode::from_bits_truncate(0o600),
            )
            .unwrap();
        };
        let outcome = delivery::run_delivery_with_hook(
            delivery::RunRequest {
                catalog_path: delivery_root().join("catalog.json"),
                profile: "operator-delivery-v1".into(),
                fixture_root: root.clone(),
                manifest_path: None,
                template_path: None,
                output_dir: out.join("run"),
                mapping_policy: "no-new-target-mappings".into(),
                adapter: &mut delivery::DeliveryAdapter::new().unwrap(),
                oracle: &delivery::DeliveryOracle::new().unwrap(),
            },
            Some(&hook),
        );
        let _ = done_tx.send(outcome.map(|o| o.qualification));
    });
    let outcome = done_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("run blocked on a substituted closure FIFO");
    let err = outcome.expect_err("substituted vector must fail");
    assert_eq!(err.kind(), OperatorErrorKind::Engine);
    assert!(
        err.detail().contains("not a regular file"),
        "substitution must refuse on the type check: {}",
        err.detail()
    );
}
