// SPDX-License-Identifier: Apache-2.0
//! TT07 downstream consumer tests: packaged crates usable under an
//! independent manifest with an independently built adapter.
//!
//! NEW (TT07): no donor lines copied.
use conformance_client::{fixture_root, RenamedAdapter, CONSUMER_ADAPTER, CONSUMER_PACKAGE};
use scopebase_conformance::{delivery, receipt, OperatorErrorKind};
use scopebase_testkit::{ConformanceAdapter, Qualification};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tt07-consumer-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// The packaged operator runs the delivery profile from this manifest.
#[test]
fn downstream_reference_run_is_qualified() {
    let root = fixture_root();
    let out = scratch("reference");
    let outcome = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: delivery::DELIVERY_PROFILE.into(),
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
    let report = receipt::verify_receipt(&out.join("run").join("receipt.json")).unwrap();
    assert_eq!(report.qualification, Qualification::Qualified);
    assert!(!report.runtime_authority);
}

// This crate's own adapter is refused under the reference template: a
// differently resolved library is not certified.
#[test]
fn downstream_own_adapter_is_not_certified_elsewhere() {
    let root = fixture_root();
    let out = scratch("renamed-refused");
    let mut adapter = RenamedAdapter::new().unwrap();
    assert_eq!(adapter.subject().package_name(), CONSUMER_PACKAGE);
    assert_eq!(adapter.subject().consumer().name(), CONSUMER_ADAPTER);
    let err = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: delivery::DELIVERY_PROFILE.into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: None,
        output_dir: out.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut adapter,
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap_err();
    assert_eq!(err.kind(), OperatorErrorKind::SubjectMismatch);
    assert!(!out.join("run").join("receipt.json").exists());
}

// With its own template pinning its own coordinates, the consumer adapter
// executes the real profile through the operator route.
#[test]
fn downstream_own_template_run_is_qualified() {
    let root = fixture_root();
    let work = scratch("own-template");
    let template_path = work.join("consumer-template.json");
    let mut template: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("contract-template.json")).unwrap())
            .unwrap();
    let adapter = RenamedAdapter::new().unwrap();
    template["expected_coordinates"]["package_name"] =
        adapter.subject().package_name().clone().into();
    template["expected_coordinates"]["package_version"] =
        adapter.subject().package_version().clone().into();
    template["expected_coordinates"]["source_sha256"] =
        adapter.subject().source_sha256().as_str().into();
    template["expected_coordinates"]["consumer"] =
        adapter.subject().consumer().name().clone().into();
    std::fs::write(&template_path, serde_json::to_vec(&template).unwrap()).unwrap();
    let mut adapter = RenamedAdapter::new().unwrap();
    let outcome = delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: delivery::DELIVERY_PROFILE.into(),
        fixture_root: root.clone(),
        manifest_path: None,
        template_path: Some(template_path),
        output_dir: work.join("run"),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut adapter,
        oracle: &delivery::DeliveryOracle::new().unwrap(),
    })
    .unwrap();
    assert_eq!(outcome.qualification, Qualification::Qualified);
    // Full engine admission of the consumer receipt.
    let catalog_bytes = std::fs::read(root.join("catalog.json")).unwrap();
    let report = receipt::verify_receipt_with_catalog(
        &work.join("run").join("receipt.json"),
        &catalog_bytes,
    )
    .unwrap();
    assert_eq!(report.qualification, Qualification::Qualified);
}
