// SPDX-License-Identifier: Apache-2.0
//! TC01: strict compiler-profile, patch-register and toolchain-inventory parsing.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! evidence/llvm-toolchain-review-20260922/kernel-oracle/{cases.json,prepare.py,
//! run.py,run-raw-bpf.c}, llvm-bpf-toolchain-experiment.md,
//! llvm-bpf-atomic-load-report.md (whole files, user-authored). The register
//! cites only patch identity and preimage metadata; no upstream
//! context/deletion lines are copied.
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use scopebase_testkit::object::{ObjectContract, PatchRegister, ToolchainInventory};

fn limits() -> Limits {
    Limits {
        input_bytes: 1 << 20,
        retained_bytes: 1 << 20,
        work_steps: 1 << 20,
        sites: 64,
        live_links: 64,
        pending_retirements: 64,
    }
}

fn refusal(error: &OperationError) -> (ErrorKind, Stage) {
    (error.kind(), error.stage())
}

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn valid_profile() -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "artifact": "llvm-rmw-oracle",
  "profile": "compiler-object-v1",
  "target": {{"triple": "bpfel-unknown-none", "arch": "bpfel", "endian": "little", "pointer_width_bits": 64}},
  "backend": {{"kind": "llvm-llc", "name": "llc", "version": "23.1.2-pristine", "sha256": "{EMPTY_SHA256}"}},
  "cpu": "v3",
  "features_enabled": [],
  "features_disabled": ["acqrel"],
  "required_cells": ["kernel-6.12-x86_64-verifier"],
  "optional_cells": ["kernel-7.0-x86_64-runtime"]
}}"#
    )
}

fn valid_patch() -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "kind": "tc01_patch_register",
  "patches": [
    {{
      "id": "llvm-used-result-rmw",
      "scope": "llvm-bpf-backend",
      "upstream_base": "llvmorg-23.1.2",
      "preimage_kind": "sha256",
      "preimage": "{EMPTY_SHA256}",
      "preimage_note": "test archive bytes",
      "patch_sha256": "{EMPTY_SHA256}",
      "applicability": "BPF backend used-result RMW lowering",
      "affected_profiles": ["compiler-object-v1"],
      "owner": "compiler-owner",
      "defect_test": "H29.live-old-value",
      "upstream_status": {{"state": "merged", "ref": "9d18ac3e726403b493a54079d5c760f36db33244"}},
      "inclusion_test": "H29.live-old-value-on-selected-backend",
      "removal_test": "H29.fixed-backend-controls",
      "expired": false
    }}
  ]
}}"#
    )
}

fn valid_toolchains() -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "kind": "tc01_toolchain_inventory",
  "tools": [
    {{
      "id": "llvm-23.1.2-source",
      "role": "source-archive",
      "name": "llvm-project",
      "version": "23.1.2",
      "version_detail": "llvmorg-23.1.2 release archive",
      "sha256": "c98bbef08a2b4c2613cd50e9aa9ae7b69b1fe6c16b2c40373bc0ab6116fdf78a",
      "hash_status": "recorded",
      "origin": "pinned-archive",
      "origin_ref": "evidence EXCLUDED-large-files.sha256",
      "used_for": "pristine baseline build"
    }},
    {{
      "id": "ubuntu-clang-18.1.8",
      "role": "frontend",
      "name": "clang",
      "version": "18.1.8",
      "version_detail": "Ubuntu clang version 18.1.8 (20ubuntu8)",
      "sha256": null,
      "hash_status": "unrecorded",
      "origin": "system-observed",
      "origin_ref": "llvm-bpf-atomic-load-repro/versions.json",
      "used_for": "C reproducer frontend"
    }}
  ]
}}"#
    )
}

#[test]
fn valid_profile_admits_with_exact_fields() {
    let contract = ObjectContract::from_json(valid_profile().as_bytes(), &limits()).unwrap();
    assert_eq!(contract.schema_version(), 1);
    assert_eq!(contract.artifact(), "llvm-rmw-oracle");
    assert_eq!(contract.profile(), "compiler-object-v1");
    assert_eq!(contract.triple(), "bpfel-unknown-none");
    assert_eq!(contract.cpu(), Some("v3"));
    assert_eq!(contract.backend_version(), "23.1.2-pristine");
    assert_eq!(contract.required_cells(), ["kernel-6.12-x86_64-verifier"]);
    assert!(contract.features_enabled().is_empty());
    assert_eq!(contract.features_disabled(), ["acqrel"]);
}

#[test]
fn duplicate_json_fields_reject_at_every_level() {
    let top = valid_profile().replacen(
        "\"optional_cells\"",
        "\"artifact\": \"llvm-rmw-oracle\", \"optional_cells\"",
        1,
    );
    assert_eq!(
        refusal(&ObjectContract::from_json(top.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    let nested = valid_profile().replacen(
        "\"version\": \"23.1.2-pristine\"",
        "\"version\": \"23.1.2-pristine\", \"version\": \"23.1.2-patched\"",
        1,
    );
    assert_eq!(
        refusal(&ObjectContract::from_json(nested.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Same decoded key through different JSON escapes is still a duplicate.
    let escaped = valid_profile().replacen(
        "\"optional_cells\"",
        "\"\\u0061rtifact\": \"llvm-rmw-oracle\", \"optional_cells\"",
        1,
    );
    assert_eq!(
        refusal(&ObjectContract::from_json(escaped.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    let patch_dup = valid_patch().replacen(
        "\"expired\": false",
        "\"expired\": false, \"expired\": true",
        1,
    );
    assert_eq!(
        refusal(&PatchRegister::from_json(patch_dup.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn malformed_hashes_reject_including_newline_suffix() {
    for bad in [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "x3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\\n",
        " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ] {
        let doc = valid_profile().replace(EMPTY_SHA256, bad);
        assert_eq!(
            refusal(&ObjectContract::from_json(doc.as_bytes(), &limits()).unwrap_err()),
            (ErrorKind::InvalidInput, Stage::Admission),
            "backend hash {bad:?} must refuse"
        );
        let doc = valid_patch().replace(EMPTY_SHA256, bad);
        assert_eq!(
            refusal(&PatchRegister::from_json(doc.as_bytes(), &limits()).unwrap_err()),
            (ErrorKind::InvalidInput, Stage::Admission),
            "patch hash {bad:?} must refuse"
        );
    }
}

#[test]
fn unknown_schema_version_rejects() {
    for (doc, parse) in [
        (valid_profile(), "profile"),
        (valid_patch(), "patch"),
        (valid_toolchains(), "toolchains"),
    ] {
        for bad in ["0", "2", "99", "\"1\"", "1.0", "true", "null"] {
            let mutated = doc.replacen(
                "\"schema_version\": 1",
                &format!("\"schema_version\": {bad}"),
                1,
            );
            let error = match parse {
                "profile" => ObjectContract::from_json(mutated.as_bytes(), &limits()).unwrap_err(),
                "patch" => PatchRegister::from_json(mutated.as_bytes(), &limits()).unwrap_err(),
                _ => ToolchainInventory::from_json(mutated.as_bytes(), &limits()).unwrap_err(),
            };
            assert_eq!(
                refusal(&error),
                (ErrorKind::InvalidInput, Stage::Admission),
                "{parse} schema_version {bad} must refuse"
            );
        }
        let missing = doc.replacen("\"schema_version\": 1,", "", 1);
        let error = match parse {
            "profile" => ObjectContract::from_json(missing.as_bytes(), &limits()).unwrap_err(),
            "patch" => PatchRegister::from_json(missing.as_bytes(), &limits()).unwrap_err(),
            _ => ToolchainInventory::from_json(missing.as_bytes(), &limits()).unwrap_err(),
        };
        assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Admission));
    }
}

#[test]
fn contradictory_cpu_and_feature_state_rejects() {
    // Same feature enabled and disabled.
    let both = valid_profile().replace(
        "\"features_enabled\": []",
        "\"features_enabled\": [\"acqrel\"]",
    );
    assert_eq!(
        refusal(&ObjectContract::from_json(both.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // v4-only acquire/release enabled on a v3 CPU pin.
    let v3_acqrel = valid_profile()
        .replace(
            "\"features_enabled\": []",
            "\"features_enabled\": [\"acqrel\"]",
        )
        .replace(
            "\"features_disabled\": [\"acqrel\"]",
            "\"features_disabled\": []",
        );
    assert_eq!(
        refusal(&ObjectContract::from_json(v3_acqrel.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // Baseline generic CPU with an explicitly enabled ISA feature.
    let generic = valid_profile()
        .replace("\"cpu\": \"v3\"", "\"cpu\": \"generic\"")
        .replace(
            "\"features_enabled\": []",
            "\"features_enabled\": [\"alu32\"]",
        )
        .replace(
            "\"features_disabled\": [\"acqrel\"]",
            "\"features_disabled\": []",
        );
    assert_eq!(
        refusal(&ObjectContract::from_json(generic.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // Enabled features without any CPU pin.
    let unpinned = valid_profile()
        .replace("\"cpu\": \"v3\"", "\"cpu\": null")
        .replace(
            "\"features_enabled\": []",
            "\"features_enabled\": [\"alu32\"]",
        )
        .replace(
            "\"features_disabled\": [\"acqrel\"]",
            "\"features_disabled\": []",
        );
    assert_eq!(
        refusal(&ObjectContract::from_json(unpinned.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // Unknown CPU and unknown feature names refuse as invalid input.
    let cpu = valid_profile().replace("\"cpu\": \"v3\"", "\"cpu\": \"v9\"");
    assert_eq!(
        refusal(&ObjectContract::from_json(cpu.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    let feature = valid_profile().replace(
        "\"features_disabled\": [\"acqrel\"]",
        "\"features_disabled\": [\"quantum\"]",
    );
    assert_eq!(
        refusal(&ObjectContract::from_json(feature.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Valid twins: v4 admits acquire/release; null CPU admits no enabled features.
    let v4 = valid_profile()
        .replace("\"cpu\": \"v3\"", "\"cpu\": \"v4\"")
        .replace(
            "\"features_enabled\": []",
            "\"features_enabled\": [\"acqrel\"]",
        )
        .replace(
            "\"features_disabled\": [\"acqrel\"]",
            "\"features_disabled\": []",
        );
    assert!(ObjectContract::from_json(v4.as_bytes(), &limits()).is_ok());
    let bare = valid_profile()
        .replace("\"cpu\": \"v3\"", "\"cpu\": null")
        .replace(
            "\"features_disabled\": [\"acqrel\"]",
            "\"features_disabled\": []",
        )
        .replace(
            "\"required_cells\": [\"kernel-6.12-x86_64-verifier\"]",
            "\"required_cells\": []",
        );
    assert!(ObjectContract::from_json(bare.as_bytes(), &limits()).is_ok());
}

#[test]
fn missing_backend_identity_rejects() {
    let doc: serde_json::Value = serde_json::from_str(&valid_profile()).unwrap();
    let mut missing = doc.clone();
    missing.as_object_mut().unwrap().remove("backend");
    assert_eq!(
        refusal(
            &ObjectContract::from_json(serde_json::to_vec(&missing).unwrap().as_slice(), &limits())
                .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    for field in ["kind", "name", "version", "sha256"] {
        let mut doc = doc.clone();
        doc["backend"].as_object_mut().unwrap().remove(field);
        assert_eq!(
            refusal(
                &ObjectContract::from_json(serde_json::to_vec(&doc).unwrap().as_slice(), &limits())
                    .unwrap_err()
            ),
            (ErrorKind::InvalidInput, Stage::Admission),
            "backend without {field} must refuse"
        );
    }
    let unknown = valid_profile().replace("\"kind\": \"llvm-llc\"", "\"kind\": \"telepathy\"");
    assert_eq!(
        refusal(&ObjectContract::from_json(unknown.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    let empty = valid_profile().replace("\"version\": \"23.1.2-pristine\"", "\"version\": \"\"");
    assert_eq!(
        refusal(&ObjectContract::from_json(empty.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn wildcard_required_cells_reject() {
    for wildcard in [
        "*",
        "kernel-*",
        "H29.*",
        "*runtime",
        "kernel-6.12-*-verifier",
    ] {
        let doc = valid_profile().replace("kernel-6.12-x86_64-verifier", wildcard);
        assert_eq!(
            refusal(&ObjectContract::from_json(doc.as_bytes(), &limits()).unwrap_err()),
            (ErrorKind::InvalidInput, Stage::Admission),
            "required cell {wildcard:?} must refuse"
        );
        let doc = valid_profile().replace("kernel-7.0-x86_64-runtime", wildcard);
        assert_eq!(
            refusal(&ObjectContract::from_json(doc.as_bytes(), &limits()).unwrap_err()),
            (ErrorKind::InvalidInput, Stage::Admission),
            "optional cell {wildcard:?} must refuse"
        );
    }
}

#[test]
fn patch_without_preimage_or_removal_test_rejects() {
    let doc: serde_json::Value = serde_json::from_str(&valid_patch()).unwrap();
    for field in [
        "preimage_kind",
        "preimage",
        "preimage_note",
        "patch_sha256",
        "removal_test",
        "defect_test",
        "inclusion_test",
        "upstream_base",
        "affected_profiles",
    ] {
        let mut doc = doc.clone();
        doc["patches"][0].as_object_mut().unwrap().remove(field);
        assert_eq!(
            refusal(
                &PatchRegister::from_json(serde_json::to_vec(&doc).unwrap().as_slice(), &limits())
                    .unwrap_err()
            ),
            (ErrorKind::InvalidInput, Stage::Admission),
            "patch without {field} must refuse"
        );
    }
    let mut doc = doc.clone();
    doc["patches"][0]["upstream_status"]["state"] = serde_json::json!("maybe");
    assert_eq!(
        refusal(
            &PatchRegister::from_json(serde_json::to_vec(&doc).unwrap().as_slice(), &limits())
                .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // A second record reusing the same id is a merged-register mutant.
    let mut doc = doc.clone();
    let twin = doc["patches"][0].clone();
    doc["patches"].as_array_mut().unwrap().push(twin);
    assert_eq!(
        refusal(
            &PatchRegister::from_json(serde_json::to_vec(&doc).unwrap().as_slice(), &limits())
                .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn git_sha1_preimage_admits_exact_40_hex_only() {
    let base = "24ccdfd47d0627f2dd88066e26a51526dac14cc4";
    // The preimage field precedes patch_sha256, so the first rewrite hits it.
    let doc = valid_patch()
        .replace(
            "\"preimage_kind\": \"sha256\"",
            "\"preimage_kind\": \"git-sha1\"",
        )
        .replacen(EMPTY_SHA256, base, 1);
    let register = PatchRegister::from_json(doc.as_bytes(), &limits()).unwrap();
    let record = &register.patches()[0];
    assert_eq!(record.preimage_kind(), "git-sha1");
    assert_eq!(record.preimage(), base);
    for bad in [
        "24ccdfd47d0627f2dd88066e26a51526dac14cc",
        "24ccdfd47d0627f2dd88066e26a51526dac14cc40",
        "24CCDFD47D0627F2DD88066E26A51526DAC14CC4",
        "24ccdfd47d0627f2dd88066e26a51526dac14cc4\\n",
        EMPTY_SHA256,
    ] {
        let doc = valid_patch()
            .replace(
                "\"preimage_kind\": \"sha256\"",
                "\"preimage_kind\": \"git-sha1\"",
            )
            .replacen(EMPTY_SHA256, bad, 1);
        assert_eq!(
            refusal(&PatchRegister::from_json(doc.as_bytes(), &limits()).unwrap_err()),
            (ErrorKind::InvalidInput, Stage::Admission),
            "git-sha1 preimage {bad:?} must refuse"
        );
    }
    let kind = valid_patch().replace(
        "\"preimage_kind\": \"sha256\"",
        "\"preimage_kind\": \"md5\"",
    );
    assert_eq!(
        refusal(&PatchRegister::from_json(kind.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn input_bounds_refuse_before_parsing() {
    let bytes = valid_profile().into_bytes();
    let zero = Limits {
        input_bytes: 0,
        retained_bytes: 1 << 20,
        work_steps: 1 << 20,
        sites: 64,
        live_links: 64,
        pending_retirements: 64,
    };
    assert_eq!(
        refusal(&ObjectContract::from_json(&bytes, &zero).unwrap_err()),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    let tight = Limits {
        input_bytes: bytes.len() - 1,
        ..limits()
    };
    assert_eq!(
        refusal(&ObjectContract::from_json(&bytes, &tight).unwrap_err()),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    assert_eq!(
        refusal(&ObjectContract::from_json(b"{not json", &limits()).unwrap_err()),
        (ErrorKind::Malformed, Stage::Admission)
    );
    assert_eq!(
        refusal(&ObjectContract::from_json(b"\xff\xfe", &limits()).unwrap_err()),
        (ErrorKind::Malformed, Stage::Admission)
    );
}

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{MANIFEST_DIR}/../../{relative}"))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

#[test]
fn shipped_patch_register_loads_with_separate_llvm_and_linker_repairs() {
    let bytes = repo_bytes("tools/bpf-compat/patches.json");
    let register = PatchRegister::from_json(&bytes, &limits()).unwrap();
    let llvm = register.find("llvm-used-result-rmw").expect("llvm record");
    let linker = register
        .find("bpf-linker-debug-records")
        .expect("linker record");
    assert_ne!(llvm.id(), linker.id());
    assert_ne!(llvm.patch_sha256(), linker.patch_sha256());
    assert_ne!(llvm.preimage(), linker.preimage());
    assert_eq!(llvm.preimage_kind(), "sha256");
    assert_eq!(linker.preimage_kind(), "git-sha1");
    assert_ne!(llvm.removal_test(), linker.removal_test());
    assert_ne!(llvm.scope(), linker.scope());
    assert!(!llvm.expired());
    assert!(!linker.expired());
    assert_eq!(
        llvm.applicability(),
        "BPF backend used-result RMW old-value lowering (LLVM issue 210280)."
    );
    assert_ne!(llvm.applicability(), linker.applicability());
    assert!(register.find("aya-ring-reader").is_some());
    assert!(register.find("aya-obj-map-relocation").is_some());
    assert_eq!(register.len(), 4);
}

#[test]
fn shipped_toolchain_inventory_resolves_offline() {
    let bytes = repo_bytes("tools/bpf-compat/toolchains.json");
    assert!(
        !bytes.windows(4).any(|window| window == b"http"),
        "inventory must not reference the network"
    );
    let inventory = ToolchainInventory::from_json(&bytes, &limits()).unwrap();
    assert_eq!(inventory.len(), 11);
    for id in [
        "ubuntu-clang-18.1.8",
        "ubuntu-llc-18.1.8",
        "ubuntu-llc-21.1.8",
        "llvm-23.1.2-source",
        "llvm-23.1.2-pristine-llc",
        "llvm-23.1.2-pr210371-llc",
        "rustc-nightly-2026-05-20",
        "rust-llvm-22.1.4",
        "bpf-linker-0.10.4",
        "bpf-linker-0.11.1-unrepaired",
        "bpf-linker-0.11.1-repaired",
    ] {
        let pin = inventory.find(id).unwrap_or_else(|| panic!("pin {id}"));
        assert!(
            !pin.version().is_empty(),
            "pin {id} carries an exact version"
        );
    }
    for pin in inventory.tools() {
        if pin.hash_recorded() {
            assert_eq!(pin.sha256().unwrap().len(), 32);
        } else {
            assert_eq!(pin.hash_status(), "unrecorded");
        }
    }
}

#[test]
fn shipped_provenance_files_load_and_cross_resolve() {
    let patches = repo_bytes("tools/bpf-compat/patches.json");
    let register = PatchRegister::from_json(&patches, &limits()).unwrap();
    let tools = repo_bytes("tools/bpf-compat/toolchains.json");
    let inventory = ToolchainInventory::from_json(&tools, &limits()).unwrap();
    for area in [
        "atomic-rmw",
        "atomic-load",
        "isa",
        "metadata",
        "object-graph",
    ] {
        let bytes = repo_bytes(&format!("fixtures/bpf/{area}/provenance.json"));
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["schema_version"], 1, "{area}: schema version");
        assert_eq!(doc["kind"], "tc01_issue_provenance", "{area}: kind");
        assert_eq!(doc["area"], area, "{area}: area");
        assert_eq!(
            doc["qualification"], "NOT_EVALUATED",
            "{area}: never a pass"
        );
        assert!(
            !doc["defect"].as_str().unwrap_or("").is_empty(),
            "{area}: defect"
        );
        for reference in doc["toolchain_refs"].as_array().unwrap() {
            let id = reference.as_str().unwrap();
            assert!(
                inventory.find(id).is_some(),
                "{area}: toolchain {id} resolves"
            );
        }
        for reference in doc["patch_refs"].as_array().unwrap() {
            let id = reference.as_str().unwrap();
            assert!(register.find(id).is_some(), "{area}: patch {id} resolves");
        }
        assert!(
            !doc["selected_sources"].as_array().unwrap().is_empty(),
            "{area}: sources"
        );
        assert!(
            !doc["cells"].as_array().unwrap().is_empty(),
            "{area}: cells"
        );
        for cell in doc["cells"].as_array().unwrap() {
            assert_ne!(
                cell["status"], "PASS",
                "{area}: historical cells never PASS"
            );
        }
    }
}

#[test]
fn patch_test_ids_require_validated_case_ids() {
    // TC01 Interfaces: defect/inclusion/removal test ids consume the shared
    // validated CaseId constructors, not bare nonempty strings.
    for field in ["defect_test", "inclusion_test", "removal_test"] {
        for bad in [
            String::new(),
            "has space".to_owned(),
            "H29.bad\n".to_owned(),
            "x".repeat(97),
        ] {
            let mut doc: serde_json::Value = serde_json::from_str(&valid_patch()).unwrap();
            doc["patches"][0][field] = serde_json::json!(bad);
            assert_eq!(
                refusal(
                    &PatchRegister::from_json(
                        serde_json::to_vec(&doc).unwrap().as_slice(),
                        &limits()
                    )
                    .unwrap_err()
                ),
                (ErrorKind::InvalidInput, Stage::Admission),
                "{field} {bad:?} must refuse"
            );
        }
    }
    // Valid twins still admit with exact ids and applicability preserved.
    let register = PatchRegister::from_json(valid_patch().as_bytes(), &limits()).unwrap();
    let record = &register.patches()[0];
    assert_eq!(record.defect_test(), "H29.live-old-value");
    assert_eq!(
        record.inclusion_test(),
        "H29.live-old-value-on-selected-backend"
    );
    assert_eq!(record.removal_test(), "H29.fixed-backend-controls");
    assert_eq!(
        record.applicability(),
        "BPF backend used-result RMW lowering"
    );
}
