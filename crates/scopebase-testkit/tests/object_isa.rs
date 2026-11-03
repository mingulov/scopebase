// SPDX-License-Identifier: Apache-2.0
//! TC03: final-object inventory, decoded ISA inspection and explicit ISA profile admission.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! `llvm-bpf-toolchain-experiment.md` lines 77-100 (user-authored H30 preset
//! warning: v4 is a compiler preset, not a kernel promise; LLVM 18 original
//! bundle; acqrel/indirect-jump kernel entries). Emission facts come from the
//! pinned local tool (ubuntu-llc-21.1.8, hashed in
//! `fixtures/bpf/isa/expected.json`); opcode numbers are cited from pinned
//! kernel UAPI headers (hashes only, no lines copied). Grant: OWNER-2026-10-23.
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use scopebase_testkit::object::{
    admit_profile, check_object, contract_families, inspect_final_object, FinalObjectManifest,
    IsaProfile, ObjectContract, ObjectKind,
};
use sha2::{Digest, Sha256};

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

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{MANIFEST_DIR}/../../{relative}"))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

/// S228: objects-dir listing with a naming failure. A single non-UTF8
/// file must fail naming the directory and entry — not a bare
/// `into_string().unwrap()` panic far from the cause.
fn object_names(dir: &str) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("list {dir}: {error}"))
        .map(|entry| {
            let name = entry
                .unwrap_or_else(|error| panic!("list {dir} entry: {error}"))
                .file_name();
            name.into_string()
                .unwrap_or_else(|bad| panic!("object name in {dir} is not UTF-8: {bad:?}"))
        })
        .collect()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Real llc 21.1.8 binary identity (fixtures/bpf/isa/expected.json emitter pin).
const LLC_SHA256: &str = "935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382";
// Real base.o bytes (expected.json); the tamper test below re-verifies this.
const BASE_SHA256: &str = "98db7702fa43d55c83f6f6966f4f1a0002ca9a636fd600cef719c8eeb34c7757";
const SDIV_SHA256: &str = "ac66177b755e4ef8fdaadb056670844b1863690b44442d36ec6c019df606b7bc";
const EXEC_TWIN_SHA256: &str = "f898f4bf20e92d695c9126813c93181919adb6b55ee6a503d79c344ebfb28082";

fn contract_json(
    cpu: Option<&str>,
    enabled: &[&str],
    arch: &str,
    endian: &str,
    triple: &str,
) -> String {
    let cpu = cpu.map_or("null".to_owned(), |c| format!("\"{c}\""));
    let enabled = enabled
        .iter()
        .map(|f| format!("\"{f}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{
  "schema_version": 1,
  "artifact": "tc03-isa-vectors",
  "profile": "compiler-object-v1",
  "target": {{"triple": "{triple}", "arch": "{arch}", "endian": "{endian}", "pointer_width_bits": 64}},
  "backend": {{"kind": "llvm-llc", "name": "llc", "version": "21.1.8", "sha256": "{LLC_SHA256}"}},
  "cpu": {cpu},
  "features_enabled": [{enabled}],
  "features_disabled": [],
  "required_cells": ["kernel-6.12-x86_64-verifier"],
  "optional_cells": []
}}"#
    )
}

fn contract(cpu: Option<&str>, enabled: &[&str]) -> ObjectContract {
    ObjectContract::from_json(
        contract_json(cpu, enabled, "bpfel", "little", "bpfel-unknown-none").as_bytes(),
        &limits(),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn profile_json(
    name: &str,
    version: &str,
    cpu: Option<&str>,
    features: &[&str],
    allowed: &[&str],
    required: &[&str],
    licenses: &[&str],
    requires_license: bool,
) -> String {
    let cpu = cpu.map_or("null".to_owned(), |c| format!("\"{c}\""));
    let list = |items: &[&str]| {
        items
            .iter()
            .map(|f| format!("\"{f}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        r#"{{
  "schema_version": 1,
  "kind": "tc03_isa_profile",
  "name": "{name}",
  "version": "{version}",
  "cpu": {cpu},
  "features_enabled": [{0}],
  "allowed_families": [{1}],
  "required_families": [{2}],
  "admitted_licenses": [{3}],
  "requires_license": {requires_license}
}}"#,
        list(features),
        list(allowed),
        list(required),
        list(licenses)
    )
}

#[allow(clippy::too_many_arguments)]
fn profile(
    name: &str,
    version: &str,
    cpu: Option<&str>,
    features: &[&str],
    allowed: &[&str],
    required: &[&str],
    licenses: &[&str],
    requires_license: bool,
) -> IsaProfile {
    IsaProfile::from_json(
        profile_json(
            name,
            version,
            cpu,
            features,
            allowed,
            required,
            licenses,
            requires_license,
        )
        .as_bytes(),
        &limits(),
    )
    .unwrap()
}

fn baseline_profile() -> IsaProfile {
    profile(
        "tc03-baseline",
        "1",
        Some("generic"),
        &[],
        &["base"],
        &["base"],
        &[],
        false,
    )
}

fn manifest_json(entries: &str) -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "kind": "tc03_final_object_manifest",
  "objects": [{entries}]
}}"#
    )
}

fn entry_json(
    id: &str,
    kind: &str,
    sha: &str,
    isa_profile: &str,
    isa_version: &str,
    license: Option<&str>,
) -> String {
    let license = license.map_or("null".to_owned(), |l| format!("\"{l}\""));
    format!(
        r#"{{
    "id": "{id}",
    "kind": "{kind}",
    "path": "fixtures/bpf/isa/objects/{id}.o",
    "sha256": "{sha}",
    "producer_name": "llc",
    "producer_version": "21.1.8",
    "artifact": "tc03-isa-vectors",
    "profile": "compiler-object-v1",
    "isa_profile": "{isa_profile}",
    "isa_version": "{isa_version}",
    "license_declared": {license}
  }}"#
    )
}

// ---------------------------------------------------------------------------
// Manifest: inventory and hash-bound admission
// ---------------------------------------------------------------------------

#[test]
fn manifest_admits_inventoried_object_with_attribution() {
    let doc = manifest_json(&entry_json(
        "tc03-base",
        "rel",
        BASE_SHA256,
        "tc03-baseline",
        "1",
        None,
    ));
    let manifest = FinalObjectManifest::from_json(doc.as_bytes(), &limits()).unwrap();
    assert_eq!(manifest.len(), 1);
    assert!(!manifest.is_empty());
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let admitted = manifest.admit("tc03-base", &bytes, &limits()).unwrap();
    let entry = admitted.entry();
    assert_eq!(entry.id(), "tc03-base");
    assert_eq!(entry.kind(), ObjectKind::Rel);
    assert_eq!(hex(entry.sha256()), BASE_SHA256);
    assert_eq!(entry.producer_name(), "llc");
    assert_eq!(entry.producer_version(), "21.1.8");
    assert_eq!(entry.artifact(), "tc03-isa-vectors");
    assert_eq!(entry.profile(), "compiler-object-v1");
    assert_eq!(entry.isa_profile(), "tc03-baseline");
    assert_eq!(entry.isa_version(), "1");
    assert_eq!(entry.license_declared(), None);
    assert_eq!(admitted.object_id().id(), "tc03-base");
    assert_eq!(hex(admitted.sha256()), BASE_SHA256);
    assert!(manifest.find("tc03-base").is_some());
    assert!(manifest.find("tc03-elsewhere").is_none());
    // Executable (.elf role) entries admit through the same hash binding.
    let exec_doc = manifest_json(&entry_json(
        "tc03-exec-twin",
        "exec",
        EXEC_TWIN_SHA256,
        "tc03-baseline",
        "1",
        None,
    ));
    let exec_manifest = FinalObjectManifest::from_json(exec_doc.as_bytes(), &limits()).unwrap();
    let exec = repo_bytes("fixtures/bpf/isa/objects/exec-twin.o");
    let exec_admitted = exec_manifest
        .admit("tc03-exec-twin", &exec, &limits())
        .unwrap();
    assert_eq!(exec_admitted.entry().kind(), ObjectKind::Exec);
}

#[test]
fn manifest_rejects_hash_mismatch() {
    // Genuine sdiv.o hash under the base.o id: swapped attribution still refuses.
    let doc = manifest_json(&entry_json(
        "tc03-base",
        "rel",
        SDIV_SHA256,
        "tc03-baseline",
        "1",
        None,
    ));
    let manifest = FinalObjectManifest::from_json(doc.as_bytes(), &limits()).unwrap();
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    assert_eq!(
        refusal(&manifest.admit("tc03-base", &bytes, &limits()).unwrap_err()),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // Mutated bytes against the true manifest refuse identically.
    let doc = manifest_json(&entry_json(
        "tc03-base",
        "rel",
        BASE_SHA256,
        "tc03-baseline",
        "1",
        None,
    ));
    let manifest = FinalObjectManifest::from_json(doc.as_bytes(), &limits()).unwrap();
    let mut mutated = bytes.clone();
    let last = mutated.len() - 1;
    mutated[last] ^= 0x01;
    assert_eq!(
        refusal(
            &manifest
                .admit("tc03-base", &mutated, &limits())
                .unwrap_err()
        ),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // Valid twin admits.
    manifest.admit("tc03-base", &bytes, &limits()).unwrap();
}

#[test]
fn manifest_rejects_uninventoried_object() {
    let doc = manifest_json(&entry_json(
        "tc03-base",
        "rel",
        BASE_SHA256,
        "tc03-baseline",
        "1",
        None,
    ));
    let manifest = FinalObjectManifest::from_json(doc.as_bytes(), &limits()).unwrap();
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    assert_eq!(
        refusal(
            &manifest
                .admit("tc03-not-inventoried", &bytes, &limits())
                .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    manifest.admit("tc03-base", &bytes, &limits()).unwrap();
}

#[test]
fn manifest_rejects_duplicate_unknown_and_malformed_entries() {
    let entry = entry_json("tc03-x", "rel", BASE_SHA256, "tc03-baseline", "1", None);
    let dup = manifest_json(&format!("{entry},{entry}"));
    assert_eq!(
        refusal(&FinalObjectManifest::from_json(dup.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    let bad_kind = entry_json("tc03-x", "dyn", BASE_SHA256, "tc03-baseline", "1", None);
    assert_eq!(
        refusal(
            &FinalObjectManifest::from_json(manifest_json(&bad_kind).as_bytes(), &limits())
                .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    assert_eq!(
        refusal(
            &FinalObjectManifest::from_json(
                manifest_json(&entry_json(
                    "tc03-x",
                    "rel",
                    &BASE_SHA256.to_ascii_uppercase(),
                    "tc03-baseline",
                    "1",
                    None
                ))
                .as_bytes(),
                &limits()
            )
            .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    let unknown_field = manifest_json(&entry_json(
        "tc03-x",
        "rel",
        BASE_SHA256,
        "tc03-baseline",
        "1",
        None,
    ))
    .replace(
        "\"license_declared\": null",
        "\"license_declared\": null, \"extra\": 1",
    );
    assert_eq!(
        refusal(&FinalObjectManifest::from_json(unknown_field.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn shipped_objects_match_expected_hashes_and_families() {
    let expected: serde_json::Value =
        serde_json::from_slice(&repo_bytes("fixtures/bpf/isa/expected.json")).unwrap();
    assert_eq!(expected["schema_version"], 1);
    assert_eq!(expected["kind"], "tc03_isa_vectors");
    let objects = expected["objects"].as_array().unwrap();
    assert_eq!(
        objects.len(),
        16,
        "every emitted and derived object recorded"
    );
    let on_disk = object_names(&format!("{MANIFEST_DIR}/../../fixtures/bpf/isa/objects"));
    assert_eq!(on_disk.len(), 16, "no unrecorded object on disk");
    let contract = contract(Some("v4"), &["signed-div", "acqrel", "signed-load-move"]);
    let big = ObjectContract::from_json(
        contract_json(
            Some("v4"),
            &["signed-div"],
            "bpfeb",
            "big",
            "bpfeb-unknown-none",
        )
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    for object in objects {
        let file = object["file"].as_str().unwrap();
        let bytes = repo_bytes(&format!("fixtures/bpf/isa/{file}"));
        let contract = if object["march"] == "bpfeb" {
            &big
        } else {
            &contract
        };
        assert_eq!(
            hex(&digest(&bytes)),
            object["sha256"].as_str().unwrap(),
            "{file}: frozen hash"
        );
        let name = file.rsplit('/').next().unwrap().to_owned();
        assert!(
            on_disk.contains(&name),
            "{file}: recorded object exists on disk"
        );
        let inspection = inspect_final_object(&bytes, contract, &limits()).unwrap();
        let want: Vec<String> = object["families"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(inspection.families(), &want, "{file}: effective families");
        assert_eq!(
            inspection.license(),
            object["license"].as_str(),
            "{file}: license declaration"
        );
        assert!(
            inspection.conforms(),
            "{file}: shipped vectors carry no violations"
        );
    }
}

// ---------------------------------------------------------------------------
// Inspection: bounded ELF decode and family classification
// ---------------------------------------------------------------------------

#[test]
fn inspect_binds_object_id_to_content_hash() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let inspection =
        inspect_final_object(&bytes, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(inspection.conforms());
    assert!(inspection.violations().is_empty());
    assert_eq!(hex(inspection.object_id().sha256()), BASE_SHA256);
    assert_eq!(inspection.kind(), ObjectKind::Rel);
    let exec = repo_bytes("fixtures/bpf/isa/objects/exec-twin.o");
    let inspection =
        inspect_final_object(&exec, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert_eq!(inspection.kind(), ObjectKind::Exec);
    assert!(inspection.conforms());
}

#[test]
fn inspect_reports_per_instruction_inventory_with_locations() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let inspection =
        inspect_final_object(&bytes, &contract(Some("generic"), &[]), &limits()).unwrap();
    let spans = inspection.spans();
    assert_eq!(spans.len(), 3);
    assert_eq!(spans[0].family, "base");
    assert_eq!(spans[0].section, "socket");
    assert_eq!(spans[0].offset, 0);
    assert_eq!(spans[2].offset, 16);
    assert!(spans.iter().all(|span| span.section == "socket"));
}

#[test]
fn inspect_admits_big_endian_object_on_matching_contract_only() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base-be.o");
    let big = ObjectContract::from_json(
        contract_json(Some("generic"), &[], "bpfeb", "big", "bpfeb-unknown-none").as_bytes(),
        &limits(),
    )
    .unwrap();
    let inspection = inspect_final_object(&bytes, &big, &limits()).unwrap();
    assert_eq!(inspection.families(), &["base".to_owned()]);
    assert!(inspection.conforms());
    assert_eq!(
        refusal(
            &inspect_final_object(&bytes, &contract(Some("generic"), &[]), &limits()).unwrap_err()
        ),
        (ErrorKind::Incompatible, Stage::Admission)
    );
}

#[test]
fn inspect_refuses_non_elf_truncated_and_wrong_machine() {
    let contract = contract(Some("generic"), &[]);
    assert_eq!(
        refusal(&inspect_final_object(b"not an elf object", &contract, &limits()).unwrap_err()),
        (ErrorKind::Malformed, Stage::Admission)
    );
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    assert_eq!(
        refusal(
            &inspect_final_object(&bytes[..bytes.len() / 2], &contract, &limits()).unwrap_err()
        ),
        (ErrorKind::Malformed, Stage::Admission)
    );
    let mut machine = bytes.clone();
    assert_eq!(&machine[0x12..0x14], &[247, 0], "guard: EM_BPF fixture");
    machine[0x12..0x14].copy_from_slice(&[62, 0]); // EM_X86_64
    assert_eq!(
        refusal(&inspect_final_object(&machine, &contract, &limits()).unwrap_err()),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    inspect_final_object(&bytes, &contract, &limits()).unwrap();
}

#[test]
fn inspect_unknown_opcode_violation_carries_location() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    assert_eq!(bytes[0x48], 0x07, "guard: socket insn1 is the ADD");
    let mut mutant = bytes.clone();
    mutant[0x48] = 0xf5; // JMP class, undefined op 0xf0.
    let inspection =
        inspect_final_object(&mutant, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(!inspection.conforms());
    let hit = inspection
        .violations()
        .iter()
        .find(|v| v.rule_id == "isa.unknown-opcode")
        .expect("unknown-opcode violation");
    assert_eq!(hit.section.as_deref(), Some("socket"));
    assert_eq!(hit.offset, Some(8));
    assert_eq!(hit.kind, ErrorKind::InvalidInput);
    let valid = inspect_final_object(&bytes, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(valid.conforms());
}

#[test]
fn inspect_executable_non_code_section_refuses() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    // Section 3 (socket) header: shoff 0xd0 + 3*64 = 0x190, type at +4.
    assert_eq!(
        &bytes[0x194..0x198],
        &[1, 0, 0, 0],
        "guard: PROGBITS fixture"
    );
    let mut mutant = bytes.clone();
    mutant[0x194..0x198].copy_from_slice(&[8, 0, 0, 0]); // NOBITS, still EXECINSTR.
    let inspection =
        inspect_final_object(&mutant, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(!inspection.conforms());
    assert!(inspection
        .violations()
        .iter()
        .any(|v| v.rule_id == "object.unsupported-section"));
    let valid = inspect_final_object(&bytes, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(valid.conforms());
}

#[test]
fn inspect_truncated_final_slot_refuses() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    assert_eq!(bytes[0x50], 0x95, "guard: socket insn2 is the exit");
    let mut mutant = bytes.clone();
    mutant[0x50] = 0x18; // LDDW occupies 16 bytes; the second half is missing.
    let inspection =
        inspect_final_object(&mutant, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(!inspection.conforms());
    assert!(inspection
        .violations()
        .iter()
        .any(|v| v.rule_id == "isa.truncated-stream"));
}

#[test]
fn inspect_license_positive_and_mutants() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/lic.o");
    let start = bytes
        .windows(4)
        .position(|w| w == b"GPL\0")
        .expect("license bytes in fixture");
    let inspection =
        inspect_final_object(&bytes, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert_eq!(inspection.license(), Some("GPL"));
    assert!(inspection.conforms());
    let mut truncated = bytes.clone();
    truncated[start..start + 4].copy_from_slice(b"GPLX");
    let hit = inspect_final_object(&truncated, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(!hit.conforms());
    assert!(hit
        .violations()
        .iter()
        .any(|v| v.rule_id == "license.truncated"));
    assert_eq!(hit.license(), None);
    let mut duplicated = bytes.clone();
    duplicated[start..start + 4].copy_from_slice(b"G\0PL");
    let hit =
        inspect_final_object(&duplicated, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(!hit.conforms());
    assert!(hit
        .violations()
        .iter()
        .any(|v| v.rule_id == "license.duplicated"));
    let mut binary = bytes.clone();
    binary[start..start + 4].copy_from_slice(b"G\xffL\0");
    let hit = inspect_final_object(&binary, &contract(Some("generic"), &[]), &limits()).unwrap();
    assert!(!hit.conforms());
    assert!(hit
        .violations()
        .iter()
        .any(|v| v.rule_id == "license.non-ascii"));
}

#[test]
fn inspect_respects_input_section_and_work_bounds() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let contract = contract(Some("generic"), &[]);
    let mut tight = limits();
    tight.input_bytes = bytes.len() - 1;
    assert_eq!(
        refusal(&inspect_final_object(&bytes, &contract, &tight).unwrap_err()),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    let mut tiny_work = limits();
    tiny_work.work_steps = 2;
    assert_eq!(
        refusal(&inspect_final_object(&bytes, &contract, &tiny_work).unwrap_err()),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    let mut tiny_sites = limits();
    tiny_sites.sites = 2; // base.o carries five section headers.
    assert_eq!(
        refusal(&inspect_final_object(&bytes, &contract, &tiny_sites).unwrap_err()),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    inspect_final_object(&bytes, &contract, &limits()).unwrap();
}

// ---------------------------------------------------------------------------
// Rules: explicit ISA profile admission
// ---------------------------------------------------------------------------

#[test]
fn cpu_bundles_match_recorded_emission_matrix() {
    let matrix = |cpu: Option<&str>| contract_families(&contract(cpu, &[]));
    assert_eq!(matrix(None), ["base".to_owned()]);
    assert_eq!(
        matrix(Some("generic")),
        ["base", "byte-swap", "ext-jumps", "jump32"].map(str::to_string)
    );
    assert_eq!(
        matrix(Some("v3")),
        ["alu32", "base", "byte-swap", "ext-jumps", "jump32"].map(str::to_string)
    );
    assert_eq!(
        matrix(Some("v4")),
        [
            "acqrel",
            "alu32",
            "base",
            "byte-swap",
            "ext-jumps",
            "jump32",
            "signed-div",
            "signed-load-move"
        ]
        .map(str::to_string)
    );
    // Explicit features add families without preset broadening.
    assert!(contract_families(&contract(
        Some("v4"),
        &["long-jump", "imm-store", "indirect-jumps"]
    ))
    .contains(&"long-jump".to_owned()));
    assert!(!contract_families(&contract(Some("v4"), &[])).contains(&"long-jump".to_owned()));
}

#[test]
fn profiles_admit_by_exact_name_and_version_only() {
    let profiles = vec![
        baseline_profile(),
        profile(
            "tc03-v4div",
            "2",
            Some("v4"),
            &["signed-div"],
            &["base", "signed-div"],
            &["base"],
            &[],
            false,
        ),
    ];
    let hit = admit_profile(&profiles, "tc03-v4div", "2").unwrap();
    assert_eq!(hit.name(), "tc03-v4div");
    assert_eq!(hit.version(), "2");
    assert_eq!(
        refusal(&admit_profile(&profiles, "no-such-isa", "1").unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    assert_eq!(
        refusal(&admit_profile(&profiles, "tc03-baseline", "9.9").unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    assert_eq!(
        refusal(&admit_profile(&[], "tc03-baseline", "1").unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn profiles_reject_incoherent_and_unknown_content() {
    // Unknown family.
    assert_eq!(
        refusal(
            &IsaProfile::from_json(
                profile_json(
                    "tc03-x",
                    "1",
                    Some("generic"),
                    &[],
                    &["base", "mind-meld"],
                    &["base"],
                    &[],
                    false
                )
                .as_bytes(),
                &limits()
            )
            .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Required family outside the allowed set: unsatisfiable profile.
    assert_eq!(
        refusal(
            &IsaProfile::from_json(
                profile_json(
                    "tc03-x",
                    "1",
                    Some("generic"),
                    &[],
                    &["base"],
                    &["base", "signed-div"],
                    &[],
                    false
                )
                .as_bytes(),
                &limits()
            )
            .unwrap_err()
        ),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // License required but nothing admitted.
    assert_eq!(
        refusal(
            &IsaProfile::from_json(
                profile_json(
                    "tc03-x",
                    "1",
                    Some("generic"),
                    &[],
                    &["base"],
                    &["base"],
                    &[],
                    true
                )
                .as_bytes(),
                &limits()
            )
            .unwrap_err()
        ),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // v4-only feature on a v3 profile pin: same coherence as the contract grammar.
    assert_eq!(
        refusal(
            &IsaProfile::from_json(
                profile_json(
                    "tc03-x",
                    "1",
                    Some("v3"),
                    &["acqrel"],
                    &["acqrel", "base"],
                    &["base"],
                    &[],
                    false
                )
                .as_bytes(),
                &limits()
            )
            .unwrap_err()
        ),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // Unknown field refuses.
    let unknown = profile_json(
        "tc03-x",
        "1",
        Some("generic"),
        &[],
        &["base"],
        &["base"],
        &[],
        false,
    )
    .replace(
        "\"requires_license\": false",
        "\"requires_license\": false, \"extra\": 1",
    );
    assert_eq!(
        refusal(&IsaProfile::from_json(unknown.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn check_accepts_matching_manifest_contract_and_profile() {
    let manifest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-sdiv",
            "rel",
            SDIV_SHA256,
            "tc03-v4div",
            "2",
            None,
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let bytes = repo_bytes("fixtures/bpf/isa/objects/sdiv.o");
    let admitted = manifest.admit("tc03-sdiv", &bytes, &limits()).unwrap();
    let contract = contract(Some("v4"), &["signed-div"]);
    let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
    assert!(inspection.conforms());
    let test_profile = profile(
        "tc03-v4div",
        "2",
        Some("v4"),
        &["signed-div"],
        &["base", "signed-div"],
        &["base"],
        &[],
        false,
    );
    let profiles = vec![test_profile];
    let admitted_profile = admit_profile(&profiles, "tc03-v4div", "2").unwrap();
    let violations =
        check_object(admitted_profile, &contract, &inspection, admitted.entry()).unwrap();
    assert!(
        violations.is_empty(),
        "matching triple admits: {violations:?}"
    );
}

#[test]
fn check_refuses_preset_drift_between_contract_and_profile() {
    let manifest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-sdiv",
            "rel",
            SDIV_SHA256,
            "tc03-v4div",
            "2",
            None,
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let bytes = repo_bytes("fixtures/bpf/isa/objects/sdiv.o");
    let admitted = manifest.admit("tc03-sdiv", &bytes, &limits()).unwrap();
    // Same bytes, but the contract claims a different effective subset than the
    // profile pins: the decoded families match neither side exactly.
    let drifted = contract(Some("v4"), &[]);
    let inspection = inspect_final_object(&bytes, &drifted, &limits()).unwrap();
    assert!(inspection.conforms());
    let test_profile = profile(
        "tc03-v4div",
        "2",
        Some("v4"),
        &["signed-div"],
        &["base", "signed-div"],
        &["base"],
        &[],
        false,
    );
    let violations = check_object(&test_profile, &drifted, &inspection, admitted.entry()).unwrap();
    assert!(
        violations.iter().any(|v| v.rule_id == "isa.profile-drift"),
        "drifted contract refuses: {violations:?}"
    );
    // Valid twin: exact (cpu, features) match admits.
    let exact = contract(Some("v4"), &["signed-div"]);
    let inspection = inspect_final_object(&bytes, &exact, &limits()).unwrap();
    let violations = check_object(&test_profile, &exact, &inspection, admitted.entry()).unwrap();
    assert!(violations.is_empty());
}

#[test]
fn check_refuses_effective_jump32_under_base_only_profile() {
    // The preset-name-as-proof control: jmp32.o decodes an effective jump32
    // family, which the base-only profile refuses even though the generic
    // contract (like llc 21.1.8 at -mcpu=generic) can produce it.
    let bytes = repo_bytes("fixtures/bpf/isa/objects/jmp32.o");
    let manifest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-jmp32",
            "rel",
            &hex(&digest(&bytes)),
            "tc03-baseline",
            "1",
            None,
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let admitted = manifest.admit("tc03-jmp32", &bytes, &limits()).unwrap();
    let contract = contract(Some("generic"), &[]);
    let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
    assert!(inspection.conforms());
    let test_profile = baseline_profile();
    let violations = check_object(&test_profile, &contract, &inspection, admitted.entry()).unwrap();
    let rules: Vec<&str> = violations.iter().map(|v| v.rule_id.as_str()).collect();
    assert!(
        rules.contains(&"isa.forbidden-family"),
        "effective jump32 refused: {rules:?}"
    );
    assert!(
        !rules.contains(&"isa.contract-forbidden-family"),
        "generic contract honestly covers jump32: {rules:?}"
    );
    assert!(violations
        .iter()
        .filter(|v| v.rule_id == "isa.forbidden-family")
        .all(|v| v.section.as_deref() == Some("socket") && v.offset.is_some()));
    // Valid twin: base.o under the same profile admits.
    let base = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let manifest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-base",
            "rel",
            BASE_SHA256,
            "tc03-baseline",
            "1",
            None,
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let admitted = manifest.admit("tc03-base", &base, &limits()).unwrap();
    let inspection = inspect_final_object(&base, &contract, &limits()).unwrap();
    let violations = check_object(&test_profile, &contract, &inspection, admitted.entry()).unwrap();
    assert!(violations.is_empty());
}

#[test]
fn check_refuses_alu32_outside_generic_contract() {
    // alu32 is never emitted below v3, so the generic contract forbids it at
    // the contract layer as well as the profile layer.
    let bytes = repo_bytes("fixtures/bpf/isa/objects/alu32.o");
    let manifest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-alu32",
            "rel",
            &hex(&digest(&bytes)),
            "tc03-baseline",
            "1",
            None,
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let admitted = manifest.admit("tc03-alu32", &bytes, &limits()).unwrap();
    let contract = contract(Some("generic"), &[]);
    let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
    assert!(inspection.conforms());
    let violations = check_object(
        &baseline_profile(),
        &contract,
        &inspection,
        admitted.entry(),
    )
    .unwrap();
    let rules: Vec<&str> = violations.iter().map(|v| v.rule_id.as_str()).collect();
    assert!(
        rules.contains(&"isa.contract-forbidden-family"),
        "{rules:?}"
    );
    assert!(rules.contains(&"isa.forbidden-family"), "{rules:?}");
}

#[test]
fn check_enforces_required_families_and_license() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let manifest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-base",
            "rel",
            BASE_SHA256,
            "tc03-needy",
            "1",
            None,
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let admitted = manifest.admit("tc03-base", &bytes, &limits()).unwrap();
    let contract = contract(Some("generic"), &[]);
    let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
    let needy = profile(
        "tc03-needy",
        "1",
        Some("generic"),
        &[],
        &["base", "signed-div"],
        &["base", "signed-div"],
        &[],
        false,
    );
    let violations = check_object(&needy, &contract, &inspection, admitted.entry()).unwrap();
    assert!(violations
        .iter()
        .any(|v| v.rule_id == "isa.missing-required-family"));
    // License required: unlicensed base.o refuses, licensed lic.o admits.
    let strict = profile(
        "tc03-needy",
        "1",
        Some("generic"),
        &[],
        &["base"],
        &["base"],
        &["GPL"],
        true,
    );
    let violations = check_object(&strict, &contract, &inspection, admitted.entry()).unwrap();
    assert!(violations.iter().any(|v| v.rule_id == "license.missing"));
    let lic = repo_bytes("fixtures/bpf/isa/objects/lic.o");
    let manifest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-lic",
            "rel",
            &hex(&digest(&lic)),
            "tc03-needy",
            "1",
            Some("GPL"),
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let admitted = manifest.admit("tc03-lic", &lic, &limits()).unwrap();
    let inspection = inspect_final_object(&lic, &contract, &limits()).unwrap();
    let violations = check_object(&strict, &contract, &inspection, admitted.entry()).unwrap();
    assert!(violations.is_empty(), "{violations:?}");
    // Swapped token: MIT bytes under a GPL-only profile refuse.
    let mut mit = lic.clone();
    let start = mit.windows(4).position(|w| w == b"GPL\0").unwrap();
    mit[start..start + 4].copy_from_slice(b"MIT\0");
    let inspection = inspect_final_object(&mit, &contract, &limits()).unwrap();
    assert!(inspection.conforms(), "MIT is well-formed, just unadmitted");
    // Entry carries the MIT bytes' true hash but still declares GPL.
    let stale = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-mit",
            "rel",
            &hex(&digest(&mit)),
            "tc03-needy",
            "1",
            Some("GPL"),
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let stale_admitted = stale.admit("tc03-mit", &mit, &limits()).unwrap();
    assert_eq!(
        refusal(
            &check_object(&strict, &contract, &inspection, stale_admitted.entry()).unwrap_err()
        ),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    // Honest MIT declaration under a GPL-only profile: violation, not error.
    let honest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-mit",
            "rel",
            &hex(&digest(&mit)),
            "tc03-needy",
            "1",
            Some("MIT"),
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let honest_admitted = honest.admit("tc03-mit", &mit, &limits()).unwrap();
    let violations =
        check_object(&strict, &contract, &inspection, honest_admitted.entry()).unwrap();
    assert!(violations
        .iter()
        .any(|v| v.rule_id == "license.incompatible"));
}

#[test]
fn check_detects_attribution_mismatch_typed() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let manifest = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-base",
            "rel",
            BASE_SHA256,
            "tc03-baseline",
            "1",
            None,
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let admitted = manifest.admit("tc03-base", &bytes, &limits()).unwrap();
    let base_contract = contract(Some("generic"), &[]);
    let inspection = inspect_final_object(&bytes, &base_contract, &limits()).unwrap();
    let other_profile = profile(
        "tc03-other",
        "1",
        Some("generic"),
        &[],
        &["base"],
        &["base"],
        &[],
        false,
    );
    assert_eq!(
        refusal(
            &check_object(
                &other_profile,
                &base_contract,
                &inspection,
                admitted.entry()
            )
            .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Inspection of different bytes than the admitted entry refuses.
    let sdiv = repo_bytes("fixtures/bpf/isa/objects/sdiv.o");
    let sdiv_contract = contract(Some("v4"), &["signed-div"]);
    let sdiv_inspection = inspect_final_object(&sdiv, &sdiv_contract, &limits()).unwrap();
    assert_eq!(
        refusal(
            &check_object(
                &baseline_profile(),
                &base_contract,
                &sdiv_inspection,
                admitted.entry()
            )
            .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Kind mismatch between manifest and bytes refuses typed: the entry
    // carries the exec twin's true hash but claims kind rel.
    let kind_lie = FinalObjectManifest::from_json(
        manifest_json(&entry_json(
            "tc03-exec-twin",
            "rel",
            EXEC_TWIN_SHA256,
            "tc03-baseline",
            "1",
            None,
        ))
        .as_bytes(),
        &limits(),
    )
    .unwrap();
    let exec = repo_bytes("fixtures/bpf/isa/objects/exec-twin.o");
    let kind_admitted = kind_lie.admit("tc03-exec-twin", &exec, &limits()).unwrap();
    let exec_inspection = inspect_final_object(&exec, &base_contract, &limits()).unwrap();
    assert_eq!(exec_inspection.kind(), ObjectKind::Exec);
    assert_eq!(
        refusal(
            &check_object(
                &baseline_profile(),
                &base_contract,
                &exec_inspection,
                kind_admitted.entry()
            )
            .unwrap_err()
        ),
        (ErrorKind::Incompatible, Stage::Admission)
    );
}

#[test]
fn documented_mutants_match_exercised_ids() {
    const EXERCISED: &[&str] = &[
        "unknown-opcode",
        "truncated-stream",
        "wrong-machine",
        "truncated-file",
        "license-truncated",
        "license-duplicated",
        "license-incompatible",
        "hash-mismatch",
        "uninventoried",
        "unknown-profile-name",
        "unknown-profile-version",
        "preset-drift",
        "forbidden-family",
        "contract-forbidden-family",
        "missing-required-family",
        "license-missing",
    ];
    let mutants: serde_json::Value =
        serde_json::from_slice(&repo_bytes("fixtures/bpf/isa/mutants.json")).unwrap();
    assert_eq!(mutants["schema_version"], 1);
    assert_eq!(mutants["kind"], "tc03_isa_mutants");
    let documented: Vec<&str> = mutants["mutants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(documented.len(), EXERCISED.len());
    for id in EXERCISED {
        assert!(documented.contains(id), "mutant {id} documented");
    }
}

/// S228: a non-UTF8 entry fails naming the directory — never a bare
/// `into_string().unwrap()` panic. External R1-2: `catch_unwind`
/// instead of `should_panic`, so the fixture cleanup below is
/// reachable and the no-leak assert runs on every passing run.
#[cfg(unix)]
#[test]
fn s228_object_names_names_non_utf8_entry() {
    use std::os::unix::ffi::OsStringExt;
    let dir = std::env::temp_dir().join(format!(
        "s228-isa-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join(std::ffi::OsString::from_vec(vec![0xff, 0xfe]));
    std::fs::write(&bad, b"x").unwrap();
    let outcome = std::panic::catch_unwind(|| object_names(dir.to_str().unwrap()));
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!dir.exists(), "fixture must not leak");
    let message = match outcome {
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                payload
                    .downcast_ref::<&str>()
                    .map(|text| text.to_string())
            })
            .unwrap_or_default(),
        Ok(_) => panic!("non-UTF8 entry must panic"),
    };
    assert!(
        message.contains("is not UTF-8"),
        "unexpected panic: {message}"
    );
}
