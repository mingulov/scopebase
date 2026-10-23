// SPDX-License-Identifier: Apache-2.0
//! TT08 tail: `scopebase-select` CLI over the reviewed causal selector core.
//!
//! The GitHub workflow and the local equivalent script drive affected-check
//! selection through this CLI (`manifest`/`select`/`resolve`/`account`/`gate`)
//! so CI and local runs share one selection implementation. Fixtures under
//! `tests/fixtures/select/` are the recorded synthetic CI outcomes: selection
//! inputs plus attempt histories exercising the retry gate.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_scopebase-select");

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/select")
        .join(name)
}

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "scopebase-select-cli-{}-{}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("scopebase-select must launch")
}

fn run_ok(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "args {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn select_plan(dir: &Path, manifest: &str, requested: &str) -> serde_json::Value {
    let out = dir.join(format!("plan-{requested}.json"));
    let catalog = fixture("catalog.json");
    let manifest = fixture(manifest);
    run_ok(&[
        "select",
        "--catalog",
        catalog.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--requested",
        requested,
        "--out",
        out.to_str().unwrap(),
    ]);
    read_json(&out)
}

fn cell_ids(cells: &serde_json::Value) -> Vec<String> {
    cells
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["cell_id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn select_narrowed_cell_change_reports_denominator() {
    let dir = workdir("narrowed");
    let plan = select_plan(&dir, "manifest-cell-b.json", "mid-v1");
    assert_eq!(cell_ids(&plan["selected"]), ["cell-b"]);
    assert_eq!(cell_ids(&plan["declared"]), ["cell-a", "cell-b"]);
    assert_eq!(plan["is_full"], false);
    assert!(plan["unresolved"].as_array().unwrap().is_empty());
    assert!(plan["excluded_out_of_scope"].as_array().unwrap().is_empty());
    assert_eq!(plan["selected"][0]["change_index"], 0);
    assert_eq!(plan["selected"][0]["case_id"], "H08.mid");
}

#[test]
fn select_case_change_reaches_transitive_dependents() {
    let dir = workdir("full");
    let plan = select_plan(&dir, "manifest-case-base.json", "mid-v1");
    assert_eq!(cell_ids(&plan["selected"]), ["cell-a", "cell-b"]);
    assert_eq!(plan["is_full"], true);
    assert!(plan["unresolved"].as_array().unwrap().is_empty());
}

#[test]
fn select_unknown_change_broadens_and_never_succeeds_empty() {
    let dir = workdir("unknown");
    let plan = select_plan(&dir, "manifest-unknown.json", "mid-v1");
    assert_eq!(plan["unresolved"].as_array().unwrap().len(), 1);
    assert_eq!(plan["unresolved"][0]["boundary"], "mid-v1");
    assert!(!plan["selected"].as_array().unwrap().is_empty());
    assert_eq!(plan["is_full"], false);
}

#[test]
fn select_rejects_unknown_profile() {
    let dir = workdir("bad-profile");
    let out = dir.join("plan.json");
    let catalog = fixture("catalog.json");
    let manifest = fixture("manifest-cell-b.json");
    let result = run(&[
        "select",
        "--catalog",
        catalog.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--requested",
        "nope-v9",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert!(!out.exists());
}

#[test]
fn account_narrowed_run_cannot_attest_full() {
    let dir = workdir("account-narrowed");
    let out = dir.join("accounting.json");
    let catalog = fixture("catalog.json");
    let manifest = fixture("manifest-cell-b.json");
    let executed = fixture("executed-cell-b.json");
    let result = run(&[
        "account",
        "--catalog",
        catalog.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--requested",
        "mid-v1",
        "--executed",
        executed.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--attest-full",
    ]);
    assert!(!result.status.success());
    let accounting = read_json(&out);
    assert_eq!(accounting["status"], "complete");
    assert_eq!(accounting["scope"], "narrowed");
    assert_eq!(accounting["full_matrix_complete"], false);
    assert!(accounting["missing_selected"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn account_full_execution_attests() {
    let dir = workdir("account-full");
    let out = dir.join("accounting.json");
    let catalog = fixture("catalog.json");
    let manifest = fixture("manifest-case-base.json");
    let executed = fixture("executed-full.json");
    run_ok(&[
        "account",
        "--catalog",
        catalog.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--requested",
        "mid-v1",
        "--executed",
        executed.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--attest-full",
    ]);
    let accounting = read_json(&out);
    assert_eq!(accounting["status"], "complete");
    assert_eq!(accounting["scope"], "full");
    assert_eq!(accounting["full_matrix_complete"], true);
}

#[test]
fn gate_retry_without_resolution_stays_unresolved() {
    let dir = workdir("gate-unresolved");
    let out = dir.join("verdict.json");
    let attempts = fixture("attempts-unresolved.json");
    let result = run(&[
        "gate",
        "--attempts",
        attempts.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(2));
    let verdict = read_json(&out);
    assert_eq!(verdict["verdict"], "unresolved");
    assert_eq!(verdict["failed_attempts"], serde_json::json!([1]));
}

#[test]
fn gate_cause_fix_candidate_with_later_pass_resolves() {
    let dir = workdir("gate-resolved");
    let out = dir.join("verdict.json");
    let attempts = fixture("attempts-resolved.json");
    run_ok(&[
        "gate",
        "--attempts",
        attempts.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let verdict = read_json(&out);
    assert_eq!(verdict["verdict"], "resolved");
    assert_eq!(verdict["attempts"], 2);
}

#[test]
fn gate_infrastructure_retry_keeps_history() {
    let dir = workdir("gate-infra");
    let out = dir.join("verdict.json");
    let attempts = fixture("attempts-infra.json");
    run_ok(&[
        "gate",
        "--attempts",
        attempts.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let verdict = read_json(&out);
    assert_eq!(verdict["verdict"], "resolved");
    assert_eq!(verdict["attempts"], 2);
}

#[test]
fn manifest_derives_changes_from_changed_paths() {
    let dir = workdir("manifest");
    let impact = fixture("impact.json");
    let out = dir.join("manifest.json");
    let changed = fixture("changed-mixed.txt");
    run_ok(&[
        "manifest",
        "--impact",
        impact.to_str().unwrap(),
        "--changed",
        changed.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let manifest = read_json(&out);
    // src/mid.rs contributes its cell change; docs/ contributes none.
    assert_eq!(manifest["changes"].as_array().unwrap().len(), 1);
    assert_eq!(manifest["changes"][0]["type"], "cell");
    assert_eq!(manifest["changes"][0]["cell_id"], "cell-b");

    let out = dir.join("manifest-unmatched.json");
    let changed = fixture("changed-unmatched.txt");
    run_ok(&[
        "manifest",
        "--impact",
        impact.to_str().unwrap(),
        "--changed",
        changed.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let manifest = read_json(&out);
    // Unmatched paths broaden via the default unknown change, never vanish.
    assert_eq!(manifest["changes"].as_array().unwrap().len(), 1);
    assert_eq!(manifest["changes"][0]["type"], "unknown");
}

#[test]
fn resolve_maps_selected_cells_to_gates_or_unavailable() {
    let dir = workdir("resolve");
    let plan = select_plan(&dir, "manifest-cell-b.json", "mid-v1");
    let plan_path = dir.join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let impact = fixture("impact.json");
    let catalog = fixture("catalog.json");
    let manifest = fixture("manifest-cell-b.json");
    let out = dir.join("gates.json");
    run_ok(&[
        "resolve",
        "--catalog",
        catalog.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--requested",
        "mid-v1",
        "--plan",
        plan_path.to_str().unwrap(),
        "--impact",
        impact.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let gates = read_json(&out);
    assert!(gates["runnable"].as_array().unwrap().is_empty());
    assert_eq!(cell_ids(&gates["unavailable"]), ["cell-b"]);
    assert!(gates["unavailable"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("LOGICAL_ONLY"));
    // mid-v1's denominator intersects the selection, so its gate is affected.
    let profiles: Vec<String> = gates["profile_gates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["profile"].as_str().unwrap().to_owned())
        .collect();
    assert!(profiles.contains(&"mid-v1".to_owned()));
    assert_eq!(gates["fast_gates"].as_array().unwrap().len(), 1);
}

#[test]
fn resolve_consumes_impact_id_for_fast_and_profile_gates() {
    // TT08 fixup: the impact `id` key is consumed for BOTH fast and profile
    // gates; every emitted gate carries a uniform `gate_id`.
    let dir = workdir("resolve-id");
    let plan = select_plan(&dir, "manifest-cell-b.json", "mid-v1");
    let plan_path = dir.join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let impact = fixture("impact.json");
    let catalog = fixture("catalog.json");
    let manifest = fixture("manifest-cell-b.json");
    let out = dir.join("gates.json");
    run_ok(&[
        "resolve",
        "--catalog",
        catalog.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--requested",
        "mid-v1",
        "--plan",
        plan_path.to_str().unwrap(),
        "--impact",
        impact.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let gates = read_json(&out);
    // The profile gate_id comes from the impact `id`, not the profile name.
    let mid = gates["profile_gates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gate| gate["profile"] == "mid-v1")
        .expect("mid-v1 gate is affected");
    assert_eq!(mid["gate_id"], "mid-true");
    // Fast gates are normalized to the same uniform shape.
    let fast = &gates["fast_gates"].as_array().unwrap()[0];
    assert_eq!(fast["gate_id"], "fixture-true");
    assert_eq!(fast["id"], "fixture-true");
}
