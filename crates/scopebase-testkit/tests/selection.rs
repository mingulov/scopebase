// SPDX-License-Identifier: Apache-2.0
//! TT08 causal selection core: affected-check selector, independent selection
//! oracle, and scheduling/accounting records over the TT01 CaseCatalog graph.
//!
//! CI workflow authoring/execution is explicitly excluded (blocked on owner
//! CI-platform decision Q-TT08-1); this suite covers the pure core only.

use scopebase_testkit::select::{
    qualification_gate, AttemptOutcome, AttemptRecord, Change, ChangeManifest,
    EnvironmentAttribute, GateVerdict, RegistrationRole, ResolutionRecord, RunAccounting,
    SelectionErrorKind, SelectionLimits,
};
use scopebase_testkit::{CaseCatalog, CaseId, ProfileId};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn artifact(id: &str) -> serde_json::Value {
    json!({
        "id": id,
        "revision": 1u32,
        "path": "artifacts/x.bin",
        "sha256": SHA,
        "entrypoint": id,
    })
}

fn registration() -> serde_json::Value {
    json!({
        "executable": artifact("H08.exec"),
        "fixture": artifact("H08.fixt"),
        "oracle": artifact("H08.orac"),
        "bad_control": artifact("H08.badc"),
        "oracle_basis": "independent literal",
        "control_assertion": "wrong value fails",
    })
}

/// Diamond graph: top-v1 -> {midb-v1, midc-v1} -> base-v1; top-v1 also pulls
/// in extension feat-v1 (based on midc-v1), which gates H08.midc v1
/// conditionally. H08.orphan v1 is admitted but required by no profile.
fn diamond_catalog() -> CaseCatalog {
    let case = |id: &str, version: u32, cells: &[&str], registered: bool| {
        json!({
            "id": id,
            "family": "H08",
            "version": version,
            "implementation_status": if registered { "REGISTERED_EXECUTABLE" } else { "UNIMPLEMENTED" },
            "owners": ["TT08"],
            "obligations": [{"kind": "regression_family", "id": "H08"}],
            "required_cells": cells,
            "registration": if registered { registration() } else { json!(null) },
        })
    };
    let profile = |id: &str, reqp: &[&str], reqe: &[&str], cases: serde_json::Value| {
        json!({
            "id": id,
            "definition_state": "DRAFT",
            "requires_profiles": reqp,
            "requires_extensions": reqe,
            "required_cases": cases,
            "open_owners": ["TT08"],
        })
    };
    let req = |case_id: &str, case_version: u32, when: &[&str]| json!({"case_id": case_id, "case_version": case_version, "when_extensions": when});
    let doc = json!({
        "schema_version": 1u32,
        "catalog_revision": 1u32,
        "tasks": ["TT08"],
        "obligations": [{"kind": "regression_family", "id": "H08",
            "description": "TT08 selection", "owners": ["TT08"]}],
        "families": [{"id": "H08", "short_contract": "TT08 selection",
            "obligations": [{"kind": "regression_family", "id": "H08"}]}],
        "cells": [
            {"id": "cell-a", "tier": "T0", "description": "a", "binding": "LOGICAL_ONLY"},
            {"id": "cell-b", "tier": "T0", "description": "b", "binding": "LOGICAL_ONLY"},
            {"id": "cell-c", "tier": "T1", "description": "c", "binding": "LOGICAL_ONLY"},
            {"id": "cell-d", "tier": "T0", "description": "d", "binding": "LOGICAL_ONLY"},
            {"id": "cell-orphan", "tier": "T0", "description": "o", "binding": "LOGICAL_ONLY"},
        ],
        "cases": [
            case("H08.base", 1, &["cell-a"], true),
            case("H08.midb", 1, &["cell-b"], false),
            case("H08.midc", 1, &["cell-c"], false),
            case("H08.top", 1, &["cell-d"], false),
            case("H08.orphan", 1, &["cell-orphan"], false),
        ],
        "profiles": [
            profile("base-v1", &[], &[], json!([req("H08.base", 1, &[])])),
            profile("midb-v1", &["base-v1"], &[], json!([req("H08.midb", 1, &[])])),
            profile("midc-v1", &["base-v1"], &[],
                json!([req("H08.midc", 1, &["feat-v1"])])),
            profile("top-v1", &["midb-v1", "midc-v1"], &["feat-v1"],
                json!([req("H08.top", 1, &[])])),
        ],
        "extensions": [
            {"id": "feat-v1", "profile": "midc-v1", "requires_profiles": [],
             "requires_tasks": [], "required_cases": []},
        ],
    });
    CaseCatalog::load(
        &serde_json::to_vec(&doc).unwrap(),
        scopebase_testkit::CatalogLimits::default(),
    )
    .expect("diamond catalog must admit")
}

fn pid(s: &str) -> ProfileId {
    ProfileId::parse(s).unwrap()
}

fn cid(s: &str) -> CaseId {
    CaseId::parse(s).unwrap()
}

fn manifest(changes: Vec<Change>) -> ChangeManifest {
    ChangeManifest::new(changes)
}

fn cells_of(plan: &scopebase_testkit::select::SelectionPlan) -> Vec<String> {
    let mut out: Vec<String> = plan
        .selected()
        .iter()
        .map(|c| c.key().cell_id().to_owned())
        .collect();
    out.sort();
    out
}

fn top_request() -> Vec<ProfileId> {
    vec![pid("top-v1")]
}

#[test]
fn dependency_change_selects_transitive_dependents() {
    let catalog = diamond_catalog();
    let m = manifest(vec![Change::case(cid("H08.base"), 1)]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    assert_eq!(cells_of(&plan), ["cell-a", "cell-b", "cell-c", "cell-d"]);
    assert!(plan.is_full_selection());
    assert!(!plan.has_unresolved());
}

#[test]
fn leaf_change_selects_only_itself_and_dependents() {
    let catalog = diamond_catalog();
    let m = manifest(vec![Change::case(cid("H08.midb"), 1)]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    // cell-b (own check) plus cell-d (top-v1 depends on midb-v1); the sibling
    // branch and the base contract are unaffected.
    assert_eq!(cells_of(&plan), ["cell-b", "cell-d"]);
    assert!(!plan.is_full_selection());
}

#[test]
fn conditional_requirement_is_conservative() {
    let catalog = diamond_catalog();
    // H08.midc v1 is required only when feat-v1 is active; the condition may
    // activate, so a change must still select the dependent branch.
    let m = manifest(vec![Change::case(cid("H08.midc"), 1)]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    assert_eq!(cells_of(&plan), ["cell-c", "cell-d"]);
}

#[test]
fn fixture_role_change_invalidates_dependent_verdicts() {
    let catalog = diamond_catalog();
    // A fixture artifact change without production changes invalidates every
    // dependent verdict (TT08 plan line 30).
    let m = manifest(vec![Change::registration_role(
        cid("H08.base"),
        1,
        RegistrationRole::Fixture,
    )]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    assert_eq!(cells_of(&plan), ["cell-a", "cell-b", "cell-c", "cell-d"]);
    let m = manifest(vec![Change::registration_role(
        cid("H08.base"),
        1,
        RegistrationRole::Oracle,
    )]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    assert_eq!(cells_of(&plan), ["cell-a", "cell-b", "cell-c", "cell-d"]);
}

#[test]
fn cell_change_selects_requiring_cases_and_dependents() {
    let catalog = diamond_catalog();
    let m = manifest(vec![Change::cell("cell-c")]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    assert_eq!(cells_of(&plan), ["cell-c", "cell-d"]);
}

#[test]
fn out_of_scope_impact_is_excluded_reviewably_not_selected() {
    let catalog = diamond_catalog();
    // H08.orphan v1 is required by no profile, so it cannot affect the
    // top-v1 request; the impact is recorded as a reviewable exclusion
    // rather than silently dropped or silently selected.
    let m = manifest(vec![Change::case(cid("H08.orphan"), 1)]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    assert!(plan.selected().is_empty());
    assert!(!plan.is_full_selection());
    assert!(!plan.has_unresolved());
    assert!(plan.excluded_out_of_scope().iter().any(|n| matches!(
        n,
        scopebase_testkit::select::OutOfScopeNode::Case(id, 1)
            if id.as_str() == "H08.orphan"
    )));
    // Same treatment for an affected profile outside the narrowed request.
    let m = manifest(vec![Change::case(cid("H08.top"), 1)]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &[pid("midb-v1")],
        &SelectionLimits::default(),
    )
    .unwrap();
    assert!(plan.selected().is_empty());
    assert!(!plan.excluded_out_of_scope().is_empty());
}

#[test]
fn unknown_impact_broadens_boundary_and_cannot_be_empty() {
    let catalog = diamond_catalog();
    let m = manifest(vec![Change::unknown(
        Some(pid("midb-v1")),
        "compiler flag provenance unclear",
    )]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    // Broadens to the named boundary closure (midb-v1 + base-v1) plus every
    // profile depending on it (midc-v1 via base-v1, top-v1). Unknown impact
    // cannot claim containment, so dependents are included.
    assert_eq!(cells_of(&plan), ["cell-a", "cell-b", "cell-c", "cell-d"]);
    assert!(plan.has_unresolved());
    assert_eq!(plan.unresolved().len(), 1);
    assert!(!plan.selected().is_empty());
    // The broadened impact is unresolved, so the plan never reports Full even
    // though every denominator cell is selected.
    assert!(!plan.is_full_selection());

    // Whole-catalog unknown impact over a narrowed request selects the full
    // requested denominator; it cannot return empty success. The selection
    // still never reports Full: unresolved impact cannot attest coverage.
    let m = manifest(vec![Change::unknown(
        None,
        "dependency tree changed opaquely",
    )]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &[pid("midb-v1")],
        &SelectionLimits::default(),
    )
    .unwrap();
    assert_eq!(cells_of(&plan), ["cell-a", "cell-b"]);
    assert!(!plan.is_full_selection());
    assert!(plan.has_unresolved());
}

#[test]
fn environment_change_broadens_named_boundary() {
    let catalog = diamond_catalog();
    let m = manifest(vec![Change::environment(
        EnvironmentAttribute::Compiler,
        Some(pid("midb-v1")),
    )]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    assert_eq!(cells_of(&plan), ["cell-a", "cell-b", "cell-c", "cell-d"]);
    assert!(plan.has_unresolved());
}

#[test]
fn empty_manifest_selects_nothing_without_claiming_completeness() {
    let catalog = diamond_catalog();
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &manifest(vec![]),
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    assert!(plan.selected().is_empty());
    assert!(!plan.is_full_selection());
    assert!(!plan.has_unresolved());
}

#[test]
fn explanations_trace_cause_chain_to_each_cell() {
    let catalog = diamond_catalog();
    let m = manifest(vec![Change::case(cid("H08.base"), 1)]);
    let plan = scopebase_testkit::select::select_affected(
        &catalog,
        &m,
        &top_request(),
        &SelectionLimits::default(),
    )
    .unwrap();
    for cell in plan.selected() {
        assert_eq!(cell.explanation().change_index(), 0);
        assert!(!cell.explanation().path().is_empty());
    }
}

#[test]
fn manifest_and_request_are_validated() {
    let catalog = diamond_catalog();
    let limits = SelectionLimits::default();
    // Unknown request root.
    let err = scopebase_testkit::select::select_affected(
        &catalog,
        &manifest(vec![Change::case(cid("H08.base"), 1)]),
        &[pid("nope-v1")],
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.kind(), SelectionErrorKind::UnknownProfile);
    // Exact revision matching: H08.base v2 was never admitted.
    let err = scopebase_testkit::select::select_affected(
        &catalog,
        &manifest(vec![Change::case(cid("H08.base"), 2)]),
        &top_request(),
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.kind(), SelectionErrorKind::UnknownChangeTarget);
    // Unknown cell.
    let err = scopebase_testkit::select::select_affected(
        &catalog,
        &manifest(vec![Change::cell("cell-missing")]),
        &top_request(),
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.kind(), SelectionErrorKind::UnknownChangeTarget);
    // Empty request cannot silently succeed with an empty denominator.
    let err = scopebase_testkit::select::select_affected(
        &catalog,
        &manifest(vec![Change::case(cid("H08.base"), 1)]),
        &[],
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.kind(), SelectionErrorKind::InvalidManifest);
    // Empty reason cannot broaden silently.
    let err = scopebase_testkit::select::select_affected(
        &catalog,
        &manifest(vec![Change::unknown(Some(pid("base-v1")), "")]),
        &top_request(),
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.kind(), SelectionErrorKind::InvalidManifest);
    // Bounds are enforced.
    let tight = SelectionLimits {
        max_changes: 1,
        ..SelectionLimits::default()
    };
    let err = scopebase_testkit::select::select_affected(
        &catalog,
        &manifest(vec![
            Change::case(cid("H08.base"), 1),
            Change::case(cid("H08.top"), 1),
        ]),
        &top_request(),
        &tight,
    )
    .unwrap_err();
    assert_eq!(err.kind(), SelectionErrorKind::LimitExceeded);
}

#[test]
fn oracle_agrees_with_selector_on_change_battery() {
    use scopebase_testkit::select::{check_agreement, expected_selection};
    let catalog = diamond_catalog();
    let limits = SelectionLimits::default();
    let manifests = vec![
        manifest(vec![]),
        manifest(vec![Change::case(cid("H08.base"), 1)]),
        manifest(vec![Change::case(cid("H08.midb"), 1)]),
        manifest(vec![Change::case(cid("H08.midc"), 1)]),
        manifest(vec![Change::case(cid("H08.top"), 1)]),
        manifest(vec![Change::case(cid("H08.orphan"), 1)]),
        manifest(vec![Change::cell("cell-a")]),
        manifest(vec![Change::profile(pid("midc-v1"))]),
        manifest(vec![Change::extension(pid("feat-v1"))]),
        manifest(vec![Change::obligation("regression_family", "H08")]),
        manifest(vec![Change::registration_role(
            cid("H08.base"),
            1,
            RegistrationRole::BadControl,
        )]),
        manifest(vec![Change::unknown(
            Some(pid("base-v1")),
            "opaque source edit",
        )]),
        manifest(vec![Change::unknown(None, "opaque world")]),
        manifest(vec![Change::environment(
            EnvironmentAttribute::Features,
            None,
        )]),
        manifest(vec![
            Change::case(cid("H08.midb"), 1),
            Change::cell("cell-d"),
        ]),
    ];
    for m in &manifests {
        let plan = scopebase_testkit::select::select_affected(&catalog, m, &top_request(), &limits)
            .unwrap();
        let expected = expected_selection(&catalog, m, &top_request(), &limits).unwrap();
        check_agreement(&plan, &expected).expect("oracle must agree with selector");
    }
}

#[test]
fn mutant_dropped_dependent_fails_oracle() {
    use scopebase_testkit::select::{check_agreement, expected_selection};
    let catalog = diamond_catalog();
    let limits = SelectionLimits::default();
    let m = manifest(vec![Change::case(cid("H08.base"), 1)]);
    let plan =
        scopebase_testkit::select::select_affected(&catalog, &m, &top_request(), &limits).unwrap();
    let full_expected = expected_selection(&catalog, &m, &top_request(), &limits).unwrap();
    assert_eq!(plan.selected().len(), 4);
    // Mutant selector output: only the midb branch, as if the selector had
    // dropped the base cell and the midc dependent for this same manifest.
    let mutant = scopebase_testkit::select::select_affected(
        &catalog,
        &manifest(vec![Change::case(cid("H08.midb"), 1)]),
        &top_request(),
        &limits,
    )
    .unwrap();
    let disagreement = check_agreement(&mutant, &full_expected).unwrap_err();
    let missing: Vec<&str> = disagreement.missing().iter().map(|k| k.cell_id()).collect();
    assert_eq!(missing, ["cell-a", "cell-c"]);
    assert!(disagreement.extra().is_empty());
    // Mutant in the other direction: a plan reporting the full base-change
    // set where the oracle expects only the narrowed midb branch is caught
    // as over-selection.
    let narrow_expected = expected_selection(
        &catalog,
        &manifest(vec![Change::case(cid("H08.midb"), 1)]),
        &top_request(),
        &limits,
    )
    .unwrap();
    let disagreement = check_agreement(&plan, &narrow_expected).unwrap_err();
    assert!(disagreement.missing().is_empty());
    let extra: Vec<&str> = disagreement.extra().iter().map(|k| k.cell_id()).collect();
    assert_eq!(extra, ["cell-a", "cell-c"]);
}

fn selected_keys(
    plan: &scopebase_testkit::select::SelectionPlan,
) -> BTreeSet<scopebase_testkit::select::CellKey> {
    plan.selected().iter().map(|c| c.key().clone()).collect()
}

fn evidence_for(
    plan: &scopebase_testkit::select::SelectionPlan,
) -> BTreeMap<scopebase_testkit::select::CellKey, scopebase_testkit::select::EvidenceRef> {
    plan.declared()
        .iter()
        .map(|k| {
            (
                k.clone(),
                scopebase_testkit::select::EvidenceRef::new(&format!(
                    "receipt:{}:{}",
                    k.case_id().as_str(),
                    k.cell_id()
                ))
                .unwrap(),
            )
        })
        .collect()
}

#[test]
fn accounting_completes_only_when_denominator_executes() {
    use scopebase_testkit::select::{AccountingScope, AccountingStatus};
    let catalog = diamond_catalog();
    let limits = SelectionLimits::default();
    // Full selection, fully executed: complete.
    let m = manifest(vec![Change::case(cid("H08.base"), 1)]);
    let plan =
        scopebase_testkit::select::select_affected(&catalog, &m, &top_request(), &limits).unwrap();
    let accounting = RunAccounting::account(&plan, &selected_keys(&plan), &evidence_for(&plan));
    assert_eq!(accounting.status(), AccountingStatus::Complete);
    assert_eq!(accounting.scope(), AccountingScope::Full);
    assert!(accounting.full_matrix_complete());
    assert!(accounting.missing_selected().is_empty());
    assert!(accounting.unchanged_missing_evidence().is_empty());
    accounting
        .attest_complete()
        .expect("full execution attests");

    // Narrowed selection, fully executed: selected work is complete but the
    // matrix is not; status and scope are separate assertions.
    let m = manifest(vec![Change::case(cid("H08.midb"), 1)]);
    let plan =
        scopebase_testkit::select::select_affected(&catalog, &m, &top_request(), &limits).unwrap();
    let accounting = RunAccounting::account(&plan, &selected_keys(&plan), &evidence_for(&plan));
    assert_eq!(accounting.status(), AccountingStatus::Complete);
    assert_eq!(accounting.scope(), AccountingScope::Narrowed);
    assert!(!accounting.full_matrix_complete());
    let err = accounting.attest_complete().unwrap_err();
    assert_eq!(
        err.kind(),
        scopebase_testkit::select::AccountingErrorKind::IncompleteDenominator
    );
    // Unchanged required gates are enumerated explicitly with inherited evidence.
    let unchanged: Vec<&str> = accounting
        .unchanged_with_evidence()
        .iter()
        .map(|(k, _)| k.cell_id())
        .collect();
    assert_eq!(unchanged, ["cell-a", "cell-c"]);
}

#[test]
fn mutant_falsely_claimed_full_result_fails() {
    // Mutant: an accounting that reports full-matrix completion for a narrowed
    // run (e.g. by reusing a full-selection summary unchanged) must fail its
    // semantic assertion instead of merely differing in setup.
    let catalog = diamond_catalog();
    let limits = SelectionLimits::default();
    let m = manifest(vec![Change::case(cid("H08.midb"), 1)]);
    let plan =
        scopebase_testkit::select::select_affected(&catalog, &m, &top_request(), &limits).unwrap();
    let accounting = RunAccounting::account(&plan, &selected_keys(&plan), &evidence_for(&plan));
    assert!(!accounting.full_matrix_complete());
    assert!(accounting.attest_complete().is_err());
    // Oracle-starved accounting: no executed results at all. Nothing is
    // complete, every selected cell is missing, and attestation fails.
    let empty = BTreeSet::new();
    let accounting = RunAccounting::account(&plan, &empty, &evidence_for(&plan));
    assert_eq!(
        accounting.status(),
        scopebase_testkit::select::AccountingStatus::Incomplete
    );
    assert_eq!(accounting.missing_selected().len(), 2);
    assert!(!accounting.full_matrix_complete());
    assert!(accounting.attest_complete().is_err());
}

#[test]
fn accounting_names_missing_rows_and_missing_inherited_evidence() {
    let catalog = diamond_catalog();
    let limits = SelectionLimits::default();
    let m = manifest(vec![Change::case(cid("H08.midb"), 1)]);
    let plan =
        scopebase_testkit::select::select_affected(&catalog, &m, &top_request(), &limits).unwrap();
    // Execute only cell-b; cell-d is a missing required row.
    let mut executed = BTreeSet::new();
    for cell in plan.selected() {
        if cell.key().cell_id() == "cell-b" {
            executed.insert(cell.key().clone());
        }
    }
    assert_eq!(executed.len(), 1);
    // Inherit evidence for cell-a only; cell-c lacks inherited evidence.
    let mut inherited = BTreeMap::new();
    for key in plan.declared() {
        if key.cell_id() == "cell-a" {
            inherited.insert(
                key.clone(),
                scopebase_testkit::select::EvidenceRef::new("receipt:H08.base:cell-a").unwrap(),
            );
        }
    }
    let accounting = RunAccounting::account(&plan, &executed, &inherited);
    assert_eq!(
        accounting.status(),
        scopebase_testkit::select::AccountingStatus::Incomplete
    );
    let missing: Vec<&str> = accounting
        .missing_selected()
        .iter()
        .map(|k| k.cell_id())
        .collect();
    assert_eq!(missing, ["cell-d"]);
    let no_evidence: Vec<&str> = accounting
        .unchanged_missing_evidence()
        .iter()
        .map(|k| k.cell_id())
        .collect();
    assert_eq!(no_evidence, ["cell-c"]);
    assert!(!accounting.full_matrix_complete());
}

#[test]
fn retry_after_semantic_failure_stays_unresolved_until_recorded() {
    // A prior semantic failure followed by a successful retry: qualification
    // remains unresolved until an explicit reviewed cause/fix/new candidate
    // is recorded. Provisioning retries retain attempt history without
    // pretending a semantic failure was infrastructure.
    let attempts = vec![
        AttemptRecord::new(1, AttemptOutcome::InfrastructureFailure, "lease denied").unwrap(),
        AttemptRecord::new(2, AttemptOutcome::SemanticFailure, "wrong value").unwrap(),
        AttemptRecord::new(3, AttemptOutcome::Pass, "green retry").unwrap(),
    ];
    match qualification_gate(&attempts, &[]).unwrap() {
        GateVerdict::Unresolved { failed_attempts } => assert_eq!(failed_attempts, [2]),
        GateVerdict::Resolved { .. } => panic!("retry must not erase semantic failure"),
    }
    let resolutions =
        vec![
            ResolutionRecord::new(2, "oracle literal stale", "refresh literal", "candidate-b")
                .unwrap(),
        ];
    match qualification_gate(&attempts, &resolutions).unwrap() {
        GateVerdict::Resolved { attempts: n } => assert_eq!(n, 3),
        GateVerdict::Unresolved { .. } => panic!("explicit resolution must resolve"),
    }
    // Pure infrastructure history with a later pass resolves, retaining all
    // three attempts in the record.
    let infra = vec![
        AttemptRecord::new(1, AttemptOutcome::InfrastructureFailure, "lease denied").unwrap(),
        AttemptRecord::new(2, AttemptOutcome::Pass, "green").unwrap(),
    ];
    match qualification_gate(&infra, &[]).unwrap() {
        GateVerdict::Resolved { attempts: n } => assert_eq!(n, 2),
        GateVerdict::Unresolved { .. } => panic!("infra-only history must not block"),
    }
    // Malformed attempt numbering is rejected, not silently accepted.
    let bad = vec![AttemptRecord::new(2, AttemptOutcome::Pass, "skipped one").unwrap()];
    assert!(qualification_gate(&bad, &[]).is_err());
    // An empty history cannot resolve anything.
    assert!(qualification_gate(&[], &[]).is_err());
    // An empty resolution cannot close a semantic failure.
    let failing = vec![AttemptRecord::new(1, AttemptOutcome::SemanticFailure, "wrong").unwrap()];
    let hollow = vec![ResolutionRecord::new(1, "", "", "").unwrap()];
    assert!(qualification_gate(&failing, &hollow).is_err());
}

/// Two-profile cross-extension catalog (F1 counterexample): `p1-v1` carries
/// extension `featx-v1` but never declares the conditional case; `p2-v1`
/// declares `H09.cond` conditional on `featx-v1` without carrying the
/// extension. Neither profile's own plan activates the case, so `cell-cond`
/// is in no denominator; a union-extension activation rule leaks it into
/// selection while oracle agreement still passes.
fn cross_extension_catalog() -> CaseCatalog {
    let case = |id: &str, version: u32, cells: &[&str]| {
        json!({
            "id": id,
            "family": "H09",
            "version": version,
            "implementation_status": "UNIMPLEMENTED",
            "owners": ["TT08"],
            "obligations": [{"kind": "regression_family", "id": "H09"}],
            "required_cells": cells,
            "registration": json!(null),
        })
    };
    let profile = |id: &str, reqp: &[&str], reqe: &[&str], cases: serde_json::Value| {
        json!({
            "id": id,
            "definition_state": "DRAFT",
            "requires_profiles": reqp,
            "requires_extensions": reqe,
            "required_cases": cases,
            "open_owners": ["TT08"],
        })
    };
    let req = |case_id: &str, case_version: u32, when: &[&str]| json!({"case_id": case_id, "case_version": case_version, "when_extensions": when});
    let doc = json!({
        "schema_version": 1u32,
        "catalog_revision": 1u32,
        "tasks": ["TT08"],
        "obligations": [{"kind": "regression_family", "id": "H09",
            "description": "TT08 cross-extension", "owners": ["TT08"]}],
        "families": [{"id": "H09", "short_contract": "TT08 cross-extension",
            "obligations": [{"kind": "regression_family", "id": "H09"}]}],
        "cells": [
            {"id": "cell-a", "tier": "T0", "description": "a", "binding": "LOGICAL_ONLY"},
            {"id": "cell-1", "tier": "T0", "description": "one", "binding": "LOGICAL_ONLY"},
            {"id": "cell-cond", "tier": "T1", "description": "cond", "binding": "LOGICAL_ONLY"},
        ],
        "cases": [
            case("H09.base", 1, &["cell-a"]),
            case("H09.one", 1, &["cell-1"]),
            case("H09.cond", 1, &["cell-cond"]),
        ],
        "profiles": [
            profile("base-v1", &[], &[], json!([req("H09.base", 1, &[])])),
            profile("p1-v1", &["base-v1"], &["featx-v1"],
                json!([req("H09.one", 1, &[])])),
            profile("p2-v1", &["base-v1"], &[],
                json!([req("H09.cond", 1, &["featx-v1"])])),
        ],
        "extensions": [
            {"id": "featx-v1", "profile": "base-v1", "requires_profiles": [],
             "requires_tasks": [], "required_cases": []},
        ],
    });
    CaseCatalog::load(
        &serde_json::to_vec(&doc).unwrap(),
        scopebase_testkit::CatalogLimits::default(),
    )
    .expect("cross-extension catalog must admit")
}

#[test]
fn conditional_activation_is_per_profile_not_union() {
    use scopebase_testkit::select::{check_agreement, expected_selection};
    let catalog = cross_extension_catalog();
    let limits = SelectionLimits::default();
    let requested = vec![pid("p1-v1"), pid("p2-v1")];
    // Independently specified expectation, hand-derived from the fixture
    // graph (not from implementation output): the union denominator is
    // {cell-a, cell-1} because H09.cond is active in neither profile's own
    // plan (p1-v1 never declares it; p2-v1 lacks featx-v1).
    let m = manifest(vec![Change::case(cid("H09.base"), 1)]);
    let plan =
        scopebase_testkit::select::select_affected(&catalog, &m, &requested, &limits).unwrap();
    assert_eq!(cells_of(&plan), ["cell-1", "cell-a"]);
    // Selected cells must stay inside the declaring profiles' denominator.
    let declared: BTreeSet<String> = plan
        .declared()
        .iter()
        .map(|k| k.cell_id().to_owned())
        .collect();
    assert_eq!(
        declared,
        BTreeSet::from(["cell-a".to_owned(), "cell-1".to_owned()])
    );
    for cell in plan.selected() {
        assert!(
            declared.contains(cell.key().cell_id()),
            "selected cell outside every profile denominator: {}",
            cell.key().cell_id()
        );
    }
    // The conditional case's own change selects nothing: no requested
    // profile requires the inactive case.
    let m = manifest(vec![Change::case(cid("H09.cond"), 1)]);
    let plan =
        scopebase_testkit::select::select_affected(&catalog, &m, &requested, &limits).unwrap();
    assert!(plan.selected().is_empty());
    assert!(!plan.is_full_selection());
    // The oracle follows the same per-profile rule, so agreement holds.
    for m in [
        manifest(vec![Change::case(cid("H09.base"), 1)]),
        manifest(vec![Change::case(cid("H09.cond"), 1)]),
        manifest(vec![Change::case(cid("H09.one"), 1)]),
    ] {
        let plan =
            scopebase_testkit::select::select_affected(&catalog, &m, &requested, &limits).unwrap();
        let expected = expected_selection(&catalog, &m, &requested, &limits).unwrap();
        check_agreement(&plan, &expected).expect("oracle must agree with selector");
    }
}

#[test]
fn retry_gate_requires_qualifying_pass_for_resolution() {
    // A lone infrastructure failure with zero passes stays unresolved.
    let infra_only =
        vec![AttemptRecord::new(1, AttemptOutcome::InfrastructureFailure, "lease denied").unwrap()];
    match qualification_gate(&infra_only, &[]).unwrap() {
        GateVerdict::Unresolved { failed_attempts } => assert_eq!(failed_attempts, [1]),
        GateVerdict::Resolved { .. } => panic!("zero-pass history must not resolve"),
    }
    // A semantic failure with a recorded resolution but zero passes stays
    // unresolved: the resolution string alone evidences no passing candidate.
    let failing =
        vec![AttemptRecord::new(1, AttemptOutcome::SemanticFailure, "wrong value").unwrap()];
    let resolutions =
        vec![ResolutionRecord::new(1, "stale literal", "refresh literal", "candidate-b").unwrap()];
    match qualification_gate(&failing, &resolutions).unwrap() {
        GateVerdict::Unresolved { failed_attempts } => assert_eq!(failed_attempts, [1]),
        GateVerdict::Resolved { .. } => {
            panic!("resolution without a passing attempt must not resolve")
        }
    }
    // A pass that predates the failure does not qualify its resolution: the
    // qualifying pass must be bound to the resolved candidate (a later
    // attempt number, evidencing the fix).
    let attempts = vec![
        AttemptRecord::new(1, AttemptOutcome::Pass, "green before").unwrap(),
        AttemptRecord::new(2, AttemptOutcome::SemanticFailure, "regressed").unwrap(),
    ];
    let resolutions = vec![ResolutionRecord::new(2, "cause", "fix", "candidate-c").unwrap()];
    match qualification_gate(&attempts, &resolutions).unwrap() {
        GateVerdict::Unresolved { failed_attempts } => assert_eq!(failed_attempts, [2]),
        GateVerdict::Resolved { .. } => panic!("pre-failure pass must not qualify the fix"),
    }
}

/// Empty-denominator catalog (F3): `empty-v1` is a DRAFT profile with zero
/// required cases (admitted: only Frozen rejects an empty required set), and
/// `cond-only-v1` requires only a case conditional on an extension it never
/// carries. Both yield an admitted, reachable, empty denominator.
fn empty_denominator_catalog() -> CaseCatalog {
    let doc = json!({
        "schema_version": 1u32,
        "catalog_revision": 1u32,
        "tasks": ["TT08"],
        "obligations": [{"kind": "regression_family", "id": "H10",
            "description": "TT08 empty denominator", "owners": ["TT08"]}],
        "families": [{"id": "H10", "short_contract": "TT08 empty denominator",
            "obligations": [{"kind": "regression_family", "id": "H10"}]}],
        "cells": [
            {"id": "cell-a", "tier": "T0", "description": "a", "binding": "LOGICAL_ONLY"},
        ],
        "cases": [
            {"id": "H10.base", "family": "H10", "version": 1u32,
             "implementation_status": "UNIMPLEMENTED", "owners": ["TT08"],
             "obligations": [{"kind": "regression_family", "id": "H10"}],
             "required_cells": ["cell-a"], "registration": json!(null)},
        ],
        "profiles": [
            {"id": "empty-v1", "definition_state": "DRAFT",
             "requires_profiles": [], "requires_extensions": [],
             "required_cases": [], "open_owners": ["TT08"]},
            {"id": "cond-only-v1", "definition_state": "DRAFT",
             "requires_profiles": [], "requires_extensions": [],
             "required_cases": [
                {"case_id": "H10.base", "case_version": 1u32,
                 "when_extensions": ["featy-v1"]},
             ],
             "open_owners": ["TT08"]},
        ],
        "extensions": [
            {"id": "featy-v1", "profile": "empty-v1", "requires_profiles": [],
             "requires_tasks": [], "required_cases": []},
        ],
    });
    CaseCatalog::load(
        &serde_json::to_vec(&doc).unwrap(),
        scopebase_testkit::CatalogLimits::default(),
    )
    .expect("empty-denominator catalog must admit")
}

#[test]
fn empty_denominator_never_reports_full_or_attests() {
    use scopebase_testkit::select::{AccountingScope, AccountingStatus};
    let catalog = empty_denominator_catalog();
    let limits = SelectionLimits::default();
    for root in ["empty-v1", "cond-only-v1"] {
        let requested = vec![pid(root)];
        // Even an explicit self-change selects nothing from nothing, and the
        // vacuous coverage must not report Full or attest complete.
        let m = manifest(vec![Change::profile(pid(root))]);
        let plan =
            scopebase_testkit::select::select_affected(&catalog, &m, &requested, &limits).unwrap();
        assert!(
            plan.declared().is_empty(),
            "{root}: denominator must be empty"
        );
        assert!(plan.selected().is_empty());
        assert!(
            !plan.is_full_selection(),
            "{root}: empty denominator must not be Full"
        );
        let accounting = RunAccounting::account(&plan, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(accounting.status(), AccountingStatus::Complete);
        assert_eq!(accounting.scope(), AccountingScope::Narrowed);
        assert!(!accounting.full_matrix_complete());
        accounting
            .attest_complete()
            .expect_err("empty denominator must not attest complete");
    }
}

#[test]
fn unresolved_selection_never_reports_full_or_attests() {
    use scopebase_testkit::select::{AccountingScope, AccountingStatus};
    let catalog = diamond_catalog();
    let limits = SelectionLimits::default();
    // Whole-request broadening selects the full requested denominator, but
    // the impact is unresolved: never Full, never complete-attested.
    let m = manifest(vec![Change::unknown(None, "opaque world")]);
    let plan = scopebase_testkit::select::select_affected(&catalog, &m, &[pid("midb-v1")], &limits)
        .unwrap();
    assert_eq!(cells_of(&plan), ["cell-a", "cell-b"]);
    assert!(plan.has_unresolved());
    assert!(!plan.is_full_selection());
    let accounting = RunAccounting::account(&plan, &selected_keys(&plan), &evidence_for(&plan));
    assert_eq!(accounting.status(), AccountingStatus::Complete);
    assert_eq!(accounting.scope(), AccountingScope::Narrowed);
    assert!(!accounting.full_matrix_complete());
    accounting
        .attest_complete()
        .expect_err("unresolved selection must not attest complete");
}

/// Two profiles sharing one case and one cell: the duplicate must not
/// consume cap twice.
fn shared_cell_catalog() -> CaseCatalog {
    let doc = json!({
        "schema_version": 1u32,
        "catalog_revision": 1u32,
        "tasks": ["TT08"],
        "obligations": [{"kind": "regression_family", "id": "H08",
            "description": "shared cell", "owners": ["TT08"]}],
        "families": [{"id": "H08", "short_contract": "shared cell",
            "obligations": [{"kind": "regression_family", "id": "H08"}]}],
        "cells": [
            {"id": "cell-s", "tier": "T0", "description": "s", "binding": "LOGICAL_ONLY"},
        ],
        "cases": [
            {"id": "H08.shared", "family": "H08", "version": 1u32,
             "implementation_status": "UNIMPLEMENTED", "owners": ["TT08"],
             "obligations": [{"kind": "regression_family", "id": "H08"}],
             "required_cells": ["cell-s"], "registration": null},
        ],
        "profiles": [
            {"id": "pa-v1", "definition_state": "DRAFT",
             "requires_profiles": [], "requires_extensions": [],
             "required_cases": [{"case_id": "H08.shared", "case_version": 1u32,
                                 "when_extensions": []}],
             "open_owners": ["TT08"]},
            {"id": "pb-v1", "definition_state": "DRAFT",
             "requires_profiles": [], "requires_extensions": [],
             "required_cases": [{"case_id": "H08.shared", "case_version": 1u32,
                                 "when_extensions": []}],
             "open_owners": ["TT08"]},
        ],
        "extensions": [],
    });
    CaseCatalog::load(
        &serde_json::to_vec(&doc).unwrap(),
        scopebase_testkit::CatalogLimits::default(),
    )
    .expect("shared-cell catalog must admit")
}

/// S222: the oracle cap must not count duplicates. One cell reachable
/// via two affected owners with `max_selected_cells = 1` succeeds in
/// the selector (its guard skips keys already present); the oracle
/// must agree instead of erroring at capacity.
/// Pre-fix the oracle returned LimitExceeded on the second owner.
#[test]
fn s222_oracle_cap_ignores_duplicate_cells() {
    use scopebase_testkit::select::{check_agreement, expected_selection};
    let catalog = shared_cell_catalog();
    let limits = SelectionLimits {
        max_selected_cells: 1,
        ..SelectionLimits::default()
    };
    let m = manifest(vec![Change::cell("cell-s")]);
    let requested = vec![pid("pa-v1"), pid("pb-v1")];
    let plan =
        scopebase_testkit::select::select_affected(&catalog, &m, &requested, &limits).unwrap();
    let expected = expected_selection(&catalog, &m, &requested, &limits).unwrap();
    check_agreement(&plan, &expected).expect("oracle must agree with selector");
    assert_eq!(expected.len(), 1);
}
