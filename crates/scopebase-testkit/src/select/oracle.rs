// SPDX-License-Identifier: Apache-2.0
//! TT08 selection oracle: independent expected-set computation.
//!
//! [`expected_selection`] recomputes the affected cell set by forward
//! per-owner closure intersection: every profile and extension is expanded
//! forward over `graph_edges` plus its declared cases/cells/obligations
//! (conditions ignored for reachability), and an owner is affected when its
//! forward closure intersects the change's trigger set. The selector instead
//! walks dependents from change targets over a reverse index. The two share
//! only mechanical input validation, the per-requesting-profile condition
//! rule and cell-key expansion; the affected-owner derivation is independent.
//!
//! [`check_agreement`] compares a selector plan against the oracle set and
//! names dropped (`missing`) and invented (`extra`) cells. A selector mutant
//! that drops a dependent fails here after valid setup.

use super::manifest::{Change, ChangeManifest};
use super::selector::{
    CellKey, Node, SelectionError, SelectionLimits, SelectionPlan, forward_closure,
    owner_active_cases, validated_inputs,
};
use crate::{CaseCatalog, CaseId, ProfileId};
use std::collections::BTreeSet;

/// Trigger sets are compared against forward owner closures. Profiles and
/// extensions share one closure shape: reachable owners plus declared
/// cases/cells/obligations.
struct ForwardClosure {
    owners: BTreeSet<ProfileId>,
    cases: BTreeSet<(CaseId, u32)>,
    cells: BTreeSet<String>,
    obligations: BTreeSet<(String, String)>,
}

fn owner_closure(catalog: &CaseCatalog, owner: &ProfileId) -> ForwardClosure {
    let mut owners = BTreeSet::new();
    let mut todo = vec![owner.clone()];
    while let Some(next) = todo.pop() {
        if !owners.insert(next.clone()) {
            continue;
        }
        if catalog.profiles.contains_key(&next) || catalog.extensions.contains_key(&next) {
            todo.extend(catalog.graph_edges(&next));
        }
    }
    let mut cases = BTreeSet::new();
    let mut cells = BTreeSet::new();
    let mut obligations = BTreeSet::new();
    for id in &owners {
        let entries: &[crate::RequiredCaseSpec] = if let Some(p) = catalog.profiles.get(id) {
            &p.required_cases
        } else if let Some(e) = catalog.extensions.get(id) {
            &e.required_cases
        } else {
            continue;
        };
        // Reachability ignores conditions: a condition may activate.
        for r in entries {
            cases.insert((r.case_id.clone(), r.case_version));
        }
    }
    for (case_id, case_version) in &cases {
        if let Some(case) = catalog.cases.get(&(case_id.clone(), *case_version)) {
            cells.extend(case.required_cells.iter().cloned());
            obligations.extend(
                case.obligations
                    .iter()
                    .map(|o| (o.kind().to_owned(), o.id().to_owned())),
            );
        }
    }
    ForwardClosure {
        owners,
        cases,
        cells,
        obligations,
    }
}

fn change_hits(change: &Change, catalog: &CaseCatalog, closure: &ForwardClosure) -> bool {
    match change {
        Change::Case { case_id, case_version } => {
            closure.cases.contains(&(case_id.clone(), *case_version))
        }
        Change::Cell { cell_id } => closure.cells.contains(cell_id),
        Change::Profile { profile } => closure.owners.contains(profile),
        Change::Extension { extension } => closure.owners.contains(extension),
        Change::Obligation { kind, id } => {
            closure.obligations.contains(&(kind.clone(), id.clone()))
        }
        Change::RegistrationRole { case_id, case_version, .. } => {
            closure.cases.contains(&(case_id.clone(), *case_version))
        }
        // Broadening without a boundary affects every owner.
        Change::Unknown { boundary: None, .. } | Change::Environment { boundary: None, .. } => true,
        // A named boundary affects its closure plus every dependent: the
        // owner's forward closure intersects the boundary's forward closure.
        // Unknown impact cannot claim containment.
        Change::Unknown {
            boundary: Some(root),
            ..
        }
        | Change::Environment {
            boundary: Some(root),
            ..
        } => {
            let boundary = forward_closure(catalog, root);
            boundary.iter().any(|node| match node {
                super::selector::Node::Profile(p) | super::selector::Node::Extension(p) => {
                    closure.owners.contains(p)
                }
                _ => false,
            })
        }
    }
}

/// Independently recompute the expected affected cell set for one request.
/// Sorted; duplicates impossible.
pub fn expected_selection(
    catalog: &CaseCatalog,
    manifest: &ChangeManifest,
    requested: &[ProfileId],
    limits: &SelectionLimits,
) -> Result<Vec<CellKey>, SelectionError> {
    let inputs = validated_inputs(catalog, manifest, requested, limits)?;
    let mut affected_profiles = BTreeSet::new();
    let mut affected_extensions = BTreeSet::new();
    for profile in inputs.closure_profiles.iter() {
        let closure = owner_closure(catalog, profile);
        if manifest
            .changes()
            .iter()
            .any(|c| change_hits(c, catalog, &closure))
        {
            affected_profiles.insert(profile.clone());
        }
    }
    for extension in inputs.closure_extensions.iter() {
        let closure = owner_closure(catalog, extension);
        if manifest
            .changes()
            .iter()
            .any(|c| change_hits(c, catalog, &closure))
        {
            affected_extensions.insert(extension.clone());
        }
    }
    let mut selected = BTreeSet::new();
    for profile in &affected_profiles {
        for (case_id, case_version) in owner_active_cases(
            &catalog.profiles[profile].required_cases,
            &Node::Profile(profile.clone()),
            &inputs,
        ) {
            let case = &catalog.cases[&(case_id.clone(), case_version)];
            for cell in &case.required_cells {
                if selected.len() == limits.max_selected_cells {
                    return Err(SelectionError(
                        super::selector::SelectionErrorKind::LimitExceeded,
                    ));
                }
                selected.insert(CellKey {
                    case_id: case_id.clone(),
                    case_version,
                    cell_id: cell.clone(),
                });
            }
        }
    }
    for extension in &affected_extensions {
        for (case_id, case_version) in owner_active_cases(
            &catalog.extensions[extension].required_cases,
            &Node::Extension(extension.clone()),
            &inputs,
        ) {
            let case = &catalog.cases[&(case_id.clone(), case_version)];
            for cell in &case.required_cells {
                if selected.len() == limits.max_selected_cells {
                    return Err(SelectionError(
                        super::selector::SelectionErrorKind::LimitExceeded,
                    ));
                }
                selected.insert(CellKey {
                    case_id: case_id.clone(),
                    case_version,
                    cell_id: cell.clone(),
                });
            }
        }
    }
    Ok(selected.into_iter().collect())
}

/// Selector/oracle disagreement: `missing` cells were expected but not
/// selected (dropped dependents); `extra` cells were selected but not
/// expected (over-selection). Both sorted.
#[derive(Debug)]
pub struct OracleDisagreement {
    missing: Vec<CellKey>,
    extra: Vec<CellKey>,
}

impl OracleDisagreement {
    pub fn missing(&self) -> &[CellKey] {
        &self.missing
    }
    pub fn extra(&self) -> &[CellKey] {
        &self.extra
    }
}

/// Compare a selector plan's selected set against the oracle expectation.
pub fn check_agreement(
    plan: &SelectionPlan,
    expected: &[CellKey],
) -> Result<(), OracleDisagreement> {
    let planned: BTreeSet<&CellKey> = plan.selected().iter().map(|c| c.key()).collect();
    let wanted: BTreeSet<&CellKey> = expected.iter().collect();
    let missing: Vec<CellKey> = wanted
        .difference(&planned)
        .map(|k| (*k).clone())
        .collect();
    let extra: Vec<CellKey> = planned
        .difference(&wanted)
        .map(|k| (*k).clone())
        .collect();
    if missing.is_empty() && extra.is_empty() {
        Ok(())
    } else {
        Err(OracleDisagreement { missing, extra })
    }
}
