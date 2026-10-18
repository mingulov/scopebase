// SPDX-License-Identifier: Apache-2.0
use crate::*;
use std::{error::Error, fmt};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanErrorKind {
    UnknownProfile,
    ExtensionNotProfile,
    SelectionMismatch,
    LimitExceeded,
}
#[derive(Debug)]
pub struct PlanError(pub(crate) PlanErrorKind);
impl PlanError {
    pub fn kind(&self) -> PlanErrorKind {
        self.0
    }
}
impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "plan rejected: {:?}", self.0)
    }
}
impl Error for PlanError {}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequiredCell {
    pub(crate) case_id: CaseId,
    pub(crate) case_version: u32,
    pub(crate) cell_id: String,
    pub(crate) tier: EvidenceTier,
    pub(crate) implementation_status: ImplementationStatus,
    pub(crate) required_by: Vec<ProfileId>,
}
impl RequiredCell {
    pub fn case_id(&self) -> &CaseId {
        &self.case_id
    }
    pub fn case_version(&self) -> u32 {
        self.case_version
    }
    pub fn cell_id(&self) -> &str {
        &self.cell_id
    }
    pub fn tier(&self) -> EvidenceTier {
        self.tier
    }
    pub fn implementation_status(&self) -> ImplementationStatus {
        self.implementation_status
    }
    pub fn required_by(&self) -> &[ProfileId] {
        &self.required_by
    }
}
#[derive(Debug)]
pub struct ProfilePlan {
    pub(crate) requested: ProfileId,
    pub(crate) profiles: Vec<ProfileId>,
    pub(crate) extensions: Vec<ProfileId>,
    pub(crate) required: Vec<RequiredCell>,
    pub(crate) open_owners: Vec<String>,
    pub(crate) definition_complete: bool,
}
impl ProfilePlan {
    pub fn requested(&self) -> &ProfileId {
        &self.requested
    }
    pub fn profiles(&self) -> &[ProfileId] {
        &self.profiles
    }
    pub fn extensions(&self) -> &[ProfileId] {
        &self.extensions
    }
    pub fn required(&self) -> &[RequiredCell] {
        &self.required
    }
    pub fn open_owners(&self) -> &[String] {
        &self.open_owners
    }
    pub fn definition_complete(&self) -> bool {
        self.definition_complete
    }
    pub fn select(catalog: &CaseCatalog, id: &ProfileId) -> Result<Self, PlanError> {
        if !catalog.profiles.contains_key(id) {
            return Err(PlanError(if catalog.extensions.contains_key(id) {
                PlanErrorKind::ExtensionNotProfile
            } else {
                PlanErrorKind::UnknownProfile
            }));
        }
        build(catalog, id).map_err(|_| PlanError(PlanErrorKind::LimitExceeded))
    }
    pub fn validate_selection(
        &self,
        p: &[ProfileId],
        e: &[ProfileId],
        r: &[RequiredCell],
    ) -> Result<(), PlanError> {
        fn equal<T: Ord>(a: &[T], b: &[T]) -> bool {
            a.len() == b.len()
                && a.iter().collect::<std::collections::BTreeSet<_>>().len() == a.len()
                && a.iter().collect::<std::collections::BTreeSet<_>>()
                    == b.iter().collect::<std::collections::BTreeSet<_>>()
        }
        if equal(p, &self.profiles) && equal(e, &self.extensions) && equal(r, &self.required) {
            Ok(())
        } else {
            Err(PlanError(PlanErrorKind::SelectionMismatch))
        }
    }
}
pub(crate) fn build(catalog: &CaseCatalog, id: &ProfileId) -> Result<ProfilePlan, CatalogError> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut selected = BTreeSet::new();
    let mut todo = vec![id.clone()];
    while let Some(next) = todo.pop() {
        if selected.insert(next.clone()) {
            todo.extend(catalog.graph_edges(&next));
        }
    }
    let mut versions = BTreeMap::new();
    let mut profiles = Vec::new();
    let mut extensions = Vec::new();
    let mut open = BTreeSet::new();
    let mut complete = true;
    for next in &selected {
        let (stem, version) = next.as_str().rsplit_once("-v").expect("admitted suffix");
        let namespace = if catalog.profiles.contains_key(next) {
            "profile"
        } else {
            "extension"
        };
        if versions
            .insert((namespace, stem), version)
            .is_some_and(|old| old != version)
        {
            return Err(CatalogError(CatalogErrorKind::VersionConflict));
        }
        if let Some(p) = catalog.profiles.get(next) {
            profiles.push(next.clone());
            open.extend(p.open_owners.iter().cloned());
            complete &= p.definition_state == DefinitionState::Frozen;
        } else {
            extensions.push(next.clone());
        }
    }
    // Conditions are evaluated only after the fixed point and never create edges.
    let mut case_versions = BTreeMap::new();
    let mut required: BTreeMap<(CaseId, u32, String), RequiredCell> = BTreeMap::new();
    for next in &selected {
        let declared = if let Some(p) = catalog.profiles.get(next) {
            &p.required_cases
        } else {
            &catalog.extensions[next].required_cases
        };
        for r in declared {
            if !r.when_extensions.iter().all(|e| selected.contains(e)) {
                continue;
            }
            if case_versions
                .insert(r.case_id.clone(), r.case_version)
                .is_some_and(|v| v != r.case_version)
            {
                return Err(CatalogError(CatalogErrorKind::VersionConflict));
            }
            let case = &catalog.cases[&(r.case_id.clone(), r.case_version)];
            for cell in &case.required_cells {
                let key = (r.case_id.clone(), r.case_version, cell.clone());
                if !required.contains_key(&key) && required.len() == catalog.max_selected_cells {
                    return Err(CatalogError(CatalogErrorKind::LimitExceeded));
                }
                let value = required.entry(key).or_insert_with(|| RequiredCell {
                    case_id: r.case_id.clone(),
                    case_version: r.case_version,
                    cell_id: catalog.cells[cell].id.clone(),
                    tier: catalog.cells[cell].tier,
                    implementation_status: case.implementation_status,
                    required_by: Vec::new(),
                });
                if !value.required_by.contains(next) {
                    value.required_by.push(next.clone())
                }
            }
        }
    }
    if catalog.profiles[id].definition_state == DefinitionState::Frozen
        && (!complete || required.is_empty())
    {
        return Err(CatalogError(CatalogErrorKind::InvalidDefinition));
    }
    Ok(ProfilePlan {
        requested: id.clone(),
        profiles,
        extensions,
        required: required.into_values().collect(),
        open_owners: open.into_iter().collect(),
        definition_complete: complete,
    })
}
