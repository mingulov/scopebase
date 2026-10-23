// SPDX-License-Identifier: Apache-2.0
//! TT08 affected-check selector over the TT01 [`CaseCatalog`] graph.
//!
//! [`select_affected`] maps a [`ChangeManifest`] to the required checks of the
//! requested profiles by reverse reachability: changed nodes seed an affected
//! set that propagates to dependents (requiring profiles/extensions, requiring
//! cases, required cells). Conditional `when_extensions` entries create
//! reachability edges regardless of activation — a condition may activate —
//! while cell expansion evaluates each condition against the requesting
//! profile's own plan extensions: a condition active in no requesting
//! profile's own plan never selects, so selection cannot leak across
//! profiles through another profile's extension.
//!
//! Selection is scoped to the requested profiles. Affected nodes outside that
//! scope are reported as reviewable [`OutOfScopeNode`] exclusions, never
//! silently dropped and never silently selected. Unknown and environment
//! changes broaden their named boundary (or the whole request when no boundary
//! is named) and are recorded as [`UnresolvedImpact`]; they cannot return
//! empty success.

use super::manifest::{Change, ChangeManifest, RegistrationRole};
use crate::{CaseCatalog, CaseId, ProfileId, ProfilePlan};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{error::Error, fmt};

/// Bounds for causal selection. Mirrors [`CatalogLimits`](crate::CatalogLimits):
/// every field must be nonzero and at most its default ceiling.
#[derive(Clone, Debug)]
pub struct SelectionLimits {
    pub max_changes: usize,
    pub max_requested_profiles: usize,
    pub max_path_steps: usize,
    pub max_reason_bytes: usize,
    pub max_selected_cells: usize,
}

impl Default for SelectionLimits {
    fn default() -> Self {
        Self {
            max_changes: 1024,
            max_requested_profiles: 128,
            max_path_steps: 4096,
            max_reason_bytes: 4096,
            max_selected_cells: 16384,
        }
    }
}

impl SelectionLimits {
    fn validate(&self) -> Result<(), SelectionError> {
        let ceiling = Self::default();
        let actual = [
            self.max_changes,
            self.max_requested_profiles,
            self.max_path_steps,
            self.max_reason_bytes,
            self.max_selected_cells,
        ];
        let maximum = [
            ceiling.max_changes,
            ceiling.max_requested_profiles,
            ceiling.max_path_steps,
            ceiling.max_reason_bytes,
            ceiling.max_selected_cells,
        ];
        if actual.iter().zip(maximum).any(|(a, b)| *a == 0 || *a > b) {
            return Err(SelectionError(SelectionErrorKind::InvalidLimits));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionErrorKind {
    InvalidLimits,
    LimitExceeded,
    UnknownProfile,
    UnknownChangeTarget,
    InvalidManifest,
}

#[derive(Debug)]
pub struct SelectionError(pub(crate) SelectionErrorKind);

impl SelectionError {
    pub fn kind(&self) -> SelectionErrorKind {
        self.0
    }
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "selection rejected: {:?}", self.0)
    }
}

impl Error for SelectionError {}

/// One required check: an exact case revision plus one of its required cells.
/// Exact revisions never select latest.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CellKey {
    pub(crate) case_id: CaseId,
    pub(crate) case_version: u32,
    pub(crate) cell_id: String,
}

impl CellKey {
    pub fn new(case_id: CaseId, case_version: u32, cell_id: &str) -> Result<Self, SelectionError> {
        if case_version == 0 || cell_id.is_empty() || cell_id.len() > 65536 {
            return Err(SelectionError(SelectionErrorKind::InvalidManifest));
        }
        Ok(Self {
            case_id,
            case_version,
            cell_id: cell_id.to_owned(),
        })
    }
    pub fn case_id(&self) -> &CaseId {
        &self.case_id
    }
    pub fn case_version(&self) -> u32 {
        self.case_version
    }
    pub fn cell_id(&self) -> &str {
        &self.cell_id
    }
}

/// One step of a causal explanation path, from the change target outward.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExplanationStep {
    ChangeTarget,
    Case { case_id: CaseId, case_version: u32 },
    Cell { cell_id: String },
    Profile { profile: ProfileId },
    Extension { extension: ProfileId },
    Obligation { kind: String, id: String },
    RegistrationRole { role: RegistrationRole },
    BoundaryBroadening { boundary: Option<ProfileId> },
}

/// Why one selected cell is affected: the first manifest change reaching it
/// and the causal path from that change target to the cell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Explanation {
    change_index: usize,
    path: Vec<ExplanationStep>,
}

impl Explanation {
    pub fn change_index(&self) -> usize {
        self.change_index
    }
    pub fn path(&self) -> &[ExplanationStep] {
        &self.path
    }
}

/// One selected required check with its causal explanation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedCell {
    key: CellKey,
    explanation: Explanation,
}

impl SelectedCell {
    pub fn key(&self) -> &CellKey {
        &self.key
    }
    pub fn explanation(&self) -> &Explanation {
        &self.explanation
    }
}

/// One broadening applied for unknown or environment impact. The named
/// boundary (or the whole request when `None`) was selected in full because
/// precise impact is not known.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnresolvedImpact {
    change_index: usize,
    boundary: Option<ProfileId>,
    reason: String,
}

impl UnresolvedImpact {
    pub fn change_index(&self) -> usize {
        self.change_index
    }
    pub fn boundary(&self) -> Option<&ProfileId> {
        self.boundary.as_ref()
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// An affected node outside the requested profiles: reviewable exclusion.
/// Neither selected nor silently dropped.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum OutOfScopeNode {
    Profile(ProfileId),
    Extension(ProfileId),
    Case(CaseId, u32),
}

/// The causal selection for one request: required checks to run, the declared
/// denominator they narrow, explanations, broadenings and exclusions.
#[derive(Debug)]
pub struct SelectionPlan {
    requested: Vec<ProfileId>,
    selected: Vec<SelectedCell>,
    declared: Vec<CellKey>,
    unresolved: Vec<UnresolvedImpact>,
    excluded: Vec<OutOfScopeNode>,
    full: bool,
}

impl SelectionPlan {
    pub fn requested(&self) -> &[ProfileId] {
        &self.requested
    }
    pub fn selected(&self) -> &[SelectedCell] {
        &self.selected
    }
    pub fn declared(&self) -> &[CellKey] {
        &self.declared
    }
    pub fn unresolved(&self) -> &[UnresolvedImpact] {
        &self.unresolved
    }
    pub fn excluded_out_of_scope(&self) -> &[OutOfScopeNode] {
        &self.excluded
    }
    /// True only when the denominator is nonempty, the impact is fully
    /// resolved, and every declared denominator cell is selected. An empty
    /// denominator (reachable: an admitted DRAFT profile may require nothing,
    /// directly or through only-inactive conditions) can never be full, and
    /// neither can a selection with unresolved (broadened) impact, whose true
    /// affected set is unknown.
    pub fn is_full_selection(&self) -> bool {
        self.full
    }
    pub fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Node {
    Profile(ProfileId),
    Extension(ProfileId),
    Case(CaseId, u32),
    Cell(String),
    Obligation(String, String),
}

impl Node {
    fn step(&self) -> ExplanationStep {
        match self {
            Node::Profile(p) => ExplanationStep::Profile { profile: p.clone() },
            Node::Extension(e) => ExplanationStep::Extension {
                extension: e.clone(),
            },
            Node::Case(id, v) => ExplanationStep::Case {
                case_id: id.clone(),
                case_version: *v,
            },
            Node::Cell(c) => ExplanationStep::Cell { cell_id: c.clone() },
            Node::Obligation(kind, id) => ExplanationStep::Obligation {
                kind: kind.clone(),
                id: id.clone(),
            },
        }
    }
}

fn profileish(catalog: &CaseCatalog, id: &ProfileId) -> Option<Node> {
    if catalog.profiles.contains_key(id) {
        Some(Node::Profile(id.clone()))
    } else if catalog.extensions.contains_key(id) {
        Some(Node::Extension(id.clone()))
    } else {
        None
    }
}

/// Dependency -> direct dependents. Conditional `when_extensions` entries
/// create edges regardless of activation: the condition may activate.
pub(crate) fn reverse_index(catalog: &CaseCatalog) -> BTreeMap<Node, BTreeSet<Node>> {
    let mut rev: BTreeMap<Node, BTreeSet<Node>> = BTreeMap::new();
    for id in catalog.profiles.keys() {
        let dependent = Node::Profile(id.clone());
        for target in catalog.graph_edges(id) {
            if let Some(node) = profileish(catalog, &target) {
                rev.entry(node).or_default().insert(dependent.clone());
            }
        }
        for r in &catalog.profiles[id].required_cases {
            rev.entry(Node::Case(r.case_id.clone(), r.case_version))
                .or_default()
                .insert(dependent.clone());
        }
    }
    for id in catalog.extensions.keys() {
        let dependent = Node::Extension(id.clone());
        for target in catalog.graph_edges(id) {
            if let Some(node) = profileish(catalog, &target) {
                rev.entry(node).or_default().insert(dependent.clone());
            }
        }
        for r in &catalog.extensions[id].required_cases {
            rev.entry(Node::Case(r.case_id.clone(), r.case_version))
                .or_default()
                .insert(dependent.clone());
        }
    }
    for ((id, version), case) in &catalog.cases {
        let dependent = Node::Case(id.clone(), *version);
        for cell in &case.required_cells {
            rev.entry(Node::Cell(cell.clone()))
                .or_default()
                .insert(dependent.clone());
        }
        for obligation in &case.obligations {
            rev.entry(Node::Obligation(
                obligation.kind().to_owned(),
                obligation.id().to_owned(),
            ))
            .or_default()
            .insert(dependent.clone());
        }
    }
    rev
}

/// Forward profile/extension closure of one boundary root over `graph_edges`.
/// The oracle reuses this forward walk; it never touches the reverse index.
pub(crate) fn forward_closure(catalog: &CaseCatalog, root: &ProfileId) -> BTreeSet<Node> {
    let mut seen = BTreeSet::new();
    let mut todo = vec![root.clone()];
    while let Some(next) = todo.pop() {
        let node = match profileish(catalog, &next) {
            Some(node) => node,
            None => continue,
        };
        if seen.insert(node) {
            todo.extend(catalog.graph_edges(&next));
        }
    }
    seen
}

/// Required cases an affected owner contributes: a conditional entry is
/// active only through a requesting profile whose own plan both contains the
/// owner and carries every named extension. Evaluating against the union of
/// requested-closure extensions would leak a condition across profiles (an
/// entry inactive in every requesting profile's own plan activating via
/// another profile's extension); the per-profile rule also matches
/// [`ProfilePlan`](crate::ProfilePlan) construction, so an activated cell is
/// always inside the activating profile's denominator and never selected
/// outside it.
pub(crate) fn owner_active_cases(
    entries: &[crate::RequiredCaseSpec],
    owner: &Node,
    inputs: &ValidatedInputs,
) -> Vec<(CaseId, u32)> {
    entries
        .iter()
        .filter(|r| {
            inputs.per_root.iter().any(|root| {
                root.owners.contains(owner)
                    && r.when_extensions
                        .iter()
                        .all(|e| root.extensions.contains(e))
            })
        })
        .map(|r| (r.case_id.clone(), r.case_version))
        .collect()
}

fn validate_change(
    catalog: &CaseCatalog,
    change: &Change,
    limits: &SelectionLimits,
) -> Result<(), SelectionError> {
    let unknown = SelectionError(SelectionErrorKind::UnknownChangeTarget);
    let malformed = SelectionError(SelectionErrorKind::InvalidManifest);
    match change {
        Change::Case {
            case_id,
            case_version,
        } => {
            if *case_version == 0 {
                return Err(malformed);
            }
            if !catalog
                .cases
                .contains_key(&(case_id.clone(), *case_version))
            {
                return Err(unknown);
            }
        }
        Change::Cell { cell_id } => {
            if cell_id.is_empty() || !catalog.cells.contains_key(cell_id) {
                return Err(if cell_id.is_empty() {
                    malformed
                } else {
                    unknown
                });
            }
        }
        Change::Profile { profile } => {
            if !catalog.profiles.contains_key(profile) {
                return Err(unknown);
            }
        }
        Change::Extension { extension } => {
            if !catalog.extensions.contains_key(extension) {
                return Err(unknown);
            }
        }
        Change::Obligation { kind, id } => {
            if kind.is_empty() || id.is_empty() {
                return Err(malformed);
            }
            if !catalog
                .obligations
                .iter()
                .any(|o| o.kind() == kind && o.id() == id)
            {
                return Err(unknown);
            }
        }
        Change::RegistrationRole {
            case_id,
            case_version,
            ..
        } => {
            if *case_version == 0 {
                return Err(malformed);
            }
            match catalog.cases.get(&(case_id.clone(), *case_version)) {
                Some(case) if case.registration().is_some() => {}
                _ => return Err(unknown),
            }
        }
        Change::Unknown { boundary, reason } => {
            if reason.is_empty() || reason.len() > limits.max_reason_bytes {
                return Err(malformed);
            }
            if let Some(b) = boundary {
                if profileish(catalog, b).is_none() {
                    return Err(unknown);
                }
            }
        }
        Change::Environment { boundary, .. } => {
            if let Some(b) = boundary {
                if profileish(catalog, b).is_none() {
                    return Err(unknown);
                }
            }
        }
    }
    Ok(())
}

/// One requesting profile's own plan slice: its closure owners and its own
/// extension set, against which that profile's conditional entries activate.
pub(crate) struct RootInputs {
    pub(crate) owners: BTreeSet<Node>,
    pub(crate) extensions: BTreeSet<ProfileId>,
}

pub(crate) struct ValidatedInputs {
    pub(crate) roots: Vec<ProfileId>,
    pub(crate) closure_profiles: BTreeSet<ProfileId>,
    pub(crate) closure_extensions: BTreeSet<ProfileId>,
    pub(crate) per_root: Vec<RootInputs>,
    pub(crate) denominator: Vec<CellKey>,
}

pub(crate) fn validated_inputs(
    catalog: &CaseCatalog,
    manifest: &ChangeManifest,
    requested: &[ProfileId],
    limits: &SelectionLimits,
) -> Result<ValidatedInputs, SelectionError> {
    limits.validate()?;
    if requested.is_empty() {
        return Err(SelectionError(SelectionErrorKind::InvalidManifest));
    }
    if requested.len() > limits.max_requested_profiles
        || manifest.changes().len() > limits.max_changes
    {
        return Err(SelectionError(SelectionErrorKind::LimitExceeded));
    }
    for id in requested {
        if !catalog.profiles.contains_key(id) {
            return Err(SelectionError(SelectionErrorKind::UnknownProfile));
        }
    }
    for change in manifest.changes() {
        validate_change(catalog, change, limits)?;
    }
    let mut roots: Vec<ProfileId> = requested.to_vec();
    roots.sort();
    roots.dedup();
    let mut closure_profiles = BTreeSet::new();
    let mut closure_extensions = BTreeSet::new();
    let mut denominator = BTreeSet::new();
    let mut per_root = Vec::new();
    for root in &roots {
        let plan = ProfilePlan::select(catalog, root).map_err(|e| {
            use crate::PlanErrorKind as K;
            SelectionError(match e.kind() {
                K::LimitExceeded => SelectionErrorKind::LimitExceeded,
                _ => SelectionErrorKind::UnknownProfile,
            })
        })?;
        closure_profiles.extend(plan.profiles().iter().cloned());
        closure_extensions.extend(plan.extensions().iter().cloned());
        let mut owners = BTreeSet::new();
        owners.extend(plan.profiles().iter().cloned().map(Node::Profile));
        owners.extend(plan.extensions().iter().cloned().map(Node::Extension));
        per_root.push(RootInputs {
            owners,
            extensions: plan.extensions().iter().cloned().collect(),
        });
        for cell in plan.required() {
            denominator.insert(CellKey {
                case_id: cell.case_id().clone(),
                case_version: cell.case_version(),
                cell_id: cell.cell_id().to_owned(),
            });
        }
    }
    Ok(ValidatedInputs {
        roots,
        closure_profiles,
        closure_extensions,
        per_root,
        denominator: denominator.into_iter().collect(),
    })
}

/// Select the required checks of `requested` affected by `manifest`.
///
/// The selector walks dependents from each validated change target over the
/// reverse catalog index, intersects affected owners with the requested
/// closures, and expands each affected owner's directly declared required
/// cases (each condition evaluated against the requesting profile's own plan
/// extensions; entries active in no requesting profile's plan never select).
/// Deterministic: sorted worklists, first-change-wins explanations.
pub fn select_affected(
    catalog: &CaseCatalog,
    manifest: &ChangeManifest,
    requested: &[ProfileId],
    limits: &SelectionLimits,
) -> Result<SelectionPlan, SelectionError> {
    let inputs = validated_inputs(catalog, manifest, requested, limits)?;
    let rev = reverse_index(catalog);
    // Affected node -> (change index, causal path). First visit wins.
    let mut affected: BTreeMap<Node, (usize, Vec<ExplanationStep>)> = BTreeMap::new();
    let mut queue: VecDeque<Node> = VecDeque::new();
    let mut unresolved = Vec::new();
    let seed = |node: Node,
                index: usize,
                path: Vec<ExplanationStep>,
                affected: &mut BTreeMap<Node, (usize, Vec<ExplanationStep>)>,
                queue: &mut VecDeque<Node>| {
        if path.len() > limits.max_path_steps {
            return Err(SelectionError(SelectionErrorKind::LimitExceeded));
        }
        if let std::collections::btree_map::Entry::Vacant(e) = affected.entry(node.clone()) {
            e.insert((index, path));
            queue.push_back(node);
        }
        Ok(())
    };
    for (index, change) in manifest.changes().iter().enumerate() {
        let target = ExplanationStep::ChangeTarget;
        match change {
            Change::Case {
                case_id,
                case_version,
            } => {
                let node = Node::Case(case_id.clone(), *case_version);
                let path = vec![target, node.step()];
                seed(node, index, path, &mut affected, &mut queue)?;
            }
            Change::Cell { cell_id } => {
                let node = Node::Cell(cell_id.clone());
                let path = vec![target, node.step()];
                seed(node, index, path, &mut affected, &mut queue)?;
            }
            Change::Profile { profile } => {
                let node = Node::Profile(profile.clone());
                let path = vec![target, node.step()];
                seed(node, index, path, &mut affected, &mut queue)?;
            }
            Change::Extension { extension } => {
                let node = Node::Extension(extension.clone());
                let path = vec![target, node.step()];
                seed(node, index, path, &mut affected, &mut queue)?;
            }
            Change::Obligation { kind, id } => {
                let mut cases: Vec<(CaseId, u32)> = catalog
                    .cases
                    .iter()
                    .filter(|(_, case)| {
                        case.obligations
                            .iter()
                            .any(|o| o.kind() == kind && o.id() == id)
                    })
                    .map(|((case_id, version), _)| (case_id.clone(), *version))
                    .collect();
                cases.sort();
                for (case_id, case_version) in cases {
                    let node = Node::Case(case_id, case_version);
                    let path = vec![
                        target.clone(),
                        ExplanationStep::Obligation {
                            kind: kind.clone(),
                            id: id.clone(),
                        },
                        node.step(),
                    ];
                    seed(node, index, path, &mut affected, &mut queue)?;
                }
            }
            Change::RegistrationRole {
                case_id,
                case_version,
                role,
            } => {
                let node = Node::Case(case_id.clone(), *case_version);
                let path = vec![
                    target,
                    ExplanationStep::RegistrationRole { role: *role },
                    node.step(),
                ];
                seed(node, index, path, &mut affected, &mut queue)?;
            }
            Change::Unknown { boundary, reason } => {
                unresolved.push(UnresolvedImpact {
                    change_index: index,
                    boundary: boundary.clone(),
                    reason: reason.clone(),
                });
                seed_broadening(
                    catalog,
                    boundary.clone(),
                    index,
                    &mut affected,
                    &mut queue,
                    &seed,
                )?;
            }
            Change::Environment {
                attribute,
                boundary,
            } => {
                unresolved.push(UnresolvedImpact {
                    change_index: index,
                    boundary: boundary.clone(),
                    reason: format!("environment:{attribute:?}"),
                });
                seed_broadening(
                    catalog,
                    boundary.clone(),
                    index,
                    &mut affected,
                    &mut queue,
                    &seed,
                )?;
            }
        }
        // Drain per change in manifest order: lower change indices claim
        // shared dependents first, so explanations are deterministic and
        // first-affecting-change-wins.
        while let Some(node) = queue.pop_front() {
            let (index, path) = affected[&node].clone();
            let dependents = rev.get(&node).cloned().unwrap_or_default();
            for dependent in dependents {
                if affected.contains_key(&dependent) {
                    continue;
                }
                let mut next = path.clone();
                next.push(dependent.step());
                seed(dependent, index, next, &mut affected, &mut queue)?;
            }
        }
    }
    // Expand in-scope affected owners to their directly declared cells.
    let mut selected: BTreeMap<CellKey, Explanation> = BTreeMap::new();
    let expand = |node: &Node,
                  entries: &[crate::RequiredCaseSpec],
                  selected: &mut BTreeMap<CellKey, Explanation>,
                  limits: &SelectionLimits|
     -> Result<(), SelectionError> {
        let (index, path) = affected[node].clone();
        for (case_id, case_version) in owner_active_cases(entries, node, &inputs) {
            let case = &catalog.cases[&(case_id.clone(), case_version)];
            for cell in &case.required_cells {
                if selected.len() == limits.max_selected_cells
                    && !selected.contains_key(&CellKey {
                        case_id: case_id.clone(),
                        case_version,
                        cell_id: cell.clone(),
                    })
                {
                    return Err(SelectionError(SelectionErrorKind::LimitExceeded));
                }
                let mut full = path.clone();
                full.push(ExplanationStep::Case {
                    case_id: case_id.clone(),
                    case_version,
                });
                full.push(ExplanationStep::Cell {
                    cell_id: cell.clone(),
                });
                if full.len() > limits.max_path_steps {
                    return Err(SelectionError(SelectionErrorKind::LimitExceeded));
                }
                let key = CellKey {
                    case_id: case_id.clone(),
                    case_version,
                    cell_id: cell.clone(),
                };
                // Lowest affecting change index wins; owner iteration is
                // sorted, so ties are deterministic.
                match selected.entry(key) {
                    std::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(Explanation {
                            change_index: index,
                            path: full,
                        });
                    }
                    std::collections::btree_map::Entry::Occupied(mut o) => {
                        if index < o.get().change_index() {
                            o.insert(Explanation {
                                change_index: index,
                                path: full,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    };
    let mut in_scope_profiles: Vec<&ProfileId> = inputs.closure_profiles.iter().collect();
    in_scope_profiles.sort();
    for profile in in_scope_profiles {
        if affected.contains_key(&Node::Profile(profile.clone())) {
            let entries = catalog.profiles[profile].required_cases.clone();
            expand(
                &Node::Profile(profile.clone()),
                &entries,
                &mut selected,
                limits,
            )?;
        }
    }
    let mut in_scope_extensions: Vec<&ProfileId> = inputs.closure_extensions.iter().collect();
    in_scope_extensions.sort();
    for extension in in_scope_extensions {
        if affected.contains_key(&Node::Extension(extension.clone())) {
            let entries = catalog.extensions[extension].required_cases.clone();
            expand(
                &Node::Extension(extension.clone()),
                &entries,
                &mut selected,
                limits,
            )?;
        }
    }
    // Reviewable exclusions: affected owners outside the requested closures.
    let mut excluded = BTreeSet::new();
    for node in affected.keys() {
        match node {
            Node::Profile(p) if !inputs.closure_profiles.contains(p) => {
                excluded.insert(OutOfScopeNode::Profile(p.clone()));
            }
            Node::Extension(e) if !inputs.closure_extensions.contains(e) => {
                excluded.insert(OutOfScopeNode::Extension(e.clone()));
            }
            Node::Case(id, v) => {
                if !covered_in_scope(catalog, &inputs, &affected, id, *v) {
                    excluded.insert(OutOfScopeNode::Case(id.clone(), *v));
                }
            }
            _ => {}
        }
    }
    let declared_set: BTreeSet<&CellKey> = inputs.denominator.iter().collect();
    let selected_set: BTreeSet<&CellKey> = selected.keys().collect();
    // Full attests coverage of a real, fully resolved required boundary: an
    // empty denominator or any unresolved (broadened) impact keeps the plan
    // incomplete, never Full.
    let full = !declared_set.is_empty()
        && unresolved.is_empty()
        && declared_set.iter().all(|k| selected_set.contains(*k));
    Ok(SelectionPlan {
        requested: inputs.roots,
        selected: selected
            .into_iter()
            .map(|(key, explanation)| SelectedCell { key, explanation })
            .collect(),
        declared: inputs.denominator,
        unresolved,
        excluded: excluded.into_iter().collect(),
        full,
    })
}

#[allow(clippy::too_many_arguments)]
fn seed_broadening(
    catalog: &CaseCatalog,
    boundary: Option<ProfileId>,
    index: usize,
    affected: &mut BTreeMap<Node, (usize, Vec<ExplanationStep>)>,
    queue: &mut VecDeque<Node>,
    seed: &impl Fn(
        Node,
        usize,
        Vec<ExplanationStep>,
        &mut BTreeMap<Node, (usize, Vec<ExplanationStep>)>,
        &mut VecDeque<Node>,
    ) -> Result<(), SelectionError>,
) -> Result<(), SelectionError> {
    let broaden = ExplanationStep::BoundaryBroadening {
        boundary: boundary.clone(),
    };
    match boundary {
        None => {
            // Whole-request broadening: every requested-closure owner, plus
            // every other catalog owner so exclusions stay reviewable.
            let mut owners: Vec<Node> = catalog
                .profiles
                .keys()
                .map(|p| Node::Profile(p.clone()))
                .chain(
                    catalog
                        .extensions
                        .keys()
                        .map(|e| Node::Extension(e.clone())),
                )
                .chain(
                    catalog
                        .cases
                        .keys()
                        .map(|(id, v)| Node::Case(id.clone(), *v)),
                )
                .collect();
            owners.sort();
            for node in owners {
                let path = vec![ExplanationStep::ChangeTarget, broaden.clone(), node.step()];
                seed(node, index, path, affected, queue)?;
            }
        }
        Some(root) => {
            // Boundary closure plus every dependent of it: unknown impact
            // cannot claim containment. Dependents arrive via the reverse
            // walk from the seeded closure.
            let mut closure: Vec<Node> = forward_closure(catalog, &root).into_iter().collect();
            closure.sort();
            for node in &closure {
                let path = vec![ExplanationStep::ChangeTarget, broaden.clone(), node.step()];
                seed(node.clone(), index, path, affected, queue)?;
            }
            // Declared cases of the broadened closure, so case-level
            // exclusions stay reviewable.
            let mut cases = BTreeSet::new();
            for node in &closure {
                let entries: &[crate::RequiredCaseSpec] = match node {
                    Node::Profile(p) => &catalog.profiles[p].required_cases,
                    Node::Extension(e) => &catalog.extensions[e].required_cases,
                    _ => continue,
                };
                for r in entries {
                    cases.insert(Node::Case(r.case_id.clone(), r.case_version));
                }
            }
            for node in cases {
                let path = vec![ExplanationStep::ChangeTarget, broaden.clone(), node.step()];
                seed(node, index, path, affected, queue)?;
            }
        }
    }
    Ok(())
}

/// An affected case is covered in scope when an in-scope affected owner
/// declares it (conditions ignored: coverage is about declaration, and cell
/// expansion applies the condition rule separately).
fn covered_in_scope(
    catalog: &CaseCatalog,
    inputs: &ValidatedInputs,
    affected: &BTreeMap<Node, (usize, Vec<ExplanationStep>)>,
    case_id: &CaseId,
    case_version: u32,
) -> bool {
    let declares = |entries: &[crate::RequiredCaseSpec]| {
        entries
            .iter()
            .any(|r| &r.case_id == case_id && r.case_version == case_version)
    };
    inputs.closure_profiles.iter().any(|p| {
        affected.contains_key(&Node::Profile(p.clone()))
            && declares(&catalog.profiles[p].required_cases)
    }) || inputs.closure_extensions.iter().any(|e| {
        affected.contains_key(&Node::Extension(e.clone()))
            && declares(&catalog.extensions[e].required_cases)
    })
}
