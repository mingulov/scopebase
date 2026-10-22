// SPDX-License-Identifier: Apache-2.0
use std::{error::Error, fmt};
#[derive(Clone, Debug)]
pub struct CatalogLimits {
    pub max_input_bytes: usize,
    pub max_cases: usize,
    pub max_profiles: usize,
    pub max_extensions: usize,
    pub max_obligations: usize,
    pub max_cells: usize,
    pub max_edges: usize,
    pub max_string_bytes: usize,
    pub max_depth: usize,
    pub max_selected_cells: usize,
}
impl Default for CatalogLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 8388608,
            max_cases: 4096,
            max_profiles: 128,
            max_extensions: 128,
            max_obligations: 512,
            max_cells: 256,
            max_edges: 8192,
            max_string_bytes: 65536,
            max_depth: 32,
            max_selected_cells: 16384,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogErrorKind {
    InvalidRegistration,
    InvalidLimits,
    InputTooLarge,
    InvalidJson,
    DuplicateField,
    UnknownField,
    UnsupportedSchema,
    LimitExceeded,
    InvalidId,
    DuplicateId,
    UnknownReference,
    InvalidVersion,
    VersionConflict,
    Cycle,
    InvalidDefinition,
}
#[derive(Debug)]
pub struct CatalogError(pub(crate) CatalogErrorKind);
impl CatalogError {
    pub fn kind(&self) -> CatalogErrorKind {
        self.0
    }
}
impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "catalog rejected: {:?}", self.0)
    }
}
impl Error for CatalogError {}

use crate::{CaseId, ProfileId};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ObligationRef {
    pub(crate) kind: String,
    pub(crate) id: String,
}
impl ObligationRef {
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ObligationSpec {
    pub(crate) kind: String,
    pub(crate) id: String,
    pub(crate) description: String,
    pub(crate) owners: Vec<String>,
}
impl ObligationSpec {
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn description(&self) -> &str {
        &self.description
    }
    pub fn owners(&self) -> &[String] {
        &self.owners
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ArtifactRegistration {
    pub(crate) id: CaseId,
    pub(crate) revision: u32,
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) entrypoint: CaseId,
}
impl ArtifactRegistration {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }
    pub fn revision(&self) -> u32 {
        self.revision
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn entrypoint(&self) -> &str {
        self.entrypoint.as_str()
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ExecutableRegistration {
    pub(crate) executable: ArtifactRegistration,
    pub(crate) fixture: ArtifactRegistration,
    pub(crate) oracle: ArtifactRegistration,
    pub(crate) bad_control: ArtifactRegistration,
    pub(crate) oracle_basis: String,
    pub(crate) control_assertion: String,
}
impl ExecutableRegistration {
    pub fn executable(&self) -> &ArtifactRegistration {
        &self.executable
    }
    pub fn fixture(&self) -> &ArtifactRegistration {
        &self.fixture
    }
    pub fn oracle(&self) -> &ArtifactRegistration {
        &self.oracle
    }
    pub fn bad_control(&self) -> &ArtifactRegistration {
        &self.bad_control
    }
    pub fn oracle_basis(&self) -> &str {
        &self.oracle_basis
    }
    pub fn control_assertion(&self) -> &str {
        &self.control_assertion
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CaseSpec {
    pub(crate) id: CaseId,
    pub(crate) family: String,
    pub(crate) version: u32,
    pub(crate) implementation_status: ImplementationStatus,
    pub(crate) owners: Vec<String>,
    pub(crate) obligations: Vec<ObligationRef>,
    pub(crate) required_cells: Vec<String>,
    pub(crate) registration: Option<ExecutableRegistration>,
}
impl CaseSpec {
    pub fn id(&self) -> &CaseId {
        &self.id
    }
    pub fn family(&self) -> &str {
        &self.family
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn implementation_status(&self) -> ImplementationStatus {
        self.implementation_status
    }
    pub fn owners(&self) -> &[String] {
        &self.owners
    }
    pub fn obligations(&self) -> &[ObligationRef] {
        &self.obligations
    }
    pub fn required_cells(&self) -> &[String] {
        &self.required_cells
    }
    pub fn registration(&self) -> Option<&ExecutableRegistration> {
        self.registration.as_ref()
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequiredCaseSpec {
    pub(crate) case_id: CaseId,
    pub(crate) case_version: u32,
    pub(crate) when_extensions: Vec<ProfileId>,
}
impl RequiredCaseSpec {
    pub fn case_id(&self) -> &CaseId {
        &self.case_id
    }
    pub fn case_version(&self) -> u32 {
        self.case_version
    }
    pub fn when_extensions(&self) -> &[ProfileId] {
        &self.when_extensions
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProfileSpec {
    pub(crate) id: ProfileId,
    pub(crate) definition_state: DefinitionState,
    pub(crate) requires_profiles: Vec<ProfileId>,
    pub(crate) requires_extensions: Vec<ProfileId>,
    pub(crate) required_cases: Vec<RequiredCaseSpec>,
    pub(crate) open_owners: Vec<String>,
}
impl ProfileSpec {
    pub fn id(&self) -> &ProfileId {
        &self.id
    }
    pub fn definition_state(&self) -> DefinitionState {
        self.definition_state
    }
    pub fn requires_profiles(&self) -> &[ProfileId] {
        &self.requires_profiles
    }
    pub fn requires_extensions(&self) -> &[ProfileId] {
        &self.requires_extensions
    }
    pub fn required_cases(&self) -> &[RequiredCaseSpec] {
        &self.required_cases
    }
    pub fn open_owners(&self) -> &[String] {
        &self.open_owners
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EvidenceTier {
    T0,
    T1,
    T2,
    T3,
    T4,
    T5,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ImplementationStatus {
    Unimplemented,
    RegisteredExecutable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DefinitionState {
    Draft,
    Frozen,
}
#[derive(Clone, Debug)]
pub(crate) struct CellSpec {
    pub(crate) id: String,
    pub(crate) tier: EvidenceTier,
}
#[derive(Clone, Debug)]
pub(crate) struct ExtensionSpec {
    pub(crate) profile: ProfileId,
    pub(crate) requires_profiles: Vec<ProfileId>,
    pub(crate) required_cases: Vec<RequiredCaseSpec>,
}
#[derive(Debug)]
pub struct CaseCatalog {
    source_sha256: crate::Digest256,
    pub(crate) revision: u32,
    pub(crate) cases: BTreeMap<(CaseId, u32), CaseSpec>,
    pub(crate) profiles: BTreeMap<ProfileId, ProfileSpec>,
    pub(crate) extensions: BTreeMap<ProfileId, ExtensionSpec>,
    pub(crate) obligations: Vec<ObligationSpec>,
    pub(crate) cells: BTreeMap<String, CellSpec>,
    pub(crate) max_selected_cells: usize,
}
impl CaseCatalog {
    pub fn source_sha256(&self) -> crate::Digest256 {
        self.source_sha256
    }
    pub fn revision(&self) -> u32 {
        self.revision
    }
    pub fn case(&self, id: &CaseId, version: u32) -> Option<&CaseSpec> {
        self.cases.get(&(id.clone(), version))
    }
    pub fn profile(&self, id: &ProfileId) -> Option<&ProfileSpec> {
        self.profiles.get(id)
    }
    pub fn obligations(&self) -> &[ObligationSpec] {
        &self.obligations
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    schema_version: u32,
    catalog_revision: u32,
    tasks: Vec<String>,
    obligations: Vec<RawObligation>,
    families: Vec<RawFamily>,
    cells: Vec<RawCell>,
    cases: Vec<RawCase>,
    profiles: Vec<RawProfile>,
    extensions: Vec<RawExtension>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRef {
    kind: String,
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObligation {
    kind: String,
    id: String,
    description: String,
    owners: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFamily {
    id: String,
    short_contract: String,
    obligations: Vec<RawRef>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCell {
    id: String,
    tier: String,
    description: String,
    binding: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    id: String,
    revision: u32,
    path: String,
    sha256: String,
    entrypoint: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistration {
    executable: RawArtifact,
    fixture: RawArtifact,
    oracle: RawArtifact,
    bad_control: RawArtifact,
    oracle_basis: String,
    control_assertion: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCase {
    id: String,
    family: String,
    version: u32,
    implementation_status: String,
    owners: Vec<String>,
    obligations: Vec<RawRef>,
    required_cells: Vec<String>,
    registration: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequired {
    case_id: String,
    case_version: u32,
    when_extensions: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    id: String,
    definition_state: String,
    requires_profiles: Vec<String>,
    requires_extensions: Vec<String>,
    required_cases: Vec<RawRequired>,
    open_owners: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExtension {
    id: String,
    profile: String,
    requires_profiles: Vec<String>,
    requires_tasks: Vec<String>,
    required_cases: Vec<RawRequired>,
}

fn err<T>(k: CatalogErrorKind) -> Result<T, CatalogError> {
    Err(CatalogError(k))
}
impl CatalogLimits {
    fn validate(&self) -> Result<(), CatalogError> {
        let ceiling = Self::default();
        let actual = [
            self.max_input_bytes,
            self.max_cases,
            self.max_profiles,
            self.max_extensions,
            self.max_obligations,
            self.max_cells,
            self.max_edges,
            self.max_string_bytes,
            self.max_depth,
            self.max_selected_cells,
        ];
        let maximum = [
            ceiling.max_input_bytes,
            ceiling.max_cases,
            ceiling.max_profiles,
            ceiling.max_extensions,
            ceiling.max_obligations,
            ceiling.max_cells,
            ceiling.max_edges,
            ceiling.max_string_bytes,
            ceiling.max_depth,
            ceiling.max_selected_cells,
        ];
        if actual.iter().zip(maximum).any(|(a, b)| *a == 0 || *a > b) {
            return err(CatalogErrorKind::InvalidLimits);
        }
        Ok(())
    }
}
// Delimiter preflight bounds nesting without interpreting JSON syntax. Serde remains
// the grammar authority, including escapes, surrogate pairs and trailing input.
fn depth_bound(bytes: &[u8], max: usize) -> Result<(), CatalogError> {
    let (mut quoted, mut escaped, mut depth) = (false, false, 0usize);
    for &b in bytes {
        if quoted {
            if escaped {
                escaped = false
            } else if b == b'\\' {
                escaped = true
            } else if b == b'"' {
                quoted = false
            }
        } else if b == b'"' {
            quoted = true
        } else if b == b'{' || b == b'[' {
            depth += 1;
            if depth > max {
                return err(CatalogErrorKind::LimitExceeded);
            }
        } else if b == b'}' || b == b']' {
            depth = depth.saturating_sub(1)
        }
    }
    Ok(())
}
struct Seed<'a> {
    limits: &'a CatalogLimits,
    key: &'a str,
    edges: &'a std::cell::Cell<usize>,
    root: bool,
}
impl<'de> serde::de::DeserializeSeed<'de> for Seed<'_> {
    type Value = serde_json::Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for Seed<'_> {
    type Value = serde_json::Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(v)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("InvalidJson"))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if v.len() > self.limits.max_string_bytes {
            return Err(E::custom("LimitExceeded"));
        }
        Ok(v.into())
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        if v.len() > self.limits.max_string_bytes {
            return Err(E::custom("LimitExceeded"));
        }
        Ok(v.into())
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        let cap = match self.key {
            "tasks" | "families" => 128,
            "cases" => self.limits.max_cases,
            "profiles" => self.limits.max_profiles,
            "extensions" => self.limits.max_extensions,
            "cells" => self.limits.max_cells,
            "obligations" if self.root => self.limits.max_obligations,
            _ => self.limits.max_edges,
        };
        let edge = matches!(
            self.key,
            "owners"
                | "required_cells"
                | "requires_profiles"
                | "requires_extensions"
                | "required_cases"
                | "when_extensions"
                | "open_owners"
                | "requires_tasks"
        ) || (self.key == "obligations" && !self.root);
        let mut out = Vec::new();
        loop {
            // Deserialize at most one bounded element beyond the ceiling, never push or
            // reserve for it. IgnoredAny would skip nested duplicate/size validation.
            let next = a.next_element_seed(Seed {
                limits: self.limits,
                key: "",
                edges: self.edges,
                root: false,
            })?;
            let Some(value) = next else { break };
            if out.len() == cap {
                return Err(A::Error::custom("LimitExceeded"));
            }
            if edge {
                let n = self.edges.get();
                if n == self.limits.max_edges {
                    return Err(A::Error::custom("LimitExceeded"));
                }
                self.edges.set(n + 1)
            }
            out.push(value);
        }
        Ok(out.into())
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        let mut out = serde_json::Map::new();
        while let Some(key) = a.next_key::<String>()? {
            if key.len() > self.limits.max_string_bytes {
                return Err(A::Error::custom("LimitExceeded"));
            }
            if out.contains_key(&key) {
                return Err(A::Error::custom("DuplicateField"));
            }
            // The schema's widest object is the ten-field root. Reject unknown giant
            // maps before growing them, even when nested in an unselected record.
            if out.len() == 10 {
                return Err(A::Error::custom("UnknownField"));
            }
            if key == "profile" || key == "family" {
                let n = self.edges.get();
                if n == self.limits.max_edges {
                    return Err(A::Error::custom("LimitExceeded"));
                }
                self.edges.set(n + 1)
            }
            let value = a.next_value_seed(Seed {
                limits: self.limits,
                key: &key,
                edges: self.edges,
                root: self.root && self.key.is_empty(),
            })?;
            if matches!(
                key.as_str(),
                "version" | "revision" | "case_version" | "catalog_revision"
            ) && (!value
                .as_u64()
                .is_some_and(|n| n > 0 && n <= u32::MAX as u64))
            {
                return Err(A::Error::custom("InvalidVersion"));
            }
            out.insert(key, value);
        }
        Ok(out.into())
    }
}
fn parse_error(e: serde_json::Error) -> CatalogError {
    let s = e.to_string();
    let kind = if s.starts_with("DuplicateField") {
        CatalogErrorKind::DuplicateField
    } else if s.starts_with("unknown field") || s.starts_with("UnknownField") {
        CatalogErrorKind::UnknownField
    } else if s.starts_with("LimitExceeded") {
        CatalogErrorKind::LimitExceeded
    } else if s.starts_with("InvalidVersion") {
        CatalogErrorKind::InvalidVersion
    } else {
        CatalogErrorKind::InvalidJson
    };
    CatalogError(kind)
}
fn unique<T: Ord>(v: &[T]) -> Result<(), CatalogError> {
    if v.iter().collect::<BTreeSet<_>>().len() != v.len() {
        return err(CatalogErrorKind::DuplicateId);
    }
    Ok(())
}
fn strings(v: &[String], nonempty: bool) -> Result<(), CatalogError> {
    unique(v)?;
    if nonempty && v.is_empty() {
        return err(CatalogErrorKind::InvalidDefinition);
    }
    Ok(())
}
fn cid(s: &str) -> Result<CaseId, CatalogError> {
    CaseId::parse(s).map_err(|_| CatalogError(CatalogErrorKind::InvalidId))
}
fn pid(s: &str) -> Result<ProfileId, CatalogError> {
    let id = ProfileId::parse(s).map_err(|_| CatalogError(CatalogErrorKind::InvalidId))?;
    let Some((stem, version)) = s.rsplit_once("-v") else {
        return err(CatalogErrorKind::InvalidVersion);
    };
    if stem.is_empty()
        || version.starts_with('0')
        || !version.bytes().all(|b| b.is_ascii_digit())
        || !version.parse::<u32>().is_ok_and(|n| n > 0)
    {
        return err(CatalogErrorKind::InvalidVersion);
    }
    Ok(id)
}
fn refs(
    raw: Vec<RawRef>,
    registered: &BTreeSet<(String, String)>,
) -> Result<Vec<ObligationRef>, CatalogError> {
    let out: Vec<_> = raw
        .into_iter()
        .map(|r| ObligationRef {
            kind: r.kind,
            id: r.id,
        })
        .collect();
    unique(&out)?;
    if out
        .iter()
        .any(|r| !registered.contains(&(r.kind.clone(), r.id.clone())))
    {
        return err(CatalogErrorKind::UnknownReference);
    }
    Ok(out)
}
fn owners(v: &[String], tasks: &BTreeSet<String>, nonempty: bool) -> Result<(), CatalogError> {
    strings(v, nonempty)?;
    if v.iter().any(|s| !tasks.contains(s)) {
        return err(CatalogErrorKind::UnknownReference);
    }
    Ok(())
}
fn artifact(a: RawArtifact) -> Result<ArtifactRegistration, CatalogError> {
    let good_path = !a.path.is_empty()
        && !a.path.contains(['\\', '\0'])
        && a.path
            .split('/')
            .all(|v| !v.is_empty() && v != "." && v != "..");
    if !good_path
        || a.sha256.len() != 64
        || !a
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return err(CatalogErrorKind::InvalidRegistration);
    }
    let id = cid(&a.id).map_err(|_| CatalogError(CatalogErrorKind::InvalidRegistration))?;
    let entrypoint =
        cid(&a.entrypoint).map_err(|_| CatalogError(CatalogErrorKind::InvalidRegistration))?;
    Ok(ArtifactRegistration {
        id,
        revision: a.revision,
        path: a.path,
        sha256: a.sha256,
        entrypoint,
    })
}
fn registration(v: serde_json::Value) -> Result<ExecutableRegistration, CatalogError> {
    let raw: RawRegistration = serde_json::from_value(v).map_err(|e| {
        let k = parse_error(e).kind();
        CatalogError(if k == CatalogErrorKind::UnknownField {
            k
        } else {
            CatalogErrorKind::InvalidRegistration
        })
    })?;
    let out = ExecutableRegistration {
        executable: artifact(raw.executable)?,
        fixture: artifact(raw.fixture)?,
        oracle: artifact(raw.oracle)?,
        bad_control: artifact(raw.bad_control)?,
        oracle_basis: raw.oracle_basis,
        control_assertion: raw.control_assertion,
    };
    let identity =
        |a: &ArtifactRegistration| (a.path.clone(), a.sha256.clone(), a.entrypoint.clone());
    if out.oracle_basis.is_empty()
        || out.control_assertion.is_empty()
        || identity(&out.oracle) == identity(&out.executable)
        || identity(&out.bad_control) == identity(&out.executable)
    {
        return err(CatalogErrorKind::InvalidRegistration);
    }
    Ok(out)
}
fn required(v: Vec<RawRequired>) -> Result<Vec<RequiredCaseSpec>, CatalogError> {
    let out: Vec<_> = v
        .into_iter()
        .map(|r| {
            Ok(RequiredCaseSpec {
                case_id: cid(&r.case_id)?,
                case_version: r.case_version,
                when_extensions: r
                    .when_extensions
                    .iter()
                    .map(|s| pid(s))
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect::<Result<_, CatalogError>>()?;
    for r in &out {
        unique(&r.when_extensions)?
    }
    let mut out = out;
    for r in &mut out {
        r.when_extensions.sort();
    }
    unique(&out)?;
    Ok(out)
}
impl CaseCatalog {
    pub fn load(bytes: &[u8], limits: CatalogLimits) -> Result<Self, CatalogError> {
        use serde::de::DeserializeSeed;
        limits.validate()?;
        if bytes.len() > limits.max_input_bytes {
            return err(CatalogErrorKind::InputTooLarge);
        }
        depth_bound(bytes, limits.max_depth)?;
        let edges = std::cell::Cell::new(0);
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let value = Seed {
            limits: &limits,
            key: "",
            edges: &edges,
            root: true,
        }
        .deserialize(&mut decoder)
        .map_err(parse_error)?;
        decoder.end().map_err(parse_error)?;
        let raw: RawCatalog = serde_json::from_value(value).map_err(parse_error)?;
        if raw.schema_version != 1 {
            return err(CatalogErrorKind::UnsupportedSchema);
        }
        strings(&raw.tasks, true)?;
        for t in &raw.tasks {
            cid(t)?;
        }
        let tasks: BTreeSet<_> = raw.tasks.into_iter().collect();
        let mut obligations = Vec::new();
        let mut registered = BTreeSet::new();
        for o in raw.obligations {
            if !matches!(
                o.kind.as_str(),
                "research_todo"
                    | "regression_family"
                    | "public_contract_gap"
                    | "user_conformance"
                    | "overlap_row"
            ) {
                return err(CatalogErrorKind::InvalidDefinition);
            }
            cid(&o.id)?;
            owners(&o.owners, &tasks, true)?;
            if !registered.insert((o.kind.clone(), o.id.clone())) {
                return err(CatalogErrorKind::DuplicateId);
            }
            obligations.push(ObligationSpec {
                kind: o.kind,
                id: o.id,
                description: o.description,
                owners: o.owners,
            });
        }
        let mut families = BTreeSet::new();
        for f in raw.families {
            cid(&f.id)?;
            if !families.insert(f.id.clone()) {
                return err(CatalogErrorKind::DuplicateId);
            }
            let obligations = refs(f.obligations, &registered)?;
            if f.short_contract.is_empty()
                || !obligations
                    .iter()
                    .any(|r| r.kind == "regression_family" && r.id == f.id)
            {
                return err(CatalogErrorKind::InvalidDefinition);
            }
        }
        let mut cells = BTreeMap::new();
        for c in raw.cells {
            cid(&c.id)?;
            let tier = match c.tier.as_str() {
                "T0" => EvidenceTier::T0,
                "T1" => EvidenceTier::T1,
                "T2" => EvidenceTier::T2,
                "T3" => EvidenceTier::T3,
                "T4" => EvidenceTier::T4,
                "T5" => EvidenceTier::T5,
                _ => return err(CatalogErrorKind::InvalidDefinition),
            };
            if c.binding != "LOGICAL_ONLY" || c.description.is_empty() {
                return err(CatalogErrorKind::InvalidDefinition);
            }
            if cells
                .insert(c.id.clone(), CellSpec { id: c.id, tier })
                .is_some()
            {
                return err(CatalogErrorKind::DuplicateId);
            }
        }
        let mut cases = BTreeMap::new();
        for c in raw.cases {
            let id = cid(&c.id)?;
            if !families.contains(&c.family) {
                return err(CatalogErrorKind::UnknownReference);
            }
            if !c.id.starts_with(&(c.family.clone() + ".")) {
                return err(CatalogErrorKind::InvalidId);
            }
            owners(&c.owners, &tasks, true)?;
            strings(&c.required_cells, true)?;
            if c.required_cells.iter().any(|s| !cells.contains_key(s)) {
                return err(CatalogErrorKind::UnknownReference);
            }
            let (status, registration) = match c.implementation_status.as_str() {
                "UNIMPLEMENTED" if c.registration.is_null() => {
                    (ImplementationStatus::Unimplemented, None)
                }
                "REGISTERED_EXECUTABLE" if !c.registration.is_null() => (
                    ImplementationStatus::RegisteredExecutable,
                    Some(registration(c.registration)?),
                ),
                _ => return err(CatalogErrorKind::InvalidRegistration),
            };
            let out = CaseSpec {
                id: id.clone(),
                family: c.family,
                version: c.version,
                implementation_status: status,
                owners: c.owners,
                obligations: refs(c.obligations, &registered)?,
                required_cells: c.required_cells,
                registration,
            };
            if cases.insert((id, c.version), out).is_some() {
                return err(CatalogErrorKind::DuplicateId);
            }
        }
        let mut profiles = BTreeMap::new();
        for p in raw.profiles {
            let id = pid(&p.id)?;
            let state = match p.definition_state.as_str() {
                "DRAFT" => DefinitionState::Draft,
                "FROZEN" => DefinitionState::Frozen,
                _ => return err(CatalogErrorKind::InvalidDefinition),
            };
            owners(&p.open_owners, &tasks, state == DefinitionState::Draft)?;
            if state == DefinitionState::Frozen && !p.open_owners.is_empty() {
                return err(CatalogErrorKind::InvalidDefinition);
            }
            let reqp = p
                .requires_profiles
                .iter()
                .map(|s| pid(s))
                .collect::<Result<Vec<_>, _>>()?;
            unique(&reqp)?;
            let reqe = p
                .requires_extensions
                .iter()
                .map(|s| pid(s))
                .collect::<Result<Vec<_>, _>>()?;
            unique(&reqe)?;
            let out = ProfileSpec {
                id: id.clone(),
                definition_state: state,
                requires_profiles: reqp,
                requires_extensions: reqe,
                required_cases: required(p.required_cases)?,
                open_owners: p.open_owners,
            };
            if profiles.insert(id, out).is_some() {
                return err(CatalogErrorKind::DuplicateId);
            }
        }
        let mut extensions = BTreeMap::new();
        for e in raw.extensions {
            let id = pid(&e.id)?;
            owners(&e.requires_tasks, &tasks, false)?;
            let reqp = e
                .requires_profiles
                .iter()
                .map(|s| pid(s))
                .collect::<Result<Vec<_>, _>>()?;
            unique(&reqp)?;
            let out = ExtensionSpec {
                profile: pid(&e.profile)?,
                requires_profiles: reqp,
                required_cases: required(e.required_cases)?,
            };
            if profiles.contains_key(&id) || extensions.insert(id, out).is_some() {
                return err(CatalogErrorKind::DuplicateId);
            }
        }
        let catalog = Self {
            source_sha256: crate::Digest256::of_bytes(bytes),
            revision: raw.catalog_revision,
            cases,
            profiles,
            extensions,
            obligations,
            cells,
            max_selected_cells: limits.max_selected_cells,
        };
        catalog.validate_graph()?;
        Ok(catalog)
    }
    pub(crate) fn graph_edges(&self, id: &ProfileId) -> Vec<ProfileId> {
        if let Some(p) = self.profiles.get(id) {
            p.requires_profiles
                .iter()
                .chain(p.requires_extensions.iter())
                .cloned()
                .collect()
        } else {
            let e = &self.extensions[id];
            std::iter::once(&e.profile)
                .chain(e.requires_profiles.iter())
                .cloned()
                .collect()
        }
    }
    fn validate_graph(&self) -> Result<(), CatalogError> {
        let check_required = |r: &RequiredCaseSpec| -> Result<(), CatalogError> {
            if !self
                .cases
                .contains_key(&(r.case_id.clone(), r.case_version))
                || r.when_extensions
                    .iter()
                    .any(|s| !self.extensions.contains_key(s))
            {
                return err(CatalogErrorKind::UnknownReference);
            }
            Ok(())
        };
        for p in self.profiles.values() {
            if p.requires_profiles
                .iter()
                .any(|s| !self.profiles.contains_key(s))
                || p.requires_extensions
                    .iter()
                    .any(|s| !self.extensions.contains_key(s))
            {
                return err(CatalogErrorKind::UnknownReference);
            }
            for r in &p.required_cases {
                check_required(r)?
            }
        }
        for e in self.extensions.values() {
            if !self.profiles.contains_key(&e.profile)
                || e.requires_profiles
                    .iter()
                    .any(|s| !self.profiles.contains_key(s))
            {
                return err(CatalogErrorKind::UnknownReference);
            }
            for r in &e.required_cases {
                check_required(r)?
            }
        }
        // Iterative DFS: gray nodes are on the active path, black nodes retired.
        let mut color = BTreeMap::new();
        for id in self.profiles.keys().chain(self.extensions.keys()) {
            let mut stack = vec![(id.clone(), false)];
            while let Some((id, exit)) = stack.pop() {
                if exit {
                    color.insert(id, 2);
                    continue;
                }
                match color.get(&id) {
                    Some(1) => return err(CatalogErrorKind::Cycle),
                    Some(2) => continue,
                    _ => {}
                }
                color.insert(id.clone(), 1);
                stack.push((id.clone(), true));
                for next in self.graph_edges(&id).into_iter().rev() {
                    stack.push((next, false))
                }
            }
        }
        for id in self.profiles.keys() {
            crate::profile::build(self, id)?;
        }
        Ok(())
    }
}
