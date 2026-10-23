// SPDX-License-Identifier: Apache-2.0
//! TC03: explicit ISA profile admission. Profiles are admitted by exact
//! name/version only; unlisted names or versions refuse typed. Each profile
//! pins the exact expected `(cpu, features)` subset plus the allowed and
//! required effective families and the license gate, so a preset drift or an
//! unlisted effective family refuses instead of silently broadening support.
//! Contract `(cpu, features)` map to effective families through the recorded
//! llc 21.1.8 emission bundles (`fixtures/bpf/isa/expected.json`
//! `cpu_bundles`); `None` stays distinct from `generic` with baseline-only
//! content.
//!
//! Donor slice (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! `llvm-bpf-toolchain-experiment.md` lines 77-100 (user-authored H30 preset
//! warning and LLVM 18 original v4 bundle). Grant: OWNER-2026-10-23.
use scopebase_bpf::{ErrorKind, Limits, OperationError};
use serde_json::Value;

use super::inspect::{ObjectInspection, RuleViolation};
use super::manifest::ObjectEntry;
use super::{
    check_no_unknown, check_version, get_str, parse_label, strict_value, tc03_refuse,
    ObjectContract, KNOWN_CPUS, KNOWN_FEATURES, V4_ONLY_FEATURES,
};

const PROFILE_FIELDS: &[&str] = &[
    "schema_version",
    "kind",
    "name",
    "version",
    "cpu",
    "features_enabled",
    "allowed_families",
    "required_families",
    "admitted_licenses",
    "requires_license",
];

/// Every family the decoder can report. Feature names from the TC01 contract
/// grammar map 1:1 onto these; `base` has no feature flag.
const KNOWN_FAMILIES: &[&str] = &[
    "base",
    "alu32",
    "jump32",
    "ext-jumps",
    "signed-load-move",
    "byte-swap",
    "signed-div",
    "long-jump",
    "imm-store",
    "acqrel",
    "indirect-jumps",
];

/// Families a CPU preset was observed to emit without explicit features
/// (llc 21.1.8, `fixtures/bpf/isa/expected.json` probe matrix). `None` (no
/// preset claim) is baseline-only; `generic` honestly covers the jump32,
/// signed-jump and byte-swap forms that preset emits.
fn cpu_bundle(cpu: Option<&str>) -> Vec<&'static str> {
    match cpu {
        None => vec!["base"],
        Some("generic") => vec!["base", "byte-swap", "ext-jumps", "jump32"],
        Some("v3") => vec!["alu32", "base", "byte-swap", "ext-jumps", "jump32"],
        Some("v4") => vec![
            "acqrel",
            "alu32",
            "base",
            "byte-swap",
            "ext-jumps",
            "jump32",
            "signed-div",
            "signed-load-move",
        ],
        // Unreachable: TC01 admits only generic/v3/v4.
        Some(_) => vec!["base"],
    }
}

/// Effective families a contract describes: its CPU bundle plus explicitly
/// enabled features, sorted and deduplicated.
pub fn contract_families(contract: &ObjectContract) -> Vec<String> {
    let mut out = cpu_bundle(contract.cpu());
    out.extend(
        contract
            .features_enabled()
            .iter()
            .map(String::as_str)
            .filter(|feature| KNOWN_FAMILIES.contains(feature)),
    );
    out.sort();
    out.dedup();
    out.iter().map(|family| family.to_string()).collect()
}

/// One explicitly admitted ISA profile: exact `(cpu, features)` pin, allowed
/// and required effective families, and the license gate.
#[derive(Debug, Clone)]
pub struct IsaProfile {
    name: String,
    version: String,
    cpu: Option<String>,
    features_enabled: Vec<String>,
    allowed_families: Vec<String>,
    required_families: Vec<String>,
    admitted_licenses: Vec<String>,
    requires_license: bool,
}

fn parse_family_list(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Vec<String>, OperationError> {
    let values = root
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, field))?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let text = value
            .as_str()
            .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, field))?;
        if !KNOWN_FAMILIES.contains(&text) {
            return Err(tc03_refuse(ErrorKind::InvalidInput, field));
        }
        if out.iter().any(|seen: &String| seen == text) {
            return Err(tc03_refuse(ErrorKind::InvalidInput, field));
        }
        out.push(text.to_owned());
    }
    Ok(out)
}

fn parse_feature_list(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Vec<String>, OperationError> {
    let values = root
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, field))?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let text = value
            .as_str()
            .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, field))?;
        parse_label(text, field)?;
        if !KNOWN_FEATURES.contains(&text) {
            return Err(tc03_refuse(ErrorKind::InvalidInput, field));
        }
        if out.iter().any(|seen: &String| seen == text) {
            return Err(tc03_refuse(ErrorKind::InvalidInput, field));
        }
        out.push(text.to_owned());
    }
    Ok(out)
}

impl IsaProfile {
    /// Admit one strict versioned ISA profile document.
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError> {
        let value = strict_value(bytes, limits)?;
        let root = value
            .as_object()
            .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "isa profile object"))?;
        check_version(root)?;
        check_no_unknown(root, PROFILE_FIELDS)?;
        if get_str(root, "kind")? != "tc03_isa_profile" {
            return Err(tc03_refuse(ErrorKind::InvalidInput, "kind"));
        }
        let name = get_str(root, "name")?;
        parse_label(name, "profile name")?;
        let version = get_str(root, "version")?;
        if version.is_empty()
            || version.len() > 64
            || !version.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(tc03_refuse(ErrorKind::InvalidInput, "profile version"));
        }
        let cpu = match root.get("cpu") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) => {
                if !KNOWN_CPUS.contains(&text.as_str()) {
                    return Err(tc03_refuse(ErrorKind::InvalidInput, "cpu"));
                }
                Some(text.clone())
            }
            Some(_) => return Err(tc03_refuse(ErrorKind::InvalidInput, "cpu")),
        };
        let features_enabled = parse_feature_list(root, "features_enabled")?;
        match cpu.as_deref() {
            None | Some("generic") => {
                if !features_enabled.is_empty() {
                    return Err(tc03_refuse(
                        ErrorKind::Incompatible,
                        "enabled features without a v3/v4 cpu pin",
                    ));
                }
            }
            Some("v3") => {
                if features_enabled
                    .iter()
                    .any(|feature| V4_ONLY_FEATURES.contains(&feature.as_str()))
                {
                    return Err(tc03_refuse(
                        ErrorKind::Incompatible,
                        "v4-only feature on v3",
                    ));
                }
            }
            Some(_) => {}
        }
        let allowed_families = parse_family_list(root, "allowed_families")?;
        let required_families = parse_family_list(root, "required_families")?;
        if required_families
            .iter()
            .any(|family| !allowed_families.iter().any(|other| other == family))
        {
            return Err(tc03_refuse(
                ErrorKind::Incompatible,
                "required family outside allowed set",
            ));
        }
        let licenses = root
            .get("admitted_licenses")
            .and_then(Value::as_array)
            .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "admitted_licenses"))?;
        let mut admitted_licenses = Vec::with_capacity(licenses.len());
        for license in licenses {
            let text = license
                .as_str()
                .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "admitted_licenses"))?;
            if text.is_empty()
                || text.len() > 128
                || !text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            {
                return Err(tc03_refuse(ErrorKind::InvalidInput, "admitted_licenses"));
            }
            if admitted_licenses.iter().any(|seen: &String| seen == text) {
                return Err(tc03_refuse(ErrorKind::InvalidInput, "admitted_licenses"));
            }
            admitted_licenses.push(text.to_owned());
        }
        let requires_license = root
            .get("requires_license")
            .and_then(Value::as_bool)
            .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "requires_license"))?;
        if requires_license && admitted_licenses.is_empty() {
            return Err(tc03_refuse(
                ErrorKind::Incompatible,
                "license required but nothing admitted",
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            version: version.to_owned(),
            cpu,
            features_enabled,
            allowed_families,
            required_families,
            admitted_licenses,
            requires_license,
        })
    }

    /// Admitted profile name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Admitted exact profile version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Pinned CPU preset; `None` is distinct from every named preset.
    pub fn cpu(&self) -> Option<&str> {
        self.cpu.as_deref()
    }

    /// Pinned exact enabled features.
    pub fn features_enabled(&self) -> &[String] {
        &self.features_enabled
    }

    /// Admitted effective families.
    pub fn allowed_families(&self) -> &[String] {
        &self.allowed_families
    }

    /// Effective families that must be present.
    pub fn required_families(&self) -> &[String] {
        &self.required_families
    }

    /// Admitted runtime license tokens.
    pub fn admitted_licenses(&self) -> &[String] {
        &self.admitted_licenses
    }

    /// Whether a license declaration is required.
    pub fn requires_license(&self) -> bool {
        self.requires_license
    }
}

/// Admit one profile by exact name and version. Unlisted names and unlisted
/// versions of listed names both refuse [`ErrorKind::InvalidInput`]: version
/// drift never silently re-resolves.
pub fn admit_profile<'a>(
    profiles: &'a [IsaProfile],
    name: &str,
    version: &str,
) -> Result<&'a IsaProfile, OperationError> {
    let profile = profiles
        .iter()
        .find(|profile| profile.name() == name)
        .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "unlisted isa profile"))?;
    if profile.version() != version {
        return Err(tc03_refuse(
            ErrorKind::InvalidInput,
            "unlisted isa profile version",
        ));
    }
    Ok(profile)
}

fn sorted_set(items: &[String]) -> Vec<&str> {
    let mut out: Vec<&str> = items.iter().map(String::as_str).collect();
    out.sort();
    out
}

/// Check an admitted, inspected object against a profile and contract.
///
/// Attribution errors (entry naming another profile/contract, inspection of
/// other bytes, kind or declared-license contradiction) refuse typed.
/// Semantic findings return as violations: preset drift between contract and
/// profile pins, families forbidden by the contract or the profile, missing
/// required families, and license gate findings.
pub fn check_object(
    profile: &IsaProfile,
    contract: &ObjectContract,
    inspection: &ObjectInspection,
    entry: &ObjectEntry,
) -> Result<Vec<RuleViolation>, OperationError> {
    if entry.isa_profile() != profile.name() || entry.isa_version() != profile.version() {
        return Err(tc03_refuse(
            ErrorKind::InvalidInput,
            "manifest entry names a different isa profile",
        ));
    }
    if entry.artifact() != contract.artifact() || entry.profile() != contract.profile() {
        return Err(tc03_refuse(
            ErrorKind::InvalidInput,
            "manifest entry names a different contract",
        ));
    }
    if entry.sha256() != inspection.object_id().sha256() {
        return Err(tc03_refuse(
            ErrorKind::InvalidInput,
            "inspection is not of the admitted bytes",
        ));
    }
    if entry.kind() != inspection.kind() {
        return Err(tc03_refuse(
            ErrorKind::Incompatible,
            "manifest kind contradicts object",
        ));
    }
    match (entry.license_declared(), inspection.license()) {
        (None, _) => {}
        (Some(_), None) => {
            return Err(tc03_refuse(
                ErrorKind::Incompatible,
                "manifest declares a license the object lacks",
            ));
        }
        (Some(declared), Some(actual)) => {
            if declared != actual {
                return Err(tc03_refuse(
                    ErrorKind::Incompatible,
                    "manifest license differs from object",
                ));
            }
        }
    }
    let mut violations = Vec::new();
    if contract.cpu() != profile.cpu()
        || sorted_set(contract.features_enabled()) != sorted_set(profile.features_enabled())
    {
        violations.push(RuleViolation {
            rule_id: "isa.profile-drift".to_owned(),
            section: None,
            offset: None,
            kind: ErrorKind::Incompatible,
        });
    }
    let contract_allowed = contract_families(contract);
    for span in inspection.spans() {
        if !contract_allowed.iter().any(|family| family == &span.family) {
            violations.push(RuleViolation {
                rule_id: "isa.contract-forbidden-family".to_owned(),
                section: Some(span.section.clone()),
                offset: Some(span.offset),
                kind: ErrorKind::Incompatible,
            });
        }
    }
    for span in inspection.spans() {
        if !profile
            .allowed_families()
            .iter()
            .any(|family| family == &span.family)
        {
            violations.push(RuleViolation {
                rule_id: "isa.forbidden-family".to_owned(),
                section: Some(span.section.clone()),
                offset: Some(span.offset),
                kind: ErrorKind::Incompatible,
            });
        }
    }
    for family in profile.required_families() {
        if !inspection.families().iter().any(|other| other == family) {
            violations.push(RuleViolation {
                rule_id: "isa.missing-required-family".to_owned(),
                section: None,
                offset: None,
                kind: ErrorKind::Incompatible,
            });
        }
    }
    match (profile.requires_license(), inspection.license()) {
        (true, None) => violations.push(RuleViolation {
            rule_id: "license.missing".to_owned(),
            section: None,
            offset: None,
            kind: ErrorKind::Incompatible,
        }),
        (_, Some(actual))
            if !profile
                .admitted_licenses()
                .iter()
                .any(|other| other == actual) =>
        {
            violations.push(RuleViolation {
                rule_id: "license.incompatible".to_owned(),
                section: None,
                offset: None,
                kind: ErrorKind::Incompatible,
            });
        }
        _ => {}
    }
    Ok(violations)
}
