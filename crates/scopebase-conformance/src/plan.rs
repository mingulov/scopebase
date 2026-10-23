// SPDX-License-Identifier: Apache-2.0
//! TT07 `plan`: selection plus closure accounting, no active setup.
//!
//! NEW (TT07): no donor lines copied.

use crate::closure::{self, MANIFEST_FILE};
use crate::error::{OperatorError, OperatorErrorKind};
use scopebase_testkit::{CaseCatalog, CatalogLimits, ProfileId, ProfilePlan};
use serde::Serialize;
use std::path::Path;

/// One planned required cell.
#[derive(Clone, Debug, Serialize)]
pub struct PlannedCell {
    /// Case identifier.
    pub case_id: String,
    /// Case version.
    pub case_version: u32,
    /// Cell identifier.
    pub cell_id: String,
}

/// A run plan: selection, closure status and declared effects (none).
#[derive(Clone, Debug, Serialize)]
pub struct PlanDoc {
    /// Always `not_evaluated`: planning claims no behavioral support.
    pub qualification: String,
    /// Requested profile identifier.
    pub profile: String,
    /// Expanded profile closure.
    pub profiles: Vec<String>,
    /// Planned required cells.
    pub required: Vec<PlannedCell>,
    /// Whether the fixture-root closure verified completely.
    pub closure_complete: bool,
    /// Closure files absent from the fixture root.
    pub missing: Vec<String>,
    /// Closure files whose bytes do not match their pins.
    pub mismatched: Vec<String>,
    /// Recorded mapping policy.
    pub mapping_policy: String,
    /// Effects planning performs (always empty).
    pub effects: Vec<String>,
}

/// Plan a profile against a fixture root without executing anything.
pub fn plan(
    catalog_bytes: &[u8],
    profile: &str,
    fixture_root: &Path,
    mapping_policy: &str,
) -> Result<PlanDoc, OperatorError> {
    crate::delivery::check_mapping_policy(mapping_policy)?;
    let catalog =
        CaseCatalog::load(catalog_bytes, CatalogLimits::default()).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!("catalog rejected: {e}"),
            )
        })?;
    let id = ProfileId::parse(profile).map_err(|_| {
        OperatorError::new(
            OperatorErrorKind::UnknownProfile,
            format!("profile id rejected: {profile}"),
        )
    })?;
    let selected = ProfilePlan::select(&catalog, &id).map_err(|_| {
        OperatorError::new(
            OperatorErrorKind::UnknownProfile,
            format!("profile is not in the catalog: {profile}"),
        )
    })?;
    let required = selected
        .required()
        .iter()
        .map(|cell| PlannedCell {
            case_id: cell.case_id().as_str().to_string(),
            case_version: cell.case_version(),
            cell_id: cell.cell_id().to_string(),
        })
        .collect();
    let manifest_path = fixture_root.join(MANIFEST_FILE);
    let manifest_bytes = std::fs::read(&manifest_path).unwrap_or_default();
    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    let closure_complete =
        closure::verify_closure(fixture_root, &manifest_path).is_ok() && !manifest_bytes.is_empty();
    if !closure_complete {
        // Account each pinned file individually without failing fast.
        if let Ok(doc) =
            serde_json::from_slice::<serde_json::Value>(&manifest_bytes)
        {
            for entry in doc
                .get("files")
                .and_then(|f| f.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let path = entry
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("?")
                    .to_string();
                let target = fixture_root.join(&path);
                match std::fs::read(&target) {
                    Err(_) => missing.push(path),
                    Ok(bytes) => {
                        let length = entry
                            .get("length")
                            .and_then(|l| l.as_str())
                            .and_then(|l| l.parse::<u64>().ok());
                        let sha = entry.get("sha256").and_then(|s| s.as_str());
                        let digest =
                            scopebase_testkit::Digest256::of_bytes(&bytes).as_str();
                        if length != Some(bytes.len() as u64) || sha != Some(digest.as_str()) {
                            mismatched.push(path);
                        }
                    }
                }
            }
        } else if manifest_bytes.is_empty() {
            missing.push(MANIFEST_FILE.into());
        } else {
            mismatched.push(MANIFEST_FILE.into());
        }
    }
    Ok(PlanDoc {
        qualification: crate::error::NO_QUALIFICATION.to_string(),
        profile: profile.to_string(),
        profiles: selected
            .profiles()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect(),
        required,
        closure_complete,
        missing,
        mismatched,
        mapping_policy: mapping_policy.to_string(),
        effects: Vec::new(),
    })
}
