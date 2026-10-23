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
    let catalog = CaseCatalog::load(catalog_bytes, CatalogLimits::default()).map_err(|e| {
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
    // R38: every planning read is bounded and root-validated —
    // the same reader the verifier uses. A manifest that failed
    // verification is untrusted input: entries are re-validated
    // before any read, so escapes, devices and oversized objects
    // land in `mismatched` without ever being opened the old way.
    let manifest_path = fixture_root.join(MANIFEST_FILE);
    let manifest_bytes =
        closure::read_member(fixture_root, MANIFEST_FILE, closure::MAX_MANIFEST_BYTES);
    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    let closure_complete = closure::verify_closure(fixture_root, &manifest_path).is_ok()
        && matches!(&manifest_bytes, Ok(bytes) if !bytes.is_empty());
    if !closure_complete {
        // Account each pinned file individually without failing fast.
        match manifest_bytes {
            Err(closure::BoundedReadError::NotFound(_)) => {
                missing.push(MANIFEST_FILE.into());
            }
            Err(closure::BoundedReadError::Refused(_)) => {
                mismatched.push(MANIFEST_FILE.into());
            }
            Ok(manifest_bytes) => {
                match serde_json::from_slice::<serde_json::Value>(&manifest_bytes) {
                    Err(_) if manifest_bytes.is_empty() => {
                        missing.push(MANIFEST_FILE.into());
                    }
                    Err(_) => {
                        mismatched.push(MANIFEST_FILE.into());
                    }
                    Ok(doc) => {
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
                            match closure::read_member(
                                fixture_root,
                                &path,
                                closure::MAX_CLOSURE_FILE_BYTES,
                            ) {
                                Err(closure::BoundedReadError::NotFound(_)) => missing.push(path),
                                Err(closure::BoundedReadError::Refused(_)) => {
                                    mismatched.push(path);
                                }
                                Ok(bytes) => {
                                    let length = entry
                                        .get("length")
                                        .and_then(|l| l.as_str())
                                        .and_then(|l| l.parse::<u64>().ok());
                                    let sha = entry.get("sha256").and_then(|s| s.as_str());
                                    let digest =
                                        scopebase_testkit::Digest256::of_bytes(&bytes).as_str();
                                    if length != Some(bytes.len() as u64)
                                        || sha != Some(digest.as_str())
                                    {
                                        mismatched.push(path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
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
