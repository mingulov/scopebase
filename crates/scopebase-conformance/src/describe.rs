// SPDX-License-Identifier: Apache-2.0
//! TT07 `describe`: pure catalog listing, no active setup.
//!
//! NEW (TT07): no donor lines copied.

use crate::error::{OperatorError, OperatorErrorKind};
use scopebase_testkit::{CaseCatalog, CatalogLimits};
use serde::Serialize;

/// One described profile.
#[derive(Clone, Debug, Serialize)]
pub struct ProfileEntry {
    /// Profile identifier.
    pub id: String,
    /// Frozen definition state marker.
    pub definition_state: String,
    /// Required case coordinates.
    pub required_cases: Vec<String>,
}

/// One described case.
#[derive(Clone, Debug, Serialize)]
pub struct CaseEntry {
    /// Case identifier.
    pub id: String,
    /// Case version.
    pub version: u32,
    /// Required cell identifiers.
    pub required_cells: Vec<String>,
}

/// A pure catalog description.
#[derive(Clone, Debug, Serialize)]
pub struct Description {
    /// Always `not_evaluated`: describing claims no behavioral support.
    pub qualification: String,
    /// Catalog revision.
    pub catalog_revision: u32,
    /// Catalog source digest.
    pub catalog_sha256: String,
    /// Described profiles.
    pub profiles: Vec<ProfileEntry>,
    /// Described cases.
    pub cases: Vec<CaseEntry>,
}

/// Describe catalog bytes without touching any other input.
///
/// Reads nothing but the supplied bytes and creates no files.
pub fn describe(catalog_bytes: &[u8]) -> Result<Description, OperatorError> {
    let catalog =
        CaseCatalog::load(catalog_bytes, CatalogLimits::default()).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!("catalog rejected: {e}"),
            )
        })?;
    let doc: serde_json::Value =
        serde_json::from_slice(catalog_bytes).map_err(|_| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                "catalog is not JSON",
            )
        })?;
    let mut profiles = Vec::new();
    for profile in doc
        .get("profiles")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let id = profile
            .get("id")
            .and_then(|i| i.as_str())
            .unwrap_or("?")
            .to_string();
        let mut required_cases = Vec::new();
        for case in profile
            .get("required_cases")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let case_id = case
                .get("case_id")
                .and_then(|i| i.as_str())
                .unwrap_or("?");
            let version = case.get("case_version").and_then(|v| v.as_u64()).unwrap_or(0);
            required_cases.push(format!("{case_id}:v{version}"));
        }
        profiles.push(ProfileEntry {
            id,
            definition_state: profile
                .get("definition_state")
                .and_then(|s| s.as_str())
                .unwrap_or("?")
                .to_string(),
            required_cases,
        });
    }
    let mut cases = Vec::new();
    for case in doc
        .get("cases")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default()
    {
        cases.push(CaseEntry {
            id: case
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("?")
                .to_string(),
            version: case
                .get("version")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            required_cells: case
                .get("required_cells")
                .and_then(|c| c.as_array())
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect(),
        });
    }
    Ok(Description {
        qualification: crate::error::NO_QUALIFICATION.to_string(),
        catalog_revision: catalog.revision(),
        catalog_sha256: catalog.source_sha256().as_str(),
        profiles,
        cases,
    })
}
