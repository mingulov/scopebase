// SPDX-License-Identifier: Apache-2.0
//! TT07 `cleanup`: identity-checked run-directory removal.
//!
//! NEW (TT07): no donor lines copied.

use crate::error::{OperatorError, OperatorErrorKind};
use std::path::Path;

/// Run manifest schema marker.
pub const RUN_MANIFEST_SCHEMA: &str = "operator-run-manifest-v1";
/// Run manifest file name inside an output directory.
pub const RUN_MANIFEST_FILE: &str = "run-manifest.json";

/// A completed cleanup report.
#[derive(Debug)]
pub struct CleanupReport {
    /// Removed run identifier.
    pub run_id: String,
    /// Removed profile.
    pub profile: String,
}

/// Remove a run directory after checking its run-manifest identity.
///
/// Refuses anything without a matching manifest; an optional expected run id
/// must also match. Nothing is removed on refusal.
pub fn cleanup_run(dir: &Path, expected_run_id: Option<&str>) -> Result<CleanupReport, OperatorError> {
    let refused = |detail: String| OperatorError::new(OperatorErrorKind::CleanupRefused, detail);
    if !dir.is_dir() {
        return Err(refused(format!("not a run directory: {}", dir.display())));
    }
    let manifest_path = dir.join(RUN_MANIFEST_FILE);
    let bytes = std::fs::read(&manifest_path)
        .map_err(|_| refused(format!("run manifest missing: {}", dir.display())))?;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| refused(format!("run manifest is not JSON: {}", dir.display())))?;
    if manifest.get("schema").and_then(|s| s.as_str()) != Some(RUN_MANIFEST_SCHEMA) {
        return Err(refused(format!(
            "not an operator run directory: {}",
            dir.display()
        )));
    }
    let run_id = manifest
        .get("run_id")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();
    if run_id.is_empty() {
        return Err(refused(format!(
            "run manifest lacks a run id: {}",
            dir.display()
        )));
    }
    if let Some(expected) = expected_run_id {
        if expected != run_id {
            return Err(refused(format!(
                "run id mismatch: expected {expected}, found {run_id}"
            )));
        }
    }
    let profile = manifest
        .get("profile")
        .and_then(|p| p.as_str())
        .unwrap_or("?")
        .to_string();
    std::fs::remove_dir_all(dir)
        .map_err(|e| refused(format!("cannot remove {}: {e}", dir.display())))?;
    Ok(CleanupReport { run_id, profile })
}
