// SPDX-License-Identifier: Apache-2.0
//! TT07 installed closure: hash-pinned offline fixture roots.
//!
//! NEW (TT07): no donor lines copied.
//!
//! A fixture root is self-describing: `fixture-manifest.json` pins every file
//! the operator may read (catalog, contract template, vectors, registered
//! sources, H33 notices) by relative path, byte length and sha256. Verification
//! reads only the named root; nothing is resolved relative to a checkout.

use crate::error::{OperatorError, OperatorErrorKind};
use scopebase_testkit::Digest256;
use std::path::{Path, PathBuf};

/// Closure manifest schema marker.
pub const MANIFEST_SCHEMA: &str = "tt07-fixture-manifest-v1";
/// Closure manifest file name inside a fixture root.
pub const MANIFEST_FILE: &str = "fixture-manifest.json";
/// Upper bound for a closure manifest document.
pub const MAX_MANIFEST_BYTES: u64 = 1 << 20;
/// Upper bound for a single verified closure file.
pub const MAX_CLOSURE_FILE_BYTES: u64 = 1 << 26;

/// One pinned closure file.
#[derive(Clone, Debug)]
pub struct PinnedFile {
    /// Path relative to the fixture root (no parent escapes).
    pub path: String,
    /// Vector file identifier, when this file feeds the engine bundle.
    pub file_id: Option<String>,
    /// Exact byte length.
    pub length: u64,
    /// sha256 over the exact bytes.
    pub sha256: String,
}

/// A verified fixture-root closure.
#[derive(Clone, Debug)]
pub struct VerifiedClosure {
    /// The fixture root that was verified.
    pub root: PathBuf,
    /// sha256 of the manifest bytes (receipt binding).
    pub manifest_sha256: Digest256,
    /// Verified pinned files in manifest order.
    pub files: Vec<PinnedFile>,
}

impl VerifiedClosure {
    /// Resolve a pinned path against the verified root.
    pub fn join(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }

    /// Read verified bytes for a pinned path (re-checks length and hash).
    pub fn read(&self, path: &str) -> Result<Vec<u8>, OperatorError> {
        let pinned = self.files.iter().find(|f| f.path == path).ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                format!("closure file is not pinned: {path}"),
            )
        })?;
        let bytes = read_bounded(&self.root.join(path), MAX_CLOSURE_FILE_BYTES).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::ClosureIncomplete,
                format!("closure file unreadable: {path}: {e}"),
            )
        })?;
        check_pin(path, &bytes, pinned)?;
        Ok(bytes)
    }

    /// Map vector file identifiers to their fixture-root paths.
    pub fn vector_paths(&self) -> Vec<(String, PathBuf)> {
        self.files
            .iter()
            .filter_map(|f| {
                f.file_id
                    .as_ref()
                    .map(|id| (id.clone(), self.root.join(&f.path)))
            })
            .collect()
    }
}

/// Load and verify a fixture-root closure.
///
/// Missing files are [`OperatorErrorKind::ClosureIncomplete`]; hash, length or
/// notice violations are [`OperatorErrorKind::BrokenPackage`].
pub fn verify_closure(root: &Path, manifest_path: &Path) -> Result<VerifiedClosure, OperatorError> {
    let bytes = read_bounded(manifest_path, MAX_MANIFEST_BYTES).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!("cannot read closure manifest {}: {e}", manifest_path.display()),
        )
    })?;
    let manifest_sha256 = Digest256::of_bytes(&bytes);
    let doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            format!("closure manifest is not JSON: {e}"),
        )
    })?;
    if doc.get("schema_version") != Some(&serde_json::Value::from(1u64))
        || doc.get("kind").and_then(|k| k.as_str()) != Some(MANIFEST_SCHEMA)
    {
        return Err(OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            "closure manifest has the wrong schema",
        ));
    }
    let files = doc
        .get("files")
        .and_then(|f| f.as_array())
        .ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                "closure manifest lacks a files array",
            )
        })?;
    let mut pinned = Vec::with_capacity(files.len());
    for entry in files {
        let path = entry
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| {
                OperatorError::new(
                    OperatorErrorKind::BrokenPackage,
                    "closure entry lacks a path string",
                )
            })?;
        reject_escape(root, path)?;
        let length = entry
            .get("length")
            .and_then(|l| l.as_str())
            .and_then(|l| l.parse::<u64>().ok())
            .ok_or_else(|| {
                OperatorError::new(
                    OperatorErrorKind::BrokenPackage,
                    format!("closure entry lacks a decimal length: {path}"),
                )
            })?;
        let sha256 = entry
            .get("sha256")
            .and_then(|s| s.as_str())
            .ok_or_else(|| {
                OperatorError::new(
                    OperatorErrorKind::BrokenPackage,
                    format!("closure entry lacks a sha256: {path}"),
                )
            })?;
        let file_id = entry
            .get("file_id")
            .and_then(|i| i.as_str())
            .map(str::to_string);
        pinned.push(PinnedFile {
            path: path.to_string(),
            file_id,
            length,
            sha256: sha256.to_string(),
        });
    }
    let notices = doc
        .get("notices")
        .and_then(|n| n.as_array())
        .ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                "closure manifest lacks a notices array",
            )
        })?;
    if notices.is_empty() {
        return Err(OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            "closure manifest names no H33 notices",
        ));
    }
    let mut notice_paths = Vec::new();
    for notice in notices {
        let path = notice.as_str().ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                "closure notice is not a path string",
            )
        })?;
        if !pinned.iter().any(|f| f.path == path) {
            return Err(OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                format!("closure notice is not a pinned file: {path}"),
            ));
        }
        notice_paths.push(path.to_string());
    }
    let closure = VerifiedClosure {
        root: root.to_path_buf(),
        manifest_sha256,
        files: pinned,
    };
    // Verify every pinned file before reporting success. A missing H33
    // notice breaks the installed route; any other missing file is
    // incomplete input.
    for file in closure.files.clone() {
        let bytes = read_bounded(&closure.root.join(&file.path), MAX_CLOSURE_FILE_BYTES).map_err(
            |_| {
                let kind = if notice_paths.iter().any(|n| n == &file.path) {
                    OperatorErrorKind::BrokenPackage
                } else {
                    OperatorErrorKind::ClosureIncomplete
                };
                OperatorError::new(kind, format!("closure file missing: {}", file.path))
            },
        )?;
        check_pin(&file.path, &bytes, &file)?;
    }
    Ok(closure)
}

fn check_pin(path: &str, bytes: &[u8], pinned: &PinnedFile) -> Result<(), OperatorError> {
    if bytes.len() as u64 != pinned.length {
        return Err(OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            format!(
                "closure length mismatch: {path}: manifest says {}, disk has {}",
                pinned.length,
                bytes.len()
            ),
        ));
    }
    if Digest256::of_bytes(bytes).as_str() != pinned.sha256 {
        return Err(OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            format!("closure sha256 mismatch: {path}"),
        ));
    }
    Ok(())
}

fn reject_escape(root: &Path, path: &str) -> Result<(), OperatorError> {
    let candidate = root.join(path);
    let normal_root = normalize(root);
    let normal_candidate = normalize(&candidate);
    if normal_candidate != normal_root && !normal_candidate.starts_with(&format!("{normal_root}/"))
    {
        return Err(OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            format!("closure path escapes the fixture root: {path}"),
        ));
    }
    Ok(())
}

fn normalize(path: &Path) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for comp in path.components() {
        use std::path::Component;
        match comp {
            Component::ParentDir => {
                parts.pop();
            }
            Component::CurDir => {}
            _ => parts.push(comp.as_os_str().to_str().unwrap_or("?")),
        }
    }
    parts.join("/")
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > max {
        return Err(format!("exceeds {max} bytes"));
    }
    std::fs::read(path).map_err(|e| e.to_string())
}
