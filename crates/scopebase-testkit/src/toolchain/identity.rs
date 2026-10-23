// SPDX-License-Identifier: Apache-2.0
//! TC02: strict compiler-closure admission. Every tool pinned, offline only.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! `llvm-bpf-toolchain-experiment.md` (lines 1-216) and
//! `llvm-bpf-atomic-load-report.md` (lines 1-140) supply the tool pins; only
//! hashes and pin metadata are recorded, via the TC01 inventory. Hashes are
//! re-checked before use after `evidence/llvm-toolchain-review-20260922/
//! kernel-oracle/run.py` (lines 63-64). Whole donor files are user-authored
//! (TC01). No upstream lines copied. Grant: OWNER-2026-10-23.
//!
//! The TC01 inventory tolerates unrecorded system-observed tools; this
//! closure refuses them. Admission requires a nonempty tool list, exact
//! lowercase sha256 per tool, an offline origin and an exact version with
//! no wildcard.
use scopebase_bpf::{Limits, OperationError};
use serde_json::Value;

use crate::object::{
    check_no_unknown, check_version, get_str, invalid, parse_label, parse_sha256, strict_value,
};

const CLOSURE_FIELDS: &[&str] = &["schema_version", "kind", "tools"];
const TOOL_FIELDS: &[&str] = &[
    "id",
    "role",
    "name",
    "version",
    "version_detail",
    "sha256",
    "origin",
    "origin_ref",
    "used_for",
];
const TOOL_ROLES: &[&str] = &[
    "frontend",
    "backend",
    "linker",
    "rust",
    "runner",
    "source-archive",
];
/// Origins that resolve without the network. `system-observed` is absent:
/// an observed install without a recorded hash cannot pin a build.
const OFFLINE_ORIGINS: &[&str] = &["pinned-archive", "preserved-binary"];

/// One pinned compiler tool: exact version plus exact recorded hash.
#[derive(Debug, Clone)]
pub struct PinnedTool {
    id: String,
    role: String,
    name: String,
    version: String,
    version_detail: String,
    sha256: [u8; 32],
    origin: String,
    origin_ref: String,
    used_for: String,
}

impl PinnedTool {
    /// Pin identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Tool role in the compiler closure.
    pub fn role(&self) -> &str {
        &self.role
    }
    /// Tool name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Exact pinned version; wildcards refuse at admission.
    pub fn version(&self) -> &str {
        &self.version
    }
    /// Exact observed version detail.
    pub fn version_detail(&self) -> &str {
        &self.version_detail
    }
    /// Exact recorded binary/archive hash. Always present.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    /// Offline origin class: `pinned-archive` or `preserved-binary`.
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Frozen-evidence reference for the pin.
    pub fn origin_ref(&self) -> &str {
        &self.origin_ref
    }
    /// What the pinned tool was used for.
    pub fn used_for(&self) -> &str {
        &self.used_for
    }
}

/// Strict versioned compiler closure: every tool pinned and offline.
#[derive(Debug, Clone)]
pub struct CompilerClosure {
    tools: Vec<PinnedTool>,
}

impl CompilerClosure {
    /// Admit one strict versioned compiler-closure document.
    ///
    /// Shares the TC01 prelude: [`Limits`] bounds, UTF-8, duplicate-field
    /// rejection at every object level, then typed admission. Unknown
    /// fields refuse, so no `url` or download key can enter later without
    /// a new `schema_version`.
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError> {
        let value = strict_value(bytes, limits)?;
        let root = value.as_object().ok_or_else(|| invalid("closure object"))?;
        check_version(root)?;
        check_no_unknown(root, CLOSURE_FIELDS)?;
        if get_str(root, "kind")? != "tc02_compiler_closure" {
            return Err(invalid("kind"));
        }
        let tools = root
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("tools"))?;
        if tools.is_empty() {
            return Err(invalid("closure holds no tools"));
        }
        let mut out = Vec::with_capacity(tools.len());
        for tool in tools {
            let tool = tool.as_object().ok_or_else(|| invalid("tool"))?;
            check_no_unknown(tool, TOOL_FIELDS)?;
            let id = get_str(tool, "id")?;
            parse_label(id, "tool id")?;
            if out.iter().any(|seen: &PinnedTool| seen.id == id) {
                return Err(invalid("duplicate tool id"));
            }
            let role = get_str(tool, "role")?;
            if !TOOL_ROLES.contains(&role) {
                return Err(invalid("role"));
            }
            let name = get_str(tool, "name")?;
            if name.is_empty() || name.len() > 128 {
                return Err(invalid("name"));
            }
            let version = get_str(tool, "version")?;
            // Exact pins are numeric releases or version@commit; all carry a
            // digit. Floating tags (`latest`, `stable`) and wildcards refuse.
            if version.is_empty()
                || version.len() > 128
                || version.contains('*')
                || !version.bytes().any(|byte| byte.is_ascii_digit())
            {
                return Err(invalid("version"));
            }
            let version_detail = get_str(tool, "version_detail")?;
            if version_detail.is_empty() {
                return Err(invalid("version_detail"));
            }
            // Null or missing hashes refuse: every closure tool is pinned.
            let sha256 = match tool.get("sha256") {
                Some(Value::String(text)) => parse_sha256(text, "sha256")?,
                _ => return Err(invalid("sha256")),
            };
            let origin = get_str(tool, "origin")?;
            if !OFFLINE_ORIGINS.contains(&origin) {
                return Err(invalid("origin"));
            }
            let origin_ref = get_str(tool, "origin_ref")?;
            if origin_ref.is_empty() {
                return Err(invalid("origin_ref"));
            }
            let used_for = get_str(tool, "used_for")?;
            if used_for.is_empty() {
                return Err(invalid("used_for"));
            }
            out.push(PinnedTool {
                id: id.to_owned(),
                role: role.to_owned(),
                name: name.to_owned(),
                version: version.to_owned(),
                version_detail: version_detail.to_owned(),
                sha256,
                origin: origin.to_owned(),
                origin_ref: origin_ref.to_owned(),
                used_for: used_for.to_owned(),
            });
        }
        Ok(Self { tools: out })
    }

    /// Admitted pinned tools.
    pub fn tools(&self) -> &[PinnedTool] {
        &self.tools
    }

    /// Number of admitted pins.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the closure holds no pins. Admission refuses empty
    /// documents, so an admitted closure is never empty.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Find one pin by id.
    pub fn find(&self, id: &str) -> Option<&PinnedTool> {
        self.tools.iter().find(|tool| tool.id == id)
    }
}
