// SPDX-License-Identifier: Apache-2.0
//! Developer conformance vocabulary for downstream Linux clients.
//!
//! Deterministic operation ledgers, explicit caller-owned fixture roots and
//! stable contract-refusal encoding. Pure/test-support vocabulary: no file
//! authority, no BPF, no policy. Both LX11 reference consumers build on
//! exactly this surface plus the frozen file/procfs/process/mapping/walk
//! APIs; no consumer-only helper is shared any other way.
//! NEW (LX11): reference-only; no donor lines copied.
use crate::error::LinuxError;
use std::{
    io,
    path::{Component, Path, PathBuf},
};

#[cfg(test)]
mod tests;

/// Append-only deterministic operation ledger: pairs render as
/// `op=detail;` in record order. Adapters build observation bodies from
/// this so downstream tests assert one exact string.
#[derive(Clone, Debug, Default)]
pub struct ExpectedLedger {
    entries: Vec<(String, String)>,
}

impl ExpectedLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed operation. `detail` must already be the exact
    /// bytes the observation carries; no normalization is applied.
    pub fn record(&mut self, op: &str, detail: &str) {
        self.entries.push((op.to_string(), detail.to_string()));
    }

    /// Render every entry as `op=detail;` in record order.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (op, detail) in &self.entries {
            out.push_str(op);
            out.push('=');
            out.push_str(detail);
            out.push(';');
        }
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Explicit caller-owned fixture root: `parent/name` created by the caller,
/// files written only underneath it, cleanup only through [`FixtureRoot::close`].
/// There is no `Drop` cleanup: a forgotten root stays visible in the parent,
/// never silently retired.
#[derive(Debug)]
pub struct FixtureRoot {
    path: PathBuf,
}

impl FixtureRoot {
    /// Create `parent/name`. `name` must be one normal component; the parent
    /// must already exist. Fails (rather than reusing) when present.
    pub fn create(parent: &Path, name: &str) -> io::Result<Self> {
        if name.is_empty() || name.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad root name"));
        }
        let mut parts = Path::new(name).components();
        match (parts.next(), parts.next()) {
            (Some(Component::Normal(_)), None) => {}
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad root name")),
        }
        let path = parent.join(name);
        std::fs::create_dir(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write `bytes` to `rel` under the root, creating parent directories.
    /// Absolute paths and any `..`/prefix escape are refused before any write.
    pub fn write_file(&self, rel: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let full = self.join(rel)?;
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&full, bytes)?;
        Ok(full)
    }

    /// Create (or reuse) `rel` as a directory under the root.
    pub fn subdir(&self, rel: &str) -> io::Result<PathBuf> {
        let full = self.join(rel)?;
        std::fs::create_dir_all(&full)?;
        Ok(full)
    }

    /// Remove the whole tree. Consumes the root so cleanup runs exactly once.
    pub fn close(self) -> io::Result<()> {
        std::fs::remove_dir_all(&self.path)
    }

    fn join(&self, rel: &str) -> io::Result<PathBuf> {
        if rel.is_empty() || rel.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad rel path"));
        }
        let target = Path::new(rel);
        if target.is_absolute() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "abs rel path"));
        }
        let mut full = self.path.clone();
        for part in target.components() {
            match part {
                Component::Normal(piece) => full.push(piece),
                Component::CurDir => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "escaping rel path",
                    ))
                }
            }
        }
        if full == self.path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty rel path",
            ));
        }
        Ok(full)
    }
}

/// Stable contract-refusal encoding: `refuse=<Stage>:<Reason>;` with a
/// `:line=N` suffix when the error carries a parser line. Linux contract
/// refusals are observed data, never adapter failures.
pub fn refusal_of(error: &LinuxError) -> String {
    match error.parse_line() {
        Some(line) => format!(
            "refuse={:?}:{:?}:line={};",
            error.stage(),
            error.reason(),
            line
        ),
        None => format!("refuse={:?}:{:?};", error.stage(), error.reason()),
    }
}
