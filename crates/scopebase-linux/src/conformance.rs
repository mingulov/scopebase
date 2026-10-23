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
use rustix::fs::{self as rfs, Mode, OFlags};
use std::{
    ffi::CString,
    io::{self, Write as _},
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
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
    ///
    /// F25: every level resolves descriptor-relative with symlinks
    /// refused (`NOFOLLOW` per component over pinned directory fds —
    /// the fd-pinned equivalent of `openat2` `NO_SYMLINKS`, matching
    /// the `HeldFile` open discipline). A symlink planted at an
    /// intermediate or final component refuses with `ELOOP` instead
    /// of writing outside the root.
    pub fn write_file(&self, rel: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let pieces = self.split(rel)?;
        let dir = self.open_parent_dir(&pieces)?;
        let name = piece_cstr(pieces[pieces.len() - 1])?;
        let fd = rfs::openat(
            dir.as_fd(),
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o666),
        )
        .map_err(io::Error::from)?;
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)?;
        self.join(rel)
    }

    /// Create (or reuse) `rel` as a directory under the root.
    /// Idempotent for real directories; symlinks (intermediate or
    /// final) refuse (F25).
    pub fn subdir(&self, rel: &str) -> io::Result<PathBuf> {
        let pieces = self.split(rel)?;
        let dir = self.open_parent_dir(&pieces)?;
        let name = piece_cstr(pieces[pieces.len() - 1])?;
        match rfs::mkdirat(dir.as_fd(), &name, Mode::from_bits_truncate(0o777)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                // Present: verify it is a real directory, since
                // mkdirat also reports EEXIST for symlinks and files.
                rfs::openat(
                    dir.as_fd(),
                    &name,
                    OFlags::RDONLY
                        | OFlags::DIRECTORY
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(io::Error::from)?;
            }
            Err(errno) => return Err(io::Error::from(errno)),
        }
        self.join(rel)
    }

    /// Remove the whole tree. Consumes the root so cleanup runs exactly once.
    pub fn close(self) -> io::Result<()> {
        std::fs::remove_dir_all(&self.path)
    }

    fn join(&self, rel: &str) -> io::Result<PathBuf> {
        let mut full = self.path.clone();
        for piece in self.split(rel)? {
            full.push(piece);
        }
        Ok(full)
    }

    /// Validated normal pieces of `rel`: relative, NUL-free, no
    /// `..`/prefix escapes, at least one real component.
    fn split<'a>(&self, rel: &'a str) -> io::Result<Vec<&'a std::ffi::OsStr>> {
        if rel.is_empty() || rel.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad rel path"));
        }
        let target = Path::new(rel);
        if target.is_absolute() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "abs rel path"));
        }
        let mut pieces = Vec::new();
        for part in target.components() {
            match part {
                Component::Normal(piece) => pieces.push(piece),
                Component::CurDir => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "escaping rel path",
                    ))
                }
            }
        }
        if pieces.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty rel path",
            ));
        }
        Ok(pieces)
    }

    /// Open the directory holding the final piece, creating missing
    /// intermediate directories. Every level resolves with symlinks
    /// refused; held directory fds pin each level against renames.
    fn open_parent_dir(&self, pieces: &[&std::ffi::OsStr]) -> io::Result<OwnedFd> {
        let mut dir = rfs::open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        for piece in &pieces[..pieces.len() - 1] {
            dir = open_child_dir(dir.as_fd(), &piece_cstr(piece)?)?;
        }
        Ok(dir)
    }
}

/// One path piece as a `CString` (NUL was already rejected, so this
/// only re-checks the invariant at the FFI boundary).
fn piece_cstr(piece: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(piece.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad rel path"))
}

/// Open one child directory, creating it when missing. Symlinks
/// refuse with `ELOOP` (`NOFOLLOW`); files refuse with `ENOTDIR`.
fn open_child_dir(parent: BorrowedFd<'_>, name: &CString) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rfs::openat(parent, name, flags, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(rustix::io::Errno::NOENT) => {
            rfs::mkdirat(parent, name, Mode::from_bits_truncate(0o777))
                .map_err(io::Error::from)?;
            rfs::openat(parent, name, flags, Mode::empty()).map_err(io::Error::from)
        }
        Err(errno) => Err(io::Error::from(errno)),
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
