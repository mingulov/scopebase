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
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Closure manifest schema marker.
pub const MANIFEST_SCHEMA: &str = "tt07-fixture-manifest-v1";
/// Closure manifest file name inside a fixture root.
pub const MANIFEST_FILE: &str = "fixture-manifest.json";
/// Upper bound for a closure manifest document.
pub const MAX_MANIFEST_BYTES: u64 = 1 << 20;
/// Upper bound for a single verified closure file.
pub const MAX_CLOSURE_FILE_BYTES: u64 = 1 << 26;
/// S39: upper bound for a receipt envelope read. Envelopes are small
/// report documents; the bound keeps a hostile path from inflating
/// the verifier before JSON admission.
pub const MAX_RECEIPT_BYTES: u64 = 1 << 20;
/// S39: upper bound for a catalog read. Catalogs scale with case
/// count, so the bound is generous; parser admission re-validates
/// below it.
pub const MAX_CATALOG_BYTES: u64 = 1 << 26;
/// S39: upper bound for a contract-template override read.
pub const MAX_TEMPLATE_BYTES: u64 = 1 << 20;
/// S39: upper bound for a staged run-contract read.
pub const MAX_STAGED_CONTRACT_BYTES: u64 = 1 << 20;

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
            format!(
                "cannot read closure manifest {}: {e}",
                manifest_path.display()
            ),
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
    let files = doc.get("files").and_then(|f| f.as_array()).ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            "closure manifest lacks a files array",
        )
    })?;
    let mut pinned = Vec::with_capacity(files.len());
    for entry in files {
        let path = entry.get("path").and_then(|p| p.as_str()).ok_or_else(|| {
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
        let bytes =
            read_bounded(&closure.root.join(&file.path), MAX_CLOSURE_FILE_BYTES).map_err(|e| {
                let kind = if notice_paths.iter().any(|n| n == &file.path) {
                    OperatorErrorKind::BrokenPackage
                } else {
                    OperatorErrorKind::ClosureIncomplete
                };
                let detail = match e {
                    BoundedReadError::NotFound(_) => {
                        format!("closure file missing: {}", file.path)
                    }
                    BoundedReadError::Refused(cause) => {
                        format!("closure file unreadable: {}: {cause}", file.path)
                    }
                };
                OperatorError::new(kind, detail)
            })?;
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
    // F35: anchor a relative root (".") to the current directory first;
    // without this the normalized root is empty and every in-root file
    // is misread as an escape.
    let abs_root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| {
                OperatorError::new(
                    OperatorErrorKind::MissingInput,
                    format!("cannot anchor fixture root: {e}"),
                )
            })?
            .join(root)
    };
    let candidate = abs_root.join(path);
    // R49: native component vectors — prefix comparison without any
    // lossy text rendering.
    let normal_root = normalize(&abs_root);
    let normal_candidate = normalize(&candidate);
    if normal_candidate != normal_root && !normal_candidate.starts_with(&normal_root) {
        return Err(OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            format!("closure path escapes the fixture root: {path}"),
        ));
    }
    Ok(())
}

/// R49: normalize to native components. No lossy substitution: two
/// paths alias only when their byte-exact components match, so a
/// non-UTF-8 root never compares equal to a literal `?` sibling.
fn normalize(path: &Path) -> Vec<&OsStr> {
    let mut parts: Vec<&OsStr> = Vec::new();
    for comp in path.components() {
        use std::path::Component;
        match comp {
            Component::ParentDir => {
                parts.pop();
            }
            Component::CurDir => {}
            _ => parts.push(comp.as_os_str()),
        }
    }
    parts
}

/// R38: a bounded read distinguishes "absent" (the planner's
/// `missing` bucket) from every other refusal (its `mismatched`
/// bucket) at the variant level, without string matching. The
/// payload keeps the absence honest: a path that never existed and
/// a FIFO whose writer never arrived are both "no input", but only
/// the first is "no such file".
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BoundedReadError {
    /// No input: absent path, or a stream that produced nothing.
    NotFound(String),
    /// Present but refused: non-regular, oversized, unreadable, escaped.
    Refused(String),
}

impl std::fmt::Display for BoundedReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(detail) => write!(f, "{detail}"),
            Self::Refused(detail) => write!(f, "{detail}"),
        }
    }
}

/// S39: the shared bounded package-input read. Non-blocking open,
/// same-fd regular-file check, size pre-check plus a capped read:
/// manifests, members, templates, catalogs and staged contracts
/// admit through here so no `fs::read` can inflate or block before
/// parser admission. Package inputs are regular-only: a FIFO (or
/// anything else non-regular) refuses instantly, never waits — the
/// receipt envelope below is the one streaming transport.
pub(crate) fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, BoundedReadError> {
    // F32: open once and validate the open descriptor. Metadata and the
    // capped read both go through the FD, so a path swapped (or a symlink
    // raced in) between a stat and a read cannot bypass the type check or
    // the length cap. Symlinks still resolve; callers pin the bytes by
    // hash afterward, so substituted content fails there.
    // R39: the open never blocks on a FIFO: `O_NONBLOCK` opens
    // succeed and the type check below refuses the non-regular
    // descriptor instead of hanging. Regular files ignore
    // `O_NONBLOCK`, so their reads are unchanged.
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(map_open_error)?;
    read_regular_capped(fd, max)
}

/// S42/R37: bound on receipt-envelope FIFO rendezvous + streaming.
/// A writer-less FIFO never becomes readable, so the wait must end
/// somewhere: 5s is ~1000x the observed thread-rendezvous cost
/// (R37's writer arrives in ms) and 2x under S39's own 10s
/// writer-less tripwire budget, while a writer-less envelope still
/// refuses instead of hanging the verifier.
const ENVELOPE_FIFO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// S42: the receipt-envelope input read. Regular files admit through
/// the strict capped reader; FIFOs stream under the rendezvous read
/// below — R37 serves the envelope over a FIFO by design, so the
/// envelope is the one path input that waits for a writer. Anything
/// else refuses.
pub(crate) fn read_envelope_stream(path: &Path, max: u64) -> Result<Vec<u8>, BoundedReadError> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(map_open_error)?;
    let meta = rustix::fs::fstat(&fd).map_err(|e| refused(format!("not statable: {e}")))?;
    match rustix::fs::FileType::from_raw_mode(meta.st_mode) {
        rustix::fs::FileType::RegularFile => read_regular_capped(fd, max),
        rustix::fs::FileType::Fifo => read_fifo_capped(fd, max, ENVELOPE_FIFO_DEADLINE),
        _ => Err(refused("not a regular file or FIFO".to_string())),
    }
}

/// S42: capped read of a FIFO envelope under a total rendezvous
/// bound. Poll-first: a writer-less FIFO reads instant EOF (even
/// nonblocking), which would masquerade as empty input, so only a
/// readable event proves a writer exists; a writer-less FIFO polls
/// the full bound, then refuses (S39: the path exists but delivered
/// nothing, so this is `Refused`, not `NotFound`). Past the first
/// data the same bound covers the rest of the stream, so a writer
/// that stalls mid-envelope cannot hold the verifier past it
/// either. The byte cap holds throughout: `max + 1` buffered bytes
/// refuse no matter how much the writer sends.
fn read_fifo_capped(
    fd: std::os::fd::OwnedFd,
    max: u64,
    deadline: std::time::Duration,
) -> Result<Vec<u8>, BoundedReadError> {
    use std::os::fd::AsFd;
    let missing =
        || BoundedReadError::Refused(format!("FIFO produced no data within {deadline:?}"));
    let end = std::time::Instant::now() + deadline;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let now = std::time::Instant::now();
        if now >= end {
            return Err(missing());
        }
        let remaining = end - now;
        let timeout = rustix::event::Timespec {
            tv_sec: remaining.as_secs() as i64,
            tv_nsec: remaining.subsec_nanos() as _,
        };
        let mut fds = [rustix::event::PollFd::new(
            &fd,
            rustix::event::PollFlags::IN,
        )];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Err(missing()),
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(refused(e.to_string())),
        }
        match rustix::io::read(fd.as_fd(), &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.len() as u64 > max {
                    return Err(refused(format!("exceeds {max} bytes")));
                }
            }
            Err(rustix::io::Errno::AGAIN) => continue,
            Err(e) => return Err(refused(e.to_string())),
        }
    }
    Ok(bytes)
}

/// S38: type-check and capped-read an already-open member
/// descriptor. Closure members are regular-only: unlike path
/// inputs (which serve pinned transports like the R37 FIFO), a
/// member is engine input resolved under a manifest, and a FIFO
/// planted there must refuse rather than stall the run.
fn read_regular_capped(fd: std::os::fd::OwnedFd, max: u64) -> Result<Vec<u8>, BoundedReadError> {
    use std::io::Read;
    let meta = rustix::fs::fstat(&fd).map_err(|e| refused(format!("not statable: {e}")))?;
    if rustix::fs::FileType::from_raw_mode(meta.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(refused("not a regular file".to_string()));
    }
    if meta.st_size < 0 || meta.st_size as u64 > max {
        return Err(refused(format!("exceeds {max} bytes")));
    }
    let file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(map_read_error)?;
    if bytes.len() as u64 > max {
        return Err(refused(format!("exceeds {max} bytes")));
    }
    Ok(bytes)
}

fn refused(detail: String) -> BoundedReadError {
    BoundedReadError::Refused(detail)
}

fn map_open_error(e: rustix::io::Errno) -> BoundedReadError {
    if e == rustix::io::Errno::NOENT {
        BoundedReadError::NotFound("no such file".to_string())
    } else {
        refused(e.to_string())
    }
}

/// S38: diagnose a refused intermediate open. `O_DIRECTORY` reports
/// `ENOTDIR` (not `ELOOP`) for symlinks — the directory shape is
/// checked first — so a post-refusal `fstatat` names the actual
/// obstacle. Diagnosis only: the open already refused, and nothing
/// here reopens or follows.
fn walk_open_error(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    e: rustix::io::Errno,
) -> BoundedReadError {
    if e == rustix::io::Errno::LOOP {
        return refused("member path crosses a symlink".to_string());
    }
    if e != rustix::io::Errno::NOTDIR {
        return map_open_error(e);
    }
    match rustix::fs::statat(dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st)
            if rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Symlink =>
        {
            refused("member path crosses a symlink".to_string())
        }
        Ok(_) => refused("member path crosses a non-directory".to_string()),
        Err(rustix::io::Errno::NOENT) => {
            BoundedReadError::NotFound("member path is missing".to_string())
        }
        Err(other) => refused(other.to_string()),
    }
}

fn map_read_error(e: std::io::Error) -> BoundedReadError {
    if e.kind() == std::io::ErrorKind::NotFound {
        BoundedReadError::NotFound("no such file".to_string())
    } else {
        refused(e.to_string())
    }
}

/// R38: one planner-facing member read: root-validated, bounded,
/// non-blocking, bucketed. The manifest that failed verification is
/// untrusted, so every entry re-validates its path before any read.
///
/// S38: the read resolves beneath a retained root descriptor without
/// following any symlink. Lexical confinement alone cannot see a
/// symlinked leaf or intermediate directory pointing outside, so the
/// walk opens every component with `O_NOFOLLOW`: a symlink anywhere
/// in the member path refuses with `ELOOP` instead of escaping.
pub(crate) fn read_member(root: &Path, path: &str, max: u64) -> Result<Vec<u8>, BoundedReadError> {
    if let Err(e) = reject_escape(root, path) {
        return Err(refused(e.detail().to_string()));
    }
    read_member_at(root, path, max)
}

fn read_member_at(root: &Path, path: &str, max: u64) -> Result<Vec<u8>, BoundedReadError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::AsFd as _;
    let mut dir = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_open_error)?;
    // Shape already confined by `reject_escape`; empty and dot pieces
    // (from `./x` or doubled slashes) skip like the lexical
    // normalization, while `..` refuses (unreachable past the gate).
    let mut run: Vec<&str> = Vec::new();
    for piece in path.split('/') {
        if piece.is_empty() || piece == "." {
            continue;
        }
        if piece == ".." {
            return Err(refused("member path escapes the fixture root".to_string()));
        }
        run.push(piece);
    }
    let Some((leaf, parents)) = run.split_last() else {
        return Err(refused("member path names no file".to_string()));
    };
    for piece in parents {
        let name = std::ffi::CString::new(*piece)
            .map_err(|_| refused("member path contains NUL".to_string()))?;
        dir = rustix::fs::openat(
            dir.as_fd(),
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| walk_open_error(dir.as_fd(), &name, e))?;
    }
    let name = std::ffi::CString::new(*leaf)
        .map_err(|_| refused("member path contains NUL".to_string()))?;
    let fd = rustix::fs::openat(
        dir.as_fd(),
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        if e == rustix::io::Errno::LOOP {
            refused("member is a symlink".to_string())
        } else {
            map_open_error(e)
        }
    })?;
    read_regular_capped(fd, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(case: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tt07-closure-{case}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // F32: the length cap and the type check bind the bytes read.
    #[test]
    fn bounded_read_caps_bytes_and_rejects_directories() {
        let dir = scratch("bounded");
        std::fs::write(dir.join("exact.bin"), vec![7u8; 16]).unwrap();
        std::fs::write(dir.join("over.bin"), vec![7u8; 17]).unwrap();
        std::fs::create_dir(dir.join("subdir")).unwrap();
        assert_eq!(read_bounded(&dir.join("exact.bin"), 16).unwrap().len(), 16);
        assert!(read_bounded(&dir.join("over.bin"), 16).is_err());
        assert!(read_bounded(&dir.join("subdir"), 16).is_err());
        assert!(read_bounded(&dir.join("missing.bin"), 16).is_err());
    }

    // F35: relative roots (".") anchor to the working directory, so
    // in-root files pass and parent escapes fail, same as absolute roots.
    #[test]
    fn escape_check_handles_relative_and_absolute_roots() {
        let abs = scratch("abs-root");
        assert!(reject_escape(&abs, "catalog.json").is_ok());
        assert!(reject_escape(&abs, "vectors/closure-input.txt").is_ok());
        assert!(reject_escape(&abs, "../evil.json").is_err());
        assert!(reject_escape(&abs, "vectors/../../evil.json").is_err());
        assert!(reject_escape(Path::new("."), "catalog.json").is_ok());
        assert!(reject_escape(Path::new("."), "./catalog.json").is_ok());
        assert!(reject_escape(Path::new("."), "../evil.json").is_err());
        assert!(reject_escape(Path::new("some/rel/root"), "file.json").is_ok());
        assert!(reject_escape(Path::new("some/rel/root"), "../../evil.json").is_err());
    }

    // S38: a symlinked leaf pointing outside refuses instead of
    // escaping, and the outside canary is never read. (Lexical
    // confinement alone passes this path; the old join+read followed
    // the link and returned the canary.)
    #[test]
    fn member_read_refuses_symlinked_leaf_escape() {
        let dir = scratch("leaf-link");
        let outside = scratch("leaf-outside");
        std::fs::write(outside.join("canary.txt"), b"canary").unwrap();
        std::os::unix::fs::symlink(outside.join("canary.txt"), dir.join("evil-link")).unwrap();
        let err = read_member(&dir, "evil-link", 1 << 20).expect_err("leaf link refuses");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err}"
        );
    }

    // S38: a symlinked intermediate directory pointing outside
    // refuses instead of escaping into it.
    #[test]
    fn member_read_refuses_symlinked_dir_escape() {
        let dir = scratch("dir-link");
        let outside = scratch("dir-outside");
        std::fs::write(outside.join("inner.json"), b"canary").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("sub-link")).unwrap();
        let err = read_member(&dir, "sub-link/inner.json", 1 << 20).expect_err("dir link refuses");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err}"
        );
    }

    // S38: no symlinks are followed, even in-root ones — strictness
    // is the rule, not confinement alone. Genuine nested members
    // still read (the over-refusal control).
    #[test]
    fn member_read_refuses_even_in_root_symlinks() {
        let dir = scratch("inroot-link");
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("real.json"), b"real").unwrap();
        std::os::unix::fs::symlink("real.json", dir.join("sub").join("alias.json")).unwrap();
        let err = read_member(&dir, "sub/alias.json", 1 << 20).expect_err("in-root link refuses");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err}"
        );
        assert_eq!(
            read_member(&dir, "sub/real.json", 1 << 20).unwrap(),
            b"real",
            "genuine nested member reads"
        );
        assert_eq!(
            read_member(&dir, "./sub/real.json", 1 << 20).unwrap(),
            b"real",
            "dot-prefixed member reads"
        );
    }

    // R49: a non-UTF-8 root component never aliases a literal `?`
    // sibling. The old lossy renderer normalized both to `?`, so
    // `../?/file` (resolving outside the root) passed the check.
    #[cfg(unix)]
    #[test]
    fn escape_check_distinguishes_non_utf8_roots() {
        use std::os::unix::ffi::OsStrExt;
        let base = scratch("non-utf8-root");
        let ff_root = base.join(std::ffi::OsStr::from_bytes(b"\xff"));
        let q_root = base.join("?");
        std::fs::create_dir_all(&ff_root).unwrap();
        std::fs::create_dir_all(&q_root).unwrap();
        // In-root files pass under both roots.
        assert!(reject_escape(&ff_root, "file.json").is_ok());
        assert!(reject_escape(&q_root, "file.json").is_ok());
        // `../?/file` escapes the 0xFF root into its `?` sibling.
        assert!(reject_escape(&ff_root, "../?/file.json").is_err());
        // Ordinary parent escapes still fail under both roots.
        assert!(reject_escape(&ff_root, "../evil.json").is_err());
        assert!(reject_escape(&q_root, "../evil.json").is_err());
    }

    // R39: FIFO members and FIFO manifests refuse fast. The old
    // blocking open hung on both; completing at all proves the fix.
    #[cfg(unix)]
    #[test]
    fn fifo_members_and_manifests_refuse_without_blocking() {
        let dir = scratch("fifo");
        std::fs::write(dir.join("member.bin"), b"0123456789abcdef").unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            dir.join("stream.bin"),
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        // The FIFO pin is arbitrary: verification must refuse the
        // non-regular object before any pin comparison.
        write_manifest(
            &dir,
            &[
                ("member.bin", None, None),
                ("stream.bin", None, Some(b"0123456789abcdef".as_slice())),
            ],
        );
        let err = verify_closure(&dir, &dir.join(MANIFEST_FILE)).unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::ClosureIncomplete);
        // A FIFO served as the manifest itself refuses the same way.
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            dir.join("fifo-manifest.json"),
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let err = verify_closure(&dir, &dir.join("fifo-manifest.json")).unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::MissingInput);
    }

    // S42: the envelope FIFO stream delivers writer bytes under the
    // cap, and refuses an oversized stream on the bound — not on a
    // meaningless `st_size` (FIFOs report zero).
    #[cfg(target_os = "linux")]
    #[test]
    fn envelope_fifo_streams_under_cap() {
        let dir = scratch("envelope-fifo");
        let fifo = dir.join("envelope.json");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let writer_path = fifo.clone();
        let writer = std::thread::spawn(move || {
            std::fs::write(&writer_path, b"{\"ok\":true}").unwrap();
        });
        let bytes = read_envelope_stream(&fifo, 1 << 20).unwrap();
        writer.join().unwrap();
        assert_eq!(bytes, b"{\"ok\":true}");

        // Oversized stream: the writer sends more than the cap.
        let fifo2 = dir.join("big.json");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo2,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let writer_path = fifo2.clone();
        let writer = std::thread::spawn(move || {
            let _ = std::fs::write(&writer_path, vec![b'x'; 64]);
        });
        let err = read_envelope_stream(&fifo2, 16).unwrap_err();
        writer.join().unwrap();
        assert_eq!(
            err,
            BoundedReadError::Refused("exceeds 16 bytes".to_string())
        );
    }

    // S42: a writer-less envelope FIFO refuses when the rendezvous
    // bound expires — it never hangs, and never masquerades as
    // empty input (a writer-less read is instant EOF). Short
    // deadline: pins the timeout path in ~0.1s, not 5s.
    #[cfg(target_os = "linux")]
    #[test]
    fn envelope_fifo_timeout_is_missing_input() {
        use std::os::fd::AsFd;
        let dir = scratch("envelope-fifo-timeout");
        let fifo = dir.join("empty.json");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let fd = rustix::fs::open(
            &fifo,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(fd.as_fd()).unwrap().st_mode),
            rustix::fs::FileType::Fifo,
        );
        let err = read_fifo_capped(fd, 1 << 20, std::time::Duration::from_millis(100)).unwrap_err();
        assert_eq!(
            err,
            BoundedReadError::Refused("FIFO produced no data within 100ms".to_string()),
        );
    }

    // R41 (F31 window): bytes mutated after verification but before
    // use are refused at use. Same-length swaps fail the hash,
    // growth fails the length — `read` re-checks the pin every time.
    #[test]
    fn read_rechecks_pin_after_verify() {
        let dir = scratch("tamper-window");
        std::fs::write(dir.join("member.bin"), b"0123456789abcdef").unwrap();
        std::fs::write(dir.join("grown.bin"), b"0123456789abcdef").unwrap();
        write_manifest(
            &dir,
            &[("member.bin", None, None), ("grown.bin", None, None)],
        );
        let closure = verify_closure(&dir, &dir.join(MANIFEST_FILE)).unwrap();
        assert_eq!(closure.read("member.bin").unwrap(), b"0123456789abcdef");
        // Mutate after verification, before use.
        std::fs::write(dir.join("member.bin"), b"fedcba9876543210").unwrap();
        std::fs::write(dir.join("grown.bin"), b"0123456789abcdefEXTRA").unwrap();
        let err = closure.read("member.bin").unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage);
        let err = closure.read("grown.bin").unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::BrokenPackage);
    }

    // R41 (F32 window): the post-read cap binds even when the
    // pre-read size lies. `/proc` pseudo-files report `st_size == 0`
    // while yielding bytes; the cap still applies to bytes read.
    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_read_enforces_cap_despite_zero_reported_size() {
        let cmdline = Path::new("/proc/self/cmdline");
        let bytes = read_bounded(cmdline, 1 << 20).unwrap();
        assert!(!bytes.is_empty());
        let err = read_bounded(cmdline, 0).unwrap_err();
        assert_eq!(
            err,
            BoundedReadError::Refused("exceeds 0 bytes".to_string())
        );
    }

    /// One manifest member: name, optional vector id, optional
    /// explicit pin (for members that cannot be read).
    type ManifestMember<'a> = (&'a str, Option<&'a str>, Option<&'a [u8]>);

    /// Write a manifest pinning the current bytes of `members`; the
    /// first member doubles as the H33 notice.
    fn write_manifest(dir: &Path, members: &[ManifestMember<'_>]) {
        let mut files = Vec::new();
        for (name, file_id, pin) in members {
            let bytes = match pin {
                Some(pinned) => pinned.to_vec(),
                None => std::fs::read(dir.join(name)).unwrap_or_default(),
            };
            let mut entry = serde_json::json!({
                "path": name,
                "length": (bytes.len() as u64).to_string(),
                "sha256": Digest256::of_bytes(&bytes).as_str(),
            });
            if let Some(id) = file_id {
                entry["file_id"] = (*id).into();
            }
            files.push(entry);
        }
        let notices: Vec<&str> = members.first().map(|m| vec![m.0]).unwrap_or_default();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "kind": MANIFEST_SCHEMA,
            "files": files,
            "notices": notices,
        });
        std::fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }
}
