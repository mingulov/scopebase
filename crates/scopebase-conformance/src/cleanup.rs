// SPDX-License-Identifier: Apache-2.0
//! TT07 run cleanup: only an identity-checked run directory is removed.
//!
//! NEW (TT07): no donor lines copied.
//!
//! R36: validation and destruction share pinned descriptors. The
//! parent is opened once, the run dir is opened through it, the
//! manifest is read through the held fd, the tree is cleared
//! through the held fd, and the name is unlinked through the pinned
//! parent — with a pre-unlink re-verify plus a link-count proof
//! that OUR directory lost its name. A symlink, a swap between
//! validation and deletion, or an unreadable/non-run occupant
//! refuses instead of deleting something else.
use crate::error::{OperatorError, OperatorErrorKind};
use rustix::fs::{AtFlags, Mode, OFlags};
use std::ffi::{CStr, CString};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Run manifest schema marker.
pub const RUN_MANIFEST_SCHEMA: &str = "operator-run-manifest-v1";
/// Run manifest file name inside an output directory.
pub const RUN_MANIFEST_FILE: &str = "run-manifest.json";
const RUN_MANIFEST_C: &CStr = c"run-manifest.json";
/// R36: run manifests are small JSON; nothing legitimate approaches this.
const MAX_RUN_MANIFEST_BYTES: u64 = 1024 * 1024;

/// A completed cleanup report.
#[derive(Clone, Debug)]
pub struct CleanupReport {
    /// Removed run identifier.
    pub run_id: String,
    /// Removed profile.
    pub profile: String,
}

fn refused(detail: impl Into<String>) -> OperatorError {
    OperatorError::new(OperatorErrorKind::CleanupRefused, detail)
}

/// R36: remove one identity-checked run directory.
///
/// Refuses (leaving everything in place) when `dir` is not a
/// single-component directory name under an openable parent, when
/// the manifest read through the pinned fd is missing/corrupt, or
/// when `expected_run_id` disagrees. On success the whole tree is
/// gone and the returned report names the validated run id.
pub fn cleanup_run(
    dir: &Path,
    expected_run_id: Option<&str>,
) -> Result<CleanupReport, OperatorError> {
    let name = dir
        .file_name()
        .filter(|n| *n != "." && *n != "..")
        .ok_or_else(|| refused("run dir must name one directory"))?;
    let parent = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name_c = CString::new(name.as_bytes())
        .map_err(|_| refused("run dir name is not a single component"))?;
    // Pin the parent first: the path resolves exactly once, here;
    // every later effect is descriptor-relative.
    let parent_fd = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| refused(format!("run dir parent not openable: {e}")))?;
    let root_fd = rustix::fs::openat(
        &parent_fd,
        name_c.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| refused(format!("run dir not openable: {e}")))?;
    // Identity bound at open; the manifest and every removal below
    // must address exactly this inode.
    let expected =
        dev_ino(root_fd.as_fd()).map_err(|e| refused(format!("run dir not statable: {e}")))?;

    let manifest_bytes = read_at(root_fd.as_fd(), RUN_MANIFEST_C, MAX_RUN_MANIFEST_BYTES)?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|_| refused("run manifest is not JSON"))?;
    if manifest.get("schema").and_then(|v| v.as_str()) != Some(RUN_MANIFEST_SCHEMA) {
        return Err(refused("not an operator run directory"));
    }
    let run_id = manifest
        .get("run_id")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| refused("run manifest has no run id"))?;
    if let Some(expected) = expected_run_id {
        if run_id != expected {
            return Err(refused(format!(
                "run id {run_id} does not match expected {expected}"
            )));
        }
    }

    // Clear through the held fd, then re-verify the name still
    // addresses our inode before unlinking it.
    clear_dir(root_fd.as_fd())?;
    let live = rustix::fs::openat(
        &parent_fd,
        name_c.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| refused(format!("run dir not re-openable before removal: {e}")))?;
    let live_id =
        dev_ino(live.as_fd()).map_err(|e| refused(format!("run dir not statable: {e}")))?;
    if live_id != expected {
        return Err(refused("run dir replaced before removal"));
    }
    drop(live);
    rustix::fs::unlinkat(&parent_fd, name_c.as_c_str(), AtFlags::REMOVEDIR)
        .map_err(|e| refused(format!("run dir not removable: {e}")))?;
    // Prove OUR directory lost its name: a swap-and-replace between
    // the re-verify and the unlink leaves our fd linked.
    let after = dev_ino_nlink(root_fd.as_fd())
        .map_err(|e| refused(format!("run dir not statable: {e}")))?;
    if after != 0 {
        return Err(refused("run dir replaced during removal"));
    }
    let profile = manifest
        .get("profile")
        .and_then(|p| p.as_str())
        .unwrap_or("?")
        .to_string();
    Ok(CleanupReport {
        run_id: run_id.to_string(),
        profile,
    })
}

fn dev_ino(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<(u64, u64)> {
    let st = rustix::fs::fstat(fd)?;
    Ok((st.st_dev, st.st_ino))
}

fn dev_ino_nlink(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<u64> {
    Ok(rustix::fs::fstat(fd)?.st_nlink)
}

/// R36: read one bounded regular file through a held directory fd.
/// The open pins the inode; symlinks refuse; oversized and
/// non-regular occupants refuse without partial reads.
fn read_at(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    max: u64,
) -> Result<Vec<u8>, OperatorError> {
    use std::io::Read as _;
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| refused(format!("run manifest not readable: {e}")))?;
    let meta =
        rustix::fs::fstat(&fd).map_err(|e| refused(format!("run manifest not statable: {e}")))?;
    if rustix::fs::FileType::from_raw_mode(meta.st_mode as u32) != rustix::fs::FileType::RegularFile
    {
        return Err(refused("run manifest is not a regular file"));
    }
    if meta.st_size < 0 || meta.st_size as u64 > max {
        return Err(refused("run manifest exceeds size bounds"));
    }
    let file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refused(format!("run manifest not readable: {e}")))?;
    if bytes.len() as u64 > max {
        return Err(refused("run manifest exceeds size bounds"));
    }
    Ok(bytes)
}

/// Recursively remove every entry under `dir` (fd-relative; never
/// resolves a path). Each entry is opened as a directory first:
/// `NOFOLLOW` refuses symlinks with `ELOOP` and files with
/// `ENOTDIR`, and either falls through to a plain unlink, which
/// never follows a link. A swap between listing and open fails
/// closed instead of mis-removing.
fn clear_dir(dir: std::os::fd::BorrowedFd<'_>) -> Result<(), OperatorError> {
    let entries = rustix::fs::Dir::read_from(dir)
        .map_err(|e| refused(format!("run dir not listable: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| refused(format!("run dir not listable: {e}")))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        match rustix::fs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(child) => {
                clear_dir(child.as_fd())?;
                rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)
                    .map_err(|e| refused(format!("run entry not removable: {e}")))?;
            }
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                rustix::fs::unlinkat(dir, name, AtFlags::empty())
                    .map_err(|e| refused(format!("run entry not removable: {e}")))?;
            }
            Err(errno) => {
                return Err(refused(format!("run entry not openable: {errno}")));
            }
        }
    }
    Ok(())
}
