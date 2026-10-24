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
///
/// S13: mutation exclusion gates the destruction. The parent's
/// exclusivity is verified at acquisition and re-verified
/// immediately before the unlink (tight window): only an exclusive
/// parent excludes a foreign swapper from the re-verify/unlink
/// window. Clearing refuses non-exclusive nested directories (see
/// `clear_dir`); the link-count proof stays as the backstop.
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
    require_exclusive_parent(parent_fd.as_fd(), "run dir parent")?;
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
    #[cfg(test)]
    fire_unlink_window_hook();
    // S13: tight window — the parent proved exclusive at acquisition;
    // prove it again here, immediately before the unlink, so a
    // loosened parent refuses instead of deleting through a
    // swappable window.
    require_exclusive_parent(parent_fd.as_fd(), "run dir parent")?;
    rustix::fs::unlinkat(&parent_fd, name_c.as_c_str(), AtFlags::REMOVEDIR)
        .map_err(|e| refused(format!("run dir not removable: {e}")))?;
    // Prove OUR directory lost its name: a swap-and-replace between
    // the re-verify and the unlink leaves our fd linked.
    prove_unlinked(root_fd.as_fd(), "run dir")?;
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

/// S14: prove the pinned directory is mutation-exclusive to us:
/// owned by our euid with no group/other write bit (the
/// mask-backed mode check covers ACL grants too). Without this,
/// the verify/unlink destruction window below admits a foreign
/// swapper. Mirrors `scopebase_linux::conformance`'s gate; this
/// crate has `rustix/process`, so the euid is native.
///
/// S13: the same gate guards every deletion container: the parent
/// is verified at acquisition and re-verified immediately before
/// the unlink, and `clear_dir` verifies each traversed directory
/// before unlinking inside it.
/// S56: the shared exclusivity rule — euid-owned with no group/other
/// write bit. Cleanup and acquisition agree on it: cleanup refuses
/// shared parents, so acquisition refuses to create under them and
/// no successful run is uncleanable-by-policy. Returns the refusal
/// detail on violation, `None` when exclusive.
pub(crate) fn exclusive_parent_violation(
    dir: std::os::fd::BorrowedFd<'_>,
    what: &str,
) -> Result<Option<String>, OperatorError> {
    let st = rustix::fs::fstat(dir).map_err(|e| refused(format!("{what} not statable: {e}")))?;
    if st.st_uid != rustix::process::geteuid().as_raw() || st.st_mode & 0o022 != 0 {
        return Ok(Some(format!(
            "{what} not exclusive: stage run dirs under a private 0700 directory"
        )));
    }
    Ok(None)
}

fn require_exclusive_parent(
    dir: std::os::fd::BorrowedFd<'_>,
    what: &str,
) -> Result<(), OperatorError> {
    if let Some(detail) = exclusive_parent_violation(dir, what)? {
        return Err(refused(detail));
    }
    Ok(())
}

/// S13: prove the held inode lost its name. Unlinking a swapped-in
/// replacement leaves OUR inode linked and refuses instead of
/// reporting success over a foreign deletion.
fn prove_unlinked(held: std::os::fd::BorrowedFd<'_>, what: &str) -> Result<(), OperatorError> {
    let after = dev_ino_nlink(held).map_err(|e| refused(format!("{what} not statable: {e}")))?;
    if after != 0 {
        return Err(refused(format!("{what} replaced during removal")));
    }
    Ok(())
}

fn dev_ino(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<(u64, u64)> {
    let st = rustix::fs::fstat(fd)?;
    Ok((st.st_dev, st.st_ino))
}

/// S13-round3: forced-window hook for the unlink re-check. Fires
/// once per arming, between the identity re-verify and the
/// deletion-time exclusivity check, then auto-disarms (take
/// semantics) so a stale hook can never affect another test. Only
/// the forced-window test arms it; production builds have no hook.
#[cfg(test)]
static UNLINK_WINDOW_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);

/// S13-round3: arm (or clear, with `None`) the unlink-window hook.
#[cfg(test)]
pub(crate) fn set_unlink_window_hook(hook: Option<Box<dyn FnOnce() + Send>>) {
    *UNLINK_WINDOW_HOOK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = hook;
}

/// S13-round3: run the armed unlink-window hook, if any.
#[cfg(test)]
fn fire_unlink_window_hook() {
    let hook = UNLINK_WINDOW_HOOK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .take();
    if let Some(hook) = hook {
        hook();
    }
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
    // S37: `O_NONBLOCK` like the R39 closure reads — the open must
    // never block on a writer-less FIFO substituted for the
    // manifest. Regular files ignore the flag, so their reads are
    // unchanged; the same descriptor is type-checked below and
    // non-regular objects refuse instead of hanging.
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
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
/// resolves a path).
///
/// S13: one `O_PATH` hold per entry (follows nothing; holds files,
/// dirs, symlinks and fifos without opening their data, so no fifo
/// blocks the walk). Directories reopen through the hold with `"."`
/// — no second name lookup, so renaming the entry itself mid-walk
/// cannot redirect the recursion. Every unlink proves against the
/// held inode afterwards: a swapped-in replacement takes the
/// deletion while OUR inode stays linked, and `prove_unlinked`
/// refuses loudly instead of reporting success over it.
/// Multi-linked entries (hardlinks — never created by the
/// operator, so always foreign evidence) refuse the same way: the
/// inode would survive the unlink, and "removed" would be a lie.
/// Mirrors `scopebase_linux::conformance`'s walk.
fn clear_dir(dir: std::os::fd::BorrowedFd<'_>) -> Result<(), OperatorError> {
    // S13: mutation exclusion before deletion — each traversed
    // directory proves exclusive before any entry inside it is
    // unlinked (see `scopebase_linux::conformance::clear_dir`).
    require_exclusive_parent(dir, "run dir")?;
    let entries = rustix::fs::Dir::read_from(dir)
        .map_err(|e| refused(format!("run dir not listable: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| refused(format!("run dir not listable: {e}")))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let held = match rustix::fs::openat(
            dir,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(held) => held,
            Err(rustix::io::Errno::NOENT) => {
                // Already gone (a cooperative sibling retired it):
                // converge rather than fail the whole removal.
                continue;
            }
            Err(errno) => {
                return Err(refused(format!("run entry not openable: {errno}")));
            }
        };
        let mode = rustix::fs::fstat(&held)
            .map_err(|e| refused(format!("run entry not statable: {e}")))?
            .st_mode;
        if rustix::fs::FileType::from_raw_mode(mode) == rustix::fs::FileType::Directory {
            let child = rustix::fs::openat(
                held.as_fd(),
                c".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| refused(format!("run entry not openable: {e}")))?;
            clear_dir(child.as_fd())?;
            rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)
                .map_err(|e| refused(format!("run entry not removable: {e}")))?;
        } else {
            // Plain unlink never follows a link, whatever the entry
            // changed into — dangling symlink, fifo, socket alike.
            rustix::fs::unlinkat(dir, name, AtFlags::empty())
                .map_err(|e| refused(format!("run entry not removable: {e}")))?;
        }
        prove_unlinked(held.as_fd(), "run entry")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S13-round3: a parent loosened inside the unlink window refuses
    /// before unlinking. The hook fires between the identity
    /// re-verify and the deletion-time exclusivity check (the exact
    /// S13 schedule, forced deterministically): the late gate
    /// refuses, and the cleared run directory stands. Pre-gate code
    /// unlinked the run here.
    #[test]
    fn unlink_window_loosening_refuses_before_unlink() {
        let base = std::env::temp_dir().join(format!(
            "s13-unlink-window-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let run = base.join("run");
        std::fs::create_dir(&run).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(
            run.join(RUN_MANIFEST_FILE),
            r#"{"schema":"operator-run-manifest-v1","run_id":"13131313131313131313131313131313","profile":"p"}"#,
        )
        .unwrap();
        std::fs::write(run.join("filler.txt"), b"run-owned").unwrap();
        let hook_base = base.clone();
        set_unlink_window_hook(Some(Box::new(move || {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &hook_base,
                    std::fs::Permissions::from_mode(0o777),
                )
                .unwrap();
            }
        })));
        let err = cleanup_run(&run, None).unwrap_err();
        assert_eq!(err.kind(), OperatorErrorKind::CleanupRefused);
        assert!(
            err.detail().contains("not exclusive"),
            "unexpected detail: {}",
            err.detail()
        );
        // The forcing landed (parent loosened) and the run stands.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&base).unwrap().permissions().mode() & 0o777,
                0o777,
                "hook did not loosen the parent"
            );
        }
        assert!(run.is_dir(), "refused cleanup unlinked the run");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
}
