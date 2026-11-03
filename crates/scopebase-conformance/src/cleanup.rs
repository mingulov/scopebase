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

    // Z1: the validated manifest descriptor stays open through
    // clearing, removal, and restoration — its pin is what makes
    // the restore identity comparison sound against inode reuse.
    let (manifest_bytes, manifest_fd) =
        read_at(root_fd.as_fd(), RUN_MANIFEST_C, MAX_RUN_MANIFEST_BYTES)?;
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
    if let Err(clear) = clear_dir(root_fd.as_fd()) {
        return Err(with_restore_report(
            clear,
            root_fd.as_fd(),
            &manifest_bytes,
            manifest_fd.as_fd(),
        ));
    }
    // S198/X1: every failure below refuses AFTER our inode was
    // emptied — restore the validated manifest through the held fd
    // first, so our inode (wherever a same-uid swapper parked it)
    // stays a valid, later-removable run instead of stranding as a
    // manifest-less husk. The original refusal kind is always
    // preserved; an unrestorable occupant is reported in its detail.
    let removal = (|| -> Result<(), OperatorError> {
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
        Ok(())
    })();
    if let Err(failed) = removal {
        return Err(with_restore_report(
            failed,
            root_fd.as_fd(),
            &manifest_bytes,
            manifest_fd.as_fd(),
        ));
    }
    let profile = manifest
        .get("profile")
        .and_then(|p| p.as_str())
        .unwrap_or("?")
        .to_string();
    // Z1: the validation pin held through removal; release it only
    // now that no restore can run.
    drop(manifest_fd);
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

// S13-round3/R4: forced-window hook for the unlink re-check.
// Fires once per arming, between the identity re-verify and the
// deletion-time exclusivity check, then auto-disarms (take
// semantics) so a stale hook can never affect another test. Only
// the forced-window test arms it; production builds have no hook.
// THREAD-LOCAL (R4 hardening): a process-global cell would let a
// parallel sibling's `cleanup_run` steal the armed hook.
#[cfg(test)]
thread_local! {
    static UNLINK_WINDOW_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce() + Send>>> =
        const { std::cell::RefCell::new(None) };
}

/// S13-round3: arm (or clear, with `None`) the unlink-window hook.
#[cfg(test)]
pub(crate) fn set_unlink_window_hook(hook: Option<Box<dyn FnOnce() + Send>>) {
    UNLINK_WINDOW_HOOK.with(|cell| *cell.borrow_mut() = hook);
}

/// S13-round3: run the armed unlink-window hook, if any.
#[cfg(test)]
fn fire_unlink_window_hook() {
    let hook = UNLINK_WINDOW_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

// Z3/R4: forced-window hooks for the restore races. AFTER_STAT
// fires in `verify_survivor` before the open (after `statat`
// matched); ENOENT_RACE fires in the open-ENOENT arm where a blind
// unlink used to sit; ABSENT_RACE fires in the statat-Err arm
// likewise. THREAD-LOCAL with take semantics: each test thread
// arms and fires its own hooks synchronously, so a parallel
// sibling's restore can neither consume nor observe them (a
// process-global cell would let any test-build survivor path
// steal an armed hook). Production builds have no hooks.
#[cfg(test)]
thread_local! {
    static RESTORE_AFTER_STAT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce() + Send>>> =
        const { std::cell::RefCell::new(None) };
    static RESTORE_ENOENT_RACE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce() + Send>>> =
        const { std::cell::RefCell::new(None) };
    static RESTORE_ABSENT_RACE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce() + Send>>> =
        const { std::cell::RefCell::new(None) };
}

/// Z3: arm (or clear, with `None`) the restore window hooks.
#[cfg(test)]
pub(crate) fn set_restore_after_stat_hook(hook: Option<Box<dyn FnOnce() + Send>>) {
    RESTORE_AFTER_STAT_HOOK.with(|cell| *cell.borrow_mut() = hook);
}

/// Z3: arm (or clear, with `None`) the ENOENT-race hook.
#[cfg(test)]
pub(crate) fn set_restore_enoent_race_hook(hook: Option<Box<dyn FnOnce() + Send>>) {
    RESTORE_ENOENT_RACE_HOOK.with(|cell| *cell.borrow_mut() = hook);
}

/// Z3: arm (or clear, with `None`) the absent-race hook.
#[cfg(test)]
pub(crate) fn set_restore_absent_race_hook(hook: Option<Box<dyn FnOnce() + Send>>) {
    RESTORE_ABSENT_RACE_HOOK.with(|cell| *cell.borrow_mut() = hook);
}

#[cfg(test)]
fn fire_restore_after_stat_hook() {
    let hook = RESTORE_AFTER_STAT_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn fire_restore_enoent_race_hook() {
    let hook = RESTORE_ENOENT_RACE_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn fire_restore_absent_race_hook() {
    let hook = RESTORE_ABSENT_RACE_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

fn dev_ino_nlink(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<u64> {
    Ok(rustix::fs::fstat(fd)?.st_nlink)
}

/// S198/X1/Y1/Z1: manifest restore through a held directory fd
/// after a post-clear refusal. `validated` is the RETAINED OPEN
/// descriptor the bytes were validated against — still pinning our
/// inode, so the number comparison below is sound (a reused number
/// is impossible while we hold the inode). Only an
/// identity-matching regular occupant is a proven survivor (bytes
/// re-verified through the pinned descriptor, healed in place when
/// tampered, byte-identical survivors left fully untouched). An
/// identity-mismatching regular file is an unproven replacement —
/// reported, never blessed, never overwritten. A planted
/// non-regular occupant is evicted and the restore creates only
/// exclusively. Returns `None` when the manifest is present and
/// valid, `Some(reason)` otherwise, so the caller reports the
/// residential state instead of stranding silently.
fn restore_manifest_at(
    dir: std::os::fd::BorrowedFd<'_>,
    bytes: &[u8],
    validated: std::os::fd::BorrowedFd<'_>,
) -> Option<String> {
    use rustix::fs::FileType;
    let expected = match rustix::fs::fstat(validated) {
        Ok(st) => (st.st_dev, st.st_ino),
        Err(e) => {
            return Some(format!(
                "validated manifest descriptor lost ({e}); refusing blind restore"
            ));
        }
    };
    match rustix::fs::statat(dir, RUN_MANIFEST_C, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {
            if (st.st_dev, st.st_ino) != expected {
                return Some(
                    "unproven replacement at manifest slot (not the validated manifest); left untouched"
                        .to_string(),
                );
            }
            return verify_survivor(dir, bytes, expected);
        }
        Ok(_) => {
            // Z3 residual: a regular replant landing between this
            // statat and the eviction unlink is deleted without a
            // report (name-based deletion cannot re-verify). The
            // window is a same-uid microsecond, and every outcome
            // is still a safe state — our validated bytes or a
            // reported EEXIST — but the tamper evidence is lost.
            if let Err(e) = rustix::fs::unlinkat(dir, RUN_MANIFEST_C, AtFlags::empty()) {
                return Some(format!("occupant eviction failed: {e}"));
            }
        }
        Err(_) => {
            // Z3: no unlink — absence is unproven (the error may
            // itself have raced a plant), so create exclusively and
            // let EEXIST report a contest.
            #[cfg(test)]
            fire_restore_absent_race_hook();
        }
    }
    restore_absent(dir, bytes)
}

/// Y1: prove a statat-matching survivor through its own pinned
/// descriptor — the name may have raced since the `statat`, so the
/// identity is re-checked on the open fd before any byte is trusted
/// or written. Pristine survivors return untouched (no rewrite
/// churn); tampered ones are healed via the fd (no name race).
fn verify_survivor(
    dir: std::os::fd::BorrowedFd<'_>,
    bytes: &[u8],
    expected: (u64, u64),
) -> Option<String> {
    use std::io::{Read as _, Seek as _, Write as _};
    #[cfg(test)]
    fire_restore_after_stat_hook();
    let fd = match rustix::fs::openat(
        dir,
        RUN_MANIFEST_C,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Raced away between statat and open: treat as absent.
            // Z3: no unlink — a plant landing here must EEXIST
            // into a report, never be deleted blind.
            #[cfg(test)]
            fire_restore_enoent_race_hook();
            return restore_absent(dir, bytes);
        }
        Err(e) => {
            return Some(format!(
                "validated survivor not verifiable ({e}); left untouched"
            ));
        }
    };
    let pinned = match rustix::fs::fstat(&fd) {
        Ok(st) => (st.st_dev, st.st_ino),
        Err(e) => return Some(format!("validated survivor not verifiable ({e}); left untouched")),
    };
    if pinned != expected {
        return Some(
            "unproven replacement at manifest slot (raced after stat); left untouched".to_string(),
        );
    }
    let mut file = std::fs::File::from(fd);
    let mut current = Vec::new();
    match std::io::Read::by_ref(&mut file)
        .take(MAX_RUN_MANIFEST_BYTES + 1)
        .read_to_end(&mut current)
    {
        Ok(_) => {}
        Err(e) => {
            return Some(format!(
                "validated survivor not verifiable ({e}); left untouched"
            ));
        }
    }
    if current == bytes {
        return None;
    }
    // Same inode, altered bytes: heal through the pinned fd.
    // Z5: a failure here can strike after truncation, so the
    // report must not claim the file is untouched.
    if let Err(e) = file.rewind().and_then(|_| file.set_len(0)).and_then(|_| file.write_all(bytes)) {
        return Some(format!(
            "tampered survivor not healable ({e}); heal failed partway, contents uncertain"
        ));
    }
    None
}

/// Y1: exclusive-create leg shared by the absent slot and the
/// statat-to-open race eviction.
fn restore_absent(dir: std::os::fd::BorrowedFd<'_>, bytes: &[u8]) -> Option<String> {
    let fd = match rustix::fs::openat(
        dir,
        RUN_MANIFEST_C,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    ) {
        Ok(fd) => fd,
        Err(e) => return Some(format!("manifest restore refused: {e}")),
    };
    {
        use std::io::Write as _;
        let mut file = std::fs::File::from(fd);
        if let Err(e) = file.write_all(bytes) {
            let _ = rustix::fs::unlinkat(dir, RUN_MANIFEST_C, AtFlags::empty());
            return Some(format!("manifest rewrite failed: {e}"));
        }
    }
    None
}

/// X1: attempt manifest restore after a post-clear refusal; when
/// restoration cannot be completed, report the residential reason in
/// the refusal detail (kind preserved) instead of stranding silently.
fn with_restore_report(
    err: OperatorError,
    dir: std::os::fd::BorrowedFd<'_>,
    bytes: &[u8],
    validated: std::os::fd::BorrowedFd<'_>,
) -> OperatorError {
    match restore_manifest_at(dir, bytes, validated) {
        None => err,
        Some(reason) => OperatorError::new(err.kind(), format!("{}; unrestorable: {reason}", err.detail())),
    }
}

/// R36: read one bounded regular file through a held directory fd.
/// The open pins the inode; symlinks refuse; oversized and
/// non-regular occupants refuse without partial reads.
/// Y1/Z1: returns the bytes plus the OPEN descriptor they were
/// validated against. The caller retains it through clearing and
/// restoration: the pin keeps our inode allocated, so a later
/// identity comparison is sound — without it, an unlinked-then-
/// reused inode number could bless a replacement as a survivor.
fn read_at(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    max: u64,
) -> Result<(Vec<u8>, std::os::fd::OwnedFd), OperatorError> {
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
    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refused(format!("run manifest not readable: {e}")))?;
    if bytes.len() as u64 > max {
        return Err(refused("run manifest exceeds size bounds"));
    }
    Ok((bytes, file.into()))
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

    #[cfg(unix)]
    fn restore_scratch(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "restore-x1-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        base
    }

    #[cfg(unix)]
    fn file_id(path: &std::path::Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    /// Z1: retain the validated file the way `read_at` does in
    /// production — the open descriptor pins our inode, so identity
    /// comparisons against it are sound against number reuse.
    #[cfg(unix)]
    fn open_retained(path: &std::path::Path) -> std::fs::File {
        std::fs::File::options().read(true).open(path).unwrap()
    }

    /// Z4: probe the REAL capability behind the test's gate instead
    /// of branching on uid — uid 0 without DAC override must take
    /// the refusal branch, and an override-capable non-root the
    /// success branch. Each probe mirrors its test's gated op on a
    /// scratch twin.
    #[cfg(unix)]
    fn probe_can_create_in_readonly_dir() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let base = restore_scratch("probe-ro");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o555)).unwrap();
        let probe = base.join("probe");
        let ok = std::fs::write(&probe, b"p").is_ok();
        let _ = std::fs::remove_file(&probe);
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
        ok
    }

    /// Z4: probe open-for-write of a mode-000 file on a scratch twin.
    #[cfg(unix)]
    fn probe_can_open_mode_zero_file() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let base = restore_scratch("probe-zero");
        let slot = base.join("probe");
        std::fs::write(&slot, b"p").unwrap();
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o000)).unwrap();
        let ok = std::fs::File::options().read(true).write(true).open(&slot).is_ok();
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
        ok
    }

    #[cfg(unix)]
    fn open_scratch_dir(base: &std::path::Path) -> std::os::fd::OwnedFd {
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(base.as_os_str().as_bytes()).unwrap();
        rustix::fs::openat(
            rustix::fs::CWD,
            c.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// X1/Y1: a surviving regular manifest is left untouched — same
    /// inode, same mode, same bytes, same mtime (no rewrite churn),
    /// no report.
    #[cfg(unix)]
    #[test]
    fn restore_skips_surviving_regular_manifest() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let base = restore_scratch("skip");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o644)).unwrap();
        let pinned = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&slot)
            .unwrap()
            .set_modified(pinned)
            .unwrap();
        let retained = open_retained(&slot);
        let before = std::fs::metadata(&slot).unwrap();
        let dir = open_scratch_dir(&base);
        assert_eq!(
            restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd()),
            None
        );
        let after = std::fs::metadata(&slot).unwrap();
        assert_eq!(before.modified().unwrap(), after.modified().unwrap(), "survivor rewritten");
        assert_eq!(before.ino(), after.ino(), "survivor inode churned");
        assert_eq!(
            before.permissions().mode() & 0o777,
            after.permissions().mode() & 0o777,
            "survivor mode churned"
        );
        assert_eq!(std::fs::read(&slot).unwrap(), b"validated");
        drop(dir);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// X1/Z1: an absent manifest (validated, retained, then
    /// cleared like production) is recreated exclusively with the
    /// validated bytes at 0600, no report.
    #[cfg(unix)]
    #[test]
    fn restore_recreates_absent_manifest() {
        use std::os::unix::fs::PermissionsExt;
        let base = restore_scratch("absent");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        std::fs::remove_file(&slot).unwrap();
        let dir = open_scratch_dir(&base);
        assert_eq!(
            restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd()),
            None
        );
        drop(dir);
        drop(retained);
        assert_eq!(std::fs::read(&slot).unwrap(), b"validated");
        assert_eq!(
            std::fs::metadata(&slot).unwrap().permissions().mode() & 0o777,
            0o600,
            "restored manifest must be owner-only"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// X1/Z1: a planted symlink at the slot is evicted (never
    /// followed) and the validated bytes are restored.
    #[cfg(unix)]
    #[test]
    fn restore_evicts_planted_symlink() {
        let base = restore_scratch("link");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        std::fs::remove_file(&slot).unwrap();
        std::os::unix::fs::symlink("elsewhere", &slot).unwrap();
        let dir = open_scratch_dir(&base);
        assert_eq!(
            restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd()),
            None
        );
        drop(dir);
        assert!(std::fs::symlink_metadata(&slot).unwrap().is_file());
        assert_eq!(std::fs::read(&slot).unwrap(), b"validated");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// X1/Z1: an unevictable occupant (a directory at the slot
    /// refuses plain unlink) reports instead of stranding silently.
    #[cfg(unix)]
    #[test]
    fn restore_reports_unevictable_occupant() {
        let base = restore_scratch("dir");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        std::fs::remove_file(&slot).unwrap();
        std::fs::create_dir(&slot).unwrap();
        let dir = open_scratch_dir(&base);
        let reason = restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd())
            .expect("unevictable occupant must report");
        assert!(
            reason.contains("eviction failed"),
            "unexpected reason: {reason}"
        );
        drop(dir);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Y1: a planted replacement regular file is reported, never
    /// blessed as a survivor and never overwritten — its bytes and
    /// inode stand untouched.
    #[cfg(unix)]
    #[test]
    fn restore_reports_unproven_replacement() {
        use std::os::unix::fs::MetadataExt;
        let base = restore_scratch("replant");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let validated_id = file_id(&slot);
        let retained = open_retained(&slot);
        let donor = base.join("donor");
        std::fs::write(&donor, b"planted").unwrap();
        let planted_ino = std::fs::metadata(&donor).unwrap().ino();
        std::fs::rename(&donor, &slot).unwrap();
        assert_ne!(file_id(&slot), validated_id, "replant must differ");
        let dir = open_scratch_dir(&base);
        let reason = restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd())
            .expect("replacement must report");
        assert!(
            reason.contains("unproven replacement"),
            "unexpected reason: {reason}"
        );
        drop(dir);
        assert_eq!(std::fs::metadata(&slot).unwrap().ino(), planted_ino);
        assert_eq!(std::fs::read(&slot).unwrap(), b"planted");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Y1: a same-inode tampered survivor (bytes rewritten after
    /// validation) is healed to the validated bytes through the
    /// pinned descriptor — no name race, same inode after.
    #[cfg(unix)]
    #[test]
    fn restore_heals_tampered_survivor() {
        let base = restore_scratch("tamper");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let validated_id = file_id(&slot);
        let retained = open_retained(&slot);
        std::fs::write(&slot, b"tampered!!").unwrap();
        assert_eq!(file_id(&slot), validated_id, "rewrite keeps inode");
        let dir = open_scratch_dir(&base);
        assert_eq!(restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd()), None);
        drop(dir);
        assert_eq!(file_id(&slot), validated_id);
        assert_eq!(std::fs::read(&slot).unwrap(), b"validated");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Y1/Z4: an identity-matching but unreadable survivor (mode
    /// 000) reports instead of guessing. The expected branch comes
    /// from a capability probe, not the uid; a behavior/probe
    /// mismatch fails loudly either way.
    #[cfg(unix)]
    #[test]
    fn restore_reports_unverifiable_survivor() {
        use std::os::unix::fs::PermissionsExt;
        let override_present = probe_can_open_mode_zero_file();
        let base = restore_scratch("noperm");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o000)).unwrap();
        let dir = open_scratch_dir(&base);
        match (
            override_present,
            restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd()),
        ) {
            (true, None) => {}
            (false, Some(reason)) => {
                assert!(
                    reason.contains("not verifiable"),
                    "unexpected reason: {reason}"
                );
            }
            (true, Some(reason)) => panic!("refused despite override capability: {reason}"),
            (false, None) => panic!("verified without override capability"),
        }
        drop(dir);
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Z1: the retained descriptor is what makes the identity
    /// comparison sound — an open fd pins our inode number, so a
    /// replacement created after our unlink NECESSARILY differs and
    /// reports unproven. (Number-remembering code could bless a
    /// reused number; reuse is unobservable on this btrfs fs, so
    /// the pin guarantee itself is proved by the next test.)
    #[cfg(unix)]
    #[test]
    fn restore_reports_replacement_after_unlink_while_held() {
        let base = restore_scratch("held");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        let ours = file_id(&slot);
        std::fs::remove_file(&slot).unwrap();
        std::fs::write(&slot, b"planted").unwrap();
        assert_ne!(file_id(&slot), ours, "pin must prevent number reuse");
        let dir = open_scratch_dir(&base);
        let reason = restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd())
            .expect("post-unlink replacement must report");
        assert!(
            reason.contains("unproven replacement"),
            "unexpected reason: {reason}"
        );
        drop(dir);
        assert_eq!(std::fs::read(&slot).unwrap(), b"planted");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Z1: mechanism proof for the pin — while our descriptor holds
    /// an unlinked inode open, its number is not reallocated to any
    /// of 32 fresh files. Kernel guarantee, verified on this
    /// machine rather than assumed.
    #[cfg(unix)]
    #[test]
    fn retained_descriptor_pins_inode_number() {
        let base = restore_scratch("pin");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        let ours = file_id(&slot);
        std::fs::remove_file(&slot).unwrap();
        for i in 0..32 {
            let p = base.join(format!("filler{i}"));
            std::fs::write(&p, b"x").unwrap();
            assert_ne!(file_id(&p), ours, "pinned number reallocated to {p:?}");
        }
        drop(retained);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Z3: a replacement planted in the statat-to-open window
    /// (forced deterministically via hooks: the survivor vanishes
    /// after statat, the plant lands before create) must EEXIST
    /// into an unrestorable report — never be unlinked blind.
    #[cfg(unix)]
    #[test]
    fn restore_never_unlinks_window_replant() {
        let base = restore_scratch("race");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        let dir = open_scratch_dir(&base);
        let slot_stat = slot.clone();
        set_restore_after_stat_hook(Some(Box::new(move || {
            std::fs::remove_file(&slot_stat).unwrap();
        })));
        let slot_create = slot.clone();
        set_restore_enoent_race_hook(Some(Box::new(move || {
            std::fs::write(&slot_create, b"planted").unwrap();
        })));
        let reason = restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd())
            .expect("window replant must report, not vanish");
        assert!(
            reason.contains("restore refused"),
            "unexpected reason: {reason}"
        );
        drop(dir);
        assert_eq!(std::fs::read(&slot).unwrap(), b"planted", "replant deleted");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// R4: restore hooks are thread-local — a sibling thread's
    /// restore must neither consume nor fire this thread's armed
    /// hook. Deterministic: the child always passes the consume
    /// point (survivor path), so global storage always steals.
    #[cfg(unix)]
    #[test]
    fn restore_hooks_do_not_leak_across_threads() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let fired = Arc::new(AtomicBool::new(false));
        let base = restore_scratch("tls");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        let flag = fired.clone();
        set_restore_after_stat_hook(Some(Box::new(move || {
            flag.store(true, Ordering::SeqCst);
        })));
        let child = std::thread::spawn({
            let base = base.clone();
            let fired = fired.clone();
            move || {
                let dir = open_scratch_dir(&base);
                let retained = open_retained(&slot);
                let outcome = restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd());
                (outcome, fired.load(Ordering::SeqCst))
            }
        });
        let (outcome, fired_in_child) = child.join().unwrap();
        assert_eq!(outcome, None, "child restore must succeed unhooked");
        assert!(!fired_in_child, "child consumed the parent's hook");
        // Parent's hook is still armed (take semantics untouched).
        let dir = open_scratch_dir(&base);
        let outcome = restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd());
        assert_eq!(outcome, None);
        assert!(fired.load(Ordering::SeqCst), "parent hook must still fire");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Z3: a replacement planted in the statat-Err-to-create window
    /// (slot absent at statat, plant lands before create) must
    /// EEXIST into a report — the absent leg never unlinks.
    #[cfg(unix)]
    #[test]
    fn restore_absent_leg_never_unlinks_replant() {
        let base = restore_scratch("race-absent");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        std::fs::remove_file(&slot).unwrap();
        let dir = open_scratch_dir(&base);
        let slot_create = slot.clone();
        set_restore_absent_race_hook(Some(Box::new(move || {
            std::fs::write(&slot_create, b"planted").unwrap();
        })));
        let reason = restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd())
            .expect("absent-leg replant must report, not vanish");
        assert!(
            reason.contains("restore refused"),
            "unexpected reason: {reason}"
        );
        drop(dir);
        assert_eq!(std::fs::read(&slot).unwrap(), b"planted", "replant deleted");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// X1/Y4/Z4: an uncreatable slot (read-only dir) reports
    /// instead of stranding silently. The expected branch comes
    /// from a capability probe, not the uid: a DAC-override run
    /// restores successfully, a restricted run reports — and a
    /// behavior/probe mismatch fails loudly either way.
    #[cfg(unix)]
    #[test]
    fn restore_reports_uncreatable_slot() {
        use std::os::unix::fs::PermissionsExt;
        let override_present = probe_can_create_in_readonly_dir();
        let base = restore_scratch("ro");
        let slot = base.join(RUN_MANIFEST_FILE);
        std::fs::write(&slot, b"validated").unwrap();
        let retained = open_retained(&slot);
        std::fs::remove_file(&slot).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o555)).unwrap();
        let dir = open_scratch_dir(&base);
        match (
            override_present,
            restore_manifest_at(dir.as_fd(), b"validated", retained.as_fd()),
        ) {
            (true, None) => {
                drop(dir);
                assert_eq!(
                    std::fs::read(base.join(RUN_MANIFEST_FILE)).unwrap(),
                    b"validated"
                );
            }
            (false, Some(reason)) => {
                assert!(
                    reason.contains("restore refused"),
                    "unexpected reason: {reason}"
                );
                drop(dir);
            }
            (true, Some(reason)) => panic!("refused despite override capability: {reason}"),
            (false, None) => panic!("restored without override capability"),
        }
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }
}
