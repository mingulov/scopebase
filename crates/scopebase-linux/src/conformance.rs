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
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};
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
///
/// R14: the root retains pinned authority from creation — an open fd to
/// the parent, the single-component name, and an open fd to the root
/// directory itself. Writes resolve descriptor-relative from the pinned
/// root fd, and retirement clears the tree through that fd and unlinks
/// the name through the pinned parent fd. Replacing an ancestor, or
/// swapping another directory in at the root path, redirects neither
/// writes nor cleanup: both stay bound to the created directory.
/// [`FixtureRoot::path`] is advisory (display, `HeldFile` opens) and is
/// never resolved for an effect.
#[derive(Debug)]
pub struct FixtureRoot {
    path: PathBuf,
    parent: OwnedFd,
    name: CString,
    root: OwnedFd,
}

impl FixtureRoot {
    /// Create `parent/name`. `name` must be one normal component; the parent
    /// must already exist. Fails (rather than reusing) when present.
    ///
    /// S14: the parent must be mutation-exclusive to this process —
    /// owned by our euid with no group/other write bit — so no other
    /// writer can swap the just-created name between `mkdirat` and
    /// `open`, and none can race later destruction. A shared parent
    /// (world-writable temp, group-writable project dir) refuses:
    /// stage a private `0700` directory first. Same-uid processes
    /// share all our rights and stay out of model, but every effect
    /// below stays descriptor-bound, so even a same-uid swapper can
    /// only strand (visible) residue, never redirect an effect.
    pub fn create(parent: &Path, name: &str) -> io::Result<Self> {
        if name.is_empty() || name.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad root name"));
        }
        let mut parts = Path::new(name).components();
        match (parts.next(), parts.next()) {
            (Some(Component::Normal(_)), None) => {}
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad root name")),
        }
        // Pin the parent first: the path resolves exactly once, at
        // creation; every later effect is descriptor-relative.
        let parent_fd = rfs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        require_exclusive_parent(parent_fd.as_fd(), "fixture parent")?;
        let cname = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad root name"))?;
        // mkdirat, not create_dir: fails (EEXIST) when present, like before.
        // S60: restrictive creation mode — the pre-chmod window is
        // 0755&~umask, never 0777&~umask; the fchmod below still pins
        // exactly 0755 regardless of umask.
        rfs::mkdirat(&parent_fd, &cname, Mode::from_bits_truncate(0o755))
            .map_err(io::Error::from)?;
        // S48: transactional acquisition. The just-created empty
        // directory is ours alone (exclusive parent, mkdirat
        // succeeded), so a failed open removes it instead of
        // leaking a root no owner can close.
        let root_fd = open_created(&parent_fd, &cname, AtFlags::REMOVEDIR)?;
        // S14: fresh roots are 0755 regardless of ambient umask, so
        // they nest as exclusive parents and no umask ever admits
        // group/other writers. S60: the chmod runs under rollback —
        // FixtureRoot (the owner) does not exist yet. The scope ends
        // the borrows before the fds move into Self.
        {
            let mut rollback = UnlinkArmed::armed(parent_fd.as_fd(), &cname);
            fchmod_created(
                &mut rollback,
                root_fd.as_fd(),
                Mode::from_bits_truncate(0o755),
            )?;
        }
        Ok(Self {
            path: parent.join(name),
            parent: parent_fd,
            name: cname,
            root: root_fd,
        })
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
        match rfs::mkdirat(dir.as_fd(), &name, Mode::from_bits_truncate(0o755)) {
            // S14: fresh dirs are 0755 regardless of umask (see
            // create). Reused dirs keep their modes: not ours to
            // dictate, and the gate judges them if nested under.
            // S60: restrictive creation mode plus chmod rollback —
            // a denied chmod removes the fresh dir instead of
            // leaving residue its caller never owned.
            Ok(()) => {
                let fresh = rfs::openat(
                    dir.as_fd(),
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(io::Error::from)?;
                {
                    let mut rollback = UnlinkArmed::armed(dir.as_fd(), &name);
                    fchmod_created(
                        &mut rollback,
                        fresh.as_fd(),
                        Mode::from_bits_truncate(0o755),
                    )?;
                }
            }
            Err(rustix::io::Errno::EXIST) => {
                // Present: verify it is a real directory, since
                // mkdirat also reports EEXIST for symlinks and files.
                rfs::openat(
                    dir.as_fd(),
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(io::Error::from)?;
            }
            Err(errno) => return Err(io::Error::from(errno)),
        }
        self.join(rel)
    }

    /// Remove the whole tree. Consumes the root so cleanup runs exactly once.
    ///
    /// R14: retirement is descriptor-bound. The tree is cleared through
    /// the pinned root fd; the name is then verified to still address
    /// our own directory before it is unlinked through the pinned
    /// parent fd. A final link-count check on the held fd proves OUR
    /// directory lost its name (a swap-and-replace between verify and
    /// unlink leaves our fd linked and fails instead of silently
    /// deleting the replacement).
    ///
    /// S13: mutation exclusion gates the destruction. The parent's
    /// exclusivity is re-verified both before clearing (fail fast,
    /// tree left fully in place) and immediately before the unlink
    /// (tight window): only an exclusive parent excludes a foreign
    /// swapper from the verify/unlink window. Clearing itself refuses
    /// non-exclusive nested directories (see `clear_dir`); the
    /// link-count proof stays as the backstop.
    pub fn close(self) -> io::Result<()> {
        // Fail fast on a loosened parent: nothing is cleared.
        require_exclusive_parent(self.parent.as_fd(), "fixture parent")?;
        clear_dir(self.root.as_fd())?;
        // Refuse a planted replacement BEFORE unlinking: the name
        // must still address our own directory.
        let live = rfs::openat(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let want = rfs::fstat(&self.root).map_err(io::Error::from)?;
        let got = rfs::fstat(&live).map_err(io::Error::from)?;
        if (got.st_dev, got.st_ino) != (want.st_dev, want.st_ino) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture root replaced before close",
            ));
        }
        drop(live);
        #[cfg(test)]
        fire_close_swap_hook();
        // Tight window: no foreign swapper can be inside it.
        require_exclusive_parent(self.parent.as_fd(), "fixture parent")?;
        rfs::unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR).map_err(io::Error::from)?;
        prove_unlinked(self.root.as_fd(), "fixture root")?;
        Ok(())
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
    /// R14: the walk starts from the pinned root fd, never from the
    /// advisory path, so ancestor swaps cannot redirect writes.
    fn open_parent_dir(&self, pieces: &[&std::ffi::OsStr]) -> io::Result<OwnedFd> {
        let mut dir = self.root.try_clone()?;
        for piece in &pieces[..pieces.len() - 1] {
            dir = open_child_dir(dir.as_fd(), &piece_cstr(piece)?)?;
        }
        Ok(dir)
    }
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
/// Multi-linked entries (hardlinks — never created by `FixtureRoot`,
/// so always foreign evidence) refuse the same way: the inode would
/// survive the unlink, and "removed" would be a lie.
///
/// S13: mutation exclusion before deletion. Each traversed directory
/// proves exclusive (euid-owned, no group/other write) before any
/// entry inside it is unlinked: in a shared directory another UID
/// could rename the held entry away and plant a replacement between
/// the hold and the unlink, and the post-unlink proof would only
/// detect the foreign deletion after it happened. Recursion carries
/// the gate to every level; the root's own name is gated by
/// `close`'s parent re-verification.
fn clear_dir(dir: BorrowedFd<'_>) -> io::Result<()> {
    require_exclusive_parent(dir, "fixture directory")?;
    let entries = rfs::Dir::read_from(dir).map_err(io::Error::from)?;
    for entry in entries {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let held = match rfs::openat(
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
            Err(errno) => return Err(io::Error::from(errno)),
        };
        let mode = rfs::fstat(&held).map_err(io::Error::from)?.st_mode;
        if FileType::from_raw_mode(mode) == FileType::Directory {
            let dot = piece_cstr(std::ffi::OsStr::new("."))?;
            let child = rfs::openat(
                held.as_fd(),
                &dot,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?;
            clear_dir(child.as_fd())?;
            rfs::unlinkat(dir, name, AtFlags::REMOVEDIR).map_err(io::Error::from)?;
        } else {
            // Plain unlink never follows a link, whatever the entry
            // changed into — dangling symlink, fifo, socket alike.
            rfs::unlinkat(dir, name, AtFlags::empty()).map_err(io::Error::from)?;
        }
        prove_unlinked(held.as_fd(), "entry")?;
    }
    Ok(())
}

/// Effective uid of this process, parsed from `/proc/self/status`
/// (the Uid line's second field). `rustix/process` (native
/// `geteuid`) sits behind the non-default `process` feature while
/// this module must build with default features, and
/// scopebase-linux already assumes procfs — so the parser adds no
/// dependency for the S14 gate.
fn euid() -> io::Result<u32> {
    let text = std::fs::read_to_string("/proc/self/status").map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot read own status: {error}"),
        )
    })?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut ids = rest.split_whitespace();
            ids.next();
            if let Some(effective) = ids.next().and_then(|id| id.parse().ok()) {
                return Ok(effective);
            }
            break;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "own Uid line malformed",
    ))
}

/// S14: prove the pinned directory is mutation-exclusive to us:
/// owned by our euid with no group/other write bit. An ACL write
/// grant to anyone would surface in the mask-backed group bits and
/// trip the same test, so the mode check covers ACLs too. Without
/// this, both the mkdir/open acquisition window and the
/// verify/unlink destruction window admit a foreign swapper.
///
/// S13: the same gate guards every deletion container: `close`
/// re-verifies the parent before clearing and again immediately
/// before the unlink, and `clear_dir` verifies each traversed
/// directory before unlinking inside it. Shared directories refuse
/// with `PermissionDenied` instead of deleting through a swappable
/// window.
fn require_exclusive_parent(parent: BorrowedFd<'_>, what: &str) -> io::Result<()> {
    let st = rfs::fstat(parent).map_err(io::Error::from)?;
    if st.st_uid != euid()? || st.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{what} not exclusive: stage a private 0700 directory"),
        ));
    }
    Ok(())
}

/// S13-round3: forced-substitution hook for the close window. Fires
/// once per arming, between the identity re-verify and the
/// deletion-time exclusivity check, then auto-disarms (take
/// semantics) so a stale hook can never affect another test. Only
/// the forced-window test arms it; production builds have no hook.
///
/// S79-round4: the hook binds to the ARMING THREAD, keyed per
/// thread. A process-global slot lets a parallel test's ordinary
/// `close` consume the hook first (mangling the forced test's
/// fixture and failing its assertions on correct production
/// code) — and a second arming test would overwrite the first
/// one's hook. Each thread arms, fires, and clears only its own
/// entry; foreign threads never observe it.
#[cfg(test)]
static CLOSE_SWAP_HOOK: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<std::thread::ThreadId, Box<dyn FnOnce() + Send>>>,
> = std::sync::OnceLock::new();

/// S79-round4: the per-thread hook table (see above).
#[cfg(test)]
fn close_swap_hooks() -> &'static std::sync::Mutex<
    std::collections::HashMap<std::thread::ThreadId, Box<dyn FnOnce() + Send>>,
> {
    CLOSE_SWAP_HOOK.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// S13-round3: arm (or clear, with `None`) the close-window hook.
#[cfg(test)]
pub(crate) fn set_close_swap_hook(hook: Option<Box<dyn FnOnce() + Send>>) {
    let mut guard = close_swap_hooks()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    match hook {
        Some(hook) => guard.insert(std::thread::current().id(), hook),
        None => guard.remove(&std::thread::current().id()),
    };
}

/// S13-round3: run the armed close-window hook, if any — only the
/// calling thread's own entry (S79-round4).
#[cfg(test)]
fn fire_close_swap_hook() {
    let hook = close_swap_hooks()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .remove(&std::thread::current().id());
    if let Some(hook) = hook {
        hook();
    }
}

/// S48: open a just-created name, removing it when the open
/// fails so a failed acquisition strands nothing. The caller
/// passes the unlink shape matching what it created (`REMOVEDIR`
/// for roots). With stable modes a just-created root always
/// opens, so production reaches the cleanup only on a mid-call
/// mode change or a resource fault; the test below pins a
/// `NOFOLLOW` refusal through the same branch to prove the
/// removal runs and the original error reports.
fn open_created(parent_fd: &OwnedFd, name: &CString, cleanup: AtFlags) -> io::Result<OwnedFd> {
    match rfs::openat(
        parent_fd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(fd),
        Err(errno) => {
            let opened = io::Error::from(errno);
            if let Err(removed) = rfs::unlinkat(parent_fd, name, cleanup).map_err(io::Error::from) {
                return Err(io::Error::new(
                    opened.kind(),
                    format!("root open failed: {opened} (cleanup: {removed})"),
                ));
            }
            Err(opened)
        }
    }
}

/// S60: rollback for a just-created directory, armed at creation
/// and disarmed once an owner holds it. Every initialization step
/// between (open, chmod) runs under the guard, so a failed step —
/// or a future added one — strands nothing. The armed drop is
/// best-effort; call sites that can still report unlink explicitly
/// with a combined error (see `open_created`'s idiom) and treat the
/// guard as the backstop.
struct UnlinkArmed<'a> {
    parent: BorrowedFd<'a>,
    name: &'a CString,
    armed: bool,
}

impl<'a> UnlinkArmed<'a> {
    fn armed(parent: BorrowedFd<'a>, name: &'a CString) -> Self {
        Self {
            parent,
            name,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for UnlinkArmed<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = rfs::unlinkat(self.parent, self.name, AtFlags::REMOVEDIR);
        }
    }
}

/// S60: chmod a just-created directory under its rollback guard.
/// Success disarms (an owner holds the name from here on); failure
/// removes the directory and reports the chmod error, combined with
/// the cleanup outcome when removal itself fails.
fn fchmod_created(guard: &mut UnlinkArmed<'_>, fd: BorrowedFd<'_>, mode: Mode) -> io::Result<()> {
    match rfs::fchmod(fd, mode) {
        Ok(()) => {
            guard.disarm();
            Ok(())
        }
        Err(errno) => {
            guard.disarm();
            let chmod = io::Error::from(errno);
            if let Err(removed) =
                rfs::unlinkat(guard.parent, guard.name, AtFlags::REMOVEDIR).map_err(io::Error::from)
            {
                return Err(io::Error::new(
                    chmod.kind(),
                    format!("dir chmod failed: {chmod} (cleanup: {removed})"),
                ));
            }
            // Named stage: distinguishes the chmod refusal from any
            // other PermissionDenied the construction can report.
            Err(io::Error::new(
                chmod.kind(),
                format!("fresh dir chmod refused: {chmod}"),
            ))
        }
    }
}

/// S13: prove the held inode lost its name. Unlinking a swapped-in
/// replacement leaves OUR inode linked and refuses instead of
/// reporting success over a foreign deletion.
fn prove_unlinked(held: BorrowedFd<'_>, what: &str) -> io::Result<()> {
    if rfs::fstat(held).map_err(io::Error::from)?.st_nlink != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} replaced during removal"),
        ));
    }
    Ok(())
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
            // S60: restrictive creation mode plus chmod rollback
            // (see create).
            rfs::mkdirat(parent, name, Mode::from_bits_truncate(0o755)).map_err(io::Error::from)?;
            let fresh = rfs::openat(parent, name, flags, Mode::empty()).map_err(io::Error::from)?;
            // S14: fresh intermediate dirs are 0755 (see create).
            {
                let mut rollback = UnlinkArmed::armed(parent, name);
                fchmod_created(
                    &mut rollback,
                    fresh.as_fd(),
                    Mode::from_bits_truncate(0o755),
                )?;
            }
            Ok(fresh)
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
