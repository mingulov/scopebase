// SPDX-License-Identifier: Apache-2.0
//! Explicit bounded descriptor-relative directory discovery (LX10).
//!
//! Traversal starts from a caller-held directory descriptor, never follows
//! directory symlinks, and never crosses mount boundaries unless
//! [`WalkPolicy::AllowMountCrossing`] is explicit. There is no ambient default
//! root. Every spend is precharged against explicit per-round and total
//! ceilings before enqueue, path clone, allocation, open, read or sort; no
//! collect-then-check path exists. Per-round exhaustion ends the current batch
//! with `done == false`; total exhaustion fails typed with the queue retained
//! in the budget. Spent work is never refunded, including on cancellation.
//!
//! # Lineage
//!
//! ADAPT of the two-window check-before-spend plus checked-add budget
//! mechanism from p11scope `src/discovery/scan.rs` (`remaining_window_io`,
//! `allowed_io`, `record_io`, `charge`, lines 1051-1123) at commit
//! `7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4`, under blanket grant
//! `OWNER-2026-10-23` and the scoped D03 GPL-to-Apache destination grant. Only
//! the allowance/checked-charge/sticky-stop shape is carried over; limits,
//! charges, epochs and the traversal itself are new vocabulary for the frozen
//! LX10 contract. NEW narrow adapter over the pinned rustix dependency: no
//! donor slice implements bounded descriptor-relative traversal (P discovery
//! uses ambient `std::fs::read_dir`; O slices cover file identity only).
//!
//! # D11 dependency probe (recorded 2026-10-23)
//!
//! cap-std/pathrs were evaluated at this first confined-traversal consumer.
//! Neither crate is in the offline lockfile or the local cargo cache, so no
//! build against them is possible under the offline rule; both would also need
//! a bespoke adapter for the frozen contract (explicit per-round plus total
//! ceilings with typed limit errors, epoch-bound resume, retained queue
//! custody, no-refund cancellation), which neither crate's API supplies. The
//! probe outcome is therefore a narrow adapter over SB02-admitted rustix
//! 1.1.5 (`std,fs,pipe`): `Dir` iteration, `statat` with
//! `AT_SYMLINK_NOFOLLOW`, and `openat` with
//! `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`. No new dependency was added.

use crate::{
    control::OperationControl,
    error::{
        CleanupDisposition, DescriptorFlagEffect, EffectSummary, LimitKind, LinuxError, Reason,
        ResourceCharges, Stage,
    },
};
use rustix::{
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags},
    io::Errno,
};
use std::{
    fmt,
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Explicit ceilings. Every field is a nonzero bound; allocator overhead and
/// concurrent calls are outside these budgets.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WalkLimits {
    /// Entries admitted to output.
    pub max_entries_visited: u64,
    /// Subdirectories enqueued for descent.
    pub max_entries_queued: usize,
    /// Depth of emitted entries; the root's direct entries are depth 1.
    pub max_depth: usize,
    /// Sum of queued relative-path bytes cloned for processing.
    pub max_path_bytes: usize,
    /// Sum of observed directory-entry name bytes.
    pub max_read_bytes: u64,
    /// Sum of emitted relative-path bytes retained in output.
    pub max_output_bytes: usize,
    /// Directory levels opened (root level plus one per descended subdir).
    pub max_open_fds: usize,
    /// Metadata observations (one per entry plus one confirm per subdir).
    pub max_stat_calls: u64,
    /// Directory-entry read attempts, including end-of-directory reads.
    pub max_read_calls: u64,
}

/// Mount-crossing policy, fixed when the root is opened.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WalkPolicy {
    /// Report mounted children but never descend into them.
    StayOnMount,
    /// Explicitly allow descent across mount boundaries.
    AllowMountCrossing,
}

/// Explicit caller root: a retained directory descriptor plus its policy.
///
/// The root path is never stored; only the descriptor, policy and the root
/// `(st_dev, st_ino)` are kept. A symlink, non-directory or missing path is
/// refused at open.
pub struct HeldDirectory {
    fd: OwnedFd,
    policy: WalkPolicy,
    root_dev: u64,
    root_ino: u64,
}

impl HeldDirectory {
    /// Open `path` as a traversal root with `policy`. The open uses
    /// `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`: a symlink root fails with
    /// `WrongContext`, a non-directory with `NonRegular`. Empty and
    /// NUL-containing paths fail with `InvalidInput` before any syscall.
    pub fn open(path: &Path, policy: WalkPolicy) -> Result<Self, LinuxError> {
        let raw = path.as_os_str().as_bytes();
        if raw.is_empty() || raw.contains(&0) {
            return Err(zero_error(Stage::WalkDirectory, Reason::InvalidInput));
        }
        let fd = match fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(errno) => {
                let refined = refine_notdir(path, errno);
                return Err(open_error(errno, refined, 1, 0));
            }
        };
        let stat = match fs::fstat(&fd) {
            Ok(stat) => stat,
            Err(errno) => return Err(open_error(errno, None, 2, 1)),
        };
        debug_assert_eq!(
            FileType::from_raw_mode(stat.st_mode),
            FileType::Directory,
            "O_DIRECTORY guarantees a directory"
        );
        Ok(Self {
            fd,
            policy,
            root_dev: stat.st_dev,
            root_ino: stat.st_ino,
        })
    }

    /// The mount policy fixed at open.
    pub fn policy(&self) -> WalkPolicy {
        self.policy
    }

    /// Device of the root directory, the StayOnMount comparison point.
    pub fn root_device(&self) -> u64 {
        self.root_dev
    }

    /// Inode of the root directory.
    pub fn root_inode(&self) -> u64 {
        self.root_ino
    }
}

impl fmt::Debug for HeldDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeldDirectory")
            .field("policy", &self.policy)
            .field("root_dev", &self.root_dev)
            .field("root_ino", &self.root_ino)
            .finish()
    }
}

/// `O_DIRECTORY|O_NOFOLLOW` reports a symlink root as `ENOTDIR`; refine the
/// failure-path diagnosis with one `lstat` so a refused symlink keeps its
/// `WrongContext` type instead of merging with non-directories.
fn refine_notdir(path: &Path, errno: Errno) -> Option<Reason> {
    if errno != Errno::NOTDIR {
        return None;
    }
    match fs::lstat(path) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
            Some(Reason::WrongContext)
        }
        _ => None,
    }
}

fn open_error(errno: Errno, refined: Option<Reason>, attempted: u64, completed: u64) -> LinuxError {
    let reason = if let Some(reason) = refined {
        reason
    } else {
        match errno {
            Errno::NOENT | Errno::STALE => Reason::Disappeared,
            Errno::NOTDIR => Reason::NonRegular,
            Errno::LOOP => Reason::WrongContext,
            Errno::ACCESS | Errno::PERM => Reason::Denied,
            Errno::NOSYS | Errno::OPNOTSUPP | Errno::MFILE | Errno::NFILE | Errno::NOMEM => {
                Reason::Unavailable
            }
            _ => Reason::Inconclusive,
        }
    };
    LinuxError {
        parse_line: None,
        stage: Stage::WalkDirectory,
        reason,
        source: Some(errno.into()),
        effect: EffectSummary {
            attempted,
            completed,
            cleanup: CleanupDisposition::NotNeeded,
            flags: DescriptorFlagEffect::NotAttempted,
        },
        charges: ResourceCharges {
            parse: None,
            syscalls: attempted,
            acquired: 0,
            peak: 0,
            read: None,
            #[cfg(feature = "process")]
            process: None,
        },
        #[cfg(feature = "process")]
        process: None,
    }
}

fn zero_error(stage: Stage, reason: Reason) -> LinuxError {
    LinuxError {
        parse_line: None,
        stage,
        reason,
        source: None,
        effect: EffectSummary {
            attempted: 0,
            completed: 0,
            cleanup: CleanupDisposition::NotNeeded,
            flags: DescriptorFlagEffect::NotAttempted,
        },
        charges: ResourceCharges {
            parse: None,
            syscalls: 0,
            acquired: 0,
            peak: 0,
            read: None,
            #[cfg(feature = "process")]
            process: None,
        },
        #[cfg(feature = "process")]
        process: None,
    }
}

/// Walk-local observer epoch. A new epoch (restart, rescan) never compares
/// equal to an old one; partial queue state resumes only under its own epoch.
///
/// This is a walk-local identity until LX08 lands, at which point budgets bind
/// the LX08 `ObserverEpoch` instead. The incompatibility rule (LX-R16) is
/// preserved either way: old state plus a new epoch refuses with
/// `WrongContext`, it never merges.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WalkEpoch {
    id: u64,
}

static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);

impl WalkEpoch {
    /// Allocate a fresh epoch identity unique within this process.
    pub fn new() -> Self {
        Self {
            id: NEXT_EPOCH.fetch_add(1, Ordering::SeqCst),
        }
    }

    /// Diagnostic identity. Equal ids mean the same epoch.
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Default for WalkEpoch {
    fn default() -> Self {
        Self::new()
    }
}

/// Cumulative (or per-round) traversal charges. Clones describe the same
/// ledger; summing aliases double counts.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct WalkCharges {
    entries_visited: u64,
    entries_queued: u64,
    stat_calls: u64,
    read_calls: u64,
    read_bytes: u64,
    path_bytes: u64,
    output_bytes: u64,
    open_fds: u64,
    peak_open_fds: u64,
    depth_pruned: u64,
    mount_pruned: u64,
    skipped_denied: u64,
    skipped_unstable: u64,
}

impl WalkCharges {
    /// Entries admitted to output.
    pub fn entries_visited(&self) -> u64 {
        self.entries_visited
    }
    /// Subdirectories enqueued for descent.
    pub fn entries_queued(&self) -> u64 {
        self.entries_queued
    }
    /// Metadata observations performed.
    pub fn stat_calls(&self) -> u64 {
        self.stat_calls
    }
    /// Directory-entry read attempts performed.
    pub fn read_calls(&self) -> u64 {
        self.read_calls
    }
    /// Entry name bytes charged.
    pub fn read_bytes(&self) -> u64 {
        self.read_bytes
    }
    /// Relative-path bytes cloned for processing.
    pub fn path_bytes(&self) -> u64 {
        self.path_bytes
    }
    /// Emitted path bytes retained in output.
    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }
    /// Directory levels opened.
    pub fn open_fds(&self) -> u64 {
        self.open_fds
    }
    /// Peak concurrently held level descriptors.
    pub fn peak_open_fds(&self) -> u64 {
        self.peak_open_fds
    }
    /// Entries skipped by the depth bound (observed, never emitted).
    pub fn depth_pruned(&self) -> u64 {
        self.depth_pruned
    }
    /// Mounted directories reported but not descended.
    pub fn mount_pruned(&self) -> u64 {
        self.mount_pruned
    }
    /// Subdirectories whose open was denied (entry reported, descent skipped).
    pub fn skipped_denied(&self) -> u64 {
        self.skipped_denied
    }
    /// Entries that vanished or were replaced between observation and use.
    pub fn skipped_unstable(&self) -> u64 {
        self.skipped_unstable
    }
}

/// Observed entry type, confirmed by `statat`, never by dirent type alone.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum WalkFileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symlink, reported and never followed.
    Symlink,
    /// FIFO, socket, device or anything else statable.
    Other,
}

fn classify(mode: u32) -> WalkFileType {
    match FileType::from_raw_mode(mode) {
        FileType::RegularFile => WalkFileType::Regular,
        FileType::Directory => WalkFileType::Directory,
        FileType::Symlink => WalkFileType::Symlink,
        _ => WalkFileType::Other,
    }
}

/// One emitted entry: path relative to the root plus confirmed identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkEntry {
    path: PathBuf,
    depth: usize,
    kind: WalkFileType,
    dev: u64,
    ino: u64,
}

impl WalkEntry {
    /// Path relative to the walk root, with raw bytes preserved.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Depth; the root's direct entries are depth 1.
    pub fn depth(&self) -> usize {
        self.depth
    }
    /// Confirmed file type.
    pub fn file_type(&self) -> WalkFileType {
        self.kind
    }
    /// Device of the entry itself.
    pub fn device(&self) -> u64 {
        self.dev
    }
    /// Inode of the entry itself.
    pub fn inode(&self) -> u64 {
        self.ino
    }
}

/// One bounded batch, sorted by path bytes within the batch only.
/// Deterministic global ordering across batches is not promised.
#[derive(Clone, Debug)]
pub struct WalkBatch {
    entries: Vec<WalkEntry>,
    done: bool,
    round: WalkCharges,
}

impl WalkBatch {
    /// Entries in this batch, sorted by path bytes.
    pub fn entries(&self) -> &[WalkEntry] {
        &self.entries
    }
    /// True when the traversal is complete; further calls return empty batches.
    pub fn is_done(&self) -> bool {
        self.done
    }
    /// Charges consumed by this round alone.
    pub fn round_charges(&self) -> WalkCharges {
        self.round
    }
}

/// Failed round: typed error, sorted partial output, cumulative charges and
/// the epoch the retained queue still belongs to. Queue custody stays in the
/// budget; retry with the same budget (and, for total exhaustion, a
/// same-epoch [`WalkBudget::raise_total`] first).
#[derive(Debug)]
pub struct WalkFailure {
    error: LinuxError,
    partial: Vec<WalkEntry>,
    charges: WalkCharges,
    epoch: u64,
}

impl WalkFailure {
    /// The typed refusal. Display/Debug omit paths.
    pub fn error(&self) -> &LinuxError {
        &self.error
    }
    /// Entries emitted before the failure, sorted by path bytes. They are
    /// consumed: a resume continues after them, it does not repeat them.
    pub fn partial(&self) -> &[WalkEntry] {
        &self.partial
    }
    /// Cumulative charges at the failure, never refunded.
    pub fn charges(&self) -> WalkCharges {
        self.charges
    }
    /// Epoch the retained queue belongs to.
    pub fn epoch_id(&self) -> u64 {
        self.epoch
    }
}

struct Level {
    dir: Dir,
    path: PathBuf,
    depth: usize,
}

/// A stream-consumed entry held across a round boundary (or a failure) so a
/// resume loses nothing. Unstatted entries re-observe by name under the still
/// pinned parent level; statted entries carry their observation forward.
enum Stash {
    Unstatted {
        path: PathBuf,
        depth: usize,
        name: Vec<u8>,
    },
    Statted {
        path: PathBuf,
        depth: usize,
        kind: WalkFileType,
        dev: u64,
        ino: u64,
        descend: bool,
        name: Vec<u8>,
    },
}

/// Which window a precharge refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Window {
    Round,
    Total,
}

struct SpendFail {
    kind: LimitKind,
    window: Window,
}

fn cap(limit: usize) -> u64 {
    u64::try_from(limit).unwrap_or(u64::MAX)
}

/// Checked two-window spend, adapting the donor allowance shape: the total
/// window fails first so global exhaustion surfaces immediately, then the
/// per-round window. Arithmetic overflow fails closed. Refused spends change
/// no counter; committed spends are never refunded.
fn spend(
    round: &mut u64,
    spent: &mut u64,
    per_max: u64,
    total_max: u64,
    amount: u64,
    kind: LimitKind,
) -> Result<(), SpendFail> {
    let next_round = round.checked_add(amount);
    let next_total = spent.checked_add(amount);
    match (next_round, next_total) {
        (Some(r), Some(t)) if t <= total_max && r <= per_max => {
            *round = r;
            *spent = t;
            Ok(())
        }
        (_, Some(t)) if t > total_max => Err(SpendFail {
            kind,
            window: Window::Total,
        }),
        (Some(r), _) if r > per_max => Err(SpendFail {
            kind,
            window: Window::Round,
        }),
        _ => Err(SpendFail {
            kind,
            window: Window::Total,
        }),
    }
}

/// Explicit per-round plus total budgets with retained queue custody.
///
/// The budget owns the open descent stack and at most one stashed in-flight
/// entry, so a failure or a batch boundary never loses traversal state. State
/// resumes only under the epoch bound at construction.
pub struct WalkBudget {
    per_round: WalkLimits,
    total: WalkLimits,
    epoch: u64,
    round: WalkCharges,
    spent: WalkCharges,
    attempted: u64,
    completed: u64,
    stack: Vec<Level>,
    stash: Option<Stash>,
    started: bool,
}

impl WalkBudget {
    /// Bind `per_round` and `total` ceilings to `epoch`. Every limit in both
    /// sets must be nonzero and each per-round ceiling must not exceed its
    /// total ceiling, else `InvalidInput` with zero charges.
    pub fn new(
        per_round: WalkLimits,
        total: WalkLimits,
        epoch: &WalkEpoch,
    ) -> Result<Self, LinuxError> {
        if !valid_limits(&per_round) || !valid_limits(&total) || !rounds_fit(&per_round, &total) {
            return Err(zero_error(Stage::WalkDirectory, Reason::InvalidInput));
        }
        Ok(Self {
            per_round,
            total,
            epoch: epoch.id,
            round: WalkCharges::default(),
            spent: WalkCharges::default(),
            attempted: 0,
            completed: 0,
            stack: Vec::new(),
            stash: None,
            started: false,
        })
    }

    /// Raise the total ceilings without losing queue custody. The epoch must
    /// match (`WrongContext` otherwise) and the new totals must be nonzero,
    /// dominate the per-round ceilings and dominate the current totals
    /// (`InvalidInput` otherwise). Per-round ceilings never change here.
    pub fn raise_total(&mut self, total: &WalkLimits, epoch: &WalkEpoch) -> Result<(), LinuxError> {
        if epoch.id != self.epoch {
            return Err(zero_error(Stage::WalkDirectory, Reason::WrongContext));
        }
        if !valid_limits(total)
            || !rounds_fit(&self.per_round, total)
            || !dominates(&self.total, total)
        {
            return Err(zero_error(Stage::WalkDirectory, Reason::InvalidInput));
        }
        self.total = *total;
        Ok(())
    }

    /// Refuse resumption under any epoch but the bound one.
    pub fn assert_epoch(&self, epoch: &WalkEpoch) -> Result<(), LinuxError> {
        if epoch.id != self.epoch {
            return Err(zero_error(Stage::WalkDirectory, Reason::WrongContext));
        }
        Ok(())
    }

    /// Per-round ceilings.
    pub fn per_round(&self) -> WalkLimits {
        self.per_round
    }

    /// Total ceilings.
    pub fn total(&self) -> WalkLimits {
        self.total
    }

    /// Epoch this budget's queue belongs to.
    pub fn epoch_id(&self) -> u64 {
        self.epoch
    }

    /// Cumulative charges across all rounds.
    pub fn cumulative_charges(&self) -> WalkCharges {
        self.spent
    }

    /// Retained queue depth: open levels plus any stashed in-flight entry.
    pub fn pending(&self) -> usize {
        self.stack.len() + usize::from(self.stash.is_some())
    }

    fn effect(&self) -> EffectSummary {
        EffectSummary {
            attempted: self.attempted,
            completed: self.completed,
            cleanup: CleanupDisposition::NotNeeded,
            flags: DescriptorFlagEffect::NotAttempted,
        }
    }

    fn charges(&self) -> ResourceCharges {
        ResourceCharges {
            parse: None,
            syscalls: self.attempted,
            acquired: self.spent.open_fds,
            peak: self.spent.peak_open_fds,
            read: None,
            #[cfg(feature = "process")]
            process: None,
        }
    }

    fn error(&self, reason: Reason, source: Option<std::io::Error>) -> LinuxError {
        LinuxError {
            parse_line: None,
            stage: Stage::WalkDirectory,
            reason,
            source,
            effect: self.effect(),
            charges: self.charges(),
            #[cfg(feature = "process")]
            process: None,
        }
    }

    fn errno_error(&self, errno: Errno) -> LinuxError {
        let reason = match errno {
            Errno::ACCESS | Errno::PERM => Reason::Denied,
            Errno::NOSYS | Errno::OPNOTSUPP | Errno::MFILE | Errno::NFILE | Errno::NOMEM => {
                Reason::Unavailable
            }
            Errno::NOENT | Errno::STALE => Reason::Disappeared,
            Errno::LOOP => Reason::WrongContext,
            _ => Reason::Inconclusive,
        };
        self.error(reason, Some(errno.into()))
    }

    fn failure(&self, error: LinuxError, mut partial: Vec<WalkEntry>) -> WalkFailure {
        partial.sort_by(|a, b| {
            a.path
                .as_os_str()
                .as_bytes()
                .cmp(b.path.as_os_str().as_bytes())
        });
        WalkFailure {
            error,
            partial,
            charges: self.spent,
            epoch: self.epoch,
        }
    }

    fn limit_failure(&self, kind: LimitKind, partial: Vec<WalkEntry>) -> WalkFailure {
        self.failure(self.error(Reason::LimitExceeded(kind), None), partial)
    }

    fn sample_peak(&mut self) {
        let concurrent = self.stack.len() as u64 + 1;
        self.round.peak_open_fds = self.round.peak_open_fds.max(concurrent);
        self.spent.peak_open_fds = self.spent.peak_open_fds.max(concurrent);
    }
}

impl fmt::Debug for WalkBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalkBudget")
            .field("epoch", &self.epoch)
            .field("pending", &self.pending())
            .field("spent", &self.spent)
            .finish()
    }
}

fn valid_limits(limits: &WalkLimits) -> bool {
    limits.max_entries_visited != 0
        && limits.max_entries_queued != 0
        && limits.max_depth != 0
        && limits.max_path_bytes != 0
        && limits.max_read_bytes != 0
        && limits.max_output_bytes != 0
        && limits.max_open_fds != 0
        && limits.max_stat_calls != 0
        && limits.max_read_calls != 0
}

fn rounds_fit(per_round: &WalkLimits, total: &WalkLimits) -> bool {
    per_round.max_entries_visited <= total.max_entries_visited
        && per_round.max_entries_queued <= total.max_entries_queued
        && per_round.max_depth <= total.max_depth
        && per_round.max_path_bytes <= total.max_path_bytes
        && per_round.max_read_bytes <= total.max_read_bytes
        && per_round.max_output_bytes <= total.max_output_bytes
        && per_round.max_open_fds <= total.max_open_fds
        && per_round.max_stat_calls <= total.max_stat_calls
        && per_round.max_read_calls <= total.max_read_calls
}

fn dominates(current: &WalkLimits, next: &WalkLimits) -> bool {
    rounds_fit(current, next)
}

impl WalkBudget {
    fn spend_read_call(&mut self) -> Result<(), SpendFail> {
        let out = spend(
            &mut self.round.read_calls,
            &mut self.spent.read_calls,
            self.per_round.max_read_calls,
            self.total.max_read_calls,
            1,
            LimitKind::ReadCalls,
        );
        if out.is_ok() {
            self.attempted += 1;
        }
        out
    }

    fn spend_open(&mut self) -> Result<(), SpendFail> {
        let out = spend(
            &mut self.round.open_fds,
            &mut self.spent.open_fds,
            cap(self.per_round.max_open_fds),
            cap(self.total.max_open_fds),
            1,
            LimitKind::OpenFds,
        );
        if out.is_ok() {
            self.attempted += 1;
        }
        out
    }
}

/// Traverse one bounded round from `root`, charging `budget`.
///
/// Cooperative cancellation is checkpoint-based: directory open/read calls on
/// local filesystems do not block, so checkpoints sit after entering each
/// charged operation and a stop surfaces at the next one with all spent work
/// retained. No worker threads are created.
pub fn walk(
    root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
) -> Result<WalkBatch, WalkFailure> {
    if let Err(stop) = control.checkpoint() {
        let error = stop.into_error(Stage::WalkDirectory, budget.effect(), budget.charges());
        return Err(budget.failure(error, Vec::new()));
    }
    budget.round = WalkCharges::default();
    let mut batch: Vec<WalkEntry> = Vec::new();
    // Stream progress this round: an end-of-batch without any is a refusal,
    // never an empty spin.
    let mut progressed = false;

    if let Some(stash) = budget.stash.take() {
        progressed = true;
        process_stash(root, budget, control, &mut batch, stash)?;
    }

    loop {
        if budget.stack.is_empty() {
            if budget.started {
                return Ok(finish_batch(budget, batch, true));
            }
            match budget.spend_open() {
                Ok(()) => {}
                Err(fail) => return Err(budget.limit_failure(fail.kind, batch)),
            }
            let dir = match Dir::read_from(&root.fd) {
                Ok(dir) => {
                    budget.completed += 1;
                    dir
                }
                Err(errno) => {
                    let error = budget.errno_error(errno);
                    return Err(budget.failure(error, batch));
                }
            };
            budget.sample_peak();
            budget.stack.push(Level {
                dir,
                path: PathBuf::new(),
                depth: 0,
            });
            budget.started = true;
            progressed = true;
            if let Err(failure) = checkpoint_after(root, budget, control, &mut batch) {
                return Err(failure);
            }
            continue;
        }
        match step_level(root, budget, control, &mut batch, &mut progressed) {
            Step::Continue => {}
            Step::EndBatch => return Ok(finish_batch(budget, batch, false)),
            Step::Failed(failure) => return Err(failure),
        }
    }
}

fn finish_batch(budget: &WalkBudget, mut entries: Vec<WalkEntry>, done: bool) -> WalkBatch {
    entries.sort_by(|a, b| {
        a.path
            .as_os_str()
            .as_bytes()
            .cmp(b.path.as_os_str().as_bytes())
    });
    WalkBatch {
        entries,
        done,
        round: budget.round,
    }
}

/// Post-operation checkpoint: a stop keeps the sorted partial batch and every
/// spent charge. Queue custody stays in the budget.
fn checkpoint_after(
    _root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
    batch: &mut Vec<WalkEntry>,
) -> Result<(), WalkFailure> {
    if let Err(stop) = control.checkpoint() {
        let error = stop.into_error(Stage::WalkDirectory, budget.effect(), budget.charges());
        let partial = std::mem::take(batch);
        return Err(budget.failure(error, partial));
    }
    Ok(())
}

enum Step {
    Continue,
    EndBatch,
    Failed(WalkFailure),
}

fn step_level(
    root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
    batch: &mut Vec<WalkEntry>,
    progressed: &mut bool,
) -> Step {
    match budget.spend_read_call() {
        Ok(()) => {}
        Err(fail) => return window_full(budget, batch, *progressed, fail),
    }
    let entry = {
        let level = budget.stack.last_mut().expect("level present");
        level.dir.read()
    };
    match entry {
        None => {
            budget.completed += 1;
            budget.stack.pop();
            *progressed = true;
            match checkpoint_after(root, budget, control, batch) {
                Ok(()) => Step::Continue,
                Err(failure) => Step::Failed(failure),
            }
        }
        Some(Err(errno)) => {
            let error = budget.errno_error(errno);
            Step::Failed(budget.failure(error, std::mem::take(batch)))
        }
        Some(Ok(entry)) => {
            budget.completed += 1;
            *progressed = true;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                return Step::Continue;
            }
            let name: Vec<u8> = name.to_vec();
            let (parent_path, parent_depth) = {
                let level = budget.stack.last().expect("level present");
                (level.path.clone(), level.depth)
            };
            let path = parent_path.join(std::ffi::OsStr::from_bytes(&name));
            let depth = parent_depth + 1;
            // Free structural bound before any per-entry spend.
            if depth > budget.per_round.max_depth || depth > budget.total.max_depth {
                budget.round.depth_pruned += 1;
                budget.spent.depth_pruned += 1;
                return Step::Continue;
            }
            process_fresh(root, budget, control, batch, path, depth, name)
        }
    }
}

/// Route a streaming precharge refusal: end the batch when this round already
/// moved, else the single operation is unsatisfiable under per-round ceilings.
fn window_full(
    budget: &WalkBudget,
    batch: &mut Vec<WalkEntry>,
    progressed: bool,
    fail: SpendFail,
) -> Step {
    match fail.window {
        Window::Total => Step::Failed(budget.limit_failure(fail.kind, std::mem::take(batch))),
        Window::Round if progressed || !batch.is_empty() => Step::EndBatch,
        Window::Round => Step::Failed(budget.limit_failure(fail.kind, std::mem::take(batch))),
    }
}

fn process_fresh(
    root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
    batch: &mut Vec<WalkEntry>,
    path: PathBuf,
    depth: usize,
    name: Vec<u8>,
) -> Step {
    match observe_entry(budget, batch, &path, &name) {
        Observe::Done => Step::Continue,
        Observe::Failed(failure) => Step::Failed(failure),
        Observe::Statted { kind, dev, ino } => emit_or_descend(
            root, budget, control, batch, path, depth, name, kind, dev, ino, None, false,
        ),
        Observe::RoundFull(_) => {
            budget.stash = Some(Stash::Unstatted { path, depth, name });
            Step::EndBatch
        }
    }
}

enum Observe {
    Statted {
        kind: WalkFileType,
        dev: u64,
        ino: u64,
    },
    /// Vanished or replaced between read and stat; counted, not emitted.
    Done,
    RoundFull(SpendFail),
    Failed(WalkFailure),
}

/// Phase-A precharge (name bytes, path bytes, one stat) then the stat itself.
/// All-or-nothing: a refusal spends nothing for this entry.
fn observe_entry(
    budget: &mut WalkBudget,
    batch: &mut Vec<WalkEntry>,
    path: &Path,
    name: &[u8],
) -> Observe {
    let name_len = name.len() as u64;
    let path_len = path.as_os_str().len() as u64;
    let mut round = budget.round;
    let mut spent = budget.spent;
    let per = budget.per_round;
    let total = budget.total;
    let attempt = spend(
        &mut round.read_bytes,
        &mut spent.read_bytes,
        per.max_read_bytes,
        total.max_read_bytes,
        name_len,
        LimitKind::ReadBytes,
    )
    .and(spend(
        &mut round.path_bytes,
        &mut spent.path_bytes,
        cap(per.max_path_bytes),
        cap(total.max_path_bytes),
        path_len,
        LimitKind::PathBytes,
    ))
    .and(spend(
        &mut round.stat_calls,
        &mut spent.stat_calls,
        per.max_stat_calls,
        total.max_stat_calls,
        1,
        LimitKind::StatCalls,
    ));
    match attempt {
        Ok(()) => {}
        Err(fail) => match fail.window {
            Window::Total => {
                let failure = budget.limit_failure(fail.kind, std::mem::take(batch));
                return Observe::Failed(failure);
            }
            Window::Round => return Observe::RoundFull(fail),
        },
    }
    // The confirm-stat is charged in phase B, once the stat below decides
    // whether this entry descends.
    budget.round = round;
    budget.spent = spent;
    budget.attempted += 1;
    let dir_fd = budget.stack.last().expect("parent level pinned").dir.fd();
    let dir_fd = match dir_fd {
        Ok(fd) => fd,
        Err(errno) => {
            let error = budget.errno_error(errno);
            return Observe::Failed(budget.failure(error, std::mem::take(batch)));
        }
    };
    let owned: Vec<u8> = name.iter().copied().chain(std::iter::once(0)).collect();
    let cname = match std::ffi::CStr::from_bytes_with_nul(&owned) {
        Ok(cname) => cname,
        Err(_) => {
            budget.round.skipped_unstable += 1;
            budget.spent.skipped_unstable += 1;
            return Observe::Done;
        }
    };
    match fs::statat(&dir_fd, cname, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            budget.completed += 1;
            Observe::Statted {
                kind: classify(stat.st_mode),
                dev: stat.st_dev,
                ino: stat.st_ino,
            }
        }
        Err(errno) if matches!(errno, Errno::NOENT | Errno::STALE) => {
            budget.round.skipped_unstable += 1;
            budget.spent.skipped_unstable += 1;
            Observe::Done
        }
        Err(errno) => {
            let error = budget.errno_error(errno);
            Observe::Failed(budget.failure(error, std::mem::take(batch)))
        }
    }
}

/// Phase-B all-or-nothing precharge (visit, output, and for descents the queue
/// slot, the level open and its confirm-stat), then emission and descent.
///
/// `descend_hint` carries the stored descent decision for destashed entries so
/// the mount-prune count is recorded exactly once per observation. `strict`
/// turns a per-round refusal into a typed failure: a destashed entry faces
/// fresh round counters, so a second round refusal proves the single entry is
/// unsatisfiable under the per-round ceilings.
#[allow(clippy::too_many_arguments)]
fn emit_or_descend(
    root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
    batch: &mut Vec<WalkEntry>,
    path: PathBuf,
    depth: usize,
    name: Vec<u8>,
    kind: WalkFileType,
    dev: u64,
    ino: u64,
    descend_hint: Option<bool>,
    strict: bool,
) -> Step {
    let descend = descend_hint.unwrap_or_else(|| {
        let descend = kind == WalkFileType::Directory
            && (root.policy == WalkPolicy::AllowMountCrossing || dev == root.root_dev);
        if kind == WalkFileType::Directory && !descend {
            budget.round.mount_pruned += 1;
            budget.spent.mount_pruned += 1;
        }
        descend
    });
    let path_len = path.as_os_str().len() as u64;
    let mut round = budget.round;
    let mut spent = budget.spent;
    let per = budget.per_round;
    let total = budget.total;
    let mut attempt = spend(
        &mut round.entries_visited,
        &mut spent.entries_visited,
        per.max_entries_visited,
        total.max_entries_visited,
        1,
        LimitKind::Entries,
    )
    .and(spend(
        &mut round.output_bytes,
        &mut spent.output_bytes,
        cap(per.max_output_bytes),
        cap(total.max_output_bytes),
        path_len,
        LimitKind::OutputBytes,
    ));
    if descend {
        attempt = attempt
            .and(spend(
                &mut round.entries_queued,
                &mut spent.entries_queued,
                cap(per.max_entries_queued),
                cap(total.max_entries_queued),
                1,
                LimitKind::QueuedEntries,
            ))
            .and(spend(
                &mut round.open_fds,
                &mut spent.open_fds,
                cap(per.max_open_fds),
                cap(total.max_open_fds),
                1,
                LimitKind::OpenFds,
            ))
            .and(spend(
                &mut round.stat_calls,
                &mut spent.stat_calls,
                per.max_stat_calls,
                total.max_stat_calls,
                1,
                LimitKind::StatCalls,
            ));
    }
    match attempt {
        Ok(()) => {}
        Err(fail) => {
            // Lossless either way: the consumed entry waits in the stash.
            budget.stash = Some(Stash::Statted {
                path,
                depth,
                kind,
                dev,
                ino,
                descend,
                name,
            });
            match fail.window {
                Window::Total => {
                    let failure = budget.limit_failure(fail.kind, std::mem::take(batch));
                    return Step::Failed(failure);
                }
                Window::Round if strict => {
                    let failure = budget.limit_failure(fail.kind, std::mem::take(batch));
                    return Step::Failed(failure);
                }
                Window::Round => return Step::EndBatch,
            }
        }
    }
    budget.round = round;
    budget.spent = spent;
    batch.push(WalkEntry {
        path: path.clone(),
        depth,
        kind,
        dev,
        ino,
    });
    if !descend {
        return match checkpoint_after(root, budget, control, batch) {
            Ok(()) => Step::Continue,
            Err(failure) => Step::Failed(failure),
        };
    }
    open_child(root, budget, control, batch, path, depth, &name, dev, ino)
}

fn open_child(
    root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
    batch: &mut Vec<WalkEntry>,
    path: PathBuf,
    depth: usize,
    name: &[u8],
    expect_dev: u64,
    expect_ino: u64,
) -> Step {
    budget.attempted += 1;
    let dir_fd = budget.stack.last().expect("parent level pinned").dir.fd();
    let dir_fd = match dir_fd {
        Ok(fd) => fd,
        Err(errno) => {
            let error = budget.errno_error(errno);
            return Step::Failed(budget.failure(error, std::mem::take(batch)));
        }
    };
    let owned: Vec<u8> = name.iter().copied().chain(std::iter::once(0)).collect();
    let cname = match std::ffi::CStr::from_bytes_with_nul(&owned) {
        Ok(cname) => cname,
        Err(_) => {
            budget.round.skipped_unstable += 1;
            budget.spent.skipped_unstable += 1;
            return Step::Continue;
        }
    };
    let child = match fs::openat(
        &dir_fd,
        cname,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(child) => {
            budget.completed += 1;
            child
        }
        Err(errno) if matches!(errno, Errno::ACCESS | Errno::PERM) => {
            budget.round.skipped_denied += 1;
            budget.spent.skipped_denied += 1;
            return match checkpoint_after(root, budget, control, batch) {
                Ok(()) => Step::Continue,
                Err(failure) => Step::Failed(failure),
            };
        }
        Err(errno)
            if matches!(
                errno,
                Errno::NOENT | Errno::STALE | Errno::NOTDIR | Errno::LOOP
            ) =>
        {
            budget.round.skipped_unstable += 1;
            budget.spent.skipped_unstable += 1;
            return match checkpoint_after(root, budget, control, batch) {
                Ok(()) => Step::Continue,
                Err(failure) => Step::Failed(failure),
            };
        }
        Err(errno) => {
            let error = budget.errno_error(errno);
            return Step::Failed(budget.failure(error, std::mem::take(batch)));
        }
    };
    budget.attempted += 1;
    match fs::fstat(&child) {
        Ok(stat) if stat.st_dev == expect_dev && stat.st_ino == expect_ino => {
            budget.completed += 1;
        }
        Ok(_) => {
            drop(child);
            budget.round.skipped_unstable += 1;
            budget.spent.skipped_unstable += 1;
            return match checkpoint_after(root, budget, control, batch) {
                Ok(()) => Step::Continue,
                Err(failure) => Step::Failed(failure),
            };
        }
        Err(errno) => {
            drop(child);
            let error = budget.errno_error(errno);
            return Step::Failed(budget.failure(error, std::mem::take(batch)));
        }
    }
    let dir = match Dir::new(child) {
        Ok(dir) => dir,
        Err(errno) => {
            let error = budget.errno_error(errno);
            return Step::Failed(budget.failure(error, std::mem::take(batch)));
        }
    };
    budget.sample_peak();
    budget.stack.push(Level { dir, path, depth });
    match checkpoint_after(root, budget, control, batch) {
        Ok(()) => Step::Continue,
        Err(failure) => Step::Failed(failure),
    }
}

fn process_stash(
    root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
    batch: &mut Vec<WalkEntry>,
    stash: Stash,
) -> Result<(), WalkFailure> {
    match stash {
        Stash::Unstatted { path, depth, name } => {
            match observe_entry(budget, batch, &path, &name) {
                Observe::Done => Ok(()),
                Observe::Failed(failure) => {
                    budget.stash = Some(Stash::Unstatted { path, depth, name });
                    Err(failure)
                }
                Observe::Statted { kind, dev, ino } => {
                    match emit_or_descend(
                        root, budget, control, batch, path, depth, name, kind, dev, ino, None, true,
                    ) {
                        Step::Continue => Ok(()),
                        Step::EndBatch => {
                            unreachable!("strict destash never ends the batch")
                        }
                        Step::Failed(failure) => Err(failure),
                    }
                }
                Observe::RoundFull(fail) => {
                    // Fresh round counters and the single entry still does not
                    // fit: unsatisfiable under these per-round ceilings.
                    budget.stash = Some(Stash::Unstatted { path, depth, name });
                    Err(budget.limit_failure(fail.kind, std::mem::take(batch)))
                }
            }
        }
        Stash::Statted {
            path,
            depth,
            kind,
            dev,
            ino,
            descend,
            name,
        } => match emit_or_descend(
            root,
            budget,
            control,
            batch,
            path,
            depth,
            name,
            kind,
            dev,
            ino,
            Some(descend),
            true,
        ) {
            Step::Continue => Ok(()),
            Step::EndBatch => unreachable!("strict destash never ends the batch"),
            Step::Failed(failure) => Err(failure),
        },
    }
}
