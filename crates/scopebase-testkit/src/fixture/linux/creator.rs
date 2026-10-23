// SPDX-License-Identifier: Apache-2.0
//! TT03 retained-root creator/context guard (private specialization).
//!
//! Normative: `creator-context.md`, `guard-error-map.json`. Successful
//! constructor retains exactly three original owners (authenticated proc
//! root, original creator pidfd, authenticated active-PID namespace FD)
//! with 6 acquisitions / peak 4 / 3 retained / 3 explicit closes and
//! 23+R native attempts (minimum 28). Each guarded entry costs 19+R
//! (minimum 24) with 4 fresh acquisitions and 4 explicit closes.
use rustix::fd::OwnedFd;
use std::fmt;

const NSFS_SUPER_MAGIC: u64 = 0x6e73_6673;
const CLONE_NEWPID: i32 = 0x2000_0000;
const STATUS_READ_CAP: usize = 65536;
const READLINK_STACK: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatorError {
    pub stage: GuardStage,
    pub reason: GuardReason,
    pub errno: Option<i32>,
    pub detail: String,
    pub attempts: u64,
}
impl CreatorError {
    fn new(stage: GuardStage, reason: GuardReason, errno: Option<i32>, detail: String) -> Self {
        Self {
            stage,
            reason,
            errno,
            detail,
            attempts: 0,
        }
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}
impl fmt::Display for CreatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "creator {:?}/{:?}: {}", self.stage, self.reason, self.detail)
    }
}
impl std::error::Error for CreatorError {}

/// Normative guard vocabulary (guard-error-map.json); close/cancel/timeout
/// mappings attach in the TT02 wiring follow-up.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardStage {
    CreatorPid,
    ProcRoot,
    SelfLink,
    ObserverDirectory,
    ObserverStatus,
    ActivePidNamespace,
    CreatorPidfd,
    TemporaryClose,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardReason {
    WrongContext,
    Inconclusive,
    Malformed,
    Unavailable,
    Denied,
    Io,
    Cancelled,
    TimedOut,
    Limit,
    CloseError,
}

fn errno_reason(errno: i32) -> GuardReason {
    match errno {
        1 | 13 => GuardReason::Denied,
        38 | 95 | 24 | 23 | 12 => GuardReason::Unavailable,
        _ => GuardReason::Io,
    }
}

fn rustix_error(stage: GuardStage, error: rustix::io::Errno) -> CreatorError {
    let errno = error.raw_os_error();
    CreatorError::new(stage, errno_reason(errno), Some(errno), error.to_string())
}

struct NsGetNstype;
unsafe impl rustix::ioctl::Ioctl for NsGetNstype {
    type Output = i32;
    const IS_MUTATING: bool = false;
    fn opcode(&self) -> rustix::ioctl::Opcode {
        rustix::ioctl::opcode::none(0xb7, 0x03)
    }
    fn as_ptr(&mut self) -> *mut std::ffi::c_void {
        std::ptr::null_mut()
    }
    unsafe fn output_from_ptr(
        out: rustix::ioctl::IoctlOutput,
        _extract: *mut std::ffi::c_void,
    ) -> rustix::io::Result<i32> {
        Ok(out)
    }
}

struct Counter {
    attempts: u64,
    data_attempts: u64,
}
impl Counter {
    fn syscall(&mut self) {
        self.attempts += 1;
    }
    fn data(&mut self) {
        self.attempts += 1;
        self.data_attempts += 1;
    }
}

fn check_cloexec(fd: &OwnedFd, counter: &mut Counter, stage: GuardStage) -> Result<(), CreatorError> {
    counter.syscall();
    let flags = rustix::io::fcntl_getfd(fd).map_err(|e| rustix_error(stage, e))?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(CreatorError::new(
            stage,
            GuardReason::Malformed,
            None,
            "new descriptor lacks CLOEXEC".to_string(),
        ));
    }
    Ok(())
}

fn open_child(
    dir: &OwnedFd,
    name: &str,
    dir_flag: bool,
    counter: &mut Counter,
    stage: GuardStage,
) -> Result<OwnedFd, CreatorError> {
    counter.syscall();
    let mut oflags = rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC;
    if dir_flag {
        oflags |= rustix::fs::OFlags::DIRECTORY;
    }
    let resolve = rustix::fs::ResolveFlags::BENEATH
        | rustix::fs::ResolveFlags::NO_SYMLINKS
        | rustix::fs::ResolveFlags::NO_MAGICLINKS
        | rustix::fs::ResolveFlags::NO_XDEV;
    let fd = rustix::fs::openat2(dir, name, oflags, rustix::fs::Mode::empty(), resolve).map_err(|e| rustix_error(stage, e))?;
    check_cloexec(&fd, counter, stage)?;
    Ok(fd)
}

fn read_to_end_bounded(
    fd: &OwnedFd,
    counter: &mut Counter,
    stage: GuardStage,
) -> Result<Vec<u8>, CreatorError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if out.len() >= STATUS_READ_CAP {
            return Err(CreatorError::new(
                stage,
                GuardReason::Limit,
                None,
                "status exceeds read ceiling".to_string(),
            ));
        }
        counter.data();
        match rustix::io::read(fd, &mut chunk) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(rustix_error(stage, e)),
        }
    }
}

fn readlink_bounded(
    dir: &OwnedFd,
    name: &str,
    counter: &mut Counter,
    stage: GuardStage,
) -> Result<Vec<u8>, CreatorError> {
    counter.data();
    let link = rustix::fs::readlinkat(dir, name, Vec::with_capacity(READLINK_STACK))
        .map_err(|e| rustix_error(stage, e))?;
    Ok(link.to_bytes().to_vec())
}

/// Explicit close with exact ownership transfer. rustix 1.1.5 exposes no
/// fallible OwnedFd close, so the errno is unreportable here; the descriptor
/// number is consumed exactly once and can never be reused or double-closed.
pub(crate) fn explicit_close_fd(fd: OwnedFd) {
    use std::os::unix::io::IntoRawFd;
    let raw = fd.into_raw_fd();
    // SAFETY: ownership moved out of the OwnedFd exactly once; no live alias.
    unsafe { rustix::io::close(raw) }
}

fn explicit_close(fd: OwnedFd, counter: &mut Counter, _what: &str) {
    counter.syscall();
    explicit_close_fd(fd);
}

fn parse_own_status(
    status: &[u8],
    me: u32,
) -> Result<(), CreatorError> {
    let text = std::str::from_utf8(status).map_err(|_| {
        CreatorError::new(
            GuardStage::ObserverStatus,
            GuardReason::Malformed,
            None,
            "status is not UTF-8".to_string(),
        )
    })?;
    let mut pid = Vec::new();
    let mut tgid = Vec::new();
    let mut nspid: Vec<Vec<u32>> = Vec::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Pid:") {
            pid.push(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Tgid:") {
            tgid.push(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("NSpid:") {
            let row: Option<Vec<u32>> = v
                .split_whitespace()
                .map(|n| n.parse::<u32>().ok())
                .collect();
            nspid.push(row.ok_or_else(|| {
                CreatorError::new(
                    GuardStage::ObserverStatus,
                    GuardReason::Malformed,
                    None,
                    "NSpid is not numeric".to_string(),
                )
            })?);
        }
    }
    if pid.len() != 1 || tgid.len() != 1 || nspid.len() != 1 {
        return Err(CreatorError::new(
            GuardStage::ObserverStatus,
            GuardReason::Malformed,
            None,
            "status must carry exactly one Pid/Tgid/NSpid".to_string(),
        ));
    }
    if pid[0] != me.to_string() || tgid[0] != me.to_string() {
        return Err(CreatorError::new(
            GuardStage::ObserverStatus,
            GuardReason::WrongContext,
            None,
            "Pid/Tgid differs from creator".to_string(),
        ));
    }
    if nspid[0] != [me] {
        return Err(CreatorError::new(
            GuardStage::ObserverStatus,
            GuardReason::WrongContext,
            None,
            "NSpid is not the singleton creator view".to_string(),
        ));
    }
    Ok(())
}

struct NamespaceSample {
    key: (u64, u64),
    handle: OwnedFd,
}

fn namespace_sample(
    numeric: &OwnedFd,
    counter: &mut Counter,
) -> Result<(NamespaceSample, OwnedFd), CreatorError> {
    let ns_dir = open_child(numeric, "ns", true, counter, GuardStage::ActivePidNamespace)?;
    let before_link = readlink_bounded(&ns_dir, "pid", counter, GuardStage::ActivePidNamespace)?;
    counter.syscall();
    let before_stat = rustix::fs::statat(
        &ns_dir,
        "pid",
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|e| rustix_error(GuardStage::ActivePidNamespace, e))?;
    counter.syscall();
    let handle = rustix::fs::openat(
        &ns_dir,
        "pid",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| rustix_error(GuardStage::ActivePidNamespace, e))?;
    check_cloexec(&handle, counter, GuardStage::ActivePidNamespace)?;
    counter.syscall();
    let fstype = rustix::fs::fstatfs(&handle)
        .map_err(|e| rustix_error(GuardStage::ActivePidNamespace, e))?;
    if fstype.f_type as u64 != NSFS_SUPER_MAGIC {
        return Err(CreatorError::new(
            GuardStage::ActivePidNamespace,
            GuardReason::WrongContext,
            None,
            "namespace handle is not nsfs".to_string(),
        ));
    }
    counter.syscall();
    let fstat = rustix::fs::fstat(&handle).map_err(|e| rustix_error(GuardStage::ActivePidNamespace, e))?;
    counter.syscall();
    let kind = unsafe { rustix::ioctl::ioctl(&handle, NsGetNstype) }.map_err(|e| {
        if e.raw_os_error() == 25 {
            CreatorError::new(
                GuardStage::ActivePidNamespace,
                GuardReason::Unavailable,
                Some(25),
                "namespace kind ioctl not supported".to_string(),
            )
        } else {
            rustix_error(GuardStage::ActivePidNamespace, e)
        }
    })?;
    if kind != CLONE_NEWPID {
        return Err(CreatorError::new(
            GuardStage::ActivePidNamespace,
            GuardReason::WrongContext,
            None,
            "namespace kind is not PID".to_string(),
        ));
    }
    let after_link = readlink_bounded(&ns_dir, "pid", counter, GuardStage::ActivePidNamespace)?;
    counter.syscall();
    let after_stat = rustix::fs::statat(
        &ns_dir,
        "pid",
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|e| rustix_error(GuardStage::ActivePidNamespace, e))?;
    for link in [&before_link, &after_link] {
        let text = std::str::from_utf8(link).map_err(|_| {
            CreatorError::new(
                GuardStage::ActivePidNamespace,
                GuardReason::Malformed,
                None,
                "namespace link is not UTF-8".to_string(),
            )
        })?;
        let bracketed = text.strip_prefix("pid:[").ok_or_else(|| {
            CreatorError::new(
                GuardStage::ActivePidNamespace,
                GuardReason::Malformed,
                None,
                "namespace link is not typed pid".to_string(),
            )
        })?;
        let digits = bracketed.strip_suffix(']').ok_or_else(|| {
            CreatorError::new(
                GuardStage::ActivePidNamespace,
                GuardReason::Malformed,
                None,
                "namespace link lacks its close bracket".to_string(),
            )
        })?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CreatorError::new(
                GuardStage::ActivePidNamespace,
                GuardReason::Malformed,
                None,
                "namespace link inode is not decimal".to_string(),
            ));
        }
    }
    if before_link != after_link
        || (before_stat.st_dev, before_stat.st_ino) != (after_stat.st_dev, after_stat.st_ino)
    {
        return Err(CreatorError::new(
            GuardStage::ActivePidNamespace,
            GuardReason::WrongContext,
            None,
            "namespace link identity moved during sampling".to_string(),
        ));
    }
    let link_text = std::str::from_utf8(&after_link).expect("validated UTF-8 link");
    let target_inode: u64 = link_text
        .strip_prefix("pid:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            CreatorError::new(
                GuardStage::ActivePidNamespace,
                GuardReason::Malformed,
                None,
                "namespace link target is not numeric".to_string(),
            )
        })?;
    if fstat.st_ino != target_inode {
        return Err(CreatorError::new(
            GuardStage::ActivePidNamespace,
            GuardReason::WrongContext,
            None,
            "namespace handle disagrees with sampled link".to_string(),
        ));
    }
    Ok((
        NamespaceSample {
            key: (fstat.st_dev, fstat.st_ino),
            handle,
        },
        ns_dir,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstructorEvidence {
    pub aux_acquired: u32,
    pub peak_aux_owners: u32,
    pub retained: u32,
    pub temp_closes: u32,
    pub native_attempts: u64,
    pub data_attempts: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardEvidence {
    pub poll_count: Option<u64>,
    pub poll_revents: Option<i32>,
    pub native_attempts: u64,
    pub data_attempts: u64,
    pub temp_closes: u32,
}

pub struct CreatorContext {
    proc_root: OwnedFd,
    creator_pidfd: OwnedFd,
    pid_ns: OwnedFd,
    creator_tgid: u32,
    ns_key: (u64, u64),
    constructor: ConstructorEvidence,
}

impl CreatorContext {
    pub fn acquire() -> Result<Self, CreatorError> {
        let mut counter = Counter {
            attempts: 0,
            data_attempts: 0,
        };
        counter.syscall();
        let me = std::process::id();
        if me == 0 || me > i32::MAX as u32 {
            return Err(CreatorError::new(
                GuardStage::CreatorPid,
                GuardReason::Malformed,
                None,
                "getpid is not a positive i32".to_string(),
            ));
        }
        counter.syscall();
        let proc_root = rustix::fs::open(
            "/proc",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| rustix_error(GuardStage::ProcRoot, e))?;
        check_cloexec(&proc_root, &mut counter, GuardStage::ProcRoot)?;
        counter.syscall();
        let fstype = rustix::fs::fstatfs(&proc_root)
            .map_err(|e| rustix_error(GuardStage::ProcRoot, e))?;
        if fstype.f_type != rustix::fs::PROC_SUPER_MAGIC {
            return Err(CreatorError::new(
                GuardStage::ProcRoot,
                GuardReason::WrongContext,
                None,
                "/proc is not procfs".to_string(),
            ));
        }
        let self_link = readlink_bounded(&proc_root, "self", &mut counter, GuardStage::SelfLink)?;
        if self_link != me.to_string().as_bytes() {
            return Err(CreatorError::new(
                GuardStage::SelfLink,
                GuardReason::WrongContext,
                None,
                "self link differs from creator".to_string(),
            ));
        }
        let numeric =
            open_child(&proc_root, &me.to_string(), true, &mut counter, GuardStage::ObserverDirectory)?;
        let status =
            open_child(&numeric, "status", false, &mut counter, GuardStage::ObserverStatus)?;
        let status_bytes = read_to_end_bounded(&status, &mut counter, GuardStage::ObserverStatus)?;
        parse_own_status(&status_bytes, me).map_err(|mut e| {
            e.attempts = counter.attempts;
            e
        })?;
        explicit_close(status, &mut counter, "status");
        let (sample, ns_dir) = namespace_sample(&numeric, &mut counter).map_err(|mut e| {
            e.attempts = counter.attempts;
            e
        })?;
        explicit_close(ns_dir, &mut counter, "nsdir");
        explicit_close(numeric, &mut counter, "numeric");
        counter.syscall();
        let pid = rustix::process::Pid::from_raw(me as i32).unwrap();
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
            .map_err(|e| rustix_error(GuardStage::CreatorPidfd, e))?;
        check_cloexec(&pidfd, &mut counter, GuardStage::CreatorPidfd)?;
        let evidence = poll_nonterminal(&pidfd, &mut counter)?;
        if evidence.poll_count != Some(0) || evidence.poll_revents != Some(0) {
            let mut e = CreatorError::new(
                GuardStage::CreatorPidfd,
                GuardReason::WrongContext,
                None,
                "creator pidfd is already terminal".to_string(),
            );
            e.attempts = counter.attempts;
            return Err(e);
        }
        Ok(Self {
            proc_root,
            creator_pidfd: pidfd,
            pid_ns: sample.handle,
            creator_tgid: me,
            ns_key: sample.key,
            constructor: ConstructorEvidence {
                aux_acquired: 6,
                peak_aux_owners: 4,
                retained: 3,
                temp_closes: 3,
                native_attempts: counter.attempts,
                data_attempts: counter.data_attempts,
            },
        })
    }

    pub fn constructor_evidence(&self) -> &ConstructorEvidence {
        &self.constructor
    }

    pub fn ledger_bytes(&self) -> Vec<u8> {
        let e = &self.constructor;
        format!(
            "{{\"creator_tgid\":{},\"ns_device\":\"{}\",\"ns_inode\":\"{}\",\
             \"aux_acquired\":{},\"peak_aux_owners\":{},\"retained\":{},\
             \"temp_closes\":{},\"native_attempts\":\"{}\",\"data_attempts\":\"{}\"}}",
            self.creator_tgid,
            self.ns_key.0,
            self.ns_key.1,
            e.aux_acquired,
            e.peak_aux_owners,
            e.retained,
            e.temp_closes,
            e.native_attempts,
            e.data_attempts,
        )
        .into_bytes()
    }

    pub fn guard(&self) -> Result<GuardEvidence, CreatorError> {
        let mut counter = Counter {
            attempts: 0,
            data_attempts: 0,
        };
        counter.syscall();
        if std::process::id() != self.creator_tgid {
            let mut e = CreatorError::new(
                GuardStage::CreatorPid,
                GuardReason::WrongContext,
                None,
                "current pid differs from creator".to_string(),
            );
            e.attempts = counter.attempts;
            return Err(e);
        }
        let poll = poll_nonterminal(&self.creator_pidfd, &mut counter)?;
        const POLLIN: i32 = 0x01;
        const POLLERR: i32 = 0x08;
        const POLLNVAL: i32 = 0x20;
        match (poll.poll_count, poll.poll_revents) {
            (Some(0), Some(0)) => {}
            (Some(1), Some(flags))
                if flags & POLLIN != 0 && flags & (POLLERR | POLLNVAL) == 0 => {
                let mut e = CreatorError::new(
                    GuardStage::CreatorPidfd,
                    GuardReason::WrongContext,
                    None,
                    "creator pidfd turned terminal".to_string(),
                );
                e.attempts = counter.attempts;
                return Err(e);
            }
            _ => {
                let mut e = CreatorError::new(
                    GuardStage::CreatorPidfd,
                    GuardReason::Inconclusive,
                    None,
                    "creator poll output is inconclusive".to_string(),
                );
                e.attempts = counter.attempts;
                return Err(e);
            }
        }
        let self_link = readlink_bounded(&self.proc_root, "self", &mut counter, GuardStage::SelfLink)?;
        if self_link != self.creator_tgid.to_string().as_bytes() {
            let mut e = CreatorError::new(
                GuardStage::SelfLink,
                GuardReason::WrongContext,
                None,
                "self link differs from creator".to_string(),
            );
            e.attempts = counter.attempts;
            return Err(e);
        }
        let numeric = open_child(
            &self.proc_root,
            &self.creator_tgid.to_string(),
            true,
            &mut counter,
            GuardStage::ObserverDirectory,
        )
        .map_err(|mut e| {
            e.attempts = counter.attempts;
            e
        })?;
        let status = open_child(&numeric, "status", false, &mut counter, GuardStage::ObserverStatus)
            .map_err(|mut e| {
            e.attempts = counter.attempts;
            e
        })?;
        let status_bytes =
            read_to_end_bounded(&status, &mut counter, GuardStage::ObserverStatus).map_err(|mut e| {
                e.attempts = counter.attempts;
                e
            })?;
        parse_own_status(&status_bytes, self.creator_tgid).map_err(|mut e| {
            e.attempts = counter.attempts;
            e
        })?;
        explicit_close(status, &mut counter, "status");
        let (sample, ns_dir) = namespace_sample(&numeric, &mut counter).map_err(|mut e| {
            e.attempts = counter.attempts;
            e
        })?;
        if sample.key != self.ns_key {
            let mut e = CreatorError::new(
                GuardStage::ActivePidNamespace,
                GuardReason::WrongContext,
                None,
                "active PID namespace key changed".to_string(),
            );
            e.attempts = counter.attempts;
            return Err(e);
        }
        explicit_close(ns_dir, &mut counter, "nsdir");
        explicit_close(sample.handle, &mut counter, "nshandle");
        explicit_close(numeric, &mut counter, "numeric");
        Ok(GuardEvidence {
            poll_count: poll.poll_count,
            poll_revents: poll.poll_revents,
            native_attempts: counter.attempts,
            data_attempts: counter.data_attempts,
            temp_closes: 4,
        })
    }

    pub fn close(self) -> CreatorCloseOutcome {
        let mut outcome = CreatorCloseOutcome {
            closed: 0,
            errors: Vec::new(),
        };
        for (fd, what) in [
            (self.proc_root, "proc_root"),
            (self.creator_pidfd, "creator_pidfd"),
            (self.pid_ns, "pid_ns"),
        ] {
            let _ = what;
            explicit_close_fd(fd);
            outcome.closed += 1;
        }
        outcome
    }
}

fn poll_nonterminal(pidfd: &OwnedFd, counter: &mut Counter) -> Result<GuardEvidence, CreatorError> {
    counter.syscall();
    let mut fds = [rustix::event::PollFd::new(pidfd, rustix::event::PollFlags::IN)];
    let zero = rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 };
    let count = rustix::event::poll(&mut fds, Some(&zero))
        .map_err(|e| rustix_error(GuardStage::CreatorPidfd, e))?;
    let revents = fds[0].revents();
    Ok(GuardEvidence {
        poll_count: Some(count as u64),
        poll_revents: Some(revents.bits() as i32),
        native_attempts: counter.attempts,
        data_attempts: counter.data_attempts,
        temp_closes: 0,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatorCloseOutcome {
    pub closed: u32,
    pub errors: Vec<(String, i32)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_inventories_and_minimums() {
        let context = CreatorContext::acquire().unwrap();
        let e = context.constructor_evidence();
        assert_eq!(
            (e.aux_acquired, e.peak_aux_owners, e.retained, e.temp_closes),
            (6, 4, 3, 3)
        );
        assert_eq!(e.native_attempts, 23 + e.data_attempts);
        assert!(e.data_attempts >= 5, "R floor: {}", e.data_attempts);
        assert!(e.native_attempts >= 28);
        assert!(!context.ledger_bytes().is_empty());
        let outcome = context.close();
        assert_eq!((outcome.closed, outcome.errors.len()), (3, 0));
    }

    #[test]
    fn guard_costs_and_nonterminal_poll() {
        let context = CreatorContext::acquire().unwrap();
        let evidence = context.guard().unwrap();
        assert_eq!((evidence.poll_count, evidence.poll_revents), (Some(0), Some(0)));
        assert_eq!(evidence.temp_closes, 4);
        assert_eq!(evidence.native_attempts, 19 + evidence.data_attempts);
        assert!(evidence.data_attempts >= 5);
        assert!(evidence.native_attempts >= 24);
        context.close();
    }

    #[test]
    fn own_status_vectors() {
        let me = 4242u32;
        let good = format!(
            "Name:\tsleep\nPid:\t{me}\nTgid:\t{me}\nNSpid:\t{me}\n"
        );
        assert!(parse_own_status(good.as_bytes(), me).is_ok());
        assert!(parse_own_status(good.as_bytes(), me + 1).is_err());
        let nested = format!("Name:\tsleep\nPid:\t{me}\nTgid:\t{me}\nNSpid:\t9\t{me}\n");
        assert!(parse_own_status(nested.as_bytes(), me).is_err());
        let doubled =
            format!("Name:\tsleep\nPid:\t{me}\nPid:\t{me}\nTgid:\t{me}\nNSpid:\t{me}\n");
        assert!(parse_own_status(doubled.as_bytes(), me).is_err());
        assert!(parse_own_status(b"\xff\xfe", me).is_err());
    }
}
