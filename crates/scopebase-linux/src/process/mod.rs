// SPDX-License-Identifier: Apache-2.0
// LX08 strict process observation core (bounded slice: epochs, birth, authority).
//
// ADAPT O src/pin.rs @4bcb24ce (TargetPin/pin/verify/parse_starttime, lines
// 15-24/43-95/98-105; ExternalTarget no-signal wrapper 113-138; regressions
// 144-177): pidfd + starttime pin, last-')' field-22 parse, re-read under pin,
// no-signal custody at the type level.
// ADAPT P src/process.rs @2c2713e6 (PidPin/acquire_proc_dir_with three-bracket
// custody 708-752, retained relative opens + bracketed maps reads 754-874,
// pidfd poll readiness 1274-1296, start_time_from_stat 1394-1404, zombie
// discrimination 1365-1383, race regressions 944-1033): original-pidfd
// brackets, relative retained reads, generation-state classification.
// ADAPT P src/pidns.rs @2c2713e6 (typed pid:[n] link grammar 81-88, Own proc
// view self/NSpid classifier 141-172, link/status negatives 470-507/592-635):
// descriptive link/view classifiers; only the authenticated retained-root
// algorithm below acquires authority.
// NEW strict ObserverEpoch/creator guard/FD-free markers, bounded raw-link
// transport, namespace_sample with kernel-confirmed kind, exact error/stage
// routing and fixed resource inventories: the donor has no complete bounded
// reusable composition. D03 scoped grant (2026-10-23) covers GPL-source to
// Apache-2.0 destination inside this library; donor files/terms untouched.
use crate::{
    control::{ControlStop, OperationControl},
    error::{
        CleanupDisposition, DescriptorFlagEffect, EffectSummary, LimitKind, LinuxError,
        PidfdPollEvidence, ProcCharges, ProcMember, ProcNamespaceKind, ProcOperation,
        ProcessErrorContext, Reason, ResourceCharges, Stage,
    },
    procfs::{ParseCharges, ParseLimits},
};
use rustix::{
    fs::{AtFlags, Mode, OFlags, ResolveFlags},
    io::{Errno, FdFlags},
};
use std::{
    ffi::CStr,
    fmt,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

mod epoch;
mod native;
mod observation;
pub use crate::identity::{MountViewId, ProcViewId, TaskBirthObservation};
pub use epoch::ObserverEpoch;
pub use observation::{
    BirthStatus, BirthVerification, MapsObservation, MountObservation, ProcessObservation,
};

/// Checked positive process ID. Accepts exactly 1..=i32::MAX in all modes.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pid {
    raw: i32,
}
impl Pid {
    pub const fn new(raw: i32) -> Option<Self> {
        if raw >= 1 {
            Some(Self { raw })
        } else {
            None
        }
    }
    pub const fn as_raw(self) -> i32 {
        self.raw
    }
    pub(crate) fn rustix(self) -> rustix::process::Pid {
        // Checked positive above; rustix 1.1.5's own negative check is
        // debug-only, so this expect cannot fire on a constructed Pid.
        rustix::process::Pid::from_raw(self.raw).expect("checked positive pid")
    }
}

/// Explicit nonzero ceilings. No Default; R additionally fits every declared
/// conservative syscall expression (R <= (u64::MAX-76)/3).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProcLimits {
    pub parse: ParseLimits,
    pub max_read_calls: u64,
    pub max_metadata_bytes: usize,
}

/// Largest admissible R: every conservative syscall/count expression fits u64.
pub(crate) const MAX_READ_CALLS: u64 = (u64::MAX - 76) / 3;

/// Validate nonzero limits and representable ceilings before any native work.
pub(crate) fn validate_limits(limits: ProcLimits) -> Result<(), LinuxError> {
    let bad = limits.parse.max_bytes == 0
        || limits.parse.max_entries == 0
        || limits.parse.max_line_bytes == 0
        || limits.max_read_calls == 0
        || limits.max_metadata_bytes == 0
        || limits.max_read_calls > MAX_READ_CALLS;
    if bad {
        return Err(entry_error(Reason::InvalidInput));
    }
    let meta_plus = limits.max_metadata_bytes.checked_add(1);
    let body_plus = limits.parse.max_bytes.checked_add(1);
    let fits = |v: Option<usize>| v.is_some_and(|v| v <= isize::MAX as usize);
    if !fits(meta_plus) || !fits(body_plus) {
        return Err(entry_error(Reason::LimitExceeded(
            LimitKind::BufferCapacity,
        )));
    }
    Ok(())
}

/// Entry refusal before any OS attempt: ConfigureProcess, member None, zero
/// native cost, but process charges present with body 0 and retained 0.
pub(crate) fn entry_error(reason: Reason) -> LinuxError {
    LinuxError {
        parse_line: None,
        stage: Stage::ConfigureProcess,
        reason,
        source: None,
        effect: EffectSummary {
            attempted: 0,
            completed: 0,
            cleanup: CleanupDisposition::NotNeeded,
            flags: DescriptorFlagEffect::NotAttempted,
        },
        charges: ResourceCharges {
            syscalls: 0,
            acquired: 0,
            peak: 0,
            read: None,
            parse: None,
            #[cfg(feature = "process")]
            process: Some(ProcCharges {
                read_calls: 0,
                metadata_bytes: 0,
                body_bytes: 0,
                requested_transport: 0,
                peak_granted_transport: 0,
                retained_transport: 0,
            }),
        },
        #[cfg(feature = "process")]
        process: None,
    }
}

/// Map errno at the actual operation; preserve the original error.
pub(crate) fn map_errno(errno: Errno) -> Reason {
    match errno {
        Errno::ACCESS | Errno::PERM => Reason::Denied,
        Errno::NOSYS | Errno::OPNOTSUPP | Errno::MFILE | Errno::NFILE | Errno::NOMEM => {
            Reason::Unavailable
        }
        Errno::NOENT | Errno::SRCH | Errno::STALE => Reason::Disappeared,
        _ => Reason::Unreadable,
    }
}

/// Per-invocation charged operation state: syscall/FD totals, M/R budgets,
/// transport capacities and the current member for staged refusals.
pub(crate) struct ProcOps {
    pub(crate) operation: ProcOperation,
    pub(crate) attempted: u64,
    pub(crate) completed: u64,
    pub(crate) acquired: u64,
    pub(crate) current: u64,
    pub(crate) peak: u64,
    pub(crate) read_calls: u64,
    pub(crate) metadata_bytes: u64,
    pub(crate) body_bytes: u64,
    pub(crate) requested_transport: usize,
    pub(crate) peak_granted_transport: usize,
    pub(crate) read_ceiling: u64,
    pub(crate) meta_ceiling: u64,
    pub(crate) flags: DescriptorFlagEffect,
    pub(crate) member: Option<ProcMember>,
    pub(crate) parse: Option<ParseCharges>,
}
impl ProcOps {
    pub(crate) fn new(operation: ProcOperation, limits: ProcLimits) -> Self {
        Self {
            operation,
            attempted: 0,
            completed: 0,
            acquired: 0,
            current: 0,
            peak: 0,
            read_calls: 0,
            metadata_bytes: 0,
            body_bytes: 0,
            requested_transport: 0,
            peak_granted_transport: 0,
            read_ceiling: limits.max_read_calls,
            meta_ceiling: limits.max_metadata_bytes as u64,
            flags: DescriptorFlagEffect::NotAttempted,
            member: None,
            parse: None,
        }
    }
    /// One counted explicit OS operation; completions include poll-zero/EOF.
    pub(crate) fn syscall<T>(&mut self, f: impl FnOnce() -> Result<T, Errno>) -> Result<T, Errno> {
        self.attempted += 1;
        match f() {
            Ok(value) => {
                self.completed += 1;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }
    pub(crate) fn fd_acquired(&mut self) {
        self.acquired += 1;
        self.current += 1;
        self.peak = self.peak.max(self.current);
    }
    pub(crate) fn fd_released(&mut self, count: u64) {
        self.current -= count;
    }
    /// Entry/edge control checkpoint; no refund, custody retained by caller.
    pub(crate) fn check(&self, control: &OperationControl, stage: Stage) -> Result<(), LinuxError> {
        control
            .checkpoint()
            .map_err(|stop| self.stop_error(stop, stage))
    }
    fn stop_error(&self, stop: ControlStop, stage: Stage) -> LinuxError {
        self.fail(
            stage,
            match stop {
                ControlStop::Cancelled => Reason::Cancelled,
                ControlStop::Deadline => Reason::Deadline,
            },
            None,
        )
    }
    /// Post-effect checkpoint: failed syscall errors (already returned) win;
    /// for a successful effect the stop wins before interpreting bytes/flags.
    pub(crate) fn post(&self, control: &OperationControl, stage: Stage) -> Result<(), LinuxError> {
        self.check(control, stage)
    }
    pub(crate) fn charges(&self) -> ResourceCharges {
        ResourceCharges {
            syscalls: self.attempted,
            acquired: self.acquired,
            peak: self.peak,
            read: None,
            parse: self.parse,
            #[cfg(feature = "process")]
            process: Some(ProcCharges {
                read_calls: self.read_calls,
                metadata_bytes: self.metadata_bytes,
                body_bytes: self.body_bytes,
                requested_transport: self.requested_transport,
                peak_granted_transport: self.peak_granted_transport,
                retained_transport: 0,
            }),
        }
    }
    pub(crate) fn effects(&self) -> EffectSummary {
        self.effect()
    }
    fn effect(&self) -> EffectSummary {
        EffectSummary {
            attempted: self.attempted,
            completed: self.completed,
            cleanup: if self.acquired == 0 {
                CleanupDisposition::NotNeeded
            } else {
                CleanupDisposition::Complete
            },
            flags: self.flags,
        }
    }
    /// Typed refusal at the actual stage with reached cost and outer context.
    pub(crate) fn fail(
        &self,
        stage: Stage,
        reason: Reason,
        source: Option<std::io::Error>,
    ) -> LinuxError {
        self.fail_with(
            stage,
            reason,
            source,
            ProcessErrorContext::new(self.operation, self.member),
        )
    }
    pub(crate) fn fail_with(
        &self,
        stage: Stage,
        reason: Reason,
        source: Option<std::io::Error>,
        context: ProcessErrorContext,
    ) -> LinuxError {
        LinuxError {
            parse_line: None,
            stage,
            reason,
            source,
            effect: self.effect(),
            charges: self.charges(),
            #[cfg(feature = "process")]
            process: Some(context),
        }
    }
    /// Preflight one more data attempt against R; refuses before issuing.
    pub(crate) fn preflight_read(&self, stage: Stage) -> Result<(), LinuxError> {
        if self.read_calls >= self.read_ceiling {
            return Err(self.fail(stage, Reason::LimitExceeded(LimitKind::ReadCalls), None));
        }
        Ok(())
    }
}

/// Positive-PID decimal scratch: at most 10 digits plus NUL.
pub(crate) fn pid_name(pid: Pid, scratch: &mut [u8; 12]) -> &CStr {
    let mut text = [0u8; 12];
    let digits = pid.as_raw().to_string();
    text[..digits.len()].copy_from_slice(digits.as_bytes());
    scratch.copy_from_slice(&text);
    let len = digits.len();
    CStr::from_bytes_with_nul(&scratch[..len + 1]).expect("numeric pid name")
}

/// Strict whole-input stat parse (ADAPT O pin.rs parse_starttime 43-57, P
/// process.rs start_time_from_stat 1394-1404): canonical PID prefix, last-')'
/// alignment, single alpha state, checked decimal field 22 (post-comm 19).
/// Comm bytes (spaces, newlines, deceptive parentheses) never separate fields.
pub(crate) struct ParsedStat {
    pub(crate) state: u8,
    pub(crate) start_ticks: u64,
}
pub(crate) fn parse_stat(input: &[u8], expected: Pid) -> Result<ParsedStat, ()> {
    let text = core::str::from_utf8(input).map_err(|_| ())?;
    let prefix = expected.as_raw().to_string() + " (";
    let after_prefix = text.strip_prefix(prefix.as_str()).ok_or(())?;
    let end = after_prefix.rfind(')').ok_or(())?;
    let suffix = &after_prefix[end + 1..];
    let mut tokens = suffix.split_ascii_whitespace();
    let state = tokens.next().ok_or(())?;
    if state.len() != 1 || !state.as_bytes()[0].is_ascii_alphabetic() {
        return Err(());
    }
    // Post-comm token 19 is field 22; token 0 is the state just consumed.
    let ticks = tokens.nth(18).ok_or(())?;
    if ticks.is_empty() || !ticks.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let start_ticks = ticks.parse::<u64>().map_err(|_| ())?;
    Ok(ParsedStat {
        state: state.as_bytes()[0],
        start_ticks,
    })
}

/// Strict Own status (ADAPT P pidns.rs classify_proc_view 141-172): exactly
/// one each of Pid/Tgid/NSpid; Pid and Tgid equal the observer; NSpid is
/// exactly that one positive decimal value. Other lines ignored.
pub(crate) fn parse_own_status(input: &[u8], me: Pid) -> Result<(), ()> {
    let text = core::str::from_utf8(input).map_err(|_| ())?;
    let canonical = me.as_raw().to_string();
    let (mut pid, mut tgid, mut nspid) = (0u32, 0u32, 0u32);
    for line in text.split('\n') {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        match name {
            "Pid" => {
                pid += 1;
                if single_decimal(values)? != canonical {
                    return Err(());
                }
            }
            "Tgid" => {
                tgid += 1;
                if single_decimal(values)? != canonical {
                    return Err(());
                }
            }
            "NSpid" => {
                nspid += 1;
                if single_decimal(values)? != canonical {
                    return Err(());
                }
            }
            _ => {}
        }
    }
    if pid == 1 && tgid == 1 && nspid == 1 {
        Ok(())
    } else {
        Err(())
    }
}

/// Strict target status: exactly one positive Pid/Tgid, both equal the
/// requested PID. Target NSpid is not constrained to a singleton.
pub(crate) fn parse_target_status(input: &[u8], target: Pid) -> Result<(), ()> {
    let text = core::str::from_utf8(input).map_err(|_| ())?;
    let canonical = target.as_raw().to_string();
    let (mut pid, mut tgid) = (0u32, 0u32);
    for line in text.split('\n') {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        match name {
            "Pid" => {
                pid += 1;
                if single_decimal(values)? != canonical {
                    return Err(());
                }
            }
            "Tgid" => {
                tgid += 1;
                if single_decimal(values)? != canonical {
                    return Err(());
                }
            }
            _ => {}
        }
    }
    if pid == 1 && tgid == 1 {
        Ok(())
    } else {
        Err(())
    }
}

/// Exactly one positive decimal field (no sign, no hex, no padding).
fn single_decimal(values: &str) -> Result<String, ()> {
    let mut fields = values.split_whitespace();
    let first = fields.next().ok_or(())?;
    if fields.next().is_some() {
        return Err(());
    }
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let canonical = first.parse::<i64>().map_err(|_| ())?.to_string();
    if canonical != first || canonical == "0" {
        return Err(());
    }
    Ok(canonical)
}

/// Typed namespace link grammar (ADAPT P pidns.rs parse_pid_ns_link 81-88):
/// exactly `pid:[decimal]` or `mnt:[decimal]`; any other shape refuses.
pub(crate) fn parse_ns_link(link: &[u8], prefix: &[u8]) -> Result<u64, ()> {
    let digits = link.strip_prefix(prefix).ok_or(())?;
    let digits = digits.strip_suffix(b"]").ok_or(())?;
    if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    core::str::from_utf8(digits)
        .map_err(|_| ())?
        .parse::<u64>()
        .map_err(|_| ())
}

/// Authenticated namespace key: nsfs device/inode plus kernel-confirmed kind.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct NsKey {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) kind: i32,
}

/// Ordinary traversal resolve policy: beneath, no symlinks/magiclinks/xdev.
fn strict_resolve() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}

/// One open plus one CLOEXEC flag check: exactly two counted attempts.
/// A missing bit is Malformed with observed flags; a failed query keeps its
/// actual errno/stage with no flag payload. Never silently fixes the bit.
pub(crate) fn checked_open_at2(
    ops: &mut ProcOps,
    control: &OperationControl,
    dirfd: BorrowedFd<'_>,
    name: &CStr,
    directory: bool,
    stage: Stage,
) -> Result<OwnedFd, LinuxError> {
    ops.check(control, stage)?;
    let mut oflags = OFlags::RDONLY | OFlags::CLOEXEC;
    if directory {
        oflags |= OFlags::DIRECTORY;
    }
    let fd =
        ops.syscall(|| rustix::fs::openat2(dirfd, name, oflags, Mode::empty(), strict_resolve()));
    let fd = match fd {
        Ok(fd) => fd,
        Err(errno) => return Err(ops.fail(stage, map_errno(errno), Some(errno.into()))),
    };
    ops.fd_acquired();
    if let Err(error) = ops.post(control, stage) {
        ops.fd_released(1);
        return Err(error);
    }
    check_cloexec(ops, control, &fd, stage)?;
    Ok(fd)
}

/// Global /proc capture: DIRECTORY|CLOEXEC|NOFOLLOW plus procfs proof.
pub(crate) fn checked_proc_root(
    ops: &mut ProcOps,
    control: &OperationControl,
) -> Result<OwnedFd, LinuxError> {
    let stage = Stage::AcquireProcRoot;
    ops.member = Some(ProcMember::Root);
    ops.check(control, stage)?;
    let fd = ops.syscall(|| {
        rustix::fs::open(
            "/proc",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
    });
    let fd = match fd {
        Ok(fd) => fd,
        Err(errno) => return Err(ops.fail(stage, map_errno(errno), Some(errno.into()))),
    };
    ops.fd_acquired();
    if let Err(error) = ops.post(control, stage) {
        ops.fd_released(1);
        return Err(error);
    }
    check_cloexec(ops, control, &fd, stage)?;
    ops.check(control, stage)?;
    let fs = ops.syscall(|| rustix::fs::fstatfs(&fd));
    let fs = match fs {
        Ok(fs) => fs,
        Err(errno) => {
            ops.fd_released(1);
            return Err(ops.fail(stage, map_errno(errno), Some(errno.into())));
        }
    };
    ops.post(control, stage)?;
    if fs.f_type != rustix::fs::PROC_SUPER_MAGIC {
        ops.fd_released(1);
        return Err(ops.fail(stage, Reason::WrongContext, None));
    }
    Ok(fd)
}

pub(crate) fn check_cloexec(
    ops: &mut ProcOps,
    control: &OperationControl,
    fd: &OwnedFd,
    stage: Stage,
) -> Result<(), LinuxError> {
    ops.check(control, stage)?;
    match ops.syscall(|| rustix::io::fcntl_getfd(fd)) {
        Ok(flags) => {
            if let Err(error) = ops.post(control, stage) {
                ops.flags = DescriptorFlagEffect::Unknown;
                ops.fd_released(1);
                return Err(error);
            }
            if flags.contains(FdFlags::CLOEXEC) {
                ops.flags = DescriptorFlagEffect::CloexecSet;
                Ok(())
            } else {
                ops.flags = DescriptorFlagEffect::Unknown;
                ops.fd_released(1);
                let mut context = ProcessErrorContext::new(ops.operation, ops.member);
                context.flags_observed = Some(flags.bits());
                Err(ops.fail_with(stage, Reason::Malformed, None, context))
            }
        }
        Err(errno) => {
            ops.flags = DescriptorFlagEffect::Unknown;
            ops.fd_released(1);
            Err(ops.fail(stage, map_errno(errno), Some(errno.into())))
        }
    }
}

/// Bounded exact link read: request exactly min(64, remaining_M+1) frozen
/// kernel bytes on an initialized stack slice. Oversize is tested before
/// grammar; a full buffer is truncated/Malformed. EINTR retries share R.
/// Returns the initialized length plus the stack buffer.
pub(crate) struct LinkBytes {
    pub(crate) len: usize,
    pub(crate) buf: [u8; 64],
}
impl LinkBytes {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}
pub(crate) fn read_link_exact(
    ops: &mut ProcOps,
    control: &OperationControl,
    dirfd: BorrowedFd<'_>,
    name: &CStr,
    stage: Stage,
) -> Result<LinkBytes, LinuxError> {
    let mut out = [0u8; 64];
    loop {
        ops.check(control, stage)?;
        ops.preflight_read(stage)?;
        let remaining = ops.meta_ceiling.saturating_sub(ops.metadata_bytes);
        let request = core::cmp::min(64, remaining.saturating_add(1) as usize).max(1);
        let slot = &mut out[..request];
        // Initialize the exact requested slice so the kernel writes only a
        // frozen buffer; spare tail bytes are never exposed.
        slot.fill(0);
        let init: &mut [core::mem::MaybeUninit<u8>] =
            unsafe { core::slice::from_raw_parts_mut(slot.as_mut_ptr().cast(), slot.len()) };
        let got = ops.syscall(|| rustix::fs::readlinkat_raw(dirfd, name, init));
        match got {
            Err(Errno::INTR) => {
                ops.read_calls += 1;
                ops.post(control, stage)?;
                continue;
            }
            Err(errno) => {
                ops.read_calls += 1;
                return Err(ops.fail(stage, map_errno(errno), Some(errno.into())));
            }
            Ok(bytes) => {
                let len = bytes.0.len();
                ops.read_calls += 1;
                ops.metadata_bytes += len as u64;
                ops.post(control, stage)?;
                if ops.metadata_bytes > ops.meta_ceiling {
                    return Err(ops.fail(
                        stage,
                        Reason::LimitExceeded(LimitKind::MetadataBytes),
                        None,
                    ));
                }
                if len == request {
                    return Err(ops.fail(stage, Reason::Malformed, None));
                }
                // readlinkat_raw initialized exactly `len` bytes of the
                // zeroed slice; the rest stays zero and unobserved.
                return Ok(LinkBytes { len, buf: out });
            }
        }
    }
}

/// Allocate one reusable transport Vec with requested capacity `bound + 1`;
/// refuse actual overgrant before initialization or processing.
pub(crate) fn transport_vec(
    ops: &mut ProcOps,
    bound: usize,
    stage: Stage,
) -> Result<Vec<u8>, LinuxError> {
    let requested = bound.checked_add(1).ok_or_else(|| {
        ops.fail(
            stage,
            Reason::LimitExceeded(LimitKind::BufferCapacity),
            None,
        )
    })?;
    ops.requested_transport = ops.requested_transport.saturating_add(requested);
    let mut vec = Vec::new();
    if vec.try_reserve_exact(requested).is_err() {
        return Err(ops.fail(stage, Reason::Allocation, None));
    }
    ops.peak_granted_transport = ops.peak_granted_transport.max(vec.capacity());
    if vec.capacity() > requested {
        return Err(ops.fail(
            stage,
            Reason::LimitExceeded(LimitKind::BufferCapacity),
            None,
        ));
    }
    Ok(vec)
}

/// Read one metadata file to actual EOF into the shared transport Vec (no
/// st_size or first-short-read completion). Charged against the invocation's
/// single M/R; a one-byte witness may consume M+1 before refusal.
pub(crate) fn read_metadata_eof(
    ops: &mut ProcOps,
    control: &OperationControl,
    fd: BorrowedFd<'_>,
    buf: &mut Vec<u8>,
    stage: Stage,
) -> Result<(), LinuxError> {
    buf.clear();
    loop {
        ops.check(control, stage)?;
        ops.preflight_read(stage)?;
        let spare = buf.capacity().saturating_sub(buf.len()).min(4096);
        if spare == 0 {
            return Err(ops.fail(stage, Reason::LimitExceeded(LimitKind::MetadataBytes), None));
        }
        let base = buf.len();
        buf.resize(base + spare, 0);
        let slot = &mut buf[base..];
        let got = ops.syscall(|| rustix::io::read(fd, slot));
        match got {
            Err(Errno::INTR) => {
                buf.truncate(base);
                ops.read_calls += 1;
                ops.post(control, stage)?;
                continue;
            }
            Err(errno) => {
                buf.truncate(base);
                ops.read_calls += 1;
                return Err(ops.fail(stage, map_errno(errno), Some(errno.into())));
            }
            Ok(0) => {
                buf.truncate(base);
                ops.read_calls += 1;
                ops.post(control, stage)?;
                return Ok(());
            }
            Ok(n) => {
                buf.truncate(base + n);
                ops.read_calls += 1;
                ops.metadata_bytes += n as u64;
                ops.post(control, stage)?;
                if ops.metadata_bytes > ops.meta_ceiling {
                    return Err(ops.fail(
                        stage,
                        Reason::LimitExceeded(LimitKind::MetadataBytes),
                        None,
                    ));
                }
            }
        }
    }
}

/// Zero-timeout pidfd readiness: requested POLLIN on the actual original fd.
/// Accept count0/revents0 nonterminal; count1 IN (+HUP) terminal; ERR/NVAL
/// wins even with IN; anything else is an Inconclusive contradiction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PollClass {
    Nonterminal,
    Terminal,
    Contradiction,
}
pub(crate) fn classify_poll(count: usize, revents: u16) -> PollClass {
    use rustix::event::PollFlags;
    let flags = PollFlags::from_bits_retain(revents);
    if flags.intersects(PollFlags::ERR | PollFlags::NVAL) {
        return PollClass::Contradiction;
    }
    match count {
        0 if flags.is_empty() => PollClass::Nonterminal,
        1 if flags.contains(PollFlags::IN)
            && !flags.intersects(!(PollFlags::IN | PollFlags::HUP)) =>
        {
            PollClass::Terminal
        }
        _ => PollClass::Contradiction,
    }
}

pub(crate) struct PollSample {
    pub(crate) class: PollClass,
    pub(crate) evidence: PidfdPollEvidence,
}

/// One counted zero-timeout poll; no retry. Syscall failure keeps its actual
/// errno at PollPidfd; contradictions carry exact evidence, no fake errno.
pub(crate) fn poll_pidfd(
    ops: &mut ProcOps,
    control: &OperationControl,
    fd: BorrowedFd<'_>,
    member: ProcMember,
) -> Result<PollSample, LinuxError> {
    let stage = Stage::PollPidfd;
    ops.member = Some(member);
    ops.check(control, stage)?;
    let mut target = rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN);
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let count =
        ops.syscall(|| rustix::event::poll(core::slice::from_mut(&mut target), Some(&zero)));
    match count {
        Err(errno) => Err(ops.fail(stage, map_errno(errno), Some(errno.into()))),
        Ok(count) => {
            ops.post(control, stage)?;
            let revents = target.revents().bits();
            let evidence = PidfdPollEvidence {
                ready: count,
                revents: revents as i16,
            };
            let class = classify_poll(count, revents);
            if class == PollClass::Contradiction {
                let mut context = ProcessErrorContext::new(ops.operation, Some(member));
                context.poll = Some(evidence);
                return Err(ops.fail_with(stage, Reason::Inconclusive, None, context));
            }
            Ok(PollSample { class, evidence })
        }
    }
}

/// Fresh ordinary `ns` sample with kernel-confirmed kind: nine fixed non-data
/// calls plus two bounded link reads. Holds at most two temporary FDs; the
/// caller retains the handle and closes the directory before returning.
pub(crate) fn namespace_sample(
    ops: &mut ProcOps,
    control: &OperationControl,
    procdir: BorrowedFd<'_>,
    name: &CStr,
    prefix: &[u8],
    expected: ProcNamespaceKind,
    expected_kind: i32,
    member: ProcMember,
) -> Result<(OwnedFd, NsKey), LinuxError> {
    let stage = Stage::CheckProcessNamespace;
    ops.member = Some(member);
    let nsdir = checked_open_at2(ops, control, procdir, c"ns", true, stage)?;
    let before = {
        let raw = read_link_exact(ops, control, nsdir.as_fd(), name, stage)?;
        let inode = parse_ns_link(raw.as_bytes(), prefix)
            .map_err(|_| ops.fail(stage, Reason::Malformed, None))?;
        ops.check(control, stage)?;
        let link = ops.syscall(|| rustix::fs::statat(&nsdir, name, AtFlags::SYMLINK_NOFOLLOW));
        let link = match link {
            Ok(link) => link,
            Err(errno) => {
                ops.fd_released(1);
                return Err(ops.fail(stage, map_errno(errno), Some(errno.into())));
            }
        };
        ops.post(control, stage)?;
        (inode, link.st_dev, link.st_ino)
    };
    let after = {
        let raw = read_link_exact(ops, control, nsdir.as_fd(), name, stage)?;
        let inode = parse_ns_link(raw.as_bytes(), prefix)
            .map_err(|_| ops.fail(stage, Reason::Malformed, None))?;
        ops.check(control, stage)?;
        let link = ops.syscall(|| rustix::fs::statat(&nsdir, name, AtFlags::SYMLINK_NOFOLLOW));
        let link = match link {
            Ok(link) => link,
            Err(errno) => {
                ops.fd_released(1);
                return Err(ops.fail(stage, map_errno(errno), Some(errno.into())));
            }
        };
        ops.post(control, stage)?;
        (inode, link.st_dev, link.st_ino)
    };
    if before != after {
        ops.fd_released(1);
        return Err(ops.fail(stage, Reason::ChangedSource, None));
    }
    // Intentionally follow the final magic link: plain openat, no NO_MAGICLINKS.
    ops.check(control, stage)?;
    let handle = ops.syscall(|| {
        rustix::fs::openat(
            &nsdir,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    });
    let handle = match handle {
        Ok(handle) => handle,
        Err(errno) => {
            ops.fd_released(1);
            return Err(ops.fail(stage, map_errno(errno), Some(errno.into())));
        }
    };
    ops.fd_acquired();
    if let Err(error) = ops.post(control, stage) {
        ops.fd_released(2);
        return Err(error);
    }
    if let Err(error) = check_cloexec(ops, control, &handle, stage) {
        ops.fd_released(1);
        return Err(error);
    }
    ops.check(control, stage)?;
    let fs = ops.syscall(|| rustix::fs::fstatfs(&handle));
    let fs = match fs {
        Ok(fs) => fs,
        Err(errno) => {
            ops.fd_released(2);
            return Err(ops.fail(stage, map_errno(errno), Some(errno.into())));
        }
    };
    ops.post(control, stage)?;
    if fs.f_type as u64 != native::NSFS_MAGIC as u64 {
        ops.fd_released(2);
        return Err(ops.fail(stage, Reason::WrongContext, None));
    }
    ops.check(control, stage)?;
    let stat = ops.syscall(|| rustix::fs::fstat(&handle));
    let stat = match stat {
        Ok(stat) => stat,
        Err(errno) => {
            ops.fd_released(2);
            return Err(ops.fail(stage, map_errno(errno), Some(errno.into())));
        }
    };
    ops.post(control, stage)?;
    if stat.st_ino != before.0 {
        ops.fd_released(2);
        return Err(ops.fail(stage, Reason::WrongContext, None));
    }
    ops.check(control, stage)?;
    let kind = ops.syscall(|| native::namespace_kind(handle.as_fd()));
    let kind = match kind {
        Ok(kind) => kind,
        Err(errno) => {
            ops.fd_released(2);
            let mut context = ProcessErrorContext::new(ops.operation, Some(member));
            context.kind_expected = Some(expected);
            context.kind_observed = None;
            let reason = if errno == Errno::NOTTY {
                Reason::Unavailable
            } else {
                map_errno(errno)
            };
            return Err(ops.fail_with(stage, reason, Some(errno.into()), context));
        }
    };
    ops.post(control, stage)?;
    if kind != expected_kind {
        ops.fd_released(2);
        let mut context = ProcessErrorContext::new(ops.operation, Some(member));
        context.kind_expected = Some(expected);
        context.kind_observed = Some(kind);
        return Err(ops.fail_with(stage, Reason::WrongContext, None, context));
    }
    ops.fd_released(1);
    drop(nsdir);
    Ok((
        handle,
        NsKey {
            device: stat.st_dev,
            inode: stat.st_ino,
            kind,
        },
    ))
}

/// Counted getpid with checked positive conversion. A nonpositive native
/// result is ConfigureProcess/Malformed (impossible-native-value seam).
pub(crate) fn current_pid(
    ops: &mut ProcOps,
    control: &OperationControl,
) -> Result<Pid, LinuxError> {
    let stage = Stage::ConfigureProcess;
    ops.member = None;
    ops.check(control, stage)?;
    let Ok(raw) =
        ops.syscall(|| Ok::<i32, Errno>(rustix::process::getpid().as_raw_nonzero().get()))
    else {
        unreachable!("counted getpid closure is infallible")
    };
    ops.post(control, stage)?;
    Pid::new(raw).ok_or_else(|| ops.fail(stage, Reason::Malformed, None))
}

/// Allocation-free creator comparison for the post-fork refusal probe: the
/// child runs only a vDSO getpid plus an integer comparison.
pub(crate) fn creator_pid_refused(creator: Pid) -> bool {
    rustix::process::getpid().as_raw_nonzero().get() != creator.as_raw()
}

impl fmt::Debug for ProcOps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcOps")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_line(pid: i32, comm: &str, state: &str, ticks: &str) -> Vec<u8> {
        // Fields 3..=21 after ")": state + 18 middle tokens, then starttime.
        let mut line = format!("{pid} ({comm}) {state}");
        for token in 1..=18 {
            line.push_str(&format!(" {token}"));
        }
        line.push_str(&format!(" {ticks} 20"));
        line.into_bytes()
    }

    #[test]
    fn stat_parse_finds_field22_after_last_paren() {
        // ADAPT O pin.rs stat_parse_tolerates_tricky_comm 169-177.
        let tricky = stat_line(123, "a)b (c", "R", "777");
        let parsed = parse_stat(&tricky, Pid::new(123).unwrap()).unwrap();
        assert_eq!(parsed.start_ticks, 777);
        assert_eq!(parsed.state, b'R');
        assert!(parse_stat(b"123 broken", Pid::new(123).unwrap()).is_err());
        assert!(parse_stat(b"123 (x) R", Pid::new(123).unwrap()).is_err());
    }

    #[test]
    fn stat_parse_rejects_prefix_state_and_field_faults() {
        let good = stat_line(42, "p11scope", "S", "999");
        let me = Pid::new(42).unwrap();
        assert!(parse_stat(&good, me).is_ok());
        // Wrong PID prefix, padded prefix, missing space-paren.
        assert!(parse_stat(&stat_line(43, "p11scope", "S", "999"), me).is_err());
        assert!(parse_stat(
            b"042 (p11scope) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999 20",
            me
        )
        .is_err());
        assert!(parse_stat(
            b"42(p11scope) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999 20",
            me
        )
        .is_err());
        // Non-alpha or multi-byte state, bad ticks, short suffix.
        assert!(parse_stat(&stat_line(42, "p11scope", "R+", "999"), me).is_err());
        assert!(parse_stat(&stat_line(42, "p11scope", "9", "999"), me).is_err());
        assert!(parse_stat(&stat_line(42, "p11scope", "S", "0x999"), me).is_err());
        assert!(parse_stat(
            &stat_line(42, "p11scope", "S", "99999999999999999999999"),
            me
        )
        .is_err());
        assert!(parse_stat(b"42 (x) S", me).is_err());
        // Invalid UTF-8 refuses; embedded newlines in comm are data.
        let mut bad_utf8 = good.clone();
        bad_utf8[6] = 0xFF;
        assert!(parse_stat(&bad_utf8, me).is_err());
        let newline = stat_line(42, "a\nb) (Z", "D", "5");
        let parsed = parse_stat(&newline, me).unwrap();
        assert_eq!((parsed.state, parsed.start_ticks), (b'D', 5));
        // Zero ticks are valid (never a globally unique task key).
        assert_eq!(
            parse_stat(&stat_line(42, "x", "R", "0"), me)
                .unwrap()
                .start_ticks,
            0
        );
    }

    #[test]
    fn own_status_requires_singleton_pid_tgid_nspid() {
        // ADAPT P pidns.rs only_this_namespaces_own_proc_classifies_own 592-635.
        let me = Pid::new(42).unwrap();
        let status = |nspid: &str| {
            format!("Name:\tp11scope\nTgid:\t42\nPid:\t42\nNSpid:{nspid}\n").into_bytes()
        };
        assert!(parse_own_status(&status("\t42"), me).is_ok());
        assert!(parse_own_status(&status(" 42 "), me).is_ok());
        for bad in [
            "\t7",
            "\t3026492\t42",
            "\t42\t1",
            "\t43",
            "",
            "\t042",
            "\t+42",
        ] {
            assert!(parse_own_status(&status(bad), me).is_err(), "{bad:?}");
        }
        // Duplicate fields, missing fields, wrong Tgid each refuse.
        let dup = b"Name:\tx\nTgid:\t42\nPid:\t42\nPid:\t42\nNSpid:\t42\n".as_slice();
        assert!(parse_own_status(dup, me).is_err());
        assert!(parse_own_status(b"Name:\tx\nPid:\t42\n", me).is_err());
        let wrong_tgid = b"Tgid:\t7\nPid:\t42\nNSpid:\t42\n".as_slice();
        assert!(parse_own_status(wrong_tgid, me).is_err());
        // Non-leader shape refuses here (InvalidInput at the call site).
        let nontgid = b"Tgid:\t42\nPid:\t7\nNSpid:\t7\n".as_slice();
        assert!(parse_own_status(nontgid, me).is_err());
    }

    #[test]
    fn target_status_pins_pid_tgid_without_nspid_singleton() {
        let target = Pid::new(7).unwrap();
        let both = b"Tgid:\t7\nPid:\t7\nNSpid:\t99\t7\n".as_slice();
        assert!(parse_target_status(both, target).is_ok());
        assert!(parse_target_status(b"Tgid:\t7\nPid:\t8\n", target).is_err());
        assert!(parse_target_status(b"Tgid:\t7\nPid:\t7\nPid:\t7\n", target).is_err());
        assert!(parse_target_status(b"Pid:\t7\n", target).is_err());
    }

    #[test]
    fn ns_link_grammar_accepts_only_typed_decimal() {
        // ADAPT P pidns.rs a_link_that_is_not_a_pid_namespace_is_unknown 481-507.
        assert_eq!(parse_ns_link(b"pid:[4026531836]", b"pid:["), Ok(4026531836));
        assert_eq!(parse_ns_link(b"mnt:[4026531832]", b"mnt:["), Ok(4026531832));
        for bad in [
            b"".as_slice(),
            b"4026531836",
            b"net:[4026531836]",
            b"pid_for_children:[4026531836]",
            b"pid:[]",
            b"pid:[4026531836",
            b"pid:4026531836]",
            b"pid:[ 4026531836]",
            b"pid:[4026531836] ",
            b"pid:[+4026531836]",
            b"pid:[0x4026531836]",
            b"pid:[18446744073709551616]",
            b"pid:[4026531836]\n",
            b"mnt:[4026531832]",
        ] {
            assert!(parse_ns_link(bad, b"pid:[").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn poll_classification_matches_status_table() {
        use rustix::event::PollFlags;
        let bits = |f: PollFlags| f.bits();
        assert_eq!(classify_poll(0, 0), PollClass::Nonterminal);
        assert_eq!(classify_poll(1, bits(PollFlags::IN)), PollClass::Terminal);
        assert_eq!(
            classify_poll(1, bits(PollFlags::IN | PollFlags::HUP)),
            PollClass::Terminal
        );
        // ERR/NVAL win even with IN.
        assert_eq!(
            classify_poll(1, bits(PollFlags::IN | PollFlags::ERR)),
            PollClass::Contradiction
        );
        assert_eq!(
            classify_poll(0, bits(PollFlags::NVAL)),
            PollClass::Contradiction
        );
        // HUP without IN, unknown flags, count anomalies contradict.
        assert_eq!(
            classify_poll(1, bits(PollFlags::HUP)),
            PollClass::Contradiction
        );
        assert_eq!(classify_poll(1, 0), PollClass::Contradiction);
        assert_eq!(
            classify_poll(0, bits(PollFlags::IN)),
            PollClass::Contradiction
        );
        assert_eq!(
            classify_poll(2, bits(PollFlags::IN)),
            PollClass::Contradiction
        );
        assert_eq!(
            classify_poll(1, bits(PollFlags::IN | PollFlags::OUT)),
            PollClass::Contradiction
        );
    }

    #[test]
    fn pid_decimal_scratch_is_nul_terminated() {
        let mut scratch = [0u8; 12];
        assert_eq!(
            pid_name(Pid::new(42).unwrap(), &mut scratch).to_bytes(),
            b"42"
        );
        assert_eq!(
            pid_name(Pid::new(i32::MAX).unwrap(), &mut scratch).to_bytes(),
            b"2147483647"
        );
    }
}
