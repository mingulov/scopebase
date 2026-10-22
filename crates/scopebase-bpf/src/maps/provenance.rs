// SPDX-License-Identifier: Apache-2.0
//! Authentic kernel source and original-task continuity; no imported authority.
use super::{budget::Work, error, native, CpuTopology};
use crate::{ErrorKind as K, Limits, OperationError, Stage as S};
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags, StatxFlags};
use std::{cell::Cell, marker::PhantomData, os::fd::OwnedFd, rc::Rc};
const DIR: u16 = 0x4000;
const REG: u16 = 0x8000;
const LINK: u16 = 0xa000;
const CHILD: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_XDEV)
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    major: u32,
    minor: u32,
    ino: u64,
    mount: u64,
    kind: u16,
}
fn traversal_errno(e: rustix::io::Errno, stage: S, prior: bool) -> OperationError {
    let n = e.raw_os_error();
    if n == 18 || n == 40 {
        return OperationError::new(
            if prior { K::Changed } else { K::Unsupported },
            stage,
            Some(n),
            None,
        );
    }
    native::os_error(n, stage)
}
fn errno(e: rustix::io::Errno, stage: S, _prior: bool) -> OperationError {
    native::os_error(e.raw_os_error(), stage)
}
fn identity(fd: &OwnedFd, work: &mut Work, prior: bool) -> Result<Identity, OperationError> {
    work.charge(1, S::Admission)?;
    identity_unmetered(fd, prior)
}
fn identity_unmetered(fd: &OwnedFd, prior: bool) -> Result<Identity, OperationError> {
    let mask = StatxFlags::TYPE | StatxFlags::INO | StatxFlags::MNT_ID;
    let x =
        fs::statx(fd, "", AtFlags::EMPTY_PATH, mask).map_err(|e| errno(e, S::Admission, prior))?;
    if !StatxFlags::from_bits_retain(x.stx_mask).contains(mask) || x.stx_mnt_id == 0 {
        return Err(error(K::Unsupported, S::Admission));
    }
    Ok(Identity {
        major: x.stx_dev_major,
        minor: x.stx_dev_minor,
        ino: x.stx_ino,
        mount: x.stx_mnt_id,
        kind: x.stx_mode & 0xf000,
    })
}
fn same_fs(a: Identity, b: Identity) -> bool {
    a.major == b.major && a.minor == b.minor && a.mount == b.mount
}
fn root(
    path: &str,
    magic: i64,
    work: &mut Work,
    prior: bool,
) -> Result<(OwnedFd, Identity), OperationError> {
    work.charge(1, S::Admission)?;
    let fd = fs::openat2(
        fs::CWD,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| traversal_errno(e, S::Admission, prior))?;
    work.charge(1, S::Admission)?;
    let f = fs::fstatfs(&fd).map_err(|e| errno(e, S::Admission, prior))?;
    let id = identity(&fd, work, prior)?;
    if f.f_type as i64 != magic || id.kind != DIR || id.ino != 1 {
        return Err(error(
            if prior { K::Changed } else { K::Unsupported },
            S::Admission,
        ));
    }
    Ok((fd, id))
}
fn child(
    root: &OwnedFd,
    path: &str,
    flags: OFlags,
    root_id: Identity,
    kind: u16,
    work: &mut Work,
    prior: bool,
) -> Result<(OwnedFd, Identity), OperationError> {
    work.charge(1, S::Admission)?;
    let fd = fs::openat2(root, path, flags | OFlags::CLOEXEC, Mode::empty(), CHILD)
        .map_err(|e| traversal_errno(e, S::Admission, prior))?;
    let id = identity(&fd, work, prior)?;
    if id.kind != kind || !same_fs(root_id, id) {
        return Err(error(
            if prior { K::Changed } else { K::Unsupported },
            S::Admission,
        ));
    }
    Ok((fd, id))
}
fn text(fd: &OwnedFd, work: &mut Work) -> Result<([u8; 64], usize), OperationError> {
    work.charge(64, S::Read)?;
    let mut out = [0; 64];
    work.charge(1, S::Read)?;
    work.charge(64, S::Read)?;
    let n = fs::readlinkat_raw(fd, "", out.as_mut_slice()).map_err(|e| errno(e, S::Read, false))?;
    Ok((out, n))
}
fn task_path(bytes: &[u8]) -> Result<&str, OperationError> {
    let s = std::str::from_utf8(bytes).map_err(|_| error(K::Malformed, S::Admission))?;
    let mut p = s.split('/');
    let tgid = p.next().unwrap_or_default();
    let task = p.next();
    let tid = p.next().unwrap_or_default();
    let valid = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && s.parse::<u32>().is_ok_and(|n| n > 0)
    };
    if task != Some("task") || p.next().is_some() || !valid(tgid) || !valid(tid) {
        return Err(error(K::Malformed, S::Admission));
    }
    Ok(s)
}
fn read_topology(
    fd: &OwnedFd,
    limits: &Limits,
    existing: usize,
    work: &mut Work,
) -> Result<CpuTopology, OperationError> {
    work.charge(4096, S::Read)?;
    let mut out = [0; 4096];
    let mut used = 0usize;
    loop {
        if used >= 4095 {
            return Err(error(K::LimitExceeded, S::Read));
        }
        let requested = out.len() - used;
        work.charge(1, S::Read)?;
        work.charge(requested, S::Read)?;
        let n = rustix::io::pread(fd, &mut out[used..], used as u64)
            .map_err(|e| errno(e, S::Read, false))?;
        if n > requested {
            return Err(error(K::Backend, S::Read));
        }
        if n == 0 {
            break;
        }
        used = used
            .checked_add(n)
            .ok_or_else(|| error(K::Overflow, S::Read))?;
    }
    if used == 0 || out[used - 1] != b'\n' {
        return Err(error(K::Malformed, S::Read));
    }
    if used > limits.input_bytes {
        return Err(error(K::LimitExceeded, S::Read));
    }
    CpuTopology::parse_budget(
        &out[..used],
        65535,
        65536,
        limits.retained_bytes,
        existing,
        work,
    )
}
fn online(
    root: &OwnedFd,
    id: Identity,
    possible: &CpuTopology,
    limits: &Limits,
    existing: usize,
    work: &mut Work,
    prior: bool,
) -> Result<(), OperationError> {
    let (fd, _) = child(
        root,
        "devices/system/cpu/online",
        OFlags::RDONLY,
        id,
        REG,
        work,
        prior,
    )?;
    let online = read_topology(&fd, limits, existing, work)?;
    work.charge(
        possible
            .count()
            .checked_add(online.count())
            .ok_or_else(|| error(K::Overflow, S::Read))?,
        S::Read,
    )?;
    let mut i = 0;
    for n in online.ids() {
        while i < possible.count() && possible.ids()[i] < *n {
            i += 1;
        }
        if possible.ids().get(i) != Some(n) {
            return Err(error(
                if prior { K::Changed } else { K::Incompatible },
                S::Read,
            ));
        }
    }
    Ok(())
}
/// Owns authentic kernel sources and the original task; descriptive snapshots
/// cannot construct this owner. Failed revalidation is permanently sticky.
pub struct LiveCpuTopology {
    snapshot: CpuTopology,
    limits: Limits,
    _sys: OwnedFd,
    _proc: OwnedFd,
    possible: OwnedFd,
    task: OwnedFd,
    thread: OwnedFd,
    sys_id: Identity,
    proc_id: Identity,
    possible_id: Identity,
    task_id: Identity,
    thread_id: Identity,
    pid: u32,
    tid: u32,
    saved: [u8; 64],
    saved_len: usize,
    invalid: Cell<bool>,
    _local: PhantomData<Rc<()>>,
}
impl LiveCpuTopology {
    pub fn acquire(limits: &Limits) -> Result<Self, OperationError> {
        Self::acquire_work(limits, &mut Work::new(limits.work_steps))
    }
    pub(super) fn acquire_work(limits: &Limits, work: &mut Work) -> Result<Self, OperationError> {
        if limits.input_bytes < 4096 {
            return Err(error(K::LimitExceeded, S::Admission));
        }
        #[cfg(test)]
        QUERIES.with(|n| n.set(n.get() + 1));
        work.charge(1, S::Admission)?;
        let pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
        work.charge(1, S::Admission)?;
        let tid = rustix::thread::gettid().as_raw_nonzero().get() as u32;
        let (sys, sys_id) = root("/sys", 0x62656572, work, false)?;
        let (proc, proc_id) = root("/proc", 0x9fa0, work, false)?;
        let (possible, possible_id) = child(
            &sys,
            "devices/system/cpu/possible",
            OFlags::RDONLY,
            sys_id,
            REG,
            work,
            false,
        )?;
        let (thread, thread_id) = child(
            &proc,
            "thread-self",
            OFlags::PATH | OFlags::NOFOLLOW,
            proc_id,
            LINK,
            work,
            false,
        )?;
        let (current, n) = text(&thread, work)?;
        if n == 64 {
            return Err(error(K::LimitExceeded, S::Read));
        }
        let path = task_path(&current[..n])?;
        let (task, task_id) = child(
            &proc,
            path,
            OFlags::PATH | OFlags::DIRECTORY,
            proc_id,
            DIR,
            work,
            false,
        )?;
        work.charge(64, S::Admission)?;
        let mut saved = [0; 64];
        work.charge(n, S::Admission)?;
        saved[..n].copy_from_slice(&current[..n]);
        let snapshot = read_topology(&possible, limits, 0, work)?;
        online(
            &sys,
            sys_id,
            &snapshot,
            limits,
            snapshot.retained(),
            work,
            false,
        )?;
        let owner = Self {
            snapshot,
            limits: *limits,
            _sys: sys,
            _proc: proc,
            possible,
            task,
            thread,
            sys_id,
            proc_id,
            possible_id,
            task_id,
            thread_id,
            pid,
            tid,
            saved,
            saved_len: n,
            invalid: Cell::new(false),
            _local: PhantomData,
        };
        owner.check(work, owner.snapshot.retained(), false)?;
        Ok(owner)
    }
    pub fn snapshot(&self) -> &CpuTopology {
        &self.snapshot
    }
    pub(super) fn retained(&self) -> usize {
        self.snapshot.retained()
    }
    pub(super) fn usable(&self) -> Result<(), OperationError> {
        if self.invalid.get() {
            Err(error(K::Poisoned, S::Admission))
        } else {
            Ok(())
        }
    }
    pub fn revalidate(&self) -> Result<(), OperationError> {
        self.revalidate_work(&mut Work::new(self.limits.work_steps), self.retained())
    }
    pub(super) fn revalidate_work(
        &self,
        work: &mut Work,
        existing: usize,
    ) -> Result<(), OperationError> {
        #[cfg(test)]
        QUERIES.with(|n| n.set(n.get() + 1));
        run_revalidation(&self.invalid, || self.check(work, existing, true))
    }
    fn check(&self, work: &mut Work, existing: usize, prior: bool) -> Result<(), OperationError> {
        work.charge(1, S::Admission)?;
        let pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
        work.charge(1, S::Admission)?;
        let tid = rustix::thread::gettid().as_raw_nonzero().get() as u32;
        if pid != self.pid || tid != self.tid {
            return Err(error(K::Changed, S::Admission));
        }
        {
            let (sys, id) = root("/sys", 0x62656572, work, prior)?;
            if id != self.sys_id {
                return Err(error(K::Changed, S::Read));
            }
            let (fresh, identity) = child(
                &sys,
                "devices/system/cpu/possible",
                OFlags::RDONLY,
                id,
                REG,
                work,
                prior,
            )?;
            if identity != self.possible_id {
                return Err(error(K::Changed, S::Read));
            }
            drop(fresh);
            let current = read_topology(&self.possible, &self.limits, existing, work)?;
            work.charge(current.source.len(), S::Read)?;
            if current.source != self.snapshot.source {
                return Err(error(K::Changed, S::Read));
            }
            drop(current);
            online(
                &sys,
                id,
                &self.snapshot,
                &self.limits,
                existing,
                work,
                prior,
            )?;
        }
        {
            let (proc, id) = root("/proc", 0x9fa0, work, prior)?;
            if id != self.proc_id {
                return Err(error(K::Changed, S::Read));
            }
            let (thread, identity) = child(
                &proc,
                "thread-self",
                OFlags::PATH | OFlags::NOFOLLOW,
                id,
                LINK,
                work,
                prior,
            )?;
            if identity != self.thread_id {
                return Err(error(K::Changed, S::Admission));
            }
            let (current, n) = text(&thread, work)?;
            if n == 64 {
                return Err(error(K::Changed, S::Admission));
            }
            let path = task_path(&current[..n])?;
            let (task, identity) = child(
                &proc,
                path,
                OFlags::PATH | OFlags::DIRECTORY,
                id,
                DIR,
                work,
                prior,
            )?;
            if identity != self.task_id {
                return Err(error(K::Changed, S::Admission));
            }
            drop(task);
        }
        // All other validation temporaries are closed before original-anchor probe.
        let (current, n) = text(&self.thread, work)?;
        task_text_equal(&self.saved[..self.saved_len], &current[..n], work)?;
        probe(&self.task, self.proc_id, work, prior)
    }
}
fn run_revalidation(
    invalid: &Cell<bool>,
    check: impl FnOnce() -> Result<(), OperationError>,
) -> Result<(), OperationError> {
    if invalid.get() {
        return Err(error(K::Poisoned, S::Admission));
    }
    let result = check();
    if result.is_err() {
        invalid.set(true);
    }
    result
}
fn task_text_equal(saved: &[u8], current: &[u8], work: &mut Work) -> Result<(), OperationError> {
    work.charge(current.len(), S::Admission)?;
    if current != saved {
        return Err(error(K::Changed, S::Admission));
    }
    Ok(())
}
// A narrow private probe seam, with the same effect order in model and native
// execution. Model probes never construct LiveCpuTopology or a map-copy owner.
trait ProbeIo {
    type File;
    fn open(&self) -> Result<Self::File, OperationError>;
    fn stat(&self, fd: &Self::File) -> Result<Identity, OperationError>;
    fn read(&self, fd: &Self::File, byte: &mut [u8; 1]) -> Result<usize, OperationError>;
}
struct OriginalProbe<'a> {
    task: &'a OwnedFd,
    prior: bool,
}
impl ProbeIo for OriginalProbe<'_> {
    type File = OwnedFd;
    fn open(&self) -> Result<OwnedFd, OperationError> {
        #[cfg(test)]
        STAT_OPENS.with(|n| n.set(n.get() + 1));
        fs::openat2(
            self.task,
            "stat",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            CHILD,
        )
        .map_err(|e| traversal_errno(e, S::Admission, self.prior))
    }
    fn stat(&self, fd: &OwnedFd) -> Result<Identity, OperationError> {
        identity_unmetered(fd, self.prior)
    }
    fn read(&self, fd: &OwnedFd, byte: &mut [u8; 1]) -> Result<usize, OperationError> {
        rustix::io::pread(fd, byte.as_mut_slice(), 0).map_err(|e| errno(e, S::Read, self.prior))
    }
}
fn probe_io(
    io: &impl ProbeIo,
    proc_id: Identity,
    work: &mut Work,
    prior: bool,
) -> Result<(), OperationError> {
    let loss = |e: OperationError| {
        if prior && matches!(e.raw_os_error(), Some(2 | 3)) {
            OperationError::new(K::Changed, S::Admission, e.raw_os_error(), None)
        } else {
            e
        }
    };
    work.charge(1, S::Admission)?;
    let fd = io.open().map_err(loss)?;
    work.charge(1, S::Admission)?;
    let id = io.stat(&fd).map_err(loss)?;
    if id.kind != REG || !same_fs(id, proc_id) {
        return Err(error(
            if prior { K::Changed } else { K::Unsupported },
            S::Admission,
        ));
    }
    work.charge(1, S::Read)?;
    let mut byte = [0u8; 1];
    work.charge(1, S::Read)?;
    work.charge(1, S::Read)?;
    match io.read(&fd, &mut byte).map_err(loss)? {
        1 => Ok(()),
        0 => Err(error(
            if prior { K::Changed } else { K::Malformed },
            if prior { S::Admission } else { S::Read },
        )),
        _ => Err(error(K::Backend, S::Read)),
    }
}
fn probe(
    task: &OwnedFd,
    proc_id: Identity,
    work: &mut Work,
    prior: bool,
) -> Result<(), OperationError> {
    probe_io(&OriginalProbe { task, prior }, proc_id, work, prior)
}
#[cfg(test)]
#[path = "../../tests/support/task_models.rs"]
mod tests;

#[cfg(test)]
thread_local! {pub(super) static QUERIES:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}

#[cfg(test)]
thread_local! {static STAT_OPENS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}
