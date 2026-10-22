// SPDX-License-Identifier: Apache-2.0
// ADAPT P open_regular/type gate and O PinnedFile/opened-file stat/retention.
// NEW retained resolver, original-owner adoption and bounded error adapters.
use crate::{
    error::{
        CleanupDisposition, DescriptorFlagEffect, EffectSummary, LinuxError, Reason,
        ResourceCharges, Stage,
    },
    identity::{StatFileKey, StatObservation},
};
use rustix::{
    fs::{self, FileType, Mode, OFlags},
    io::{self, Errno, FdFlags},
    pipe::{pipe_with, PipeFlags},
};
use std::{
    ffi::CStr,
    fmt,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};

/// Kernel symlink resolution, with optional refusal of the final symlink only.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SymlinkPolicy {
    Follow,
    RejectFinal,
}
/// A validated retained proc directory for the creating process's shared FD table.
///
/// Ordinary threads sharing that table are supported. Recreate after a context
/// transition. Fork-without-exec reuse, private FD tables, main-thread proc entry
/// loss and coherent hostile mount/descriptor substitution are unsupported.
/// Retention continues across ordinary ambient `/proc` replacement. No universal
/// namespace attestation or hard syscall/Drop latency bound is provided.
pub struct ProcFdResolver {
    directory: OwnedFd,
    creating_pid: u32,
}
/// Readable regular-file authority. Share it through `Arc`; `AsFd` borrows it.
///
/// This acquisition increment neither reads nor maps target data. An observation
/// is not content immutability or mapping proof. Deliberate closure, flag changes
/// or other mutating FD use through a borrow invalidates affected guarantees.
pub struct HeldFile {
    file: File,
}
/// Refusal that returns exactly the submitted File, including its original FD.
pub struct AdoptFileError {
    pub error: LinuxError,
    pub file: File,
}
impl fmt::Debug for ProcFdResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcFdResolver")
    }
}
impl fmt::Debug for HeldFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HeldFile")
    }
}
impl fmt::Debug for AdoptFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AdoptFileError {{ error: {} }}", self.error)
    }
}
impl fmt::Display for AdoptFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for AdoptFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
impl AsFd for HeldFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Step {
    RootOpen,
    RootFs,
    SelfLink,
    SelfOpen,
    FdOpen,
    FdFs,
    SelfLinkAgain,
    Pipe,
    PipeStat,
    CheckOpen,
    CheckStat,
    PathOpen,
    PathStat,
    Reopen,
    ReopenStat,
    Stat,
    AdoptStat,
    GetFl,
    GetFd,
    SetFd,
    VerifyFd,
}
#[derive(Default)]
struct Ops {
    attempted: u64,
    completed: u64,
    syscalls: u64,
    acquired: u64,
    current: u64,
    peak: u64,
    #[cfg(test)]
    hooks: Hooks,
}
impl Ops {
    fn pid(&mut self) -> u32 {
        self.attempted += 1;
        self.completed += 1;
        std::process::id()
    }
    fn call<T>(&mut self, step: Step, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.attempted += 1;
        self.syscalls += 1;
        #[cfg(test)]
        {
            self.hooks.trace.push(step);
            if let Some((which, errno)) = self.hooks.fail {
                if which == step {
                    return Err(errno);
                }
            }
            if step == Step::VerifyFd {
                if let Some(e) = self.hooks.verify_error {
                    return Err(e);
                }
            }
        }
        let result = f();
        #[cfg(test)]
        if step == Step::SetFd && result.is_ok() {
            if let Some(e) = self.hooks.set_then_error {
                return Err(e);
            }
        }
        if result.is_ok() {
            self.completed += 1;
        }
        #[cfg(not(test))]
        let _ = step;
        result
    }
    fn gained(&mut self, fd: &OwnedFd) {
        self.acquired += 1;
        self.current += 1;
        self.peak = self.peak.max(self.current);
        #[cfg(test)]
        self.hooks.fds.push(fd.as_raw_fd());
        #[cfg(not(test))]
        let _ = fd;
    }
    fn error(
        &self,
        stage: Stage,
        reason: Reason,
        source: Option<std::io::Error>,
        flags: DescriptorFlagEffect,
    ) -> LinuxError {
        LinuxError {
            parse_line: None,
            stage,
            reason,
            source,
            effect: EffectSummary {
                attempted: self.attempted,
                completed: self.completed,
                cleanup: if self.acquired == 0 {
                    CleanupDisposition::NotNeeded
                } else {
                    CleanupDisposition::Complete
                },
                flags,
            },
            charges: ResourceCharges {
                parse: None,
                syscalls: self.syscalls,
                acquired: self.acquired,
                peak: self.peak,
                read: None,
            },
        }
    }
    fn semantic(&self, stage: Stage, reason: Reason) -> LinuxError {
        self.error(stage, reason, None, DescriptorFlagEffect::NotAttempted)
    }
    fn io(&self, stage: Stage, errno: Errno) -> LinuxError {
        self.error(
            stage,
            classify(stage, errno),
            Some(errno.into()),
            DescriptorFlagEffect::NotAttempted,
        )
    }
}
fn classify(stage: Stage, e: Errno) -> Reason {
    match e {
        Errno::ACCESS | Errno::PERM => Reason::Denied,
        Errno::NOSYS | Errno::OPNOTSUPP | Errno::MFILE | Errno::NFILE | Errno::NOMEM => {
            Reason::Unavailable
        }
        Errno::NOENT | Errno::STALE => Reason::Disappeared,
        Errno::NOTDIR | Errno::LOOP if stage == Stage::ResolveProc => Reason::WrongContext,
        Errno::NAMETOOLONG | Errno::LOOP | Errno::NOTDIR if stage == Stage::AcquirePath => {
            Reason::InvalidInput
        }
        _ => Reason::Inconclusive,
    }
}
fn key(s: &fs::Stat) -> StatFileKey {
    StatFileKey {
        device: s.st_dev as u64,
        inode: s.st_ino as u64,
    }
}
fn regular(s: &fs::Stat) -> bool {
    FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
}
fn fifo(s: &fs::Stat) -> bool {
    FileType::from_raw_mode(s.st_mode) == FileType::Fifo
}
fn decimal(mut n: u32, buf: &mut [u8; 32]) -> &CStr {
    let mut pos = 30;
    buf[31] = 0;
    loop {
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
        pos -= 1;
    }
    CStr::from_bytes_with_nul(&buf[pos..]).expect("fixed decimal")
}
fn canonical_pid(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() >= 32 || bytes[0] == b'0' {
        return None;
    }
    let mut n = 0u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(n)
}
fn self_pid(root: &OwnedFd, step: Step, ops: &mut Ops) -> Result<u32, LinuxError> {
    let mut buf = [0u8; 32];
    let n = ops
        .call(step, || fs::readlinkat_raw(root, c"self", &mut buf[..]))
        .map_err(|e| ops.io(Stage::ResolveProc, e))?;
    #[cfg(test)]
    if let Some(ref bytes) = ops.hooks.self_link {
        return canonical_pid(bytes)
            .ok_or_else(|| ops.semantic(Stage::ResolveProc, Reason::WrongContext));
    }
    canonical_pid(&buf[..n]).ok_or_else(|| ops.semantic(Stage::ResolveProc, Reason::WrongContext))
}
impl ProcFdResolver {
    pub fn open_self() -> Result<Self, LinuxError> {
        Self::open_with(&mut Ops::default())
    }
    fn open_with(ops: &mut Ops) -> Result<Self, LinuxError> {
        let pid = ops.pid();
        let dir_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        #[cfg(test)]
        let root_override = ops.hooks.root_override.take();
        #[cfg(test)]
        let root_path = root_override.as_deref().unwrap_or(Path::new("/proc"));
        #[cfg(not(test))]
        let root_path = c"/proc";
        let root = ops
            .call(Step::RootOpen, || {
                fs::open(root_path, dir_flags, Mode::empty())
            })
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        ops.gained(&root);
        let ty = ops
            .call(Step::RootFs, || fs::fstatfs(&root))
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        #[cfg(test)]
        let ty = if ops.hooks.non_proc {
            0
        } else {
            ty.f_type as i64
        };
        #[cfg(not(test))]
        let ty = ty.f_type as i64;
        if ty != 0x9fa0 {
            return Err(ops.semantic(Stage::ResolveProc, Reason::WrongContext));
        }
        if self_pid(&root, Step::SelfLink, ops)? != pid {
            return Err(ops.semantic(Stage::ResolveProc, Reason::WrongContext));
        }
        let process = ops
            .call(Step::SelfOpen, || {
                fs::openat(&root, c"self", dir_flags, Mode::empty())
            })
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        ops.gained(&process);
        let candidate = ops
            .call(Step::FdOpen, || {
                fs::openat(&process, c"fd", dir_flags | OFlags::NOFOLLOW, Mode::empty())
            })
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        ops.gained(&candidate);
        let ty = ops
            .call(Step::FdFs, || fs::fstatfs(&candidate))
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        if ty.f_type as i64 != 0x9fa0 {
            return Err(ops.semantic(Stage::ResolveProc, Reason::WrongContext));
        }
        let again = ops.pid();
        if self_pid(&root, Step::SelfLinkAgain, ops)? != pid || again != pid {
            return Err(ops.semantic(Stage::ResolveProc, Reason::WrongContext));
        }
        drop(root);
        drop(process);
        ops.current -= 2;
        // This private phase substitution only arranges real test contexts after
        // ordinary checks. It is not a production backend or an overmount test.
        #[cfg(test)]
        let candidate = if let Some(other) = ops.hooks.candidate.take() {
            drop(candidate);
            other
        } else {
            candidate
        };
        let (read, write) = ops
            .call(Step::Pipe, || pipe_with(PipeFlags::CLOEXEC))
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        ops.gained(&read);
        ops.gained(&write);
        let original = ops
            .call(Step::PipeStat, || fs::fstat(&read))
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        #[cfg(test)]
        let original = mutate_stat(original, ops.hooks.pipe_mutation);
        #[cfg(test)]
        if let Some(callback) = ops.hooks.pipe_observer.as_mut() {
            callback(read.as_raw_fd(), original);
        }
        if !fifo(&original) {
            return Err(ops.semantic(Stage::ResolveProc, Reason::WrongContext));
        }
        let mut buf = [0; 32];
        let name = decimal(read.as_raw_fd() as u32, &mut buf);
        let check = ops
            .call(Step::CheckOpen, || {
                fs::openat(
                    &candidate,
                    name,
                    OFlags::PATH | OFlags::CLOEXEC,
                    Mode::empty(),
                )
            })
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        ops.gained(&check);
        let actual = ops
            .call(Step::CheckStat, || fs::fstat(&check))
            .map_err(|e| ops.io(Stage::ResolveProc, e))?;
        #[cfg(test)]
        let actual = mutate_stat(actual, ops.hooks.check_mutation);
        if !fifo(&actual) || key(&original) != key(&actual) {
            return Err(ops.semantic(Stage::ResolveProc, Reason::WrongContext));
        }
        drop(check);
        drop(read);
        drop(write);
        ops.current -= 3;
        Ok(Self {
            directory: candidate,
            creating_pid: pid,
        })
    }
}
impl HeldFile {
    pub fn open(
        path: &Path,
        resolver: &ProcFdResolver,
        symlinks: SymlinkPolicy,
    ) -> Result<Self, LinuxError> {
        Self::open_with(path, resolver, symlinks, &mut Ops::default())
    }
    fn open_with(
        path: &Path,
        resolver: &ProcFdResolver,
        symlinks: SymlinkPolicy,
        ops: &mut Ops,
    ) -> Result<Self, LinuxError> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > 4095 || bytes.contains(&0) {
            return Err(ops.semantic(Stage::AcquirePath, Reason::InvalidInput));
        }
        let mut storage = [0u8; 4096];
        storage[..bytes.len()].copy_from_slice(bytes);
        let path = CStr::from_bytes_with_nul(&storage[..bytes.len() + 1]).expect("admitted path");
        if ops.pid() != resolver.creating_pid {
            return Err(ops.semantic(Stage::ResolveProc, Reason::WrongContext));
        }
        let mut flags = OFlags::PATH | OFlags::CLOEXEC;
        if symlinks == SymlinkPolicy::RejectFinal {
            flags |= OFlags::NOFOLLOW;
        }
        #[cfg(test)]
        ops.hooks.path_flags.push(flags);
        let pin = ops
            .call(Step::PathOpen, || fs::open(path, flags, Mode::empty()))
            .map_err(|e| ops.io(Stage::AcquirePath, e))?;
        ops.gained(&pin);
        let original = ops
            .call(Step::PathStat, || fs::fstat(&pin))
            .map_err(|e| ops.io(Stage::ValidateFile, e))?;
        if !regular(&original) {
            return Err(ops.semantic(Stage::ValidateFile, Reason::NonRegular));
        }
        #[cfg(test)]
        if let Some(callback) = ops.hooks.after_pin.as_mut() {
            callback(pin.as_raw_fd());
        }
        let mut buf = [0; 32];
        let name = decimal(pin.as_raw_fd() as u32, &mut buf);
        let reopened = ops
            .call(Step::Reopen, || {
                fs::openat(
                    &resolver.directory,
                    name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
            })
            .map_err(|e| ops.io(Stage::ReopenHeld, e))?;
        ops.gained(&reopened);
        let actual = ops
            .call(Step::ReopenStat, || fs::fstat(&reopened))
            .map_err(|e| ops.io(Stage::ReopenHeld, e))?;
        #[cfg(test)]
        let actual = mutate_stat(actual, ops.hooks.reopen_mutation);
        if !regular(&actual) || key(&original) != key(&actual) {
            return Err(ops.semantic(Stage::ReopenHeld, Reason::ChangedSource));
        }
        drop(pin);
        ops.current -= 1;
        Ok(Self {
            file: reopened.into(),
        })
    }
    /// Adopt readable regular authority without procfs. No dup, seek or status
    /// mutation occurs. An incoming descriptor's earlier inheritance window is
    /// not retroactively eliminated by setting CLOEXEC here.
    pub fn from_file(file: File) -> Result<Self, AdoptFileError> {
        Self::adopt_with(file, &mut Ops::default())
    }
    fn adopt_with(file: File, ops: &mut Ops) -> Result<Self, AdoptFileError> {
        let validate = || -> Result<(), LinuxError> {
            let s = ops
                .call(Step::AdoptStat, || fs::fstat(&file))
                .map_err(|e| ops.io(Stage::ValidateFile, e))?;
            if !regular(&s) {
                return Err(ops.semantic(Stage::ValidateFile, Reason::NonRegular));
            }
            let mode = ops
                .call(Step::GetFl, || fs::fcntl_getfl(&file))
                .map_err(|e| ops.io(Stage::ValidateFile, e))?;
            let access = mode & OFlags::ACCMODE;
            if mode.contains(OFlags::PATH) || (access != OFlags::RDONLY && access != OFlags::RDWR) {
                return Err(ops.semantic(Stage::ValidateFile, Reason::Unreadable));
            }
            let old = ops
                .call(Step::GetFd, || io::fcntl_getfd(&file))
                .map_err(|e| ops.io(Stage::ValidateFile, e))?;
            if !old.contains(FdFlags::CLOEXEC) {
                if let Err(primary) = ops.call(Step::SetFd, || {
                    io::fcntl_setfd(&file, old | FdFlags::CLOEXEC)
                }) {
                    let observed = ops.call(Step::VerifyFd, || io::fcntl_getfd(&file));
                    #[cfg(test)]
                    let observed = ops.hooks.verify_flags.map(Ok).unwrap_or(observed);
                    let effect = match observed {
                        Ok(now) if now == old => DescriptorFlagEffect::Unchanged,
                        Ok(now) if now == old | FdFlags::CLOEXEC => {
                            DescriptorFlagEffect::CloexecSet
                        }
                        _ => DescriptorFlagEffect::Unknown,
                    };
                    return Err(ops.error(
                        Stage::ValidateFile,
                        classify(Stage::ValidateFile, primary),
                        Some(primary.into()),
                        effect,
                    ));
                }
            }
            Ok(())
        };
        let mut validate = validate;
        match validate() {
            Ok(()) => Ok(Self { file }),
            Err(error) => Err(AdoptFileError { error, file }),
        }
    }
    pub fn stat(&self) -> Result<StatObservation, LinuxError> {
        self.stat_with(&mut Ops::default())
    }
    fn stat_with(&self, ops: &mut Ops) -> Result<StatObservation, LinuxError> {
        let stat = ops
            .call(Step::Stat, || fs::fstat(&self.file))
            .map_err(|e| ops.io(Stage::ValidateFile, e))?;
        #[cfg(test)]
        let stat = if ops.hooks.malformed_stat {
            let mut invalid = stat;
            invalid.st_size = -1;
            invalid
        } else {
            stat
        };
        StatObservation::from_stat(&stat)
            .ok_or_else(|| ops.semantic(Stage::ValidateFile, Reason::Malformed))
    }
}
#[cfg(test)]
#[derive(Default)]
struct Hooks {
    fail: Option<(Step, Errno)>,
    verify_error: Option<Errno>,
    set_then_error: Option<Errno>,
    candidate: Option<OwnedFd>,
    self_link: Option<Vec<u8>>,
    non_proc: bool,
    root_override: Option<std::path::PathBuf>,
    check_mutation: u8,
    pipe_mutation: u8,
    malformed_stat: bool,
    verify_flags: Option<FdFlags>,
    reopen_mutation: u8,
    after_pin: Option<Box<dyn FnMut(i32)>>,
    pipe_observer: Option<Box<dyn FnMut(i32, fs::Stat)>>,
    trace: Vec<Step>,
    fds: Vec<i32>,
    path_flags: Vec<OFlags>,
}
#[cfg(test)]
fn mutate_stat(mut s: fs::Stat, mutation: u8) -> fs::Stat {
    match mutation {
        1 => s.st_dev ^= 1,
        2 => s.st_ino ^= 1,
        3 => s.st_mode = FileType::RegularFile.as_raw_mode(),
        4 => s.st_mode = FileType::Fifo.as_raw_mode(),
        _ => {}
    }
    s
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs as stdfs,
        os::unix::fs::{FileExt, MetadataExt},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Barrier,
        },
    };
    // Tests share one real process FD table. Serialize these fixtures so a freed
    // number cannot be recycled by another test before its exact close oracle.
    // This mutex coordinates fixtures only; syscall seams remain per-invocation.
    use crate::FD_TABLE;
    static SEQ: AtomicU64 = AtomicU64::new(0);
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "lx02-unit-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            stdfs::create_dir(&p).unwrap();
            Self(p)
        }
        fn write(&self, n: &str, b: &[u8]) -> std::path::PathBuf {
            let p = self.0.join(n);
            stdfs::write(&p, b).unwrap();
            p
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            stdfs::remove_dir_all(&self.0).unwrap();
        }
    }
    struct ReapChild(std::process::Child);
    impl std::ops::Deref for ReapChild {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl std::ops::DerefMut for ReapChild {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl Drop for ReapChild {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }
    fn slot_flags(fd: i32) -> std::io::Result<i32> {
        unsafe extern "C" {
            fn fcntl(fd: std::ffi::c_int, cmd: std::ffi::c_int, ...) -> std::ffi::c_int;
        }
        // Raw F_GETFD explicitly accepts invalid slots; no invalid BorrowedFd.
        let result = unsafe { fcntl(fd, 1) };
        if result == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }
    fn assert_closed(fds: &[i32]) {
        for &fd in fds {
            assert_eq!(
                slot_flags(fd).unwrap_err().raw_os_error(),
                Some(9),
                "temporary FD {fd} survived"
            );
        }
    }
    fn check_error(e: &LinuxError, stage: Stage, reason: Reason, errno: Option<i32>) {
        assert_eq!(
            (
                e.stage(),
                e.reason(),
                e.source().and_then(std::io::Error::raw_os_error)
            ),
            (stage, reason, errno)
        );
        assert_eq!(e.effect().target_mappings_created(), 0);
        assert_eq!(e.effect().target_mappings_retired(), 0);
    }
    #[test]
    fn success_counts_are_exact() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let mut r = Ops::default();
        let resolver = ProcFdResolver::open_with(&mut r).unwrap();
        assert_eq!(
            (
                r.syscalls,
                r.attempted,
                r.completed,
                r.acquired,
                r.peak,
                r.current
            ),
            (11, 13, 13, 6, 4, 1)
        );
        assert_eq!(r.hooks.trace.len(), 11);
        let fixture = Fixture::new();
        let p = fixture.write("a", b"A");
        let mut o = Ops::default();
        let h = HeldFile::open_with(&p, &resolver, SymlinkPolicy::Follow, &mut o).unwrap();
        assert_eq!(
            (
                o.syscalls,
                o.attempted,
                o.completed,
                o.acquired,
                o.peak,
                o.current
            ),
            (4, 5, 5, 2, 2, 1)
        );
        let mut stat = Ops::default();
        h.stat_with(&mut stat).unwrap();
        assert_eq!(
            (
                stat.syscalls,
                stat.attempted,
                stat.completed,
                stat.acquired,
                stat.peak
            ),
            (1, 1, 1, 0, 0)
        );
        for cloexec in [false, true] {
            let file = File::open(&p).unwrap();
            if !cloexec {
                io::fcntl_setfd(&file, FdFlags::empty()).unwrap();
            }
            let mut a = Ops::default();
            HeldFile::adopt_with(file, &mut a).unwrap();
            let n = if cloexec { 3 } else { 4 };
            assert_eq!(
                (a.syscalls, a.attempted, a.completed, a.acquired, a.peak),
                (n, n, n, 0, 0)
            );
        }
    }
    #[test]
    fn resolver_failure_prefixes_charge_and_release_exact_owners() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let steps = [
            Step::RootOpen,
            Step::RootFs,
            Step::SelfLink,
            Step::SelfOpen,
            Step::FdOpen,
            Step::FdFs,
            Step::SelfLinkAgain,
            Step::Pipe,
            Step::PipeStat,
            Step::CheckOpen,
            Step::CheckStat,
        ];
        let acquired = [0, 1, 1, 1, 2, 3, 3, 3, 5, 5, 6];
        let peak = [0, 1, 1, 1, 2, 3, 3, 3, 3, 3, 4];
        for (i, step) in steps.into_iter().enumerate() {
            let mut o = Ops::default();
            o.hooks.fail = Some((step, Errno::IO));
            let e = ProcFdResolver::open_with(&mut o).unwrap_err();
            check_error(&e, Stage::ResolveProc, Reason::Inconclusive, Some(5));
            let pids = if i >= 6 { 2 } else { 1 };
            assert_eq!(
                (
                    e.charges().syscall_attempts(),
                    e.effect().attempted_operations(),
                    e.effect().completed_operations(),
                    e.charges().fd_acquisitions(),
                    e.charges().peak_new_fds()
                ),
                (
                    i as u64 + 1,
                    i as u64 + 1 + pids,
                    i as u64 + pids,
                    acquired[i],
                    peak[i]
                ),
                "{step:?}"
            );
            assert_eq!(
                e.effect().cleanup(),
                if acquired[i] == 0 {
                    CleanupDisposition::NotNeeded
                } else {
                    CleanupDisposition::Complete
                }
            );
            assert_closed(&o.hooks.fds);
        }
    }
    #[test]
    fn open_failure_prefixes_preserve_primary_errno_without_retry() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let f = Fixture::new();
        let p = f.write("a", b"A");
        let r = ProcFdResolver::open_self().unwrap();
        for (i, (step, stage)) in [
            (Step::PathOpen, Stage::AcquirePath),
            (Step::PathStat, Stage::ValidateFile),
            (Step::Reopen, Stage::ReopenHeld),
            (Step::ReopenStat, Stage::ReopenHeld),
        ]
        .into_iter()
        .enumerate()
        {
            let mut o = Ops::default();
            o.hooks.fail = Some((step, Errno::NOENT));
            let e = HeldFile::open_with(&p, &r, SymlinkPolicy::Follow, &mut o)
                .expect_err("first error must be retained without retry");
            check_error(&e, stage, Reason::Disappeared, Some(2));
            let n = [0, 1, 1, 2][i];
            assert_eq!(
                (
                    e.charges().syscall_attempts(),
                    e.effect().attempted_operations(),
                    e.effect().completed_operations(),
                    e.charges().fd_acquisitions(),
                    e.charges().peak_new_fds()
                ),
                (i as u64 + 1, i as u64 + 2, i as u64 + 1, n, n)
            );
            assert_eq!(o.hooks.trace.iter().filter(|s| **s == step).count(), 1);
            assert_closed(&o.hooks.fds);
        }
    }
    #[test]
    fn resolver_denial_never_reopens_path() {
        let _fd_table = FD_TABLE.lock().unwrap();
        for (errno, reason) in [
            (Errno::ACCESS, Reason::Denied),
            (Errno::NOENT, Reason::Disappeared),
            (Errno::MFILE, Reason::Unavailable),
        ] {
            let f = Fixture::new();
            let path = f.write("live", b"original-A");
            let b = f.write("other", b"accessible-B");
            let original = File::open(&path).unwrap();
            let other = File::open(&b).unwrap();
            let a_key = key(&fs::fstat(&original).unwrap());
            let b_key = key(&fs::fstat(&other).unwrap());
            assert_ne!(a_key, b_key);
            let moved = f.0.join("saved-A");
            let barrier = Arc::new(Barrier::new(2));
            let twin = Arc::clone(&barrier);
            let live = path.clone();
            let worker = std::thread::spawn(move || {
                twin.wait();
                stdfs::rename(&live, &moved).unwrap();
                stdfs::rename(&b, &live).unwrap();
                let current = File::open(&live).unwrap();
                assert_eq!(
                    key(&fs::fstat(&current).unwrap()),
                    b_key,
                    "B must be accessible before failed reopen"
                );
                let mut bytes = [0; 12];
                current.read_exact_at(&mut bytes, 0).unwrap();
                assert_eq!(&bytes, b"accessible-B");
                twin.wait();
            });
            let resolver = ProcFdResolver::open_self().unwrap();
            let mut o = Ops::default();
            o.hooks.fail = Some((Step::Reopen, errno));
            o.hooks.after_pin = Some(Box::new(move |_| {
                barrier.wait();
                barrier.wait();
            }));
            let result = HeldFile::open_with(&path, &resolver, SymlinkPolicy::Follow, &mut o);
            worker.join().unwrap();
            if let Ok(held) = &result {
                assert_eq!(
                    held.stat().unwrap().key(),
                    a_key,
                    "error path must retain A and never fall back to accessible B"
                );
            }
            let error = result
                .expect_err("retained reopen error must be returned without pathname fallback");
            check_error(
                &error,
                Stage::ReopenHeld,
                reason,
                Some(errno.raw_os_error()),
            );
            assert_eq!(
                o.hooks.trace,
                [Step::PathOpen, Step::PathStat, Step::Reopen]
            );
            assert_eq!(
                (o.syscalls, o.attempted, o.completed, o.acquired, o.peak),
                (3, 4, 3, 1, 1)
            );
            assert_closed(&o.hooks.fds);
        }
    }
    #[test]
    fn fifo_trace_proves_no_data_open() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let f = Fixture::new();
        let p = f.0.join("fifo");
        fs::mknodat(fs::CWD, &p, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        let r = ProcFdResolver::open_self().unwrap();
        let mut o = Ops::default();
        let e = HeldFile::open_with(&p, &r, SymlinkPolicy::Follow, &mut o).unwrap_err();
        check_error(&e, Stage::ValidateFile, Reason::NonRegular, None);
        assert_eq!(o.hooks.trace, [Step::PathOpen, Step::PathStat]);
        assert_eq!(
            o.hooks.path_flags,
            [OFlags::PATH | OFlags::CLOEXEC],
            "no FIFO data open"
        );
        assert_eq!(o.completed, 3);
        assert_closed(&o.hooks.fds);
    }
    #[test]
    fn open_holds_a_through_a_b_a_and_unlink() {
        let _fd_table = FD_TABLE.lock().unwrap();
        for unlink in [false, true] {
            let f = Fixture::new();
            let p = f.write("live", b"original-A");
            let b = f.write("other", b"replacement-B");
            let oracle = File::open(&p).unwrap();
            let other = File::open(&b).unwrap();
            let akey = (
                oracle.metadata().unwrap().dev(),
                oracle.metadata().unwrap().ino(),
            );
            let bkey = (
                other.metadata().unwrap().dev(),
                other.metadata().unwrap().ino(),
            );
            assert_ne!(akey, bkey);
            let barrier = Arc::new(Barrier::new(2));
            let twin = Arc::clone(&barrier);
            let path = p.clone();
            let stash = f.0.join("stash");
            let saved = stash.clone();
            let worker = std::thread::spawn(move || {
                twin.wait();
                stdfs::rename(&path, &stash).unwrap();
                stdfs::rename(&b, &path).unwrap();
                let m = stdfs::metadata(&path).unwrap();
                assert_eq!((m.dev(), m.ino()), bkey, "B installed before reopen");
                if unlink {
                    stdfs::remove_file(&stash).unwrap();
                }
                twin.wait();
            });
            let mut o = Ops::default();
            o.hooks.after_pin = Some(Box::new(move |_| {
                barrier.wait();
                barrier.wait();
            }));
            let r = ProcFdResolver::open_self().unwrap();
            let h = HeldFile::open_with(&p, &r, SymlinkPolicy::Follow, &mut o).unwrap();
            worker.join().unwrap();
            assert_eq!(
                (
                    h.stat().unwrap().key().device_raw(),
                    h.stat().unwrap().key().inode()
                ),
                akey,
                "retained A identity"
            );
            let mut payload = [0; 10];
            h.file.read_exact_at(&mut payload, 0).unwrap();
            assert_eq!(&payload, b"original-A", "retained A payload");
            if !unlink {
                stdfs::rename(saved, &p).unwrap();
                assert_eq!(
                    stdfs::metadata(&p).unwrap().ino(),
                    akey.1,
                    "completed A B A"
                );
            } else {
                stdfs::remove_file(&p).unwrap();
            }
            assert_eq!(h.stat().unwrap().key().inode(), akey.1);
        }
    }
    #[test]
    fn stat_key_and_type_mismatches_are_rejected() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let f = Fixture::new();
        let p = f.write("a", b"A");
        let r = ProcFdResolver::open_self().unwrap();
        for mutation in [1, 2, 4] {
            let mut o = Ops::default();
            o.hooks.reopen_mutation = mutation;
            let e = HeldFile::open_with(&p, &r, SymlinkPolicy::Follow, &mut o).unwrap_err();
            check_error(&e, Stage::ReopenHeld, Reason::ChangedSource, None);
            assert_eq!(e.effect().completed_operations(), 5);
            assert_closed(&o.hooks.fds);
        }
        for mutation in [1, 2, 3] {
            let mut o = Ops::default();
            o.hooks.check_mutation = mutation;
            let e = ProcFdResolver::open_with(&mut o).unwrap_err();
            check_error(&e, Stage::ResolveProc, Reason::WrongContext, None);
            assert_eq!(e.effect().completed_operations(), 13);
            assert_closed(&o.hooks.fds);
        }
    }
    #[test]
    fn malformed_self_links_and_nonproc_refuse() {
        let _fd_table = FD_TABLE.lock().unwrap();
        for bytes in [
            b"".as_slice(),
            b"0",
            b"01",
            b"+1",
            b"-1",
            b" 1",
            b"1\n",
            b"4294967296",
            b"99999999999999999999999999999999",
            b"1",
        ] {
            let mut o = Ops::default();
            o.hooks.self_link = Some(bytes.to_vec());
            let e = ProcFdResolver::open_with(&mut o).unwrap_err();
            check_error(&e, Stage::ResolveProc, Reason::WrongContext, None);
            assert_closed(&o.hooks.fds);
        }
        let mut o = Ops::default();
        o.hooks.non_proc = true;
        let e = ProcFdResolver::open_with(&mut o).unwrap_err();
        assert_eq!(o.syscalls, 2);
        check_error(&e, Stage::ResolveProc, Reason::WrongContext, None);
        assert_closed(&o.hooks.fds);
    }
    #[test]
    fn wrong_creating_pid_refuses_before_file_acquisition() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let mut r = ProcFdResolver::open_self().unwrap();
        r.creating_pid ^= 1;
        let f = Fixture::new();
        let p = f.write("a", b"A");
        let mut o = Ops::default();
        let e = HeldFile::open_with(&p, &r, SymlinkPolicy::Follow, &mut o).unwrap_err();
        check_error(&e, Stage::ResolveProc, Reason::WrongContext, None);
        assert_eq!(
            (o.attempted, o.completed, o.syscalls, o.acquired),
            (1, 1, 0, 0)
        );
    }
    #[test]
    fn pipe_fault_categories_do_not_skip_validation() {
        let _fd_table = FD_TABLE.lock().unwrap();
        for (errno, reason) in [
            (Errno::PERM, Reason::Denied),
            (Errno::ACCESS, Reason::Denied),
            (Errno::MFILE, Reason::Unavailable),
            (Errno::NFILE, Reason::Unavailable),
            (Errno::NOMEM, Reason::Unavailable),
            (Errno::NOSYS, Reason::Unavailable),
            (Errno::OPNOTSUPP, Reason::Unavailable),
            (Errno::INTR, Reason::Inconclusive),
        ] {
            let mut o = Ops::default();
            o.hooks.fail = Some((Step::Pipe, errno));
            let e = ProcFdResolver::open_with(&mut o).unwrap_err();
            check_error(&e, Stage::ResolveProc, reason, Some(errno.raw_os_error()));
            assert_eq!(o.syscalls, 8);
            assert_closed(&o.hooks.fds);
        }
    }
    #[test]
    fn adoption_failures_return_exact_input_and_effect() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let f = Fixture::new();
        let p = f.write("a", b"A");
        for step in [Step::AdoptStat, Step::GetFl, Step::GetFd, Step::SetFd] {
            let file = File::open(&p).unwrap();
            io::fcntl_setfd(&file, FdFlags::empty()).unwrap();
            let fd = file.as_raw_fd();
            let meta = file.metadata().unwrap();
            let mut o = Ops::default();
            o.hooks.fail = Some((step, Errno::IO));
            let e = HeldFile::adopt_with(file, &mut o).unwrap_err();
            assert_eq!(e.file.as_raw_fd(), fd);
            assert_eq!(e.file.metadata().unwrap().ino(), meta.ino());
            check_error(&e.error, Stage::ValidateFile, Reason::Inconclusive, Some(5));
            assert_eq!(
                e.error.effect().descriptor_flags(),
                if step == Step::SetFd {
                    DescriptorFlagEffect::Unchanged
                } else {
                    DescriptorFlagEffect::NotAttempted
                }
            );
            assert_eq!(o.acquired, 0);
            let n = match step {
                Step::AdoptStat => 1,
                Step::GetFl => 2,
                Step::GetFd => 3,
                _ => 5,
            };
            assert_eq!((o.syscalls, o.attempted, o.completed), (n, n, n - 1));
            assert_eq!(io::fcntl_getfd(&e.file).unwrap(), FdFlags::empty());
        }
    }
    #[test]
    fn real_set_effect_then_error_is_reported_and_primary_errno_survives() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let f = Fixture::new();
        let p = f.write("a", b"A");
        for verify_failed in [false, true] {
            let file = File::open(&p).unwrap();
            io::fcntl_setfd(&file, FdFlags::empty()).unwrap();
            let fd = file.as_raw_fd();
            let mut o = Ops::default();
            o.hooks.set_then_error = Some(Errno::IO);
            if verify_failed {
                o.hooks.verify_error = Some(Errno::BADF);
            }
            let e = HeldFile::adopt_with(file, &mut o).unwrap_err();
            assert_eq!(e.file.as_raw_fd(), fd);
            assert!(
                io::fcntl_getfd(&e.file).unwrap().contains(FdFlags::CLOEXEC),
                "real owned effect occurred"
            );
            assert_eq!(e.error.source().unwrap().raw_os_error(), Some(5));
            assert_eq!(
                e.error.effect().descriptor_flags(),
                if verify_failed {
                    DescriptorFlagEffect::Unknown
                } else {
                    DescriptorFlagEffect::CloexecSet
                }
            );
            assert_eq!(
                (o.syscalls, o.completed),
                (5, if verify_failed { 3 } else { 4 })
            );
        }
    }
    #[test]
    fn stat_fault_keeps_owner_and_charges_one_attempt() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let f = Fixture::new();
        let p = f.write("a", b"A");
        let h = HeldFile::from_file(File::open(&p).unwrap()).unwrap();
        let fd = h.as_fd().as_raw_fd();
        let mut o = Ops::default();
        o.hooks.fail = Some((Step::Stat, Errno::INTR));
        let e = h.stat_with(&mut o).unwrap_err();
        check_error(&e, Stage::ValidateFile, Reason::Inconclusive, Some(4));
        assert_eq!((o.syscalls, o.completed, o.acquired), (1, 0, 0));
        assert_eq!(h.as_fd().as_raw_fd(), fd);
        assert!(h.stat().is_ok());
    }
    #[test]
    fn diagnostic_bound_omits_arbitrary_source_text_in_every_format() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let mut o = Ops::default();
        o.attempted = u64::MAX;
        o.syscalls = u64::MAX;
        let e = o.error(
            Stage::ResolveProc,
            Reason::Inconclusive,
            Some(std::io::Error::other("CANARY\n\x1b".repeat(10_000))),
            DescriptorFlagEffect::Unknown,
        );
        let f = Fixture::new();
        let p = f.write("CANARY", b"PAYLOAD-CANARY");
        let file = File::open(p).unwrap();
        let e = AdoptFileError { error: e, file };
        for text in [
            format!("{e}"),
            format!("{e:?}"),
            format!("{e:#?}"),
            format!("{}", e.error),
            format!("{:?}", e.error),
            format!("{:#?}", e.error),
        ] {
            assert!(text.len() <= 256 && text.is_ascii());
            assert!(
                text.bytes().all(|b| (0x20..=0x7e).contains(&b)),
                "diagnostic must contain only printable bytes"
            );
            assert!(!text.contains("CANARY"));
        }
    }
    #[test]
    fn private_real_foreign_table_refuses_despite_inherited_directory_parity() {
        let _fd_table = FD_TABLE.lock().unwrap();
        use std::io::{BufRead, Write};
        let root = fs::open(
            c"/proc",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let own = fs::open(
            c"/proc/self",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        // Deliberate fixture-only inheritance establishes the old parity blind spot.
        io::fcntl_setfd(&root, FdFlags::empty()).unwrap();
        io::fcntl_setfd(&own, FdFlags::empty()).unwrap();
        let mut child = ReapChild(
            std::process::Command::new("/bin/sh")
                .args(["-c", "printf 'ready\\n'; read line"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ready\n");
        let base = format!("/proc/{}/fd", child.id());
        let child_dir = fs::open(
            &base,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        for fd in [&root, &own] {
            let other = fs::open(
                format!("{base}/{}", fd.as_raw_fd()),
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            assert_eq!(
                key(&fs::fstat(fd).unwrap()),
                key(&fs::fstat(&other).unwrap()),
                "inherited-directory parity accepts foreign table"
            );
        }
        io::fcntl_setfd(&root, FdFlags::CLOEXEC).unwrap();
        io::fcntl_setfd(&own, FdFlags::CLOEXEC).unwrap();
        let base2 = base.clone();
        let mut o = Ops::default();
        let injected_fd = child_dir.as_raw_fd();
        o.hooks.candidate = Some(child_dir);
        o.hooks.pipe_observer = Some(Box::new(move |fd, pipe| {
            match stdfs::metadata(format!("{base2}/{fd}")) {
                Err(e) => assert_eq!(e.raw_os_error(), Some(2)),
                Ok(m) => assert_ne!(
                    (m.dev(), m.ino()),
                    (pipe.st_dev as u64, pipe.st_ino as u64),
                    "foreign slot independently differs"
                ),
            }
        }));
        let result = ProcFdResolver::open_with(&mut o);
        let cleanup = child.stdin.take().unwrap().write_all(b"done\n");
        let status = child.wait().unwrap();
        cleanup.unwrap();
        assert!(status.success());
        let e = result.expect_err("foreign FD table must be refused");
        assert_closed(&[injected_fd]);
        assert_eq!(e.stage(), Stage::ResolveProc);
        assert!(matches!(
            e.reason(),
            Reason::Disappeared | Reason::WrongContext
        ));
        assert_closed(&o.hooks.fds);
        let mut twin = Ops::default();
        twin.hooks.candidate = Some(
            fs::open(
                c"/proc/self/fd",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap(),
        );
        let injected_twin_fd = twin.hooks.candidate.as_ref().unwrap().as_raw_fd();
        assert!(ProcFdResolver::open_with(&mut twin).is_ok());
        assert_closed(&[injected_twin_fd]);
    }
    #[test]
    fn additional_model_refusals_preserve_counts_and_effect_uncertainty() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let mut o = Ops::default();
        o.hooks.pipe_mutation = 3;
        let e = ProcFdResolver::open_with(&mut o).unwrap_err();
        check_error(&e, Stage::ResolveProc, Reason::WrongContext, None);
        assert_eq!(
            (o.syscalls, o.attempted, o.completed, o.acquired, o.peak),
            (9, 11, 11, 5, 3)
        );
        assert_closed(&o.hooks.fds);
        let f = Fixture::new();
        let p = f.write("a", b"A");
        for unknown_bits in [false, true] {
            let file = File::open(&p).unwrap();
            io::fcntl_setfd(&file, FdFlags::empty()).unwrap();
            let mut o = Ops::default();
            o.hooks.fail = Some((Step::SetFd, Errno::IO));
            if unknown_bits {
                o.hooks.verify_flags = Some(FdFlags::from_bits_retain(8));
            } else {
                o.hooks.verify_error = Some(Errno::BADF);
            }
            let e = HeldFile::adopt_with(file, &mut o).unwrap_err();
            assert_eq!(
                e.error.effect().descriptor_flags(),
                DescriptorFlagEffect::Unknown
            );
            assert_eq!(e.error.source().unwrap().raw_os_error(), Some(5));
            assert_eq!(io::fcntl_getfd(&e.file).unwrap(), FdFlags::empty());
        }
        let h = HeldFile::from_file(File::open(&p).unwrap()).unwrap();
        let mut o = Ops::default();
        o.hooks.malformed_stat = true;
        let e = h.stat_with(&mut o).unwrap_err();
        check_error(&e, Stage::ValidateFile, Reason::Malformed, None);
        assert_eq!(
            (o.syscalls, o.attempted, o.completed, o.acquired),
            (1, 1, 1, 0)
        );
        assert!(h.stat().is_ok());
    }
    #[test]
    fn errno_table_is_stage_specific() {
        for stage in [
            Stage::ResolveProc,
            Stage::AcquirePath,
            Stage::ValidateFile,
            Stage::ReopenHeld,
        ] {
            for (errno, expected) in [
                (Errno::PERM, Reason::Denied),
                (Errno::ACCESS, Reason::Denied),
                (Errno::NOSYS, Reason::Unavailable),
                (Errno::OPNOTSUPP, Reason::Unavailable),
                (Errno::MFILE, Reason::Unavailable),
                (Errno::NFILE, Reason::Unavailable),
                (Errno::NOMEM, Reason::Unavailable),
                (Errno::NOENT, Reason::Disappeared),
                (Errno::STALE, Reason::Disappeared),
                (Errno::INTR, Reason::Inconclusive),
                (Errno::IO, Reason::Inconclusive),
                (Errno::BADF, Reason::Inconclusive),
                (Errno::INVAL, Reason::Inconclusive),
            ] {
                assert_eq!(classify(stage, errno), expected);
            }
        }
        assert_eq!(
            classify(Stage::ResolveProc, Errno::NOTDIR),
            Reason::WrongContext
        );
        assert_eq!(
            classify(Stage::ResolveProc, Errno::LOOP),
            Reason::WrongContext
        );
        for e in [Errno::NAMETOOLONG, Errno::NOTDIR, Errno::LOOP] {
            assert_eq!(classify(Stage::AcquirePath, e), Reason::InvalidInput);
            assert_eq!(classify(Stage::ValidateFile, e), Reason::Inconclusive);
        }
    }
    #[test]
    fn real_nonproc_root_is_refused_before_self_lookup() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let f = Fixture::new();
        let oracle = File::open(&f.0).unwrap();
        assert_ne!(
            fs::fstatfs(&oracle).unwrap().f_type as i64,
            0x9fa0,
            "fixture must be nonproc"
        );
        let mut o = Ops::default();
        o.hooks.root_override = Some(f.0.clone());
        let e = ProcFdResolver::open_with(&mut o).unwrap_err();
        check_error(&e, Stage::ResolveProc, Reason::WrongContext, None);
        assert_eq!(
            (o.syscalls, o.attempted, o.completed, o.acquired, o.peak),
            (2, 3, 3, 1, 1)
        );
        assert_eq!(o.hooks.trace, [Step::RootOpen, Step::RootFs]);
        assert_closed(&o.hooks.fds);
    }
    fn exec_must_close(fd: i32, expected: StatFileKey, canary: &OwnedFd) {
        // Caller retains the actual owner through this complete synchronous probe.
        let actual = fs::fstat(unsafe { BorrowedFd::borrow_raw(fd) }).unwrap();
        assert_eq!(key(&actual), expected, "pre-exec original FD identity");
        let c = fs::fstat(canary).unwrap();
        let value = format!("{} {} {} {}", fd, canary.as_raw_fd(), c.st_dev, c.st_ino);
        let standalone = std::env::var_os("SCOPEBASE_EXEC_PROBE");
        let executable = standalone
            .clone()
            .map(std::path::PathBuf::from)
            .unwrap_or(std::env::current_exe().unwrap());
        let mut command = std::process::Command::new(executable);
        if standalone.is_some() {
            command.env("LX02_EXEC", value);
        } else {
            command
                .args([
                    "--exact",
                    "file::held::tests::private_exec_probe_child",
                    "--nocapture",
                ])
                .env("LX02_INTERNAL_EXEC", value);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "internal owner must close across exec: {:?}",
            output
        );
        if standalone.is_some() {
            assert!(output.stdout.is_empty() && output.stderr.is_empty());
        }
    }
    #[test]
    fn private_exec_probe_child() {
        if let Ok(value) = std::env::var("LX02_INTERNAL_EXEC") {
            let values: Vec<u64> = value.split(' ').map(|v| v.parse().unwrap()).collect();
            let owner = slot_flags(values[0] as i32);
            let canary = slot_flags(values[1] as i32);
            assert_eq!(
                owner
                    .expect_err("internal owner must close across exec")
                    .raw_os_error(),
                Some(9)
            );
            canary.unwrap();
            let actual = fs::fstat(unsafe { BorrowedFd::borrow_raw(values[1] as i32) }).unwrap();
            assert_eq!(
                (actual.st_dev as u64, actual.st_ino as u64),
                (values[2], values[3]),
                "independent canary must survive"
            );
        }
    }
    #[test]
    fn resolver_and_live_path_pin_close_across_exec() {
        let _fd_table = FD_TABLE.lock().unwrap();
        let fixture = Fixture::new();
        let path = fixture.write("a", b"A");
        let oracle = File::open(&path).unwrap();
        let expected_pin = key(&fs::fstat(&oracle).unwrap());
        let resolver = ProcFdResolver::open_self().unwrap();
        let resolver_fd = resolver.directory.as_raw_fd();
        let expected_resolver = key(&fs::fstat(&resolver.directory).unwrap());
        let canary = fs::open(&path, OFlags::RDONLY, Mode::empty()).unwrap();
        let mut o = Ops::default();
        o.hooks.after_pin = Some(Box::new(move |pin_fd| {
            exec_must_close(resolver_fd, expected_resolver, &canary);
            exec_must_close(pin_fd, expected_pin, &canary);
        }));
        let held = HeldFile::open_with(&path, &resolver, SymlinkPolicy::Follow, &mut o).unwrap();
        assert_eq!(held.stat().unwrap().key(), expected_pin);
    }
}
