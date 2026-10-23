// SPDX-License-Identifier: Apache-2.0
//! FS10 independent syscall audit: a ptrace tracer that records every
//! mmap-family call of an owned subject and attributes fd-backed maps
//! to their (device, inode) object identity.
//!
//! The tracer spawns the subject with `PTRACE_TRACEME` (via
//! `pre_exec`, so the multithreaded test binary never raw-forks
//! production code), follows syscall enter/exit with
//! `PTRACE_O_TRACESYSGOOD`, resolves fd arguments through
//! `/proc/<pid>/fd` at enter time, and matches completed maps against
//! the audited target identity. Anonymous maps are counted, never
//! attributed: allocator/runtime activity is outside the
//! target-scoped promise and doubles as instrument-liveness proof.
//!
//! F15: the tracer follows the whole subject: worker threads (via
//! `PTRACE_O_TRACECLONE`) and fork/vfork children (via
//! `PTRACE_O_TRACEFORK`/`PTRACE_O_TRACEVFORK`) are traced with
//! per-thread syscall state, and `PTRACE_O_TRACEEXEC` reports execs
//! so threads an exec silently killed can be pruned. A newborn
//! thread's birth SIGSTOP is suppressed, never forwarded (forwarding
//! it would re-stop forever). S47: the same holds for any SIGSTOP
//! stop on a tracked tid — SIGSTOP is uncatchable, so the stop is
//! always a group stop, never a deliverable signal, and resuming
//! clean lets a subject that stops itself proceed. Other stop
//! signals keep default forwarding; full SIGCONT job control of the
//! subject is NOT supported. The audit runs until every traced
//! thread and child has exited; the config deadline backstops every
//! wait, so a deaf or hung subject fails loud instead of hanging.
//!
//! NEW per the frozen FS10 design; no donor implements a syscall
//! tracer. The Yama-scope read in [`preflight`] ADAPTs the KryProbe
//! read idiom (crates/kryprobe-privilege/src/probe/host_rows.rs
//! @d153f3aa:118-127: unreadable/unparseable stays a recorded
//! unknown). x86_64 only; other architectures report unsupported.
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Audit failure with its stage. Denied carries the Yama/errno note
/// the cell reports as its exact SKIP reason.
#[derive(Debug, Clone)]
pub struct AuditError {
    detail: String,
}

impl AuditError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for AuditError {}

/// What to attribute: the audited target object plus ledger bounds.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub target_dev: u64,
    pub target_ino: u64,
    pub max_entries: usize,
    pub timeout: Duration,
}

/// One completed mmap-family call (mmap, mremap).
#[derive(Debug, Clone)]
pub struct MmapEvent {
    /// Raw syscall number (`libc::SYS_mmap` / `SYS_mremap`).
    pub nr: i64,
    /// Descriptor argument (-1 anonymous, -2 inapplicable).
    pub fd: i32,
    pub anonymous: bool,
    /// fd identity resolved at syscall enter, when the fd is valid.
    pub dev: Option<u64>,
    pub ino: Option<u64>,
    pub path: Option<String>,
    pub addr: u64,
    pub len: u64,
    pub prot: u32,
    pub flags: u32,
    /// R46: mremap new size (`rdx`); 0 for mmap (which has no second
    /// length). Separating it from `flags` keeps size bits out of
    /// the flag ledger.
    pub new_len: u64,
    /// Raw return: map address or -errno.
    pub result: i64,
    /// R28/R29: a successful file-backed map whose object identity
    /// could not be established (unreadable fd at enter, or the
    /// enter sample disagreeing with the authoritative maps row at
    /// exit). Unattributed successes are audit-incomplete, never
    /// clean: [`AuditReport::unattributed_mmaps`].
    pub unattributed: bool,
}

impl MmapEvent {
    /// F17: raw ptrace return decode. A success is a map address; any
    /// value in -4095..=-1 is a raw -errno failure. (libc reports
    /// MAP_FAILED for all of these, but that mapping happens above
    /// the raw layer this tracer observes, so `result != -1`
    /// misclassifies e.g. -EBADF as a successful map.)
    pub fn succeeded(&self) -> bool {
        !(-4095..=-1).contains(&self.result)
    }

    /// Raw errno when [`MmapEvent::succeeded`] is false.
    pub fn errno(&self) -> Option<i32> {
        if self.succeeded() {
            None
        } else {
            Some(-self.result as i32)
        }
    }

    pub fn result_addr(&self) -> u64 {
        self.result as u64
    }
}

/// One completed munmap call.
#[derive(Debug, Clone)]
pub struct MunmapEvent {
    pub addr: u64,
    pub len: u64,
    pub result: i64,
}

/// Completed trace: subject exit plus the bounded syscall ledger.
#[derive(Debug)]
pub struct AuditReport {
    pub exit_code: Option<i32>,
    pub target_dev: u64,
    pub target_ino: u64,
    pub mmaps: Vec<MmapEvent>,
    pub munmaps: Vec<MunmapEvent>,
    /// True when the ledger hit `max_entries` and stopped recording
    /// (the subject still ran to completion).
    pub truncated: bool,
    /// F15: distinct thread/child ids the tracer observed (1 for a
    /// single-threaded subject that never forks).
    pub threads_seen: usize,
}

impl AuditReport {
    /// Successful maps attributed to the audited target object.
    pub fn target_backed_mmaps(&self) -> Vec<&MmapEvent> {
        self.mmaps
            .iter()
            .filter(|e| {
                e.succeeded()
                    && !e.anonymous
                    && e.dev == Some(self.target_dev)
                    && e.ino == Some(self.target_ino)
            })
            .collect()
    }

    pub fn munmaps(&self) -> Vec<&MunmapEvent> {
        self.munmaps.iter().collect()
    }

    /// Successful anonymous maps: instrument-liveness proof.
    pub fn anonymous_mmaps(&self) -> usize {
        self.mmaps
            .iter()
            .filter(|e| e.succeeded() && e.anonymous)
            .count()
    }

    /// Successful file-backed maps the tracer could not bind to an
    /// object (R28/R29). A non-empty set means the audit is
    /// incomplete: [`audit_subject`] refuses with an error rather
    /// than reporting a possibly false clean.
    pub fn unattributed_mmaps(&self) -> Vec<&MmapEvent> {
        self.mmaps
            .iter()
            .filter(|e| e.succeeded() && e.unattributed)
            .collect()
    }
}

/// The preflight child: attempt TRACEME, report the errno byte,
/// stop once for the register probe when traced, exit. Syscalls and
/// atomics only; diverges.
fn preflight_child() -> ! {
    let (w, _, _) = super::fork::slots();
    // SAFETY: raw ptrace on self; always permitted to attempt.
    let traced = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
    let code: u8 = if traced == 0 {
        0
    } else {
        // SAFETY: errno location for this thread.
        let errno = unsafe { libc::__errno_location().read() };
        errno.clamp(1, 127) as u8
    };
    // SAFETY: one byte to the inherited pipe, then (when traced) one
    // SIGSTOP for the parent's register probe, then exit. The stop
    // is skipped when TRACEME failed: an untraced stop is invisible
    // to the parent's flag-0 wait and would hang it.
    unsafe {
        libc::write(w, &code as *const u8 as *const _, 1);
        if traced == 0 {
            libc::raise(libc::SIGSTOP);
        }
        libc::_exit(0);
    }
}

fn yama_note() -> String {
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(text) => match text.trim().parse::<i64>() {
            Ok(n) => format!("yama_scope={n}"),
            Err(_) => "yama_scope=unparseable".to_string(),
        },
        Err(_) => "yama_scope=unreadable".to_string(),
    }
}

/// Prove this environment can trace an owned child before auditing.
/// Returns the Yama note on success; refusal names the exact cause.
pub fn preflight() -> Result<String, AuditError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(AuditError::new("tracer needs x86_64 registers"));
    }
    let mut pipe = [0; 2];
    // SAFETY: valid out-pointer; ends checked below.
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return Err(AuditError::new("preflight pipe failed"));
    }
    // SAFETY: the child runs only ptrace/write/_exit (syscalls plus
    // one atomic load), never allocating, locking, or returning.
    let pid = unsafe {
        super::fork::fork_guarded((pipe[1], -1, -1), |child| child, || preflight_child())
    };
    if pid < 0 {
        // SAFETY: ends owned by this scope.
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(AuditError::new("preflight fork failed"));
    }
    // SAFETY: write end owned by this scope; the child holds its own.
    unsafe { libc::close(pipe[1]) };
    let mut code = [1u8; 1];
    // SAFETY: one byte from the inherited pipe.
    let got = unsafe { libc::read(pipe[0], code.as_mut_ptr() as *mut _, 1) };
    // SAFETY: read end owned by this scope.
    unsafe { libc::close(pipe[0]) };
    // S05: the traced child stops once for the register probe. An
    // environment that permits TRACEME but denies GETREGS cannot
    // observe anything, so it refuses here instead of mid-audit.
    let mut regs_ok = false;
    // Reap the child through any ptrace stop it raised on exit.
    loop {
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(AuditError::new(format!("preflight wait: {error}")));
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            break;
        }
        if libc::WIFSTOPPED(status) && code[0] == 0 {
            let mut regs = std::mem::MaybeUninit::<libc::user_regs_struct>::zeroed();
            // SAFETY: valid regs out-pointer for a stopped owned child.
            regs_ok = unsafe {
                libc::ptrace(
                    libc::PTRACE_GETREGS,
                    pid,
                    0,
                    regs.as_mut_ptr() as *mut libc::c_void,
                ) == 0
            };
        }
        // SAFETY: continue an owned ptrace-stopped child.
        unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) };
    }
    if got != 1 {
        return Err(AuditError::new(format!(
            "preflight child silent ({})",
            yama_note()
        )));
    }
    if code[0] != 0 {
        return Err(AuditError::new(format!(
            "PTRACE_TRACEME refused with errno {} ({})",
            code[0],
            yama_note()
        )));
    }
    if !regs_ok {
        return Err(AuditError::new(format!(
            "PTRACE_GETREGS refused ({})",
            yama_note()
        )));
    }
    Ok(yama_note())
}

/// Trace `program args` to completion and attribute its mmap family.
pub fn audit_subject(
    program: &Path,
    args: &[String],
    config: &AuditConfig,
) -> Result<AuditReport, AuditError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(AuditError::new("tracer needs x86_64 registers"));
    }
    audit_subject_x86_64(program, args, config)
}

#[cfg(target_arch = "x86_64")]
fn audit_subject_x86_64(
    program: &Path,
    args: &[String],
    config: &AuditConfig,
) -> Result<AuditReport, AuditError> {
    use std::os::unix::process::CommandExt as _;
    // R05: the deadline must exist before the subject does. An
    // unrepresentable timeout refuses here, with no spawn and no
    // side effect; computing it after spawn panicked.
    let deadline = Instant::now()
        .checked_add(config.timeout)
        .ok_or_else(|| AuditError::new("audit timeout overflows representable deadline"))?;
    let program: PathBuf = program.to_path_buf();
    let mut child = unsafe {
        Command::new(&program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .pre_exec(|| {
                // Async-signal-safe: one raw syscall, then exec or error.
                let result = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                if result == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            })
            .spawn()
    }
    .map_err(|e| AuditError::new(format!("subject spawn refused: {e}")))?;
    let pid = child.id() as libc::pid_t;
    let mut report = AuditReport {
        exit_code: None,
        target_dev: config.target_dev,
        target_ino: config.target_ino,
        mmaps: Vec::new(),
        munmaps: Vec::new(),
        truncated: false,
        threads_seen: 0,
    };
    let mut main_reaped = false;
    let outcome = trace_loop(pid, config, deadline, &mut report, &mut main_reaped);
    // R26: signal the main only while it is provably unreaped. The
    // tracer reaps through raw waitpid, which never updates Child's
    // private status: killing after our own reap would signal a
    // possibly reused PID. Bounded: this only covers a main the
    // tracer never saw exit.
    if !main_reaped {
        let _ = child.kill();
        let reap_end = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {
                    if Instant::now() >= reap_end {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
    outcome?;
    // R28: successful but unattributable file mappings are an
    // incomplete audit, never a clean report.
    let unattributed = report.unattributed_mmaps();
    if !unattributed.is_empty() {
        let addrs: Vec<String> = unattributed
            .iter()
            .take(4)
            .map(|e| format!("{:#x}", e.result_addr()))
            .collect();
        let plural = if unattributed.len() == 1 { "" } else { "s" };
        return Err(AuditError::new(format!(
            "audit incomplete: {} successful file mapping{plural} unattributable (addrs {})",
            unattributed.len(),
            addrs.join(","),
        )));
    }
    Ok(report)
}

#[cfg(not(target_arch = "x86_64"))]
fn audit_subject_x86_64(
    _program: &Path,
    _args: &[String],
    _config: &AuditConfig,
) -> Result<AuditReport, AuditError> {
    Err(AuditError::new("tracer needs x86_64 registers"))
}

#[cfg(target_arch = "x86_64")]
struct Pending {
    nr: i64,
    fd: i32,
    anonymous: bool,
    dev: Option<u64>,
    ino: Option<u64>,
    path: Option<String>,
    addr: u64,
    len: u64,
    prot: u32,
    flags: u32,
    new_len: u64,
    /// Enter-time attribution already failed (R28); the exit stop
    /// can only confirm or extend this, never clear it.
    unattributed: bool,
}

#[cfg(target_arch = "x86_64")]
fn fd_identity(pid: libc::pid_t, fd: i32) -> (Option<u64>, Option<u64>, Option<String>) {
    let link = format!("/proc/{pid}/fd/{fd}");
    let path = std::fs::read_link(&link)
        .ok()
        .map(|p| p.display().to_string());
    let (dev, ino) = std::fs::metadata(&link)
        .ok()
        .map(|m| {
            use std::os::unix::fs::MetadataExt as _;
            (Some(m.dev()), Some(m.ino()))
        })
        .unwrap_or((None, None));
    (dev, ino, path)
}

/// R29: authoritative object of the mapping containing `addr` in
/// `pid`'s address space. Independent of the fd sampled at syscall
/// enter: a descriptor swapped mid-call cannot forge the object the
/// kernel actually mapped.
///
/// Identity comes from stating the row's own pathname, never from
/// the row's dev:ino text: row device numbers and stat device
/// numbers legitimately disagree on some filesystems (observed:
/// btrfs reports st_dev 37 where the row says 00:23 for the same
/// inode), while two stat-path identities always share one
/// encoding. (`map_files` would be authoritative too, but stating
/// through it needs attach-grade permission and fails even for
/// self reads under Yama.) Malformed rows are skipped; a missing
/// row, an unreadable table, a non-absolute or deleted pathname,
/// or a failed stat attributes nothing.
#[cfg(target_arch = "x86_64")]
fn mapped_object(pid: libc::pid_t, addr: u64) -> Option<(u64, u64, Option<String>)> {
    match mapping_class(pid, addr) {
        MappingClass::File(dev, ino, path) => Some((dev, ino, path)),
        _ => None,
    }
}

/// S30: what the mapping containing `addr` is. Anonymous rows (no
/// absolute live pathname) are a KNOWN classification, not
/// unattributed: an mremap of anonymous memory preserves it. Only a
/// missing row or an unreadable table (Absent), or a file-shaped
/// row whose identity cannot be read (Unidentified), attributes
/// nothing.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, PartialEq, Eq)]
enum MappingClass {
    Anonymous,
    File(u64, u64, Option<String>),
    Unidentified,
    Absent,
}

#[cfg(target_arch = "x86_64")]
fn mapping_class(pid: libc::pid_t, addr: u64) -> MappingClass {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return MappingClass::Absent;
    };
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some((lo_text, hi_text)) = range.split_once('-') else {
            continue;
        };
        let (Ok(lo), Ok(hi)) = (
            u64::from_str_radix(lo_text, 16),
            u64::from_str_radix(hi_text, 16),
        ) else {
            continue;
        };
        if addr < lo || addr >= hi {
            continue;
        }
        // Drain to the optional pathname (fields: range perms
        // offset dev inode [pathname]).
        let mut path = None;
        for (index, field) in fields.enumerate() {
            if index == 4 {
                path = Some(field.to_string());
                break;
            }
        }
        // Only an absolute live pathname identifies the object: a
        // deleted name no longer does, and anything else (special
        // rows, memfd) must never resolve against our CWD. Rows
        // without one are anonymous by definition here.
        let path = match path {
            Some(path) if path.starts_with('/') && !path.ends_with(" (deleted)") => path,
            _ => return MappingClass::Anonymous,
        };
        let Ok(stated) = std::fs::metadata(&path) else {
            return MappingClass::Unidentified;
        };
        use std::os::unix::fs::MetadataExt as _;
        return MappingClass::File(stated.dev(), stated.ino(), Some(path));
    }
    MappingClass::Absent
}

#[cfg(target_arch = "x86_64")]
#[derive(Default)]
struct TidState {
    in_syscall: bool,
    pending: Option<Pending>,
    /// A newborn thread's first stop is its birth SIGSTOP, which must
    /// be suppressed (forwarding it would re-stop forever). Cleared
    /// by that stop, or by any other first stop.
    newborn_sigstop: bool,
    /// S06: set by the EXEC event. The next syscall stop is either
    /// the execve's own exit (success: rax=0 — consumed silently,
    /// the entry half died with the old image) or the next call's
    /// entry (rax=-ENOSYS — classified normally). Peeking rax
    /// self-synchronizes on kernels that report the exit stop, the
    /// event, or both: without it the exit stop re-inverts the
    /// reset phase and every later entry/exit pair lags by one.
    exec_armed: bool,
}

#[cfg(target_arch = "x86_64")]
impl TidState {
    fn newborn() -> Self {
        Self {
            newborn_sigstop: true,
            ..Self::default()
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn trace_loop(
    pid: libc::pid_t,
    config: &AuditConfig,
    deadline: Instant,
    report: &mut AuditReport,
    main_reaped: &mut bool,
) -> Result<(), AuditError> {
    // Only the main thread exists yet; every birth below joins this set.
    let mut tids: HashMap<libc::pid_t, TidState> = HashMap::new();
    tids.insert(pid, TidState::default());
    report.threads_seen = 1;
    // Initial exec-stop: the TRACEME child stops with SIGTRAP.
    let (_, stop) = wait_for_event(Some(pid), deadline, pid, &mut tids, main_reaped)?;
    if !libc::WIFSTOPPED(stop) {
        // The exit status above already reaped the main: flag it so
        // the outer cleanup never signals the stale PID (R26), and
        // drain for uniformity (R31).
        *main_reaped = true;
        let unknowns = drain_tracked(&mut tids, pid, main_reaped);
        return Err(AuditError::new(format!(
            "subject died before its exec-stop{unknowns}"
        )));
    }
    // F15: follow threads and fork/vfork children (options inherit
    // across clone/fork, the strace -f recipe) and learn about execs.
    // SAFETY: options on an owned ptrace-stopped child.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            0,
            (libc::PTRACE_O_TRACESYSGOOD
                | libc::PTRACE_O_TRACECLONE
                | libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACEVFORK
                | libc::PTRACE_O_TRACEEXEC) as *mut libc::c_void,
        )
    } != 0
    {
        // R31: the stopped main keeps its custody through this
        // error; survivors are named, never silently kept.
        let unknowns = drain_tracked(&mut tids, pid, main_reaped);
        return Err(drained_err(
            format!("PTRACE_SETOPTIONS refused{unknowns}"),
            &tids,
        ));
    }
    // The tid whose consumed stop still needs a resume (each tid is
    // resumed exactly once per consumed stop; running tids are never
    // touched, so concurrent stops queue without loss).
    let mut resume: Option<libc::pid_t> = Some(pid);
    // A consumed stop awaiting classification (signal-forward path).
    let mut held: Option<(libc::pid_t, i32)> = None;
    loop {
        let (tid, status) = match held.take() {
            Some(pair) => pair,
            None => {
                if let Some(t) = resume.take() {
                    // SAFETY: resume a tid whose stop this loop consumed.
                    if unsafe { libc::ptrace(libc::PTRACE_SYSCALL, t, 0, 0) } != 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() == std::io::ErrorKind::Interrupted {
                            resume = Some(t);
                            continue;
                        }
                        // The tid may have exited between stops.
                        if try_reap(t, pid, report, &mut tids) {
                            if t == pid {
                                *main_reaped = true;
                            }
                            if tids.is_empty() {
                                return Ok(());
                            }
                            continue;
                        }
                        // R31: a resume failure retires every
                        // tracked tracee before reporting; R26: the
                        // drain flags the main when it reaps it.
                        let unknowns = drain_tracked(&mut tids, pid, main_reaped);
                        return Err(drained_err(
                            format!("PTRACE_SYSCALL: {error}{unknowns}"),
                            &tids,
                        ));
                    }
                }
                if tids.is_empty() {
                    return Ok(());
                }
                wait_for_event(None, deadline, pid, &mut tids, main_reaped)?
            }
        };
        // Track first-sight tids: a birth event can lose the race
        // with the newborn's own first stop. Known tids keep their
        // syscall state; only true first sights become newborns.
        if !tids.contains_key(&tid) {
            tids.insert(tid, TidState::newborn());
            report.threads_seen += 1;
        }
        if libc::WIFEXITED(status) {
            if tid == pid {
                report.exit_code = Some(libc::WEXITSTATUS(status));
                *main_reaped = true;
            }
            tids.remove(&tid);
            if tids.is_empty() {
                return Ok(());
            }
            continue;
        }
        if libc::WIFSIGNALED(status) {
            if tid == pid {
                *main_reaped = true;
            }
            tids.remove(&tid);
            if tids.is_empty() {
                return Ok(());
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            resume = Some(tid);
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        if sig == libc::SIGTRAP | 0x80 {
            // S06: self-synchronize after an exec. The execve
            // succeeded (a failed one reports no event), so rax=0
            // is its own exit stop and rax=-ENOSYS is the next
            // call's entry; any other value is impossible here and
            // consumes like the exit (nothing is attributed either
            // way until the next entry).
            if tids.get(&tid).is_some_and(|state| state.exec_armed) {
                let regs = match read_regs(tid) {
                    Ok(regs) => regs,
                    Err(error) => {
                        let unknowns = drain_tracked(&mut tids, pid, main_reaped);
                        return Err(drained_err(
                            format!("PTRACE_GETREGS exec-sync: {error}{unknowns}"),
                            &tids,
                        ));
                    }
                };
                let is_entry = regs.rax as i64 == -libc::ENOSYS as i64;
                if let Some(state) = tids.get_mut(&tid) {
                    state.exec_armed = false;
                    state.newborn_sigstop = false;
                    if !is_entry {
                        resume = Some(tid);
                        continue;
                    }
                }
            }
            // S05: observe before mutating. A register failure drains
            // (which needs `tids`) and reports an incomplete audit
            // instead of an absent call or a fabricated result.
            let entering = tids.get(&tid).map(|state| !state.in_syscall);
            match entering {
                Some(true) => match syscall_enter(tid) {
                    Ok(pending) => {
                        if let Some(state) = tids.get_mut(&tid) {
                            state.in_syscall = true;
                            state.pending = pending;
                            state.newborn_sigstop = false;
                        }
                    }
                    Err(error) => {
                        let unknowns = drain_tracked(&mut tids, pid, main_reaped);
                        return Err(drained_err(
                            format!("PTRACE_GETREGS enter: {error}{unknowns}"),
                            &tids,
                        ));
                    }
                },
                Some(false) => {
                    let call = tids.get_mut(&tid).and_then(|state| state.pending.take());
                    if let Some(call) = call {
                        if let Err(error) = syscall_exit(tid, call, config, report) {
                            let unknowns = drain_tracked(&mut tids, pid, main_reaped);
                            return Err(drained_err(
                                format!("PTRACE_GETREGS exit: {error}{unknowns}"),
                                &tids,
                            ));
                        }
                    }
                    if let Some(state) = tids.get_mut(&tid) {
                        state.in_syscall = false;
                        state.newborn_sigstop = false;
                    }
                }
                None => {}
            }
            resume = Some(tid);
            continue;
        }
        if sig == libc::SIGTRAP {
            let event = ((status >> 16) & 0xffff) as i64;
            if event == libc::PTRACE_EVENT_CLONE as i64
                || event == libc::PTRACE_EVENT_FORK as i64
                || event == libc::PTRACE_EVENT_VFORK as i64
            {
                // Pre-register the birth; its own first stop (or an
                // already-queued one) reconciles below. Never
                // overwrite a state the newborn already reported.
                // S31: an unreadable birth message is an explicit
                // custody failure, never a skipped registration: the
                // drain below retires the tracked set, and the
                // unknown-tracee sweep retires the child this message
                // would have named.
                let new = match event_msg(tid) {
                    Ok(new) => new as libc::pid_t,
                    Err(error) => {
                        let unknowns = drain_tracked(&mut tids, pid, main_reaped);
                        return Err(drained_err(
                            format!("PTRACE_GETEVENTMSG birth: {error}{unknowns}"),
                            &tids,
                        ));
                    }
                };
                if !tids.contains_key(&new) {
                    tids.insert(new, TidState::newborn());
                    report.threads_seen += 1;
                }
                // Event stops resume without delivery.
                if let Some(state) = tids.get_mut(&tid) {
                    state.newborn_sigstop = false;
                }
                resume = Some(tid);
                continue;
            }
            if event == libc::PTRACE_EVENT_EXEC as i64 {
                // An exec silently kills its sibling threads: prune
                // tracked tids that are no longer traced by us.
                prune_exec_siblings(tid, &mut tids);
                // S06: the survivor's pre-exec phase is meaningless
                // (its entry half died with the old image), so the
                // phase resets and arms for self-synchronization. A
                // worker that execs is renumbered to the leader
                // before this event (the old number frees with
                // ECHILD and drops as stale), so this same entry now
                // describes the execing thread; keeping the old
                // leader's phase would invert every later entry/exit
                // classification and hide successful mappings behind
                // a following entry's -ENOSYS.
                tids.insert(
                    tid,
                    TidState {
                        exec_armed: true,
                        ..TidState::default()
                    },
                );
                resume = Some(tid);
                continue;
            }
            if event != 0 {
                // A ptrace event this tracer did not enable: nothing
                // to decode, so resume without delivery like the
                // known events rather than injecting a trap.
                if let Some(state) = tids.get_mut(&tid) {
                    state.newborn_sigstop = false;
                }
                resume = Some(tid);
                continue;
            }
            // R30: event-zero is a genuine signal-delivery trap (the
            // subject raised SIGTRAP itself): fall through and
            // forward it like any real signal instead of swallowing
            // the handler run or the fatal termination.
        }
        // A real signal: forward it so the subject, not the tracer,
        // decides its fate — except a SIGSTOP stop on a tracked tid,
        // which is suppressed. SIGSTOP is uncatchable, so the stop is
        // always a group stop (or the newborn birth stop), never a
        // deliverable signal, and forwarding it would re-stop
        // forever; resuming clean lets a subject that stops itself
        // proceed. Unknown tids keep the old forward path; the sweep
        // retires them. The following stop is held for the same
        // classification instead of being dropped. The deadline
        // backstops this wait like every other, so a signal that
        // re-traps fails loud.
        let suppress = sig == libc::SIGSTOP && tids.contains_key(&tid);
        if let Some(state) = tids.get_mut(&tid) {
            state.newborn_sigstop = false;
        }
        let data = if suppress {
            std::ptr::null_mut()
        } else {
            sig as *mut libc::c_void
        };
        // SAFETY: resume an owned stopped tid, optionally with delivery.
        // Errors are ignored: the targeted wait below observes
        // whatever the tid did next.
        unsafe { libc::ptrace(libc::PTRACE_SYSCALL, tid, 0, data) };
        held = Some(wait_for_event(
            Some(tid),
            deadline,
            pid,
            &mut tids,
            main_reaped,
        )?);
    }
}

/// F16: deadline-aware wait for `target` (one tid) or, when None,
/// a round-robin poll over every tracked tid. Every wait is
/// tid-specific: parallel audits and other tests' children never
/// exchange events (a waitpid(-1) here would steal them). On
/// deadline: SIGKILLs every tracked tid — group leaders die with
/// their threads, ESRCH on plain members is harmless — drains every
/// exit, and reports the timeout. ECHILD for the main means this
/// tracer lost it, which is a loud error, never silence; ECHILD
/// for any other tracked tid is a stale exec-renumber (see
/// [`waitpid_one`]) and drops the number.
#[cfg(target_arch = "x86_64")]
fn wait_for_event(
    target: Option<libc::pid_t>,
    deadline: Instant,
    main: libc::pid_t,
    tids: &mut HashMap<libc::pid_t, TidState>,
    main_reaped: &mut bool,
) -> Result<(libc::pid_t, i32), AuditError> {
    // A targeted wait whose number went stale (exec renumber)
    // degrades to broadcast: the affinity was promptness, not
    // correctness — every stop still classifies.
    let mut target = target;
    loop {
        if Instant::now() >= deadline {
            let unknowns = drain_tracked(tids, main, main_reaped);
            return Err(drained_err(format!("audit timed out{unknowns}"), tids));
        }
        // Snapshot: births register through parent fork events the
        // caller decodes, so the set only grows between polls and a
        // stopped birth simply waits its turn.
        let watch: Vec<libc::pid_t> = match target {
            Some(t) => vec![t],
            None => tids.keys().copied().collect(),
        };
        for t in watch {
            match waitpid_one(t) {
                Ok(WaitOne::Status(status)) => return Ok((t, status)),
                Ok(WaitOne::None) => {}
                Ok(WaitOne::StaleNumber) => {
                    // The leader never renumbers, so its ECHILD is
                    // a genuinely lost tracer link: loud, as before.
                    if t == main {
                        let unknowns = drain_tracked(tids, main, main_reaped);
                        return Err(drained_err(format!("tracer lost tid {t}{unknowns}"), tids));
                    }
                    tids.remove(&t);
                    if Some(t) == target {
                        target = None;
                    }
                }
                // R31: wait failures retire the remaining tracees
                // before reporting; survivors are named.
                Err(error) => {
                    let unknowns = drain_tracked(tids, main, main_reaped);
                    return Err(drained_err(format!("{}{unknowns}", error.detail), tids));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// R31: an error that names the tracees a bounded retirement could
/// not finish, so unresolved ownership is reported, never dropped.
#[cfg(target_arch = "x86_64")]
fn drained_err(detail: impl Into<String>, tids: &HashMap<libc::pid_t, TidState>) -> AuditError {
    let detail = detail.into();
    if tids.is_empty() {
        return AuditError::new(detail);
    }
    let mut stuck: Vec<libc::pid_t> = tids.keys().copied().collect();
    stuck.sort_unstable();
    AuditError::new(format!("{detail}; unresolved tracees: {stuck:?}"))
}

/// One nonblocking reap-check for exactly one tracee.
#[cfg(target_arch = "x86_64")]
enum WaitOne {
    Status(i32),
    None,
    /// ECHILD: the number is freed. Every registration here is
    /// wait-observed and no wait-stealer exists (all waits are
    /// tid-specific; the only other waiter reaps just the main
    /// after the loop), so a freed non-leader number is an
    /// exec-renumber — the task lives on under the leader number
    /// and the pending EXEC event reconciles it — never a silent
    /// death (traced deaths always report). The caller drops the
    /// number, or fails loud for the leader itself.
    StaleNumber,
}

#[cfg(target_arch = "x86_64")]
fn waitpid_one(tid: libc::pid_t) -> Result<WaitOne, AuditError> {
    let mut status = 0;
    // SAFETY: valid status out-pointer for an owned tracee.
    let result = unsafe { libc::waitpid(tid, &mut status, libc::WNOHANG) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(WaitOne::None);
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(WaitOne::StaleNumber);
        }
        return Err(AuditError::new(format!("audit wait: {error}")));
    }
    if result == 0 {
        return Ok(WaitOne::None);
    }
    Ok(WaitOne::Status(status))
}

/// Reap-check one tid after a failed resume: true when it had exited.
#[cfg(target_arch = "x86_64")]
fn try_reap(
    tid: libc::pid_t,
    main: libc::pid_t,
    report: &mut AuditReport,
    tids: &mut HashMap<libc::pid_t, TidState>,
) -> bool {
    let mut status = 0;
    // SAFETY: valid status out-pointer for an owned tracee.
    let result = unsafe { libc::waitpid(tid, &mut status, libc::WNOHANG) };
    if result != tid {
        return false;
    }
    if libc::WIFEXITED(status) {
        if tid == main {
            report.exit_code = Some(libc::WEXITSTATUS(status));
        }
        tids.remove(&tid);
        return true;
    }
    if libc::WIFSIGNALED(status) {
        tids.remove(&tid);
        return true;
    }
    false
}

/// Retire every tracked tracee: a fatal signal first (running or
/// stopped), then reap every exit. Stop statuses are resumed with a
/// fatal signal, and fork births racing the kill register through
/// their parent's event so they die too; ECHILD here means gone
/// (only death matters in the drain). The grace bound caps D-state
/// hangs; survivors stay in the set for [`drained_err`] to name.
/// R26: flags the main when it reaps it (or when waitpid proves it
/// gone), so no stale PID is signalled. S31: finishes with the
/// unknown-tracee sweep and returns its error-text suffix (empty
/// when nothing was unknown).
#[cfg(target_arch = "x86_64")]
fn drain_tracked(
    tids: &mut HashMap<libc::pid_t, TidState>,
    main: libc::pid_t,
    main_reaped: &mut bool,
) -> String {
    // R31: retirement starts here, not at the call sites: running
    // tids get the same fatal signal stopped ones do.
    for tid in tids.keys() {
        // SAFETY: signal an owned tracee.
        unsafe { libc::kill(*tid, libc::SIGKILL) };
        // S31: resume a consumed stop with fatal delivery. A
        // ptrace-stopped tracee holds SIGKILL pending until resumed,
        // and its already-consumed stop reports no new status, so
        // the signal alone would spin the grace out and strand it.
        // SAFETY: resume an owned tracee with a fatal signal; the
        // error on a running tid is harmless and ignored.
        unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                *tid,
                0,
                libc::SIGKILL as *mut libc::c_void,
            );
        }
    }
    // S31: unknowns retire BEFORE the first reap pass: a dead
    // leader reports nothing while an unknown sibling thread lives
    // (waitpid on the group waits for the last thread), so reaping
    // first would burn the whole grace. A second sweep/reap round
    // catches births racing the first pass.
    let first = reconcile_unknown_tracees(tids);
    reap_tracked(tids, main, main_reaped, Duration::from_secs(10));
    let second = reconcile_unknown_tracees(tids);
    reap_tracked(tids, main, main_reaped, Duration::from_secs(2));
    format!("{first}{second}")
}

/// Bounded reap pass over the tracked set (split from
/// [`drain_tracked`] so the unknown sweep can unblock leaders
/// between passes).
#[cfg(target_arch = "x86_64")]
fn reap_tracked(
    tids: &mut HashMap<libc::pid_t, TidState>,
    main: libc::pid_t,
    main_reaped: &mut bool,
    grace: Duration,
) {
    let end = Instant::now() + grace;
    while !tids.is_empty() && Instant::now() < end {
        let live: Vec<libc::pid_t> = tids.keys().copied().collect();
        let mut progress = false;
        for t in live {
            let mut status = 0;
            // SAFETY: valid status out-pointer for an owned tracee.
            let result = unsafe { libc::waitpid(t, &mut status, libc::WNOHANG) };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // S32: only ECHILD proves the number freed (no signal
                // may ever target it again). Any other failure — EPERM
                // from a caller seccomp denial, EIO — is an
                // observation failure, not a death: the tid stays in
                // unresolved custody (no progress, so the grace bound
                // below caps the retry) and `drained_err` names it.
                if error.raw_os_error() != Some(libc::ECHILD) {
                    continue;
                }
                tids.remove(&t);
                if t == main {
                    *main_reaped = true;
                }
                progress = true;
                continue;
            }
            if result == 0 {
                continue;
            }
            progress = true;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                tids.remove(&t);
                if t == main {
                    *main_reaped = true;
                }
                continue;
            }
            if libc::WIFSTOPPED(status) {
                let event = ((status >> 16) & 0xffff) as i64;
                if event == libc::PTRACE_EVENT_CLONE as i64
                    || event == libc::PTRACE_EVENT_FORK as i64
                    || event == libc::PTRACE_EVENT_VFORK as i64
                {
                    // Best-effort: a denied message here leaves the
                    // newborn unknown, and the sweep below retires it
                    // by tracer ownership instead of by number.
                    if let Ok(new) = event_msg(t) {
                        let new = new as libc::pid_t;
                        tids.entry(new).or_default();
                        // SAFETY: signal an owned tracee.
                        unsafe { libc::kill(new, libc::SIGKILL) };
                    }
                }
                // SAFETY: a stopped owned tracee takes a fatal resume.
                unsafe {
                    libc::ptrace(libc::PTRACE_CONT, t, 0, libc::SIGKILL as *mut libc::c_void);
                    libc::kill(t, libc::SIGKILL);
                }
            }
        }
        if !progress {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// S31: retire tracees this tracer owns but never registered (a
/// denied GETEVENTMSG hides the newborn tid from the birth arm, and
/// drain-time births race the kill). Selection is by tracer
/// ownership (`TracerPid` equals this thread), never by a guessed
/// number; DETACH-with-SIGKILL only acts on owned tracees, so a
/// recycled pid belonging to a stranger gets ESRCH, not a signal.
/// A re-read ownership proof precedes the plain-kill fallback for a
/// tracee DETACH could not retire. Waits are specific-pid only:
/// `waitpid(-1)` would steal other tests' children (F16). Tracked
/// tids are excluded: drain survivors keep their own reporting, and
/// only true unknowns retire here. Returns the error-text suffix
/// (empty when nothing was unknown).
#[cfg(target_arch = "x86_64")]
fn reconcile_unknown_tracees(tids: &HashMap<libc::pid_t, TidState>) -> String {
    // SAFETY: pure TID query, no state touched.
    let me = unsafe { libc::gettid() };
    let owned = |status_path: &str| -> bool {
        std::fs::read_to_string(status_path)
            .ok()
            .is_some_and(|text| {
                text.lines().any(|line| {
                    line.strip_prefix("TracerPid:")
                        .is_some_and(|value| value.trim() == me.to_string())
                })
            })
    };
    // Both process entries and per-task entries: a missed CLONE
    // birth strands a thread, whose TracerPid lives only under
    // `/proc/<pid>/task/<tid>/status`.
    let mut candidates: Vec<(libc::pid_t, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name
                .to_str()
                .and_then(|text| text.parse::<libc::pid_t>().ok())
            else {
                continue;
            };
            candidates.push((pid, format!("/proc/{pid}/status")));
            if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
                for task in tasks.flatten() {
                    if let Some(tid) = task
                        .file_name()
                        .to_str()
                        .and_then(|text| text.parse::<libc::pid_t>().ok())
                    {
                        candidates.push((tid, format!("/proc/{pid}/task/{tid}/status")));
                    }
                }
            }
        }
    }
    let mut unknown: Vec<(libc::pid_t, String)> = Vec::new();
    for (pid, status_path) in &candidates {
        if *pid == me || tids.contains_key(pid) || unknown.iter().any(|(known, _)| known == pid) {
            continue;
        }
        if owned(status_path) {
            unknown.push((*pid, status_path.clone()));
        }
    }
    if unknown.is_empty() {
        return String::new();
    }
    for (pid, status_path) in &unknown {
        // SAFETY: detach an owned tracee with a fatal delivery; a
        // stranger's recycled number fails here without effect, as
        // does an already-dead task (group SIGKILL beats the sweep
        // to sibling threads).
        if unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                *pid,
                0,
                libc::SIGKILL as *mut libc::c_void,
            )
        } == 0
        {
            continue;
        }
        if !owned(status_path) {
            continue;
        }
        // Still ours and DETACH refused: resume any consumed stop
        // with fatal delivery (a stopped tracee holds SIGKILL
        // pending until resumed), then insist.
        // SAFETY: resume/signal a re-proven owned tracee; the CONT
        // error on a running task is harmless.
        unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                *pid,
                0,
                libc::SIGKILL as *mut libc::c_void,
            );
            libc::kill(*pid, libc::SIGKILL);
        }
    }
    let end = Instant::now() + Duration::from_secs(2);
    let found = unknown.len();
    let mut unreaped: Vec<(libc::pid_t, String)> = unknown;
    while !unreaped.is_empty() && Instant::now() < end {
        unreaped.retain(|(pid, status_path)| {
            let mut status = 0;
            // SAFETY: valid out-pointer; the pid is ours or gone.
            let got = unsafe { libc::waitpid(*pid, &mut status, libc::WNOHANG) };
            if got == *pid {
                return false;
            }
            if got == 0 {
                return true;
            }
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                return true;
            }
            // A wait refusal settles only when the task is actually
            // gone: ECHILD for a lingering `/proc` entry keeps
            // waiting, and the bound names it honestly below.
            std::fs::read_to_string(status_path).is_ok()
        });
        if !unreaped.is_empty() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let mut unreaped: Vec<libc::pid_t> = unreaped.into_iter().map(|(pid, _)| pid).collect();
    unreaped.sort_unstable();
    format!("; unknown tracees: {found} found, unreaped: {unreaped:?}")
}

/// Read a ptrace event message (the newborn tid for clone/fork/vfork).
/// S31: the failure propagates. Without the newborn tid the child is
/// auto-attached yet untracked, and the known-tid poll can never see
/// it; swallowing the error would strand it stopped and invisible.
#[cfg(target_arch = "x86_64")]
fn event_msg(tid: libc::pid_t) -> Result<libc::c_ulong, std::io::Error> {
    let mut msg: libc::c_ulong = 0;
    // SAFETY: valid message out-pointer for a stopped owned tracee.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            tid,
            0,
            &mut msg as *mut libc::c_ulong as *mut libc::c_void,
        )
    };
    if result == 0 {
        Ok(msg)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// F15: after an exec by `exec_tid`, drop every other tracked tid
/// that is no longer traced by this process: an exec silently kills
/// its sibling threads (no wait event), and their numbers must not
/// linger. Live fork children keep their TracerPid; a reused number
/// belonging to a stranger does not match, so it drops too.
///
/// R25: the kernel reports the tracer task's TID, which differs from
/// the process ID when auditing from a worker thread — comparing
/// against the PID forgets live tracees. Proven-dead tids (their
/// status is gone) drop; any other read failure retains: uncertain
/// custody waits for a wait event or a loud ECHILD, never vanishes.
#[cfg(target_arch = "x86_64")]
fn prune_exec_siblings(exec_tid: libc::pid_t, tids: &mut HashMap<libc::pid_t, TidState>) {
    // SAFETY: pure TID query, no state touched.
    let me = unsafe { libc::gettid() }.to_string();
    tids.retain(|tid, _| {
        if *tid == exec_tid {
            return true;
        }
        match std::fs::read_to_string(format!("/proc/{tid}/status")) {
            Ok(text) => text.lines().any(|line| {
                line.strip_prefix("TracerPid:")
                    .is_some_and(|value| value.trim() == me)
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => true,
        }
    });
}

/// S05: register observation is fallible, and the failure must
/// propagate: without the entry sample the exit stop cannot be
/// attributed, and without the exit sample no result exists. `None`
/// (via [`decode_enter`]) remains reserved for syscalls the ledger
/// does not track.
#[cfg(target_arch = "x86_64")]
fn read_regs(pid: libc::pid_t) -> Result<libc::user_regs_struct, std::io::Error> {
    let mut regs = std::mem::MaybeUninit::<libc::user_regs_struct>::zeroed();
    // SAFETY: valid regs out-pointer for a stopped owned child.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            0,
            regs.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: filled by successful GETREGS.
    Ok(unsafe { regs.assume_init() })
}

#[cfg(target_arch = "x86_64")]
fn syscall_enter(pid: libc::pid_t) -> Result<Option<Pending>, std::io::Error> {
    let regs = read_regs(pid)?;
    Ok(decode_enter(pid, &regs))
}

/// Pure register decode behind [`syscall_enter`], split out so
/// register vectors (R46) test without a live tracee.
#[cfg(target_arch = "x86_64")]
fn decode_enter(pid: libc::pid_t, regs: &libc::user_regs_struct) -> Option<Pending> {
    let nr = regs.orig_rax as i64;
    if nr != libc::SYS_mmap && nr != libc::SYS_munmap && nr != libc::SYS_mremap {
        return None;
    }
    if nr == libc::SYS_munmap {
        return Some(Pending {
            nr,
            fd: -2,
            anonymous: false,
            dev: None,
            ino: None,
            path: None,
            addr: regs.rdi,
            len: regs.rsi,
            prot: 0,
            flags: 0,
            new_len: 0,
            unattributed: false,
        });
    }
    if nr == libc::SYS_mremap {
        // An mremap carries no fd: its object is whatever the old
        // address maps, resolved authoritatively from maps. S30: an
        // anonymous old address preserves that classification (an
        // anonymous remap is ordinary allocator activity, not an
        // unattributable file mapping); only an unresolvable old
        // address is unattributed (R28), exactly like an unreadable
        // mmap fd.
        let (anonymous, unattributed, dev, ino, path) = match mapping_class(pid, regs.rdi) {
            MappingClass::Anonymous => (true, false, None, None, None),
            MappingClass::File(dev, ino, path) => (false, false, Some(dev), Some(ino), path),
            MappingClass::Unidentified | MappingClass::Absent => (false, true, None, None, None),
        };
        // R46: x86-64 mremap is (old_addr=rdi, old_size=rsi,
        // new_size=rdx, flags=r10, new_addr=r8). Flags come from
        // r10; the new size rides separately, never as flag bits.
        return Some(Pending {
            nr,
            fd: -2,
            anonymous,
            unattributed,
            dev,
            ino,
            path,
            addr: regs.rdi,
            len: regs.rsi,
            prot: 0,
            flags: regs.r10 as u32,
            new_len: regs.rdx,
        });
    }
    let fd = regs.r8 as i32;
    let flags = regs.r10 as u32;
    let anonymous = fd < 0 || flags & libc::MAP_ANONYMOUS as u32 != 0;
    let (dev, ino, path) = if anonymous || fd < 0 {
        (None, None, None)
    } else {
        fd_identity(pid, fd)
    };
    // R28: a file-backed map whose fd identity is unreadable (the
    // subject went non-dumpable, or the fd is otherwise denied) is
    // unattributed from here on, never silently clean.
    let unattributed = !anonymous && fd >= 0 && dev.is_none();
    Some(Pending {
        nr,
        fd,
        anonymous,
        dev,
        ino,
        path,
        addr: regs.rdi,
        len: regs.rsi,
        prot: regs.rdx as u32,
        flags,
        new_len: 0,
        unattributed,
    })
}

#[cfg(target_arch = "x86_64")]
fn syscall_exit(
    pid: libc::pid_t,
    call: Pending,
    config: &AuditConfig,
    report: &mut AuditReport,
) -> Result<(), std::io::Error> {
    if report.mmaps.len() + report.munmaps.len() >= config.max_entries {
        report.truncated = true;
        return Ok(());
    }
    // S05: a denied exit sample is an incomplete audit, never a
    // fabricated `result=-1` (which would record a successful mapping
    // as failed).
    let result = read_regs(pid).map(|regs| regs.rax as i64)?;
    if call.nr == libc::SYS_munmap {
        report.munmaps.push(MunmapEvent {
            addr: call.addr,
            len: call.len,
            result,
        });
        return Ok(());
    }
    // R29: a successful file-backed map attributes only when the
    // enter sample and the authoritative maps row at exit agree. A
    // descriptor swapped mid-call, a mapping raced away by another
    // thread, or an unreadable table marks the success
    // unattributed instead of silently clean. (For mremap the
    // enter sample is the old address's object and the exit check
    // binds the new address to it.)
    let mut unattributed = call.unattributed;
    if !call.anonymous && !(-4095..=-1).contains(&result) {
        let confirmed = match (call.dev, call.ino) {
            (Some(dev), Some(ino)) => mapped_object(pid, result as u64)
                .is_some_and(|(mdev, mino, _)| mdev == dev && mino == ino),
            _ => false,
        };
        if !confirmed {
            unattributed = true;
        }
    }
    // S30: the R29 binding for an anonymous remap: a successful
    // mremap of anonymous memory lands anonymous (the kernel unmaps
    // any FIXED destination first). A missing or file-backed new
    // address is incoherent and marks the success unattributed.
    if call.anonymous && call.nr == libc::SYS_mremap && !(-4095..=-1).contains(&result) {
        if mapping_class(pid, result as u64) != MappingClass::Anonymous {
            unattributed = true;
        }
    }
    report.mmaps.push(MmapEvent {
        nr: call.nr,
        fd: call.fd,
        anonymous: call.anonymous,
        dev: call.dev,
        ino: call.ino,
        path: call.path,
        addr: call.addr,
        len: call.len,
        prot: call.prot,
        flags: call.flags,
        new_len: call.new_len,
        result,
        unattributed,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn laden(path: &str) -> serde_json::Value {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        // Unit tests run with the package root as CWD; the vectors
        // live in the workspace fixtures tree.
        let from_cwd = Path::new("../../fixtures/linux/mmap-audit").join(path);
        let from_pkg = root.join("../../fixtures/linux/mmap-audit").join(path);
        let bytes = std::fs::read(&from_cwd)
            .or_else(|_| std::fs::read(&from_pkg))
            .unwrap_or_else(|_| panic!("missing vector {path}"));
        serde_json::from_slice(&bytes).expect("vector parses")
    }

    fn check_schema(vector: &serde_json::Value) {
        assert_eq!(vector["schema"].as_str(), Some("tt04-mmap-ledger-v1"));
        for entry in vector["events"].as_array().expect("events") {
            assert!(entry["syscall"].is_string());
            assert!(entry["fd"].is_number());
            assert!(entry["anonymous"].is_boolean());
            assert!(entry["result"].is_number());
            if entry["anonymous"].as_bool().unwrap() {
                assert!(entry["dev"].is_null());
            } else if entry["syscall"] == "mmap" {
                assert!(entry["dev"].is_number());
                assert!(entry["ino"].is_number());
            }
        }
    }

    /// F17: the golden vectors apply the same raw-return rule as
    /// `MmapEvent::succeeded` (success is outside -4095..=-1).
    fn raw_succeeded(result: &serde_json::Value) -> bool {
        !(-4095..=-1).contains(&result.as_i64().expect("numeric result"))
    }

    #[test]
    fn golden_planted_transient_marks_target() {
        let vector = laden("planted-transient.json");
        check_schema(&vector);
        let events = vector["events"].as_array().unwrap();
        let hits = events
            .iter()
            .filter(|e| {
                e["syscall"] == "mmap"
                    && e["path"] == "/run/tt04/target.bin"
                    && raw_succeeded(&e["result"])
            })
            .count();
        assert_eq!(
            hits, 1,
            "planted vector must flag exactly one target map (the raw -EBADF entry is a failure)"
        );
        let hit = events
            .iter()
            .find(|e| {
                e["syscall"] == "mmap"
                    && e["path"] == "/run/tt04/target.bin"
                    && raw_succeeded(&e["result"])
            })
            .expect("planted target mmap present");
        let addr = hit["result"].as_u64().unwrap();
        assert!(
            events.iter().any(|e| {
                e["syscall"] == "munmap"
                    && e["addr"].as_u64().unwrap() <= addr
                    && addr < e["addr"].as_u64().unwrap() + e["len"].as_u64().unwrap()
            }),
            "planted transient lacks its munmap close"
        );
    }

    #[test]
    fn golden_clean_no_new_has_no_target_maps() {
        let vector = laden("clean-no-new.json");
        check_schema(&vector);
        let events = vector["events"].as_array().unwrap();
        assert!(
            events
                .iter()
                .any(|e| e["anonymous"].as_bool() == Some(true)),
            "clean vector must show allocator mmaps"
        );
        assert!(
            events
                .iter()
                .all(|e| { e["syscall"] != "mmap" || e["anonymous"].as_bool() == Some(true) }),
            "clean vector must not map the target"
        );
    }

    #[test]
    fn golden_vectors_classify_like_reports() {
        for name in ["planted-transient.json", "clean-no-new.json"] {
            let vector = laden(name);
            let events = vector["events"].as_array().unwrap();
            let target = events
                .iter()
                .filter(|e| {
                    e["syscall"] == "mmap"
                        && e["anonymous"].as_bool() == Some(false)
                        && raw_succeeded(&e["result"])
                })
                .count();
            if name.starts_with("planted") {
                assert_eq!(target, 1, "{name} must flag one target map");
            } else {
                assert_eq!(target, 0, "{name} must flag none");
            }
        }
    }

    fn event_with_result(result: i64) -> MmapEvent {
        MmapEvent {
            nr: 9,
            fd: 7,
            anonymous: false,
            dev: Some(37),
            ino: Some(101),
            path: None,
            addr: 0,
            len: 4096,
            prot: 1,
            flags: 2,
            new_len: 0,
            result,
            unattributed: false,
        }
    }

    // F17: raw -errno variety. Every value in -4095..=-1 is a
    // failure (the old `!= -1` rule passed all but -1 as success);
    // the boundaries just outside the range are successes.
    #[test]
    fn succeeded_decodes_raw_errno_range() {
        for (result, errno) in [
            (-4095, 4095),
            (-133, 133),
            (-22, 22),
            (-9, 9),
            (-2, 2),
            (-1, 1),
        ] {
            let event = event_with_result(result);
            assert!(!event.succeeded(), "raw {result} must fail");
            assert_eq!(event.errno(), Some(errno));
        }
        for result in [-4096, -65536, 0, 1, 4096, 139975124473856, i64::MAX] {
            let event = event_with_result(result);
            assert!(event.succeeded(), "raw {result} must succeed");
            assert_eq!(event.errno(), None);
        }
    }

    /// R29: `mapped_object` binds a live file mapping to its
    /// (device, inode) and reports nothing once it is gone. The
    /// test maps a real file with raw mmap so the oracle is the
    /// kernel itself; a second file proves the comparison the
    /// exit stop makes can genuinely fail.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mapped_object_binds_live_mapping() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = std::env::temp_dir().join(format!("audit-maps-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.bin");
        std::fs::write(&file, vec![7u8; 8192]).unwrap();
        let other = dir.join("b.bin");
        std::fs::write(&other, vec![9u8; 8192]).unwrap();
        let path = std::ffi::CString::new(file.to_string_lossy().into_owned()).unwrap();
        // SAFETY: raw open/mmap/munmap with checked results.
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
            assert!(fd >= 0);
            let addr = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(addr, libc::MAP_FAILED);
            let me = std::process::id() as libc::pid_t;
            let st = std::fs::metadata(&file).unwrap();
            let found = mapped_object(me, addr as u64).expect("live map binds");
            assert_eq!((found.0, found.1), (st.dev(), st.ino()));
            assert!(found.2.is_some_and(|p| p.contains("a.bin")));
            let ost = std::fs::metadata(&other).unwrap();
            assert_ne!(
                (found.0, found.1),
                (ost.dev(), ost.ino()),
                "distinct files must not compare equal"
            );
            let mid = mapped_object(me, addr as u64 + 2000).expect("mid-page binds");
            assert_eq!((mid.0, mid.1), (st.dev(), st.ino()));
            assert_eq!(libc::munmap(addr, 4096), 0);
            assert!(
                mapped_object(me, addr as u64)
                    .is_none_or(|(dev, ino, _)| (dev, ino) != (st.dev(), st.ino())),
                "withdrawn map must not bind the file"
            );
            libc::close(fd);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// R46: mremap decodes flags from r10 with the old and new
    /// sizes on separate registers (rsi/rdx), so size bits never
    /// leak into the flag ledger. The vector uses three distinct
    /// values, which the old rdx-as-flags decode fails.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mremap_decodes_flags_and_lengths_from_distinct_registers() {
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = libc::SYS_mremap as u64;
        regs.rdi = 0xdead_0000;
        regs.rsi = 0x1000;
        regs.rdx = 0x2000;
        regs.r10 = 0x3;
        let me = std::process::id() as libc::pid_t;
        let pending = decode_enter(me, &regs).expect("mremap decodes");
        assert_eq!(pending.flags, 0x3, "flags must come from r10");
        assert_eq!(pending.len, 0x1000, "old size must come from rsi");
        assert_eq!(pending.new_len, 0x2000, "new size must come from rdx");
    }

    /// R29: a mapping whose file is unlinked while mapped
    /// attributes nothing: the deleted name no longer identifies
    /// the object, so it must not confirm any sample.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mapped_object_refuses_deleted_pathname() {
        let dir = std::env::temp_dir().join(format!("audit-maps-del-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("gone.bin");
        std::fs::write(&file, vec![3u8; 8192]).unwrap();
        let path = std::ffi::CString::new(file.to_string_lossy().into_owned()).unwrap();
        // SAFETY: raw open/mmap/unlink/munmap with checked results.
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
            assert!(fd >= 0);
            let addr = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(addr, libc::MAP_FAILED);
            let me = std::process::id() as libc::pid_t;
            assert!(mapped_object(me, addr as u64).is_some());
            assert_eq!(libc::unlink(path.as_ptr()), 0);
            assert!(
                mapped_object(me, addr as u64).is_none(),
                "deleted name must not attribute"
            );
            assert_eq!(libc::munmap(addr, 4096), 0);
            libc::close(fd);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// R31: `drain_tracked` retires running children (not just
    /// stopped tracees), flags the reaped main, and empties the
    /// set. Both sleepers are fully reaped: no zombies linger.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn drain_tracked_kills_and_reaps_all() {
        use std::process::{Command, Stdio};
        let kids: Vec<std::process::Child> = (0..2)
            .map(|_| {
                Command::new("sleep")
                    .arg("30")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("sleep spawns")
            })
            .collect();
        let main = kids[0].id() as libc::pid_t;
        let other = kids[1].id() as libc::pid_t;
        let mut tids = HashMap::new();
        tids.insert(main, TidState::default());
        tids.insert(other, TidState::default());
        let mut main_reaped = false;
        let unknowns = drain_tracked(&mut tids, main, &mut main_reaped);
        assert!(
            unknowns.is_empty(),
            "drain swept unexpected unknowns: {unknowns}"
        );
        assert!(
            tids.is_empty(),
            "drain left {:?}",
            tids.keys().collect::<Vec<_>>()
        );
        assert!(main_reaped, "drain did not flag the reaped main");
        for pid in [main, other] {
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "drain left {pid} alive or zombie"
            );
        }
    }

    /// R31: errors after a bounded retirement name the survivors in
    /// sorted order; a complete drain reports the bare detail.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn drained_err_names_survivors() {
        let empty: HashMap<libc::pid_t, TidState> = HashMap::new();
        assert_eq!(drained_err("boom", &empty).to_string(), "boom");
        let mut stuck = HashMap::new();
        stuck.insert(4321, TidState::default());
        stuck.insert(1234, TidState::default());
        assert_eq!(
            drained_err("boom", &stuck).to_string(),
            "boom; unresolved tracees: [1234, 4321]"
        );
    }

    /// R26: the tracer flags the main reaped on the exit, signal,
    /// and timeout paths, so the outer cleanup never signals the
    /// stale PID. Each leg spawns a TRACEME child exactly like
    /// `audit_subject` and drives `trace_loop` directly. Live
    /// ptrace, gated on preflight like the cell tests.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn trace_loop_flags_reaped_main() {
        use std::os::unix::process::CommandExt as _;
        if preflight().is_err() {
            eprintln!("SKIP trace_loop_flags_reaped_main: ptrace refused");
            return;
        }
        fn spawn_traced(program: &str, args: &[&str]) -> std::process::Child {
            unsafe {
                std::process::Command::new(program)
                    .args(args)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .pre_exec(|| {
                        if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == 0 {
                            Ok(())
                        } else {
                            Err(std::io::Error::last_os_error())
                        }
                    })
                    .spawn()
                    .expect("tracee spawns")
            }
        }
        fn blank_report() -> AuditReport {
            AuditReport {
                exit_code: None,
                target_dev: 1,
                target_ino: 2,
                mmaps: Vec::new(),
                munmaps: Vec::new(),
                truncated: false,
                threads_seen: 0,
            }
        }
        let config = AuditConfig {
            target_dev: 1,
            target_ino: 2,
            max_entries: 4096,
            timeout: Duration::from_secs(30),
        };
        // Exit leg: /bin/true runs to status 0.
        let child = spawn_traced("true", &[]);
        let pid = child.id() as libc::pid_t;
        let mut report = blank_report();
        let mut reaped = false;
        trace_loop(
            pid,
            &config,
            Instant::now() + Duration::from_secs(30),
            &mut report,
            &mut reaped,
        )
        .expect("true traces");
        assert!(reaped, "exit leg did not flag the reaped main");
        assert_eq!(report.exit_code, Some(0));
        drop(child);
        // Signal leg: the main dies by SIGTERM, no exit status.
        let child = spawn_traced("sh", &["-c", "kill -TERM $$"]);
        let pid = child.id() as libc::pid_t;
        let mut report = blank_report();
        let mut reaped = false;
        trace_loop(
            pid,
            &config,
            Instant::now() + Duration::from_secs(30),
            &mut report,
            &mut reaped,
        )
        .expect("signalled main traces");
        assert!(reaped, "signal leg did not flag the reaped main");
        assert_eq!(report.exit_code, None);
        drop(child);
        // Timeout leg: sleep 30 against a 300ms deadline.
        let child = spawn_traced("sleep", &["30"]);
        let pid = child.id() as libc::pid_t;
        let mut report = blank_report();
        let mut reaped = false;
        let error = trace_loop(
            pid,
            &config,
            Instant::now() + Duration::from_millis(300),
            &mut report,
            &mut reaped,
        )
        .expect_err("sleep must time out");
        assert!(
            error.to_string().contains("timed out"),
            "unexpected timeout error: {error}"
        );
        assert!(reaped, "timeout leg did not flag the reaped main");
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "timeout drain left the sleeper alive or zombie"
        );
        drop(child);
    }
}
