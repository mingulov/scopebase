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
//! it would re-stop forever). The audit runs until every traced
//! thread and child has exited; the config deadline backstops every
//! wait, so a deaf or hung subject fails loud instead of hanging.
//! Real SIGSTOP/SIGCONT job control of the subject is NOT supported.
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
    /// Raw return: map address or -errno.
    pub result: i64,
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
}

/// The preflight child: attempt TRACEME, report the errno byte,
/// exit. Syscalls and atomics only; diverges.
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
    // SAFETY: one byte to the inherited pipe, then exit.
    unsafe {
        libc::write(w, &code as *const u8 as *const _, 1);
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
        super::fork::fork_guarded((pipe[1], -1, -1), |child| child, || {
            preflight_child()
        })
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
    let outcome = trace_loop(pid, config, deadline, &mut report);
    // The subject must never leak, whatever the trace outcome was.
    // Bounded: the tracer already reaped or killed everything it
    // could; this only covers a main the tracer never saw exit.
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
    outcome?;
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

#[cfg(target_arch = "x86_64")]
#[derive(Default)]
struct TidState {
    in_syscall: bool,
    pending: Option<Pending>,
    /// A newborn thread's first stop is its birth SIGSTOP, which must
    /// be suppressed (forwarding it would re-stop forever). Cleared
    /// by that stop, or by any other first stop.
    newborn_sigstop: bool,
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
) -> Result<(), AuditError> {
    // Only the main thread exists yet; every birth below joins this set.
    let mut tids: HashMap<libc::pid_t, TidState> = HashMap::new();
    tids.insert(pid, TidState::default());
    report.threads_seen = 1;
    // Initial exec-stop: the TRACEME child stops with SIGTRAP.
    let (_, stop) = wait_for_event(Some(pid), deadline, &mut tids)?;
    if !libc::WIFSTOPPED(stop) {
        return Err(AuditError::new("subject died before its exec-stop"));
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
                | libc::PTRACE_O_TRACEEXEC)
                as *mut libc::c_void,
        )
    } != 0
    {
        return Err(AuditError::new("PTRACE_SETOPTIONS refused"));
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
                            if tids.is_empty() {
                                return Ok(());
                            }
                            continue;
                        }
                        return Err(AuditError::new(format!("PTRACE_SYSCALL: {error}")));
                    }
                }
                if tids.is_empty() {
                    return Ok(());
                }
                wait_for_event(None, deadline, &mut tids)?
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
            }
            tids.remove(&tid);
            if tids.is_empty() {
                return Ok(());
            }
            continue;
        }
        if libc::WIFSIGNALED(status) {
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
            if let Some(state) = tids.get_mut(&tid) {
                state.in_syscall = !state.in_syscall;
                if state.in_syscall {
                    state.pending = syscall_enter(tid);
                } else if let Some(call) = state.pending.take() {
                    syscall_exit(tid, call, config, report);
                }
                state.newborn_sigstop = false;
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
                if let Some(new) = event_msg(tid) {
                    let new = new as libc::pid_t;
                    if !tids.contains_key(&new) {
                        tids.insert(new, TidState::newborn());
                        report.threads_seen += 1;
                    }
                }
            } else if event == libc::PTRACE_EVENT_EXEC as i64 {
                // An exec silently kills its sibling threads: prune
                // tracked tids that are no longer traced by us.
                prune_exec_siblings(tid, &mut tids);
            }
            // Event and plain-trap stops resume without delivery.
            if let Some(state) = tids.get_mut(&tid) {
                state.newborn_sigstop = false;
            }
            resume = Some(tid);
            continue;
        }
        // A real signal: forward it so the subject, not the tracer,
        // decides its fate — except a newborn's birth SIGSTOP, which
        // is suppressed (delivering it would re-stop forever). The
        // following stop is held for the same classification instead
        // of being dropped. The deadline backstops this wait like
        // every other, so a signal that re-traps fails loud.
        let suppress =
            sig == libc::SIGSTOP && tids.get(&tid).is_some_and(|s| s.newborn_sigstop);
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
        held = Some(wait_for_event(Some(tid), deadline, &mut tids)?);
    }
}

/// F16: deadline-aware wait for `target` (one tid) or, when None,
/// a round-robin poll over every tracked tid. Every wait is
/// tid-specific: parallel audits and other tests' children never
/// exchange events (a waitpid(-1) here would steal them). On
/// deadline: SIGKILLs every tracked tid — group leaders die with
/// their threads, ESRCH on plain members is harmless — drains every
/// exit, and reports the timeout. ECHILD for a tracked tid means
/// this tracer lost it, which is a loud error, never silence.
#[cfg(target_arch = "x86_64")]
fn wait_for_event(
    target: Option<libc::pid_t>,
    deadline: Instant,
    tids: &mut HashMap<libc::pid_t, TidState>,
) -> Result<(libc::pid_t, i32), AuditError> {
    loop {
        if Instant::now() >= deadline {
            // SAFETY: signal owned tracees.
            for tid in tids.keys() {
                unsafe { libc::kill(*tid, libc::SIGKILL) };
            }
            drain_tracked(tids);
            return Err(AuditError::new("audit timed out"));
        }
        // Snapshot: births register through parent fork events the
        // caller decodes, so the set only grows between polls and a
        // stopped birth simply waits its turn.
        let watch: Vec<libc::pid_t> = match target {
            Some(t) => vec![t],
            None => tids.keys().copied().collect(),
        };
        for t in watch {
            if let Some(status) = waitpid_one(t)? {
                return Ok((t, status));
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// One nonblocking reap-check for exactly one tracee.
#[cfg(target_arch = "x86_64")]
fn waitpid_one(tid: libc::pid_t) -> Result<Option<i32>, AuditError> {
    let mut status = 0;
    // SAFETY: valid status out-pointer for an owned tracee.
    let result = unsafe { libc::waitpid(tid, &mut status, libc::WNOHANG) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(None);
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Err(AuditError::new(format!("tracer lost tid {tid}")));
        }
        return Err(AuditError::new(format!("audit wait: {error}")));
    }
    if result == 0 {
        return Ok(None);
    }
    Ok(Some(status))
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

/// Drain every tracked exit after a timeout kill. Stop statuses
/// are resumed with a fatal signal, and fork births racing the kill
/// register through their parent's event so they die too; ECHILD
/// here means gone (only death matters in the drain). The grace
/// bound caps D-state hangs.
#[cfg(target_arch = "x86_64")]
fn drain_tracked(tids: &mut HashMap<libc::pid_t, TidState>) {
    let end = Instant::now() + Duration::from_secs(10);
    while !tids.is_empty() && Instant::now() < end {
        let live: Vec<libc::pid_t> = tids.keys().copied().collect();
        let mut progress = false;
        for t in live {
            let mut status = 0;
            // SAFETY: valid status out-pointer for an owned tracee.
            let result = unsafe { libc::waitpid(t, &mut status, libc::WNOHANG) };
            if result < 0 {
                tids.remove(&t);
                progress = true;
                continue;
            }
            if result == 0 {
                continue;
            }
            progress = true;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                tids.remove(&t);
                continue;
            }
            if libc::WIFSTOPPED(status) {
                let event = ((status >> 16) & 0xffff) as i64;
                if event == libc::PTRACE_EVENT_CLONE as i64
                    || event == libc::PTRACE_EVENT_FORK as i64
                    || event == libc::PTRACE_EVENT_VFORK as i64
                {
                    if let Some(new) = event_msg(t) {
                        let new = new as libc::pid_t;
                        tids.entry(new).or_default();
                        // SAFETY: signal an owned tracee.
                        unsafe { libc::kill(new, libc::SIGKILL) };
                    }
                }
                // SAFETY: a stopped owned tracee takes a fatal resume.
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_CONT,
                        t,
                        0,
                        libc::SIGKILL as *mut libc::c_void,
                    );
                    libc::kill(t, libc::SIGKILL);
                }
            }
        }
        if !progress {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Read a ptrace event message (the newborn tid for clone/fork/vfork).
#[cfg(target_arch = "x86_64")]
fn event_msg(tid: libc::pid_t) -> Option<libc::c_ulong> {
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
        Some(msg)
    } else {
        None
    }
}

/// F15: after an exec by `exec_tid`, drop every other tracked tid
/// that is no longer traced by this process: an exec silently kills
/// its sibling threads (no wait event), and their numbers must not
/// linger. Live fork children keep their TracerPid; a reused number
/// belonging to a stranger does not match, so it drops too.
#[cfg(target_arch = "x86_64")]
fn prune_exec_siblings(exec_tid: libc::pid_t, tids: &mut HashMap<libc::pid_t, TidState>) {
    let me = std::process::id().to_string();
    tids.retain(|tid, _| {
        if *tid == exec_tid {
            return true;
        }
        std::fs::read_to_string(format!("/proc/{tid}/status"))
            .ok()
            .is_some_and(|text| {
                text.lines().any(|line| {
                    line.strip_prefix("TracerPid:")
                        .is_some_and(|value| value.trim() == me)
                })
            })
    });
}

#[cfg(target_arch = "x86_64")]
fn read_regs(pid: libc::pid_t) -> Option<libc::user_regs_struct> {
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
        return None;
    }
    // SAFETY: filled by successful GETREGS.
    Some(unsafe { regs.assume_init() })
}

#[cfg(target_arch = "x86_64")]
fn syscall_enter(pid: libc::pid_t) -> Option<Pending> {
    let regs = read_regs(pid)?;
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
        });
    }
    if nr == libc::SYS_mremap {
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
            flags: regs.rdx as u32,
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
    })
}

#[cfg(target_arch = "x86_64")]
fn syscall_exit(pid: libc::pid_t, call: Pending, config: &AuditConfig, report: &mut AuditReport) {
    if report.mmaps.len() + report.munmaps.len() >= config.max_entries {
        report.truncated = true;
        return;
    }
    let result = read_regs(pid).map(|regs| regs.rax as i64).unwrap_or(-1);
    if call.nr == libc::SYS_munmap {
        report.munmaps.push(MunmapEvent {
            addr: call.addr,
            len: call.len,
            result,
        });
        return;
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
        result,
    });
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
            result,
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
}
