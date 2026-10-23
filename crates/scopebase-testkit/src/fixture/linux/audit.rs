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
//! NEW per the frozen FS10 design; no donor implements a syscall
//! tracer. The Yama-scope read in [`preflight`] ADAPTs the KryProbe
//! read idiom (crates/kryprobe-privilege/src/probe/host_rows.rs
//! @d153f3aa:118-127: unreadable/unparseable stays a recorded
//! unknown). x86_64 only; other architectures report unsupported.
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
    pub fn succeeded(&self) -> bool {
        self.result != -1
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
    let deadline = Instant::now() + config.timeout;
    let mut report = AuditReport {
        exit_code: None,
        target_dev: config.target_dev,
        target_ino: config.target_ino,
        mmaps: Vec::new(),
        munmaps: Vec::new(),
        truncated: false,
    };
    let outcome = trace_loop(pid, config, deadline, &mut report);
    // The subject must never leak, whatever the trace outcome was.
    let _ = child.kill();
    let _ = child.wait();
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
fn trace_loop(
    pid: libc::pid_t,
    config: &AuditConfig,
    deadline: Instant,
    report: &mut AuditReport,
) -> Result<(), AuditError> {
    // Initial exec-stop: the TRACEME child stops with SIGTRAP.
    wait_for_stop(pid, deadline, "exec-stop")?;
    // SAFETY: options on an owned ptrace-stopped child.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            0,
            libc::PTRACE_O_TRACESYSGOOD as *mut libc::c_void,
        )
    } != 0
    {
        return Err(AuditError::new("PTRACE_SETOPTIONS refused"));
    }
    let mut in_syscall = false;
    let mut pending: Option<Pending> = None;
    // A consumed stop awaiting classification (signal-forward path).
    let mut held: Option<i32> = None;
    loop {
        let status = match held.take() {
            Some(status) => status,
            None => {
                if Instant::now() >= deadline {
                    // SAFETY: signal an owned child.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    drain_exit(pid);
                    return Err(AuditError::new("audit timed out"));
                }
                // SAFETY: resume an owned ptrace-stopped child.
                if unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) } != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    // The subject may have exited between stops.
                    if exited(pid, &mut report.exit_code) {
                        return Ok(());
                    }
                    return Err(AuditError::new(format!("PTRACE_SYSCALL: {error}")));
                }
                let mut status = 0;
                // SAFETY: valid status out-pointer for an owned child.
                let result = unsafe { libc::waitpid(pid, &mut status, 0) };
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(AuditError::new(format!("audit wait: {error}")));
                }
                status
            }
        };
        if libc::WIFEXITED(status) {
            report.exit_code = Some(libc::WEXITSTATUS(status));
            return Ok(());
        }
        if libc::WIFSIGNALED(status) {
            return Ok(());
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        if sig == libc::SIGTRAP | 0x80 {
            in_syscall = !in_syscall;
            if in_syscall {
                pending = syscall_enter(pid);
            } else if let Some(call) = pending.take() {
                syscall_exit(pid, call, config, report);
            }
            continue;
        }
        if sig == libc::SIGTRAP {
            // Non-syscall trap (e.g. exec): resume without delivery.
            continue;
        }
        // A real signal: forward it so the subject, not the tracer,
        // decides its fate. The following stop is held for the same
        // classification instead of being dropped.
        // SAFETY: resume with signal delivery on an owned child.
        unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, sig as *mut libc::c_void) };
        let mut forwarded = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let forwarded_result = unsafe { libc::waitpid(pid, &mut forwarded, 0) };
        if forwarded_result < 0 {
            continue;
        }
        held = Some(forwarded);
    }
}

#[cfg(target_arch = "x86_64")]
fn wait_for_stop(pid: libc::pid_t, deadline: Instant, what: &str) -> Result<(), AuditError> {
    loop {
        if Instant::now() >= deadline {
            // SAFETY: signal an owned child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            drain_exit(pid);
            return Err(AuditError::new(format!("audit timed out at {what}")));
        }
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(AuditError::new(format!("audit wait: {error}")));
        }
        if result == 0 {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        if libc::WIFSTOPPED(status) {
            return Ok(());
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err(AuditError::new(format!("subject died before its {what}")));
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn exited(pid: libc::pid_t, exit_code: &mut Option<i32>) -> bool {
    let mut status = 0;
    // SAFETY: valid status out-pointer for an owned child.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if result != pid {
        return false;
    }
    if libc::WIFEXITED(status) {
        *exit_code = Some(libc::WEXITSTATUS(status));
        return true;
    }
    libc::WIFSIGNALED(status)
}

#[cfg(target_arch = "x86_64")]
fn drain_exit(pid: libc::pid_t) {
    loop {
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            return;
        }
        if result < 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
        // SAFETY: escalate on an owned child that ignores SIGKILL
        // only via ptrace stops; detach-free kill suffices here.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
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

    #[test]
    fn golden_planted_transient_marks_target() {
        let vector = laden("planted-transient.json");
        check_schema(&vector);
        let events = vector["events"].as_array().unwrap();
        let hit = events
            .iter()
            .find(|e| {
                e["syscall"] == "mmap" && e["path"] == "/run/tt04/target.bin" && e["result"] != -1
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
                        && e["result"] != serde_json::json!(-1)
                })
                .count();
            if name.starts_with("planted") {
                assert_eq!(target, 1, "{name} must flag one target map");
            } else {
                assert_eq!(target, 0, "{name} must flag none");
            }
        }
    }
}
