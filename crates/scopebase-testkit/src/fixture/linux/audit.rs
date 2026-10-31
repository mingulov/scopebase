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
    let (w, release, release_w) = super::fork::slots();
    // S110-round8: close our copy of the release WRITE end first —
    // the parent's close must produce the EOF the barrier promises
    // (a retained write end strands a denied-write parent and child
    // in a mutual block). The report READ end stays open: read-end
    // retention cannot block the parent's EOF.
    if release_w >= 0 {
        // SAFETY: inherited end this child never uses.
        unsafe { libc::close(release_w) };
    }
    // S68-round6: parent-release handshake — block until the parent
    // has acquired the birth pidfd, so the pin can never address a
    // recycled number (the child cannot exit, hence cannot be
    // reaped, before the release). EOF releases too (a vanished
    // parent must not strand the child); EINTR retries.
    // S111-round8: any OTHER read outcome PARKS the child (pause
    // until the parent's bounded retirement signals it) — it must
    // never proceed to exit before acquisition. Proceeding on a
    // denied read would let the child fail TRACEME and exit before
    // the parent's pidfd_open, voiding the birth-pin claim against
    // a competing reaper. (Pause itself denied as well would spin
    // to the parent's bound — loud in time, never silent.)
    loop {
        let mut byte = [0u8; 1];
        // SAFETY: one byte from the inherited release pipe.
        let got = unsafe { libc::read(release, byte.as_mut_ptr() as *mut _, 1) };
        if got == 1 || got == 0 {
            break;
        }
        // SAFETY: errno location for this thread.
        if unsafe { libc::__errno_location().read() } == libc::EINTR {
            continue;
        }
        // Barrier unusable: park until retired.
        loop {
            // SAFETY: suspend until a signal arrives.
            unsafe { libc::pause() };
        }
    }
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
    preflight_inner()
}

/// S53: the register probe is x86_64-only at compile time, like the
/// tracer itself: a runtime `cfg!` cannot gate name resolution, and
/// `libc::PTRACE_GETREGS` does not exist on aarch64.
#[cfg(target_arch = "x86_64")]
fn preflight_inner() -> Result<String, AuditError> {
    preflight_x86_64()
}

/// S53: non-x86_64 builds refuse without referencing x86_64-only
/// ptrace requests.
#[cfg(not(target_arch = "x86_64"))]
fn preflight_inner() -> Result<String, AuditError> {
    Err(AuditError::new("tracer needs x86_64 registers"))
}

/// True when the calling thread's errno is `want`. Reads errno
/// immediately: callers must invoke it before any other libc call.
#[cfg(target_arch = "x86_64")]
fn last_errno_is(want: libc::c_int) -> bool {
    // SAFETY: errno location for this thread.
    unsafe { libc::__errno_location().read() == want }
}

/// True when a waitpid `status` reports a terminal (reaped) state:
/// exited or signaled. A stop or continue is a LIVE child — it
/// keeps custody, never discharges it.
#[cfg(target_arch = "x86_64")]
fn wait_status_terminal(status: libc::c_int) -> bool {
    libc::WIFEXITED(status) || libc::WIFSIGNALED(status)
}

/// True when SIGCHLD currently auto-reaps children — SIG_IGN
/// disposition or SA_NOCLDWAIT. Read-back only; touches no process
/// state. A failed read-back fails closed (unknown disposition is
/// treated as auto-reap).
/// S68-round6: twin of the toolchain invoke detector (which is
/// unix-wide while this module is x86_64-only — different cfg
/// homes, same logic); keep the two in sync.
#[cfg(target_arch = "x86_64")]
fn sigchld_auto_reaps() -> bool {
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: sigaction read-back (act NULL) for this process.
    let rc = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) };
    rc != 0 || old.sa_sigaction == libc::SIG_IGN || (old.sa_flags & libc::SA_NOCLDWAIT) != 0
}

/// Owns a preflight pidfd across the probe; closes on drop so every
/// refusal path releases it. `None` when the birth open failed
/// environmentally (callers then reap without signaling — never a
/// numeric kill — and report unresolved custody for survivors).
#[cfg(target_arch = "x86_64")]
struct PidfdGuard(Option<libc::c_int>);

#[cfg(target_arch = "x86_64")]
impl Drop for PidfdGuard {
    fn drop(&mut self) {
        if let Some(fd) = self.0 {
            // SAFETY: fd owned by this guard.
            unsafe { libc::close(fd) };
        }
    }
}

/// Send `sig` through a held pidfd; returns the raw errno (0 on
/// success). The fd pins OUR task: ESRCH proves OUR child was
/// reaped — a recycled number is unaddressable through it.
#[cfg(target_arch = "x86_64")]
fn pidfd_signal(fd: libc::c_int, sig: libc::c_int) -> libc::c_int {
    // SAFETY: pidfd_send_signal(pidfd, sig, NULL, 0).
    let sent = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, sig, 0, 0) };
    if sent == 0 {
        0
    } else {
        // SAFETY: errno location for this thread.
        unsafe { libc::__errno_location().read() }
    }
}

/// The outcome of signaling a preflight child exactly once.
#[cfg(target_arch = "x86_64")]
enum PreflightSignal {
    /// The signal was delivered, or delivery failed while the process
    /// still exists: proceed to the bounded reap loop.
    Pending,
    /// No such process at signal time (already reaped): nothing to
    /// signal and no custody to report.
    Gone,
    /// No stable authority and no proof of death: reap without
    /// signaling, and report unresolved custody for survivors.
    Uncertain,
}

/// S68: signal the preflight child through stable process authority.
///
/// S68-round5: `pidfd` is the birth-opened description — opened
/// before any observation, while the just-forked child is held
/// alive — so it pins OUR task across number recycling and the
/// SIGKILL can never land on a recycled same-UID process. There is
/// NO numeric fallback: without a pidfd the number is unprovable,
/// so ownership reports Uncertain and the caller reaps without
/// signaling. `ESRCH` through a HELD fd means OUR child was already
/// reaped — gone, never signaled.
/// S68-round6: NO late reacquisition either. Round-5 late-opened on
/// `None`, but a competing reaper can free and recycle the number
/// between the WNOHANG observation and the open — a late open that
/// succeeds on a replacement would SIGKILL a stranger. The `None`
/// path now only rechecks via `waitpid` (identity-safe: it reaps
/// OUR child or reports ECHILD, never a stranger) and otherwise
/// admits uncertainty.
#[cfg(target_arch = "x86_64")]
fn signal_preflight_child(pid: libc::pid_t, pidfd: Option<libc::c_int>) -> PreflightSignal {
    let Some(fd) = pidfd else {
        // No pin: re-check for proof of death, else admit
        // uncertainty — never a numeric kill, never a late open.
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let recheck = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if recheck == pid && wait_status_terminal(status) {
            return PreflightSignal::Gone;
        }
        if recheck < 0 && last_errno_is(libc::ECHILD) {
            return PreflightSignal::Gone;
        }
        return PreflightSignal::Uncertain;
    };
    let errno = pidfd_signal(fd, libc::SIGKILL);
    if errno == libc::ESRCH {
        return PreflightSignal::Gone;
    }
    PreflightSignal::Pending
}

/// S52: retire a preflight child after a failed parent step. The
/// child may be stopped (CONT denied) or unwaitable (wait denied),
/// so SIGKILL first, then a bounded reap. Returns true when the pid
/// is proven gone.
///
/// S68-round4: ECHILD classifies BEFORE any signal — the first reap
/// attempt may already report it (a competing reaper), and the
/// number is then unreserved.
/// S52-round4: only `ESRCH` proves absence. Any other existence-probe
/// failure (`EPERM` under a kill-denying filter, ...) means
/// present-but-unobservable — never gone. The SIGKILL result is no
/// longer ignored: `ESRCH` short-circuits to gone.
/// S52-round5: only TERMINAL wait statuses (exited/signaled) or
/// proven absence (ECHILD, ESRCH) discharge custody — a stop or
/// continue is a LIVE child: signal it and keep reaping, never
/// return retired on the stop itself.
/// S68-round5: signaling runs through the birth-held pidfd; without
/// one the child is reaped-but-never-signaled and any survivor
/// reports unresolved custody after the bounded wait.
#[cfg(target_arch = "x86_64")]
fn retire_preflight_child(pid: libc::pid_t, pidfd: Option<libc::c_int>) -> bool {
    let mut status = 0;
    // SAFETY: valid status out-pointer for an owned child.
    let first = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if first == pid && wait_status_terminal(status) {
        return true;
    }
    if first < 0 && last_errno_is(libc::ECHILD) {
        return true;
    }
    if matches!(signal_preflight_child(pid, pidfd), PreflightSignal::Gone) {
        return true;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid && wait_status_terminal(status) {
            return true;
        }
        if waited < 0 {
            if last_errno_is(libc::ECHILD) {
                return true;
            }
        } else if waited == 0 {
            // No status to collect: probe OUR task for death.
            // The pidfd probe is exact (ESRCH proves OUR child
            // reaped); the numeric signum-0 probe below is an
            // existence OBSERVATION, not a signal delivery — it
            // cannot affect any process — and ESRCH soundly
            // proves OUR child gone (a live child, even a
            // zombie, would occupy the number).
            let gone = match pidfd {
                Some(fd) => pidfd_signal(fd, 0) == libc::ESRCH,
                None => {
                    // SAFETY: signal 0 probes existence without effect.
                    let probed = unsafe { libc::kill(pid, 0) };
                    probed != 0 && last_errno_is(libc::ESRCH)
                }
            };
            if gone {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(target_arch = "x86_64")]
fn preflight_x86_64() -> Result<String, AuditError> {
    // S68-round5: auto-reap makes the audit unwaitable — an exited
    // child vanishes instead of reporting its stop/exit statuses.
    // Refuse loudly instead of forking into unprovable custody.
    // S68-round6: the release handshake holds the child alive for
    // the birth pin, so acquisition itself is race-free; the
    // refusal stands because waiting needs a reaped-by-us child.
    // (Without auto-reap and without a competing reaper, our child
    // is alive-or-zombie — never recycled — at every observation.)
    if sigchld_auto_reaps() {
        return Err(AuditError::new(
            "preflight refused: SIGCHLD auto-reap (SIG_IGN or SA_NOCLDWAIT); cannot retain child custody",
        ));
    }
    let mut pipe = [0; 2];
    // SAFETY: valid out-pointer; ends checked below.
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return Err(AuditError::new("preflight pipe failed"));
    }
    // S68-round6: parent-release handshake pipe — the child blocks
    // in `read` on release[0] until the parent has acquired the
    // birth pidfd, so the pin can never address a recycled number
    // even against a competing reaper.
    let mut release = [0; 2];
    // SAFETY: valid out-pointer; ends checked below.
    if unsafe { libc::pipe(release.as_mut_ptr()) } != 0 {
        // SAFETY: ends owned by this scope.
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(AuditError::new("preflight release pipe failed"));
    }
    // SAFETY: the child runs only read/ptrace/write/_exit (syscalls
    // plus one atomic load), never allocating, locking, or
    // returning.
    let pid = unsafe {
        super::fork::fork_guarded(
            // S110-round8: the third slot carries the release
            // WRITE end so the child can close its copy (EOF
            // then works even when the release write is denied).
            (pipe[1], release[0], release[1]),
            |child| child,
            || preflight_child(),
        )
    };
    if pid < 0 {
        // SAFETY: ends owned by this scope.
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            libc::close(release[0]);
            libc::close(release[1]);
        }
        return Err(AuditError::new("preflight fork failed"));
    }
    // S68-round6: stable authority from birth — the child is
    // blocked in the release read (or parked, when the barrier is
    // denied — S111-round8), so it cannot exit (and cannot be
    // reaped) before this open: the pin addresses OUR task. The
    // guard closes on every path below.
    let pidfd = PidfdGuard(super::seccomp::pidfd_open_raw(pid).ok());
    // S110-round8: release the child — unconditional, even when
    // the birth open failed (authority then degrades to None, but
    // the child must never hang). The single-byte write retries on
    // EINTR; any other failure refuses through bounded retirement
    // instead of blocking on a report the child can no longer
    // deliver (a denied write denies its report write too). Ends
    // close on every path: with the child's own write end closed,
    // closing releases a barrier-blocked child via EOF.
    {
        let byte = [0u8; 1];
        // S139-round9: the retry deadline exists BEFORE the first
        // attempt — an EINTR-spamming write filter expires bounded
        // (through closure + retirement below), never spinning the
        // parent while the child waits.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut expired = false;
        let wrote = loop {
            // SAFETY: one byte to the release pipe; the child
            // holds the read end.
            let wrote = unsafe { libc::write(release[1], byte.as_ptr() as *const _, 1) };
            if wrote == 1 {
                break true;
            }
            if wrote < 0 && last_errno_is(libc::EINTR) {
                if std::time::Instant::now() >= deadline {
                    expired = true;
                    break false;
                }
                continue;
            }
            break false;
        };
        // Captured before the closes below (which may reset it).
        let write_error = std::io::Error::last_os_error();
        // SAFETY: ends owned by this scope.
        unsafe {
            libc::close(release[0]);
            libc::close(release[1]);
        }
        if !wrote {
            // SAFETY: report ends owned by this scope.
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            // The close above already released a
            // barrier-blocked child via EOF; the bounded
            // retirement reaps it (or reports it unproven).
            let retired = retire_preflight_child(pid, pidfd.0);
            // An expiry names its deadline (deliberately without
            // the "timed out" shape: only the barrier-timeout with
            // proven retirement classifies as expected).
            let cause = if expired {
                "EINTR retry deadline exceeded".to_string()
            } else {
                write_error.to_string()
            };
            return Err(AuditError::new(format!(
                "preflight release refused: {cause}{}",
                if retired {
                    String::new()
                } else {
                    "; preflight child not proven reaped".to_string()
                }
            )));
        }
    }
    // SAFETY: write end owned by this scope; the child holds its own.
    unsafe { libc::close(pipe[1]) };
    // S111-round8: the report read is poll-bounded (5s): a parked
    // child (barrier denied) never reports, and the parent must
    // refuse through bounded retirement instead of blocking
    // forever. A ready descriptor is read exactly once — the child
    // writes at most one byte before stopping or exiting.
    let mut code = [1u8; 1];
    let got = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32;
            if remaining <= 0 {
                // SAFETY: read end owned by this scope.
                unsafe { libc::close(pipe[0]) };
                let retired = retire_preflight_child(pid, pidfd.0);
                return Err(AuditError::new(format!(
                    "preflight report timed out (barrier unproven){}",
                    if retired {
                        String::new()
                    } else {
                        "; preflight child not proven reaped".to_string()
                    }
                )));
            }
            let mut waiting = libc::pollfd {
                fd: pipe[0],
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: valid pollfd for an owned descriptor.
            let ready = unsafe { libc::poll(&mut waiting, 1, remaining) };
            if ready < 0 {
                if last_errno_is(libc::EINTR) {
                    continue;
                }
                let error = std::io::Error::last_os_error();
                // SAFETY: read end owned by this scope.
                unsafe { libc::close(pipe[0]) };
                let retired = retire_preflight_child(pid, pidfd.0);
                return Err(AuditError::new(format!(
                    "preflight report poll refused: {error}{}",
                    if retired {
                        String::new()
                    } else {
                        "; preflight child not proven reaped".to_string()
                    }
                )));
            }
            if ready == 0 {
                continue;
            }
            // Ready (data or EOF): a single one-byte read.
            // SAFETY: one byte from the inherited pipe.
            break unsafe { libc::read(pipe[0], code.as_mut_ptr() as *mut _, 1) };
        }
    };
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
            // S68-round4: ECHILD classifies before any signal: the
            // child was already reaped (a competing reaper;
            // auto-reap is refused above) and the number is
            // unreserved — refuse without signaling it. No
            // unresolved custody: no child is left to retire.
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Err(AuditError::new(format!("preflight wait: {error}")));
            }
            // S52: an unwaitable child is not a gone child: kill
            // it before refusing, or a stopped orphan lingers.
            let retired = retire_preflight_child(pid, pidfd.0);
            return Err(AuditError::new(format!(
                "preflight wait: {error}{}",
                if retired {
                    String::new()
                } else {
                    "; preflight child not proven reaped".to_string()
                }
            )));
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
        // S52: an ignored CONT failure strands the child
        // stopped and the next waitpid blocks forever. Check the
        // resume, retire the child, and refuse instead.
        // SAFETY: continue an owned ptrace-stopped child.
        let resumed = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) };
        if resumed != 0 {
            let error = std::io::Error::last_os_error();
            let retired = retire_preflight_child(pid, pidfd.0);
            return Err(AuditError::new(format!(
                "preflight resume: {error}{}",
                if retired {
                    String::new()
                } else {
                    "; preflight child not proven reaped".to_string()
                }
            )));
        }
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
    audit_subject_x86_64(program, args, config, None)
}

/// S05-round3: test-only entry point with a post-entry arm hook. The
/// hook runs once, in the tracer thread, right after the first
/// mmap-family entry sample is recorded — the only point that can
/// deterministically fail the MATCHING exit sample (a seccomp filter
/// armed anywhere earlier fails the entry instead; anywhere later
/// races the exit). The denial driver arms its GETREGS denial here.
/// Production callers use [`audit_subject`].
#[doc(hidden)]
pub fn audit_subject_with_entry_hook(
    program: &Path,
    args: &[String],
    config: &AuditConfig,
    arm: &dyn Fn(),
) -> Result<AuditReport, AuditError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(AuditError::new("tracer needs x86_64 registers"));
    }
    audit_subject_x86_64(program, args, config, Some(arm))
}

#[cfg(target_arch = "x86_64")]
fn audit_subject_x86_64(
    program: &Path,
    args: &[String],
    config: &AuditConfig,
    arm: Option<&dyn Fn()>,
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
    let outcome = trace_loop(pid, config, deadline, &mut report, &mut main_reaped, arm);
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
// S53-round4: signature-compatible with the x86_64 implementation.
// The `cfg!` early returns above do not remove the four-argument
// calls from type checking, so the stub must accept the same
// arity (verified by the scoped cross-target check).
fn audit_subject_x86_64(
    _program: &Path,
    _args: &[String],
    _config: &AuditConfig,
    _arm: Option<&dyn Fn()>,
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
    arm: Option<&dyn Fn()>,
) -> Result<(), AuditError> {
    // S05-round3: the test-only arm hook fires once, after the first
    // recorded mmap-family entry, and never on the None path.
    let mut arm_pending = arm.is_some();
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
                        // S05-round3: a RECORDED mmap-family entry —
                        // the matching exit sample is now pending, so
                        // a denial armed here fails that exit and
                        // nothing earlier.
                        if arm_pending
                            && tids.get(&tid).is_some_and(|state| state.pending.is_some())
                        {
                            arm_pending = false;
                            if let Some(hook) = arm {
                                hook();
                            }
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

    /// IR-007: true when the suite runs as uid 0 — permission
    /// and ownership discriminators (chmod-000 unreadability,
    /// foreign-uid plants) do not exist for root, so tests
    /// staging them skip instead of failing.
    #[cfg(target_arch = "x86_64")]
    fn running_as_root() -> bool {
        // SAFETY: getuid queries only.
        unsafe { libc::getuid() == 0 }
    }

    /// /proc state letter of `pid` (None when unreadable/gone).
    #[cfg(target_arch = "x86_64")]
    fn proc_state(pid: libc::pid_t) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit_once(") ")?
            .1
            .split_whitespace()
            .next()?
            .chars()
            .next()
    }

    /// R12-005: in-process steerer serialization for audit
    /// lib tests (twin of the toolchain file's STEER_SERIAL —
    /// lib tests and integration tests are SEPARATE processes,
    /// so neither mutex covers the other; the file lock below
    /// is the cross-process half).
    #[cfg(target_arch = "x86_64")]
    static AUDIT_STEER_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// R12-005: cross-process ns_last_pid placement lock (twin
    /// of the toolchain file's guard — SAME lockfile path, kept
    /// in sync by hand): lib tests and integration tests run as
    /// separate (possibly concurrent) processes, and a foreign
    /// steer between our steer and our spawn corrupts
    /// exact-number placement. POSIX fcntl locks (NOT flock):
    /// flock locks leak into fork-only children (the lock
    /// survives our close on their inherited fd — the next
    /// holder blocks until they exit), while POSIX locks are
    /// dropped across fork. O_CLOEXEC keeps the fd out of
    /// exec'd children (their fd-count asserts would see it).
    /// NEVER NEST: same-process POSIX locks merge, so an inner
    /// drop would release the outer's lock — hold at most one
    /// (placement loops never nest). R13-009: locked_* helpers
    /// take this guard internally — never call them under a held
    /// guard (explicit drop/scope after placement first).
    #[cfg(target_arch = "x86_64")]
    struct NsLastPidFlock {
        fd: libc::c_int,
    }

    /// R12-005: take the cross-process placement lock
    /// (blocking; held for milliseconds across one
    /// steer-then-spawn placement loop).
    #[cfg(target_arch = "x86_64")]
    fn ns_last_pid_flock() -> NsLastPidFlock {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::env::temp_dir().join("scopebase-ns-last-pid.lock");
        let bytes = path.as_os_str().as_bytes();
        let cpath = std::ffi::CString::new(bytes).expect("lock path c-str");
        // SAFETY: valid path pointer; O_CLOEXEC documented above.
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
                0o600,
            )
        };
        assert!(fd >= 0, "placement lock opens");
        // SAFETY: F_SETLKW on an owned fd, whole-file write lock.
        let locked = unsafe {
            libc::fcntl(
                fd,
                libc::F_SETLKW,
                &libc::flock {
                    l_type: libc::F_WRLCK as libc::c_short,
                    l_whence: libc::SEEK_SET as libc::c_short,
                    l_start: 0,
                    l_len: 0,
                    l_pid: 0,
                },
            )
        };
        assert_eq!(locked, 0, "placement lock acquires");
        NsLastPidFlock { fd }
    }

    #[cfg(target_arch = "x86_64")]
    impl Drop for NsLastPidFlock {
        fn drop(&mut self) {
            // SAFETY: unlock-then-close an owned fd (never nest:
            // releasing here releases the process's lock).
            unsafe {
                libc::fcntl(
                    self.fd,
                    libc::F_SETLK,
                    &libc::flock {
                        l_type: libc::F_UNLCK as libc::c_short,
                        l_whence: libc::SEEK_SET as libc::c_short,
                        l_start: 0,
                        l_len: 0,
                        l_pid: 0,
                    },
                );
                libc::close(self.fd);
            }
        }
    }

    /// R13-009: unlocked allocator steer (rename of
    /// audit_steer_next_pid; twin of the toolchain file's
    /// unlocked steer). Call ONLY under a held placement guard
    /// (placement loops hold it across steer-then-spawn) or via
    /// [`audit_locked_steer_next_pid`]. Every other allocator
    /// write must take the lock: an unlocked write landing
    /// between another process's steer and fork invalidates its
    /// placement.
    #[cfg(target_arch = "x86_64")]
    fn audit_steer_next_pid_unlocked(want: i32) -> bool {
        use std::process::Stdio;
        let path = "/proc/sys/kernel/ns_last_pid";
        let text = format!("{}", want - 1);
        if std::fs::write(path, &text).is_ok() {
            return true;
        }
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("echo {text} | sudo -n tee {path} >/dev/null 2>&1"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// R13-009: allocator steer under the cross-process placement
    /// lock (twin of the toolchain file's locked steer — probes
    /// and restores, every write outside placement loops). NEVER
    /// call under a held guard: same-process POSIX locks merge,
    /// so this guard's drop would release the outer's lock (see
    /// NEVER NEST on the guard).
    #[cfg(target_arch = "x86_64")]
    fn audit_locked_steer_next_pid(want: i32) -> bool {
        let _lock = ns_last_pid_flock();
        audit_steer_next_pid_unlocked(want)
    }

    /// R13-009: bare hint restore under the cross-process
    /// placement lock (twin of the toolchain file's locked
    /// restore; same NEVER-NEST rule). Keeps the
    /// direct-write-only shape (no sudo fallback — a best-effort
    /// hint write, never load-bearing).
    #[cfg(target_arch = "x86_64")]
    fn audit_locked_restore_hint(last_before: &str) {
        let _lock = ns_last_pid_flock();
        let _ = std::fs::write("/proc/sys/kernel/ns_last_pid", last_before);
    }

    /// R12-005: python3 staged-probe marker — fork-only
    /// holders are staged probe-side (a probe-side fork
    /// inherits the piped stdio; an exec'd holder would lose
    /// the cloexec ends, and raw-fd stdio leaves
    /// child.stdout/stderr None so the drain never runs).
    /// Each script carries a unique marker comment so holders
    /// are nameable by (pgid, cmdline, birth) even after
    /// reparenting (the pgid survives it).
    #[cfg(target_arch = "x86_64")]
    const STAGED_PROBE_MARK: &str = "R12-005-STAGED-PROBE";

    /// R12-005: live (pid, starttime, pgid) tasks whose
    /// cmdline contains `mark` and born at/after `since`,
    /// excluding `exclude` — so a test can name probe-side
    /// fork-only holders by their script marker even after
    /// reparenting (cmdline + pgid survive it; ppid does not).
    #[cfg(target_arch = "x86_64")]
    fn audit_marked_tasks(
        mark: &str,
        since: u64,
        exclude: libc::pid_t,
    ) -> Vec<(libc::pid_t, u64, libc::pid_t)> {
        let mut found = Vec::new();
        let entries = std::fs::read_dir("/proc").into_iter().flatten().flatten();
        for entry in entries {
            let pid: libc::pid_t = match entry.file_name().to_string_lossy().parse() {
                Ok(pid) => pid,
                Err(_) => continue,
            };
            if pid == exclude {
                continue;
            }
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if !cmdline.windows(mark.len()).any(|w| w == mark.as_bytes()) {
                continue;
            }
            let row = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(row) => row,
                Err(_) => continue,
            };
            let fields = (|| {
                let after = row.rsplit_once(") ")?.1;
                let mut words = after.split_whitespace();
                let group = words.nth(2)?.parse::<libc::pid_t>().ok()?;
                let tick = words.nth(16)?.parse::<u64>().ok()?;
                Some((group, tick))
            })();
            if let Some((group, tick)) = fields {
                if tick >= since {
                    found.push((pid, tick, group));
                }
            }
        }
        found
    }

    /// R12-005: process group of `pid` (field 5 of
    /// /proc/PID/stat; None when unreadable/gone).
    #[cfg(target_arch = "x86_64")]
    fn proc_pgrp(pid: libc::pid_t) -> Option<libc::pid_t> {
        let row = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        row.rsplit_once(") ")?
            .1
            .split_whitespace()
            .nth(2)?
            .parse::<libc::pid_t>()
            .ok()
    }

    /// R12-005: settle whether `pid` survived a strike.
    /// Death is async (a SIGKILLed task shows R with the
    /// signal pending for µs-ms before reaching Z), so an
    /// instant aliveness read after a strike misreads murder
    /// as survival — and the first post-strike sample can even
    /// show empty-pending-live (strike/settle race at µs
    /// scale), so NEVER trust one sample: poll the FULL 500ms
    /// window and report spared only if EVERY sample shows a
    /// live task with an empty pending mask (our sleepers
    /// receive no other signals). Gone/Z/parse-failure, or any
    /// pending fatal at any sample, means struck (false —
    /// conservative: the strike landed).
    #[cfg(target_arch = "x86_64")]
    fn settle_spared(pid: libc::pid_t) -> bool {
        use std::time::{Duration, Instant};
        let end = Instant::now() + Duration::from_millis(500);
        loop {
            let row = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(row) => row,
                Err(_) => return false,
            };
            let observed = (|| {
                let after = row.rsplit_once(") ")?.1;
                let mut words = after.split_whitespace();
                let state = words.next()?.chars().next()?;
                let pending = words.nth(27)?.parse::<u64>().ok()?;
                Some((state, pending))
            })();
            match observed {
                Some(('Z', _)) | None => return false,
                Some((_, 0)) => {}
                Some((_, _)) => return false,
            }
            if Instant::now() >= end {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// R12-005: python3 presence for staged probes (fork-only
    /// holders are staged probe-side — see
    /// [`STAGED_PROBE_MARK`]).
    #[cfg(target_arch = "x86_64")]
    fn staged_probe_python3() -> bool {
        std::process::Command::new("python3")
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// Best-effort SIGKILL + reap on drop, so a failed retirement
    /// test never leaks a stopped child into the test process.
    /// S97-round6: the guard retains pidfd authority from birth and
    /// disarms on proved retirement. An armed drop signals through
    /// the pin (ESRCH-nop when already reaped — safe even when a
    /// test forgets to disarm); a disarmed drop is a pure no-op
    /// (never signals, never waits — misuse leaks instead of
    /// hanging). Disarm only after proved retirement.
    ///
    /// R10-007 regression seam: every trailing numeric wait is
    /// recorded so tests can require its absence after custody is
    /// discharged (a wait after discharge can only catch a recycled
    /// number owned by another test thread).
    #[cfg(target_arch = "x86_64")]
    static TRAILING_WAITS: std::sync::Mutex<Vec<libc::pid_t>> = std::sync::Mutex::new(Vec::new());

    #[cfg(target_arch = "x86_64")]
    fn take_trailing_waits() -> Vec<libc::pid_t> {
        std::mem::take(&mut TRAILING_WAITS.lock().unwrap())
    }

    /// Serializes the R10-007 tests: the trailing-wait log is
    /// process-global and drained per test, so concurrent R10
    /// tests could steal each other's entries. Other tests only
    /// push, and R10 assertions match per-pid, so holding this
    /// for the whole test body removes the flake.
    #[cfg(target_arch = "x86_64")]
    static R10_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(target_arch = "x86_64")]
    fn trailing_reap(pid: libc::pid_t) {
        TRAILING_WAITS.lock().unwrap().push(pid);
        // SAFETY: valid status out-pointer for an owned child;
        // ECHILD when already reaped elsewhere.
        unsafe {
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
    }

    #[cfg(target_arch = "x86_64")]
    struct ChildGuard {
        pid: libc::pid_t,
        pidfd: Option<libc::c_int>,
        armed: bool,
    }

    #[cfg(target_arch = "x86_64")]
    impl ChildGuard {
        fn new(pid: libc::pid_t) -> Self {
            ChildGuard {
                pid,
                pidfd: super::super::seccomp::pidfd_open_raw(pid).ok(),
                armed: true,
            }
        }

        /// Prove retirement: a disarmed drop signals nothing.
        fn disarm(&mut self) {
            self.armed = false;
        }
    }

    #[cfg(target_arch = "x86_64")]
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let pidfd = self.pidfd.take();
            if !self.armed {
                if let Some(fd) = pidfd {
                    // SAFETY: fd owned by this guard.
                    unsafe {
                        libc::close(fd);
                    }
                }
                return;
            }
            match pidfd {
                Some(fd) => {
                    // Pin-held kill: safe post-reap (ESRCH-nop
                    // names OUR task, never a recycled number).
                    let err = super::pidfd_signal(fd, libc::SIGKILL);
                    // SAFETY: fd owned by this guard.
                    unsafe {
                        libc::close(fd);
                    }
                    // R10-007: ESRCH through the pin proves OUR
                    // task is gone and reaped (a zombie still
                    // answers the signal) — there is nothing to
                    // wait for, and the number may already be
                    // recycled to another thread's child.
                    if err == libc::ESRCH {
                        return;
                    }
                }
                // S119-round8: no pin, NO numeric signal — the
                // number is unprovable without one.
                // R12-015: no pin, NO numeric WAIT either — not
                // even a WNOHANG recheck. A recheck after the
                // R11-018 helper already discharged the number
                // consumes a recycled number's status (another
                // test thread's zombie) — an ungated
                // post-discharge wait. R11-018 callers disarm
                // after proven retirement, so an armed pin-less
                // drop is always unproven: loud (stderr), never
                // a wait, never a stranger's death. (R10-007's
                // no-second-wait holds trivially — there is no
                // first wait.)
                None => {
                    eprintln!(
                        "ChildGuard: pin-less drop over unproven pid {}; \
                         NOT signaling, NOT waiting",
                        self.pid
                    );
                    return;
                }
            }
            trailing_reap(self.pid);
        }
    }

    /// R11-018: zombie-watch outcome. The failure arms return
    /// AFTER the owned child is retired, so the caller can
    /// skip or panic without leaking a zombie under ordinary
    /// SIGCHLD disposition. The zombie arm returns WITHOUT
    /// waiting (custody stays with the caller).
    #[cfg(target_arch = "x86_64")]
    enum ZombieWatch {
        Zombie,
        DeniedRetired,
        ExpiredRetired,
    }

    /// R11-018: retire an OWNED, NEVER-REAPED child: SIGKILL
    /// (best-effort) + blocking wait to ECHILD. Sound ONLY
    /// while the caller holds the child unreaped: the kernel
    /// cannot recycle the number of a live-or-zombie owned
    /// child, so the numeric signal/wait provably name OUR
    /// task — this is the owned-unreaped exception to the
    /// S119 no-numeric-signal rule (which governs
    /// possibly-recycled numbers). ESRCH/ECHILD are tolerated
    /// (a cleanup path must not fail on a lost race); EINTR
    /// retries. Never logs to TRAILING_WAITS: this wait
    /// precedes discharge by construction.
    #[cfg(target_arch = "x86_64")]
    fn retire_owned_unreaped(pid: libc::pid_t) {
        // SAFETY: numeric signal on an owned-unreaped child
        // (caller contract — the number cannot be recycled).
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        loop {
            let mut status = 0;
            // SAFETY: valid status out-pointer for an owned
            // child; ECHILD when already reaped elsewhere.
            let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
            if reaped == pid || (reaped < 0 && last_errno_is(libc::ECHILD)) {
                return;
            }
            if reaped < 0 && last_errno_is(libc::EINTR) {
                continue;
            }
            assert!(
                reaped >= 0,
                "retiring owned child {pid} failed unexpectedly"
            );
        }
    }

    /// R11-018: watch `pid` (an owned, never-reaped child)
    /// until it is a zombie, observation is denied, or
    /// `deadline` passes. The denied/expired arms retire the
    /// child (live-safe, not just zombie-safe) BEFORE
    /// returning. `observe` is a seam: production callers pass
    /// [`proc_state`]; the denied regression stubs it (a
    /// reaped pid would risk number recycle, and hiding real
    /// /proc needs namespaces — the stubbed arm is the same
    /// shipped code path).
    #[cfg(target_arch = "x86_64")]
    fn observe_zombie_or_retire(
        pid: libc::pid_t,
        deadline: std::time::Instant,
        observe: impl Fn(libc::pid_t) -> Option<char>,
    ) -> ZombieWatch {
        loop {
            match observe(pid) {
                Some('Z') => return ZombieWatch::Zombie,
                None => {
                    retire_owned_unreaped(pid);
                    return ZombieWatch::DeniedRetired;
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                retire_owned_unreaped(pid);
                return ZombieWatch::ExpiredRetired;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// S52-round5: an exited (zombie) child retires true on its
    /// terminal status. The zombie is observed via /proc first, so
    /// retirement is provably the first waiter (the ECHILD path is
    /// not what answers).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn retire_exited_child_proves_gone() {
        use std::time::{Duration, Instant};
        // SAFETY: child calls _exit only (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe { libc::_exit(42) };
        }
        let mut guard = ChildGuard::new(pid);
        if proc_state(pid).is_none() {
            eprintln!("skip: /proc unavailable for zombie observation");
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if proc_state(pid) == Some('Z') {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "child never reached zombie state"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            retire_preflight_child(pid, None),
            "a zombie child must retire on its terminal status"
        );
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(again < 0 && last_errno_is(libc::ECHILD));
        // S97-round6: retirement proved — disarm so the drop signals
        // nothing at the recycled number.
        guard.disarm();
    }

    /// Fork a preflight-shaped child: TRACEME, report the errno
    /// byte on `w`, stop when traced, exit otherwise. Returns the
    /// pid to the parent; the child diverges. Locals are visible
    /// post-fork, so no shared state is needed.
    #[cfg(target_arch = "x86_64")]
    fn fork_stop_child(w: libc::c_int) -> libc::pid_t {
        // SAFETY: child runs syscalls + _exit/pause only.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                // R12-008: shed inherited fds — this child never
                // execs (cloexec cannot help) and lives up to 5s
                // (the pin-less retirement burn), so any inherited
                // sibling pipe write end would hold EOF past 2s
                // guards. Keep only `w` (errno report) and stdio
                // (0,1,2 — shared, EOF-safe). close_range is a
                // single syscall (async-signal-safe, MT-fork
                // sound). Any failure exits WITHOUT reporting: the
                // parent's read then sees EOF (got == 0) and fails
                // loud — never a silent hole.
                if w > 3
                    && libc::syscall(
                        libc::SYS_close_range,
                        3 as libc::c_long,
                        (w - 1) as libc::c_long,
                        0 as libc::c_long,
                    ) != 0
                {
                    libc::_exit(127);
                }
                if libc::syscall(
                    libc::SYS_close_range,
                    (w + 1) as libc::c_long,
                    u32::MAX as libc::c_long,
                    0 as libc::c_long,
                ) != 0
                {
                    libc::_exit(127);
                }
                let traced = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                let code: u8 = if traced == 0 {
                    0
                } else {
                    libc::__errno_location().read().clamp(1, 127) as u8
                };
                libc::write(w, &code as *const u8 as *const _, 1);
                libc::close(w);
                if traced == 0 {
                    libc::raise(libc::SIGSTOP);
                    loop {
                        libc::pause();
                    }
                } else {
                    libc::_exit(0);
                }
            }
        }
        pid
    }

    /// S52-round5: a TRACEME-stopped child must NOT retire on the
    /// stop — retirement signals through the held pidfd and reaps
    /// the signaled death. Afterwards the pid is ECHILD (reaped),
    /// which a stop-blind retirement (old code) never produces.
    /// S68-round5: the pidfd here is birth-opened (before any
    /// observation), mirroring production plumbing.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn retire_stopped_child_kills_and_reaps() {
        use std::time::{Duration, Instant};
        let mut pipe = [0; 2];
        // SAFETY: valid out-pointer for the pipe ends.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let pid = fork_stop_child(pipe[1]);
        // SAFETY: write end owned by this scope.
        unsafe { libc::close(pipe[1]) };
        let mut guard = ChildGuard::new(pid);
        // S68-round5: immediate post-fork authority, before any wait.
        // S68-round6: test-local (no competitor here); production
        // holds the child via the release handshake.
        let pidfd = super::super::seccomp::pidfd_open_raw(pid).ok();
        assert!(pidfd.is_some(), "pidfd must open on a live child");
        let _held = PidfdGuard(pidfd);
        let mut code = [1u8; 1];
        // SAFETY: one byte from the inherited pipe.
        let got = unsafe { libc::read(pipe[0], code.as_mut_ptr() as *mut _, 1) };
        // SAFETY: read end owned by this scope.
        unsafe { libc::close(pipe[0]) };
        assert_eq!(got, 1, "child must report its TRACEME errno");
        if code[0] != 0 {
            eprintln!("skip: TRACEME refused here; stop path untestable");
            return;
        }
        if proc_state(pid).is_none() {
            eprintln!("skip: /proc unavailable for stop observation");
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if proc_state(pid) == Some('t') {
                break;
            }
            assert!(Instant::now() < deadline, "child never reached ptrace-stop");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            retire_preflight_child(pid, pidfd),
            "a stopped child must be signaled and reaped, not retired on its stop"
        );
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "retirement must reap (old code left the child stopped)"
        );
        // S97-round6: retirement proved — disarm so the drop signals
        // nothing at the recycled number.
        guard.disarm();
    }

    /// S68-round6: same as above without a birth pidfd — retirement
    /// CANNOT signal (no late reacquisition from the unreserved
    /// number: a competing reaper could have recycled it between the
    /// observation and the open), so it reports the child unretired
    /// after the bounded wait. The stop persists — proof no SIGKILL
    /// landed — and the pin-held guard below performs the cleanup
    /// kill. Round-5 late-opened here and required kill+reap.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn retire_stopped_child_without_birth_pidfd() {
        use std::time::{Duration, Instant};
        let mut pipe = [0; 2];
        // SAFETY: valid out-pointer for the pipe ends.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let pid = fork_stop_child(pipe[1]);
        // SAFETY: write end owned by this scope.
        unsafe { libc::close(pipe[1]) };
        let guard = ChildGuard::new(pid);
        let mut code = [1u8; 1];
        // SAFETY: one byte from the inherited pipe.
        let got = unsafe { libc::read(pipe[0], code.as_mut_ptr() as *mut _, 1) };
        // SAFETY: read end owned by this scope.
        unsafe { libc::close(pipe[0]) };
        assert_eq!(got, 1, "child must report its TRACEME errno");
        if code[0] != 0 {
            eprintln!("skip: TRACEME refused here; stop path untestable");
            return;
        }
        if proc_state(pid).is_none() {
            eprintln!("skip: /proc unavailable for stop observation");
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if proc_state(pid) == Some('t') {
                break;
            }
            assert!(Instant::now() < deadline, "child never reached ptrace-stop");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !retire_preflight_child(pid, None),
            "pin-less retirement must not claim a live child"
        );
        assert_eq!(
            proc_state(pid),
            Some('t'),
            "no signal may land without authority: the stop must persist"
        );
        // The pin-held guard retires the child through its own
        // authority (not the unreserved number).
        drop(guard);
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "guard must reap through its pin"
        );
    }

    /// R12-008: a multi-second fork-only child must shed inherited
    /// pipe write ends. The stopped child never execs (cloexec
    /// cannot help) and the pin-less retirement burns its full 5s
    /// bound on every passing run (the stop persists by design, so
    /// the reap loop always times out) — any sibling report pipe
    /// inherited at fork would hold EOF past 2s guards and flip
    /// classifications to genuine-timeout (the IR1 residual's
    /// milliseconds assumption, violated). Regression (direct and
    /// deterministic — barrier-coordination into the runner's µs
    /// pipe window would be flaky by construction): hold a victim
    /// pipe open across the fork, close our write end, and require
    /// EOF within the same 2s guard the bogus runner uses.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn stopped_child_sheds_inherited_pipe_write_end() {
        // Victim pipe (stands in for a sibling runner's
        // in-process report pipe — cloexec'd like it, which a
        // fork-only child defeats by never exec'ing): OUR write
        // end stays open across the fork below.
        let mut victim = [0; 2];
        // SAFETY: valid out-pointer for the pipe ends.
        assert_eq!(
            unsafe { libc::pipe2(victim.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let mut pipe = [0; 2];
        // SAFETY: valid out-pointer for the pipe ends.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let pid = fork_stop_child(pipe[1]);
        // SAFETY: write end owned by this scope.
        unsafe { libc::close(pipe[1]) };
        let guard = ChildGuard::new(pid);
        let mut code = [1u8; 1];
        // SAFETY: one byte from the inherited pipe.
        let got = unsafe { libc::read(pipe[0], code.as_mut_ptr() as *mut _, 1) };
        // SAFETY: read end owned by this scope.
        unsafe { libc::close(pipe[0]) };
        assert_eq!(got, 1, "child must report its TRACEME errno");
        if code[0] != 0 {
            // SAFETY: victim ends owned by this scope.
            unsafe {
                libc::close(victim[0]);
                libc::close(victim[1]);
            }
            eprintln!("skip: TRACEME refused here; stop path untestable");
            return;
        }
        // Close OUR victim write end: EOF arrives iff the stopped
        // child shed its inherited copy (it is alive — stopped —
        // either way, so a held copy blocks EOF for its 5s life).
        // SAFETY: write end owned by this scope.
        unsafe { libc::close(victim[1]) };
        // The bogus runner's 2s guard: EOF (HUP, no data) must
        // arrive, not time out.
        let mut waiting = libc::pollfd {
            fd: victim[0],
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: valid pollfd for an owned descriptor.
        let ready = unsafe { libc::poll(&mut waiting, 1, 2000) };
        // SAFETY: read end owned by this scope.
        unsafe { libc::close(victim[0]) };
        assert!(
            ready > 0,
            "stopped child holds an inherited write end past the 2s guard"
        );
        // Cleanup through the pin-held guard (kills the stopped
        // child at once — no 5s retire burn needed here; the
        // sibling test covers the retirement semantics).
        drop(guard);
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "guard must reap through its pin"
        );
    }

    /// S68-round6: first-open-fails/later-number-reused negative. A
    /// live task under the passed number with NO pin is NOT signaled
    /// (it may be a recycled stranger — the sleep stands in for one):
    /// the outcome is Uncertain and the task survives. An already
    /// reaped number reports Gone via the waitpid recheck. Pre-fix
    /// the late open succeeded on the live task and killed it.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn signal_without_pin_never_signals_replacement() {
        // SAFETY: child pauses forever (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        let guard = ChildGuard::new(pid);
        assert!(
            proc_state(pid).is_some(),
            "replacement stand-in must be observable"
        );
        assert!(
            matches!(
                signal_preflight_child(pid, None),
                PreflightSignal::Uncertain
            ),
            "pin-less signal of a live number must be Uncertain"
        );
        assert!(
            proc_state(pid).is_some() && proc_state(pid) != Some('Z'),
            "the replacement must survive a pin-less signal attempt"
        );
        // Cleanup through the guard's pin, then prove the reaped
        // number reports Gone (not Uncertain, never Pending).
        drop(guard);
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let _ = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            matches!(signal_preflight_child(pid, None), PreflightSignal::Gone),
            "reaped number must report Gone via the waitpid recheck"
        );
    }

    /// S97-round6: a disarmed drop signals nothing — the live child
    /// survives the guard's destruction. (The retire tests above
    /// disarm only after proved retirement; here the disarm itself
    /// is the fixture, so the child is cleaned up manually after.)
    /// Neuter check: a drop that ignores `armed` kills the child
    /// and fails this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn disarmed_guard_drop_signals_nothing() {
        // SAFETY: child pauses forever (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        let mut guard = ChildGuard::new(pid);
        assert!(
            proc_state(pid).is_some(),
            "guarded child must be observable"
        );
        guard.disarm();
        drop(guard);
        assert!(
            proc_state(pid).is_some() && proc_state(pid) != Some('Z'),
            "a disarmed drop must spare the live child"
        );
        // SAFETY: retiring our own verified-live child.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
    }

    /// S97-round6 control: an armed drop retires the child through
    /// the pin (kill + reap), proving the disarm test above would
    /// catch a drop that signals.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn armed_guard_drop_retires_child() {
        // SAFETY: child pauses forever (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        let guard = ChildGuard::new(pid);
        assert!(
            proc_state(pid).is_some(),
            "guarded child must be observable"
        );
        drop(guard);
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "armed drop must kill and reap through its pin"
        );
    }

    /// S68-round7: a pin-less armed drop never signals a number
    /// it cannot prove is its live child. The test process's
    /// own id is not its child (ECHILD) — dropping such a
    /// guard must skip the numeric kill (pre-fix it SIGKILLed
    /// the test process itself) and return promptly.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn none_guard_drop_skips_kill_without_proof() {
        let me = std::process::id() as libc::pid_t;
        let guard = ChildGuard {
            pid: me,
            pidfd: None,
            armed: true,
        };
        drop(guard);
        assert!(
            proc_state(me).is_some(),
            "a pin-less drop over a non-child number must spare it"
        );
    }

    /// R10-007: pin-less drop after the owned child was
    /// reaped must not issue a second numeric wait — the freed
    /// number may already name another test thread's child.
    /// R12-015: the drop no longer rechecks pin-less at all
    /// (any recheck could consume a recycled number's
    /// status), so every arm retires explicitly and disarms.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r10_pinless_drop_after_reap_issues_no_second_wait() {
        let _serial = R10_SERIAL.lock().unwrap();
        // SAFETY: child exits at once (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe { libc::_exit(41) };
        }
        // R11-018: custody from birth (the failure arms below
        // retire explicitly; the guard backstops unforeseen
        // panics and is disarmed over the retired child).
        let mut guard = ChildGuard {
            pid,
            pidfd: None,
            armed: true,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        // R11-018: the failure arms return AFTER retiring the
        // owned child (live-safe) — the skip return and the
        // expiry panic below can no longer leak a zombie.
        // R12-015: disarm after proven retirement (an armed
        // pin-less drop is always loud now, never a wait).
        match observe_zombie_or_retire(pid, deadline, proc_state) {
            ZombieWatch::Zombie => {
                // R12-015: retire explicitly while the child is
                // provably ours (owned-unreaped) — the drop no
                // longer reaps pin-less.
                retire_owned_unreaped(pid);
                guard.disarm();
            }
            ZombieWatch::DeniedRetired => {
                guard.disarm();
                eprintln!("skip: /proc unavailable for zombie observation");
                return;
            }
            ZombieWatch::ExpiredRetired => {
                guard.disarm();
                panic!("child never reached zombie state")
            }
        }
        drop(guard);
        assert!(
            !take_trailing_waits().contains(&pid),
            "pin-less drop after an explicit reap must not wait again"
        );
        // SAFETY: valid status out-pointer; ECHILD proves the
        // explicit retire reaped (not any drop wait).
        let mut status = 0;
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "the explicit retire must have reaped the zombie"
        );
    }

    /// R10-007: pin-less drop observing ECHILD (already reaped
    /// elsewhere) must return without another numeric wait.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r10_pinless_drop_on_echild_issues_no_second_wait() {
        let _serial = R10_SERIAL.lock().unwrap();
        let me = std::process::id() as libc::pid_t;
        let guard = ChildGuard {
            pid: me,
            pidfd: None,
            armed: true,
        };
        drop(guard);
        assert!(
            !take_trailing_waits().contains(&me),
            "pin-less drop on ECHILD must not wait again"
        );
    }

    /// R12-015: the denied arm retires via the helper, then
    /// drops its pin-less guard: the drop must issue NO
    /// numeric wait (the discharged number may already name
    /// another test thread's zombie — consuming its status is
    /// the bug). The guard stays ARMED here on purpose: the
    /// backstop itself must be wait-free, not just the
    /// disarming callers. Preservation follows by
    /// construction (zero waits consume nothing); a
    /// forced-recycle preservation test needs ns_last_pid
    /// steering, which lib tests cannot do (machine-global).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r12_denied_retire_drop_issues_no_wait() {
        let _serial = R10_SERIAL.lock().unwrap();
        // SAFETY: child pauses forever (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        // Deliberately pin-less AND armed at drop (backstop
        // shape — a caller that forgot to disarm).
        let guard = ChildGuard {
            pid,
            pidfd: None,
            armed: true,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        // Denied observation (stubbed): the helper retires
        // the LIVE child before returning.
        match observe_zombie_or_retire(pid, deadline, |_| None) {
            ZombieWatch::DeniedRetired => {}
            _ => panic!("stubbed denial must take the DeniedRetired arm"),
        }
        drop(guard);
        assert!(
            !take_trailing_waits().contains(&pid),
            "pin-less drop after helper retirement must not wait"
        );
    }

    /// R10-007: pinned drop whose kill observes ESRCH (task proven
    /// gone through the pin) must not fall through to a numeric
    /// wait on the possibly recycled number.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r10_pinned_drop_on_esrch_issues_no_second_wait() {
        let _serial = R10_SERIAL.lock().unwrap();
        // SAFETY: child exits at once (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe { libc::_exit(42) };
        }
        let guard = ChildGuard::new(pid);
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(reaped, pid, "setup must reap the child first");
        drop(guard);
        assert!(
            !take_trailing_waits().contains(&pid),
            "pinned drop on ESRCH must not wait again"
        );
    }

    /// R10-007 positive twin: the pinned kill path still reaps
    /// through the trailing wait (guards against over-correction).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r10_pinned_kill_path_still_reaps() {
        let _serial = R10_SERIAL.lock().unwrap();
        // SAFETY: child pauses forever (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        let guard = ChildGuard::new(pid);
        assert!(
            proc_state(pid).is_some(),
            "guarded child must be observable"
        );
        drop(guard);
        assert!(
            take_trailing_waits().contains(&pid),
            "pinned kill path must still reap"
        );
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "pinned kill path must leave no zombie"
        );
    }

    /// R10-007 assumption check: a zombie still answers the pin
    /// signal (no ESRCH), so the pinned drop reaps it instead of
    /// skipping. Fails if pidfd_send_signal ever reports ESRCH
    /// for an unreaped zombie.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r10_pinned_drop_on_zombie_still_reaps() {
        let _serial = R10_SERIAL.lock().unwrap();
        // SAFETY: child exits at once (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe { libc::_exit(43) };
        }
        // R11-018: custody from birth (the failure arms below
        // retire explicitly; the guard backstops unforeseen
        // panics and no-ops over the retired child).
        let guard = ChildGuard::new(pid);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        // R11-018: the failure arms return AFTER retiring the
        // owned child (live-safe) — the skip return and the
        // expiry panic below can no longer leak a zombie.
        match observe_zombie_or_retire(pid, deadline, proc_state) {
            ZombieWatch::Zombie => {}
            ZombieWatch::DeniedRetired => {
                eprintln!("skip: /proc unavailable for zombie observation");
                return;
            }
            ZombieWatch::ExpiredRetired => panic!("child never reached zombie state"),
        }
        drop(guard);
        assert!(
            take_trailing_waits().contains(&pid),
            "pinned drop on a zombie must still reap"
        );
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "pinned drop on a zombie must leave no zombie"
        );
    }

    /// R11-018: retiring an owned live child leaves no owned
    /// child status (ECHILD-only — no zombie, no survivor).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r11_retire_owned_unreaped_reaps_live_child() {
        // SAFETY: child pauses forever (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        retire_owned_unreaped(pid);
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "retired live child must leave no owned status"
        );
    }

    /// R11-018: retiring an owned zombie leaves no owned child
    /// status either (the already-exited arm).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r11_retire_owned_unreaped_reaps_zombie() {
        // SAFETY: child exits at once (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe { libc::_exit(44) };
        }
        // R12-016: custody before the observing setup — an
        // expiry panic above retirement must not leak.
        let mut guard = ChildGuard::new(pid);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while proc_state(pid) != Some('Z') {
            assert!(
                std::time::Instant::now() < deadline,
                "setup child never reached zombie state"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        retire_owned_unreaped(pid);
        // Retirement proved — disarm so the ECHILD below
        // proves the helper reaped (not the drop).
        guard.disarm();
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "retired zombie must leave no owned status"
        );
    }

    /// R11-018: observation expiry in isolation — a child that
    /// never zombies (pausing) past a short deadline reports
    /// expiry AND retires (no remaining owned child status).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r11_observe_expiry_retires_in_isolation() {
        // SAFETY: child pauses forever (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
        assert!(matches!(
            observe_zombie_or_retire(pid, deadline, proc_state),
            ZombieWatch::ExpiredRetired
        ));
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "expiry must leave no remaining owned child status"
        );
    }

    /// R11-018: denied observation in isolation — a stubbed
    /// observer (always None, standing in for unavailable
    /// /proc) over a LIVE child reports denial AND retires
    /// (stronger than the production shape: live-safe, not
    /// just zombie-safe).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r11_observe_denied_retires_live_child_in_isolation() {
        // SAFETY: child pauses forever (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        assert!(matches!(
            observe_zombie_or_retire(pid, deadline, |_| None),
            ZombieWatch::DeniedRetired
        ));
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "denial must leave no remaining owned child status"
        );
    }

    /// R12-016: setup-custody pattern proof — a setup panic
    /// (denied observation / expiry stand-in) with custody
    /// established at fork must leave no remaining owned
    /// child status. The guard drops during the unwind and
    /// the pinned drop reaps. Pre-fix (no guard) the ECHILD
    /// assert below fails (RED); the assert's own waitpid
    /// reaps the zombie, so even the RED run litters nothing.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r12_setup_panic_leaves_no_owned_status() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        use std::sync::atomic::{AtomicI32, Ordering};
        let slot = AtomicI32::new(-1);
        let result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: child exits at once (async-signal-safe).
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "unit fork failed");
            if pid == 0 {
                unsafe { libc::_exit(46) };
            }
            slot.store(pid, Ordering::SeqCst);
            // R12-016: custody at fork — the guard drops during
            // the unwind below and reaps.
            let _guard = ChildGuard::new(pid);
            panic!("injected setup observation failure");
        }));
        assert!(result.is_err(), "the setup must have panicked");
        let pid = slot.load(Ordering::SeqCst);
        assert!(pid >= 0, "the child must have forked before the panic");
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "setup panic must leave no remaining owned child status"
        );
    }

    /// S140-round9: re-exec probe rendezvous. The middleman stub
    /// execs the test binary at [`PROBE_TEST_PATH`] with
    /// `PROBE_DENIAL_ENV` set to the denial spec; the probe
    /// reports one `exit=… grandchild=… err=…` line on the fd named
    /// by `PROBE_REPORT_FD_ENV`, then _exits with the
    /// classification. The test path must stay exact: an exec that
    /// runs zero tests reports no line and fails loud.
    #[cfg(target_arch = "x86_64")]
    const PROBE_TEST_PATH: &str = "fixture::linux::audit::tests::tt04_preflight_denial_exec_probe";
    #[cfg(target_arch = "x86_64")]
    const PROBE_DENIAL_ENV: &str = "SCOPEBASE_TT04_PREFLIGHT_DENIAL";
    #[cfg(target_arch = "x86_64")]
    const PROBE_REPORT_FD_ENV: &str = "SCOPEBASE_TT04_PREFLIGHT_REPORT_FD";
    /// R10-012: the confined-subreaper retirement probe path
    /// (exact — the parent requires one passed test in the
    /// probe output, so a renamed path fails loud instead of
    /// passing vacuously on zero tests).
    #[cfg(target_arch = "x86_64")]
    const SUBREAPER_PROBE_PATH: &str = "fixture::linux::audit::tests::tt04_subreaper_retire_probe";
    /// R10-012: rendezvous — the probe runs only when set.
    #[cfg(target_arch = "x86_64")]
    const SUBREAPER_PROBE_ENV: &str = "SCOPEBASE_TT04_SUBREAPER_PROBE";
    /// R11-013: the confined-subreaper GUARD probe path (exact —
    /// the parent requires one passed test in the probe output,
    /// so a renamed path fails loud instead of passing
    /// vacuously on zero tests).
    #[cfg(target_arch = "x86_64")]
    const GUARD_PROBE_PATH: &str = "fixture::linux::audit::tests::tt04_adopting_guard_probe";
    /// R11-013: rendezvous — the probe runs only when set.
    #[cfg(target_arch = "x86_64")]
    const GUARD_PROBE_ENV: &str = "SCOPEBASE_TT04_ADOPTING_GUARD_PROBE";
    /// R12-007: the collection-expiry subreaper probe path (exact —
    /// the parent requires one passed test in the probe output,
    /// so a renamed path fails loud instead of passing
    /// vacuously on zero tests).
    #[cfg(target_arch = "x86_64")]
    const EXPIRY_PROBE_PATH: &str =
        "fixture::linux::audit::tests::collection_expiry_adopting_probe";
    /// R12-007: rendezvous — the probe runs only when set.
    #[cfg(target_arch = "x86_64")]
    const EXPIRY_PROBE_ENV: &str = "SCOPEBASE_COLLECTION_EXPIRY_SUBREAPER_PROBE";
    /// R13-005: rendezvous — when set, names the pidfile where an
    /// outer probe publishes each reported grandchild (`pid:start`,
    /// overwrite: these probes run middlemen sequentially and
    /// retire between, so the latest publish names the only
    /// possibly-live writer). The middleman itself cannot publish:
    /// the write-denying specs refuse its file writes — the
    /// unfiltered OUTER probe publishes from the report line
    /// instead, BEFORE retiring, so a death between birth and
    /// retirement still leaves the identity for the parent's
    /// expiry strays. A stale entry is harmless (the strays arm
    /// re-verifies (pin, starttime) before signaling).
    #[cfg(target_arch = "x86_64")]
    const GRANDCHILD_PIDFILE_ENV: &str = "SCOPEBASE_TT04_GRANDCHILD_PIDFILE";
    /// R13-005: failure injection — when set, the subreaper probe
    /// exits(42) after publishing a live grandchild but BEFORE
    /// retiring it (the abandoned-writer shape: assert-failure and
    /// early-exit paths skip retirement the same way). Gated on a
    /// Live report — exiting 42 with no grandchild would make the
    /// regression vacuous, so None proceeds normally and the
    /// parent's status assert fails loud instead.
    #[cfg(target_arch = "x86_64")]
    const SUBREAPER_ABANDON_ENV: &str = "SCOPEBASE_TT04_SUBREAPER_ABANDON";
    /// R14-011: the retire-denial probe path (exact — the parent
    /// asserts exact exit codes, so a renamed path running zero
    /// tests exits 0 and fails loud instead of passing
    /// vacuously).
    #[cfg(target_arch = "x86_64")]
    const R14011_PROBE_PATH: &str = "fixture::linux::audit::tests::tt04_r14011_retire_denial_probe";
    /// R14-011: rendezvous — the denial spec (`pidfd`, `read`, or
    /// `none`); the probe runs only when set.
    #[cfg(target_arch = "x86_64")]
    const R14011_DENIAL_ENV: &str = "SCOPEBASE_TT04_R14011_DENIAL";
    /// R14-011: rendezvous — the retire target as `pid:starttime`.
    #[cfg(target_arch = "x86_64")]
    const R14011_TARGET_ENV: &str = "SCOPEBASE_TT04_R14011_TARGET";
    /// IR-003: the unreadable-firstborn probe path (exact — the
    /// parent requires exit success plus a verdict file, so a
    /// renamed path running zero tests fails loud instead of
    /// passing vacuously).
    #[cfg(target_arch = "x86_64")]
    const IR003_PROBE_PATH: &str = "fixture::linux::audit::tests::ir003_firstborn_stat_probe";
    /// IR-003: failure injection — when set, the firstborn stat
    /// in the birth watch fails synthesized (the ~EMFILE-only
    /// trigger, staged deterministically). Set solely on the
    /// fresh probe child's command, never process-wide (a
    /// sibling probe inheriting it would inject too).
    #[cfg(target_arch = "x86_64")]
    const IR003_INJECT_ENV: &str = "SCOPEBASE_IR003_FIRSTBORN_STAT_ERR";
    /// IR-003: rendezvous — the verdict file (`pgid` line,
    /// middleman-tick line (R15-003: 0 when already gone), then
    /// the panic message) the probe writes for the parent.
    #[cfg(target_arch = "x86_64")]
    const IR003_VERDICT_ENV: &str = "SCOPEBASE_IR003_VERDICT";

    /// S132-round9: the exact expected-timeout shape — the
    /// barrier-denied report timeout WITH proven retirement.
    /// Classification compares the full string: a
    /// `; preflight child not proven reaped` suffix (or any other
    /// text) is NOT an expected timeout.
    #[cfg(target_arch = "x86_64")]
    const EXPECTED_BARRIER_TIMEOUT: &str = "preflight report timed out (barrier unproven)";

    /// S132-round9: the middleman's surviving preflight child, if
    /// any — reported so the parent test keeps independent cleanup
    /// authority over BOTH generations (middleman and grandchild).
    #[cfg(target_arch = "x86_64")]
    #[derive(Debug, Clone, Copy)]
    enum GrandchildState {
        /// The probe observed no surviving preflight child: the
        /// middleman reaped its own (the retirement proof).
        None,
        /// A surviving preflight child (pid + starttime) needing
        /// test-side cleanup via [`retire_reported_grandchild`].
        Live(libc::pid_t, u64),
    }

    /// S132/S140-round9: what the middleman reported — its exit
    /// classification, its surviving grandchild if any, and the
    /// preflight error text (empty on success).
    #[cfg(target_arch = "x86_64")]
    struct MiddlemanOutcome {
        code: i32,
        grandchild: GrandchildState,
        err: String,
    }

    /// S132-round9: parse one probe line —
    /// `exit=<n> grandchild=<none|pid:start> err=<rest>` — into its
    /// outcome. A malformed line classifies as code -1 (the caller
    /// fails loud: the middleman must always report exactly).
    #[cfg(target_arch = "x86_64")]
    fn parse_middleman_line(line: &str) -> MiddlemanOutcome {
        let mut code = -1;
        let mut grandchild = GrandchildState::None;
        let mut rest = line.trim_end_matches(['\n', '\r']);
        if let Some(tail) = rest.strip_prefix("exit=") {
            let (code_text, after) = tail.split_once(' ').unwrap_or((tail, ""));
            code = code_text.parse().unwrap_or(-1);
            rest = after;
        }
        if let Some(tail) = rest.strip_prefix("grandchild=") {
            let (gc_text, after) = tail.split_once(' ').unwrap_or((tail, ""));
            if gc_text != "none" {
                if let Some((pid_text, start_text)) = gc_text.split_once(':') {
                    if let (Ok(pid), Ok(started)) = (pid_text.parse(), start_text.parse()) {
                        grandchild = GrandchildState::Live(pid, started);
                    }
                }
            }
            rest = after;
        }
        let err = rest.strip_prefix("err=").unwrap_or("").to_string();
        MiddlemanOutcome {
            code,
            grandchild,
            err,
        }
    }

    /// R13-005: publish a reported grandchild to the rendezvous
    /// pidfile ([`GRANDCHILD_PIDFILE_ENV`]) when set. Called by the
    /// OUTER probe immediately after the runner returns — BEFORE
    /// any retire/panic/exit — and by the runner itself at birth
    /// (R14-008), so a death between birth and retirement still
    /// leaves the writer's (pid, starttime) for the parent's
    /// expiry strays (the parked grandchild holds the outer
    /// probe's pipes from its own middleman group, where the
    /// expiry killpg cannot reach). `None` CLEARS any birth
    /// record (a report naming no writer ends the birth's
    /// authority); a set-but-unwritable pidfile fails loud on
    /// `Live` (an unpublished writer would strand silently).
    /// R14-010: the `Live` publish is atomic (tmp + rename —
    /// readers see the old complete record or the new complete
    /// record, never the truncate-then-write tear), and presence
    /// is `var_os` (a set-but-non-UTF-8 path retires the known
    /// writer, then fails loud — never a silent skip).
    /// R15-008: the writer-evidence suffix appended to every
    /// publish/guard/hygiene failure message that retires a
    /// known writer — (pid, starttime, retired) travels with
    /// the report, never stranded in locals while the writer
    /// strands live.
    #[cfg(target_arch = "x86_64")]
    fn writer_retire_note(pid: libc::pid_t, started: u64, retired: bool) -> String {
        format!(" (writer pid={pid} starttime={started} retired={retired})")
    }

    #[cfg(target_arch = "x86_64")]
    fn publish_reported_grandchild(state: &GrandchildState) {
        // R14-010: presence via var_os — a set-but-non-UTF-8
        // value is a setup bug, never "unset".
        let path_os = match std::env::var_os(GRANDCHILD_PIDFILE_ENV) {
            Some(path) => path,
            None => return,
        };
        let (pid, started) = match state {
            GrandchildState::Live(pid, started) => (*pid, *started),
            // R14-008: the birth publication may have fired
            // before the middleman retired its child — the stale
            // record must not outlive a report naming no writer.
            // A failed clear stays silent: any surviving record
            // names a middleman-retired task the expiry
            // holder-check refuses (nothing strands). A
            // non-UTF-8 path skips likewise (hygiene only —
            // nothing is at stake on this arm).
            GrandchildState::None => {
                if let Some(path) = path_os.to_str() {
                    let _ = std::fs::write(path, "");
                }
                return;
            }
        };
        // A Live writer is at stake: a non-UTF-8 path retires
        // first, then fails loud (never a silent skip over a
        // live writer).
        let path = match path_os.to_str() {
            Some(path) => path,
            None => {
                let retired = retire_known_stray_best_effort(pid, started);
                panic!(
                    "grandchild rendezvous path not UTF-8: {path_os:?}{}",
                    writer_retire_note(pid, started, retired)
                );
            }
        };
        // R14-003: writability probe (plain O_WRONLY — no create,
        // no truncate, closed at once): a set-but-unwritable
        // pidfile retires the known writer, then fails loud.
        if let Err(error) = std::fs::OpenOptions::new().write(true).open(path) {
            let retired = retire_known_stray_best_effort(pid, started);
            panic!(
                "grandchild publish to {path:?} failed: {error}{}",
                writer_retire_note(pid, started, retired)
            );
        }
        // R14-010: atomic publish (tmp 600 + rename) — readers
        // see the old complete record or the new complete
        // record, never the truncate-then-write tear (an
        // empty-after-truncate file reads back as silent
        // unpublished over a live writer). A tmp WE created is
        // removed on every failure below (no litter); a refused
        // claim removes nothing (R15-001).
        // IR-001: the tmp is claimed through the same O_EXCL
        // helper as the pidfile — a planted symlink/fifo
        // refuses or reclaims before any byte is written (the
        // old create+truncate followed a planted symlink into
        // an arbitrary runner-writable victim).
        let tmp = format!("{path}.tmp");
        let published = (|| -> std::io::Result<()> {
            use std::io::Write as _;
            let mut file = claim_excl_file(std::path::Path::new(&tmp), "publish tmp")
                .map_err(std::io::Error::other)?;
            // R15-001: the claim above created (or reclaimed-then-
            // created) the tmp — it is OURS from here, so only
            // failures below clean it. A claim refusal (foreign
            // plant, reclaim-race re-plant) returns before this
            // point and must never unlink what it refused.
            let inner = (|| -> std::io::Result<()> {
                file.write_all(format!("{pid}:{started}").as_bytes())?;
                drop(file);
                std::fs::rename(&tmp, path)?;
                Ok(())
            })();
            if inner.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
            inner
        })();
        if let Err(error) = published {
            // R14-003: retire the known writer BEFORE failing
            // loud — a panic that skips retirement strands it
            // while the parent trusts a stale record.
            let retired = retire_known_stray_best_effort(pid, started);
            panic!(
                "grandchild publish to {path:?} failed: {error}{}",
                writer_retire_note(pid, started, retired)
            );
        }
    }

    /// IR-001: O_EXCL claim with owned-reclaim, shared by the
    /// pidfile pre-spawn claim (R14-003) and the atomic-publish
    /// tmp (R14-010) so the two can never drift apart again.
    /// `create_new` never follows a symlink (an existing link
    /// fails EEXIST) and never blocks on a fifo — a plant of
    /// any shape refuses or reclaims before a byte is written.
    /// An own-uid leftover (a SIGKILLed run's litter) unlinks
    /// and retries once; a foreign plant refuses loud; anything
    /// else fails loud. The reclaim retry races safe: a
    /// re-plant between unlink and create fails EEXIST again
    /// and refuses (never follows).
    #[cfg(target_arch = "x86_64")]
    fn claim_excl_file(path: &std::path::Path, what: &str) -> Result<std::fs::File, String> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let attempt = || {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        };
        match attempt() {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                use std::os::unix::fs::MetadataExt as _;
                // SAFETY: getuid queries only.
                let ours = std::fs::symlink_metadata(path)
                    .map(|meta| meta.uid() == unsafe { libc::getuid() })
                    .unwrap_or(false);
                if !ours {
                    return Err(format!(
                        "{what} {path:?} preplanted by another owner: refusing"
                    ));
                }
                std::fs::remove_file(path)
                    .map_err(|error| format!("{what} {path:?} stale reclaim failed: {error}"))?;
                attempt().map_err(|error| format!("{what} {path:?} reclaim failed: {error}"))
            }
            Err(error) => Err(format!("{what} {path:?} claim failed: {error}")),
        }
    }

    /// R14-003: claim a rendezvous pidfile BEFORE spawning
    /// (O_EXCL). Any preplant — any owner — refuses loud here,
    /// where no writer exists yet and nothing can strand; the
    /// old ignore-removal-failure idiom burned a doomed probe
    /// whose failed publication panicked past retirement. Our
    /// own stale file (a killed run under a wrapped pid) unlinks
    /// safely and retries once; a foreign plant never proceeds.
    #[cfg(target_arch = "x86_64")]
    fn claim_pidfile(path: &std::path::Path) -> Result<(), String> {
        claim_excl_file(path, "pidfile").map(|_| ())
    }

    /// R13-005: read the outer probe's published grandchild (if
    /// any) as expiry strays. The path is explicit: the parent
    /// sets the rendezvous on the CHILD's environment (its own
    /// environment carries nothing — a global set_var would race
    /// parallel tests). A missing file yields empty (a skip-path
    /// probe publishes nothing) — the expiry then behaves exactly
    /// as before. A present-but-unparseable file is OUR probe's
    /// bug and fails loud (a silently-dropped writer would
    /// strand).
    /// R14-003: the record is trusted only from OUR OWN claimed
    /// file (O_NOFOLLOW + uid check — a forged pid:starttime
    /// from another UID would otherwise grant signal authority
    /// over a non-fixture process). An empty file is a
    /// claimed-but-unpublished rendezvous (skip paths) and
    /// yields empty like a missing one.
    /// R14-010: only a MISSING file means "unpublished" — every
    /// other read failure fails closed (an empty strays list
    /// over a published writer would strand it silently).
    #[cfg(target_arch = "x86_64")]
    fn read_published_grandchild_strays(path: &std::path::Path) -> Vec<(libc::pid_t, u64)> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            // Only ENOENT means "unpublished" (a probe that
            // never published); every other open failure —
            // EACCES, EMFILE, ELOOP on a swapped symlink, EIO —
            // fails loud: silent empty would strand a published
            // writer.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("grandchild pidfile {path:?} unreadable: {error}"),
        };
        {
            use std::os::unix::fs::MetadataExt as _;
            // SAFETY: getuid queries only.
            let ours = file
                .metadata()
                .map(|meta| meta.uid() == unsafe { libc::getuid() })
                .unwrap_or(false);
            if !ours {
                panic!("grandchild pidfile {path:?} not owned by us: refusing forged record");
            }
        }
        use std::io::Read as _;
        let mut text = String::new();
        // R14-010: a mid-read failure fails closed with the
        // bytes so far (an I/O-torn record is untrusted — same
        // as unparseable below, never silent empty).
        if let Err(error) = file.read_to_string(&mut text) {
            panic!("grandchild pidfile {path:?} unreadable mid-read ({error}): {text:?} (unresolved custody — no retirement attempted, writer fate unknown)");
        }
        if text.trim().is_empty() {
            return Vec::new();
        }
        // R14-010: an untrusted identity can neither retire nor
        // silently drop — report explicit unresolved custody.
        let custody = "unresolved custody — no retirement attempted, writer fate unknown";
        let (pid_text, start_text) = text.trim().split_once(':').unwrap_or_else(|| {
            panic!("grandchild pidfile {path:?} unparseable: {text:?} ({custody})")
        });
        let pid: libc::pid_t = pid_text.parse().unwrap_or_else(|_| {
            panic!("grandchild pidfile {path:?} unparseable: {text:?} ({custody})")
        });
        let started: u64 = start_text.parse().unwrap_or_else(|_| {
            panic!("grandchild pidfile {path:?} unparseable: {text:?} ({custody})")
        });
        assert!(
            pid > 0,
            "grandchild pidfile {path:?} names no task: {text:?} ({custody})"
        );
        vec![(pid, started)]
    }

    /// R14-009: timeout retirement for a hung outer probe — the
    /// single body behind every rendezvous parent's deadline
    /// branch (a hung probe is indistinguishable from a held one,
    /// so the branch always assumes publication happened). Kills
    /// the probe's group plus the probe itself (SIGKILL lands on
    /// a stopped task too), reaps it, reads the rendezvous and
    /// retires any published writer (an independently-grouped
    /// writer survives the killpg — without this the timeout
    /// leaks it parked), removes the pidfile, then panics with
    /// `what` (a timeout is a failure — loud, never a leak).
    /// IR-004: a corrupt record fails the stray read loud, but
    /// the pidfile is still removed and `what` still headlines
    /// (the read failure chains as evidence).
    /// R15-002: descendant forensics precede the kill — the
    /// probe's middleman and firstborn are snapshotted with
    /// ticks while the probe is alive, then retired after it
    /// (a probe stopped before its birth scan publishes
    /// nothing; without forensics its independent middleman
    /// group strands the parked writer). R15-008: denied
    /// retirements keep explicit (pid, starttime) evidence in
    /// the message (the pidfile is still removed).
    #[cfg(target_arch = "x86_64")]
    fn timeout_retire_hung_probe(
        child: &mut std::process::Child,
        pidfile: &std::path::Path,
        what: &str,
    ) -> ! {
        let id = child.id() as libc::pid_t;
        // R15-002: descendant forensics BEFORE the kill — a probe
        // stopped or hung before its birth scan publishes
        // nothing, and its middleman leads an independent group
        // the killpg below cannot reach (killpg-plus-empty-
        // strays would strand the parked writer; the EOF
        // self-release never arrives under read-denying specs).
        // Snapshot the middleman and its firstborn with ticks
        // while the probe is alive (all timeout callers fire on
        // live probes; a dead probe snapshots empty and the
        // body degrades to its previous behavior). A middleman
        // forked between snapshot and kill is missed
        // (millisecond window, only injected timeouts fire that
        // early — spontaneous timeouts fire 30s+ in, when the
        // tree is long stable); a spontaneously crashed probe
        // reparents past discovery (collect paths, out of the
        // timeout model) — both recorded residuals.
        let snapshot = (|| {
            let mid = middleman_first_child(id)?;
            let mtick = proc_starttime(mid).ok()??;
            let writer = middleman_first_child(mid)
                .and_then(|born| proc_starttime(born).ok()?.map(|tick| (born, tick)));
            Some((mid, mtick, writer))
        })();
        // SAFETY: signal-only to the probe's own group, then the
        // probe itself; errors ignored. The probe is our unreaped
        // child (alive-or-zombie — the number cannot have
        // recycled), so both signals address our own tasks.
        unsafe {
            libc::killpg(id, libc::SIGKILL);
            libc::kill(id, libc::SIGKILL);
        }
        let _ = child.wait();
        // Unresolved identities accumulate here (R15-008: a
        // denied-but-live writer must keep explicit PID/starttime
        // evidence — the pidfile below is removed regardless, so
        // the message is the only record).
        let mut unresolved: Vec<(libc::pid_t, u64)> = Vec::new();
        // R15-002: retire the snapshotted descendants — the
        // middleman group by tick-gated group kill (covers a
        // writer born after the snapshot: the middleman forks
        // once, and SIGKILL resolves the fork-vs-kill race safe
        // either way), the writer individually by identity (a
        // regrouped or reparented straggler the group kill
        // missed).
        if let Some((mid, mtick, writer)) = snapshot {
            if proc_starttime(mid) == Ok(Some(mtick)) {
                if !retire_hung_middleman_group(mid) {
                    unresolved.push((mid, mtick));
                }
            } else if proc_starttime(mid).is_err() {
                unresolved.push((mid, mtick));
            }
            if let Some((wpid, wtick)) = writer {
                if !retire_known_stray_best_effort(wpid, wtick) {
                    unresolved.push((wpid, wtick));
                }
            }
        }
        // R14-009: the timeout retires the published strays — an
        // independently-grouped writer survives the killpg above
        // and would otherwise stay parked past the failure.
        // IR-004: the stray read can fail loud (forged /
        // unparseable / unreadable record) — but the TIMEOUT is
        // the verdict under report, and the pidfile must not
        // litter either way. Run the read+retire under catch,
        // remove the pidfile regardless, then panic with `what`
        // (chaining any read failure as evidence, never as the
        // headline).
        let stray_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let strays = read_published_grandchild_strays(pidfile);
            for (pid, started) in strays {
                if !retire_known_stray_best_effort(pid, started) {
                    unresolved.push((pid, started));
                }
            }
        }));
        let _ = std::fs::remove_file(pidfile);
        let unresolved_note = if unresolved.is_empty() {
            String::new()
        } else {
            format!(" (unresolved writers (retire-denied, fate unknown): {unresolved:?})")
        };
        match stray_outcome {
            Ok(()) => panic!("{what}{unresolved_note}"),
            Err(payload) => {
                let detail = payload
                    .downcast::<String>()
                    .map(|boxed| *boxed)
                    .unwrap_or_else(|_| String::from("<non-string panic>"));
                panic!("{what} (stray retirement failed: {detail}){unresolved_note}");
            }
        }
    }

    /// S140-round9: the probe's only report channel — write exactly
    /// one line, then _exit with the classification. Used on EVERY
    /// probe path (even setup refusal) so the parent never waits on
    /// a silent middleman.
    #[cfg(target_arch = "x86_64")]
    fn probe_report_and_exit(fd: libc::c_int, code: i32, grandchild: &str, err: &str) -> ! {
        let line = format!("exit={code} grandchild={grandchild} err={err}\n");
        let bytes = line.as_bytes();
        let mut written = 0;
        while written < bytes.len() {
            // SAFETY: bounded write to the inherited report fd.
            let got = unsafe {
                libc::write(
                    fd,
                    bytes[written..].as_ptr() as *const libc::c_void,
                    (bytes.len() - written) as libc::size_t,
                )
            };
            if got <= 0 {
                break;
            }
            written += got as usize;
        }
        // SAFETY: report fd owned by this scope.
        unsafe { libc::close(fd) };
        // SAFETY: report done; exit with the classification.
        unsafe { libc::_exit(code) };
    }

    /// S132-round9: read a /proc file in the probe WITHOUT the
    /// `read` syscall: under a read-denying spec `read` is refused,
    /// so discovery uses `pread64` (a different syscall number the
    /// read-denial does not cover). The subject's barrier uses
    /// `read` only (see `preflight_child`) — the scenario is
    /// unchanged; only the probe's own discovery takes the
    /// alternate number. Fails loud on any error: a silent empty
    /// read would forge a `none` retirement proof.
    #[cfg(target_arch = "x86_64")]
    fn probe_read_to_string(path: &str) -> String {
        let cpath = std::ffi::CString::new(path).expect("probe path is C-safe");
        // SAFETY: open read-only; the fd is closed below.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0, "probe opens {path}");
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let mut chunk = [0u8; 512];
            // SAFETY: bounded pread from an owned descriptor.
            let got = unsafe {
                libc::pread(
                    fd,
                    chunk.as_mut_ptr() as *mut libc::c_void,
                    chunk.len() as libc::size_t,
                    offset,
                )
            };
            if got < 0 {
                let error = std::io::Error::last_os_error();
                // SAFETY: fd owned by this scope.
                unsafe { libc::close(fd) };
                panic!("probe reads {path}: {error}");
            }
            if got == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..got as usize]);
            offset += got as libc::off_t;
        }
        // SAFETY: fd owned by this scope.
        unsafe { libc::close(fd) };
        String::from_utf8(out).expect("probe reads UTF-8")
    }

    /// S132-round9: the probe's surviving preflight children as a
    /// protocol token — `none` (reaped: the retirement proof) or
    /// `pid:starttime` (alive: the parent test cleans it up). The
    /// probe runs exactly one preflight, so at most one child can
    /// exist. Unreadable /proc fails loud (a panic the parent
    /// surfaces): without it the retirement proof is meaningless.
    #[cfg(target_arch = "x86_64")]
    fn probe_children_state() -> String {
        // SAFETY: gettid always succeeds.
        let tid = unsafe { libc::gettid() };
        // /proc/self/task/<tid>/children carries one line of pids.
        let pids = probe_read_to_string(&format!("/proc/self/task/{tid}/children"));
        let mut live: Vec<(libc::pid_t, u64)> = Vec::new();
        for word in pids.split_whitespace() {
            let pid: libc::pid_t = match word.parse() {
                Ok(pid) => pid,
                Err(_) => continue,
            };
            // The starttime binds the number to the task the probe
            // forked (a recycled number would carry another birth).
            let row = probe_read_to_string(&format!("/proc/{pid}/stat"));
            let started: Option<u64> = (|| {
                let after_comm = row.rsplit_once(") ")?.1;
                after_comm.split_whitespace().nth(19)?.parse().ok()
            })();
            match started {
                Some(started) => live.push((pid, started)),
                None => panic!("probe reads child starttime"),
            }
        }
        assert!(live.len() <= 1, "probe has unexpected children: {live:?}");
        match live.first() {
            Some((pid, started)) => format!("{pid}:{started}"),
            None => "none".to_string(),
        }
    }

    /// S139-round9: deny one syscall number with an arbitrary errno
    /// (the shared installer only offers EPERM/ENOSYS/kill; this
    /// middleman-local copy adds EINTR for the release-write retry
    /// regression). Same classic-BPF idiom as
    /// `super::super::seccomp::install_deny_one` (arch-checked,
    /// `NO_NEW_PRIVS` first): a follow-up should promote an
    /// `Errno(n)` action into the shared installer instead of
    /// duplicating it here.
    /// S140-round9: `except_fd` exempts one descriptor from the
    /// denial (the probe's report channel — without the exemption
    /// a write-denying spec would silence the middleman's own
    /// report). The subject can never address the exempted fd: it
    /// is already open, so the subject's pipes allocate elsewhere —
    /// every subject write stays denied.
    #[cfg(target_arch = "x86_64")]
    fn install_deny_errno_one(
        nr: libc::c_long,
        errno: libc::c_int,
        except_fd: Option<libc::c_int>,
    ) -> Result<(), String> {
        const BPF_LD_ABS_W: u16 = 0x20;
        const BPF_JEQ_K: u16 = 0x15;
        const BPF_RET_K: u16 = 0x06;
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        const SECCOMP_DATA_NR_OFF: u32 = 0;
        const SECCOMP_DATA_ARCH_OFF: u32 = 4;
        const SECCOMP_DATA_ARG0_OFF: u32 = 16;
        const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
        fn stmt(code: u16, k: u32) -> libc::sock_filter {
            libc::sock_filter {
                code,
                jt: 0,
                jf: 0,
                k,
            }
        }
        fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
            libc::sock_filter { code, jt, jf, k }
        }
        let mut program = vec![
            stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARCH_OFF),
            jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
            stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR_OFF),
        ];
        match except_fd {
            Some(fd) => {
                program.push(jump(BPF_JEQ_K, nr as u32, 0, 3));
                program.push(stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARG0_OFF));
                program.push(jump(BPF_JEQ_K, fd as u32, 1, 0));
                program.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | errno as u32));
                program.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
            }
            None => {
                program.push(jump(BPF_JEQ_K, nr as u32, 0, 1));
                program.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | errno as u32));
                program.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
            }
        }
        // SAFETY: `prctl` with explicit `c_ulong` arguments; the
        // program array outlives the synchronous install call.
        let nnp = unsafe {
            libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if nnp != 0 {
            return Err(format!(
                "no_new_privs errno {}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            ));
        }
        let prog = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_ptr() as *mut libc::sock_filter,
        };
        let installed = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &prog as *const libc::sock_fprog as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if installed != 0 {
            return Err(format!(
                "install_filter errno {}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            ));
        }
        Ok(())
    }

    /// R14-011: the re-exec'd retire-denial probe. Under a
    /// normal suite run (no rendezvous variables) this passes
    /// silently; the parent spawns a FRESH test-binary process at
    /// this exact path with a denial spec and a `pid:starttime`
    /// target, and the probe installs the filter, calls
    /// [`retire_known_stray_best_effort`] on the target, and
    /// _exits with the verdict: 20 = unresolved (false), 21 =
    /// disappearance certified (true), 3 = setup refused (filter
    /// install failed — skipped by the caller, never a test
    /// failure). A single-threaded fresh image: no fork hazards,
    /// and _exit (never return) so no harness destructor runs
    /// under the filter.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn tt04_r14011_retire_denial_probe() {
        use super::super::seccomp::{install_deny_one, DenyAction};
        let spec = match std::env::var(R14011_DENIAL_ENV) {
            Ok(spec) => spec,
            Err(_) => return,
        };
        let target = std::env::var(R14011_TARGET_ENV).expect("retire target set");
        let (pid_text, tick_text) = target.split_once(':').expect("target is pid:tick");
        let pid: libc::pid_t = pid_text.parse().expect("target pid numeric");
        let tick: u64 = tick_text.parse().expect("target tick numeric");
        // Parse BEFORE installing (allocation is filter-clean,
        // but parse failures must be loud setup errors, never
        // retire verdicts).
        let installed = match spec.as_str() {
            "pidfd" => install_deny_one(libc::SYS_pidfd_open, DenyAction::Eperm).is_ok(),
            "read" => install_deny_one(libc::SYS_read, DenyAction::Eperm).is_ok(),
            "none" => true,
            _ => false,
        };
        if !installed {
            // SAFETY: raw _exit in a fresh probe image.
            unsafe { libc::_exit(3) };
        }
        let certified = retire_known_stray_best_effort(pid, tick);
        // SAFETY: raw _exit in a fresh probe image.
        unsafe { libc::_exit(if certified { 21 } else { 20 }) };
    }

    /// R15-008: run one denial mode in a FRESH process image (the
    /// test binary re-executed with SCOPEBASE_R15008_MODE set):
    /// the seccomp pidfd-deny filter stays contained in the
    /// child, and the parent only reads its stderr. Returns the
    /// child's stderr after asserting a clean exit plus the
    /// completion marker (a filter miss fails loud, never
    /// vacuous). A SKIP marker (seccomp unavailable) passes with
    /// a loud note — same precedent as R14-011's exit-3 skip.
    #[cfg(target_arch = "x86_64")]
    fn r15008_probe_spawn(mode: &str, test: &str) -> String {
        let exe = std::env::current_exe().expect("own test binary");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg(test)
            .arg("--nocapture")
            .env("SCOPEBASE_R15008_MODE", mode)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("probe child runs");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "{mode}: probe child must exit 0\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("R15008-CHILD-DONE mode={mode}")),
            "{mode}: completion marker missing\n{stderr}"
        );
        stderr
    }

    /// R15-008: parse the child's `R15008-PINNED pid=N tick=M`
    /// line (the identity the messages must cite).
    #[cfg(target_arch = "x86_64")]
    fn r15008_probe_pinned(stderr: &str, mode: &str) -> (libc::pid_t, u64) {
        for line in stderr.lines() {
            if let Some(rest) = line.strip_prefix("R15008-PINNED ") {
                let mut pid = None;
                let mut tick = None;
                for word in rest.split_whitespace() {
                    if let Some(value) = word.strip_prefix("pid=") {
                        pid = value.parse::<libc::pid_t>().ok();
                    }
                    if let Some(value) = word.strip_prefix("tick=") {
                        tick = value.parse::<u64>().ok();
                    }
                }
                if let (Some(pid), Some(tick)) = (pid, tick) {
                    return (pid, tick);
                }
            }
        }
        panic!("{mode}: no parsable R15008-PINNED line\n{stderr}");
    }

    /// R15-008: the probe-child body — stage a live writer (+ a
    /// self-grouped probe stand-in for the timeout mode), print
    /// R15008-PINNED, optionally install the pidfd-deny filter
    /// (denial: pidfd_open fails EPERM while file reads work —
    /// R14-011's mechanism), drive the timeout body or a publish
    /// failure under catch, assert the (pid, starttime) evidence
    /// shape, prove denial took (writer survived) or success
    /// (writer gone), clean up loud, print DONE.
    #[cfg(target_arch = "x86_64")]
    fn r15008_probe_child(mode: &str) {
        use super::super::seccomp::{install_deny_one, DenyAction};
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        let denied = mode != "publish-ok";
        // Stage the live writer (sleep 49: unique to this probe
        // family).
        let mut writer = std::process::Command::new("/bin/sleep")
            .arg("49")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("writer spawns");
        let wpid = writer.id() as libc::pid_t;
        let wtick = proc_starttime(wpid)
            .expect("writer stat readable")
            .expect("writer visible");
        // Timeout mode also stages a self-grouped probe
        // stand-in (sleep 48: the body killpgs ITS group — it
        // must never be ours).
        let mut probe = if mode == "timeout" {
            let mut probe = std::process::Command::new("/bin/sleep");
            probe
                .arg("48")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // SAFETY: setpgid on self pre-exec, no userspace state.
            unsafe {
                probe.pre_exec(|| {
                    libc::setpgid(0, 0);
                    Ok(())
                });
            }
            Some(probe.spawn().expect("probe stand-in spawns"))
        } else {
            None
        };
        // Pidfile setup per mode (publish modes drive the
        // rendezvous publish through GRANDCHILD_PIDFILE_ENV).
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-r15008-{mode}-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        match mode {
            "timeout" => {
                std::fs::write(&pidfile, format!("{wpid}:{wtick}")).expect("stray record written");
            }
            "publish-unwritable" | "publish-ok" => {
                // A directory fails the O_WRONLY writability
                // probe (EISDIR) — no chmod games.
                std::env::set_var(GRANDCHILD_PIDFILE_ENV, std::env::temp_dir().as_os_str());
            }
            "publish-nonutf8" => {
                use std::os::unix::ffi::OsStrExt as _;
                let raw = b"/tmp/scopebase-r15008-\xff-nonutf8.pid";
                std::env::set_var(GRANDCHILD_PIDFILE_ENV, std::ffi::OsStr::from_bytes(raw));
            }
            "publish-atomic" => {
                claim_pidfile(&pidfile).expect("pidfile claimed");
                std::fs::create_dir(format!("{}.tmp", pidfile.display())).expect("tmp dir planted");
                std::env::set_var(GRANDCHILD_PIDFILE_ENV, &pidfile);
            }
            _ => panic!("unknown probe mode {mode}"),
        }
        eprintln!("R15008-PINNED pid={wpid} tick={wtick}");
        // Deny pidfd_open (file reads keep working): retire
        // calls fail EPERM while the writer stays live.
        if denied && !install_deny_one(libc::SYS_pidfd_open, DenyAction::Eperm).is_ok() {
            // Seccomp unavailable: clean up (no filter — plain
            // paths work) and SKIP loud, R14-011-style.
            let _ = writer.kill();
            let _ = writer.wait();
            if let Some(mut probe) = probe.take() {
                let _ = probe.kill();
                let _ = probe.wait();
            }
            let _ = std::fs::remove_file(&pidfile);
            let _ = std::fs::remove_dir(format!("{}.tmp", pidfile.display()));
            eprintln!("R15008-SKIP mode={mode} (seccomp unavailable)");
            eprintln!("R15008-CHILD-DONE mode={mode}");
            return;
        }
        // Drive the failing path under catch, then assert the
        // evidence shape on the caught message.
        let text = match mode {
            "timeout" => {
                let probe = probe.as_mut().expect("probe staged");
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    timeout_retire_hung_probe(probe, &pidfile, "R15008 timeout");
                }));
                match outcome {
                    Err(payload) => payload
                        .downcast::<String>()
                        .map(|boxed| *boxed)
                        .unwrap_or_else(|_| String::from("<non-string panic>")),
                    Ok(_) => panic!("timeout body must diverge"),
                }
            }
            _ => {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    publish_reported_grandchild(&GrandchildState::Live(wpid, wtick));
                }));
                match outcome {
                    Err(payload) => payload
                        .downcast::<String>()
                        .map(|boxed| *boxed)
                        .unwrap_or_else(|_| String::from("<non-string panic>")),
                    Ok(_) => panic!("{mode}: publish must fail"),
                }
            }
        };
        eprintln!("R15008-MSG {text}");
        if mode == "timeout" {
            assert!(
                text.contains(&format!("({wpid}, {wtick})")),
                "timeout must cite the unresolved tuple, got: {text}"
            );
        } else {
            let retired = mode == "publish-ok";
            assert!(
                text.contains(&format!(
                    "(writer pid={wpid} starttime={wtick} retired={retired})"
                )),
                "{mode}: publish must cite the writer tuple, got: {text}"
            );
        }
        // Anti-vacuity: denial took (writer survived the
        // failing path) or success certified (writer gone).
        if denied {
            assert_eq!(
                proc_starttime(wpid),
                Ok(Some(wtick)),
                "denied writer must survive (else the denial never took)"
            );
        } else {
            // The ok arm retires before reporting: gone now
            // (falls out of the publish before any wait — reap
            // via the handle first so the read below is final).
            let _ = writer.wait();
            assert_eq!(
                proc_starttime(wpid),
                Ok(None),
                "retired writer must be gone"
            );
        }
        // Loud cleanup (plain kill+wait need no pidfd — the
        // filter only denied pidfd_open).
        if denied {
            // SAFETY: signal-only to our own staged writer.
            unsafe {
                libc::kill(wpid, libc::SIGKILL);
            }
            let _ = writer.wait();
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                if proc_starttime(wpid) != Ok(Some(wtick)) {
                    break;
                }
                assert!(Instant::now() < end, "writer cleanup must retire");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if mode == "timeout" {
            let probe = probe.as_mut().expect("probe staged");
            assert!(
                probe.try_wait().expect("probe wait").is_some(),
                "timeout body must reap the probe"
            );
            assert!(
                std::fs::metadata(&pidfile).is_err(),
                "timeout body must remove the pidfile (IR-004)"
            );
        }
        if mode == "publish-atomic" {
            let _ = std::fs::remove_file(&pidfile);
            let _ = std::fs::remove_dir(format!("{}.tmp", pidfile.display()));
        }
        eprintln!("R15008-CHILD-DONE mode={mode}");
    }

    /// R15-008: timeout retirement denied (pidfd EPERM) against a
    /// live published writer must preserve the explicit
    /// unresolved (pid, starttime) tuple in the timeout message
    /// (the pidfile — the only other record — is still
    /// removed). Guards R15-002's append (mutant-checked: drop
    /// the note and this fails).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn timeout_denial_reports_unresolved_writer() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15008_MODE") {
            r15008_probe_child(&mode);
            return;
        }
        let stderr = r15008_probe_spawn(
            "timeout",
            "fixture::linux::audit::tests::timeout_denial_reports_unresolved_writer",
        );
        if stderr.contains("R15008-SKIP") {
            eprintln!("skip: seccomp unavailable for the denial probe");
            return;
        }
        let (pid, tick) = r15008_probe_pinned(&stderr, "timeout");
        assert!(
            stderr.contains(&format!("({pid}, {tick})")),
            "timeout stderr must cite the tuple\n{stderr}"
        );
    }

    /// R15-008: non-UTF-8 publish path denied must name the
    /// writer tuple + retired=false. Pre-fix the message names
    /// only the path (RED); post-fix it appends the tuple
    /// (GREEN).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn publish_nonutf8_denial_names_writer() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15008_MODE") {
            r15008_probe_child(&mode);
            return;
        }
        let stderr = r15008_probe_spawn(
            "publish-nonutf8",
            "fixture::linux::audit::tests::publish_nonutf8_denial_names_writer",
        );
        if stderr.contains("R15008-SKIP") {
            eprintln!("skip: seccomp unavailable for the denial probe");
            return;
        }
        let (pid, tick) = r15008_probe_pinned(&stderr, "publish-nonutf8");
        assert!(
            stderr.contains(&format!(
                "(writer pid={pid} starttime={tick} retired=false)"
            )),
            "publish stderr must cite the tuple\n{stderr}"
        );
    }

    /// R15-008: unwritable publish path denied must name the
    /// writer tuple + retired=false (same RED/GREEN as above).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn publish_unwritable_denial_names_writer() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15008_MODE") {
            r15008_probe_child(&mode);
            return;
        }
        let stderr = r15008_probe_spawn(
            "publish-unwritable",
            "fixture::linux::audit::tests::publish_unwritable_denial_names_writer",
        );
        if stderr.contains("R15008-SKIP") {
            eprintln!("skip: seccomp unavailable for the denial probe");
            return;
        }
        let (pid, tick) = r15008_probe_pinned(&stderr, "publish-unwritable");
        assert!(
            stderr.contains(&format!(
                "(writer pid={pid} starttime={tick} retired=false)"
            )),
            "publish stderr must cite the tuple\n{stderr}"
        );
    }

    /// R15-008: atomic-publish failure denied must name the
    /// writer tuple + retired=false (same RED/GREEN).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn publish_atomic_denial_names_writer() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15008_MODE") {
            r15008_probe_child(&mode);
            return;
        }
        let stderr = r15008_probe_spawn(
            "publish-atomic",
            "fixture::linux::audit::tests::publish_atomic_denial_names_writer",
        );
        if stderr.contains("R15008-SKIP") {
            eprintln!("skip: seccomp unavailable for the denial probe");
            return;
        }
        let (pid, tick) = r15008_probe_pinned(&stderr, "publish-atomic");
        assert!(
            stderr.contains(&format!(
                "(writer pid={pid} starttime={tick} retired=false)"
            )),
            "publish stderr must cite the tuple\n{stderr}"
        );
    }

    /// R15-008: unwritable publish path with retirement
    /// SUCCEEDING names the tuple + retired=true (the ok arm of
    /// the same append — pre-fix the message names only the
    /// path).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn publish_unwritable_success_names_writer() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15008_MODE") {
            r15008_probe_child(&mode);
            return;
        }
        let stderr = r15008_probe_spawn(
            "publish-ok",
            "fixture::linux::audit::tests::publish_unwritable_success_names_writer",
        );
        if stderr.contains("R15008-SKIP") {
            eprintln!("skip: seccomp unavailable for the denial probe");
            return;
        }
        let (pid, tick) = r15008_probe_pinned(&stderr, "publish-ok");
        assert!(
            stderr.contains(&format!("(writer pid={pid} starttime={tick} retired=true)")),
            "publish stderr must cite the tuple\n{stderr}"
        );
    }

    /// S140-round9: the re-exec'd denial probe (see
    /// [`run_preflight_middleman`]). Under a normal suite run (no
    /// rendezvous variables) this passes silently; the middleman
    /// stub execs the test binary at this exact path with a denial
    /// spec, and the probe installs the filter, runs `preflight()`,
    /// reports one line on the report fd, and _exits with the
    /// classification (20 = Ok, 21 = Err, 22 = expected
    /// barrier-timeout Err, 3 = setup refused). A single-threaded
    /// fresh image: the fork rendezvous lock starts unlocked.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn tt04_preflight_denial_exec_probe() {
        use super::super::seccomp::{install_deny_one, install_deny_ptrace_request, DenyAction};
        let spec = match std::env::var(PROBE_DENIAL_ENV) {
            Ok(spec) => spec,
            Err(_) => return,
        };
        let report: libc::c_int = std::env::var(PROBE_REPORT_FD_ENV)
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(-1);
        // Denial spec → filter installs. Any install failure is
        // setup refusal (exit 3, skipped by the caller — never a
        // test failure).
        // Write-denying specs exempt the report fd (the probe's
        // own channel); every other write stays denied.
        let installed = match spec.as_str() {
            "read-eperm" => install_deny_one(libc::SYS_read, DenyAction::Eperm).is_ok(),
            "write-traceme-eperm" => {
                install_deny_ptrace_request(libc::PTRACE_TRACEME, DenyAction::Eperm).is_ok()
                    && install_deny_errno_one(libc::SYS_write, libc::EPERM, Some(report)).is_ok()
            }
            "read-nopidfd" => {
                install_deny_one(libc::SYS_read, DenyAction::Eperm).is_ok()
                    && install_deny_one(libc::SYS_pidfd_open, DenyAction::Eperm).is_ok()
            }
            "read-nosignal" => {
                install_deny_one(libc::SYS_read, DenyAction::Eperm).is_ok()
                    && install_deny_one(libc::SYS_kill, DenyAction::Eperm).is_ok()
                    && install_deny_one(libc::SYS_pidfd_send_signal, DenyAction::Eperm).is_ok()
            }
            "write-eintr" => {
                install_deny_errno_one(libc::SYS_write, libc::EINTR, Some(report)).is_ok()
            }
            _ => false,
        };
        if !installed {
            probe_report_and_exit(report, 3, "none", "setup-filter-refused");
        }
        if spec == "write-eintr" || spec == "write-traceme-eperm" {
            // Self-check the duplicated installer in both
            // directions: other fds must answer the denial errno
            // (a wrong syscall number would install cleanly and
            // filter nothing) while the report fd stays writable —
            // both must fail loud, never skip.
            let want = if spec == "write-eintr" {
                libc::EINTR
            } else {
                libc::EPERM
            };
            let byte = [0u8; 1];
            // SAFETY: bad-fd write answered by the filter, never run.
            let got = unsafe { libc::write(-1, byte.as_ptr() as *const _, 1) };
            assert!(
                got < 0 && last_errno_is(want),
                "write filter must answer its errno"
            );
            // SAFETY: zero-length write emits no bytes.
            let zero = unsafe { libc::write(report, byte.as_ptr() as *const _, 0) };
            assert_eq!(zero, 0, "report fd must escape the write denial");
        }
        match preflight() {
            Ok(_) => probe_report_and_exit(report, 20, &probe_children_state(), ""),
            Err(error) => {
                let text = error.to_string();
                // S132-round9: the expected timeout is the EXACT
                // shape — never a substring: an unresolved
                // retirement (`…; preflight child not proven
                // reaped`) must refuse, not masquerade as 22.
                let code = if text == EXPECTED_BARRIER_TIMEOUT {
                    22
                } else {
                    21
                };
                probe_report_and_exit(report, code, &probe_children_state(), &text);
            }
        }
    }

    /// R10-012: the confined-subreaper retirement probe (see
    /// [`adopted_grandchild_retires_under_subreaper`]). Under a
    /// normal suite run (no rendezvous variable) this passes
    /// silently; the parent test spawns a FRESH test-binary
    /// process at this exact path with the rendezvous set, and
    /// the probe marks ITSELF a child subreaper (confined — the
    /// flag dies with this process; the suite binary never sets
    /// it globally) before running both unresolved-retirement
    /// controls. Pre-fix the retired grandchild is the probe's
    /// own zombie and `retire_reported_grandchild` panics after
    /// five seconds (RED); post-fix the wait loop reaps what it
    /// adopted. The probe finally proves no child status
    /// remains anywhere (reaping stragglers so even RED runs
    /// stay clean, then requiring zero).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn tt04_subreaper_retire_probe() {
        use std::time::Duration;
        if std::env::var(SUBREAPER_PROBE_ENV).is_err() {
            return;
        }
        // Own process group first: a hung probe run lets the
        // parent retire the whole tree by group.
        // SAFETY: setpgid on self, no userspace state.
        unsafe {
            libc::setpgid(0, 0);
        }
        // SAFETY: prctl on self; marking a fresh probe process.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0,
            "probe must become a child subreaper"
        );
        for spec in ["read-nopidfd", "read-nosignal"] {
            let outcome = run_preflight_middleman(spec, Duration::from_secs(30));
            // R13-005: publish BEFORE any retire/panic/exit — a
            // death from here to the retirement must still leave
            // the writer's identity for the parent's expiry. A
            // setup refusal (code 3) publishes nothing (None).
            publish_reported_grandchild(&outcome.grandchild);
            if outcome.code == 3 {
                eprintln!("skip: seccomp unavailable for {spec}");
                return;
            }
            // R13-005: injected abandon — exit AFTER the birth is
            // published but BEFORE the retirement below, leaving
            // the parked writer for the parent's expiry path.
            if std::env::var(SUBREAPER_ABANDON_ENV).is_ok()
                && matches!(outcome.grandchild, GrandchildState::Live(..))
            {
                std::process::exit(42);
            }
            let cleaned = match outcome.grandchild {
                GrandchildState::Live(pid, started) => retire_reported_grandchild(pid, started),
                GrandchildState::None => false,
            };
            assert_eq!(
                outcome.code, 21,
                "{spec}: unresolved retirement must refuse, got exit {}",
                outcome.code
            );
            assert!(
                outcome.err.contains("not proven reaped"),
                "{spec}: production must report the unresolved custody, got: {}",
                outcome.err
            );
            assert!(
                cleaned,
                "{spec}: the parked grandchild must need independent cleanup"
            );
        }
        // No child status may remain: the middlemen were reaped
        // by the runner, the grandchildren by the retirement —
        // reap stragglers (RED runs stay clean) then require
        // zero.
        let mut stragglers = 0;
        loop {
            let mut status = 0;
            // SAFETY: waitpid(-1) reaps any owned child.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if got > 0 {
                stragglers += 1;
                continue;
            }
            if got < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
            }
            break;
        }
        assert_eq!(stragglers, 0, "retirement must leave no child status");
    }

    /// IR-003 probe (fresh image only — runs only when
    /// IR003_INJECT_ENV is set): drives the middleman op with
    /// the firstborn-stat failure injected and reports the
    /// panic message + observed pgid to the verdict file named
    /// by IR003_VERDICT_ENV. Never asserts (the parent
    /// judges); exit success bounds the run. Under a normal
    /// suite run (no rendezvous variable) this passes
    /// silently.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ir003_firstborn_stat_probe() {
        use std::time::Duration;
        if std::env::var(IR003_INJECT_ENV).is_err() {
            return;
        }
        // Own process group first (mirror the subreaper probe:
        // a hung probe run lets the parent retire the whole
        // tree by group).
        // SAFETY: setpgid on self, no userspace state.
        unsafe {
            libc::setpgid(0, 0);
        }
        let verdict = std::env::var(IR003_VERDICT_ENV).expect("ir003 verdict path set");
        let observed = std::sync::atomic::AtomicI32::new(-1);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_preflight_middleman_observed(
                "read-nopidfd",
                Duration::from_secs(30),
                &observed,
                PROBE_TEST_PATH,
            )
        }));
        let message = match outcome {
            Ok(_) => "ir003: no panic (injection missed)".to_string(),
            Err(payload) => payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    payload
                        .downcast_ref::<&str>()
                        .map(|message| message.to_string())
                })
                .unwrap_or_else(|| "ir003: non-string panic".to_string()),
        };
        let pgid = observed.load(std::sync::atomic::Ordering::SeqCst);
        // R15-003: report the middleman tick too (0 when already
        // gone) so the parent's RED-path hygiene killpg gates on
        // identity instead of firing at a bare number.
        let mtick = proc_starttime(pgid).ok().flatten().unwrap_or(0);
        std::fs::write(&verdict, format!("{pgid}\n{mtick}\n{message}\n"))
            .expect("ir003 verdict written");
    }

    /// R11-013: the confined-subreaper GUARD probe (see
    /// [`guard_retires_adopted_grandchild`]). Under a normal
    /// suite run (no rendezvous variable) this passes silently;
    /// the parent test spawns a FRESH test-binary process at
    /// this exact path with the rendezvous set, and the probe
    /// marks ITSELF a child subreaper (confined — the flag dies
    /// with this process; the suite binary never sets it
    /// globally) before firing the pre-report guard with the
    /// grandchild born and barrier-parked. Pre-fix the adopted
    /// grandchild zombie holds the group observable and the
    /// group probe expires (RED); post-fix the group
    /// retirement drains it and both probes are clean. The
    /// sweep reaps stragglers before asserting zero, so even
    /// RED runs stay clean (and the probe's exit reparents any
    /// remainder to init).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn tt04_adopting_guard_probe() {
        use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
        use std::time::{Duration, Instant};
        if std::env::var(GUARD_PROBE_ENV).is_err() {
            return;
        }
        // Own process group first: a hung probe run lets the
        // parent retire the whole tree by group.
        // SAFETY: setpgid on self, no userspace state.
        unsafe {
            libc::setpgid(0, 0);
        }
        // SAFETY: prctl on self; marking a fresh probe process.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0,
            "probe must become a child subreaper"
        );
        let pgid = AtomicI32::new(-1);
        let born = AtomicBool::new(false);
        let done = AtomicBool::new(false);
        let caught = std::thread::scope(|scope| {
            scope.spawn(|| {
                // Birth watcher: the 2s guard spins with the
                // grandchild born and barrier-parked — stable
                // for observation, not a fleeting window.
                while !done.load(Ordering::SeqCst) {
                    if middleman_has_child(pgid.load(Ordering::SeqCst)) {
                        born.store(true, Ordering::SeqCst);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
            // The runner holds only raw descriptors and locals
            // across this boundary (no locks, no aliasing
            // invariants) — catching its guard panic is sound.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_preflight_middleman_observed(
                    "write-eintr",
                    Duration::from_secs(2),
                    &pgid,
                    PROBE_TEST_PATH,
                )
            }));
            done.store(true, Ordering::SeqCst);
            match outcome {
                Err(err) => err,
                // R13-005: the lost race — the middleman reported
                // before the guard fired, so no group retirement
                // ran. Publish the reported writer for the parent's
                // expiry, then retire it best-effort (never
                // asserted: cleanup must not mask the guard
                // evidence below) before the intended panic.
                Ok(reported) => {
                    publish_reported_grandchild(&reported.grandchild);
                    // R15-008: the lost race retires best-effort —
                    // the outcome travels with the report.
                    let mut note = String::new();
                    if let GrandchildState::Live(pid, started) = reported.grandchild {
                        let retired = retire_known_stray_best_effort(pid, started);
                        note = writer_retire_note(pid, started, retired);
                    }
                    panic!(
                        "2s guard must fire mid-EINTR-spin, got exit {}{}",
                        reported.code, note
                    )
                }
            }
        });
        assert!(
            born.load(Ordering::SeqCst),
            "grandchild birth never observed before the guard fired"
        );
        let group = pgid.load(Ordering::SeqCst);
        assert!(
            group > 1,
            "runner must publish the middleman pgid, got {group}"
        );
        // R11-017: the caught panic must be the intended
        // pre-report guard timeout (shared gate — any other
        // panic fails loud here, never vacuously below).
        assert_guard_pre_report_timeout(caught, Duration::from_secs(2), group);
        // Empty group first: a zombie still holds it observable.
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: signal 0 probes existence only.
            let probed = unsafe { libc::killpg(group, 0) };
            if probed < 0 {
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                assert_eq!(
                    errno,
                    libc::ESRCH,
                    "group probe must fail ESRCH-only, got {errno}"
                );
                break;
            }
            assert!(
                Instant::now() < end,
                "process group {group} survived the guard retirement"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // ...then no adopted child status anywhere: reap
        // stragglers (RED runs stay clean) then require zero.
        let mut stragglers = 0;
        loop {
            let mut status = 0;
            // SAFETY: waitpid(-1) reaps any owned child.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if got > 0 {
                stragglers += 1;
                continue;
            }
            if got < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
            }
            break;
        }
        assert_eq!(stragglers, 0, "retirement must leave no child status");
    }

    /// R12-007: the collection-expiry subreaper probe (see
    /// [`expiry_retires_adopted_group`]). Under a normal suite
    /// run (no rendezvous variable) this passes silently; the
    /// parent test spawns a FRESH test-binary process at this
    /// exact path with the rendezvous set, and the probe marks
    /// ITSELF a child subreaper (confined — the flag dies with
    /// this process; the suite binary never sets it globally)
    /// before staging a probe whose writer holds stdout past the
    /// collection deadline. Pre-fix the single-pass adopted
    /// drain runs µs after killpg while deaths land ~50µs later,
    /// so the adopted writer zombie holds the group observable
    /// and the group probe fails (RED); post-fix the bounded
    /// drain reaps it and both probes are clean. The sweep reaps
    /// stragglers before asserting zero, so even RED runs stay
    /// clean (and the probe's exit reparents any remainder to
    /// init).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn collection_expiry_adopting_probe() {
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        if std::env::var(EXPIRY_PROBE_ENV).is_err() {
            return;
        }
        if !staged_probe_python3() {
            eprintln!("skip: python3 unavailable (no staged probes)");
            return;
        }
        // Own process group first: a hung probe run lets the
        // parent retire the whole tree by group.
        // SAFETY: setpgid on self, no userspace state.
        unsafe {
            libc::setpgid(0, 0);
        }
        // SAFETY: prctl on self; marking a fresh probe process.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0,
            "probe must become a child subreaper"
        );
        // The probe: self-grouped python forking a SAME-group
        // writer (no setpgid in the child — killpg must reach
        // it) that sleeps past the collection deadline holding
        // stdout, then exiting at once.
        let mark = format!("{STAGED_PROBE_MARK}-R12007");
        let script = format!(
            "# {mark}\nimport os, sys, time\nkid = os.fork()\nif kid == 0:\n    os.closerange(3, 4096)\n    time.sleep(10)\n    os._exit(0)\n"
        );
        let mut probe = std::process::Command::new("python3");
        probe
            .arg("-c")
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            probe.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut probe = probe.spawn().expect("expiry probe spawns");
        let id = probe.id() as libc::pid_t;
        let expected = proc_starttime(id)
            .expect("probe stat readable")
            .expect("probe visible");
        // Staging proof: the writer exists, is marked, and sits
        // IN the probe group (a writer anywhere else would make
        // the group-absence assert below vacuous).
        let (_writer, _writer_tick, writer_group) = {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let mut marked = audit_marked_tasks(&mark, expected, id);
                if marked.len() == 1 {
                    break marked.pop().unwrap();
                }
                assert!(
                    Instant::now() < end,
                    "writer never appeared, got {marked:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        assert_eq!(writer_group, id, "writer must stay in the probe group");
        // Reap the probe (the caller-side wait the R12-005
        // contract names): the writer reparents to us (we are a
        // subreaper) and holds stdout past the deadline.
        let status = probe.wait().expect("probe exit");
        assert!(status.success());
        // Expire the collection: the writer's 10s sleep holds
        // EOF past the 2s deadline.
        let end = Instant::now() + Duration::from_secs(2);
        let got = collect_probe_output_bounded(&mut probe, end, expected, &[]);
        assert!(
            got.is_none(),
            "writer-held collection must expire (dead fixture otherwise)"
        );
        // Empty group first: a zombie still holds it observable.
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: signal 0 probes existence only.
            let probed = unsafe { libc::killpg(id, 0) };
            if probed < 0 {
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                assert_eq!(
                    errno,
                    libc::ESRCH,
                    "group probe must fail ESRCH-only, got {errno}"
                );
                break;
            }
            assert!(
                Instant::now() < end,
                "process group {id} survived the collection expiry"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // ...then no adopted child status anywhere: reap
        // stragglers (RED runs stay clean) then require zero.
        let mut stragglers = 0;
        loop {
            let mut status = 0;
            // SAFETY: waitpid(-1) reaps any owned child.
            let got = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if got > 0 {
                stragglers += 1;
                continue;
            }
            if got < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
            }
            break;
        }
        assert_eq!(stragglers, 0, "expiry must leave no child status");
    }

    /// R10-012: await /proc disappearance, reaping an adopted
    /// zombie along the way. Under a subreaper (or PID-1) runner
    /// the signaled grandchild reparents to US — its /proc entry
    /// survives until WE reap it, so the loop waitpids (WNOHANG,
    /// errors ignored: ECHILD means someone else owns it) before
    /// polling disappearance. True when gone within `timeout`,
    /// false on expiry. Never panics — the caller decides.
    /// R11-005: `expected` starttime-gates the numeric wait (see
    /// body): absence and reuse return true without waiting.
    /// IR1 (internal review round 1): the wait also skips on
    /// unreadable stats (the Err arm proves nothing — waiting
    /// there could reap an unrelated same-number child), and
    /// the gate-to-wait gap is documented below. Residual: the
    /// stat read and the wait are separate syscalls
    /// (descheduling widens the gap): the expected task could
    /// exit, be reaped elsewhere, and the number recycled to
    /// OUR new child between them — WNOHANG would then
    /// consume the newcomer's status. Accepted: the recycle
    /// must land on a number we fork concurrently in the same
    /// microsecond window (our forks are sparse and never
    /// target dead numbers), WNOHANG never blocks, and the
    /// consequence is bounded to status confusion in test
    /// retirement (never a signal). A pin-based waitid would
    /// close it; disproportionate here.
    #[cfg(target_arch = "x86_64")]
    fn await_proc_gone_reaping(
        pid: libc::pid_t,
        expected: u64,
        timeout: std::time::Duration,
    ) -> bool {
        await_proc_gone_reaping_with(pid, expected, timeout, proc_starttime)
    }

    /// IR1: seam for the unreadable-stat regression: `gate`,
    /// when it reports Err, must skip the wait (unknown is
    /// never waited on). Production callers use
    /// [`await_proc_gone_reaping`].
    #[cfg(target_arch = "x86_64")]
    fn await_proc_gone_reaping_with(
        pid: libc::pid_t,
        expected: u64,
        timeout: std::time::Duration,
        gate: impl Fn(libc::pid_t) -> Result<Option<u64>, String>,
    ) -> bool {
        let end = std::time::Instant::now() + timeout;
        loop {
            // R11-005: the numeric wait is starttime-gated —
            // waitpid fires ONLY while /proc proves the number
            // still hosts the expected task. Absence (nothing
            // left to reap: our own zombie would still show)
            // and reuse (a different holder means the awaited
            // task is gone, else the number could not host
            // another) both return true WITHOUT waiting, so an
            // unrelated same-number child is detected and
            // spared, never reaped by us. Unreadable stats keep
            // polling (never claimed gone, never waited on).
            match gate(pid) {
                Ok(None) => return true,
                Ok(Some(now)) if now != expected => return true,
                Ok(Some(_)) => {
                    // SAFETY: waitpid on the verified holder;
                    // reaps an adopted zombie, ECHILD
                    // otherwise — always ignored.
                    let mut status = 0;
                    unsafe {
                        libc::waitpid(pid, &mut status, libc::WNOHANG);
                    }
                }
                Err(_) => {}
            }
            if std::time::Instant::now() >= end {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// S140-round9: retire a grandchild the middleman reported
    /// alive: pin first, verify the reported starttime still names
    /// it, signal through the pin, prove disappearance. The
    /// grandchild reparented to init when the middleman exited, so
    /// init reaps it once dead — /proc disappearance is the proof.
    /// R10-012: when the runner itself adopted the grandchild
    /// (subreaper or PID-1 runner) the wait also reaps — an
    /// owned zombie disappears only through our own waitpid.
    /// Returns true when the grandchild was found alive and retired
    /// (false: already gone — nothing needed cleanup).
    #[cfg(target_arch = "x86_64")]
    fn retire_reported_grandchild(pid: libc::pid_t, started: u64) -> bool {
        // Pin first: the pin names whoever holds the number now.
        let pin = match super::super::seccomp::pidfd_open_raw(pid) {
            Ok(pin) => pin,
            Err(_) => return false,
        };
        // Verify the CURRENT holder is the reported task: a changed
        // holder (or none) means the original retired — close the
        // pin and report nothing to do WITHOUT signaling.
        if proc_starttime(pid) != Ok(Some(started)) {
            // SAFETY: pin owned by this scope.
            unsafe { libc::close(pin) };
            return false;
        }
        // SAFETY: pidfd_send_signal(pidfd, SIGKILL, NULL, 0).
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pin as libc::c_long,
                libc::SIGKILL as libc::c_long,
                0 as libc::c_long,
                0 as libc::c_long,
            )
        };
        // SAFETY: pin owned by this scope.
        unsafe { libc::close(pin) };
        assert_eq!(
            sent, 0,
            "reported grandchild must be signalable through its pin"
        );
        assert!(
            await_proc_gone_reaping(pid, started, std::time::Duration::from_secs(5)),
            "reported grandchild {pid} resisted retirement"
        );
        true
    }

    /// S110/S111-round8: run `preflight()` in a forked middleman
    /// under a caller-selected seccomp denial, returning what the
    /// middleman reported. The parent enforces `guard` so a
    /// deadlock FAILS instead of hanging the suite.
    /// S140-round9: the middleman stub execs a FRESH test-binary
    /// image before running any allocation- or lock-using Rust code
    /// (the denial spec crosses the exec as an environment
    /// variable — no closure can). The old raw-forked middleman
    /// inherited the multithreaded image, including a possibly
    /// locked fork rendezvous mutex, and deadlocked in
    /// `preflight()` whenever another test held it across the fork.
    /// `spec` is one of `read-eperm`, `write-traceme-eperm`,
    /// `read-nopidfd`, `read-nosignal`, `write-eintr`.
    #[cfg(target_arch = "x86_64")]
    fn run_preflight_middleman(spec: &'static str, guard: Duration) -> MiddlemanOutcome {
        let observed = std::sync::atomic::AtomicI32::new(-1);
        run_preflight_middleman_observed(spec, guard, &observed, PROBE_TEST_PATH)
    }

    /// R10-011: guard-fire retirement of a hung middleman AND its
    /// process group. The middleman leads its own group
    /// (pgid == its pid — set both pre-exec in the child and
    /// post-fork in the parent, so the group exists from
    /// microseconds after the fork regardless of child
    /// scheduling); the grandchild inherits it. Order matters:
    /// kill the group first (middleman and grandchild alike —
    /// SIGKILL reaches even a SIGSTOP-stranded orphan), then
    /// the middleman directly (belt-and-braces), reap it
    /// (proving no further fork is possible), then kill the
    /// group AGAIN (catching anything forked between the first
    /// signal's queueing and its delivery). Errors ignored: a
    /// dead or never-grouped target answers ESRCH.
    /// R11-013: then drain adopted group zombies and PROVE the
    /// group empty, returning the verdict. When the suite runs
    /// as PID 1 or under a subreaper, the dead grandchild
    /// becomes OUR zombie (otherwise init adopts and reaps it
    /// and the drain is a no-op) — and a zombie still holds
    /// the group observable. waitpid(-pgid) reaps only OUR
    /// children in THIS group, so a multithreaded suite never
    /// steals another test's children. Bounded: a
    /// doomed-but-undelivered member lands on a later pass; an
    /// unkillable one reports survival instead of hanging the
    /// guard. True when the group probes ESRCH-empty.
    #[cfg(target_arch = "x86_64")]
    fn retire_hung_middleman_group(pid: libc::pid_t) -> bool {
        use std::time::{Duration, Instant};
        // SAFETY: signal-only; the pgid names our own group.
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            libc::killpg(pid, libc::SIGKILL);
        }
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            loop {
                let mut status = 0;
                // SAFETY: -pgid filters to our children in our
                // own group; WNOHANG never blocks.
                let got = unsafe { libc::waitpid(-pid, &mut status, libc::WNOHANG) };
                if got > 0 {
                    continue;
                }
                if got < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                }
                break;
            }
            // SAFETY: signal 0 probes existence only.
            let probed = unsafe { libc::killpg(pid, 0) };
            if probed < 0 {
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                return errno == libc::ESRCH;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// S110/S111-round8 runner with R10-011 group retirement and
    /// pgid observation: `observed_pgid` receives the middleman
    /// pid (== its process-group id) microseconds post-fork, so
    /// a test can independently prove BOTH generations retired
    /// even when the guard panics (the outcome never returns on
    /// that path). Every guard-fire path retires the whole
    /// group through [`retire_hung_middleman_group`] before
    /// panicking — the failure stays loud, never a leak.
    /// R14-008: while the report is awaited, a probe's runner
    /// publishes the middleman's firstborn the slice it appears
    /// (birth publication — a probe death between birth and
    /// report still leaves the writer's identity for the
    /// parent's expiry). Dual gate: armed only when
    /// [`GRANDCHILD_PIDFILE_ENV`] plus a probe identity
    /// ([`SUBREAPER_PROBE_ENV`] or [`GUARD_PROBE_ENV`], R14-009)
    /// are set — every other caller (in-suite runners) keeps
    /// the single long poll with zero behavior change, and a
    /// transient ambient rendezvous (R14-003's own-env window)
    /// can never arm it.
    #[cfg(target_arch = "x86_64")]
    fn run_preflight_middleman_observed(
        spec: &'static str,
        guard: Duration,
        observed_pgid: &std::sync::atomic::AtomicI32,
        probe_path: &str,
    ) -> MiddlemanOutcome {
        use std::os::unix::ffi::OsStringExt as _;
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};
        // Report pipe: the probe's single line. The write end must
        // stay non-CLOEXEC (it crosses the exec); the read end is
        // cloexec'd so the probe never inherits it.
        let mut pipe = [0; 2];
        // R11-017: BOTH ends cloexec from birth (pipe2 is
        // atomic — no fcntl window). The write end must cross
        // only OUR middleman's exec: with a plain pipe, a
        // sibling guard test's concurrent fork inherits a
        // non-cloexec copy of our write end, its exec keeps
        // the copy, and our EOF never arrives — the runner
        // then dies by its own guard deadline instead of the
        // exit/report assertion (the bogus-path test failed
        // 6/10 paired runs this way). The child clears
        // cloexec on the write end pre-exec below.
        // IR1 residual (internal review round 1): cloexec
        // guards EXEC'D siblings only — a FORK-ONLY sibling
        // child (no exec) inherits the write end and holds
        // EOF for its lifetime, cloexec or not. Accepted:
        // every fork-only child in this lib test process is
        // short-lived (exits or is retired in milliseconds —
        // R10-007/R11-018 shapes), while flipping the bogus
        // runner needs EOF held past its 2 s guard deadline;
        // a future 2 s+ fork-only child must close inherited
        // fds (close_range) or this race returns.
        // R12-008: the violators are closed — the 5s stopped
        // child sheds via close_range (keeps its report fd +
        // stdio), and the 6/10/30s staged python sleepers shed
        // via os.closerange(3, 4096) (keeps stdio pipes, mark,
        // group). fork_pauser stays bare deliberately (its
        // microsecond placement loop cannot afford 1-2µs per
        // fork, and the toolchain binary has no 2s EOF guard).
        // SAFETY: valid out-pointer for the pipe ends.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // Rendezvous strings, built pre-fork: the child borrows
        // their (inherited) bytes without allocating.
        let exe = std::ffi::CString::new(
            std::env::current_exe()
                .expect("middleman test binary path")
                .into_os_string()
                .into_vec(),
        )
        .expect("test binary path is C-safe");
        // R11-017: the probe path is a parameter (production
        // callers pass PROBE_TEST_PATH) so the bogus-path
        // regression can stage a middleman that runs zero
        // tests.
        let probe = std::ffi::CString::new(probe_path).expect("probe path is C-safe");
        let exact = std::ffi::CString::new("--exact").expect("static");
        let denial =
            std::ffi::CString::new(format!("{PROBE_DENIAL_ENV}={spec}")).expect("spec is C-safe");
        // SAFETY: raw fork; the child execs immediately — stack
        // formatting plus one execve, never allocating, locking,
        // or returning into test code. Immune to the
        // inherited-mutex hazard by construction (no Rust runtime
        // call between fork and exec).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            // Stack-format the report-fd variable (the fd number
            // is dynamic — no allocation):
            // `SCOPEBASE_TT04_PREFLIGHT_REPORT_FD=<n>`.
            let mut var = [0u8; 128];
            let prefix = PROBE_REPORT_FD_ENV.as_bytes();
            var[..prefix.len()].copy_from_slice(prefix);
            var[prefix.len()] = b'=';
            let mut len = prefix.len() + 1;
            let mut digits = [0u8; 16];
            let mut dlen = 0;
            let mut value = pipe[1] as u32;
            loop {
                digits[dlen] = b'0' + (value % 10) as u8;
                dlen += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            let mut i = 0;
            while i < dlen {
                var[len] = digits[dlen - 1 - i];
                len += 1;
                i += 1;
            }
            var[len] = 0;
            let argv = [
                exe.as_ptr(),
                probe.as_ptr(),
                exact.as_ptr(),
                std::ptr::null(),
            ];
            let envp = [
                denial.as_ptr(),
                var.as_ptr() as *const libc::c_char,
                std::ptr::null(),
            ];
            // R10-011: own process group (async-signal-safe,
            // pre-exec — our grandchild inherits it, so the
            // guard can retire BOTH generations by group).
            // SAFETY: setpgid on self, no userspace state.
            unsafe {
                libc::setpgid(0, 0);
            }
            // R11-017: clear cloexec on the report write end
            // (async-signal-safe fcntl, pre-exec) so ONLY this
            // middleman carries it across exec — sibling
            // forks' copies stay cloexec and die at their
            // exec, so no sibling can hold our EOF hostage.
            // SAFETY: fcntl flag-clear on an owned descriptor.
            // No panic machinery post-fork (inherited-mutex
            // hazard) — fail fast with _exit on the
            // essentially-impossible error instead.
            unsafe {
                if libc::fcntl(pipe[1], libc::F_SETFD, 0) != 0 {
                    libc::_exit(127);
                }
            }
            unsafe {
                libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        // R10-011: group the middleman from the parent side too
        // (EACCES: it already exec'd, so the child-side call
        // above won; ESRCH: it already died — nothing to
        // group). At least one side wins before any grandchild
        // fork, and the group exists from here regardless of
        // child scheduling — a later killpg can never address
        // a foreign group id.
        // SAFETY: setpgid on our own unwaited-for child.
        unsafe {
            libc::setpgid(pid, pid);
        }
        observed_pgid.store(pid, Ordering::SeqCst);
        // SAFETY: write end owned by the middleman now.
        unsafe { libc::close(pipe[1]) };
        let deadline = Instant::now() + guard;
        // R14-008: birth watch, armed once (a probe's rendezvous
        // is process-stable; a per-slice env read would chase
        // ambient windows). R14-009: the guard probe arms it too
        // (same middleman ops, same birth-to-report window, same
        // rendezvous read by its parent). R14-010: rendezvous
        // presence via var_os (a set-but-non-UTF-8 value still
        // arms — the first birth publish then fails loud there,
        // never silently suppressed here).
        let birth_watch = std::env::var_os(GRANDCHILD_PIDFILE_ENV).is_some()
            && (std::env::var(SUBREAPER_PROBE_ENV).is_ok()
                || std::env::var(GUARD_PROBE_ENV).is_ok());
        let mut birth_published: Option<(libc::pid_t, u64)> = None;
        // Bounded newline-framed report read: the probe writes one
        // line (even on setup refusal) and a parked grandchild
        // holding the write end must not stall the parent — EOF is
        // NOT required (S138's lesson).
        let mut line = Vec::new();
        loop {
            if line.contains(&b'\n') {
                break;
            }
            assert!(
                line.len() < 4096,
                "middleman report line overruns its frame"
            );
            // R14-008: publish the firstborn the slice it appears
            // (birth before report — a probe death from here to
            // the return still leaves the writer's identity).
            if birth_watch {
                match (middleman_first_child(pid), birth_published) {
                    (Some(born), None) => {
                        // IR-003 test injection (fresh-image probe
                        // only — the env rides solely on the probe
                        // child's command): synthesize the
                        // ~EMFILE-only stat failure so the real
                        // Err arm below runs end to end.
                        let stat = if std::env::var_os(IR003_INJECT_ENV).is_some() {
                            Err("ir003-injected firstborn stat failure".to_string())
                        } else {
                            proc_starttime(born)
                        };
                        match stat {
                            Ok(Some(tick)) => {
                                publish_reported_grandchild(&GrandchildState::Live(born, tick));
                                birth_published = Some((born, tick));
                            }
                            // Listed but already gone: a fleeting task,
                            // not the parked writer — keep watching.
                            Ok(None) => {}
                            // Our own tasks stay stat-visible: an
                            // unreadable birth identity fails closed,
                            // never half-published.
                            Err(error) => {
                                // IR-003: the birth number is known
                                // but its tick is not — no record can
                                // publish, and the unwinding probe
                                // would strand the born writer in the
                                // middleman group. Retire the whole
                                // group first (the writer shares it);
                                // the verdict folds into the panic
                                // text (R11-013), and the report read
                                // end closes (mirror the timeout
                                // path) so the catching probe keeps
                                // no stale fd.
                                let retired = retire_hung_middleman_group(pid);
                                // SAFETY: read end owned by this scope.
                                unsafe {
                                    libc::close(pipe[0]);
                                }
                                panic!(
                                    "middleman firstborn stat unreadable: {error} \
                                     (group {pid} retired: {retired})"
                                );
                            }
                        }
                    }
                    (Some(born), Some((latched, _))) if born != latched => {
                        panic!("middleman forked twice ({latched}, then {born}): fixture broken")
                    }
                    // Same birth, or the latched birth already
                    // retired ahead of the report — nothing to do.
                    _ => {}
                }
            }
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32;
            if remaining <= 0 {
                // R10-011: retire the whole group (the unborn or
                // unnamed grandchild dies with its middleman —
                // no EOF→TRACEME→SIGSTOP orphan escapes), then
                // fail loud. No report arrived, so the pgid
                // (published post-fork) is the independent
                // retirement handle. R11-013: the retirement
                // verdict folds into the panic text (a surviving
                // group must never read as retired).
                let retired = retire_hung_middleman_group(pid);
                // SAFETY: read end owned by this scope.
                unsafe {
                    libc::close(pipe[0]);
                }
                panic!(
                    "middleman hung past {guard:?} (deadlock under denial; \
                     group {pid} retired: {retired}, no report received)"
                );
            }
            // R14-008: slice the poll while birth-armed (prompt
            // publication); unarmed callers keep one long wait.
            // The slice applies AFTER the guard check above, so
            // the deadline semantics never change.
            let remaining = if birth_watch {
                remaining.min(20)
            } else {
                remaining
            };
            let mut waiting = libc::pollfd {
                fd: pipe[0],
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: valid pollfd for an owned descriptor.
            let ready = unsafe { libc::poll(&mut waiting, 1, remaining) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("middleman report poll failed: {error}");
            }
            if ready == 0 {
                continue;
            }
            let mut byte = [0u8; 256];
            // SAFETY: bounded read from the report pipe.
            let got = unsafe {
                libc::read(
                    pipe[0],
                    byte.as_mut_ptr() as *mut libc::c_void,
                    byte.len() as libc::size_t,
                )
            };
            if got <= 0 {
                break;
            }
            line.extend_from_slice(&byte[..got as usize]);
        }
        // SAFETY: read end owned by this scope.
        unsafe { libc::close(pipe[0]) };
        let outcome = parse_middleman_line(&String::from_utf8_lossy(&line));
        loop {
            let mut status = 0;
            // SAFETY: valid status out-pointer for an owned child.
            let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if got == pid {
                assert!(
                    libc::WIFEXITED(status),
                    "middleman died by signal under denial"
                );
                let code = libc::WEXITSTATUS(status);
                assert_eq!(
                    code, outcome.code,
                    "middleman exit must match its report line"
                );
                return outcome;
            }
            if got < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("middleman wait failed: {error}");
            }
            if Instant::now() >= deadline {
                // R10-011: the report arrived but the middleman
                // never exited — retire the whole group before
                // failing loud (the reported grandchild dies by
                // group signal; its disappearance is polled and
                // FOLDED into the panic text, never asserted —
                // a second panic must not mask the guard).
                // R11-013: the group verdict folds in likewise.
                let retired = retire_hung_middleman_group(pid);
                let note = match &outcome.grandchild {
                    GrandchildState::Live(gpid, started) => {
                        let gone = await_proc_gone_reaping(*gpid, *started, Duration::from_secs(5));
                        format!("; reported grandchild {gpid} gone: {gone}")
                    }
                    GrandchildState::None => String::new(),
                };
                panic!("middleman hung past {guard:?} (deadlock under denial; group retired: {retired}){note}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// S110-round8: inherited write→EPERM + TRACEME→EPERM must
    /// refuse bounded — never deadlock. Pre-fix the middleman's
    /// release write fails silently while the grandchild (holding
    /// the release write end) blocks for a byte-or-EOF that never
    /// comes and the middleman blocks reading its report: the hang
    /// guard fires (RED). Post-fix the failed release write
    /// retires bounded and refuses.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn denied_release_write_refuses_bounded() {
        use std::time::Duration;
        let outcome = run_preflight_middleman("write-traceme-eperm", Duration::from_secs(20));
        if outcome.code == 3 {
            eprintln!("skip: seccomp unavailable for the combined denial");
            return;
        }
        assert_eq!(
            outcome.code, 21,
            "denied release write must refuse, got exit {}",
            outcome.code
        );
        assert!(
            outcome.err.starts_with("preflight release refused:"),
            "release refusal must name its stage, got: {}",
            outcome.err
        );
        assert!(
            !outcome.err.contains("not proven reaped"),
            "S110 retirement must be proven, got: {}",
            outcome.err
        );
        assert!(
            matches!(outcome.grandchild, GrandchildState::None),
            "refused release must leave no grandchild, got: {:?}",
            outcome.grandchild
        );
    }

    /// S111-round8: a denied barrier read must PARK the child
    /// (never proceed to exit before the parent pins it) and the
    /// parent must refuse bounded. Pre-fix the child proceeds on
    /// EPERM and preflight reports Ok — the barrier silently
    /// bypassed (RED). Post-fix the parent times out the unproven
    /// report, retires the parked child, and refuses.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn denied_barrier_read_parks_and_refuses() {
        use std::time::Duration;
        let outcome = run_preflight_middleman("read-eperm", Duration::from_secs(30));
        if outcome.code == 3 {
            eprintln!("skip: seccomp unavailable for the read denial");
            return;
        }
        assert_eq!(
            outcome.code, 22,
            "denied barrier read must time out the report, got exit {}",
            outcome.code
        );
        // S132-round9: the pass requires the EXACT expected shape
        // (not a substring) plus retirement proof: no surviving
        // grandchild may remain.
        assert_eq!(
            outcome.err, EXPECTED_BARRIER_TIMEOUT,
            "expected-timeout shape must be exact"
        );
        assert!(
            matches!(outcome.grandchild, GrandchildState::None),
            "timed-out report must retire its parked child, got: {:?}",
            outcome.grandchild
        );
    }

    /// S132-round9: an unresolved retirement must NOT classify as
    /// the expected timeout. With the barrier denied AND pidfd
    /// acquisition denied, the parked grandchild cannot be
    /// signaled, production reports `…; preflight child not proven
    /// reaped`, and the middleman must refuse (21 — never 22). The
    /// test retires the reported grandchild through its own
    /// independent authority (cleanup runs before the assertions so
    /// RED runs stay clean) and requires that cleanup to have
    /// found it alive — proving the leak the old substring
    /// classifier hid. Pre-fix this exits 22 (RED).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn denied_barrier_read_unresolved_retirement_fails() {
        use std::time::Duration;
        let outcome = run_preflight_middleman("read-nopidfd", Duration::from_secs(30));
        if outcome.code == 3 {
            eprintln!("skip: seccomp unavailable for the unresolved-retirement probe");
            return;
        }
        // Independent cleanup FIRST (RED runs stay clean even when
        // the assertions below fail), then require it to have been
        // needed.
        let cleaned = match outcome.grandchild {
            GrandchildState::Live(pid, started) => retire_reported_grandchild(pid, started),
            GrandchildState::None => false,
        };
        assert_eq!(
            outcome.code, 21,
            "unresolved retirement must refuse, got exit {}",
            outcome.code
        );
        assert!(
            outcome.err.contains("not proven reaped"),
            "production must report the unresolved custody, got: {}",
            outcome.err
        );
        assert!(
            cleaned,
            "the parked grandchild must need independent cleanup (else the leak is uncovered)"
        );
    }

    /// S132-round9 control: disabling retirement a SECOND way
    /// (signal routes denied — the pin exists but SIGKILL is
    /// refused) must also refuse (21, never 22). If the
    /// exact-shape classifier ever regresses to substring
    /// matching, this control turns red: it proves the S111 pass
    /// depends on retirement actually working.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn denied_barrier_read_signalless_retirement_control() {
        use std::time::Duration;
        let outcome = run_preflight_middleman("read-nosignal", Duration::from_secs(30));
        if outcome.code == 3 {
            eprintln!("skip: seccomp unavailable for the signalless-retirement probe");
            return;
        }
        let cleaned = match outcome.grandchild {
            GrandchildState::Live(pid, started) => retire_reported_grandchild(pid, started),
            GrandchildState::None => false,
        };
        assert_eq!(
            outcome.code, 21,
            "signalless retirement must refuse, got exit {}",
            outcome.code
        );
        assert!(
            outcome.err.contains("not proven reaped"),
            "production must report the unresolved custody, got: {}",
            outcome.err
        );
        assert!(
            cleaned,
            "the parked grandchild must need independent cleanup (else the leak is uncovered)"
        );
    }

    /// R11-014: per-pipe accumulation cap for bounded probe
    /// collection. Reachable probe runs total under 10 KiB;
    /// past the cap the drain keeps reading toward
    /// EOF-or-deadline but discards — memory stays bounded
    /// even against a chattering holder.
    #[cfg(target_arch = "x86_64")]
    const PROBE_OUTPUT_CAP: usize = 1 << 20;

    /// R12-005: best-effort retirement of one KNOWN stray
    /// (a task the caller knows holds the probe's pipes from
    /// OUTSIDE the probe group, where the group signal cannot
    /// reach): pin first, verify the pinned starttime still
    /// names it, signal through the pin (ESRCH-tolerant — it
    /// may have exited), then await disappearance (reaping an
    /// adopted zombie along the way). Never panics — expiry
    /// is fail-closed house discipline, not an assertion.
    /// R13-005: returns the disappearance proof so the caller
    /// can record accurate per-stray cleanup evidence.
    /// R14-011: `true` certifies disappearance — proven absence
    /// (ESRCH pin, ENOENT stat, recycled number) or a signaled
    /// task awaited gone. Every UNPROVEN outcome (pin denied,
    /// exhausted, or unimplemented; unreadable stat) returns
    /// `false` WITHOUT signaling: a live unsignaled writer must
    /// never produce `(gone: true)`.
    #[cfg(target_arch = "x86_64")]
    fn retire_known_stray_best_effort(pid: libc::pid_t, started: u64) -> bool {
        use std::time::Duration;
        let pin = match super::super::seccomp::pidfd_open_raw(pid) {
            Ok(pin) => pin,
            // ESRCH proves absence (nothing to signal — the
            // named task is gone); every other pin failure
            // (denied, exhausted, unimplemented) leaves the
            // task's fate unknown — unresolved, never certified.
            Err(errno) => return errno == libc::ESRCH,
        };
        match proc_starttime(pid) {
            Ok(Some(now)) if now == started => {}
            Ok(_) => {
                // Absent or recycled: the NAMED task is gone
                // (a recycled number could not host another
                // birth otherwise) — close the pin and certify
                // WITHOUT signaling (the number is unreserved).
                // SAFETY: pin owned by this scope.
                unsafe { libc::close(pin) };
                return true;
            }
            // Unreadable stat (R11-005: our own tasks stay
            // stat-visible, so this is never absence) — the
            // task may be live and unsignaled: unresolved.
            Err(_) => {
                // SAFETY: pin owned by this scope.
                unsafe { libc::close(pin) };
                return false;
            }
        }
        // SAFETY: pidfd_send_signal(pidfd, SIGKILL, NULL, 0).
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pin as libc::c_long,
                libc::SIGKILL as libc::c_long,
                0 as libc::c_long,
                0 as libc::c_long,
            );
        }
        // SAFETY: pin owned by this scope.
        unsafe { libc::close(pin) };
        await_proc_gone_reaping(pid, started, Duration::from_secs(5))
    }

    /// R11-014: fail-closed retirement for an expired (or
    /// unobservable) probe collection: signal the probe's own
    /// group, then the probe itself, then reap. The probe's
    /// pgid is its pid — every probe groups itself on entry —
    /// so the holders stranded in its group die with it.
    /// R12-005: every arm is identity-gated — callers reap the
    /// probe BEFORE collecting, so the bare numbers may name
    /// recycled strangers. Three gates: (a) killpg fires only
    /// while the group never died (`group_died` from the drain's
    /// continuity sampler) AND the number's current holder is
    /// not a live foreign self-grouper (R13-003 anchor check —
    /// presence sampling cannot see a regroup with no
    /// observable gap, so the anchor reads identity at fire
    /// time; a latched death with live strays is impossible,
    /// so a vetoed fire would have been pointless anyway).
    /// Either foreign proof also skips the adopted-zombie
    /// drain (R13-004 — waitpid(-id) would steal another
    /// owner's status in a recycled group);
    /// (b) kill + the wait run only while the number still
    /// names `expected` (a zombie keeps its starttime, so ours
    /// still reaps; anything else skips without waiting);
    /// (c) each known stray (a pipe-holder OUTSIDE the probe
    /// group, where killpg cannot reach) is retired by (pin,
    /// starttime) identity.
    /// Residuals: a regroup in the µs anchor-read→signal window
    /// (no atomic check-and-killpg exists); a same-tick number
    /// recycle still kills+reaps as ours (S100-class); a mixed
    /// group (foreign self-grouper plus our strays) skips the
    /// signal and leaks the strays loud.
    #[cfg(target_arch = "x86_64")]
    fn expire_probe_collection(
        id: libc::pid_t,
        expected: u64,
        strays: &[(libc::pid_t, u64)],
        group_died: bool,
    ) {
        expire_probe_collection_with_hook(id, expected, strays, group_died, None, None);
    }

    /// R13-003 anchor check, shared by the up-front decision
    /// and the R14-007 per-pass drain recheck: the number's
    /// current holder is a live foreign SELF-GROUPED task
    /// (presence sampling cannot see a regroup with no
    /// observable gap). Unreadable fails closed (R14-005).
    #[cfg(target_arch = "x86_64")]
    fn group_is_foreign(id: libc::pid_t, expected: u64) -> bool {
        let (holder_tick, unreadable) = match proc_starttime(id) {
            Ok(tick) => (tick, false),
            Err(error) => {
                eprintln!("expiry treats unreadable group {id} as foreign: {error}");
                (None, true)
            }
        };
        // SAFETY: getpgid queries only. ESRCH (died between the
        // reads) is freed-equivalent.
        unreadable
            || (holder_tick != Some(expected)
                && holder_tick.is_some()
                && (unsafe { libc::getpgid(id) }) == id)
    }

    /// R14-007: `pass_hook` runs after every drain pass (a
    /// between-passes barrier for the regression); the drain
    /// re-decides foreignness every pass (a regroup between
    /// passes reforms the number — draining on would reap the
    /// replacement owner's zombie).
    /// R15-007: `reap_hook` runs after every successful inner
    /// reap (BEFORE that reap's recheck — it simulates the
    /// adversary between reaps, so the recheck must observe its
    /// plant); the drain re-decides after EVERY reap (a reform
    /// between inner waits would otherwise lose the
    /// replacement's status with no further check).
    #[cfg(target_arch = "x86_64")]
    fn expire_probe_collection_with_hook(
        id: libc::pid_t,
        expected: u64,
        strays: &[(libc::pid_t, u64)],
        group_died: bool,
        pass_hook: Option<&dyn Fn()>,
        reap_hook: Option<&dyn Fn()>,
    ) {
        use std::time::Duration;
        // Known strays below still retire individually (their
        // own pin+tick gates apply).
        let grouped_stranger = group_is_foreign(id, expected);
        // R13-004: a proven-foreign group (died-and-reformed per
        // the sampler, or a sampler-invisible regroup per the
        // anchor) gets NEITHER the signal NOR the drain — the
        // drain's waitpid(-id) would reap another owner's zombie
        // in the recycled group (status theft). Nothing of ours
        // is drainable there: a latched death saw the group fully
        // empty, and an invisible regroup leaves our (unsignaled)
        // strays alive, never zombies.
        let group_foreign = group_died || grouped_stranger;
        if group_foreign {
            // R13-005: strays retire individually below (each
            // with its own proof line) — only the group signal
            // and the group-zombie drain are skipped here.
            eprintln!(
                "expiry skips foreign group {id} signal+drain \
                 (died={group_died} regrouped={grouped_stranger}; \
                 strays retire individually below)"
            );
        } else {
            // SAFETY: signal-only to the group; errors ignored
            // (house discipline).
            unsafe {
                libc::killpg(id, libc::SIGKILL);
            }
        }
        // The probe itself: only while the number still names
        // it (reaped-and-freed is the normal caller shape —
        // skip, never signal-or-wait a recycled holder). The
        // await reuses the R11-005 stat gate (mismatch/freed
        // return at once without waiting).
        if proc_starttime(id) == Ok(Some(expected)) {
            // SAFETY: the number still names our probe.
            unsafe {
                libc::kill(id, libc::SIGKILL);
            }
        }
        match proc_starttime(id) {
            Err(error) => {
                eprintln!("expiry skips unresolvable probe {id} wait: {error}");
            }
            _ => {
                await_proc_gone_reaping(id, expected, Duration::from_secs(5));
            }
        }
        // Drain adopted group zombies (R11-013 pattern, bounded):
        // under a subreaper/PID-1 runner the dead strays became
        // OUR zombies and still hold the group observable — a
        // plain killpg leaves them. Skipped for proven-foreign
        // groups (R13-004): waitpid(-id) cannot tell our zombie
        // from another owner's in a recycled group. A single
        // pass races death (the pass runs µs after killpg;
        // SIGKILL-to-zombie takes ~10-100µs), so retry until the
        // group probes ESRCH-empty or the bound lapses.
        // waitpid(-pgid) reaps only OUR children in THIS group.
        if !group_foreign {
            use std::time::Instant;
            let drain_end = Instant::now() + Duration::from_secs(5);
            loop {
                // R14-007: re-decide foreignness EVERY pass —
                // a regroup between passes reforms the number,
                // and the reap below would steal the
                // replacement owner's zombie status.
                if group_is_foreign(id, expected) {
                    eprintln!("expiry: group {id} reformed mid-drain — drain stops (no theft)");
                    break;
                }
                // One reap pass over our children in this group.
                loop {
                    let mut status = 0;
                    // SAFETY: -pgid filters to our children in our
                    // own group; WNOHANG never blocks.
                    let got = unsafe { libc::waitpid(-id, &mut status, libc::WNOHANG) };
                    if got > 0 {
                        // R15-007: the per-reap seam runs FIRST
                        // (it simulates the adversary between
                        // reaps — the recheck below must observe
                        // its plant), then re-decide: this reap
                        // may have freed the number for a
                        // reformed group, and the next wait would
                        // steal the replacement's status with no
                        // further check. Bounded: one recheck per
                        // reap, never per spin. Residual: the
                        // recheck→waitpid µs inside one iteration
                        // is unclosable TOCTOU (no atomic
                        // check-and-reap exists) — S100-class,
                        // consistent with R13-003.
                        if let Some(hook) = reap_hook {
                            hook();
                        }
                        if group_is_foreign(id, expected) {
                            eprintln!(
                                "expiry: group {id} reformed mid-reap — inner stops (no theft)"
                            );
                            break;
                        }
                        continue;
                    }
                    if got < 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                    }
                    break;
                }
                // Between-passes barrier (regression seam; None
                // in production calls). Runs after every reap
                // pass — even one that empties the group — so a
                // planted reform is visible to the next recheck.
                if let Some(hook) = pass_hook {
                    hook();
                }
                // Group-empty proof: ESRCH means no task (live or
                // zombie) still names the pgid. Any other outcome
                // (live members — a foreign group never reaches
                // here) retries to the bound, then reports loud
                // (fail-closed: expiry never panics).
                // SAFETY: killpg(id, 0) probes existence only.
                if unsafe { libc::killpg(id, 0) } < 0 {
                    // SAFETY: errno location for this thread.
                    let errno = unsafe { libc::__errno_location().read() };
                    if errno == libc::ESRCH {
                        break;
                    }
                }
                if Instant::now() >= drain_end {
                    eprintln!(
                        "expiry: group {id} still observable after drain bound \
                         (member unkillable or unreaped)"
                    );
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        // R13-005: per-stray cleanup evidence — each known
        // writer's retirement lands in the log with its
        // disappearance proof (an expiry that leaves a stray
        // alive must say so, never claim a clean group).
        for (pid, started) in strays {
            let gone = retire_known_stray_best_effort(*pid, *started);
            eprintln!("expiry retired stray {pid} (gone: {gone})");
        }
        // No Child-handle wait here by design (not even a
        // parameter for it): the caller reaped via the handle
        // already (all callers do — the contract), and a
        // numeric wait past an external reap would steal a
        // recycled holder's status. The raw await above reaps
        // adopted zombies without touching any handle cache.
    }

    /// R11-014: bounded probe-output collection shared by the
    /// R10-012/R11-013 probe parents. `wait_with_output` waits
    /// for EOF — but descendants inherit the pipe write ends,
    /// so a live descendant at probe exit holds EOF open past
    /// any try_wait deadline (the parent hangs indefinitely
    /// collecting a dead probe's output). Drain both pipes
    /// under `end` (poll + nonblocking read, 1 MiB per pipe);
    /// on expiry retire the probe's whole group and return
    /// None. Returns Some(stdout, stderr) with whatever
    /// arrived. Never blocks past `end` — except a 2 s grace
    /// when ENTERING already expired (a slow-but-successful
    /// probe still recovers; a hung pipe still expires);
    /// never panics on I/O (a dead probe's partial output is
    /// still evidence). Callers pass the SAME `end` as their
    /// try_wait loop — one deadline covers exit AND collection
    /// by construction.
    /// R12-005: `expected` is the probe's birth tick pinned at
    /// spawn (callers reap BEFORE collecting, so the number
    /// alone may name a recycled stranger — the expiry gates
    /// every signal and wait on it); `strays` names known pipe
    /// writers OUTSIDE the probe group for individual
    /// retirement. While draining, a continuity sampler
    /// probes the group's existence every ≤100ms (sticky
    /// `group_died` flag): a group that died and reformed is
    /// foreign, and the expiry must not signal it. Contract:
    /// the caller reaped via the Child handle already, and
    /// every caller pins `expected` before any wait.
    #[cfg(target_arch = "x86_64")]
    fn collect_probe_output_bounded(
        child: &mut std::process::Child,
        end: std::time::Instant,
        expected: u64,
        strays: &[(libc::pid_t, u64)],
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        use std::os::unix::io::AsRawFd as _;
        // IR1 (internal review round 1): the try_wait loop
        // may consume the whole deadline while the probe
        // exits at the last instant — entering with an
        // already-expired `end` must not fail that
        // successful probe outright. A short grace recovers
        // arrived output (and certain EOF); a still-hung
        // pipe expires normally below (group retired).
        let end = if std::time::Instant::now() >= end {
            std::time::Instant::now() + std::time::Duration::from_secs(2)
        } else {
            end
        };
        // Read dry (nonblocking: stops at WouldBlock; EOF or
        // any other error ends the pipe — partial output is
        // still evidence). Past the cap the drain discards
        // toward EOF-or-deadline.
        // R12-006: slice budget — one drain call moves at most
        // 128 successful reads (~1MB at 8KB), then yields to the
        // outer loop WITHOUT marking done (level-triggered poll
        // re-arms: data still ready → next slice; EOF → done
        // next call). Ordinary writers already yield via
        // WouldBlock backpressure gaps; the budget bounds even a
        // gapless one, so the deadline/stderr/sampler checks run
        // every ~ms under any writer. Normal probes (KBs) never
        // touch the budget.
        fn drain<T: std::io::Read>(
            pipe: &mut Option<T>,
            acc: &mut Vec<u8>,
            buf: &mut [u8; 8192],
            done: &mut bool,
        ) {
            const SLICE_READS: u32 = 128;
            let Some(pipe) = pipe else {
                *done = true;
                return;
            };
            let mut reads = 0u32;
            loop {
                match pipe.read(buf) {
                    Ok(0) => {
                        *done = true;
                        break;
                    }
                    Ok(n) => {
                        let room = PROBE_OUTPUT_CAP.saturating_sub(acc.len());
                        acc.extend_from_slice(&buf[..n.min(room)]);
                        reads += 1;
                        if reads >= SLICE_READS {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(_) => {
                        *done = true;
                        break;
                    }
                }
            }
        }
        fn nonblocking<T: std::os::unix::io::AsRawFd>(pipe: &Option<T>) -> bool {
            match pipe {
                Some(pipe) => {
                    let fd = pipe.as_raw_fd();
                    // SAFETY: flag-set on an owned descriptor.
                    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                    if flags < 0 {
                        return false;
                    }
                    // SAFETY: same descriptor.
                    (unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) }) >= 0
                }
                None => false,
            }
        }
        let id = child.id() as libc::pid_t;
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        // R12-005: group-continuity sampler state. Sampled once
        // at entry (a group already dead can only come back
        // foreign, so every path below carries at least that)
        // and every drain iteration; any failure (ESRCH: gone;
        // EPERM: foreign-owned — ours are same-uid) latches
        // `group_died` and forbids the expiry killpg. Residual:
        // a death+regroup fully inside the caller's reap→entry
        // gap (µs — callers collect immediately after reaping)
        // or inside one 100ms sample gap still fires (exotic);
        // the tick gates on kill/wait have no window at all.
        // SAFETY: killpg(id, 0) probes existence only.
        let mut group_died = unsafe { libc::killpg(id, 0) } < 0;
        let sample_group = |group_died: &mut bool| {
            // SAFETY: killpg(id, 0) probes existence only.
            if unsafe { libc::killpg(id, 0) } < 0 {
                *group_died = true;
            }
        };
        // A blocking read could outlive `end` — fail closed.
        if !nonblocking(&stdout) || !nonblocking(&stderr) {
            expire_probe_collection(id, expected, strays, group_died);
            return None;
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut out_done = false;
        let mut err_done = false;
        let mut buf = [0u8; 8192];
        loop {
            sample_group(&mut group_died);
            if out_done && err_done {
                // R12-005: the probe is reaped already on the
                // normal path — reap here only while the
                // number still names it (reuse the R11-005
                // gate: mismatch/freed return at once without
                // waiting; unresolvable skips loud instead of
                // stalling to `end` on a dead stat read).
                match proc_starttime(id) {
                    Err(error) => {
                        eprintln!("collection skips unresolvable probe {id} wait: {error}");
                    }
                    _ => {
                        let window = end.saturating_duration_since(std::time::Instant::now());
                        await_proc_gone_reaping(id, expected, window);
                    }
                }
                return Some((out, err));
            }
            if std::time::Instant::now() >= end {
                expire_probe_collection(id, expected, strays, group_died);
                return None;
            }
            // Negative fds are skipped by poll: done pipes
            // simply leave the set.
            let mut waiting = [
                libc::pollfd {
                    fd: match &stdout {
                        Some(pipe) if !out_done => pipe.as_raw_fd(),
                        _ => -1,
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: match &stderr {
                        Some(pipe) if !err_done => pipe.as_raw_fd(),
                        _ => -1,
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // R12-005: cap the poll sleep at 100ms so the
            // continuity sampler above runs ≥10/s — an
            // uncapped sleep could hide a whole
            // group-death-plus-foreign-regroup inside one
            // blind window on long collections.
            let remaining = end
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .min(100)
                .min(i32::MAX as u128) as i32;
            // SAFETY: valid pollfds for owned descriptors.
            let ready = unsafe {
                libc::poll(
                    waiting.as_mut_ptr(),
                    waiting.len() as libc::nfds_t,
                    remaining,
                )
            };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                expire_probe_collection(id, expected, strays, group_died);
                return None;
            }
            if ready == 0 {
                continue;
            }
            for i in 0..2 {
                if waiting[i].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
                    continue;
                }
                if i == 0 {
                    if !out_done {
                        drain(&mut stdout, &mut out, &mut buf, &mut out_done);
                    }
                } else if !err_done {
                    drain(&mut stderr, &mut err, &mut buf, &mut err_done);
                }
            }
        }
    }

    /// R11-014: collection must stay inside the deadline even
    /// when a pipe writer outlives the awaited child, and the
    /// expiry must retire the holder's group (independent
    /// descendant retirement). Stages it directly: a child in
    /// its own group forks a 30s pipe-holding sleeper and exits
    /// at once — the exit is observable immediately while EOF
    /// needs the sleeper. wait_with_output would hang past any
    /// try_wait deadline here (probed out-of-suite: EOF never
    /// arrives); the bounded helper expires at ~2s with the
    /// group provably dead (killpg ESRCH inside 5s — SIGKILL
    /// delivery is async but prompt — and total elapsed far
    /// below the sleeper's own 30s clock).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn probe_collection_expires_bounded_and_retires_group() {
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        let mut child = std::process::Command::new("/bin/sh");
        child
            .arg("-c")
            .arg("sleep 30 &")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: setpgid on self pre-exec, no userspace state
        // (the probes group themselves the same way on entry).
        unsafe {
            child.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut child = child.spawn().expect("spawn pipe-holding stage");
        // R12-005: pin the probe's birth tick before any wait
        // (the expiry gates every signal and wait on it).
        let staged = proc_starttime(child.id() as libc::pid_t)
            .expect("stage stat readable")
            .expect("stage visible");
        // The shell exits at once; its sleeper inherits the
        // group AND the pipe write ends.
        let status = child.wait().expect("stage exit");
        assert!(status.success());
        let group = child.id() as libc::pid_t;
        let started = Instant::now();
        let got =
            collect_probe_output_bounded(&mut child, started + Duration::from_secs(2), staged, &[]);
        assert!(got.is_none(), "collection must expire, not hang for EOF");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "expiry must stay bounded, took {:?}",
            started.elapsed()
        );
        // Independent retirement: the 30s sleeper died by OUR
        // group kill (far ahead of its own clock).
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: signal 0 probes existence only.
            if unsafe { libc::killpg(group, 0) } < 0 {
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                assert_eq!(
                    errno,
                    libc::ESRCH,
                    "group probe must fail ESRCH-only, got {errno}"
                );
                return;
            }
            assert!(
                Instant::now() < end,
                "holder group {group} survived retirement"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// R12-005: reap a probe whose pipe writer lives in an
    /// INDEPENDENT group, then stage identity reuse on the
    /// probe's freed number. The tick-gated expiry spares the
    /// replacement (starttime mismatch — no signal, no wait)
    /// and the known-strays retirement takes the actual
    /// writer. Pre-fix the expiry murders the replacement and
    /// never retires the writer (RED). The writer is staged
    /// probe-side (a python probe-side fork inherits the
    /// piped stdio and self-groups; an exec'd writer would
    /// lose the cloexec ends). A RED run strands at most the
    /// 6s writer.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn probe_expiry_spares_recycled_number_and_retires_known_writer() {
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        if !staged_probe_python3() {
            eprintln!("skip: python3 unavailable (no staged probes)");
            return;
        }
        // Serialize steerers in-process (whole-test hold); the
        // placement loop below adds the cross-process lock.
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return;
            }
        };
        if !audit_locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
            eprintln!("skip: ns_last_pid unwritable (no reuse control)");
            return;
        }
        // The probe: self-grouped python forking an
        // independently grouped writer (own group, 6s), then
        // exiting at once. The writer inherits the piped stdio
        // across the fork (no exec — cloexec would drop it).
        let mark = format!("{STAGED_PROBE_MARK}-T1");
        let script = format!(
            "# {mark}\nimport os, sys, time\nkid = os.fork()\nif kid == 0:\n    os.closerange(3, 4096)\n    os.setpgid(0, 0)\n    time.sleep(6)\n    os._exit(0)\nprint('OUT')\nprint('ERR', file=sys.stderr)\n"
        );
        let mut probe = std::process::Command::new("python3");
        probe
            .arg("-c")
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            probe.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut probe = probe.spawn().expect("staged probe spawns");
        let id = probe.id() as libc::pid_t;
        let probe_tick = proc_starttime(id)
            .expect("probe stat readable")
            .expect("probe visible");
        // Name the writer by (marker, birth): it is the only
        // marked task besides the probe itself.
        let (writer, writer_tick, writer_group) = {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let mut marked = audit_marked_tasks(&mark, probe_tick, id);
                if marked.len() == 1 {
                    break marked.pop().unwrap();
                }
                assert!(
                    Instant::now() < end,
                    "writer never appeared, got {marked:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        assert_ne!(writer_group, id, "writer must leave the probe group");
        // Reap the probe (the caller-side wait the finding
        // names): its number is free (not zombie) from here.
        let status = probe.wait().expect("probe exit");
        assert!(status.success());
        // Controlled reuse: a LIVE replacement on the probe's
        // number at a DIFFERENT birth tick (same-tick is the
        // exotic accepted residual, not this finding).
        let mut replacement = None;
        {
            let _flock = ns_last_pid_flock();
            for _ in 0..100 {
                if !audit_steer_next_pid_unlocked(id) {
                    break;
                }
                let mut cand = std::process::Command::new("/bin/sleep")
                    .arg("60")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("replacement spawns");
                if cand.id() as libc::pid_t != id {
                    let _ = cand.kill();
                    let _ = cand.wait();
                    continue;
                }
                let placed_different = match proc_starttime(id) {
                    Ok(Some(tick)) => tick != probe_tick,
                    _ => false,
                };
                if !placed_different {
                    let _ = cand.kill();
                    let _ = cand.wait();
                    continue;
                }
                replacement = Some(cand);
                break;
            }
        }
        let mut replacement = replacement.expect("replacement placed on probe's number");
        let revived_tick = proc_starttime(id)
            .expect("replacement stat readable")
            .expect("replacement visible");
        // R12-005: tick-gated expiry (the probe's number now
        // names a live replacement) with the writer named as a
        // known stray (outside the probe group, where the
        // group signal cannot reach).
        let got = collect_probe_output_bounded(
            &mut probe,
            Instant::now() + Duration::from_secs(2),
            probe_tick,
            &[(writer, writer_tick)],
        );
        // Observe before cleanup (R12-014): identity now, then
        // SETTLED aliveness (death is async — an instant read
        // misreads a mid-death task as live), then retire.
        let revived_now = proc_starttime(id);
        let revived_spared = settle_spared(id);
        // SAFETY: retiring our own replacement (live when
        // spared; already a zombie when struck — the kill is
        // then a no-op and the owner reaps below).
        unsafe {
            libc::kill(id, libc::SIGKILL);
        }
        let owned = replacement.wait();
        audit_locked_restore_hint(&last_before);
        // Expiry must have fired (else survival below is
        // vacuous — nothing addressed anyone).
        assert!(got.is_none(), "collection must expire, not hang for EOF");
        assert_eq!(
            revived_now,
            Ok(Some(revived_tick)),
            "recycled probe number keeps its holder"
        );
        assert!(
            revived_spared,
            "recycled probe number must hold a LIVE task (settled)"
        );
        let status = owned.expect("replacement owner keeps its status");
        assert!(!status.success(), "killed replacement reports signal death");
        // The actual owned writer is retired by the expiry
        // (2s bound — far below the writer's 6s natural life,
        // so a pass cannot be its natural exit).
        assert!(
            await_proc_gone_reaping(writer, writer_tick, Duration::from_secs(2)),
            "known writer must be retired by the expiry"
        );
    }

    /// R12-005 (group continuity): the probe's group dies
    /// MID-COLLECTION (its stray is retired) and a foreign task
    /// recycles the GROUP NUMBER (a replacement on the probe's
    /// freed pid that self-groups). The continuity sampler saw
    /// the group die and the expiry skips the killpg; the
    /// tick gate skips the direct kill/wait. Pre-fix the blind
    /// killpg murders the foreign group (RED). The 300ms death
    /// gap spans several 100ms
    /// samples by construction; the expiry proves it fired
    /// (EOF is held throughout by an unattributed test-group
    /// holder the expiry cannot know). The 10s holder covers
    /// the 5s deadline with margin (retired in cleanup on
    /// every path past staging).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn probe_expiry_skips_recycled_group() {
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        if !staged_probe_python3() {
            eprintln!("skip: python3 unavailable (no staged probes)");
            return;
        }
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return;
            }
        };
        if !audit_locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
            eprintln!("skip: ns_last_pid unwritable (no reuse control)");
            return;
        }
        // SAFETY: getpgrp reads our own group only.
        let test_group = unsafe { libc::getpgrp() };
        // The probe: self-grouped python forking S (its group,
        // 30s — retired mid-collection) and H (OUR group via a
        // setpgid-join, 6s — the unattributed EOF holder no
        // list names), then exiting at once. Both inherit the
        // piped stdio across the fork (no exec — cloexec would
        // drop it).
        let mark = format!("{STAGED_PROBE_MARK}-T2");
        let script = format!(
            "# {mark}\nimport os, sys, time\ns = os.fork()\nif s == 0:\n    os.closerange(3, 4096)\n    time.sleep(30)\n    os._exit(0)\nh = os.fork()\nif h == 0:\n    os.closerange(3, 4096)\n    os.setpgid(0, {test_group})\n    time.sleep(10)\n    os._exit(0)\n"
        );
        let mut probe = std::process::Command::new("python3");
        probe
            .arg("-c")
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            probe.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut probe = probe.spawn().expect("staged probe spawns");
        let id = probe.id() as libc::pid_t;
        let probe_tick = proc_starttime(id)
            .expect("probe stat readable")
            .expect("probe visible");
        // Name S (pgid == probe group) and H (pgid == our
        // group) by (marker, birth, pgid): pgid + cmdline
        // survive the probe's exit where ppid would flap.
        let ((stray, stray_tick, _), (holder, holder_tick, _)) = {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let marked = audit_marked_tasks(&mark, probe_tick, id);
                let mut stray = None;
                let mut holder = None;
                for (pid, tick, group) in marked {
                    if group == id {
                        stray = Some((pid, tick, group));
                    } else if group == test_group {
                        holder = Some((pid, tick, group));
                    }
                }
                if let (Some(stray), Some(holder)) = (stray, holder) {
                    break (stray, holder);
                }
                assert!(Instant::now() < end, "stray/holder never appeared");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        // Reap the probe: its number is free from here; S lives
        // on in the group (reparented), H in ours.
        let status = probe.wait().expect("probe exit");
        assert!(status.success());
        // Mid-collection recycler: retire S, hold the group
        // dead across several samples, then recycle the GROUP
        // NUMBER with a self-grouped foreigner on the probe's
        // freed pid. Returns the foreigner's handle for the
        // owner to retire.
        let stager = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            // SAFETY: retiring our own grandchild S (kill
            // only — reparented, never waited by us).
            unsafe {
                libc::kill(stray, libc::SIGKILL);
            }
            assert!(
                await_proc_gone_reaping(stray, stray_tick, Duration::from_secs(5)),
                "stray retires mid-collection"
            );
            // The death gap: the sampler must observe ESRCH
            // here (several 100ms samples land inside it).
            std::thread::sleep(Duration::from_millis(300));
            let _flock = ns_last_pid_flock();
            for _ in 0..100 {
                if !audit_steer_next_pid_unlocked(id) {
                    break;
                }
                let mut cmd = std::process::Command::new("/bin/sleep");
                cmd.arg("60")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                // SAFETY: setpgid on self pre-exec — this IS
                // the group-number recycle (pgid becomes id).
                unsafe {
                    cmd.pre_exec(|| {
                        libc::setpgid(0, 0);
                        Ok(())
                    });
                }
                let mut cand = cmd.spawn().expect("foreigner spawns");
                if cand.id() as libc::pid_t != id {
                    let _ = cand.kill();
                    let _ = cand.wait();
                    continue;
                }
                let tick = match proc_starttime(id) {
                    Ok(Some(tick)) => tick,
                    _ => {
                        let _ = cand.kill();
                        let _ = cand.wait();
                        continue;
                    }
                };
                assert_ne!(
                    tick, probe_tick,
                    "recycled group holder must differ in tick"
                );
                return (cand, tick, Instant::now());
            }
            panic!("foreigner placement failed");
        });
        // R12-005: tick-gated expiry (the probe's number now
        // names a live foreigner) with continuity sampling
        // (the group dies mid-collection and reforms foreign).
        // The 5s deadline gives the stager room (S-retirement
        // + 300ms gap + sudo-paced placement ≈ 1s typical);
        // the 10s H holder covers it with margin.
        let deadline = Instant::now() + Duration::from_secs(5);
        let got = collect_probe_output_bounded(&mut probe, deadline, probe_tick, &[]);
        let (mut foreign, foreign_tick, foreign_placed) = stager.join().expect("stager placed F");
        // Observe before cleanup (R12-014), then retire both
        // owned tasks on every path. SETTLED aliveness: death
        // is async (an instant read misreads a mid-death task
        // as live) and a zombie keeps its starttime, so
        // identity alone would pass a murder.
        let foreign_now = proc_starttime(id);
        let foreign_group = proc_pgrp(id);
        let foreign_spared = settle_spared(id);
        // SAFETY: retiring our own live foreigner.
        unsafe {
            libc::kill(id, libc::SIGKILL);
        }
        let owned = foreign.wait();
        // Retire H (reparented to init on the probe's exit —
        // kill only, never waited by us; init reaps it).
        // SAFETY: retiring our own staged holder.
        unsafe {
            libc::kill(holder, libc::SIGKILL);
        }
        let holder_gone = await_proc_gone_reaping(holder, holder_tick, Duration::from_secs(5));
        audit_locked_restore_hint(&last_before);
        assert!(got.is_none(), "collection must expire (EOF held)");
        assert!(
            foreign_placed + Duration::from_millis(100) < deadline,
            "foreigner must predate the strike with margin (else survival is vacuous)"
        );
        assert_eq!(
            foreign_group,
            Some(id),
            "foreigner must sit in the recycled group (else the strike cannot address it)"
        );
        assert_eq!(
            foreign_now,
            Ok(Some(foreign_tick)),
            "foreign group holder survives the expiry"
        );
        assert!(
            foreign_spared,
            "foreign group holder must be LIVE (settled)"
        );
        let status = owned.expect("foreigner owner keeps its status");
        assert!(!status.success(), "killed foreigner reports signal death");
        assert!(holder_gone, "staged holder retires in cleanup");
    }

    /// R13-003: recycle-before-entry through the real collection
    /// entry — no staged probes, no threads. Spawn a null-stdio
    /// self-grouped probe, pin, reap; steer a SELF-GROUPED
    /// foreigner onto its number (the group never dies — the
    /// entry sample sees continuous life, exactly the sampler
    /// hole). Null stdio fails the nonblocking gate
    /// deterministically, routing straight to expiry with
    /// group_died=false. Only the anchor check can spare the
    /// foreigner (pre-fix killpg murders it — RED). Repeated
    /// expiry, then settled survival + owner status.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn probe_expiry_spares_before_entry_recycled_group() {
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return;
            }
        };
        if !audit_locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
            eprintln!("skip: ns_last_pid unwritable (no reuse control)");
            return;
        }
        let mut probe = std::process::Command::new("/bin/sleep");
        probe
            .arg("61")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            probe.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut probe = probe.spawn().expect("probe spawns");
        let id = probe.id() as libc::pid_t;
        let probe_tick = proc_starttime(id)
            .expect("probe stat readable")
            .expect("probe visible");
        // SAFETY: retiring our own probe.
        unsafe {
            libc::kill(id, libc::SIGKILL);
        }
        let status = probe.wait().expect("probe reaped");
        assert!(!status.success());
        // Controlled reuse BEFORE collection entry: a LIVE
        // SELF-GROUPED foreigner on the probe's number.
        let mut foreigner = None;
        {
            let _flock = ns_last_pid_flock();
            for _ in 0..100 {
                if !audit_steer_next_pid_unlocked(id) {
                    break;
                }
                let mut cmd = std::process::Command::new("/bin/sleep");
                cmd.arg("61")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                // SAFETY: setpgid on self pre-exec — this IS
                // the group-number recycle (pgid becomes id).
                unsafe {
                    cmd.pre_exec(|| {
                        libc::setpgid(0, 0);
                        Ok(())
                    });
                }
                let mut cand = cmd.spawn().expect("foreigner spawns");
                if cand.id() as libc::pid_t != id {
                    let _ = cand.kill();
                    let _ = cand.wait();
                    continue;
                }
                let placed_different = match proc_starttime(id) {
                    Ok(Some(tick)) => tick != probe_tick,
                    _ => false,
                };
                // SAFETY: getpgid queries only.
                let placed_grouped = unsafe { libc::getpgid(id) } == id;
                if !placed_different || !placed_grouped {
                    let _ = cand.kill();
                    let _ = cand.wait();
                    continue;
                }
                foreigner = Some(cand);
                break;
            }
        }
        let mut foreigner = foreigner.expect("grouped foreigner placed on probe number");
        let foreign_tick = proc_starttime(id)
            .expect("foreigner stat readable")
            .expect("foreigner visible");
        // Repeated expiry through the real entry (null stdio
        // routes straight to expire with group_died=false).
        let end = Instant::now() + Duration::from_secs(5);
        let first = collect_probe_output_bounded(&mut probe, end, probe_tick, &[]);
        let end = Instant::now() + Duration::from_secs(5);
        let second = collect_probe_output_bounded(&mut probe, end, probe_tick, &[]);
        // Observe before cleanup (R12-014): identity, then a
        // 200ms settle (SIGKILL-to-zombie is µs-ms; a live
        // sleeper never exits on its own), then retire.
        let foreign_now = proc_starttime(id);
        std::thread::sleep(Duration::from_millis(200));
        // R14-006: shared observed cleanup (a reaped number
        // spares whoever recycled it).
        let survived = observe_then_retire_foreigner(id, foreign_tick);
        let owned = foreigner.wait();
        audit_locked_restore_hint(&last_before);
        assert!(first.is_none(), "null stdio must route to expiry");
        assert!(second.is_none(), "repeated expiry must route again");
        assert_eq!(
            foreign_now,
            Ok(Some(foreign_tick)),
            "recycled probe number keeps its holder"
        );
        assert!(
            survived,
            "before-entry regroup must survive expiry (settled)"
        );
        let status = owned.expect("foreigner owner keeps its status");
        assert!(!status.success(), "killed foreigner reports signal death");
    }

    /// R13-003: `expire_probe_collection` with a
    /// sampler-invisible regroup — foreign self-grouped
    /// holder, bogus tick, group_died=false. These inputs are
    /// identical to the before-entry and in-gap sampler holes
    /// (the function cannot distinguish a true recycle), so no
    /// steering or threads are needed. Survival through
    /// repeated expiry + owner status. (A literally mid-drain
    /// recycle test would be timing-flaky by construction —
    /// the anchor reads at fire time, so entry and mid-drain
    /// are the same case.)
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn expire_collection_spares_sampler_invisible_regroup() {
        use std::os::unix::process::CommandExt as _;
        use std::time::Duration;
        let mut foreigner = std::process::Command::new("/bin/sleep");
        foreigner
            .arg("62")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            foreigner.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut foreigner = foreigner.spawn().expect("foreigner spawns");
        let id = foreigner.id() as libc::pid_t;
        let foreign_tick = proc_starttime(id)
            .expect("foreigner stat readable")
            .expect("foreigner visible");
        // SAFETY: getpgid queries only.
        assert_eq!(
            unsafe { libc::getpgid(id) },
            id,
            "foreigner must self-group"
        );
        // Bogus tick: always mismatched (wrapping +1).
        let bogus = foreign_tick.wrapping_add(1);
        expire_probe_collection(id, bogus, &[], false);
        expire_probe_collection(id, bogus, &[], false);
        // Observe before cleanup (R12-014): identity, 200ms
        // settle, then retire.
        let foreign_now = proc_starttime(id);
        std::thread::sleep(Duration::from_millis(200));
        // R14-006: shared observed cleanup (a reaped number
        // spares whoever recycled it).
        let survived = observe_then_retire_foreigner(id, foreign_tick);
        let owned = foreigner.wait();
        assert_eq!(
            foreign_now,
            Ok(Some(foreign_tick)),
            "foreigner keeps its identity"
        );
        assert!(survived, "invisible regroup must survive expiry (settled)");
        let status = owned.expect("foreigner owner keeps its status");
        assert!(!status.success(), "killed foreigner reports signal death");
    }

    /// R14-005: unreadable identity fails closed — a live
    /// foreign self-grouped task with non-UTF8 comm must
    /// survive expiry (no signal, no drain). Pre-fix the
    /// gate collapses the read error into the freed arm and
    /// murders it (RED); post-fix it skips loud (GREEN).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn expiry_spares_unreadable_self_grouped_task() {
        use std::time::{Duration, Instant};
        // SAFETY: fork; the child only calls prctl/setpgid/
        // pause (async-signal-safe, no locks, no allocation).
        let me = std::process::id() as libc::pid_t;
        let id = unsafe { libc::fork() };
        assert!(id >= 0, "foreigner fork failed");
        if id == 0 {
            unsafe {
                // Die with the parent (never a pipe-holding
                // orphan that hangs the harness past a setup
                // failure).
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
                if libc::getppid() != me {
                    libc::_exit(0);
                }
                libc::setpgid(0, 0);
                let name = b"\xff\xfeforeign\x00";
                libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
                loop {
                    libc::pause();
                }
            }
        }
        // Setup gate: the child sets group-then-name after the
        // fork — poll for BOTH (an immediate read races the
        // child and panics past cleanup, orphaning the pauser).
        // Timeout retires before failing loud.
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let unreadable = proc_starttime(id).is_err();
            // SAFETY: getpgid queries only.
            let grouped = unsafe { libc::getpgid(id) } == id;
            if unreadable && grouped {
                break;
            }
            if Instant::now() >= end {
                // SAFETY: retiring our own unsettled foreigner.
                unsafe {
                    libc::kill(id, libc::SIGKILL);
                    let mut status = 0;
                    libc::waitpid(id, &mut status, 0);
                }
                panic!("foreigner never set group+non-UTF8 name");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let bogus = 0xDEAD_BEEF_DEAD_BEEFu64;
        expire_probe_collection(id, bogus, &[], false);
        // Settle, then aliveness WITHOUT stat (unreadable by
        // construction): kill-0 plus no reapable zombie.
        std::thread::sleep(Duration::from_millis(200));
        // SAFETY: signal 0 probes existence only.
        let present = unsafe { libc::kill(id, 0) } == 0;
        let mut status = 0;
        // SAFETY: WNOHANG reap probe of our own child.
        let unreaped = unsafe { libc::waitpid(id, &mut status, libc::WNOHANG) } == 0;
        // Loud cleanup (kill ONLY while unreaped — a reaped
        // number is free and must never be signaled), then the
        // verdict (owner keeps status).
        if unreaped {
            // SAFETY: retiring our own live foreigner.
            unsafe {
                libc::kill(id, libc::SIGKILL);
            }
        }
        let mut owned_status = 0;
        // SAFETY: blocking reap of our own dead child.
        let got = unsafe { libc::waitpid(id, &mut owned_status, 0) };
        assert!(present, "unreadable foreigner must survive expiry");
        assert!(unreaped, "no zombie may pre-exist for the owner");
        assert_eq!(got, id, "owner keeps the foreigner's status");
    }

    /// R14-006: observe-then-retire a possibly-murdered
    /// foreigner, shared by the regroup-test cleanups. WNOHANG
    /// probe first: a reaped number is free and must never be
    /// signaled (returns false). A live holder is signaled
    /// ONLY while its tick still names our fixture (returns
    /// true) — a recycled stranger or unreadable identity is
    /// spared (returns false). Residual: same-tick recycle in
    /// the µs tick-read→signal window (S100-class).
    #[cfg(target_arch = "x86_64")]
    fn observe_then_retire_foreigner(id: libc::pid_t, expected: u64) -> bool {
        let mut status = 0;
        // SAFETY: WNOHANG probe of our own child.
        if unsafe { libc::waitpid(id, &mut status, libc::WNOHANG) } != 0 {
            // Reaped (RED shape) or ECHILD (stolen): the number
            // is free — never signal whoever holds it now.
            return false;
        }
        if proc_starttime(id) == Ok(Some(expected)) {
            // SAFETY: retiring our own live foreigner.
            unsafe {
                libc::kill(id, libc::SIGKILL);
            }
            return true;
        }
        false
    }

    /// R14-006: failure cleanup must not signal a reaped-then-
    /// recycled number. Fixture killed and reaped through the
    /// observer probe, then a different-tick replacement
    /// steered onto the number; the observed cleanup must spare
    /// it and report unreaped-false. Pre-fix the unconditional
    /// kill murders the replacement (RED); post-fix it skips
    /// reaped numbers (GREEN). Duration 67 is unique to this
    /// test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn observed_cleanup_spares_recycled_replacement() {
        use std::time::{Duration, Instant};
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return;
            }
        };
        if !audit_locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
            eprintln!("skip: ns_last_pid unwritable (no reuse control)");
            return;
        }
        let fixture = std::process::Command::new("/bin/sleep")
            .arg("67")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("fixture spawns");
        let id = fixture.id() as libc::pid_t;
        let first_tick = proc_starttime(id)
            .expect("fixture stat readable")
            .expect("fixture visible");
        // Observer-reap the fixture (the RED-path shape: a
        // zombie the WNOHANG probe consumes), then force a tick
        // advance so the replacement differs.
        // SAFETY: retiring our own fixture.
        unsafe {
            libc::kill(id, libc::SIGKILL);
        }
        // Bounded reap poll (SIGKILL-to-zombie is µs-ms; an
        // immediate WNOHANG races the delivery).
        let reap_end = Instant::now() + Duration::from_secs(5);
        let got = loop {
            let mut status = 0;
            // SAFETY: WNOHANG reap of our own dying child.
            let got = unsafe { libc::waitpid(id, &mut status, libc::WNOHANG) };
            if got != 0 {
                break got;
            }
            assert!(
                Instant::now() < reap_end,
                "fixture never reached zombie state"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(got, id, "observer probe reaps the zombie");
        // Status consumed by the observer probe; the handle is
        // vestigial from here (the helper below takes the id).
        drop(fixture);
        std::thread::sleep(Duration::from_millis(50));
        let _flock = ns_last_pid_flock();
        let mut placed = None;
        for _ in 0..100 {
            if !audit_steer_next_pid_unlocked(id) {
                break;
            }
            let cand = std::process::Command::new("/bin/sleep")
                .arg("67")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("candidate spawns");
            if cand.id() as libc::pid_t != id {
                let mut cand = cand;
                let _ = cand.kill();
                let _ = cand.wait();
                continue;
            }
            placed = Some(cand);
            break;
        }
        drop(_flock);
        audit_locked_restore_hint(&last_before);
        let mut placed = match placed {
            Some(placed) => placed,
            None => {
                eprintln!("skip: fixture number not retaken (contended)");
                return;
            }
        };
        let replacement_tick = proc_starttime(id)
            .expect("replacement stat readable")
            .expect("replacement visible");
        if replacement_tick == first_tick {
            let _ = placed.kill();
            let _ = placed.wait();
            eprintln!("skip: same-tick retake (S100 — untestable this run)");
            return;
        }
        // The observed cleanup over the reaped-then-recycled
        // number: must spare the replacement (its tick differs
        // from the reaped fixture's) and report not-retired.
        // Liveness via the HANDLE-bound probe — a starttime
        // assert would pass on a zombie (kept starttime); the
        // replacement's owner then retires it.
        let retired_ours = observe_then_retire_foreigner(id, first_tick);
        assert!(!retired_ours, "recycled stranger must not be signaled");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            placed.try_wait().expect("replacement try_wait works"),
            None,
            "replacement must survive the observed cleanup"
        );
        assert_eq!(
            proc_starttime(id),
            Ok(Some(replacement_tick)),
            "survivor is the placed replacement, not a second recycle"
        );
        let _ = placed.kill();
        let status = placed.wait().expect("replacement owner keeps its status");
        assert!(!status.success(), "killed replacement reports signal death");
    }

    /// R15-003: tick-gated cleanup must spare a steered
    /// different-birth replacement on a released number.
    /// Fixture killed and reaped, then a different-tick
    /// replacement steered onto the number (root-gated: skips
    /// unless ns_last_pid is writable, mirroring the neighbor
    /// above); both gated helpers run against the OLD tick and
    /// must preserve replacement survival (handle-bound
    /// try_wait-None: unreaped, unkilled) and owner status.
    /// Pre-fix (unconditional cleanup kill) the replacement
    /// dies (RED); post-fix both helpers skip it (GREEN).
    /// Duration 55 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn gated_cleanup_spares_steered_replacement() {
        use std::time::{Duration, Instant};
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return;
            }
        };
        if !audit_locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
            eprintln!("skip: ns_last_pid unwritable (no reuse control)");
            return;
        }
        let fixture = std::process::Command::new("/bin/sleep")
            .arg("55")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("fixture spawns");
        let id = fixture.id() as libc::pid_t;
        let first_tick = proc_starttime(id)
            .expect("fixture stat readable")
            .expect("fixture visible");
        // SAFETY: retiring our own fixture.
        unsafe {
            libc::kill(id, libc::SIGKILL);
        }
        let reap_end = Instant::now() + Duration::from_secs(5);
        let got = loop {
            let mut status = 0;
            // SAFETY: WNOHANG reap of our own dying child.
            let got = unsafe { libc::waitpid(id, &mut status, libc::WNOHANG) };
            if got != 0 {
                break got;
            }
            assert!(Instant::now() < reap_end, "fixture never reaped");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(got, id, "fixture reaped");
        drop(fixture);
        std::thread::sleep(Duration::from_millis(50));
        let _flock = ns_last_pid_flock();
        let mut placed = None;
        for _ in 0..100 {
            if !audit_steer_next_pid_unlocked(id) {
                break;
            }
            let cand = std::process::Command::new("/bin/sleep")
                .arg("55")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("candidate spawns");
            if cand.id() as libc::pid_t != id {
                let mut cand = cand;
                let _ = cand.kill();
                let _ = cand.wait();
                continue;
            }
            placed = Some(cand);
            break;
        }
        drop(_flock);
        audit_locked_restore_hint(&last_before);
        let mut placed = match placed {
            Some(placed) => placed,
            None => {
                eprintln!("skip: fixture number not retaken (contended)");
                return;
            }
        };
        let replacement_tick = proc_starttime(id)
            .expect("replacement stat readable")
            .expect("replacement visible");
        if replacement_tick == first_tick {
            let _ = placed.kill();
            let _ = placed.wait();
            eprintln!("skip: same-tick retake (S100 — untestable this run)");
            return;
        }
        // Both gated helpers against the OLD tick: must skip the
        // replacement (its tick differs from the reaped
        // fixture's). Survival via the handle-bound probe (a
        // starttime assert would pass on a zombie); owner
        // status via try_wait-None (unreaped).
        assert!(
            kill_tick_gated(id, first_tick),
            "gated kill skips a recycled number"
        );
        assert!(
            retire_tick_gated_audit_child(id, first_tick),
            "gated retire skips a recycled number"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            matches!(placed.try_wait(), Ok(None)),
            "replacement must survive gated cleanup (alive and owner-unreaped)"
        );
        assert_eq!(
            proc_starttime(id),
            Ok(Some(replacement_tick)),
            "survivor is the placed replacement, not a second recycle"
        );
        let _ = placed.kill();
        let status = placed.wait().expect("replacement owner keeps its status");
        assert!(!status.success(), "killed replacement reports signal death");
    }

    /// R15-003 efficacy guard (runs everywhere, no steering):
    /// the gated helpers must still ACT on matching identity
    /// (a gate that never signals would pass the steered test
    /// vacuously). Live owned children retire; a live task
    /// under the wrong tick is spared; a gone number is a
    /// silent no-op. Duration 54 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn gated_cleanup_still_acts_on_matching_identity() {
        use std::time::{Duration, Instant};
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Helper (a): live owned child, matching tick — killed
        // and reaped.
        let mut owned = std::process::Command::new("/bin/sleep")
            .arg("54")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("owned spawns");
        let opid = owned.id() as libc::pid_t;
        let otick = proc_starttime(opid)
            .expect("owned stat readable")
            .expect("owned visible");
        assert!(
            retire_tick_gated_audit_child(opid, otick),
            "gated retire acts on matching identity"
        );
        assert!(
            !matches!(owned.try_wait(), Ok(None)),
            "owned child retired by the gated retire (reaped or ECHILD)"
        );
        // Helper (b): live task, matching tick — signaled (poll
        // it gone; the owner handle reaps).
        let mut staged = std::process::Command::new("/bin/sleep")
            .arg("54")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("staged spawns");
        let spid = staged.id() as libc::pid_t;
        let stick = proc_starttime(spid)
            .expect("staged stat readable")
            .expect("staged visible");
        assert!(
            kill_tick_gated(spid, stick),
            "gated kill acts on matching identity"
        );
        // Reap-then-assert: a zombie keeps its tick, so the
        // death poll must discharge it (bounded try_wait — a
        // blocking wait would hang a genuine kill failure).
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if staged.try_wait().expect("staged wait works").is_some() {
                break;
            }
            assert!(Instant::now() < end, "signaled task must die");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(proc_starttime(spid), Ok(None), "signaled task reaped gone");
        // Wrong tick on a live task — spared by both helpers.
        let mut stranger = std::process::Command::new("/bin/sleep")
            .arg("54")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("stranger spawns");
        let xpid = stranger.id() as libc::pid_t;
        let xtick = proc_starttime(xpid)
            .expect("stranger stat readable")
            .expect("stranger visible");
        let wrong = xtick.wrapping_add(1 << 32);
        assert!(
            kill_tick_gated(xpid, wrong),
            "gated kill skips wrong-tick tasks"
        );
        assert!(
            retire_tick_gated_audit_child(xpid, wrong),
            "gated retire skips wrong-tick tasks"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            proc_starttime(xpid),
            Ok(Some(xtick)),
            "wrong-tick task must survive"
        );
        assert!(
            matches!(stranger.try_wait(), Ok(None)),
            "wrong-tick owner status retained"
        );
        // SAFETY: retiring our own stranger by verified identity.
        unsafe {
            libc::kill(xpid, libc::SIGKILL);
        }
        let _ = stranger.wait();
        // Gone number — silent no-op for both.
        let mut gone = std::process::Command::new("/bin/true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("gone spawns");
        let gpid = gone.id() as libc::pid_t;
        let _ = gone.wait();
        assert!(
            kill_tick_gated(gpid, u64::MAX),
            "gated kill no-ops a gone number"
        );
        assert!(
            retire_tick_gated_audit_child(gpid, u64::MAX),
            "gated retire no-ops a gone number"
        );
    }

    /// R15-003: decision coverage over an injected read —
    /// unreadable reports unproven-false without signaling, and
    /// the scripted arms signal/skip exactly on tick-match
    /// (staging EMFILE process-wide would break the parallel
    /// suite, so the read is injected; signaling is observed on
    /// staged victims, never self). Duration 53 is unique to
    /// this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn gated_kill_decision_arms_over_injected_read() {
        use std::time::{Duration, Instant};
        let spawn = || {
            std::process::Command::new("/bin/sleep")
                .arg("53")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("victim spawns")
        };
        // Unreadable: false, no signal (victim survives).
        let mut parked = spawn();
        let ppid = parked.id() as libc::pid_t;
        let ptick = proc_starttime(ppid)
            .expect("victim stat readable")
            .expect("victim visible");
        assert!(
            !kill_tick_gated_with(ppid, ptick, |_| Err("injected".to_string())),
            "unreadable stat must report unproven (false)"
        );
        assert_eq!(
            proc_starttime(ppid),
            Ok(Some(ptick)),
            "unreadable arm must not signal"
        );
        // Scripted match: signals (victim dies).
        let mut doomed = spawn();
        let dpid = doomed.id() as libc::pid_t;
        let dtick = proc_starttime(dpid)
            .expect("victim stat readable")
            .expect("victim visible");
        assert!(
            kill_tick_gated_with(dpid, dtick, |_| Ok(Some(dtick))),
            "matching scripted tick signals"
        );
        // Reap-then-assert (a zombie keeps its tick).
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if doomed.try_wait().expect("doomed wait works").is_some() {
                break;
            }
            assert!(Instant::now() < end, "signaled victim must die");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            proc_starttime(dpid),
            Ok(None),
            "signaled victim reaped gone"
        );
        // Scripted mismatch: skips (victim survives).
        assert!(
            kill_tick_gated_with(ppid, ptick, |_| Ok(Some(ptick.wrapping_add(1)))),
            "mismatched scripted tick skips"
        );
        assert_eq!(
            proc_starttime(ppid),
            Ok(Some(ptick)),
            "mismatched arm must not signal"
        );
        // SAFETY: retiring our own parked victim by verified identity.
        unsafe {
            libc::kill(ppid, libc::SIGKILL);
        }
        let _ = parked.wait();
    }

    /// R15-004: audit twin of the toolchain pin-retry unit test
    /// (same scripted contract).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn audit_birth_pin_retries_transient_errors() {
        use std::cell::RefCell;
        let script = RefCell::new(vec![
            Err("blip1".to_string()),
            Err("blip2".to_string()),
            Ok(Some(42u64)),
        ]);
        let calls = RefCell::new(0);
        let read = |_: libc::pid_t| {
            *calls.borrow_mut() += 1;
            let mut script = script.borrow_mut();
            if script.is_empty() {
                return Ok(Some(42u64));
            }
            script.remove(0)
        };
        assert_eq!(
            pin_birth_tick_with(1, read),
            Some(42),
            "transient blips must heal by retry"
        );
        assert_eq!(*calls.borrow(), 3, "two blips then the pin");
        let persistent =
            |_: libc::pid_t| -> Result<Option<u64>, String> { Err("stuck".to_string()) };
        assert_eq!(
            pin_birth_tick_with(1, persistent),
            None,
            "persistent errors exhaust to None"
        );
        let gone_calls = RefCell::new(0);
        let gone = |_: libc::pid_t| {
            *gone_calls.borrow_mut() += 1;
            Ok(None)
        };
        assert_eq!(pin_birth_tick_with(1, gone), None, "gone pins None");
        assert_eq!(*gone_calls.borrow(), 1, "gone must not retry");
    }

    /// R15-004: audit twin of the toolchain late-pin test — a
    /// late pin converts an unpinned fixture guard into a gated
    /// drop across two steered retakes (skips unless
    /// steerable). Duration 50 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn audit_late_pin_spares_second_replacement() {
        use std::time::Duration;
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return;
            }
        };
        if !audit_locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
            eprintln!("skip: ns_last_pid unwritable (no reuse control)");
            return;
        }
        let spawn = || {
            std::process::Command::new("/bin/sleep")
                .arg("50")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("candidate spawns")
        };
        let place_onto = |want: libc::pid_t| -> Option<std::process::Child> {
            let _nsflock = ns_last_pid_flock();
            let mut placed = None;
            for _ in 0..100 {
                if !audit_steer_next_pid_unlocked(want) {
                    break;
                }
                let mut cand = spawn();
                if cand.id() as libc::pid_t == want {
                    placed = Some(cand);
                    break;
                }
                let _ = cand.kill();
                let _ = cand.wait();
            }
            drop(_nsflock);
            audit_locked_restore_hint(&last_before);
            placed
        };
        let mut seed = spawn();
        let number = seed.id() as libc::pid_t;
        let _ = seed.kill();
        let _ = seed.wait();
        // Guard over the gone number: initial read fails → None.
        let mut guard = FixtureGuard::new(number);
        // First replacement, steered on and late-pinned.
        std::thread::sleep(Duration::from_millis(50));
        let mut first = match place_onto(number) {
            Some(first) => first,
            None => {
                eprintln!("skip: first retake contended");
                return;
            }
        };
        let first_tick = proc_starttime(number)
            .expect("first stat readable")
            .expect("first visible");
        guard.pin(first_tick);
        // Second replacement retakes the number.
        let _ = first.kill();
        let _ = first.wait();
        std::thread::sleep(Duration::from_millis(50));
        let mut second = match place_onto(number) {
            Some(second) => second,
            None => {
                eprintln!("skip: second retake contended");
                return;
            }
        };
        let second_tick = proc_starttime(number)
            .expect("second stat readable")
            .expect("second visible");
        if second_tick == first_tick {
            let _ = second.kill();
            let _ = second.wait();
            eprintln!("skip: same-tick retake (S100 — untestable this run)");
            return;
        }
        drop(guard);
        assert_eq!(
            proc_starttime(number),
            Ok(Some(second_tick)),
            "late-pinned drop must spare the second replacement"
        );
        assert!(
            matches!(proc_state(number), Some(state) if state != 'Z'),
            "survivor must be live, not a zombie"
        );
        assert!(
            matches!(second.try_wait(), Ok(None)),
            "second owner status retained"
        );
        let _ = second.kill();
        let _ = second.wait();
    }

    /// R15-005: run one probe mode in a FRESH process image
    /// (audit twin of the toolchain spawner — same contract:
    /// contained exhaustion, completion marker, fail loud).
    #[cfg(target_arch = "x86_64")]
    fn audit_emfile_probe_spawn(mode: &str, test: &str) -> String {
        let exe = std::env::current_exe().expect("own test binary");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg(test)
            .arg("--nocapture")
            .env("SCOPEBASE_R15005_MODE", mode)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("probe child runs");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "{mode}: probe child must exit 0\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("R15005-CHILD-DONE mode={mode}")),
            "{mode}: completion marker missing\n{stderr}"
        );
        stderr
    }

    /// R15-005: parse a `PREFIX ... pid=N tick=M ...` line from
    /// the probe child's stderr (audit twin of the toolchain
    /// parser).
    #[cfg(target_arch = "x86_64")]
    fn audit_emfile_probe_tagged(stderr: &str, prefix: &str, mode: &str) -> (libc::pid_t, u64) {
        for line in stderr.lines() {
            if let Some(rest) = line.strip_prefix(prefix) {
                let mut pid = None;
                let mut tick = None;
                for word in rest.split_whitespace() {
                    if let Some(value) = word.strip_prefix("pid=") {
                        pid = value.parse::<libc::pid_t>().ok();
                    }
                    if let Some(value) = word.strip_prefix("tick=") {
                        tick = value.parse::<u64>().ok();
                    }
                }
                if let (Some(pid), Some(tick)) = (pid, tick) {
                    return (pid, tick);
                }
            }
        }
        panic!("{mode}: no parsable `{prefix}` line\n{stderr}");
    }

    /// R15-005: the probe-child body (audit twin of the
    /// toolchain child — Command-spawned fixtures, same
    /// pin/exhaust/panic-drop/verify flow).
    #[cfg(target_arch = "x86_64")]
    fn audit_emfile_probe_child(mode: &str) {
        use std::io::BufRead as _;
        use std::time::{Duration, Instant};
        fn spawn_sleep(dur: &str) -> std::process::Child {
            std::process::Command::new("/bin/sleep")
                .arg(dur)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("sleep spawns")
        }
        // Stage the fixture; owned handles stay alive for loud
        // cleanup below (the guard never waits on the live
        // modes, so no reap races the handles).
        let mut owned: Option<std::process::Child> = None;
        let mut sh_parent: Option<std::process::Child> = None;
        let pid = match mode {
            "live" | "gone" => {
                let child = spawn_sleep("51");
                let pid = child.id() as libc::pid_t;
                owned = Some(child);
                pid
            }
            "zombie" => {
                let child = std::process::Command::new("true")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("true spawns");
                let pid = child.id() as libc::pid_t;
                owned = Some(child);
                // Settle into Z BEFORE the guard (bounded poll
                // on /proc state — never a reaping wait).
                let end = Instant::now() + Duration::from_secs(5);
                loop {
                    if matches!(proc_state(pid), Some(state) if state == 'Z') {
                        break;
                    }
                    assert!(Instant::now() < end, "child never zombied");
                    std::thread::sleep(Duration::from_millis(1));
                }
                pid
            }
            "stranger" => {
                let mut parent = std::process::Command::new("/bin/sh")
                    .arg("-c")
                    .arg("sleep 52 & echo $!; wait")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("sh parent spawns");
                let mut line = String::new();
                std::io::BufReader::new(parent.stdout.take().expect("sh stdout"))
                    .read_line(&mut line)
                    .expect("grandchild pid readable");
                let stranger = line.trim().parse::<libc::pid_t>().expect("pid parses");
                assert!(
                    matches!(proc_state(stranger), Some(state) if state != 'Z'),
                    "staged stranger must be live"
                );
                {
                    let mut status = 0;
                    // SAFETY: WNOHANG probe only.
                    let got = unsafe { libc::waitpid(stranger, &mut status, libc::WNOHANG) };
                    assert!(got < 0, "staged stranger must not be our child");
                }
                sh_parent = Some(parent);
                stranger
            }
            _ => panic!("unknown probe mode {mode}"),
        };
        let guard = FixtureGuard::new(pid);
        let tick = proc_starttime(pid)
            .expect("fixture stat readable")
            .expect("fixture present");
        assert_eq!(guard.tick, Some(tick), "constructor must pin the live tick");
        eprintln!("R15005-PINNED pid={pid} tick={tick}");
        let mut held = Vec::new();
        while let Ok(file) = std::fs::File::open("/dev/null") {
            held.push(file);
        }
        assert!(!held.is_empty(), "exhaustion must consume fds");
        assert!(
            proc_starttime(pid).is_err(),
            "tick read must fail under exhaustion"
        );
        // Reap UNDER exhaustion (handle kill+wait are fd-less
        // syscalls): the gone number frees µs before the drop,
        // so suite activity almost never recycles it
        // mid-window (any hit is an honest loud skip below,
        // never a flake).
        if mode == "gone" {
            let mut child = owned.take().expect("owned staged");
            let _ = child.kill();
            let _ = child.wait();
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard_held = guard;
            panic!("R15005 injected observation failure");
        }));
        assert!(outcome.is_err(), "injection must take");
        drop(held);
        match mode {
            "live" => {
                assert_eq!(
                    proc_starttime(pid),
                    Ok(Some(tick)),
                    "live fixture must survive the unresolved drop"
                );
                let mut child = owned.take().expect("owned staged");
                let _ = child.kill();
                let _ = child.wait();
                assert_eq!(proc_starttime(pid), Ok(None), "live retired loud");
            }
            "zombie" => {
                let mut status = 0;
                // SAFETY: WNOHANG probe only.
                let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                assert!(
                    got < 0,
                    "fallback must discharge the zombie (reaped here: {got})"
                );
                // Belt-and-braces: the handle must agree (ECHILD).
                let mut child = owned.take().expect("owned staged");
                let _ = child.wait();
            }
            "gone" => {
                // A recycled number (suite activity retaking it
                // in the reap→drop window) makes the loud line
                // CORRECT — report the contention so the parent
                // skips loud instead of failing; the occupant is
                // foreign and is never touched.
                if matches!(proc_starttime(pid), Ok(Some(_))) {
                    eprintln!("R15005-GONE-RECYCLED pid={pid}");
                }
            }
            "stranger" => {
                assert_eq!(
                    proc_starttime(pid),
                    Ok(Some(tick)),
                    "stranger must survive the unresolved drop"
                );
                // SAFETY: signal-only to the staged stranger.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                let mut parent = sh_parent.expect("sh parent staged");
                let end = Instant::now() + Duration::from_secs(10);
                loop {
                    if parent.try_wait().expect("parent wait").is_some() {
                        break;
                    }
                    assert!(Instant::now() < end, "sh parent must exit");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            _ => unreachable!("mode checked above"),
        }
        eprintln!("R15005-CHILD-DONE mode={mode}");
    }

    /// R15-005: audit twin — live drop under EMFILE reports.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn audit_emfile_live_drop_reports_unresolved_custody() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
            audit_emfile_probe_child(&mode);
            return;
        }
        let stderr = audit_emfile_probe_spawn(
            "live",
            "fixture::linux::audit::tests::audit_emfile_live_drop_reports_unresolved_custody",
        );
        let pinned = audit_emfile_probe_tagged(&stderr, "R15005-PINNED ", "live");
        let cited = audit_emfile_probe_tagged(&stderr, "scopebase unresolved-custody ", "live");
        assert_eq!(cited, pinned, "custody line must cite the pinned identity");
    }

    /// R15-005: audit twin — zombie drop under EMFILE discharges
    /// silently.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn audit_emfile_zombie_drop_discharges_silently() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
            audit_emfile_probe_child(&mode);
            return;
        }
        let stderr = audit_emfile_probe_spawn(
            "zombie",
            "fixture::linux::audit::tests::audit_emfile_zombie_drop_discharges_silently",
        );
        assert!(
            !stderr.contains("unresolved-custody"),
            "zombie discharge must stay silent\n{stderr}"
        );
    }

    /// R15-005: audit twin — gone-number drop under EMFILE stays
    /// silent (guard role, mutant-checked like the toolchain).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn audit_emfile_gone_drop_stays_silent() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
            audit_emfile_probe_child(&mode);
            return;
        }
        let stderr = audit_emfile_probe_spawn(
            "gone",
            "fixture::linux::audit::tests::audit_emfile_gone_drop_stays_silent",
        );
        if stderr.contains("R15005-GONE-RECYCLED") {
            eprintln!("skip: gone number recycled mid-window (contended)");
            return;
        }
        assert!(
            !stderr.contains("unresolved-custody"),
            "gone-number drop must stay silent\n{stderr}"
        );
    }

    /// R15-005: audit twin — stranger drop under EMFILE reports.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn audit_emfile_stranger_drop_reports_unresolved_custody() {
        if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
            audit_emfile_probe_child(&mode);
            return;
        }
        let stderr = audit_emfile_probe_spawn(
            "stranger",
            "fixture::linux::audit::tests::audit_emfile_stranger_drop_reports_unresolved_custody",
        );
        let pinned = audit_emfile_probe_tagged(&stderr, "R15005-PINNED ", "stranger");
        let cited = audit_emfile_probe_tagged(&stderr, "scopebase unresolved-custody ", "stranger");
        assert_eq!(cited, pinned, "custody line must cite the pinned identity");
    }

    /// R14-007: the adopted-zombie drain must re-decide
    /// foreignness EVERY pass, not once. Own group G with a
    /// zombie (reaped legitimately on pass 1); a barrier hook
    /// then retires our last member and reforms a
    /// different-birth group on the freed pgid with its own
    /// zombie; pass 2 must NOT reap the replacement's status.
    /// Pre-fix the stale decision drains it (RED: status
    /// theft); post-fix the recheck breaks (GREEN). Duration
    /// 68 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn drain_rechecks_foreignness_each_pass() {
        use std::cell::{Cell, RefCell};
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return;
            }
        };
        if !audit_locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
            eprintln!("skip: ns_last_pid unwritable (no reuse control)");
            return;
        }
        // Own group G: self-grouped sleeper S.
        let mut sleeper = std::process::Command::new("/bin/sleep");
        sleeper
            .arg("68")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            sleeper.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let sleeper = sleeper.spawn().expect("sleeper spawns");
        let id = sleeper.id() as libc::pid_t;
        let own_tick = proc_starttime(id)
            .expect("sleeper stat readable")
            .expect("sleeper visible");
        // Own zombie Z1 in G (joins the live group, exits 3).
        let mut z1 = std::process::Command::new("/bin/sh");
        z1.arg("-c")
            .arg("exit 3")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid into our live group pre-exec.
        unsafe {
            z1.pre_exec(move || {
                libc::setpgid(0, id);
                Ok(())
            });
        }
        let mut z1 = z1.spawn().expect("z1 spawns");
        // Z1 must be a zombie BEFORE expiry (else pass 1 may
        // see only S and the barrier plants early).
        let z_end = Instant::now() + Duration::from_secs(5);
        loop {
            if z1.try_wait().expect("z1 try_wait works").is_some() {
                break;
            }
            assert!(Instant::now() < z_end, "z1 never exited");
            std::thread::sleep(Duration::from_millis(1));
        }
        // Barrier plant (fires once, after pass 1's reap):
        // retire S, reform group G at a different birth with
        // its own zombie R. Outputs via cells (Fn, not FnMut).
        let planted = Cell::new(false);
        let replacement_tick = Cell::new(0u64);
        let replacement: RefCell<Option<std::process::Child>> = RefCell::new(None);
        let reformed = Cell::new(false);
        let barrier = || {
            if planted.get() {
                return;
            }
            planted.set(true);
            // SAFETY: retiring our own sleeper.
            unsafe {
                libc::kill(id, libc::SIGKILL);
            }
            let reap_end = Instant::now() + Duration::from_secs(5);
            loop {
                let mut status = 0;
                // SAFETY: WNOHANG reap of our own dying child.
                if unsafe { libc::waitpid(id, &mut status, libc::WNOHANG) } != 0 {
                    break;
                }
                assert!(Instant::now() < reap_end, "sleeper never reaped");
                std::thread::sleep(Duration::from_millis(1));
            }
            let _flock = ns_last_pid_flock();
            for _ in 0..100 {
                if !audit_steer_next_pid_unlocked(id) {
                    break;
                }
                let mut cmd = std::process::Command::new("/bin/sh");
                cmd.arg("-c")
                    .arg("exit 3")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                // SAFETY: setpgid on self pre-exec.
                unsafe {
                    cmd.pre_exec(|| {
                        libc::setpgid(0, 0);
                        Ok(())
                    });
                }
                // The placed candidate is waited via the owner
                // cell below (clippy cannot see through the cell:
                // allow the false-positive lint on this spawn;
                // every other path waits inline).
                #[allow(clippy::zombie_processes)]
                let cand = cmd.spawn().expect("candidate spawns");
                if cand.id() as libc::pid_t != id {
                    let mut cand = cand;
                    let _ = cand.kill();
                    let _ = cand.wait();
                    continue;
                }
                // Placed at the freed pgid AND self-grouped:
                // the group is reformed at a different birth.
                if let Ok(Some(tick)) = proc_starttime(id) {
                    replacement_tick.set(tick);
                    *replacement.borrow_mut() = Some(cand);
                    reformed.set(true);
                } else {
                    // Unstatable at birth (≈ impossible — a fresh
                    // sleep): retire at once, never drop unwatched.
                    let mut cand = cand;
                    let _ = cand.kill();
                    let _ = cand.wait();
                }
                break;
            }
        };
        expire_probe_collection_with_hook(id, own_tick, &[], false, Some(&barrier), None);
        audit_locked_restore_hint(&last_before);
        // Loud owner cleanup of our fixtures either way, then
        // skips, then the verdict.
        let _ = z1.wait();
        let mut replacement = replacement.borrow_mut().take();
        if !reformed.get() {
            drop(sleeper);
            eprintln!("skip: group number not reformed (contended)");
            return;
        }
        if replacement_tick.get() == own_tick {
            if let Some(mut child) = replacement.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            drop(sleeper);
            eprintln!("skip: same-tick reform (S100 — untestable this run)");
            return;
        }
        let mut child = replacement.take().expect("replacement stored");
        // SAFETY: getpgid queries only.
        assert_eq!(
            unsafe { libc::getpgid(id) },
            id,
            "replacement must reform the group"
        );
        let status = child.wait().expect("replacement owner keeps its status");
        drop(sleeper);
        assert_eq!(
            status.code(),
            Some(3),
            "replacement status must survive the drain (no theft)"
        );
    }

    /// R15-007: the drain re-decides foreignness after EVERY
    /// successful inner reap (not once per outer pass). Stage: a
    /// group with ONE zombie Z1 and a reaped leader; the
    /// per-reap hook reforms the freed leader number after that
    /// (last) reap (steered sh/exit-3, self-grouped, zombie —
    /// the replacement shape; the steer needs the group empty —
    /// a zombie-held pgid pins its struct pid). Pre-fix the next
    /// inner waitpid steals R's status (RED: the reform is gone,
    /// the owner wait fails); post-fix the post-reap recheck
    /// sees the reform and stops (GREEN: R's exit-3 status
    /// survives for its owner). Reuse-control gated (skip when
    /// ns_last_pid unreadable/unwritable — the operative gate;
    /// root implies it upstream): without placement the reform
    /// cannot stage.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn drain_rechecks_foreignness_each_reap() {
        use std::cell::{Cell, RefCell};
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        // R12-002: serialize steerers (whole-test hold).
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return;
            }
        };
        if !audit_locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
            eprintln!("skip: ns_last_pid unwritable (no reuse control)");
            return;
        }
        // Leader L: self-grouped, exits at once; Z1 joins L's
        // group pre-exit and zombifies (true exits immediately).
        let mut leader = std::process::Command::new("/bin/sh");
        leader
            .arg("-c")
            .arg("exit 7")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            leader.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut leader = leader.spawn().expect("leader spawns");
        let id = leader.id() as libc::pid_t;
        let spawn_member = || {
            let mut member = std::process::Command::new("true");
            member
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // SAFETY: setpgid into the live leader group pre-exec.
            unsafe {
                member.pre_exec(move || {
                    libc::setpgid(0, id);
                    Ok(())
                });
            }
            member.spawn().expect("member spawns")
        };
        let mut z1 = spawn_member();
        // Settle into Z BEFORE the drain (bounded poll on /proc
        // state — never a reaping wait).
        let z1_id = z1.id() as libc::pid_t;
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(proc_state(z1_id), Some(state) if state == 'Z') {
                break;
            }
            assert!(Instant::now() < end, "z1 never zombied");
            std::thread::sleep(Duration::from_millis(1));
        }
        // Pin the leader's tick, then reap it (frees the NUMBER;
        // the pgid stays busy via Z1).
        let own_tick = proc_starttime(id)
            .expect("leader stat readable")
            .expect("leader visible");
        let leader_status = leader.wait().expect("leader reaped");
        assert_eq!(leader_status.code(), Some(7), "our leader reaped");
        // Per-reap plant (fires once, after the last — only —
        // reap, when the group is empty and the number is
        // unpinned): reform id at a different birth with its own
        // zombie R. Outputs via cells (Fn, not FnMut).
        let planted = Cell::new(false);
        let replacement_tick = Cell::new(0u64);
        let replacement: RefCell<Option<std::process::Child>> = RefCell::new(None);
        let reformed = Cell::new(false);
        let reap_hook = || {
            if planted.get() {
                return;
            }
            planted.set(true);
            // The steer succeeds: Z1 (the only member) was just
            // reaped, so the group is empty and nothing pins the
            // number (a zombie-held pgid pins its struct pid —
            // steering onto it is impossible until the group
            // empties; that is why the stage holds ONE zombie).
            let _flock = ns_last_pid_flock();
            for _ in 0..100 {
                if !audit_steer_next_pid_unlocked(id) {
                    break;
                }
                let mut cmd = std::process::Command::new("/bin/sh");
                cmd.arg("-c")
                    .arg("exit 3")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                // SAFETY: setpgid on self pre-exec.
                unsafe {
                    cmd.pre_exec(|| {
                        libc::setpgid(0, 0);
                        Ok(())
                    });
                }
                // The placed candidate is waited via the owner
                // cell below (clippy cannot see through the cell;
                // every other path waits inline).
                #[allow(clippy::zombie_processes)]
                let cand = cmd.spawn().expect("candidate spawns");
                if cand.id() as libc::pid_t != id {
                    let mut cand = cand;
                    let _ = cand.kill();
                    let _ = cand.wait();
                    continue;
                }
                // Placed at the freed number AND self-grouped:
                // the group is reformed at a different birth.
                if let Ok(Some(tick)) = proc_starttime(id) {
                    replacement_tick.set(tick);
                    *replacement.borrow_mut() = Some(cand);
                    reformed.set(true);
                    // Settle R into Z BEFORE returning: the theft
                    // under test needs R waitable at the next
                    // inner wait (a live R would skip the reap
                    // and vacate the RED — the mutant survives).
                    let z_end = Instant::now() + Duration::from_secs(5);
                    loop {
                        if matches!(proc_state(id), Some(state) if state == 'Z') {
                            break;
                        }
                        assert!(Instant::now() < z_end, "replacement never zombified");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                } else {
                    let mut cand = cand;
                    let _ = cand.kill();
                    let _ = cand.wait();
                }
                break;
            }
        };
        expire_probe_collection_with_hook(id, own_tick, &[], false, None, Some(&reap_hook));
        audit_locked_restore_hint(&last_before);
        // Loud owner cleanup of our fixtures either way (the
        // drain reaped Z1 already — the wait tolerates ECHILD),
        // then skips, then the verdict.
        let _ = z1.wait();
        let mut replacement = replacement.borrow_mut().take();
        if !reformed.get() {
            eprintln!("skip: group number not reformed (contended)");
            return;
        }
        if replacement_tick.get() == own_tick {
            if let Some(mut child) = replacement.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            eprintln!("skip: same-tick reform (S100 — untestable this run)");
            return;
        }
        let mut child = replacement.take().expect("replacement stored");
        // SAFETY: getpgid queries only.
        assert_eq!(
            unsafe { libc::getpgid(id) },
            id,
            "replacement must reform the group"
        );
        let status = child.wait().expect("replacement owner keeps its status");
        assert_eq!(
            status.code(),
            Some(3),
            "replacement status must survive the drain (no theft)"
        );
    }

    /// R13-004: expiry must not drain a proven-foreign group.
    /// `group_died` suppresses the signal but pre-fix the
    /// adopted-zombie drain still runs `waitpid(-id)` — reaping
    /// another test's exited child in the recycled group
    /// (status theft). Same for a sampler-invisible regroup
    /// (group_died=false, grouped stranger). Setup: a live
    /// self-grouped foreign holder H plus a zombie V of OURS
    /// in H's group (V = another test thread's child shape —
    /// same process, different owner). Expire twice (died,
    /// then invisible); V's status must stay available to its
    /// owner both times (pre-fix the first drain steals it —
    /// RED), and H must survive. No steering: the function
    /// cannot distinguish this from a true recycle. Duration
    /// 63 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn expiry_spares_proven_foreign_group_zombie() {
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};
        let mut holder = std::process::Command::new("/bin/sleep");
        holder
            .arg("63")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            holder.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut holder = holder.spawn().expect("holder spawns");
        let id = holder.id() as libc::pid_t;
        // R14-012: custody AT birth (auto-pins) — the reads, the
        // group assert, and the victim spawn below panic safe;
        // disarmed after the owner cleanup.
        let mut holder_guard = FixtureGuard::new(id);
        let holder_tick = proc_starttime(id)
            .expect("holder stat readable")
            .expect("holder visible");
        // R15-004: late-pin the observed live tick.
        holder_guard.pin(holder_tick);
        // SAFETY: getpgid queries only.
        assert_eq!(unsafe { libc::getpgid(id) }, id, "holder must self-group");
        // V: exits at once inside the holder's group; a stable
        // zombie owned by us (another owner's shape).
        let mut victim = std::process::Command::new("true");
        victim
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid into the live holder group pre-exec
        // (id copied — 'static satisfied).
        unsafe {
            victim.pre_exec(move || {
                libc::setpgid(0, id);
                Ok(())
            });
        }
        let mut victim = victim.spawn().expect("victim spawns");
        let victim_id = victim.id() as libc::pid_t;
        // R14-012: custody AT birth — the Z-poll assert below
        // panics safe, and the drop discharges the status;
        // disarmed once the owner collects it.
        let mut victim_guard = FixtureGuard::new(victim_id);
        // Settle V into a zombie BEFORE expiry (bounded poll on
        // /proc state — never a reaping wait).
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let state = std::fs::read_to_string(format!("/proc/{victim_id}/stat"))
                .ok()
                .and_then(|row| {
                    row.rsplit_once(") ")
                        .map(|(_, rest)| rest.split_whitespace().next().unwrap_or("?").to_string())
                });
            if state.as_deref() == Some("Z") {
                break;
            }
            assert!(
                Instant::now() < end,
                "victim never reached zombie state (state={state:?})"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // Bogus tick: always mismatched (wrapping +1).
        let bogus = holder_tick.wrapping_add(1);
        expire_probe_collection(id, bogus, &[], true);
        expire_probe_collection(id, bogus, &[], false);
        // Observe before cleanup (R12-014): the owner's wait
        // must still find V's status (a stealing drain would
        // ECHILD here), and the holder must live.
        let kept = victim.try_wait();
        let holder_now = proc_starttime(id);
        // SAFETY: retiring our own holder.
        unsafe {
            libc::kill(id, libc::SIGKILL);
        }
        let owned = holder.wait();
        // Both statuses are owner-collected now (victim via the
        // try_wait above, holder via the wait): stand the guards
        // down before the asserts below.
        holder_guard.disarm();
        victim_guard.disarm();
        let kept = kept.expect("victim status must survive expiry");
        assert!(
            kept.is_some(),
            "victim status must stay available to its owner"
        );
        assert_eq!(
            holder_now,
            Ok(Some(holder_tick)),
            "foreign holder must survive expiry"
        );
        let status = owned.expect("holder owner keeps its status");
        assert!(!status.success(), "killed holder reports signal death");
    }

    /// R15-004: audit twin of the toolchain birth pin —
    /// transient retry with injected read (see the toolchain
    /// twin for the contract).
    #[cfg(target_arch = "x86_64")]
    fn pin_birth_tick_with(
        pid: libc::pid_t,
        read: impl Fn(libc::pid_t) -> Result<Option<u64>, String>,
    ) -> Option<u64> {
        use std::time::{Duration, Instant};
        let end = Instant::now() + Duration::from_millis(100);
        loop {
            match read(pid) {
                Ok(tick) => return tick,
                Err(_) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return None,
            }
        }
    }

    /// R15-004: the production pin reader.
    #[cfg(target_arch = "x86_64")]
    fn pin_birth_tick(pid: libc::pid_t) -> Option<u64> {
        pin_birth_tick_with(pid, proc_starttime)
    }

    /// R14-012: custody AT birth for lib-test fixtures — the
    /// audit twin of the toolchain's `SilentChildGuard`
    /// (separate harnesses, same contract): auto-pins the birth
    /// tick (our unreaped child cannot have recycled),
    /// probe-first drop when the birth read failed (IR-002: a
    /// gone number or a foreign recycle takes no signal),
    /// tick-gated drop otherwise (R14-001: a recycled number
    /// is spared), disarm after explicit retires.
    #[cfg(target_arch = "x86_64")]
    struct FixtureGuard {
        pid: libc::pid_t,
        tick: Option<u64>,
        disarmed: bool,
    }

    #[cfg(target_arch = "x86_64")]
    impl FixtureGuard {
        /// Never panics: construction itself must not be a
        /// staging failure (the birth→read window it closes).
        fn new(pid: libc::pid_t) -> Self {
            let tick = pin_birth_tick(pid);
            FixtureGuard {
                pid,
                tick,
                disarmed: false,
            }
        }
        /// Stand down after an explicit loud retire — without
        /// this the drop double-retires the (possibly recycled)
        /// number.
        fn disarm(&mut self) {
            self.disarmed = true;
        }
        /// R15-004: late-pin a birth tick read after construction
        /// (audit twin of the toolchain `pin` — same contract:
        /// the drop re-verifies, so a pin of OUR child's tick
        /// degrades to a skip once stale; never pin a post-retire
        /// re-read — that could pin a squatter's tick).
        fn pin(&mut self, tick: u64) {
            self.tick = Some(tick);
        }
    }

    #[cfg(target_arch = "x86_64")]
    /// R15-005: drop-time fallback when the pinned tick
    /// re-read FAILS (audit twin of the toolchain
    /// `drop_unresolved_custody` — same contract: fd-less
    /// waitpid + kill-0 probe, silent on reaped/ESRCH, loud
    /// identity-preserving line otherwise, never signals, never
    /// panics).
    #[cfg(target_arch = "x86_64")]
    fn drop_unresolved_custody(pid: libc::pid_t, tick: u64, read_err: &str) {
        use std::io::Write as _;
        let loud = || {
            let _ = writeln!(
                std::io::stderr(),
                "scopebase unresolved-custody pid={pid} tick={tick} read_err={read_err}"
            );
        };
        let mut status = 0;
        // SAFETY: WNOHANG probe; never blocks.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if got == pid {
            return; // Reaped: discharged, silent.
        }
        if got == 0 {
            loud(); // Live owned child — loud, no kill.
            return;
        }
        // ECHILD-shaped (reaped already, or never our child):
        // kill-0 decides without fds.
        // SAFETY: signal 0 queries only.
        if unsafe { libc::kill(pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return; // Gone: discharged, silent.
        }
        // Present (kill-0 ok, EPERM, or anything else):
        // unobservable-but-there — loud.
        loud();
    }

    impl Drop for FixtureGuard {
        fn drop(&mut self) {
            if self.disarmed {
                return;
            }
            match self.tick {
                None => retire_audit_child_silent(self.pid),
                Some(tick) => match proc_starttime(self.pid) {
                    Ok(Some(now)) if now == tick => retire_audit_child_silent(self.pid),
                    // R15-005: proven-gone/recycled stays silent
                    // (as before); only a FAILED read takes the
                    // fd-less fallback probe.
                    Ok(_) => {}
                    Err(error) => drop_unresolved_custody(self.pid, tick, &error),
                },
            }
        }
    }

    /// R14-012: SIGKILL + bounded silent reap of an owned child
    /// (staging cleanup and guard drops). Never panics — a
    /// stuck child reports through the caller's loud verify,
    /// never from inside unwind.
    /// IR-002: waitpid-probes FIRST — ECHILD (not our child: a
    /// gone number, or one recycled by a foreign task) returns
    /// WITHOUT signaling; a reaped status was our zombie
    /// (done, no kill needed); only a live owned child takes
    /// the signal plus the bounded reap.
    #[cfg(target_arch = "x86_64")]
    fn retire_audit_child_silent(pid: libc::pid_t) {
        use std::time::{Duration, Instant};
        let mut status = 0;
        // SAFETY: WNOHANG probe of a possibly-owned child; never blocks.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if got != 0 {
            // Our zombie discharged (got == pid), or not our
            // child at all (got < 0: gone, or a foreign
            // recycle) — either way no signal is owed.
            return;
        }
        // SAFETY: signal-only to a live owned child; errors ignored.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: waitpid on an owned child; WNOHANG never blocks.
            let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if got == pid || got < 0 {
                return;
            }
            if Instant::now() >= end {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// R15-003: SIGKILL gated on a pinned birth tick — cleanup
    /// must never signal a number it may have released (a pump
    /// or helper may have reaped it; a steered replacement may
    /// hold it now). Signals only when the current tick matches;
    /// gone/recycled skips silently (nothing of ours); an
    /// unreadable stat skips unproven. True when no further
    /// action is needed (signaled, or nothing of ours); false
    /// only when unreadable. Never panics (cleanup context).
    /// The read fn is injected so the unreadable arm is
    /// unit-testable without staging EMFILE.
    #[cfg(target_arch = "x86_64")]
    fn kill_tick_gated_with(
        pid: libc::pid_t,
        tick: u64,
        read: impl Fn(libc::pid_t) -> Result<Option<u64>, String>,
    ) -> bool {
        match read(pid) {
            Ok(Some(now)) if now == tick => {
                // SAFETY: tick-pinned staged task; errors ignored.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                true
            }
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// R15-003: the production caller of the gate above (reads
    /// the live tick).
    #[cfg(target_arch = "x86_64")]
    fn kill_tick_gated(pid: libc::pid_t, tick: u64) -> bool {
        kill_tick_gated_with(pid, tick, proc_starttime)
    }

    /// R15-003: tick-gated retirement for owned test children —
    /// the gated signal above plus a bounded reaping wait (a
    /// stale `Child::wait` after a raw reap would block on, or
    /// steal status from, a recycled replacement; the gated
    /// waitpid below only runs on tick-match). Same return
    /// contract as the gate. Never panics.
    #[cfg(target_arch = "x86_64")]
    fn retire_tick_gated_audit_child(pid: libc::pid_t, tick: u64) -> bool {
        use std::time::{Duration, Instant};
        if proc_starttime(pid) != Ok(Some(tick)) {
            return proc_starttime(pid).is_ok();
        }
        // SAFETY: tick-pinned owned child; errors ignored.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: waitpid on a tick-pinned child; never blocks.
            let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if got == pid || got < 0 {
                return true;
            }
            if Instant::now() >= end {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// R14-012: a birth number is free only when /proc proves
    /// absence AND waitpid proves discharge (ECHILD — reaped). A
    /// zombie fails the first (it keeps its tick); an unreaped
    /// death fails the second. Checked in this order so the
    /// discharge probe can never mask a zombie by reaping it
    /// mid-check.
    #[cfg(target_arch = "x86_64")]
    fn assert_audit_pid_free(pid: libc::pid_t, what: &str) {
        assert_eq!(
            proc_starttime(pid),
            Ok(None),
            "{what} {pid} survived retirement"
        );
        // SAFETY: WNOHANG discharge probe of our own child.
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        // SAFETY: errno location for this thread.
        let errno = unsafe { libc::__errno_location().read() };
        assert!(
            got < 0 && errno == libc::ECHILD,
            "{what} {pid} status undischarged (waitpid gave {got})"
        );
    }

    /// R14-012: staging custody driver — every birth shape takes
    /// custody AT birth (guard before any fallible read), proved
    /// by two genuine injections per birth: (A) observation
    /// failure (the fixture dies before the read — the read's
    /// expect panics); (B) later-spawn failure (birth +
    /// observation succeed, then a spawn of a missing binary
    /// panics). Each case requires disappearance + status
    /// discharge BEFORE the failure report (assert order mirrors
    /// it; the guard drops during unwind, ahead of the panic).
    /// Shapes → sites: self-grouped holder = foreign-group
    /// holder-63; exiting true = foreign-group victim shape (the
    /// group-join is incidental to custody — discharge is what
    /// matters).
    #[cfg(target_arch = "x86_64")]
    fn fixture_staging_custody_holds(
        tag: &str,
        birth: impl Fn() -> libc::pid_t,
        observe: impl Fn(libc::pid_t),
    ) {
        // R12-002: serialize against steerers (whole-test hold) —
        // this driver's fork bursts must not steal steered
        // placements from concurrent tests.
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Case A: death before observation — the read must fail,
        // and the (already reaped) fixture must stay free. Silent
        // bounded retire (a surviving fixture fails loud below —
        // the injection must take, never pass vacuously).
        let slot_a = std::cell::Cell::new(-1);
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let pid = birth();
            slot_a.set(pid);
            // R14-012: custody AT birth (the fix under test).
            let mut _guard = FixtureGuard::new(pid);
            // R15-004: late-pin while known-ours and alive —
            // BEFORE the explicit retire (a post-retire re-read
            // could pin a squatter's tick).
            if let Ok(Some(tick)) = proc_starttime(pid) {
                _guard.pin(tick);
            }
            retire_audit_child_silent(pid);
            observe(pid);
        }));
        // A birth panic stages nothing (slot stays -1 — never
        // waitpid(-1): that would reap ANY sibling child).
        if slot_a.get() > 0 {
            assert_audit_pid_free(slot_a.get(), tag);
        }
        assert!(
            observed.is_err(),
            "{tag}: dead-before-read must fail the observation"
        );
        // Case B: later-spawn failure — birth + observation
        // succeed, then a missing-binary spawn panics; the live
        // fixture must still disappear with its status
        // discharged.
        let slot = std::cell::Cell::new(-1);
        let spawned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let pid = birth();
            slot.set(pid);
            // R14-012: custody AT birth (the fix under test).
            let mut _guard = FixtureGuard::new(pid);
            observe(pid);
            // R15-004: late-pin while known-ours and alive (the
            // injected failure below unwinds through the guard).
            if let Ok(Some(tick)) = proc_starttime(pid) {
                _guard.pin(tick);
            }
            // Later-spawn failure (injected): a missing
            // binary. Both arms diverge (the failure must
            // report); the impossible-Ok arm retires first so
            // even it stays clean (and clippy sees the wait).
            match std::process::Command::new("/scopebase-definitely-missing-binary-r14012").spawn()
            {
                Ok(mut stray) => {
                    let _ = stray.kill();
                    let _ = stray.wait();
                    panic!("later spawn unexpectedly succeeded");
                }
                Err(_) => panic!("injected later-spawn failure"),
            }
        }));
        let pid = slot.get();
        assert!(pid > 0, "{tag}: birth must stage a fixture");
        // Record state, clean best-effort (RED runs stay clean),
        // then assert: disappearance, discharge, and only then
        // the failure report.
        let state = proc_starttime(pid);
        retire_audit_child_silent(pid);
        assert_eq!(
            state,
            Ok(None),
            "{tag}: spawn-failure must not leak the fixture"
        );
        assert_audit_pid_free(pid, tag);
        assert!(spawned.is_err(), "{tag}: later-spawn failure must report");
    }

    /// R14-012: self-grouped-holder staging custody (foreign-group
    /// holder-63 shape). Duration 75 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn fixture_staging_custody_grouped_holder() {
        use std::os::unix::process::CommandExt as _;
        fixture_staging_custody_holds(
            "holder",
            || {
                let mut holder = std::process::Command::new("/bin/sleep");
                holder
                    .arg("75")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                // SAFETY: setpgid on self pre-exec, no userspace state.
                unsafe {
                    holder.pre_exec(|| {
                        libc::setpgid(0, 0);
                        Ok(())
                    });
                }
                holder.spawn().expect("holder spawns").id() as libc::pid_t
            },
            |pid| {
                proc_starttime(pid)
                    .expect("holder stat readable")
                    .expect("holder visible");
            },
        );
    }

    /// R14-012: exiting-child staging custody (foreign-group
    /// victim shape — `true` exits at once; the group-join is
    /// incidental to custody).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn fixture_staging_custody_exiting_child() {
        fixture_staging_custody_holds(
            "exiter",
            || {
                std::process::Command::new("true")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("exiter spawns")
                    .id() as libc::pid_t
            },
            |pid| {
                use std::time::{Duration, Instant};
                let end = Instant::now() + Duration::from_secs(5);
                loop {
                    let row =
                        std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("exiter stat");
                    let state = row
                        .rsplit_once(") ")
                        .and_then(|(_, after)| after.split_whitespace().next());
                    if state == Some("Z") {
                        break;
                    }
                    assert!(Instant::now() < end, "child never zombied");
                    std::thread::sleep(Duration::from_millis(1));
                }
                proc_starttime(pid)
                    .expect("exiter stat readable")
                    .expect("exiter present");
            },
        );
    }

    /// R14-012 pin: a guard over an already-gone number (birth
    /// read fails → unpinned) drops silently — IR-002: the
    /// waitpid probe ECHILDs first and no kill ever fires.
    /// Pins the None arm (the drivers above pin the tick-gated
    /// arm).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn unpinned_fixture_guard_over_gone_number_is_silent_noop() {
        // R12-002: serialize against steerers (whole-test hold).
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("exiter spawns");
        let pid = child.id() as libc::pid_t;
        let _ = child.wait();
        {
            let _guard = FixtureGuard::new(pid);
        }
        assert_audit_pid_free(pid, "gone-number");
    }

    /// IR-002: the silent retire must observe before it
    /// signals (R14-006 discipline for the unpinned path
    /// too). A live NON-child — a grandchild parented to
    /// `sh`, never ours, so our waitpid ECHILDs — retired
    /// through `retire_audit_child_silent` must survive. The
    /// staged trigger is a gone number recycled by a foreign
    /// task under an unpinned guard. Pre-fix the kill fires
    /// before the waitpid that would have ECHILDed (RED: the
    /// stranger is murdered); post-fix the waitpid probe
    /// comes first and ECHILD returns without signaling
    /// (GREEN). The verdict reads /proc STATE settled, never
    /// the tick — a zombie keeps its tick, and SIGKILL
    /// delivery is async. Residual: birth-read failure +
    /// recycle by OUR OWN fork is indistinguishable without a
    /// pin (waitpid 0 → kill). Duration 59 is unique to this
    /// test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn retire_silent_probe_first_spares_live_non_child() {
        use std::io::BufRead as _;
        use std::time::{Duration, Instant};
        // R12-002: serialize against steerers (whole-test hold).
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut parent = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 59 & echo $!; wait")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sh parent spawns");
        let mut line = String::new();
        std::io::BufReader::new(parent.stdout.take().expect("sh stdout"))
            .read_line(&mut line)
            .expect("grandchild pid readable");
        let stranger = line.trim().parse::<libc::pid_t>().expect("pid parses");
        let stick = proc_starttime(stranger)
            .expect("stranger stat readable")
            .expect("stranger present");
        // Sanity: live, and not our child (the probe the fix
        // relies on).
        assert!(
            matches!(proc_state(stranger), Some(state) if state != 'Z'),
            "staged stranger must be live"
        );
        {
            let mut status = 0;
            // SAFETY: WNOHANG probe only.
            let got = unsafe { libc::waitpid(stranger, &mut status, libc::WNOHANG) };
            assert!(got < 0, "staged stranger must not be our child");
        }
        retire_audit_child_silent(stranger);
        // Verdict by /proc STATE, settled: a tick check cannot
        // tell live from zombie, and SIGKILL delivery is async
        // — poll until the stranger zombifies/vanishes
        // (murdered) or stays live past the settle window
        // (spared).
        let end = Instant::now() + Duration::from_secs(2);
        let mut survived = true;
        loop {
            match proc_state(stranger) {
                Some(state) if state != 'Z' => {
                    if Instant::now() >= end {
                        break;
                    }
                }
                _ => {
                    survived = false;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Cleanup (runs on RED too): kill our staged task by
        // number + tick, poll it gone, then reap the sh parent
        // (its `wait` ends with the grandchild). R15-003: the
        // kill is tick-gated (on RED paths sh may have reaped
        // the stranger already — a blind kill would murder a
        // recycled replacement).
        let _ = kill_tick_gated(stranger, stick);
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if proc_starttime(stranger) != Ok(Some(stick)) {
                break;
            }
            assert!(Instant::now() < end, "staged stranger must die");
            std::thread::sleep(Duration::from_millis(10));
        }
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if parent.try_wait().expect("parent wait").is_some() {
                break;
            }
            assert!(Instant::now() < end, "sh parent must exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(survived, "silent retire must not murder a live non-child");
    }

    /// R12-006: collection must expire under a saturated stdout.
    /// The finding feared an unbounded inner drain loop starving
    /// the outer deadline check — but backpressure physics
    /// self-yields: a spinning reader always beats writer
    /// wakeup+refill at buffer-cycle end, so WouldBlock gaps let
    /// the outer loop run every ~ms (measured: 2.04s expiry
    /// pre-fix under `yes`; 29k gaps/3s even against a zero-copy
    /// splice pump). The hang is unreproducible; the drain slice
    /// budget below is defense-in-depth (a structural yield no
    /// writer can outrun). This characterization test locks the
    /// behavior: saturate stdout (1MB pipe buffer for maximum
    /// pressure), collect under a 2s deadline with a 15s watchdog
    /// that kills the writer only if collection hangs; require
    /// expiry (None), prompt return, watchdog silence, and writer
    /// retirement. It guards against drain refactors that remove
    /// the yield (proven: deleting both the WouldBlock break and
    /// the slice break hangs to the 15s watchdog; either yield
    /// alone still expires — the slice is defense-in-depth no
    /// buildable writer can trigger). (stderr starvation shares
    /// the root cause with no separate observable: expiry drops
    /// both buffers.)
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn probe_collection_expiry_survives_saturated_stdout() {
        use std::os::unix::process::CommandExt as _;
        use std::sync::atomic::{AtomicBool, Ordering};
        if !staged_probe_python3() {
            eprintln!("skip: python3 unavailable (no staged probes)");
            return;
        }
        // No steering here (no PID reuse) — no placement locks.
        // The probe: self-grouped python forking a same-group
        // writer that execs `yes` (stdout forever, stderr
        // closed so stderr EOFs at probe exit), reporting the
        // writer's pid through a file, then exiting at once.
        let pidfile =
            std::env::temp_dir().join(format!("scopebase-r12006-{}.pid", std::process::id()));
        // R14-003: claim before spawning (a preplant refuses
        // loud here, where no writer exists yet).
        claim_pidfile(&pidfile).expect("rendezvous pidfile claimed");
        let mark = format!("{STAGED_PROBE_MARK}-R12006");
        let script = format!(
            "# {mark}\nimport os, sys\nkid = os.fork()\nif kid == 0:\n    os.close(2)\n    os.execlp('yes', 'yes')\nopen(r'{}', 'w').write(str(kid))\n",
            pidfile.display()
        );
        let mut probe = std::process::Command::new("python3");
        probe
            .arg("-c")
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            probe.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut probe = probe.spawn().expect("saturating probe spawns");
        let id = probe.id() as libc::pid_t;
        let expected = proc_starttime(id)
            .expect("probe stat readable")
            .expect("probe visible");
        // Pin the writer (it must exist before collection —
        // else EOF arrives at once and the expiry assert below
        // fails loud on a dead fixture, not a hang).
        let writer: libc::pid_t = {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                if let Ok(text) = std::fs::read_to_string(&pidfile) {
                    if let Ok(pid) = text.trim().parse() {
                        break pid;
                    }
                }
                assert!(Instant::now() < end, "writer pid never reported");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let writer_tick = proc_starttime(writer)
            .expect("writer stat readable")
            .expect("writer live");
        // Reap the probe (the caller-side wait the R12-005
        // contract names): only the writer holds stdout now.
        let status = probe.wait().expect("probe exit");
        assert!(status.success());
        // Slack for saturation (best-effort; 64KB still usually
        // hangs pre-fix on multicore).
        if let Some(out) = probe.stdout.as_ref() {
            use std::os::unix::io::AsRawFd as _;
            // SAFETY: F_SETPIPE_SZ on an owned pipe fd.
            unsafe {
                libc::fcntl(out.as_raw_fd(), libc::F_SETPIPE_SZ, 1 << 20);
            }
        }
        let done = AtomicBool::new(false);
        let fired = AtomicBool::new(false);
        let (got, elapsed) = std::thread::scope(|scope| {
            scope.spawn(|| {
                // 15s watchdog in 100ms slices; exits within a
                // slice once collection returns.
                for _ in 0..150 {
                    if done.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                if done.load(Ordering::SeqCst) {
                    return;
                }
                // Collection hung: retire the writer through its
                // pin (numeric signals on non-children are
                // forbidden — S115). Firing here unblocks the
                // drain into EOF so the hang fails LOUD below
                // instead of forever.
                let pin = super::super::seccomp::pidfd_open_raw(writer)
                    .expect("watchdog pins a hung writer");
                assert_eq!(
                    proc_starttime(writer),
                    Ok(Some(writer_tick)),
                    "watchdog identity holds"
                );
                // SAFETY: pidfd_send_signal(pidfd, SIGKILL, NULL, 0).
                let sent = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pin as libc::c_long,
                        libc::SIGKILL as libc::c_long,
                        0 as libc::c_long,
                        0 as libc::c_long,
                    )
                };
                assert_eq!(sent, 0, "watchdog signals writer");
                // SAFETY: pin owned by this scope.
                unsafe { libc::close(pin) };
                fired.store(true, Ordering::SeqCst);
            });
            let end = Instant::now() + Duration::from_secs(2);
            let t0 = Instant::now();
            let got = collect_probe_output_bounded(&mut probe, end, expected, &[]);
            let elapsed = t0.elapsed();
            done.store(true, Ordering::SeqCst);
            (got, elapsed)
        });
        let _ = std::fs::remove_file(&pidfile);
        assert!(
            !fired.load(Ordering::SeqCst),
            "watchdog fired — collection hung past 15s (drain never yielded)"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "collection must expire near the 2s deadline, took {elapsed:?}"
        );
        assert!(got.is_none(), "saturated collection must expire");
        // The expiry retired the writer (nothing else signals
        // it — the watchdog never fired): its number is freed
        // or recycled (a foreign tick proves ours retired).
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match proc_starttime(writer) {
                Ok(None) => break,
                Ok(Some(now)) if now != writer_tick => break,
                Ok(Some(_)) => {}
                Err(error) => panic!("writer retirement unresolved: {error}"),
            }
            assert!(Instant::now() < end, "saturated writer survived expiry");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// R13-012: staged-probe tests must SKIP (not fail setup)
    /// when python3 is unavailable. Drives each newly-gated
    /// regression with an emptied PATH and requires exit
    /// success plus the explicit skip report (on machines WITH
    /// python only the emptied PATH can produce it, so the
    /// report proves the gate ran). The substantive assertions
    /// stay covered by the tests themselves (run unforced
    /// in-suite where python exists). The children exit
    /// descendant-free on every path (skip pre-spawn, or a
    /// failed spawn that panics), so the post-exit drain cannot
    /// hang on an inherited pipe.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn staged_probe_tests_skip_without_python() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        let empty =
            std::env::temp_dir().join(format!("scopebase-r13012-emptypath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        std::fs::create_dir(&empty).expect("empty PATH dir");
        for (path, env) in [
            (
                "fixture::linux::audit::tests::probe_collection_expiry_survives_saturated_stdout",
                None,
            ),
            (
                "fixture::linux::audit::tests::collection_expiry_adopting_probe",
                Some(EXPIRY_PROBE_ENV),
            ),
        ] {
            let mut cmd = std::process::Command::new(&exe);
            cmd.arg(path)
                .arg("--exact")
                .arg("--nocapture")
                .env("PATH", &empty)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if let Some(env) = env {
                cmd.env(env, "1");
            }
            let mut child = cmd.spawn().expect("spawn gated probe");
            let end = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = child.try_wait().expect("probe wait") {
                    break status;
                }
                if Instant::now() >= end {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("gated probe ({path}) hung past 30s");
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let mut stderr = Vec::new();
            if let Some(mut pipe) = child.stderr.take() {
                use std::io::Read as _;
                let _ = pipe.read_to_end(&mut stderr);
            }
            assert!(
                status.success(),
                "gated probe ({path}) must skip on missing python, got {status}"
            );
            let stderr_text = String::from_utf8_lossy(&stderr);
            assert!(
                stderr_text.contains("skip: python3 unavailable"),
                "gated probe ({path}) must report its skip: {stderr_text}"
            );
        }
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// R11-014: the bounded helper must not break the normal
    /// path — an exited child with small output collects
    /// exactly, fast.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn probe_collection_delivers_small_output() {
        use std::time::{Duration, Instant};
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("echo OUT; echo ERR >&2")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn echo stage");
        // R12-005: pin before any wait (expiry identity gate).
        let staged = proc_starttime(child.id() as libc::pid_t)
            .expect("stage stat readable")
            .expect("stage visible");
        let status = loop {
            match child.try_wait().expect("stage wait") {
                Some(status) => break status,
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        assert!(status.success());
        let started = Instant::now();
        let got = collect_probe_output_bounded(
            &mut child,
            started + Duration::from_secs(10),
            staged,
            &[],
        );
        let (stdout, stderr) = got.expect("small output must collect");
        assert_eq!(stdout, b"OUT\n");
        assert_eq!(stderr, b"ERR\n");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "small collection must be instant, took {:?}",
            started.elapsed()
        );
    }

    /// IR1 (internal review round 1): entering collection with
    /// an already-expired `end` must not fail a successful
    /// probe — the try_wait loop may consume the whole
    /// deadline while the probe exits at the last instant.
    /// A short grace recovers arrived output (EOF certain:
    /// no live descendants here); only a still-hung pipe
    /// expires. Pre-fix the immediate-expire returns None
    /// and discards the evidence (RED).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn probe_collection_expired_end_recovers_output() {
        use std::time::{Duration, Instant};
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("echo OUT; echo ERR >&2")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn echo stage");
        // R12-005: pin before any wait (expiry identity gate).
        let staged = proc_starttime(child.id() as libc::pid_t)
            .expect("stage stat readable")
            .expect("stage visible");
        let status = loop {
            match child.try_wait().expect("stage wait") {
                Some(status) => break status,
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        assert!(status.success());
        let started = Instant::now();
        let got = collect_probe_output_bounded(
            &mut child,
            started.checked_sub(Duration::from_secs(1)).unwrap(),
            staged,
            &[],
        );
        let (stdout, stderr) = got.expect("expired end must still recover");
        assert_eq!(stdout, b"OUT\n");
        assert_eq!(stderr, b"ERR\n");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "grace must stay bounded, took {:?}",
            started.elapsed()
        );
    }

    /// R10-012: the unresolved-retirement controls must clean up
    /// even when the runner ADOPTS the grandchild (subreaper or
    /// PID-1 runner): the retired task is then our own zombie
    /// and /proc disappearance needs a reap, not just a wait.
    /// The parent spawns a fresh probe process (a confined
    /// subreaper — never the suite binary) and requires exit
    /// success bounded; the probe runs both S132 controls and
    /// proves no child status remains. On timeout the parent
    /// retires the probe's whole process group before failing
    /// loud. The probe output must name one passed test — a
    /// renamed probe path fails here instead of passing
    /// vacuously on zero tests.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn adopted_grandchild_retires_under_subreaper() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        // R13-005: the probe publishes each reported grandchild
        // here; the parent's expiry retires it if the probe dies
        // between birth and retirement.
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-subreaper-{}.pid",
            std::process::id()
        ));
        // R14-003: claim before spawning (a preplant refuses
        // loud here, where no writer exists yet).
        claim_pidfile(&pidfile).expect("rendezvous pidfile claimed");
        let mut child = std::process::Command::new(exe)
            .arg(SUBREAPER_PROBE_PATH)
            .arg("--exact")
            .env(SUBREAPER_PROBE_ENV, "1")
            .env(GRANDCHILD_PIDFILE_ENV, &pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn subreaper probe");
        // R12-005: pin before any wait (expiry identity gate).
        let staged = proc_starttime(child.id() as libc::pid_t)
            .expect("probe stat readable")
            .expect("probe visible");
        let end = Instant::now() + Duration::from_secs(150);
        loop {
            match child.try_wait().expect("probe wait") {
                Some(status) => {
                    // R11-014: bounded collection under the SAME
                    // deadline — wait_with_output would wait for
                    // EOF past it whenever a descendant outlives
                    // the probe holding the pipes.
                    // R13-005: the probe's published grandchild (if
                    // any) rides as expiry strays — a writer the
                    // probe died without retiring still retires.
                    let strays = read_published_grandchild_strays(&pidfile);
                    match collect_probe_output_bounded(&mut child, end, staged, &strays) {
                        Some((stdout, stderr)) => {
                            assert!(
                                status.success(),
                                "subreaper probe must exit success, got {status}: {}",
                                String::from_utf8_lossy(&stderr)
                            );
                            assert!(
                                String::from_utf8_lossy(&stdout).contains("1 passed"),
                                "probe must run its one test (path exact)"
                            );
                        }
                        None => panic!(
                            "subreaper probe output collection expired \
                             (probe exited {status}; group retired)"
                        ),
                    }
                    let _ = std::fs::remove_file(&pidfile);
                    return;
                }
                None => {}
            }
            if Instant::now() >= end {
                // R14-009: the shared timeout body (kills the
                // group + probe, retires published strays).
                timeout_retire_hung_probe(&mut child, &pidfile, "subreaper probe hung past 150s");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// R14-003: a rendezvous record owned by another UID must
    /// never grant signal authority. Preplant a root-owned
    /// readable record naming a live independent victim's real
    /// (pid, starttime); the read path must refuse it loud.
    /// Pre-fix the forged pair is trusted (RED); post-fix the
    /// ownership check fails loud (GREEN). sudo-gated: without
    /// passwordless root file ops the plant is unmakable.
    /// Duration 64 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rendezvous_refuses_foreign_owned_record() {
        // IR-007: as root the sudo plant is own-uid (no foreign
        // discriminator) — skip before staging anything.
        if running_as_root() {
            eprintln!("skip: root-owned plant is not foreign to root");
            return;
        }
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-r14003a-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        let mut victim = std::process::Command::new("/bin/sleep")
            .arg("64")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("victim spawns");
        let vpid = victim.id() as libc::pid_t;
        let vtick = proc_starttime(vpid)
            .expect("victim stat readable")
            .expect("victim visible");
        let planted = std::process::Command::new("sudo")
            .arg("-n")
            .arg("sh")
            .arg("-c")
            .arg(format!(
                "echo {vpid}:{vtick} > {} && chmod 644 {}",
                pidfile.display(),
                pidfile.display()
            ))
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !planted {
            unsafe { libc::kill(vpid, libc::SIGKILL) };
            let _ = victim.wait();
            eprintln!("skip: passwordless sudo unavailable (no other-UID plant)");
            return;
        }
        let refused = std::panic::catch_unwind(|| read_published_grandchild_strays(&pidfile));
        // The victim must survive regardless of the verdict;
        // then root-file cleanup plus loud victim retirement.
        let survived = proc_starttime(vpid) == Ok(Some(vtick));
        let _ = std::process::Command::new("sudo")
            .arg("-n")
            .arg("rm")
            .arg("-f")
            .arg(&pidfile)
            .status();
        unsafe { libc::kill(vpid, libc::SIGKILL) };
        let _ = victim.wait();
        assert!(survived, "forged victim must survive the read");
        assert!(
            refused.is_err(),
            "foreign-owned record must be refused loud"
        );
    }

    /// R14-003: when publication fails, the probe must retire
    /// its known writer BEFORE failing loud — a panic that
    /// skips retirement strands the writer while the parent
    /// trusts a stale record. Deterministic: a chmod-444
    /// pidfile makes the probe-side write EACCES-fail against
    /// a live stand-in writer. Pre-fix the writer stays parked
    /// (RED); post-fix it retires first (GREEN). Duration 65
    /// is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn publish_failure_retires_writer_first() {
        use std::os::unix::fs::PermissionsExt as _;
        // IR-007: root writes chmod-444 files (no unwritable
        // discriminator) — skip before staging anything.
        if running_as_root() {
            eprintln!("skip: root writes chmod-444 files");
            return;
        }
        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(GRANDCHILD_PIDFILE_ENV);
            }
        }
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-r14003b-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        std::fs::write(&pidfile, "").expect("pidfile created");
        std::fs::set_permissions(&pidfile, std::fs::Permissions::from_mode(0o444))
            .expect("pidfile read-only");
        let mut writer = std::process::Command::new("/bin/sleep")
            .arg("65")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("writer spawns");
        let wpid = writer.id() as libc::pid_t;
        let wtick = proc_starttime(wpid)
            .expect("writer stat readable")
            .expect("writer visible");
        // R14-010: serialize in-suite rendezvous publishers.
        let _lock = RENDEZVOUS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(GRANDCHILD_PIDFILE_ENV, &pidfile);
        let _env_guard = EnvGuard;
        let failed = std::panic::catch_unwind(|| {
            publish_reported_grandchild(&GrandchildState::Live(wpid, wtick))
        });
        // Observe before cleanup: the writer must be gone
        // (retired before the loud failure), then loud cleanup
        // of whatever remains either way.
        let retired = proc_starttime(wpid) != Ok(Some(wtick));
        std::fs::set_permissions(&pidfile, std::fs::Permissions::from_mode(0o644)).ok();
        let _ = std::fs::remove_file(&pidfile);
        // R15-003: tick-gated (the failure path retires the
        // writer first; a blind cleanup kill would murder a
        // recycled replacement).
        let _ = retire_tick_gated_audit_child(wpid, wtick);
        assert!(failed.is_err(), "unwritable pidfile must fail loud");
        assert!(retired, "writer must retire before the loud failure");
    }

    /// R14-003: rendezvous setup must refuse a FOREIGN-preplanted
    /// pidfile BEFORE spawning (O_EXCL claim) — proceeding
    /// past a foreign plant burns a doomed probe whose failed
    /// publication panics. Root-preplant (sudo-gated); the claim
    /// must fail. (Our own stale file reclaims — crash recovery
    /// under a wrapped pid — so the plant must be foreign.)
    /// Pre-fix there is no claim (RED: the stub accepts); post-fix
    /// it errors (GREEN).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rendezvous_setup_refuses_preplant() {
        // IR-007: as root the sudo plant is own-uid and
        // reclaims (no foreign discriminator) — skip before
        // staging anything.
        if running_as_root() {
            eprintln!("skip: root-owned plant reclaims for root");
            return;
        }
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-r14003c-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        let planted = std::process::Command::new("sudo")
            .arg("-n")
            .arg("sh")
            .arg("-c")
            .arg(format!("echo 1:1 > {}", pidfile.display()))
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !planted {
            eprintln!("skip: passwordless sudo unavailable (no other-UID plant)");
            return;
        }
        let claimed = claim_pidfile(&pidfile);
        let _ = std::process::Command::new("sudo")
            .arg("-n")
            .arg("rm")
            .arg("-f")
            .arg(&pidfile)
            .status();
        assert!(
            claimed.is_err(),
            "setup must refuse a foreign-preplanted pidfile before spawning"
        );
    }

    /// R14-003: our own stale pidfile (a killed run under a
    /// wrapped pid) reclaims instead of refusing — crash
    /// recovery. Pins the non-refusal branch of the claim.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rendezvous_setup_reclaims_own_stale() {
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-r14003d-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        std::fs::write(&pidfile, "1:1").expect("stale file writes");
        let claimed = claim_pidfile(&pidfile);
        let content = std::fs::read_to_string(&pidfile).expect("claimed file readable");
        let _ = std::fs::remove_file(&pidfile);
        assert!(claimed.is_ok(), "own stale pidfile must reclaim");
        assert!(content.is_empty(), "reclaim must start empty");
    }

    /// R14-010: the rendezvous variable is process-global — tests
    /// that set it in-suite (R14-003's failure pin, R14-010's
    /// publish pins) serialize on this lock so neither reads the
    /// other's value mid-publish. Spawned probes are unaffected
    /// (their environment is fixed at spawn). Holders ignore
    /// poisoning (`into_inner`) — the mutex guards scheduling,
    /// not data (each holder's `EnvGuard` restores the variable
    /// on every path, including panics), so a RED panic must not
    /// wedge the other pins.
    #[cfg(target_arch = "x86_64")]
    static RENDEZVOUS_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// R14-010: a partial/unparseable record fails loud with
    /// EXPLICIT unresolved custody — the parent reports that no
    /// retirement was attempted and the writer's fate is unknown
    /// (an untrusted identity can neither retire nor silently
    /// drop). Pre-fix the panic names only the parse failure
    /// (RED); post-fix it names the custody (GREEN).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rendezvous_partial_record_reports_unresolved_custody() {
        for (tag, content) in [
            ("truncated-pid", "12"),
            ("missing-tick", "1234:"),
            ("missing-pid", ":5678"),
            ("non-numeric", "abc:def"),
            ("extra-field", "1:2:3"),
        ] {
            let pidfile = std::env::temp_dir().join(format!(
                "scopebase-grandchild-r14010a-{tag}-{}.pid",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&pidfile);
            std::fs::write(&pidfile, content).expect("partial record writes");
            let read = std::panic::catch_unwind(|| read_published_grandchild_strays(&pidfile));
            let _ = std::fs::remove_file(&pidfile);
            match read {
                Err(payload) => {
                    let text = payload
                        .downcast::<String>()
                        .map(|boxed| *boxed)
                        .unwrap_or_else(|_| String::from("<non-string panic>"));
                    assert!(
                        text.contains("unresolved custody"),
                        "{tag}: partial record must report unresolved custody, got: {text}"
                    );
                }
                Ok(strays) => panic!("{tag}: partial record must fail loud, got {strays:?}"),
            }
        }
    }

    /// R14-010: record-read failures fail CLOSED, never as silent
    /// empty. Only a missing file means "unpublished" (ENOENT —
    /// skip paths); EACCES (chmod-000 own file) and EIO
    /// (/proc/self/mem opens but never reads) must panic loud —
    /// an empty strays list over a published writer would strand
    /// it silently. EMFILE shares the open-failure arm (same
    /// `Err` branch — staging process-wide fd exhaustion would
    /// fail parallel tests collaterally, so EACCES pins it).
    /// Pre-fix both read empty (RED); post-fix both panic (GREEN).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rendezvous_read_errors_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;
        // IR-007: root reads chmod-000 files (no EACCES
        // discriminator) — skip before staging anything.
        if running_as_root() {
            eprintln!("skip: root reads chmod-000 files");
            return;
        }
        // EACCES: our own file, made unreadable.
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-r14010b-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        std::fs::write(&pidfile, "1:1").expect("record writes");
        std::fs::set_permissions(&pidfile, std::fs::Permissions::from_mode(0o000))
            .expect("record unreadable");
        let read = std::panic::catch_unwind(|| read_published_grandchild_strays(&pidfile));
        std::fs::set_permissions(&pidfile, std::fs::Permissions::from_mode(0o644)).ok();
        let _ = std::fs::remove_file(&pidfile);
        assert!(
            read.is_err(),
            "EACCES record read must fail loud, not empty"
        );
        // EIO: opens (owned, O_NOFOLLOW-clean) but never reads.
        let mem = std::path::Path::new("/proc/self/mem");
        let read = std::panic::catch_unwind(|| read_published_grandchild_strays(mem));
        assert!(read.is_err(), "EIO record read must fail loud, not empty");
    }

    /// R14-010: a set-but-non-UTF-8 rendezvous path fails LOUD
    /// (after retiring the known writer) — never a silent
    /// publication skip over a live writer. Pre-fix `env::var`
    /// reads the value as unset and returns quietly (RED: no
    /// panic, writer live); post-fix the publish retires first,
    /// then panics naming the path (GREEN). Duration 66 is unique
    /// to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rendezvous_non_utf8_path_fails_loud_after_retire() {
        use std::os::unix::ffi::OsStringExt as _;
        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(GRANDCHILD_PIDFILE_ENV);
            }
        }
        let mut writer = std::process::Command::new("/bin/sleep")
            .arg("66")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("writer spawns");
        let wpid = writer.id() as libc::pid_t;
        let wtick = proc_starttime(wpid)
            .expect("writer stat readable")
            .expect("writer visible");
        let _lock = RENDEZVOUS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(
            GRANDCHILD_PIDFILE_ENV,
            std::ffi::OsString::from_vec(vec![b'/', b't', b'm', b'p', 0xff, 0xfe]),
        );
        let _env_guard = EnvGuard;
        let failed = std::panic::catch_unwind(|| {
            publish_reported_grandchild(&GrandchildState::Live(wpid, wtick))
        });
        // Observe before cleanup: the writer must be gone
        // (retired before the loud failure), then loud cleanup
        // of whatever remains either way.
        let retired = proc_starttime(wpid) != Ok(Some(wtick));
        // R15-003: tick-gated (same post-retirement shape as the
        // unwritable-pidfile test above).
        let _ = retire_tick_gated_audit_child(wpid, wtick);
        assert!(failed.is_err(), "non-UTF-8 rendezvous must fail loud");
        assert!(retired, "writer must retire before the loud failure");
    }

    /// R14-010 pin (passes pre- and post-fix — it guards the
    /// atomic-publish refactor, not a behavior change): a Live
    /// publish leaves exactly one complete record and no temp
    /// litter, and a publish whose directory vanished fails loud
    /// after retiring the writer. The truncate-then-write tear
    /// (SIGKILL between truncate and write reads back as silent
    /// unpublished) has no deterministic discriminator — a
    /// concurrent read-while-publish loop would be timing-flaky —
    /// so atomicity is structural (tmp + rename) and this pins
    /// the observable contract around it. Duration 69 is unique
    /// to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rendezvous_publish_leaves_single_complete_record() {
        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(GRANDCHILD_PIDFILE_ENV);
            }
        }
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-r14010c-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        claim_pidfile(&pidfile).expect("rendezvous claimed");
        let mut writer = std::process::Command::new("/bin/sleep")
            .arg("69")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("writer spawns");
        let wpid = writer.id() as libc::pid_t;
        let wtick = proc_starttime(wpid)
            .expect("writer stat readable")
            .expect("writer visible");
        let _lock = RENDEZVOUS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(GRANDCHILD_PIDFILE_ENV, &pidfile);
        let _env_guard = EnvGuard;
        publish_reported_grandchild(&GrandchildState::Live(wpid, wtick));
        let content = std::fs::read_to_string(&pidfile).expect("record readable");
        assert_eq!(
            content,
            format!("{wpid}:{wtick}"),
            "publish must leave exactly one complete record"
        );
        let tmp = pidfile.with_extension("pid.tmp");
        assert!(
            !tmp.exists(),
            "publish must leave no temp litter at {}",
            tmp.display()
        );
        // Failure arm: the directory vanishes after the claim —
        // the publish fails loud (after retiring the writer).
        let dir = std::env::temp_dir().join(format!(
            "scopebase-grandchild-r14010d-{}.dir",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("rendezvous dir created");
        let doomed = dir.join("writer.pid");
        claim_pidfile(&doomed).expect("doomed rendezvous claimed");
        std::fs::remove_dir_all(&dir).expect("rendezvous dir removed");
        std::env::set_var(GRANDCHILD_PIDFILE_ENV, &doomed);
        let failed = std::panic::catch_unwind(|| {
            publish_reported_grandchild(&GrandchildState::Live(wpid, wtick))
        });
        let retired = proc_starttime(wpid) != Ok(Some(wtick));
        // R15-003: tick-gated (same post-retirement shape).
        let _ = retire_tick_gated_audit_child(wpid, wtick);
        let _ = std::fs::remove_file(&pidfile);
        assert!(failed.is_err(), "doomed publish must fail loud");
        assert!(retired, "writer must retire before the loud failure");
    }

    /// IR-001: the atomic-publish tmp must never be written
    /// through a plant. Pre-fix the tmp opens with
    /// create+truncate (following a planted symlink into an
    /// arbitrary runner-writable victim, or blocking on a
    /// planted fifo until the parent timeout) and the rename
    /// then succeeds — the victim is clobbered and the
    /// pidfile becomes the symlink. Post-fix the tmp is
    /// claimed O_EXCL exactly like the pidfile: an own-uid
    /// plant is unlinked and retried (no byte follows the
    /// link), a foreign plant refuses loud. RED: the victim
    /// holds `pid:tick` instead of the sentinel. Duration 66
    /// is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn publish_tmp_symlink_plant_leaves_victim_intact() {
        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(GRANDCHILD_PIDFILE_ENV);
            }
        }
        let stem = format!("scopebase-grandchild-ir001a-{}", std::process::id());
        let pidfile = std::env::temp_dir().join(format!("{stem}.pid"));
        let victim = std::env::temp_dir().join(format!("{stem}.victim"));
        let tmp = std::path::PathBuf::from(format!("{}.tmp", pidfile.display()));
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_file(&victim);
        let _ = std::fs::remove_file(&tmp);
        claim_pidfile(&pidfile).expect("rendezvous claimed");
        let mut writer = std::process::Command::new("/bin/sleep")
            .arg("66")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("writer spawns");
        let wpid = writer.id() as libc::pid_t;
        let wtick = proc_starttime(wpid)
            .expect("writer stat readable")
            .expect("writer visible");
        std::fs::write(&victim, "ir001-sentinel").expect("victim staged");
        std::os::unix::fs::symlink(&victim, &tmp).expect("tmp symlink planted");
        let _lock = RENDEZVOUS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(GRANDCHILD_PIDFILE_ENV, &pidfile);
        let _env_guard = EnvGuard;
        publish_reported_grandchild(&GrandchildState::Live(wpid, wtick));
        let content = std::fs::read(&victim).expect("victim readable");
        unsafe { libc::kill(wpid, libc::SIGKILL) };
        let _ = writer.wait();
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&victim);
        assert_eq!(
            content, b"ir001-sentinel",
            "publish must write no byte through a planted tmp symlink"
        );
    }

    /// R15-001: refusing a foreign-owned tmp must not delete it.
    /// The claim helper refuses foreign plants, but the publish
    /// error handler unconditionally removes the tmp path — a
    /// privileged runner (or any runner in a non-sticky
    /// directory) deletes the foreign file it just refused.
    /// Staged in an owned non-sticky directory (no sticky-bit
    /// rescue): a root-owned tmp plant with known content.
    /// Pre-fix the refusal still unlinks it (RED: inode gone);
    /// post-fix the plant survives with inode and content
    /// intact while the owned writer still retires (GREEN).
    /// Sudo-gated (the plant); skips as root (the plant would
    /// be own-uid, taking the reclaim path instead of refusal).
    /// Duration 56 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn publish_tmp_foreign_refusal_deletes_nothing() {
        use std::os::unix::fs::MetadataExt as _;
        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(GRANDCHILD_PIDFILE_ENV);
            }
        }
        // IR-007 discipline: as root the sudo plant is own-uid
        // (no foreign discriminator) — skip before staging.
        if running_as_root() {
            eprintln!("skip: root-owned plant is not foreign to root");
            return;
        }
        let stem = format!("scopebase-grandchild-r15001a-{}", std::process::id());
        let dir = std::env::temp_dir().join(format!("{stem}.dir"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("rendezvous dir created");
        let pidfile = dir.join("writer.pid");
        let tmp = std::path::PathBuf::from(format!("{}.tmp", pidfile.display()));
        claim_pidfile(&pidfile).expect("rendezvous claimed");
        let planted = std::process::Command::new("sudo")
            .arg("-n")
            .arg("sh")
            .arg("-c")
            .arg(format!("echo r15001-foreign > {}", tmp.display()))
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !planted {
            let _ = std::fs::remove_dir_all(&dir);
            eprintln!("skip: passwordless sudo unavailable (no foreign plant)");
            return;
        }
        let before = std::fs::symlink_metadata(&tmp).expect("plant statted");
        let mut writer = std::process::Command::new("/bin/sleep")
            .arg("56")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("writer spawns");
        let wpid = writer.id() as libc::pid_t;
        let wtick = proc_starttime(wpid)
            .expect("writer stat readable")
            .expect("writer visible");
        let _lock = RENDEZVOUS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(GRANDCHILD_PIDFILE_ENV, &pidfile);
        let _env_guard = EnvGuard;
        let failed = std::panic::catch_unwind(|| {
            publish_reported_grandchild(&GrandchildState::Live(wpid, wtick))
        });
        // Observe before cleanup: foreign inode + content, and
        // writer retirement.
        let after = std::fs::symlink_metadata(&tmp).ok();
        let content = std::fs::read_to_string(&tmp).unwrap_or_default();
        let retired = proc_starttime(wpid) != Ok(Some(wtick));
        unsafe { libc::kill(wpid, libc::SIGKILL) };
        let _ = writer.wait();
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(failed.is_err(), "foreign tmp plant must refuse loud");
        assert!(
            after.is_some_and(|meta| meta.ino() == before.ino()),
            "refusal must not delete the foreign plant"
        );
        assert!(
            content.contains("r15001-foreign"),
            "foreign plant content must survive refusal, got: {content:?}"
        );
        assert!(retired, "writer must retire before the loud refusal");
    }

    /// IR-003: an unreadable firstborn stat must retire the
    /// middleman group BEFORE panicking (the birth number is
    /// known but its tick is not — no record can publish, and
    /// the unwinding probe would strand the born writer). The
    /// trigger is ~EMFILE-only, so a fresh probe image injects
    /// the failure via IR003_INJECT_ENV (set solely on the
    /// probe child's command — never process-wide, or a
    /// sibling probe inheriting it would inject too) and
    /// reports the panic message + observed pgid. Pre-fix the
    /// message names no retirement and the group survives
    /// (RED); post-fix the message folds in `retired: true`
    /// (the retire verified the group ESRCH-empty) and no
    /// hygiene is needed (GREEN). The message must ALSO name
    /// the stat arm (not the timeout arm). RED-path hygiene
    /// kills the leaked group by its reported pgid (safe: a
    /// live group cannot have recycled) before asserting.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn unreadable_firstborn_retires_group_before_panic() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        let stem = format!("scopebase-grandchild-ir003a-{}", std::process::id());
        let pidfile = std::env::temp_dir().join(format!("{stem}.pid"));
        let verdict = std::env::temp_dir().join(format!("{stem}.verdict"));
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_file(&verdict);
        claim_pidfile(&pidfile).expect("rendezvous pidfile claimed");
        let mut child = std::process::Command::new(exe)
            .arg(IR003_PROBE_PATH)
            .arg("--exact")
            .env(IR003_INJECT_ENV, "1")
            .env(IR003_VERDICT_ENV, &verdict)
            .env(SUBREAPER_PROBE_ENV, "1")
            .env(GRANDCHILD_PIDFILE_ENV, &pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn ir003 probe");
        let end = Instant::now() + Duration::from_secs(150);
        let status = loop {
            if let Some(status) = child.try_wait().expect("probe wait") {
                break status;
            }
            if Instant::now() >= end {
                timeout_retire_hung_probe(&mut child, &pidfile, "ir003 probe hung past 150s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            status.success(),
            "ir003 probe must exit success, got {status}"
        );
        let report = std::fs::read_to_string(&verdict).expect("ir003 verdict readable");
        let (pgid_line, rest) = report.split_once('\n').expect("verdict has pgid line");
        let (mtick_line, message) = rest.split_once('\n').expect("verdict has mtick line");
        let pgid = pgid_line
            .trim()
            .parse::<libc::pid_t>()
            .expect("pgid parses");
        let mtick = mtick_line.trim().parse::<u64>().expect("mtick parses");
        assert!(pgid > 0, "probe must observe a middleman pgid, got {pgid}");
        let retired = message.contains("retired: true");
        if !retired {
            // RED-path hygiene only, tick-gated (R15-003): the
            // group kill fires only while the middleman holds
            // its reported birth (a bare-number killpg would
            // murder a recycled foreign group). GREEN runs need
            // nothing (the retire verified ESRCH-empty before
            // panicking); a gate miss falls through to the
            // message asserts below (which fail appropriately).
            if mtick != 0 && proc_starttime(pgid) == Ok(Some(mtick)) {
                // SAFETY: signal-only to our tick-pinned group.
                unsafe {
                    libc::killpg(pgid, libc::SIGKILL);
                }
                let end = Instant::now() + Duration::from_secs(10);
                loop {
                    // SAFETY: signal 0 probes existence only.
                    let probed = unsafe { libc::killpg(pgid, 0) };
                    if probed < 0 {
                        break;
                    }
                    assert!(Instant::now() < end, "leaked ir003 group must die");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_file(&verdict);
        assert!(
            message.contains("firstborn stat unreadable"),
            "panic must come from the stat arm, got: {message}"
        );
        assert!(
            retired,
            "unreadable firstborn must retire its group before panicking, got: {message}"
        );
    }

    /// IR-004: a corrupt rendezvous record must not litter the
    /// pidfile or mask the timeout verdict. The timeout body
    /// reads strays before removing the pidfile — a
    /// forged/unparseable/unreadable record panics past the
    /// removal (litter) with the read failure as the headline
    /// (the parent's timeout masked). Pre-fix the pidfile
    /// survives and the message names only the read failure
    /// (RED); post-fix the pidfile is gone and the message
    /// leads with the timeout, chaining the read failure as
    /// evidence (GREEN). The child is a plain sleep (its
    /// number-as-pgid killpg ESRCHs harmlessly); only the
    /// pidfile content is hostile. Duration 57 is unique to
    /// this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn timeout_masks_no_corrupt_record_and_litters_nothing() {
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-ir004a-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        claim_pidfile(&pidfile).expect("rendezvous claimed");
        std::fs::write(&pidfile, "ir004-not-a-record").expect("corrupt record staged");
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("57")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sleep spawns");
        let what = "ir004 probe hung past 0s";
        let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            timeout_retire_hung_probe(&mut child, &pidfile, what)
        }));
        // Observe before cleanup (R12-014): capture the
        // evidence first, remove any remainder so even RED
        // runs stay clean, then assert.
        let littered = pidfile.exists();
        let _ = std::fs::remove_file(&pidfile);
        let text = match fired {
            Err(payload) => payload
                .downcast::<String>()
                .map(|boxed| *boxed)
                .unwrap_or_else(|_| String::from("<non-string panic>")),
            Ok(_) => panic!("timeout branch must diverge (it returned)"),
        };
        assert!(
            !littered,
            "timeout over a corrupt record must still remove the pidfile"
        );
        assert!(
            text.contains(what),
            "timeout branch must lead with the parent message, got: {text}"
        );
        assert!(
            text.contains("unparseable"),
            "timeout branch must chain the read failure as evidence, got: {text}"
        );
    }

    /// R14-011: pin and stat failures against a live writer stay
    /// UNRESOLVED (false) — never certified disappearance. Each
    /// case stages a fresh live writer and retires it under a
    /// seccomp denial in a FRESH probe image (hermetic: no
    /// suite-wide fd exhaustion, no ambient filter): pidfd-denial
    /// (pin EPERM), read-denial (stat EPERM). The no-denial
    /// control runs FIRST — a writer that cannot retire would
    /// make the denial cases' live-after asserts vacuous: it must
    /// certify (21) with the writer gone. Denial cases must
    /// report 20 with the writer STILL LIVE (unproven means
    /// unsignaled — signaling by number risks a recycled task).
    /// Pre-fix the denial cases certify (RED: 21); post-fix they
    /// report unresolved (GREEN: 20). Durations 70/71/72 are
    /// unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn retire_denial_reports_unresolved_not_gone() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        // (spec, sleep duration, expected code, writer live after?)
        for (spec, duration, expect, live_after) in [
            ("none", "70", 21, false),
            ("pidfd", "71", 20, true),
            ("read", "72", 20, true),
        ] {
            let mut writer = std::process::Command::new("/bin/sleep")
                .arg(duration)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("writer spawns");
            let wpid = writer.id() as libc::pid_t;
            let wtick = proc_starttime(wpid)
                .expect("writer stat readable")
                .expect("writer visible");
            let mut probe = std::process::Command::new(&exe)
                .arg(R14011_PROBE_PATH)
                .arg("--exact")
                .env(R14011_DENIAL_ENV, spec)
                .env(R14011_TARGET_ENV, format!("{wpid}:{wtick}"))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn retire-denial probe");
            let end = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = probe.try_wait().expect("probe wait") {
                    break status;
                }
                // Reap our writer under the probe: the probe's
                // await proves disappearance via /proc, and only
                // WE can reap our zombie (the probe's waitpid
                // ECHILDs) — without this pump the control's
                // await would time out on our unreaped zombie.
                // SAFETY: WNOHANG reap of our own child; errors
                // (no zombie yet) ignored.
                let mut straggler = 0;
                unsafe { libc::waitpid(wpid, &mut straggler, libc::WNOHANG) };
                if Instant::now() >= end {
                    let _ = probe.kill();
                    let _ = probe.wait();
                    // R15-003: tick-gated (the pump above may have
                    // reaped the writer already).
                    let _ = retire_tick_gated_audit_child(wpid, wtick);
                    panic!("{spec}: retire-denial probe hung past 30s");
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let mut err = Vec::new();
            if let Some(mut stderr) = probe.stderr.take() {
                use std::io::Read as _;
                let _ = stderr.read_to_end(&mut err);
            }
            if status.code() == Some(3) {
                // R15-003: tick-gated (uniform with the main path).
                let _ = retire_tick_gated_audit_child(wpid, wtick);
                eprintln!("skip: seccomp unavailable for the retire-denial probe");
                return;
            }
            // Observe before cleanup (R12-014): capture liveness
            // first, retire the writer either way (RED runs stay
            // clean), then assert.
            let live = proc_starttime(wpid) == Ok(Some(wtick));
            // R15-003: tick-gated (the pump may have reaped the
            // writer; a blind kill would murder a recycled
            // replacement, and a stale Child::wait would steal
            // its status or wait on its lifetime).
            let _ = retire_tick_gated_audit_child(wpid, wtick);
            assert_eq!(
                status.code(),
                Some(expect),
                "{spec}: retire verdict wrong: {}",
                String::from_utf8_lossy(&err)
            );
            assert_eq!(
                live, live_after,
                "{spec}: writer liveness after retire wrong (live={live})"
            );
        }
    }

    /// R13-005: an outer probe that exits after grandchild birth
    /// but before retirement must not strand its writer. The
    /// parked grandchild holds the outer probe's pipes from its
    /// own middleman group (the middleman groups itself on
    /// entry), where the expiry killpg cannot reach — the parent
    /// supplies the probe-published identity as expiry strays, so
    /// the expiry retires the independently-grouped writer and
    /// the middleman group probes ESRCH-empty after. Pre-fix the
    /// expiry fires on an empty strays list and the writer stays
    /// alive (RED); post-fix it retires by (pin, starttime) and
    /// the log records the per-stray proof. The abandon injection
    /// stands in for deaths AFTER publication (assert-failure and
    /// early-exit paths skip retirement the same way); deaths
    /// between birth and publication are R14-008's mid-flight
    /// regression (the runner publishes at birth, during the
    /// operation — never only after it returns).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn abandoned_grandchild_retires_by_parent_expiry() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-abandon-{}.pid",
            std::process::id()
        ));
        // R14-003: claim before spawning (a preplant refuses
        // loud here, where no writer exists yet).
        claim_pidfile(&pidfile).expect("rendezvous pidfile claimed");
        let mut child = std::process::Command::new(exe)
            .arg(SUBREAPER_PROBE_PATH)
            .arg("--exact")
            .env(SUBREAPER_PROBE_ENV, "1")
            .env(SUBREAPER_ABANDON_ENV, "1")
            .env(GRANDCHILD_PIDFILE_ENV, &pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn abandoning subreaper probe");
        // R12-005: pin before any wait (expiry identity gate).
        let id = child.id() as libc::pid_t;
        let staged = proc_starttime(id)
            .expect("probe stat readable")
            .expect("probe visible");
        let end = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().expect("probe wait") {
                break status;
            }
            if Instant::now() >= end {
                // R14-009: the shared timeout body (kills the
                // group + probe, retires published strays).
                timeout_retire_hung_probe(&mut child, &pidfile, "abandoning probe hung past 60s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // Skip path first: without seccomp the probe refuses
        // setup (code 3), publishes nothing, and exits success
        // with EOF — collecting must succeed and the skip line
        // must name its cause (an unexplained success would be
        // vacuous, never a skip).
        if status.success() {
            match collect_probe_output_bounded(&mut child, end, staged, &[]) {
                Some((_, err)) => {
                    let err = String::from_utf8_lossy(&err);
                    assert!(
                        err.contains("skip: seccomp unavailable"),
                        "unexpected probe success must explain itself, got: {err}"
                    );
                    eprintln!("skip: seccomp unavailable for the abandon probe");
                    let _ = std::fs::remove_file(&pidfile);
                    return;
                }
                None => panic!("skip-path probe must EOF its output, got expiry"),
            }
        }
        assert_eq!(
            status.code(),
            Some(42),
            "probe must exit by abandon injection, got {status}"
        );
        // Staging proof: the published writer is live,
        // tick-named, and grouped OUTSIDE the outer probe (a
        // same-group writer would die by killpg without any
        // strays list, making the expiry assert vacuous).
        let strays = read_published_grandchild_strays(&pidfile);
        assert_eq!(strays.len(), 1, "abandon must publish exactly one writer");
        let (writer, writer_tick) = strays[0];
        assert_eq!(
            proc_starttime(writer),
            Ok(Some(writer_tick)),
            "published writer must be live at collection"
        );
        // SAFETY: getpgid queries only.
        let writer_group = unsafe { libc::getpgid(writer) };
        assert_ne!(
            writer_group, id,
            "abandoned writer must sit outside the outer probe group"
        );
        // The writer holds EOF past the deadline: collection must
        // expire (an EOF here means the writer never held the
        // pipes — dead fixture, not a passing test). A short
        // collection budget — the 60s above covered the spawn.
        // The published writer rides as expiry strays (the fix).
        let end = Instant::now() + Duration::from_secs(3);
        let got = collect_probe_output_bounded(&mut child, end, staged, &strays);
        assert!(
            got.is_none(),
            "writer-held collection must expire (dead fixture otherwise)"
        );
        // Post-expiry: the independently-grouped writer is retired
        // and its group probes ESRCH-empty. Observe before cleanup
        // (R12-014): capture the evidence first, retire any
        // remainder so even RED runs stay clean, then assert.
        let writer_gone = await_proc_gone_reaping(writer, writer_tick, Duration::from_secs(2));
        // R15-008: the hygiene outcome travels with the report
        // (a denied-but-live writer must not strand nameless).
        let note = if !writer_gone {
            let hygiene = retire_known_stray_best_effort(writer, writer_tick);
            writer_retire_note(writer, writer_tick, hygiene)
        } else {
            String::new()
        };
        let _ = std::fs::remove_file(&pidfile);
        assert!(
            writer_gone,
            "parent expiry must retire the abandoned writer{note}"
        );
        let group_end = Instant::now() + Duration::from_secs(2);
        loop {
            // SAFETY: signal 0 probes existence only.
            if unsafe { libc::killpg(writer_group, 0) } < 0 {
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                assert_eq!(
                    errno,
                    libc::ESRCH,
                    "writer group probe must fail ESRCH-only, got {errno}"
                );
                break;
            }
            assert!(
                Instant::now() < group_end,
                "abandoned writer group {writer_group} survived the parent expiry"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// R14-008: a probe killed AFTER grandchild birth but BEFORE
    /// report completion must still leave the writer's identity.
    /// The runner publishes at birth (during the operation), not
    /// after it returns — a death in the birth-to-report window
    /// otherwise leaves the parent with no strays while the
    /// writer sits parked in the middleman group. Birth is
    /// observed independently via /proc (never via the pidfile);
    /// the kill lands mid-flight (the probe still runs and dies
    /// by our SIGKILL, never exit 42). Pre-fix the pidfile is
    /// empty at kill time (RED: no strays, the writer survives
    /// the expiry); post-fix the birth record rides the parent's
    /// expiry and the writer retires (GREEN).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn midflight_probe_kill_retires_birth_published_writer() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-midflight-{}.pid",
            std::process::id()
        ));
        // R14-003: claim before spawning (a preplant refuses
        // loud here, where no writer exists yet).
        claim_pidfile(&pidfile).expect("rendezvous pidfile claimed");
        let mut child = std::process::Command::new(exe)
            .arg(SUBREAPER_PROBE_PATH)
            .arg("--exact")
            .env(SUBREAPER_PROBE_ENV, "1")
            .env(SUBREAPER_ABANDON_ENV, "1")
            .env(GRANDCHILD_PIDFILE_ENV, &pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn abandoning subreaper probe");
        // R12-005: pin before any wait (expiry identity gate).
        let id = child.id() as libc::pid_t;
        let staged = proc_starttime(id)
            .expect("probe stat readable")
            .expect("probe visible");
        // Birth, observed independently: the middleman (child of
        // the probe) and its firstborn (child of the middleman),
        // both via /proc task-children — never via the pidfile
        // (that would assume the publication under test).
        let end = Instant::now() + Duration::from_secs(60);
        let (writer, writer_tick) = loop {
            if let Some(status) = child.try_wait().expect("probe wait") {
                // Exited before any birth: the seccomp skip
                // path (mirrors the abandon regression), or a
                // broken fixture.
                if status.success() {
                    match collect_probe_output_bounded(&mut child, end, staged, &[]) {
                        Some((_, err)) => {
                            let err = String::from_utf8_lossy(&err);
                            assert!(
                                err.contains("skip: seccomp unavailable"),
                                "unexpected probe success must explain itself, got: {err}"
                            );
                            // R15-006: the explainer assert above stays
                            // bare (EOF'd output = tree down; the
                            // skip removes the pidfile itself).
                            eprintln!("skip: seccomp unavailable for the mid-flight probe");
                            let _ = std::fs::remove_file(&pidfile);
                            return;
                        }
                        None => held_probe_staging_failure(
                            &mut child,
                            &pidfile,
                            "midflight probe staging failure",
                            "midflight-birth",
                            "skip-path probe must EOF its output, got expiry",
                        ),
                    }
                }
                held_probe_staging_failure(
                    &mut child,
                    &pidfile,
                    "midflight probe staging failure",
                    "midflight-birth",
                    &format!("probe exited {status} before grandchild birth"),
                );
            }
            if Instant::now() >= end {
                // R14-009: the shared timeout body (kills the
                // group + probe, retires published strays).
                timeout_retire_hung_probe(&mut child, &pidfile, "grandchild never born (60s)");
            }
            if let Some(mid) = middleman_first_child(id) {
                if let Some(born) = middleman_first_child(mid) {
                    if let Ok(Some(tick)) = proc_starttime(born) {
                        break (born, tick);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // The runner's poll slices publish within ~50ms of birth;
        // wait up to 2s for the record. Pre-fix this never fills
        // (the publication sits after the runner's return) — the
        // kill below still lands mid-flight either way (the
        // report needs preflight's 5s floor), and the empty
        // strays then prove the hole.
        let published = Instant::now() + Duration::from_secs(2);
        loop {
            let filled = std::fs::read_to_string(&pidfile)
                .map(|text| !text.trim().is_empty())
                .unwrap_or(false);
            if filled || Instant::now() >= published {
                break;
            }
            if child.try_wait().expect("probe wait").is_some() {
                // R15-006: staging failure via the timeout body
                // (the completed probe is an unreaped zombie and
                // the writer is live — a bare panic leaks both).
                held_probe_staging_failure(
                    &mut child,
                    &pidfile,
                    "midflight probe staging failure",
                    "midflight-kill",
                    "probe completed before the kill",
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Mid-flight proof: still running, then dead by OUR
        // signal — never exit 42 (a completed probe would have
        // published post-return, voiding the window).
        if child.try_wait().expect("probe wait").is_some() {
            // R15-006: staging failure via the timeout body (see
            // the pre-kill check above).
            held_probe_staging_failure(
                &mut child,
                &pidfile,
                "midflight probe staging failure",
                "midflight-kill",
                "probe must still run at kill time",
            );
        }
        // SAFETY: SIGKILL to our own pinned probe child.
        if unsafe { libc::kill(id, libc::SIGKILL) } != 0 {
            let errno = std::io::Error::last_os_error();
            held_probe_staging_failure(
                &mut child,
                &pidfile,
                "midflight probe staging failure",
                "midflight-kill",
                &format!("probe SIGKILL refused ({errno})"),
            );
        }
        let end = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().expect("probe reap") {
                break status;
            }
            if Instant::now() >= end {
                // R14-009: the shared timeout body (kills the
                // group + probe, retires published strays).
                timeout_retire_hung_probe(&mut child, &pidfile, "killed probe never reaped");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "probe must die by our SIGKILL, got {status}"
        );
        // Staging proof: the birth record names the independently
        // observed grandchild, live and grouped OUTSIDE the outer
        // probe (a same-group writer would die by killpg without
        // any strays list, making the expiry assert vacuous). RED
        // path first: with no record the writer stays parked, so
        // retire it best-effort before failing (RED runs stay
        // clean), then fail loud on the missing publication.
        let strays = read_published_grandchild_strays(&pidfile);
        if strays.len() != 1 {
            let hygiene = retire_known_stray_best_effort(writer, writer_tick);
            let _ = std::fs::remove_file(&pidfile);
            assert_eq!(
                strays.len(),
                1,
                "mid-flight kill must still publish the birth (R14-008){}",
                writer_retire_note(writer, writer_tick, hygiene)
            );
        }
        assert_eq!(
            strays[0],
            (writer, writer_tick),
            "published birth must name the observed grandchild"
        );
        assert_eq!(
            proc_starttime(writer),
            Ok(Some(writer_tick)),
            "published writer must be live at collection"
        );
        // SAFETY: getpgid queries only.
        let writer_group = unsafe { libc::getpgid(writer) };
        assert_ne!(
            writer_group, id,
            "mid-flight writer must sit outside the outer probe group"
        );
        // The writer holds EOF past the deadline: collection must
        // expire (an EOF here means the writer never held the
        // pipes — dead fixture, not a passing test). The birth
        // record rides as expiry strays (the fix).
        let end = Instant::now() + Duration::from_secs(3);
        let got = collect_probe_output_bounded(&mut child, end, staged, &strays);
        assert!(
            got.is_none(),
            "writer-held collection must expire (dead fixture otherwise)"
        );
        // Post-expiry: the independently-grouped writer is retired.
        // Observe before cleanup (R12-014): capture the evidence
        // first, retire any remainder so even RED runs stay
        // clean, then assert.
        let writer_gone = await_proc_gone_reaping(writer, writer_tick, Duration::from_secs(2));
        // R15-008: the hygiene outcome travels with the report.
        let note = if !writer_gone {
            let hygiene = retire_known_stray_best_effort(writer, writer_tick);
            writer_retire_note(writer, writer_tick, hygiene)
        } else {
            String::new()
        };
        let _ = std::fs::remove_file(&pidfile);
        assert!(
            writer_gone,
            "parent expiry must retire the mid-flight writer{note}"
        );
        let group_end = Instant::now() + Duration::from_secs(2);
        loop {
            // SAFETY: signal 0 probes existence only.
            if unsafe { libc::killpg(writer_group, 0) } < 0 {
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                assert_eq!(
                    errno,
                    libc::ESRCH,
                    "writer group probe must fail ESRCH-only, got {errno}"
                );
                break;
            }
            assert!(
                Instant::now() < group_end,
                "mid-flight writer group {writer_group} survived the parent expiry"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// R15-006: per-stage staging timeouts for the held-probe
    /// driver — a timeout PARAMETER (not env: process-global
    /// env would cross-talk parallel driver runs). Production:
    /// 60s birth / 5s publication / 2s stop; regressions inject
    /// 0ns per stage.
    #[cfg(target_arch = "x86_64")]
    #[derive(Clone, Copy)]
    struct HoldStageTimeouts {
        birth: std::time::Duration,
        publication: std::time::Duration,
        stop: std::time::Duration,
    }

    #[cfg(target_arch = "x86_64")]
    impl HoldStageTimeouts {
        const PRODUCTION: Self = Self {
            birth: std::time::Duration::from_secs(60),
            publication: std::time::Duration::from_secs(5),
            stop: std::time::Duration::from_secs(2),
        };
    }

    /// R15-006: staging-failure exit for the held-probe and
    /// midflight drivers — staging failures report VIA the
    /// timeout body (retire-all + loud), never bare asserts. Runs
    /// the REAL timeout body under catch (probe kill + reap,
    /// descendant forensics, published strays, pidfile removal),
    /// VERIFIES the retirement (probe reaped, pidfile gone,
    /// recorded strays/descendants retired — any gap panics as a
    /// BUG, breaking the message shape below), then panics with
    /// the STAGING detail chained to the body's `what` (proving
    /// the body ran). Residuals: fixtures born between the
    /// prestage scan and the body's own forensics snapshot, and
    /// publications landing in that gap, are retired by the body
    /// but unverified here (µs–ms windows); a same-tick recycle
    /// inside the verify window misreads as survival (S100-µs —
    /// never observed unsteered).
    #[cfg(target_arch = "x86_64")]
    fn held_probe_staging_failure(
        child: &mut std::process::Child,
        pidfile: &std::path::Path,
        what: &str,
        stage: &str,
        detail: &str,
    ) -> ! {
        let id = child.id() as libc::pid_t;
        // Prestage scan (best-effort record for post-body
        // verification — the body re-discovers independently).
        let mid = middleman_first_child(id)
            .and_then(|mid| proc_starttime(mid).ok()?.map(|tick| (mid, tick)));
        let writer = mid.and_then(|(mid, _)| {
            middleman_first_child(mid)
                .and_then(|born| proc_starttime(born).ok()?.map(|tick| (born, tick)))
        });
        // The published record may be corrupt (IR-004 fails the
        // read loud) — record failure as empty here; the body
        // surfaces it chained (its forensics still retire the
        // writer via /proc discovery).
        let strays = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            read_published_grandchild_strays(pidfile)
        }))
        .unwrap_or_default();
        // The real timeout body, under catch (it diverges by
        // design — a return is a retirement bug).
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            timeout_retire_hung_probe(child, pidfile, what);
        }));
        let body_text = match body {
            Err(payload) => payload
                .downcast::<String>()
                .map(|boxed| *boxed)
                .unwrap_or_else(|_| String::from("<non-string panic>")),
            Ok(_) => panic!("staging {stage} failed ({detail}): timeout body returned (BUG)"),
        };
        assert!(
            body_text.contains(what),
            "staging {stage} failed ({detail}): timeout body must headline `what`, got: {body_text}"
        );
        // Verify the retirement (each gap breaks the message
        // shape the injection tests require).
        if let Ok(None) = child.try_wait() {
            panic!("staging {stage} failed ({detail}): probe NOT reaped (BUG)");
        }
        assert!(
            std::fs::metadata(pidfile).is_err(),
            "staging {stage} failed ({detail}): pidfile NOT removed (BUG)"
        );
        for (pid, tick) in strays.iter().chain(mid.iter()).chain(writer.iter()) {
            assert!(
                proc_starttime(*pid) != Ok(Some(*tick)),
                "staging {stage} failed ({detail}): recorded fixture {pid}:{tick} NOT retired (BUG)"
            );
        }
        panic!(
            "staging {stage} failed ({detail}); fixtures retired via timeout body ({body_text}); prestage scan: mid={mid:?} writer={writer:?} strays={strays:?}"
        );
    }

    /// R14-009: drive one parent's timeout branch against a probe
    /// HELD after publication, then prove the published writer
    /// retired. The probe is SIGSTOPed once the rendezvous fills
    /// (a stopped probe is held exactly as a hung one is — the
    /// branch cannot distinguish them), and the parent's real
    /// timeout body ([`timeout_retire_hung_probe`], with the
    /// parent's real message) runs under `catch_unwind` — the
    /// suite survives the intended panic and verifies the
    /// retirement the branch owes. Birth is observed
    /// independently via /proc; the publication wait afterwards
    /// proves the record exists BEFORE the hold (a hold without
    /// publication would test nothing).
    /// R15-006: staging failures exit via
    /// [`held_probe_staging_failure`] (retire-all through the
    /// timeout body, then the staging detail — never a bare
    /// assert with live fixtures); per-stage timeouts are a
    /// parameter ([`HoldStageTimeouts`]).
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::too_many_arguments)]
    fn held_probe_timeout_retires_writer(
        probe_path: &str,
        probe_env: &str,
        abandon: bool,
        tag: &str,
        what: &str,
        timeouts: HoldStageTimeouts,
    ) {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-held-{tag}-{}.pid",
            std::process::id()
        ));
        // R14-003: claim before spawning (a preplant refuses
        // loud here, where no writer exists yet).
        claim_pidfile(&pidfile).expect("rendezvous pidfile claimed");
        let mut command = std::process::Command::new(exe);
        command
            .arg(probe_path)
            .arg("--exact")
            .env(probe_env, "1")
            .env(GRANDCHILD_PIDFILE_ENV, &pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if abandon {
            command.env(SUBREAPER_ABANDON_ENV, "1");
        }
        let mut child = command.spawn().expect("spawn held probe");
        // R12-005: pin before any wait (expiry identity gate).
        let id = child.id() as libc::pid_t;
        let staged = proc_starttime(id)
            .expect("probe stat readable")
            .expect("probe visible");
        // Birth, observed independently (mirrors the mid-flight
        // regression): middleman, then its firstborn, via /proc
        // task-children — never via the pidfile.
        let end = Instant::now() + timeouts.birth;
        let (mid, mid_tick, writer, writer_tick) = loop {
            if let Some(status) = child.try_wait().expect("probe wait") {
                if status.success() {
                    match collect_probe_output_bounded(&mut child, end, staged, &[]) {
                        Some((_, err)) => {
                            let err = String::from_utf8_lossy(&err);
                            assert!(
                                err.contains("skip: seccomp unavailable"),
                                "unexpected probe success must explain itself, got: {err}"
                            );
                            // R15-006: the explainer assert above stays
                            // bare — it fires only when output EOF'd
                            // (no live descendants hold the pipes),
                            // and the skip removes the pidfile itself.
                            eprintln!("skip: seccomp unavailable for the held {tag} probe");
                            let _ = std::fs::remove_file(&pidfile);
                            return;
                        }
                        None => panic!("skip-path probe must EOF its output, got expiry"),
                    }
                }
                held_probe_staging_failure(
                    &mut child,
                    &pidfile,
                    what,
                    "birth",
                    &format!("probe exited {status} before grandchild birth"),
                );
            }
            if Instant::now() >= end {
                held_probe_staging_failure(
                    &mut child,
                    &pidfile,
                    what,
                    "birth",
                    &format!("grandchild never born ({:?})", timeouts.birth),
                );
            }
            if let Some(mid) = middleman_first_child(id) {
                if let (Ok(Some(mtick)), Some(born)) =
                    (proc_starttime(mid), middleman_first_child(mid))
                {
                    if let Ok(Some(tick)) = proc_starttime(born) {
                        break (mid, mtick, born, tick);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // The birth record must land BEFORE the hold (a hold
        // without publication tests nothing): the runner's poll
        // slices publish within ~50ms of birth; 5s is generous.
        let published = Instant::now() + timeouts.publication;
        loop {
            // R15-006: the deadline binds BEFORE arrival (a fill
            // landing exactly on expiry reports the timeout —
            // deterministic under injection, equivalent under
            // production bounds).
            if Instant::now() >= published {
                held_probe_staging_failure(
                    &mut child,
                    &pidfile,
                    what,
                    "publication",
                    "birth never published before the hold",
                );
            }
            if child.try_wait().expect("probe wait").is_some() {
                held_probe_staging_failure(
                    &mut child,
                    &pidfile,
                    what,
                    "publication",
                    "probe completed before the hold",
                );
            }
            let filled = std::fs::read_to_string(&pidfile)
                .map(|text| !text.trim().is_empty())
                .unwrap_or(false);
            if filled {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let strays = read_published_grandchild_strays(&pidfile);
        assert_eq!(
            strays,
            vec![(writer, writer_tick)],
            "published birth must name the observed grandchild"
        );
        // Hold the probe after publication: SIGSTOP, then prove
        // the stop landed (state T) — a running probe would race
        // the timeout instead of holding through it.
        // SAFETY: SIGSTOP to our own pinned probe child.
        if unsafe { libc::kill(id, libc::SIGSTOP) } != 0 {
            let errno = std::io::Error::last_os_error();
            held_probe_staging_failure(
                &mut child,
                &pidfile,
                what,
                "stop",
                &format!("probe SIGSTOP refused ({errno})"),
            );
        }
        let stopped = Instant::now() + timeouts.stop;
        loop {
            // R15-006: the deadline binds BEFORE arrival (see
            // the publication poll — deterministic under
            // injection).
            if Instant::now() >= stopped {
                held_probe_staging_failure(
                    &mut child,
                    &pidfile,
                    what,
                    "stop",
                    "probe never stopped after SIGSTOP",
                );
            }
            let state = std::fs::read_to_string(format!("/proc/{id}/stat"))
                .ok()
                .and_then(|row| {
                    row.rsplit_once(") ")
                        .and_then(|(_, after)| after.split_whitespace().next().map(str::to_string))
                });
            if state.as_deref() == Some("T") {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // The parent's real timeout body, under catch_unwind: the
        // intended panic must name the parent's timeout (proving
        // the branch ran), and the suite survives to verify the
        // retirement below.
        let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            timeout_retire_hung_probe(&mut child, &pidfile, what)
        }));
        match fired {
            Err(payload) => {
                let text = payload
                    .downcast::<String>()
                    .map(|boxed| *boxed)
                    .unwrap_or_else(|_| String::from("<non-string panic>"));
                assert!(
                    text.contains(what),
                    "timeout branch must panic the parent message, got: {text}"
                );
            }
            Ok(_) => {
                panic!("timeout branch must diverge (it returned)");
            }
        }
        // The probe itself is reaped by the branch (SIGKILL lands
        // on a stopped task): prove it before the writer asserts.
        use std::os::unix::process::ExitStatusExt as _;
        let status = child.try_wait().expect("probe reap").expect("probe reaped");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "held probe must die by the timeout SIGKILL, got {status}"
        );
        // The published writer — independently grouped, beyond the
        // killpg — must retire anyway (the requirement). Observe
        // before cleanup (R12-014): capture the evidence first,
        // retire any remainder so even RED runs stay clean, then
        // assert.
        let writer_gone = await_proc_gone_reaping(writer, writer_tick, Duration::from_secs(2));
        // R15-008: the hygiene outcome travels with the report.
        let note = if !writer_gone {
            let hygiene = retire_known_stray_best_effort(writer, writer_tick);
            writer_retire_note(writer, writer_tick, hygiene)
        } else {
            String::new()
        };
        assert!(
            writer_gone,
            "parent timeout must retire the published writer ({tag}){note}"
        );
        // Hygiene (not the requirement): the orphaned middleman is
        // mid-preflight when the probe dies and self-terminates on
        // its report to the dead reader — but a lingerer must not
        // escape the suite. Poll it gone (tick-pinned, never a
        // numeric kill), retire a straggler best-effort, then
        // require it gone. No group-ESRCH assert here: the
        // middleman legitimately outlives the timeout branch.
        let mid_end = Instant::now() + Duration::from_secs(15);
        loop {
            if proc_starttime(mid) != Ok(Some(mid_tick)) {
                break;
            }
            if Instant::now() >= mid_end {
                // R15-008: audited, unchanged — the assert below
                // names {mid} and fires only on proven survival,
                // so no stranded fixture goes nameless here.
                retire_known_stray_best_effort(mid, mid_tick);
                assert!(
                    proc_starttime(mid) != Ok(Some(mid_tick)),
                    "orphaned middleman {mid} lingered past the hold test ({tag})"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// R14-009: the subreaper parent's timeout retires the
    /// published writer (held-probe driver, normal probe).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn held_subreaper_probe_timeout_retires_published_writer() {
        held_probe_timeout_retires_writer(
            SUBREAPER_PROBE_PATH,
            SUBREAPER_PROBE_ENV,
            false,
            "subreaper",
            "subreaper probe hung past 150s",
            HoldStageTimeouts::PRODUCTION,
        );
    }

    /// R14-009: the abandon parent's timeout retires the published
    /// writer (held-probe driver, abandon probe).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn held_abandon_probe_timeout_retires_published_writer() {
        held_probe_timeout_retires_writer(
            SUBREAPER_PROBE_PATH,
            SUBREAPER_PROBE_ENV,
            true,
            "abandon",
            "abandoning probe hung past 60s",
            HoldStageTimeouts::PRODUCTION,
        );
    }

    /// R14-009: the guard parent's timeout retires the published
    /// writer (held-probe driver, guard probe — birth-armed by
    /// the R14-009 gate extension).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn held_guard_probe_timeout_retires_published_writer() {
        held_probe_timeout_retires_writer(
            GUARD_PROBE_PATH,
            GUARD_PROBE_ENV,
            false,
            "guard",
            "adopting-guard probe hung past 60s",
            HoldStageTimeouts::PRODUCTION,
        );
    }

    /// R15-006: run the held-probe driver with injected staging
    /// timeouts and require retirement-before-report: the panic
    /// must name the forced stage, prove routing through the
    /// timeout body, and chain the parent's timeout (the body's
    /// own proof it ran — plus the helper's internal reaped/
    /// removed/retired verification, whose failures break this
    /// message shape).
    #[cfg(target_arch = "x86_64")]
    fn held_probe_staging_injection(timeouts: HoldStageTimeouts, tag: &str, stage: &str) {
        let what = "subreaper probe hung past 150s";
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            held_probe_timeout_retires_writer(
                SUBREAPER_PROBE_PATH,
                SUBREAPER_PROBE_ENV,
                false,
                tag,
                what,
                timeouts,
            );
        }));
        let text = match outcome {
            Err(payload) => payload
                .downcast::<String>()
                .map(|boxed| *boxed)
                .unwrap_or_else(|_| String::from("<non-string panic>")),
            Ok(_) => panic!("{tag}: injection must force the staging failure"),
        };
        assert!(
            text.contains(stage),
            "{tag}: stage discrimination, got: {text}"
        );
        assert!(
            text.contains("retired via timeout"),
            "{tag}: routing proof, got: {text}"
        );
        assert!(text.contains(what), "{tag}: body-ran proof, got: {text}");
    }

    /// R15-006: birth-stage injection — a 0ns birth deadline
    /// forces the staging failure mid-staging (probe live, tree
    /// unborn); retirement must precede the report.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn held_probe_birth_timeout_retires_before_report() {
        use std::time::Duration;
        held_probe_staging_injection(
            HoldStageTimeouts {
                birth: Duration::ZERO,
                ..HoldStageTimeouts::PRODUCTION
            },
            "r15006-birth",
            "grandchild never born",
        );
    }

    /// R15-006: publication-stage injection — birth succeeds but
    /// the 0ns publication deadline forces the staging failure
    /// (probe + writer live); retirement must precede the
    /// report.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn held_probe_publication_timeout_retires_before_report() {
        use std::time::Duration;
        held_probe_staging_injection(
            HoldStageTimeouts {
                publication: Duration::ZERO,
                ..HoldStageTimeouts::PRODUCTION
            },
            "r15006-publish",
            "birth never published before the hold",
        );
    }

    /// R15-006: stop-stage injection — the probe SIGSTOPs, then
    /// the 0ns stop deadline forces the staging failure (a stop
    /// that never lands must not park the probe stopped
    /// forever); retirement must precede the report.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn held_probe_stop_timeout_retires_before_report() {
        use std::time::Duration;
        held_probe_staging_injection(
            HoldStageTimeouts {
                stop: Duration::ZERO,
                ..HoldStageTimeouts::PRODUCTION
            },
            "r15006-stop",
            "probe never stopped after SIGSTOP",
        );
    }

    /// R15-002: a probe stopped before its birth scan can never
    /// publish — the timeout must still retire the unpublished
    /// writer. Birth discovery polls in ≤20ms slices; a probe
    /// death after the middleman forks but before the next slice
    /// leaves no record, and the middleman group is independent
    /// of the probe group, so killpg-plus-empty-strays strands
    /// the parked writer. The EOF self-release does NOT save
    /// the read-denying specs (the rendezvous flows): the
    /// writer's release-read gets EPERM, never EOF, and parks in
    /// pause() with all parents dead. Staging is deterministic:
    /// SIGSTOP lands at middleman sight (writer unborn — the
    /// middleman needs exec+fork after that), so every
    /// pre-stop slice saw nothing and no post-stop slice runs;
    /// the empty-pidfile assert proves the hole staged (never
    /// vacuous). Pre-fix the writer strands parked (RED);
    /// post-fix the timeout's descendant forensics retire it
    /// (GREEN).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn stopped_probe_unpublished_writer_still_retires() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-r15002a-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        claim_pidfile(&pidfile).expect("rendezvous pidfile claimed");
        let mut child = std::process::Command::new(exe)
            .arg(SUBREAPER_PROBE_PATH)
            .arg("--exact")
            .env(SUBREAPER_PROBE_ENV, "1")
            .env(GRANDCHILD_PIDFILE_ENV, &pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn subreaper probe");
        let id = child.id() as libc::pid_t;
        // Middleman sight (test-side, independent of the
        // probe's own scan), then SIGSTOP at once — the writer
        // is unborn (middleman needs exec+fork first), so no
        // discovery slice could have published.
        let end = Instant::now() + Duration::from_secs(60);
        let mid = loop {
            assert!(
                child.try_wait().expect("probe wait").is_none(),
                "probe completed before middleman birth (fixture broken)"
            );
            assert!(Instant::now() < end, "middleman never born (60s)");
            if let Some(mid) = middleman_first_child(id) {
                break mid;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        // SAFETY: SIGSTOP to our own probe child.
        assert_eq!(unsafe { libc::kill(id, libc::SIGSTOP) }, 0, "probe stop");
        // Writer birth (the middleman runs unstopped).
        let end = Instant::now() + Duration::from_secs(60);
        let (writer, writer_tick) = loop {
            if let Some(born) = middleman_first_child(mid) {
                if let Ok(Some(tick)) = proc_starttime(born) {
                    break (born, tick);
                }
            }
            assert!(Instant::now() < end, "writer never born (60s)");
            std::thread::sleep(Duration::from_millis(1));
        };
        let mid_tick = proc_starttime(mid)
            .expect("middleman stat readable")
            .expect("middleman visible");
        // The hole staged: the stopped probe published nothing.
        let record = std::fs::read_to_string(&pidfile).expect("pidfile readable");
        assert!(
            record.trim().is_empty(),
            "stopped probe must publish nothing, got: {record:?}"
        );
        let what = "r15002 stopped probe timeout";
        let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            timeout_retire_hung_probe(&mut child, &pidfile, what)
        }));
        let text = match fired {
            Err(payload) => payload
                .downcast::<String>()
                .map(|boxed| *boxed)
                .unwrap_or_else(|_| String::from("<non-string panic>")),
            Ok(_) => panic!("timeout branch must diverge (it returned)"),
        };
        // Observe before cleanup: the writer must be gone
        // (bounded — the cascade either retires it fast or
        // never), then loud cleanup of whatever remains
        // either way, then assert.
        let end = Instant::now() + Duration::from_secs(30);
        let writer_gone = loop {
            if proc_starttime(writer) != Ok(Some(writer_tick)) {
                break true;
            }
            if Instant::now() >= end {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // RED-path hygiene: retire the stranded pair by
        // tick-pinned identity (no blind signals).
        if proc_starttime(writer) == Ok(Some(writer_tick)) {
            // SAFETY: tick-pinned staged writer.
            unsafe { libc::kill(writer, libc::SIGKILL) };
        }
        if proc_starttime(mid) == Ok(Some(mid_tick)) {
            // SAFETY: tick-pinned staged middleman.
            unsafe { libc::kill(mid, libc::SIGKILL) };
        }
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let writer_down = proc_starttime(writer) != Ok(Some(writer_tick));
            let mid_down = proc_starttime(mid) != Ok(Some(mid_tick));
            if writer_down && mid_down {
                break;
            }
            assert!(Instant::now() < end, "stranded pair must die in hygiene");
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = std::fs::remove_file(&pidfile);
        assert!(
            text.contains(what),
            "timeout branch must panic the parent message, got: {text}"
        );
        assert!(
            writer_gone,
            "timeout must retire the unpublished writer (stopped probe)"
        );
    }

    /// R11-005: starttime of the CURRENT holder of `pid`
    /// (field 22 of /proc/PID/stat). Ok(None) is proven
    /// absence (ENOENT only); Err is unreadable-or-unparseable
    /// (never absence — our own tasks stay stat-visible under
    /// every hidepid level, so an unreadable stat is someone
    /// else's problem, not a gone task). The await's stat gate
    /// and the retire's holder check share this one parser.
    #[cfg(target_arch = "x86_64")]
    fn proc_starttime(pid: libc::pid_t) -> Result<Option<u64>, String> {
        let row = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(row) => row,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("task {pid} stat unreadable: {error}")),
        };
        match (|| {
            let after_comm = row.rsplit_once(") ")?.1;
            after_comm.split_whitespace().nth(19)?.parse().ok()
        })() {
            Some(starttime) => Ok(Some(starttime)),
            None => Err(format!("task {pid} stat unparseable")),
        }
    }

    /// R11-005: a zombie stand-in holding the awaited number
    /// must be DETECTED (starttime mismatch) and SPARED (never
    /// reaped by us). Our own exited-unreaped child X keeps its
    /// number; awaiting X's number with a DIFFERENT expected
    /// starttime returns true (the awaited task is gone —
    /// otherwise X's number could not host X) while X stays
    /// unreaped for its owner. Pre-fix the blind numeric
    /// waitpid reaps X (RED); post-fix the stat gate spares it.
    /// Deterministic: no timing, no reuse control — X is a
    /// stable zombie throughout.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn awaited_number_stand_in_spared() {
        use std::time::{Duration, Instant};
        let child = std::process::Command::new("true")
            .spawn()
            .expect("stand-in spawns");
        let pid = child.id() as libc::pid_t;
        // R12-016: custody before the observing setup — a
        // setup panic must not leak the stand-in.
        let mut guard = ChildGuard::new(pid);
        // Leave it unreaped (our zombie); wait for the Z state
        // so the pre-fix blind waitpid would reap it.
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|row| {
                    row.rsplit_once(") ")
                        .and_then(|(_, rest)| rest.split_whitespace().next().map(str::to_string))
                });
            if state.as_deref() == Some("Z") {
                break;
            }
            assert!(Instant::now() < end, "stand-in never zombied");
            std::thread::sleep(Duration::from_millis(10));
        }
        let real = proc_starttime(pid)
            .expect("zombie stat readable")
            .expect("zombie present");
        assert!(await_proc_gone_reaping(
            pid,
            real.wrapping_add(1),
            Duration::from_secs(5)
        ));
        // Still ours and still unreaped: WE reap it now, proving
        // the await never touched it.
        let mut status = 0;
        // SAFETY: our own child, first wait.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(got, pid, "stand-in must survive the await unreaped");
        // Survival proved and reaped by us — disarm so the
        // drop stays silent.
        guard.disarm();
    }

    /// R11-005: the stat gate must not break the intended case —
    /// our own zombie with the EXPECTED starttime is still
    /// reaped by the wait (true, and already reaped after).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn awaited_owned_zombie_still_reaped() {
        use std::time::{Duration, Instant};
        let child = std::process::Command::new("true")
            .spawn()
            .expect("zombie spawns");
        let pid = child.id() as libc::pid_t;
        // R12-016: custody before the observing setup — a
        // setup panic must not leak the zombie.
        let mut guard = ChildGuard::new(pid);
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(proc_starttime(pid), Ok(Some(_))) {
                break;
            }
            assert!(Instant::now() < end, "child stat never readable");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Settle into the zombie state (spawned `true` exits at
        // once; the poll absorbs loader scheduling).
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|row| {
                    row.rsplit_once(") ")
                        .and_then(|(_, rest)| rest.split_whitespace().next().map(str::to_string))
                });
            if state.as_deref() == Some("Z") {
                break;
            }
            assert!(Instant::now() < end, "child never zombied");
            std::thread::sleep(Duration::from_millis(10));
        }
        let real = proc_starttime(pid)
            .expect("zombie stat readable")
            .expect("zombie present");
        assert!(await_proc_gone_reaping(pid, real, Duration::from_secs(5)));
        // Already reaped: nothing left for us.
        let mut status = 0;
        // SAFETY: our own (reaped) child; ECHILD expected.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            got < 0,
            "owned zombie must be reaped by the await, got {got}"
        );
        // The await's reap proved — disarm so the drop stays
        // silent over the discharged number.
        guard.disarm();
    }

    /// IR1 (internal review round 1): the Err arm must never
    /// wait — an unreadable stat proves nothing, and a blind
    /// wait could reap an unrelated same-number child. Stable
    /// zombie X + stubbed gate (Err once, then None): the
    /// await returns true (gone) while X stays unreaped for
    /// its owner. Pre-fix the Err fall-through reaps X (RED).
    /// Deterministic: the stub drives the gate, no timing.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn awaited_err_arm_never_waits() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        // SAFETY: child exits at once (async-signal-safe).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe { libc::_exit(45) };
        }
        // R12-016: custody before the observing setup — a
        // setup panic must not leak the zombie.
        let mut guard = ChildGuard::new(pid);
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while proc_state(pid) != Some('Z') {
            assert!(
                std::time::Instant::now() < end,
                "setup child never reached zombie state"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let real = proc_starttime(pid)
            .expect("zombie stat readable")
            .expect("zombie present");
        let calls = AtomicUsize::new(0);
        let gate = |observed: libc::pid_t| {
            assert_eq!(observed, pid, "gate observes the awaited pid");
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err("injected unreadable stat".to_string())
            } else {
                Ok(None)
            }
        };
        assert!(await_proc_gone_reaping_with(
            pid,
            real,
            Duration::from_secs(5),
            gate
        ));
        // Still ours and still unreaped: WE reap it now, proving
        // the Err arm never waited.
        let mut status = 0;
        // SAFETY: our own child, first wait.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(got, pid, "zombie must survive the Err arm unreaped");
        // Survival proved and reaped by us — disarm so the
        // drop stays silent.
        guard.disarm();
    }

    /// R11-005: an absent number returns true immediately
    /// (nothing to reap, no hang). The pid exceeds pid_max, so
    /// no task can ever hold it.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn awaited_absent_number_true() {
        use std::time::{Duration, Instant};
        let started = Instant::now();
        assert!(await_proc_gone_reaping(
            1073741824,
            1234,
            Duration::from_secs(5)
        ));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "absent number must answer at once, took {:?}",
            started.elapsed()
        );
    }

    /// S140-round9: the middleman must not depend on inherited
    /// multithreaded state: with the fork rendezvous lock HELD by
    /// another thread across the whole middleman run, the run must
    /// still complete. Pre-fix the raw-forked middleman inherited
    /// the locked mutex and deadlocked in `preflight()` (RED: the
    /// guard fires); post-fix the middleman execs a fresh image
    /// before any lock-using Rust code. The fast S110 spec keeps
    /// the hold short (~1s green); the holder thread times out
    /// alone so a RED run costs the guard, not the suite.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn middleman_survives_held_fork_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        let held = std::sync::Arc::new(AtomicBool::new(false));
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let held_t = held.clone();
        let done_t = done.clone();
        let holder = std::thread::spawn(move || {
            // SAFETY: the rendezvous child _exits immediately; the
            // parent holds the lock until the middleman run ends.
            unsafe {
                super::super::fork::fork_guarded(
                    (-1, -1, -1),
                    |pid| {
                        held_t.store(true, Ordering::SeqCst);
                        let end = Instant::now() + Duration::from_secs(20);
                        while !done_t.load(Ordering::SeqCst) && Instant::now() < end {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        // Reap the rendezvous child (ours, exited).
                        // (Inside the outer unsafe block: no second
                        // block needed.) SAFETY: valid status
                        // out-pointer.
                        let mut status = 0;
                        libc::waitpid(pid, &mut status, 0);
                    },
                    || libc::_exit(0),
                )
            };
        });
        // Wait for the hold (fail loud if it never arrives): from
        // here the lock is GUARANTEED held across the middleman
        // run — the deadlock is deterministic, not a window.
        let end = Instant::now() + Duration::from_secs(10);
        while !held.load(Ordering::SeqCst) {
            assert!(Instant::now() < end, "holder thread never took the lock");
            std::thread::sleep(Duration::from_millis(10));
        }
        let outcome = run_preflight_middleman("write-traceme-eperm", Duration::from_secs(8));
        done.store(true, Ordering::SeqCst);
        let _ = holder.join();
        if outcome.code == 3 {
            eprintln!("skip: seccomp unavailable for the held-lock probe");
            return;
        }
        assert_eq!(
            outcome.code, 21,
            "middleman must complete under a held fork lock, got {}",
            outcome.code
        );
    }

    /// S139-round9: an EINTR-spamming write filter must expire
    /// the release bounded: the middleman refuses (21) with the
    /// deadline named, having retired its own child — never spins.
    /// Pre-fix the release write retries EINTR forever and the
    /// guard fires (RED). Cleanup runs before the assertions so a
    /// failure never leaks the grandchild.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn eintr_release_write_expires_bounded() {
        use std::time::Duration;
        let outcome = run_preflight_middleman("write-eintr", Duration::from_secs(12));
        if outcome.code == 3 {
            eprintln!("skip: seccomp unavailable for the EINTR probe");
            return;
        }
        let cleaned = match outcome.grandchild {
            GrandchildState::Live(pid, started) => retire_reported_grandchild(pid, started),
            GrandchildState::None => false,
        };
        assert_eq!(
            outcome.code, 21,
            "EINTR-spammed release must refuse, got exit {}",
            outcome.code
        );
        assert_eq!(
            outcome.err, "preflight release refused: EINTR retry deadline exceeded",
            "expiry must name its deadline"
        );
        assert!(
            !cleaned && matches!(outcome.grandchild, GrandchildState::None),
            "expired release must retire its own child, got: {:?}",
            outcome.grandchild
        );
    }

    /// R11-017: the guard-test gate — a caught panic counts ONLY
    /// as the intended pre-report guard timeout (full-message
    /// pin, EXPECTED_BARRIER_TIMEOUT precedent): the exact
    /// pre-report guard text with this run's guard, group, and
    /// a true retirement verdict. Any other panic (exit/report
    /// asserts from a bogus probe path, poll/wait failures, ...)
    /// fails loud here instead of passing vacuously below.
    /// Both guard regressions (R10-011 and the R11-013 probe)
    /// share it.
    #[cfg(target_arch = "x86_64")]
    fn assert_guard_pre_report_timeout(
        err: Box<dyn std::any::Any + Send>,
        guard: std::time::Duration,
        group: libc::pid_t,
    ) {
        let expected = format!(
            "middleman hung past {guard:?} (deadlock under denial; group {group} retired: true, no report received)"
        );
        match err.downcast::<String>() {
            Ok(text) => assert_eq!(
                *text, expected,
                "caught panic must be the intended pre-report guard timeout"
            ),
            Err(_) => panic!(
                "caught panic must be the intended pre-report guard timeout (non-String payload)"
            ),
        }
    }

    /// R11-017: true when any task of `mid` currently has a
    /// child (the `children` file is PER-THREAD and the
    /// preflight fork runs on a libtest thread — every task's
    /// file is scanned, not just the leader's). Shared by the
    /// guard regressions' birth watchers.
    #[cfg(target_arch = "x86_64")]
    fn middleman_has_child(mid: i32) -> bool {
        if mid <= 1 {
            return false;
        }
        let tasks = format!("/proc/{mid}/task");
        let Ok(entries) = std::fs::read_dir(&tasks) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path().join("children");
            if let Ok(list) = std::fs::read_to_string(&path) {
                if list.split_whitespace().next().is_some() {
                    return true;
                }
            }
        }
        false
    }

    /// R14-008: the firstborn pid of `mid` (if any), via the same
    /// per-task `children` scan as [`middleman_has_child`]. The
    /// mid-flight regression and the runner's birth publication
    /// share this observer (birth seen through one lens, never
    /// two divergent scans).
    #[cfg(target_arch = "x86_64")]
    fn middleman_first_child(mid: i32) -> Option<libc::pid_t> {
        if mid <= 1 {
            return None;
        }
        let tasks = format!("/proc/{mid}/task");
        let Ok(entries) = std::fs::read_dir(&tasks) else {
            return None;
        };
        for entry in entries.flatten() {
            let path = entry.path().join("children");
            if let Ok(list) = std::fs::read_to_string(&path) {
                if let Some(word) = list.split_whitespace().next() {
                    if let Ok(pid) = word.parse::<libc::pid_t>() {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    /// R10-011: the infinite-retry SHAPE must die bounded with
    /// BOTH generations provably retired. A 2s guard (far below
    /// production's 5s EINTR deadline) fires while the
    /// middleman still spins its release write with the
    /// grandchild born and barrier-blocked. The guard retires
    /// the whole process group before panicking (the failure
    /// stays loud, never a leak); the test then proves
    /// retirement INDEPENDENTLY (killpg probe to ESRCH — a
    /// zombie still holds the group, so emptiness also proves
    /// init reaped the orphan). Portability note: on kernel
    /// 7.2.13/Yama-0 the orphan exits by itself within 0.4s
    /// even under a middleman-only kill (no T state ever
    /// observed), so this pins the guarantee rather than a
    /// manifesting leak — the group kill makes both-generation
    /// retirement unconditional instead of kernel-dependent.
    /// R11-017: the caught panic must be the intended
    /// pre-report guard timeout (full-message gate — a bogus
    /// probe path's exit/report panic fails here, not below),
    /// and grandchild birth must be proven by watcher (a
    /// group can only retire generations that existed).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn eintr_spin_guard_retires_both_generations() {
        use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
        use std::time::{Duration, Instant};
        let pgid = AtomicI32::new(-1);
        let born = AtomicBool::new(false);
        let done = AtomicBool::new(false);
        let started = Instant::now();
        let outcome = std::thread::scope(|scope| {
            scope.spawn(|| {
                // Birth watcher: the 2s guard spins with the
                // grandchild born and barrier-parked — stable
                // for observation, not a fleeting window.
                while !done.load(Ordering::SeqCst) {
                    if middleman_has_child(pgid.load(Ordering::SeqCst)) {
                        born.store(true, Ordering::SeqCst);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
            // The runner holds only raw descriptors and locals
            // across this boundary (no locks, no aliasing
            // invariants) — catching its guard panic is sound.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_preflight_middleman_observed(
                    "write-eintr",
                    Duration::from_secs(2),
                    &pgid,
                    PROBE_TEST_PATH,
                )
            }));
            done.store(true, Ordering::SeqCst);
            outcome
        });
        let elapsed = started.elapsed();
        let group = pgid.load(Ordering::SeqCst);
        assert!(
            group > 1,
            "runner must publish the middleman pgid, got {group}"
        );
        match outcome {
            Err(err) => assert_guard_pre_report_timeout(err, Duration::from_secs(2), group),
            Ok(reported) => panic!(
                "2s guard must fire mid-EINTR-spin, got exit {}",
                reported.code
            ),
        }
        assert!(
            born.load(Ordering::SeqCst),
            "grandchild birth never observed before the guard fired"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "guard failure must stay bounded, took {elapsed:?}"
        );
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: signal 0 probes existence only.
            let probed = unsafe { libc::killpg(group, 0) };
            if probed < 0 {
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                assert_eq!(
                    errno,
                    libc::ESRCH,
                    "group probe must fail ESRCH-only, got {errno}"
                );
                return;
            }
            assert!(
                Instant::now() < end,
                "process group {group} survived the guard retirement"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// R11-017: a nonexistent probe path must FAIL the guard
    /// regression's gates (not pass vacuously): the middleman
    /// runs zero tests and the runner's exit/report assertion
    /// panics — that panic is not the guard timeout, and no
    /// grandchild is ever born (structurally absent — no
    /// preflight runs without the probe — so the birth
    /// assertion is deterministic, not a race). Both gates must
    /// reject.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn bogus_probe_path_rejected_by_guard_gates() {
        use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
        use std::time::Duration;
        let pgid = AtomicI32::new(-1);
        let born = AtomicBool::new(false);
        let done = AtomicBool::new(false);
        let outcome = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::SeqCst) {
                    if middleman_has_child(pgid.load(Ordering::SeqCst)) {
                        born.store(true, Ordering::SeqCst);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_preflight_middleman_observed(
                    "write-eintr",
                    Duration::from_secs(2),
                    &pgid,
                    "nonexistent::probe::path",
                )
            }));
            done.store(true, Ordering::SeqCst);
            outcome
        });
        // The runner panics (exit/report mismatch on zero
        // tests)...
        let err = match outcome {
            Err(err) => err,
            Ok(reported) => panic!(
                "bogus probe path must panic the runner, got exit {}",
                reported.code
            ),
        };
        // ...but NOT with the guard timeout (the
        // classification gate rejects)...
        let gate = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_guard_pre_report_timeout(
                err,
                Duration::from_secs(2),
                pgid.load(Ordering::SeqCst),
            )
        }));
        assert!(
            gate.is_err(),
            "nonexistent probe path must fail the classification gate"
        );
        // ...and no grandchild is ever born (the birth gate
        // rejects).
        assert!(
            !born.load(Ordering::SeqCst),
            "no grandchild may exist without the probe"
        );
    }

    /// R11-013: pre-report guard retirement must REAP the
    /// adopted grandchild, not just kill it. When the runner
    /// adopts orphans (subreaper or PID-1 runner) the dead
    /// grandchild is the runner's own zombie: kill-only
    /// retirement leaves the group observable and the R10-011
    /// regression expires. The parent spawns a fresh probe
    /// process (a confined subreaper — never the suite binary)
    /// and requires exit success bounded AND one passed test
    /// (a renamed probe path fails here instead of passing
    /// vacuously on zero tests). On timeout the parent retires
    /// the probe's whole process group before failing loud.
    /// R11-014: output collection runs through the shared
    /// bounded helper under this same deadline (both parents
    /// changed together).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn guard_retires_adopted_grandchild() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        // R13-005: the probe publishes each reported grandchild
        // here; the parent's expiry retires it if the probe dies
        // between birth and retirement.
        let pidfile = std::env::temp_dir().join(format!(
            "scopebase-grandchild-guard-{}.pid",
            std::process::id()
        ));
        // R14-003: claim before spawning (a preplant refuses
        // loud here, where no writer exists yet).
        claim_pidfile(&pidfile).expect("rendezvous pidfile claimed");
        let mut child = std::process::Command::new(exe)
            .arg(GUARD_PROBE_PATH)
            .arg("--exact")
            .env(GUARD_PROBE_ENV, "1")
            .env(GRANDCHILD_PIDFILE_ENV, &pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn adopting-guard probe");
        // R12-005: pin before any wait (expiry identity gate).
        let staged = proc_starttime(child.id() as libc::pid_t)
            .expect("probe stat readable")
            .expect("probe visible");
        let end = Instant::now() + Duration::from_secs(60);
        loop {
            match child.try_wait().expect("probe wait") {
                Some(status) => {
                    // R11-014: bounded collection under the SAME
                    // deadline — wait_with_output would wait for
                    // EOF past it whenever a descendant outlives
                    // the probe holding the pipes.
                    // R13-005: the probe's published grandchild (if
                    // any) rides as expiry strays — a writer the
                    // probe died without retiring still retires.
                    let strays = read_published_grandchild_strays(&pidfile);
                    match collect_probe_output_bounded(&mut child, end, staged, &strays) {
                        Some((stdout, stderr)) => {
                            assert!(
                                status.success(),
                                "adopting-guard probe must exit success, got {status}: {}",
                                String::from_utf8_lossy(&stderr)
                            );
                            assert!(
                                String::from_utf8_lossy(&stdout).contains("1 passed"),
                                "probe must run its one test (path exact)"
                            );
                        }
                        None => panic!(
                            "adopting-guard probe output collection expired \
                             (probe exited {status}; group retired)"
                        ),
                    }
                    let _ = std::fs::remove_file(&pidfile);
                    return;
                }
                None => {}
            }
            if Instant::now() >= end {
                // R14-009: the shared timeout body (kills the
                // group + probe, retires published strays).
                timeout_retire_hung_probe(
                    &mut child,
                    &pidfile,
                    "adopting-guard probe hung past 60s",
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// R12-007: collection expiry must REAP the adopted group,
    /// not just kill it. When the runner adopts orphans
    /// (subreaper or PID-1 runner) the dead writer is the
    /// runner's own zombie: a single-pass drain runs µs after
    /// killpg while deaths land ~50µs later, so kill-only
    /// retirement leaves the group observable. The parent spawns
    /// a fresh probe process (a confined subreaper — never the
    /// suite binary) and requires exit success bounded AND one
    /// passed test (a renamed probe path fails here instead of
    /// passing vacuously on zero tests). On timeout the parent
    /// retires the probe's whole process group before failing
    /// loud.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn expiry_retires_adopted_group() {
        use std::time::{Duration, Instant};
        let exe = std::env::current_exe().expect("probe test binary path");
        let mut child = std::process::Command::new(exe)
            .arg(EXPIRY_PROBE_PATH)
            .arg("--exact")
            .env(EXPIRY_PROBE_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn expiry-adopting probe");
        // R12-005: pin before any wait (expiry identity gate).
        let staged = proc_starttime(child.id() as libc::pid_t)
            .expect("probe stat readable")
            .expect("probe visible");
        let end = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().expect("probe wait") {
                // R11-014: bounded collection under the SAME
                // deadline — wait_with_output would wait for
                // EOF past it whenever a descendant outlives
                // the probe holding the pipes.
                match collect_probe_output_bounded(&mut child, end, staged, &[]) {
                    Some((stdout, stderr)) => {
                        assert!(
                            status.success(),
                            "expiry-adopting probe must exit success, got {status}: {}",
                            String::from_utf8_lossy(&stderr)
                        );
                        assert!(
                            String::from_utf8_lossy(&stdout).contains("1 passed"),
                            "probe must run its one test (path exact)"
                        );
                    }
                    None => panic!(
                        "expiry-adopting probe output collection expired \
                         (probe exited {status}; group retired)"
                    ),
                }
                return;
            }
            if Instant::now() >= end {
                // SAFETY: signal-only to the probe's own group,
                // then the probe itself; errors ignored.
                let id = child.id() as libc::pid_t;
                unsafe {
                    libc::killpg(id, libc::SIGKILL);
                    libc::kill(id, libc::SIGKILL);
                }
                let _ = child.wait();
                panic!("expiry-adopting probe hung past 60s");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// R11-013: the group drain must touch nothing outside the
    /// retired group. A child in the suite's own group survives
    /// a retirement pass over a dead foreign pgid: still ours
    /// to reap (a stealing drain would ECHILD here) and still
    /// exited-normally (a group-wide signal would show
    /// signaled). Pins the waitpid(-pgid) filter.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn group_drain_steals_no_foreign_child() {
        // SAFETY: the child exits at once; the parent below
        // reaps it.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        assert!(
            retire_hung_middleman_group(libc::pid_t::MAX),
            "empty foreign pgid must probe retired"
        );
        let mut status = 0;
        // SAFETY: our own unwaited-for child; it exits at once
        // so the blocking reap cannot hang.
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(got, pid, "drain must not reap outside the group");
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "drain must not signal outside the group, got {status}"
        );
    }

    /// S119-round8: a pin-less guard drop under wait-denial must
    /// signal NOTHING — observation failure stays unresolved.
    /// Confined: the wait4→EPERM filter lives only in the forked
    /// child, which drops a pin-less armed guard over its OWN pid
    /// (the round-7 self-PID shape) and must survive to report.
    /// Pre-fix the EPERM wait reads as "not gone" and the drop
    /// SIGKILLs the child itself (RED).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pinless_drop_under_wait_denial_signals_nothing() {
        use super::super::seccomp::{install_deny_one, DenyAction};
        use std::time::{Duration, Instant};
        // SAFETY: the child installs a wait-denying filter, drops
        // a pin-less self guard, and reports survival via _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "unit fork failed");
        if pid == 0 {
            if install_deny_one(libc::SYS_wait4, DenyAction::Eperm).is_err() {
                unsafe { libc::_exit(3) };
            }
            // SAFETY: getpid always succeeds.
            let me = unsafe { libc::getpid() };
            let guard = ChildGuard {
                pid: me,
                pidfd: None,
                armed: true,
            };
            drop(guard);
            unsafe { libc::_exit(10) };
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut status = 0;
            // SAFETY: valid status out-pointer for an owned child.
            let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if got == pid {
                assert!(
                    libc::WIFEXITED(status),
                    "denied-wait drop must not die by signal (got {})",
                    libc::WTERMSIG(status)
                );
                let code = libc::WEXITSTATUS(status);
                if code == 3 {
                    eprintln!("skip: seccomp unavailable for the wait denial");
                    return;
                }
                assert_eq!(code, 10, "pin-less drop under wait denial must survive");
                return;
            }
            if got < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("confined wait-denial probe failed: {error}");
            }
            assert!(Instant::now() < deadline, "confined wait-denial probe hung");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

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
        // IR-007: serialize against steerers (whole-test hold).
        // This R31-era test predates the R12-002 discipline; as
        // root, steering tests run (ns_last_pid writable) and a
        // parallel steered fork snipes our just-reaped numbers
        // (caught: a fork-only `(fixture::linux:)` child holding
        // a drained sleep's number), tripping the /proc-absence
        // asserts below. Non-root suites never steer, so the
        // race is root-only — but the hold is free everywhere.
        let _serial = AUDIT_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            None,
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
            None,
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
            None,
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
