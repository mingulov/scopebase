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
    if matches!(
        signal_preflight_child(pid, pidfd),
        PreflightSignal::Gone
    ) {
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
            let wrote = unsafe {
                libc::write(release[1], byte.as_ptr() as *const _, 1)
            };
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

    /// /proc state letter of `pid` (None when unreadable/gone).
    #[cfg(target_arch = "x86_64")]
    fn proc_state(pid: libc::pid_t) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit_once(") ")?.1.split_whitespace().next()?.chars().next()
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
    static TRAILING_WAITS: std::sync::Mutex<Vec<libc::pid_t>> =
        std::sync::Mutex::new(Vec::new());

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
                // number is unprovable without one. Proven gone
                // (reaped above or ECHILD) falls through to the
                // trailing reap, which then returns at once.
                // Anything else — live, EPERM, ENOSYS,
                // interrupted — stays unresolved: the drop
                // reports and returns WITHOUT signaling and
                // WITHOUT waiting (a blocking wait on a live
                // child would hang). A leaked child is loud
                // (stderr), never a stranger's death.
                None => {
                    let mut status = 0;
                    // SAFETY: valid status out-pointer.
                    let recheck = unsafe {
                        libc::waitpid(self.pid, &mut status, libc::WNOHANG)
                    };
                    let gone = (recheck == self.pid
                        && wait_status_terminal(status))
                        || (recheck < 0 && last_errno_is(libc::ECHILD));
                    if !gone {
                        eprintln!(
                            "ChildGuard: pin-less drop over unproven pid {}; \
                             NOT signaling, NOT waiting",
                            self.pid
                        );
                        return;
                    }
                    // R10-007: reaped above or ECHILD means
                    // custody is discharged — a trailing wait
                    // could only catch a recycled number.
                    return;
                }
            }
            trailing_reap(self.pid);
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
            assert!(
                Instant::now() < deadline,
                "child never reached ptrace-stop"
            );
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
            assert!(
                Instant::now() < deadline,
                "child never reached ptrace-stop"
            );
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

    /// R10-007: pin-less drop where the recheck itself reaps the
    /// child must not issue a second numeric wait — the freed
    /// number may already name another test thread's child.
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
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match proc_state(pid) {
                Some('Z') => break,
                None => {
                    eprintln!("skip: /proc unavailable for zombie observation");
                    return;
                }
                _ => {}
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child never reached zombie state"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let guard = ChildGuard {
            pid,
            pidfd: None,
            armed: true,
        };
        drop(guard);
        assert!(
            !take_trailing_waits().contains(&pid),
            "pin-less drop after an in-drop reap must not wait again"
        );
        // SAFETY: valid status out-pointer; ECHILD proves the
        // recheck reaped (not the trailing wait).
        let mut status = 0;
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            again < 0 && last_errno_is(libc::ECHILD),
            "the recheck must have reaped the zombie"
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
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match proc_state(pid) {
                Some('Z') => break,
                None => {
                    eprintln!("skip: /proc unavailable for zombie observation");
                    return;
                }
                _ => {}
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child never reached zombie state"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let guard = ChildGuard::new(pid);
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
            if outcome.code == 3 {
                eprintln!("skip: seccomp unavailable for {spec}");
                return;
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
                Ok(reported) => panic!(
                    "2s guard must fire mid-EINTR-spin, got exit {}",
                    reported.code
                ),
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

    /// R10-012: await /proc disappearance, reaping an adopted
    /// zombie along the way. Under a subreaper (or PID-1) runner
    /// the signaled grandchild reparents to US — its /proc entry
    /// survives until WE reap it, so the loop waitpids (WNOHANG,
    /// errors ignored: ECHILD means someone else owns it) before
    /// polling disappearance. True when gone within `timeout`,
    /// false on expiry. Never panics — the caller decides.
    /// R11-005: `expected` starttime-gates the numeric wait (see
    /// body): absence and reuse return true without waiting.
    #[cfg(target_arch = "x86_64")]
    fn await_proc_gone_reaping(
        pid: libc::pid_t,
        expected: u64,
        timeout: std::time::Duration,
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
            // polling (never claimed gone).
            match proc_starttime(pid) {
                Ok(None) => return true,
                Ok(Some(now)) if now != expected => return true,
                Ok(Some(_)) => {}
                Err(_) => {}
            }
            // SAFETY: waitpid on the verified holder; reaps an
            // adopted zombie, ECHILD otherwise — always ignored.
            let mut status = 0;
            unsafe {
                libc::waitpid(pid, &mut status, libc::WNOHANG);
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

    /// R11-014: fail-closed retirement for an expired (or
    /// unobservable) probe collection: signal the probe's own
    /// group, then the probe itself, then reap. The probe's
    /// pgid is its pid — every probe groups itself on entry —
    /// so the holders stranded in its group die with it.
    #[cfg(target_arch = "x86_64")]
    fn expire_probe_collection(child: &mut std::process::Child, id: libc::pid_t) {
        // SAFETY: signal-only to the probe's own group, then
        // the probe itself; errors ignored (house discipline).
        unsafe {
            libc::killpg(id, libc::SIGKILL);
            libc::kill(id, libc::SIGKILL);
        }
        let _ = child.wait();
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
    /// arrived. Never blocks past `end`; never panics on I/O
    /// (a dead probe's partial output is still evidence).
    /// Callers pass the SAME `end` as their try_wait loop — one
    /// deadline covers exit AND collection by construction.
    #[cfg(target_arch = "x86_64")]
    fn collect_probe_output_bounded(
        child: &mut std::process::Child,
        end: std::time::Instant,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        use std::os::unix::io::AsRawFd as _;
        // Read dry (nonblocking: stops at WouldBlock; EOF or
        // any other error ends the pipe — partial output is
        // still evidence). Past the cap the drain discards
        // toward EOF-or-deadline.
        fn drain<T: std::io::Read>(
            pipe: &mut Option<T>,
            acc: &mut Vec<u8>,
            buf: &mut [u8; 8192],
            done: &mut bool,
        ) {
            let Some(pipe) = pipe else {
                *done = true;
                return;
            };
            loop {
                match pipe.read(buf) {
                    Ok(0) => {
                        *done = true;
                        break;
                    }
                    Ok(n) => {
                        let room = PROBE_OUTPUT_CAP.saturating_sub(acc.len());
                        acc.extend_from_slice(&buf[..n.min(room)]);
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
        // A blocking read could outlive `end` — fail closed.
        if !nonblocking(&stdout) || !nonblocking(&stderr) {
            expire_probe_collection(child, id);
            return None;
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut out_done = false;
        let mut err_done = false;
        let mut buf = [0u8; 8192];
        loop {
            if out_done && err_done {
                let _ = child.wait();
                return Some((out, err));
            }
            if std::time::Instant::now() >= end {
                expire_probe_collection(child, id);
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
            let remaining = end
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
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
                expire_probe_collection(child, id);
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
        // The shell exits at once; its sleeper inherits the
        // group AND the pipe write ends.
        let status = child.wait().expect("stage exit");
        assert!(status.success());
        let group = child.id() as libc::pid_t;
        let started = Instant::now();
        let got = collect_probe_output_bounded(&mut child, started + Duration::from_secs(2));
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
        let status = loop {
            match child.try_wait().expect("stage wait") {
                Some(status) => break status,
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        assert!(status.success());
        let started = Instant::now();
        let got = collect_probe_output_bounded(&mut child, started + Duration::from_secs(10));
        let (stdout, stderr) = got.expect("small output must collect");
        assert_eq!(stdout, b"OUT\n");
        assert_eq!(stderr, b"ERR\n");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "small collection must be instant, took {:?}",
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
        let mut child = std::process::Command::new(exe)
            .arg(SUBREAPER_PROBE_PATH)
            .arg("--exact")
            .env(SUBREAPER_PROBE_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn subreaper probe");
        let end = Instant::now() + Duration::from_secs(150);
        loop {
            match child.try_wait().expect("probe wait") {
                Some(status) => {
                    // R11-014: bounded collection under the SAME
                    // deadline — wait_with_output would wait for
                    // EOF past it whenever a descendant outlives
                    // the probe holding the pipes.
                    match collect_probe_output_bounded(&mut child, end) {
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
                    return;
                }
                None => {}
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
                panic!("subreaper probe hung past 150s");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
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
        let mut child = std::process::Command::new(exe)
            .arg(GUARD_PROBE_PATH)
            .arg("--exact")
            .env(GUARD_PROBE_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn adopting-guard probe");
        // The probe's worst case is ~17s (2s guard + 5s
        // retirement + 10s group probe); 60s is the same
        // proportionate bound as the R10-012 parent's 150s.
        let end = Instant::now() + Duration::from_secs(60);
        loop {
            match child.try_wait().expect("probe wait") {
                Some(status) => {
                    // R11-014: bounded collection under the SAME
                    // deadline — wait_with_output would wait for
                    // EOF past it whenever a descendant outlives
                    // the probe holding the pipes.
                    match collect_probe_output_bounded(&mut child, end) {
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
                    return;
                }
                None => {}
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
                panic!("adopting-guard probe hung past 60s");
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
                assert_eq!(
                    code, 10,
                    "pin-less drop under wait denial must survive"
                );
                return;
            }
            if got < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("confined wait-denial probe failed: {error}");
            }
            assert!(
                Instant::now() < deadline,
                "confined wait-denial probe hung"
            );
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
