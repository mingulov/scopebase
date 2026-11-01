// SPDX-License-Identifier: Apache-2.0
//! R20-004 controlled pair publisher: spawn `sleep N`,
//! transmit "pid tick" for its NEVER-auto-reaped child,
//! `wait` tail.
//!
//! This replaces the shell publisher. Bash reaps dead
//! background children at command boundaries (proven: a
//! builtins-only probe reaps within one boundary), so a
//! publisher child dying before the stat read could be
//! reaped + recycled first, transmitting the replacement's
//! tick — the exact gap R19-001 closed on the receiver
//! side. This binary normalizes SIGCHLD to SIG_DFL at
//! startup (R21-005: an inherited SIG_IGN survives exec
//! and would auto-reap) and waits only at the end: the
//! child is live-or-zombie at the stat, and both name the
//! original birth (a zombie keeps it) — the reservation is
//! genuinely sound for any launcher.
//!
//! R21-007: post-spawn custody — a [`SleepGuard`] owns the
//! sleep from spawn on; every post-spawn error site returns
//! through the guard drop (kill+reap) before the loud exit,
//! and panics unwind through it. Pre-fix, every post-spawn
//! `fail()` (`exit(2)`) and the EPIPE `println!` panic
//! stranded the sleep (a full-duration orphan) and wedged
//! the receiver's read on the held pipe.
//!
//! Usage: scopebase-pair-publisher <sleep_secs> <tail>
//!   tail: "wait" (reap the sleep, exit 0) or "exit 0" (exit
//!   at once without waiting — the sleep orphans to init;
//!   the shell script's exact tail text, kept verbatim so
//!   call sites migrate unchanged). Anything else fails
//!   loud.
//! Hook: SCOPEBASE_PUBLISHER_PAUSE_FILE=path — when set and
//!   the path is absent, wait (bounded 30s) for it to
//!   appear after spawning, before the stat (regression
//!   staging: kill the child mid-pause, prove the pair
//!   still names the original). Unset env = no-op.
//! Hook: SCOPEBASE_PUBLISHER_PAUSE_TIMEOUT_MS=ms — override
//!   the pause bound (regression only: fail the pause path
//!   promptly). Unset = 30000. Unparsable fails loud.
//! Hook: SCOPEBASE_PUBLISHER_PRE_SPAWN_HOLD=path — when set
//!   and the path is absent, print R23010-HELD, then wait
//!   (bounded by the pause timeout above) for the path to
//!   appear BEFORE spawning the sleep (R23-010 regression
//!   staging: hold the publisher pre-spawn, prove the
//!   wrapper retires it before any sleeper can appear).
//!   Unset env = no-op.
//! Hook: SCOPEBASE_PUBLISHER_GARBAGE_PAIR=1 — print a
//!   malformed pair line instead of the transmit (R23-011
//!   regression staging: the receiver's parse panics; the
//!   tree guard must still discharge both births). Unset
//!   env = no-op.
//! Hook: SCOPEBASE_PUBLISHER_FAULT_STEP=step — force the
//!   named post-spawn step to fail (regression only: prove
//!   each producer step fails loud + discharged). One of
//!   stat|comm|tick|wait. Anything else fails loud.
//! Hook: SCOPEBASE_PUBLISHER_DENY_WAIT=1 — seccomp-deny
//!   `wait4` to self post-spawn (regression only: prove
//!   the guard reports unresolved custody when reaping is
//!   denied; pair with a fault step — the wait tail itself
//!   cannot wait under the filter). Presence = on.
//! Stdio topology matches the shell script exactly: the
//! sleep inherits our stdio (pinned pipe write end and
//! all); the pair prints to stdout.
//! Exit: 0 after transmit + wait (shell `wait` with no args
//!   exits zero — mirrored); 2 on usage/setup/stage
//!   failure (loud, never silent); 3 when the failure left
//!   the sleep undischargeable (R22-006: kill-denied or
//!   unreapable — loud UNRESOLVED-CUSTODY evidence: sleeper
//!   pid + kill errno + reaped-or-not).

use std::io::Write as _;

fn fail(message: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "scopebase-pair-publisher: {message}");
    std::process::exit(2);
}

/// R22-006: the stage failed AND the sleep is
/// undischargeable — report both (sleeper pid, kill errno,
/// reaped-or-not) and exit 3 (distinct from 2: custody
/// unresolved, not merely a stage failure).
fn fail_unresolved(message: &str, outcome: &GuardOutcome) -> ! {
    let _ = writeln!(
        std::io::stderr(),
        "scopebase-pair-publisher: {message} — UNRESOLVED-CUSTODY sleeper={} kill_errno={} reaped={} ({})",
        outcome.pid,
        outcome
            .kill_errno
            .map_or_else(|| "none".to_string(), |errno| errno.to_string()),
        outcome.reaped,
        outcome.detail,
    );
    std::process::exit(3);
}

fn normalize_sigchld() {
    // R21-005: SIG_IGN survives exec (POSIX) and makes
    // Linux auto-reap children — a launcher that ignores
    // SIGCHLD would silently release the sleep's PID on
    // pre-stat death, and the stat could name a
    // replacement's birth. Normalize to SIG_DFL at startup
    // so the NEVER-auto-reaped claim holds for ANY
    // launcher; fail loud if the disposition cannot be set
    // (a child we cannot keep unreaped is unpublishable).
    // SAFETY: sigaction on SIGCHLD with an empty mask, no
    // handler installed, result checked.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        if libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) != 0 {
            fail("SIGCHLD disposition cannot be set (auto-reap risk)");
        }
    }
}

/// R21-007: post-spawn custody over the sleep child.
/// R22-006: the pipeline consumes the guard EXPLICITLY via
/// [`SleepGuard::retire`] (status-aware — the outcome feeds
/// the failure report) instead of drop-and-forget; `Drop`
/// stays only as the panic/unwind backstop (best-effort
/// retire + stderr evidence — a known direct child is not
/// an identity-observation corner, so abandonment always
/// carries unresolved-custody evidence). Bounded reap (a
/// SIGKILLed sleep dies in µs-ms; the bound only bites on
/// the denied/impossible). Never panics.
struct SleepGuard(Option<std::process::Child>);

/// R22-006: the guard's recorded outcome — pid (`-1` when
/// vacuous: disarmed/orphaned/retired), the kill errno
/// (`None` ⟺ the signal was sent), whether the sleep was
/// reaped, and a short evidence fragment. Resolved ⟺
/// reaped (a reaped sleep holds no pipes — no hang; an
/// externally-reaped one (ECHILD) strands nothing either).
/// Unresolved (kill-denied-live, wait-denied, D-state)
/// exits distinctly (3, not 2) with this evidence.
#[derive(Debug)]
struct GuardOutcome {
    pid: i32,
    kill_errno: Option<i32>,
    reaped: bool,
    detail: String,
}

impl GuardOutcome {
    fn vacuous() -> Self {
        GuardOutcome {
            pid: -1,
            kill_errno: None,
            reaped: true,
            detail: "nothing staged".to_string(),
        }
    }
    fn resolved(&self) -> bool {
        self.reaped
    }
}

impl SleepGuard {
    /// Borrow the staged child (the wait tail reaps through
    /// this, then disarms).
    fn child_mut(&mut self) -> &mut std::process::Child {
        self.0.as_mut().expect("sleep staged")
    }
    /// Stand down after the wait tail reaped the child (the
    /// drop becomes a no-op — never double-reaps).
    fn disarm(&mut self) {
        self.0 = None;
    }
    /// Deliberate orphan (the "exit 0" tail's whole point —
    /// the shell script's verbatim semantics): release the
    /// handle WITHOUT kill/wait. The one sanctioned strand.
    fn orphan(&mut self) {
        self.0 = None;
    }
    /// R22-006: explicit status-aware retire — kill (outcome
    /// RECORDED, never ignored) + bounded reap. `Ok(Some)`
    /// ⟹ resolved; ECHILD ⟹ resolved-externally (reaped
    /// behind our back — nothing stranded); any other wait
    /// error (EPERM/seccomp-denial) ⟹ unreapable-by-us —
    /// polls to the bound like a live child (uniform —
    /// denial is permanent, so the bound always bites, and
    /// the 5s keeps the D-state patience of the old drop).
    /// Timeout ⟹ unresolved (kill-denied-live or
    /// wait-denied). Never panics.
    fn retire(&mut self) -> GuardOutcome {
        let mut child = match self.0.take() {
            None => return GuardOutcome::vacuous(),
            Some(child) => child,
        };
        let pid = child.id() as i32;
        let kill_errno = match child.kill() {
            Ok(()) => None,
            Err(error) => Some(error.raw_os_error().unwrap_or(-999)),
        };
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return GuardOutcome {
                        pid,
                        kill_errno,
                        reaped: true,
                        detail: format!("status={status:?}"),
                    };
                }
                Ok(None) => {
                    if std::time::Instant::now() >= end {
                        return GuardOutcome {
                            pid,
                            kill_errno,
                            reaped: false,
                            detail: "unreaped past 5s (kill-denied-live? D-state?)".to_string(),
                        };
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        return GuardOutcome {
                            pid,
                            kill_errno,
                            reaped: true,
                            detail: "reaped externally (ECHILD — nothing stranded)".to_string(),
                        };
                    }
                    if std::time::Instant::now() >= end {
                        return GuardOutcome {
                            pid,
                            kill_errno,
                            reaped: false,
                            detail: format!("wait denied ({error}) past 5s"),
                        };
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
    }
}

impl Drop for SleepGuard {
    fn drop(&mut self) {
        let outcome = self.retire();
        if outcome.pid >= 0 {
            eprintln!("scopebase-pair-publisher: unwind-retire {outcome:?}");
        }
    }
}

fn main() {
    normalize_sigchld();
    let mut args = std::env::args();
    let _argv0 = args.next();
    let secs = args
        .next()
        .unwrap_or_else(|| fail("usage: scopebase-pair-publisher <sleep_secs> <tail>"));
    let tail = args
        .next()
        .unwrap_or_else(|| fail("usage: scopebase-pair-publisher <sleep_secs> <tail>"));
    if tail != "wait" && tail != "exit 0" {
        fail("only the wait and exit 0 tails exist");
    }
    // Hooks (parsed + validated PRE-spawn: a typo'd hook
    // fails here with nothing staged, never mid-pipeline).
    let pause_timeout_ms: u64 = match std::env::var("SCOPEBASE_PUBLISHER_PAUSE_TIMEOUT_MS") {
        Ok(text) => text
            .parse()
            .unwrap_or_else(|_| fail("pause timeout override unparsable")),
        Err(_) => 30_000,
    };
    let fault_step: Option<String> = match std::env::var("SCOPEBASE_PUBLISHER_FAULT_STEP") {
        Ok(step) if ["stat", "comm", "tick", "wait"].contains(&step.as_str()) => Some(step),
        Ok(step) => fail(&format!(
            "unknown fault step {step:?} (stat|comm|tick|wait)"
        )),
        Err(_) => None,
    };
    // R22-006 regression hook (presence = on — validated
    // pre-spawn like the others: nothing staged on typo...
    // a bool has no typo shape, so presence alone arms).
    let deny_wait = std::env::var("SCOPEBASE_PUBLISHER_DENY_WAIT").is_ok();
    // R23-010 regression hook (pre-spawn hold — unset =
    // no-op; expiry fails loud with nothing staged). Prints
    // R23010-HELD on hold entry (readiness proof — the
    // wrapper must observe it before sweeping).
    if let Ok(flag) = std::env::var("SCOPEBASE_PUBLISHER_PRE_SPAWN_HOLD") {
        println!("R23010-HELD");
        std::io::stdout()
            .flush()
            .unwrap_or_else(|error| fail(&format!("held line unflushable: {error}")));
        let end = std::time::Instant::now() + std::time::Duration::from_millis(pause_timeout_ms);
        while !std::path::Path::new(&flag).exists() {
            if std::time::Instant::now() >= end {
                fail("pre-spawn hold flag never appeared (stage broken)");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    // Spawn with inherited stdio (exactly the shell
    // script's topology: the sleep holds our stdout pipe).
    // The "exit 0" tail deliberately never waits (the
    // sleep orphans to init — the tail's whole point).
    #[allow(clippy::zombie_processes)]
    let sleep = std::process::Command::new("/bin/sleep")
        .arg(&secs)
        .spawn()
        .unwrap_or_else(|error| fail(&format!("sleep spawn failed: {error}")));
    let pid = sleep.id() as i32;
    // R21-007: the guard owns the sleep from here on. The
    // pipeline below returns `Err` (never bare `fail()` —
    // that would `exit()` past the guard and strand the
    // sleep); main retires the guard explicitly between the
    // pipeline and `fail()` (R22-006: status-aware — the
    // outcome feeds the failure report), so every error
    // path kill+reaps first. Success paths disarm/orphan
    // explicitly.
    let mut guard = SleepGuard(Some(sleep));
    let result: Result<(), String> = (|| {
        // R22-006 regression hook (inside the pipeline so
        // an install failure retires through the guard —
        // never a bare fail past the staged sleep).
        if deny_wait {
            use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};
            if let Err(error) = install_deny_one(libc::SYS_wait4, DenyAction::Eperm) {
                return Err(format!("deny-wait install failed: {error}"));
            }
        }
        // Pause hook (regression staging only — unset = no-op).
        if let Ok(flag) = std::env::var("SCOPEBASE_PUBLISHER_PAUSE_FILE") {
            let end =
                std::time::Instant::now() + std::time::Duration::from_millis(pause_timeout_ms);
            while !std::path::Path::new(&flag).exists() {
                if std::time::Instant::now() >= end {
                    return Err("pause flag never appeared (stage broken)".to_string());
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        if fault_step.as_deref() == Some("stat") {
            return Err("fault: stat".to_string());
        }
        // Stat: NEVER reaped before this (no handler, no wait
        // yet) — live-or-zombie both name the original birth.
        // Field 22 via the last-") " strip (mirrors the shell
        // `${T##*) }; ${20}` — greedy comm-strip, 1-based 20
        // ⟹ 0-based 19 past the strip).
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|error| format!("child stat unreadable: {error}"))?;
        if fault_step.as_deref() == Some("comm") {
            return Err("fault: comm".to_string());
        }
        let after = text
            .rsplit_once(") ")
            .map(|pair| pair.1)
            .ok_or_else(|| "stat comm unparseable".to_string())?;
        if fault_step.as_deref() == Some("tick") {
            return Err("fault: tick".to_string());
        }
        let tick: u64 = after
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| "stat starttime missing".to_string())?
            .parse()
            .map_err(|_| "stat starttime unparsable".to_string())?;
        // Checked transmit (R21-007: the old `println!`
        // panicked on EPIPE past the Child handle — Drop
        // never killed. Now a broken stdout fails loud
        // through the guard). R23-011: GARBAGE_PAIR swaps
        // in a malformed line (the stranger EXISTS —
        // post-spawn — but the receiver's parse panics).
        let line = if std::env::var("SCOPEBASE_PUBLISHER_GARBAGE_PAIR").is_ok() {
            "not-a-pair".to_string()
        } else {
            format!("{pid} {tick}")
        };
        {
            let mut out = std::io::stdout().lock();
            if let Err(error) = writeln!(out, "{line}") {
                return Err(format!("stdout broken (receiver gone?): {error}"));
            }
            if let Err(error) = out.flush() {
                return Err(format!("stdout broken (receiver gone?): {error}"));
            }
        }
        if fault_step.as_deref() == Some("wait") {
            return Err("fault: wait".to_string());
        }
        if tail == "wait" {
            match guard.child_mut().wait() {
                Ok(_) => guard.disarm(),
                Err(error) => return Err(format!("wait failed: {error}")),
            }
        } else {
            // "exit 0": return at once — the sleep orphans
            // (the shell script's `exit 0` tail, verbatim
            // semantics — the one sanctioned strand).
            guard.orphan();
        }
        Ok(())
    })();
    // R22-006: explicit status-aware retire (never
    // drop-and-forget — the outcome feeds the report).
    let outcome = guard.retire();
    match result {
        Ok(()) => {
            if outcome.pid >= 0 {
                eprintln!(
                    "scopebase-pair-publisher: BUG? retired a staged sleep on the success \
                     path ({outcome:?})"
                );
            }
        }
        Err(message) => {
            if outcome.resolved() {
                fail(&message);
            } else {
                fail_unresolved(&message, &outcome);
            }
        }
    }
}
