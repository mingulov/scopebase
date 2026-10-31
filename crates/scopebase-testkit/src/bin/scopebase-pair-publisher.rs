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
//! Stdio topology matches the shell script exactly: the
//! sleep inherits our stdio (pinned pipe write end and
//! all); the pair prints to stdout.
//! Exit: 0 after transmit + wait (shell `wait` with no args
//!   exits zero — mirrored); 2 on usage/setup/stage
//!   failure (loud, never silent).

use std::io::Write as _;

fn fail(message: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "scopebase-pair-publisher: {message}");
    std::process::exit(2);
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
    // Spawn with inherited stdio (exactly the shell
    // script's topology: the sleep holds our stdout pipe).
    // The "exit 0" tail deliberately never waits (the
    // sleep orphans to init — the tail's whole point).
    #[allow(clippy::zombie_processes)]
    let mut sleep = std::process::Command::new("/bin/sleep")
        .arg(&secs)
        .spawn()
        .unwrap_or_else(|error| fail(&format!("sleep spawn failed: {error}")));
    let pid = sleep.id() as i32;
    // Pause hook (regression staging only — unset = no-op).
    if let Ok(flag) = std::env::var("SCOPEBASE_PUBLISHER_PAUSE_FILE") {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !std::path::Path::new(&flag).exists() {
            if std::time::Instant::now() >= end {
                fail("pause flag never appeared (stage broken)");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    // Stat: NEVER reaped before this (no handler, no wait
    // yet) — live-or-zombie both name the original birth.
    // Field 22 via the last-") " strip (mirrors the shell
    // `${T##*) }; ${20}` — greedy comm-strip, 1-based 20
    // ⟹ 0-based 19 past the strip).
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap_or_else(|error| fail(&format!("child stat unreadable: {error}")));
    let after = text
        .rsplit_once(") ")
        .map(|pair| pair.1)
        .unwrap_or_else(|| fail("stat comm unparseable"));
    let tick: u64 = after
        .split_whitespace()
        .nth(19)
        .unwrap_or_else(|| fail("stat starttime missing"))
        .parse()
        .unwrap_or_else(|_| fail("stat starttime unparsable"));
    println!("{pid} {tick}");
    let _ = std::io::stdout().flush();
    if tail == "wait" {
        let _status = sleep
            .wait()
            .unwrap_or_else(|error| fail(&format!("wait failed: {error}")));
    }
    // "exit 0": return at once — the sleep orphans (the
    // shell script's `exit 0` tail, verbatim semantics).
}
