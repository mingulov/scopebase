// SPDX-License-Identifier: Apache-2.0
//! Multithread-safe raw-fork rendezvous for TT04 fixture children.
//!
//! Cargo test binaries are multithreaded, so a forked child may only run
//! async-signal-safe syscalls until it execs or exits. The parent tells
//! the child which inherited descriptors to use through atomic slots set
//! under a process-wide mutex held across the fork; the child performs
//! only atomic loads and raw syscalls. NEW per the frozen TT04 fixture
//! design; no donor implements this rendezvous.
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};

static FORK_GUARD: Mutex<()> = Mutex::new(());
static SLOT_A: AtomicI32 = AtomicI32::new(-1);
static SLOT_B: AtomicI32 = AtomicI32::new(-1);
static SLOT_C: AtomicI32 = AtomicI32::new(-1);

/// Hold the fork mutex, publish three descriptor slots, fork, then run
/// `parent` (with the guard still held) or `child` (syscalls only).
///
/// # Safety
///
/// `child` runs in the forked child of a multithreaded process: only
/// async-signal-safe syscalls, atomic loads and stack memory. It must
/// never allocate, lock, touch std I/O, or return into test code;
/// diverging (`_exit`) is the only sound exit.
pub unsafe fn fork_guarded<R, C>(
    slots: (i32, i32, i32),
    parent: impl FnOnce(libc::pid_t) -> R,
    child: C,
) -> R
where
    C: FnOnce() -> R,
{
    let guard: MutexGuard<'static, ()> = FORK_GUARD
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    SLOT_A.store(slots.0, Ordering::Relaxed);
    SLOT_B.store(slots.1, Ordering::Relaxed);
    SLOT_C.store(slots.2, Ordering::Relaxed);
    // SAFETY: fork itself is always safe; the child upholds the
    // syscall-only contract documented above.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // R19-007: shed everything except the rendezvous slots
        // (the child contract uses only those + stdio — a bare
        // fork here would inherit racing pipe write ends for
        // the child's whole life and be murdered at another
        // collection's expiry).
        // (The `slots` parameter shadows slots(): load directly.)
        let (a, b, c) = (
            SLOT_A.load(Ordering::Relaxed),
            SLOT_B.load(Ordering::Relaxed),
            SLOT_C.load(Ordering::Relaxed),
        );
        unsafe { shed_inherited_fds(&[a, b, c]) };
        // The child contract diverges; _exit is the sound fallback if
        // it ever returns (a panic here would be MT-unsound).
        let _ = child();
        unsafe { libc::_exit(127) };
    }
    SLOT_A.store(-1, Ordering::Relaxed);
    SLOT_B.store(-1, Ordering::Relaxed);
    SLOT_C.store(-1, Ordering::Relaxed);
    let result = parent(pid);
    drop(guard);
    result
}

/// R19-007: shed inherited descriptors in a fork-only child —
/// fork copies every fd regardless of CLOEXEC, so a child that
/// never execs keeps racing pipe write ends (EOF + discovery
/// attribution — murdered at another collection's expiry) for
/// its whole life. Closes [3, u32::MAX] minus `keep` (report
/// fds the child still needs; stdio 0,1,2 stay — shared,
/// EOF-safe); a close_range failure _exits 127 WITHOUT
/// reporting (the parent observes EOF/death — loud, never a
/// silent hole; R12-008 precedent). Single-syscall pieces,
/// async-signal-safe, MT-fork sound. Kernel floor: close_range
/// (5.9+) — ENOSYS fails loud the same way (established by
/// R12-008, not a new floor).
///
/// # Safety
///
/// Call only in a forked child that never returns to managed
/// code: on failure this diverges (`_exit`), and on success
/// the listed range is closed (the caller must need nothing
/// in it but `keep` + stdio).
pub unsafe fn shed_inherited_fds(keep: &[i32]) {
    // Close [3, u32::MAX] minus `keep`, as sorted pieces
    // (allocation-free: re-scan for the next keep in range;
    // keeps below 3 need no action — stdio never sheds).
    // Any failure _exits 127 WITHOUT reporting (R12-008
    // precedent — the parent observes EOF/death, loud).
    let mut lo: i64 = 3;
    loop {
        if lo > u32::MAX as i64 {
            break;
        }
        let mut next: i64 = u32::MAX as i64 + 1;
        for &fd in keep {
            let fd = fd as i64;
            if fd >= lo && fd < next {
                next = fd;
            }
        }
        if next > lo {
            // SAFETY: close_range on our own table copy (plain
            // fork never shares it); bounds checked above.
            if unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    lo as libc::c_long,
                    (next - 1) as libc::c_long,
                    0 as libc::c_long,
                )
            } != 0
            {
                unsafe { libc::_exit(127) };
            }
        }
        if next > u32::MAX as i64 {
            break;
        }
        lo = next + 1;
    }
}

/// R19-007: fork a pausing child that sheds inherited fds —
/// the sound replacement for bare `fork(); loop { pause() }`.
/// Parent gets the pid (<0 on fork failure, like fork); the
/// child sheds (nothing to keep) and pauses forever.
///
/// # Safety
///
/// Fork in a multithreaded context: the child runs syscalls
/// only (shed + pause) and never returns; the parent must
/// retire the child (it pauses until signaled).
#[cfg(test)]
pub unsafe fn fork_shedding_pauser() -> libc::pid_t {
    // SAFETY: fork itself is always safe; the child upholds
    // the syscall-only contract documented above.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            shed_inherited_fds(&[]);
            loop {
                libc::pause();
            }
        }
    }
    pid
}

/// R20-002: fork a pausing child that sheds inherited fds
/// only after `gate` (a `CStr` path) appears — the parent
/// holds the child pre-shed through discovery (attributed
/// while holding, deterministically), then releases it.
/// Parent gets the pid (<0 on fork failure, like fork); the
/// child polls the gate (1ms cadence, 30s bound — timeout
/// `_exit(1)`s loud), sheds (nothing to keep), and pauses
/// forever.
///
/// # Safety
///
/// Fork in a multithreaded context: the child runs syscalls
/// only (access + clock_gettime + nanosleep + shed + pause)
/// plus read-only inherited stack memory (`gate`), and never
/// returns; the parent must retire the child (it pauses until
/// signaled) and must create the gate (else the child exits 1
/// past the bound and the liveness asserts fail loud).
#[cfg(test)]
pub unsafe fn fork_gated_shedding_pauser(gate: &std::ffi::CStr) -> libc::pid_t {
    // SAFETY: fork itself is always safe; the child upholds
    // the syscall-only contract documented above.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let start = {
                let mut now: libc::timespec = std::mem::zeroed();
                libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
                now.tv_sec
            };
            let nap = libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            loop {
                if libc::access(gate.as_ptr(), libc::F_OK) == 0 {
                    break;
                }
                let mut now: libc::timespec = std::mem::zeroed();
                libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
                if now.tv_sec - start > 30 {
                    libc::_exit(1);
                }
                libc::nanosleep(&nap, std::ptr::null_mut());
            }
            shed_inherited_fds(&[]);
            loop {
                libc::pause();
            }
        }
    }
    pid
}

/// R19-007: fork a child that sheds inherited fds, then exits
/// with `code` — the sound replacement for bare
/// `fork(); _exit(N)` (even a microsecond-lived bare child is
/// discovery-visible while it holds a racing end).
/// Parent gets the pid (<0 on fork failure, like fork); the
/// child never returns.
///
/// # Safety
///
/// Fork in a multithreaded context: the child runs syscalls
/// only (shed + _exit) and never returns.
#[cfg(test)]
pub unsafe fn fork_shedding_exiter(code: u8) -> libc::pid_t {
    // SAFETY: fork itself is always safe; the child upholds
    // the syscall-only contract documented above.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            shed_inherited_fds(&[]);
            libc::_exit(code as libc::c_int);
        }
    }
    pid
}

/// R21-008: read /proc state + process-group in one
/// parse (the report-failure tail's freeze/verify
/// observations — state field 3, pgrp field 5).
#[cfg(test)]
fn stat_state_pgrp(pid: libc::pid_t) -> Option<(char, libc::pid_t)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(") ")?.1;
    let mut fields = after.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let _ppid = fields.next()?;
    let pgrp = fields.next()?.parse::<libc::pid_t>().ok()?;
    Some((state, pgrp))
}

/// R21-009: starttime read for the regression's
/// birth-aware checks (fork-local — audit's helper is
/// out of reach). `Ok(None)` is proven absence
/// (ENOENT); anything else unreadable is `Err`.
/// Parent scope (moved up for R23-019 — the jam
/// birth-gate stakes m2's birth pre-tail; tests reach
/// it via `super::*` as before).
#[cfg(test)]
fn fork_starttime(pid: libc::pid_t) -> Result<Option<u64>, String> {
    let text = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let after = text
        .rsplit_once(") ")
        .map(|pair| pair.1)
        .ok_or_else(|| "comm shape".to_string())?;
    after
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| "starttime field".to_string())?
        .parse::<u64>()
        .map(Some)
        .map_err(|error| error.to_string())
}

/// R21-008: full retirement of a REPORTLESS middleman
/// (m1, our unreaped child — the number is PINNED while
/// unreaped, which anchors every group operation below).
/// The old tail (ungated kill + ONE WNOHANG wait) stranded
/// m1 as a zombie when death lagged the single wait, and
/// never touched m2 (pid unknown on this path — the
/// grandchild slept on, a live strand behind a `None` that
/// claimed "never strands").
///
/// m2's exit conditions, verified in the middleman branch
/// below: the grandchild is exec'd /bin/sleep (no prctl,
/// no pdeathsig — stdin is /dev/null, the report pipe is
/// CLOEXEC'd out of the exec, nothing EOF-signals it), so
/// it obeys ONLY signals and its timeout. Grouping is the
/// only channel that reaches an unknown pid: the middleman
/// self-groups FIRST (setpgid pre-fork — `m2 born ⟹ m2
/// grouped` by program order), and the tail freeze-verifies
/// before signaling:
/// STOP m1 and await a frozen state (T/t/Z/X/x — a frozen
/// m1 cannot fork, so the pgrp read is STABLE: grouped ⟹
/// m2 may exist (killpg while PINNED — sound, no foreign
/// group can hold a pinned number); ungrouped ⟹ m2 UNBORN
/// (frozen pre-group ⟹ pre-fork ⟹ nothing to strand). A
/// zombie-at-freeze with pgrp == m1 takes the killpg path
/// too (died-after-grouping — e.g. OOM — m2 may live).
/// Then kill m1, await its zombie (death proven, pin still
/// held), hammer killpg once more (still pinned), REAP m1,
/// and probe killpg(m1, 0): ESRCH proves m2 dead (a live
/// grouped m2 would hold the group open — the probe is
/// sound either way zombies count for killpg: ESRCH means
/// no live member at minimum). Non-ESRCH after the bound,
/// or any unfreezable/unreapable m1, fails LOUD (citing
/// m1/the group) — never a silent strand.
/// Residual (accepted): on the wedged-box fallback path
/// (m1 unfreezable for 5 s) R22-008 kills the group
/// UNCONDITIONALLY (m1 pinned ⟹ ours-or-nonexistent) —
/// the remaining hole is m1 forking m2 between the
/// killpg and its own death (µs-narrow, gated behind a
/// wedged box, and loud via R22008-ASSUMED-GROUPED).
#[cfg(test)]
fn retire_reportless_middleman(m1: libc::pid_t) {
    use std::time::{Duration, Instant};
    // SAFETY: signals to our own unreaped child (or ESRCH
    // nop when already dead — a dead m1 still needs the
    // freeze-verify below: died-after-grouping ⟹ m2 may
    // live).
    unsafe {
        libc::kill(m1, libc::SIGSTOP);
    }
    // Freeze-await: T/t (stopped — cannot progress), Z/X/x
    // (dead — cannot progress, pgrp is death-time stable).
    // Returns the frozen observation (frozen ⟹ stable — no
    // re-read needed).
    let frozen: Option<(char, libc::pid_t)> = {
        let end = Instant::now() + Duration::from_secs(5);
        let mut seen = None;
        while Instant::now() < end {
            match stat_state_pgrp(m1) {
                Some((st, pgrp)) if matches!(st, 'T' | 't' | 'Z' | 'X' | 'x') => {
                    seen = Some((st, pgrp));
                    break;
                }
                _ => {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        seen
    };
    let Some((fstate, pgrp)) = frozen else {
        // FALLBACK: m1 unfreezable for 5 s (wedged box —
        // D-state or worse). Loud, best-effort, pinned:
        // killpg while m1 is unreaped is still sound (no
        // foreign group can hold the pinned number); the
        // µs fork-between-read-and-death residual is
        // accepted here (documented above).
        eprintln!("R21008-FALLBACK: middleman {m1} unfreezable for 5 s (wedged?) — loud best-effort retire");
        // SAFETY: our own unreaped child (pinned).
        unsafe {
            libc::kill(m1, libc::SIGKILL);
        }
        // R22-008: UNCONDITIONAL group-kill — m1 is unreaped
        // (pinned), so group m1 is ours-or-nonexistent and
        // the killpg is sound either way (hits an
        // already-born m2 or ESRCH-nops). The old
        // `is_some_and(pgrp == m1)` gate re-read None under
        // a stat outage and SUPPRESSED the kill (m1 killed
        // + reaped, live m2 stranded — no fork race needed;
        // m2 can predate the outage). The read below only
        // characterizes the kill LOUDLY, never gates it.
        match stat_state_pgrp(m1) {
            Some((_, g)) if g == m1 => {
                eprintln!("R22008-ASSUMED-GROUPED: middleman {m1} grouped at fallback read — group-killing");
            }
            Some((_, g)) => {
                eprintln!("R22008-ASSUMED-GROUPED: middleman {m1} ungrouped at fallback read (pgrp {g} — m2 unborn?) — killpg anyway (pinned: ours-or-nonexistent, ESRCH-nop when absent)");
            }
            None => {
                eprintln!("R22008-ASSUMED-GROUPED: middleman {m1} pgrp UNREADABLE at fallback (outage?) — killpg anyway (pinned: ours-or-nonexistent; an already-born m2 dies, never strands)");
            }
        }
        // SAFETY: pinned group — ours-or-nonexistent while
        // m1 is unreaped (no foreign group can hold the
        // pinned number).
        unsafe {
            libc::killpg(m1, libc::SIGKILL);
        }
        reap_child_bounded(m1, "R21008-FALLBACK");
        return;
    };
    let grouped = pgrp == m1;
    if grouped {
        eprintln!(
            "R21008: middleman {m1} grouped at freeze ({fstate}) — group-killing (m2 may live)"
        );
        // SAFETY: pinned group — ours by construction (the
        // middleman self-groups first-thing; no foreign
        // group can hold the pinned number m1).
        unsafe {
            libc::killpg(m1, libc::SIGKILL);
        }
    } else {
        eprintln!(
            "R21008: middleman {m1} ungrouped at freeze ({fstate}) — m2 unborn, numeric kill only"
        );
    }
    // SAFETY: our own unreaped child (STOPPED m1 dies on
    // SIGKILL without CONT; zombie m1 nop-accepts it).
    unsafe {
        libc::kill(m1, libc::SIGKILL);
    }
    // Await m1's zombie (death proven, pin STILL HELD —
    // unreaped — for the hammer below).
    let end = Instant::now() + Duration::from_secs(5);
    let mut zombied = false;
    while Instant::now() < end {
        match stat_state_pgrp(m1) {
            Some(('Z' | 'X' | 'x', _)) => {
                zombied = true;
                break;
            }
            _ => {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    if !zombied {
        eprintln!(
            "R21008: middleman {m1} not zombie 5 s after KILL (wedged?) — loud best-effort retire"
        );
        reap_child_bounded(m1, "R21008");
        return;
    }
    if grouped {
        // SAFETY: still pinned (m1 zombie-unreaped) —
        // idempotent hammer for a slow-dying m2.
        unsafe {
            libc::killpg(m1, libc::SIGKILL);
        }
    }
    reap_child_bounded(m1, "R21008");
    if grouped {
        // Post-reap probe: killpg(m1, 0) — NO killpg(KILL)
        // past the reap (the number is unpinned now — a
        // foreign squatter could hold it). ESRCH proves m2
        // dead (a live grouped m2 would hold the group
        // open); non-ESRCH is UNACTIONABLE (m2-live or
        // foreign-squatter — indistinguishable) ⟹ loud,
        // never a blind kill.
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: signal-0 probe (no delivery).
            let probed = unsafe { libc::killpg(m1, 0) };
            if probed != 0 {
                // R22-009: discriminate errno — ESRCH
                // proves empty (a live grouped m2 would
                // hold the group open); EPERM/other (a
                // filter denying group signals denies the
                // m2 kills AND this probe) fails
                // LOUD-UNRESOLVED — never an empty
                // citation. The old `!= 0` treated EVERY
                // failure as ESRCH-empty and falsely
                // certified death over live m2. The
                // pre-reap killpgs stay fire-and-forget
                // (this probe is the backstop).
                let errno = std::io::Error::last_os_error().raw_os_error();
                if errno == Some(libc::ESRCH) {
                    eprintln!("R21008: group {m1} empty post-reap (ESRCH) — m2 proven dead");
                    break;
                }
                eprintln!("R22009-UNRESOLVED: group {m1} post-reap probe failed errno {errno:?} (not ESRCH — group-signal denial?) — m2 fate UNKNOWN, never an empty citation");
                break;
            }
            if Instant::now() >= end {
                eprintln!("R21008: group {m1} NON-EMPTY 5 s post-reap (m2-live or foreign squatter — unactionable, loud)");
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// R21-008: bounded reap of our own child (WNOHANG loop —
/// the old tail's single wait stranded zombies when death
/// lagged it). Loud at the bound (citing the pid), never
/// silent.
#[cfg(test)]
fn reap_child_bounded(pid: libc::pid_t, tag: &str) {
    use std::time::{Duration, Instant};
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut st = 0;
        // SAFETY: WNOHANG reap of our own child (specific
        // pid — never steals).
        let got = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        if got == pid || std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            break;
        }
        if Instant::now() >= end {
            eprintln!("{tag}: child {pid} unreaped after 5 s (wedged?) — loud");
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// R20-005: fork a pausing middleman that forks an
/// exec'd grandchild sleep and reports its pid through a
/// pipe. Returns the (middleman, grandchild) pids, or
/// None when staging fails (fork/report error — never
/// strands: a report failure FULLY retires before None —
/// the middleman is freeze-verified, killed, and reaped,
/// and the unknown-pid grandchild is group-killed with
/// its death PROVEN by a post-reap group-empty probe;
/// any unprovable remainder fails LOUD, citing pids).
///
/// The grandchild's parent is the LIVE middleman — hence
/// our non-child whatever subreaper state we hold (no
/// prctl games). The middleman self-groups FIRST
/// (setpgid pre-fork — the report-failure tail's only
/// channel to the unknown-pid grandchild), sheds
/// everything but the report write end, nulls stdio (dup2
/// /dev/null — the grandchild must not inherit test stdio
/// write ends), forks, reports via
/// hand-rolled-decimal+write, and pauses forever.
/// The grandchild execs /bin/sleep with an EMPTY env (no
/// post-fork environ race). The report read is poll-bounded
/// (5s) — a wedged middleman fails loud, never hangs the
/// suite.
///
/// # Safety
///
/// Fork in a multithreaded context: the middleman runs
/// syscalls only (setpgid + shed + dup2 + fork + manual
/// decimal + write + pause) plus read-only inherited stack
/// memory, and never returns; the parent must retire both
/// children (the middleman pauses until signaled, the
/// grandchild sleeps until signaled).
#[cfg(test)]
pub unsafe fn fork_pausing_grandchild_sleep(dur: &str) -> Option<(libc::pid_t, libc::pid_t)> {
    // SAFETY: same contract as the inner helper.
    unsafe { fork_pausing_grandchild_sleep_inner(dur, false, true).0 }
}

/// R21-008: jammed-report variant — drops the report read
/// end before polling (the middleman's write fails EPIPE —
/// SIGPIPE is ignored — and it pauses with the grandchild
/// born), birth-gates on the middleman's children file
/// (panics loud if m2 is not provably born — a jam without
/// a born grandchild would be a VACUOUS retirement
/// regression), then runs the production report-failure
/// R23-019: jammed-report outcome — the helper result
/// plus the pre-tail birth observations (the gate proved
/// both live — `None` ticks only on the spawn-failure
/// path, where `m1` is already negative).
#[cfg(test)]
pub struct JamReportOutcome {
    /// None — the tail ran (the helper result).
    pub result: Option<(libc::pid_t, libc::pid_t)>,
    /// The middleman pid (for the caller's INDEPENDENT
    /// reap proof — the tail's own claim is not evidence).
    pub m1: libc::pid_t,
    /// m1's birth (the caller proves m1's reap
    /// gone-or-recycled over it — never vacancy-only).
    pub tick1: Option<u64>,
    /// m2's birth stake (m2's pid stays UNREPORTED by
    /// design — the finding's contract — but the stake
    /// lets the caller prove m2's death birth-aware).
    pub m2_stake: Option<(libc::pid_t, u64)>,
}

/// R21-008: jammed-report variant — drops the report read
/// end before polling (the middleman's write fails EPIPE —
/// SIGPIPE is ignored — and it pauses with the grandchild
/// born), birth-gates on the middleman's children file
/// (panics loud if m2 is not provably born — a jam without
/// a born grandchild would be a VACUOUS retirement
/// regression), then runs the production report-failure
/// tail. Returns [`JamReportOutcome`] (result None — the
/// tail ran — plus m1 and both pre-tail births).
///
/// # Safety
///
/// Same fork contract as
/// [`fork_pausing_grandchild_sleep`].
#[cfg(test)]
pub unsafe fn fork_pausing_grandchild_sleep_jam_report(dur: &str) -> JamReportOutcome {
    // SAFETY: same contract as the inner helper.
    let (result, m1, tick1, m2_stake) =
        unsafe { fork_pausing_grandchild_sleep_inner(dur, true, true) };
    JamReportOutcome {
        result,
        m1,
        tick1,
        m2_stake,
    }
}

/// R22-008/009: jammed-report SPAWN ONLY — the jam arm's
/// spawn + birth-gate WITHOUT the production tail (fault
/// probes stage the pair healthy, print custody, THEN
/// inject the fault before running the tail themselves).
/// Returns `Some((m1, m2, tick2))` (m2 born-proven and
/// birth-staked pre-return — R23-019: the probe prints
/// the stake as custody and the wrapper proves m2's
/// fate birth-aware) or `None` on spawn failure; the
/// birth-gate still panics loud on an unborn m2 (never
/// a vacuous staging).
///
/// Custody: the caller owns the live pair on return (m1
/// pauses forever, m2 sleeps `dur`) — print the pids (or
/// arm a guard) IMMEDIATELY; there is no backstop between
/// return and the caller's first custody act.
///
/// # Safety
///
/// Same fork contract as
/// [`fork_pausing_grandchild_sleep`].
#[cfg(test)]
pub unsafe fn fork_pausing_grandchild_sleep_jam_noretire(
    dur: &str,
) -> Option<(libc::pid_t, libc::pid_t, u64)> {
    // SAFETY: same contract as the inner helper.
    // R23-019: m1's tick discarded (noretire callers pin
    // their own — m1 is live on return).
    let (_, m1, _, stake) = unsafe { fork_pausing_grandchild_sleep_inner(dur, true, false) };
    if m1 > 0 {
        let (m2, tick2) = stake.expect("jam gate stakes m2 pre-return (unreachable)");
        Some((m1, m2, tick2))
    } else {
        None
    }
}

/// R22-016(b): PRE-EXEC-STALL pair spawn — m1 self-groups
/// first-thing (same program order as the jam spawner:
/// `stub born ⟹ stub grouped`), forks the stub, then
/// pauses forever. The stub stops ITSELF first-thing
/// (`raise(SIGSTOP)` before any exec — it never execs)
/// and then pauses: this stages the finding's
/// "fork-proven, descheduled before execve" shape
/// SYNCHRONOUSLY (no scheduling luck — the stub is
/// provably pre-exec whenever the parent observes it).
/// The stub's cmdline is the inherited middleman image
/// (argv0 ≠ `sleep`) — the argv0 scan is blind to it by
/// construction.
///
/// Returns `(m1, stub)` (stub birth-gated on m1's
/// children file — panics loud when unborn, never
/// vacuous; the stub pid is parsed from that same file).
/// `dur` is the scan key, not an argv (the stub never
/// execs — nothing stages it): the caller's scan-blind
/// pin asserts no `sleep dur` is visible, and the value
/// doubles as the stray-hunt tag. (The parameter exists
/// so call sites stay duration-keyed like the jam
/// spawner.)
///
/// Custody: the caller owns both on return (m1 pauses
/// forever, the stub sleeps stopped) — print the pids
/// (or arm guards) IMMEDIATELY; there is no backstop
/// between return and the caller's first custody act.
/// Cleanup is numeric-kill by pid (SIGKILL kills a
/// stopped process — no CONT needed).
///
/// # Safety
///
/// Same fork contract as
/// [`fork_pausing_grandchild_sleep`] (both children run
/// syscalls only and never return).
#[cfg(test)]
pub unsafe fn fork_prestall_grandchild_jam_noretire(
    dur: &str,
) -> Option<(libc::pid_t, libc::pid_t)> {
    let _ = dur;
    // R23-011 fault staging, decided parent-side (no
    // allocator use in the fork child — the child arms
    // read the stack copies): NO_STUB pauses stub-less
    // (birth gate times out, m1 alive); EXIT_M1 exits at
    // once (gate times out, m1 dead). Unset = normal.
    let no_stub = std::env::var("SCOPEBASE_PRESTALL_NO_STUB").is_ok();
    let exit_m1 = std::env::var("SCOPEBASE_PRESTALL_EXIT_M1").is_ok();
    // SAFETY: fork itself is always safe; both children
    // uphold the syscall-only contract below.
    let m1 = unsafe { libc::fork() };
    if m1 == 0 {
        unsafe {
            // R23-011 dead-arm staging: exit before
            // anything is staged (the birth gate times out
            // over the corpse).
            if exit_m1 {
                libc::_exit(127);
            }
            // Self-group FIRST (same as the jam spawner —
            // the tail's only channel to the stub).
            // Syscall-only; failure exits pre-stub with
            // the stub unborn (the parent's birth-gate
            // fails staging-loud on exactly this).
            if libc::setpgid(0, 0) != 0 {
                libc::_exit(127);
            }
            shed_inherited_fds(&[]);
            // Null stdio BEFORE forking the stub (the
            // stub must hold no test pipe — the probe's
            // output read cannot wedge).
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if null < 0 {
                libc::_exit(127);
            }
            if libc::dup2(null, 0) < 0 || libc::dup2(null, 1) < 0 || libc::dup2(null, 2) < 0 {
                libc::_exit(127);
            }
            if null > 2 {
                libc::close(null);
            }
            // R23-011 alive-arm staging: pause stub-less
            // (the birth gate times out with m1 alive).
            if no_stub {
                loop {
                    libc::pause();
                }
            }
            let stub = libc::fork();
            if stub == 0 {
                // Stub: stop SELF before any exec (never
                // execs — pre-exec by construction), then
                // pause (reached only if CONT'd — cleanup
                // KILLs instead).
                libc::raise(libc::SIGSTOP);
                loop {
                    libc::pause();
                }
            }
            if stub < 0 {
                libc::_exit(127);
            }
            loop {
                libc::pause();
            }
        }
    }
    if m1 < 0 {
        return None;
    }
    // Birth-gate on m1's children file (the stub's pid is
    // parsed from that same file — m1 has exactly one
    // child).
    let gate_end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(kids) = std::fs::read_to_string(format!("/proc/{m1}/task/{m1}/children")) {
            if let Some(first) = kids.split_whitespace().next() {
                if let Ok(stub) = first.parse::<libc::pid_t>() {
                    if stub > 0 {
                        return Some((m1, stub));
                    }
                }
            }
        }
        if std::time::Instant::now() >= gate_end {
            match stat_state_pgrp(m1) {
                Some((st, _)) => {
                    // R23-011: retire BEFORE failing loud
                    // (mirror of the R21008-JAM sibling — a
                    // timeout panic must never strand m1).
                    retire_reportless_middleman(m1);
                    panic!("R22016B-JAM: birth-gate timed out with m1 {m1} alive-childless (state {st} — wedged pre-fork? box wedged?) (m1 retired before failing loud)")
                }
                None => {
                    reap_child_bounded(m1, "R22016B-JAM");
                    panic!("R22016B-JAM: birth-gate timed out with m1 {m1} dead pre-stub (self-exit? — regression vacuous, failing loud) (corpse reaped before failing loud)")
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[cfg(test)]
unsafe fn fork_pausing_grandchild_sleep_inner(
    dur: &str,
    jam: bool,
    retire_on_jam: bool,
) -> (
    Option<(libc::pid_t, libc::pid_t)>,
    libc::pid_t,
    Option<u64>,
    Option<(libc::pid_t, u64)>,
) {
    use std::os::unix::io::FromRawFd as _;
    // Report pipe (CLOEXEC — out of the exec'd grandchild).
    let mut pipe = [0; 2];
    // SAFETY: pipe2 fills both ends.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return (None, -1, None, None);
    }
    let (read_fd, write_fd) = (pipe[0], pipe[1]);
    assert!(
        read_fd >= 3 && write_fd >= 3,
        "report pipe must clear stdio (else the middleman's stdio-nulling clobbers it)"
    );
    let dur_c = match std::ffi::CString::new(dur) {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: ends owned by this scope.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return (None, -1, None, None);
        }
    };
    // SAFETY: fork itself is always safe; the middleman
    // upholds the syscall-only contract documented above.
    let m1 = unsafe { libc::fork() };
    if m1 == 0 {
        unsafe {
            // R21-008: self-group FIRST (the tail's only
            // channel to the unknown-pid grandchild — `m2
            // born ⟹ m2 grouped` by program order).
            // Syscall-only (async-signal-safe); failure
            // exits pre-report with m2 unborn (sound —
            // the tail's ungrouped path expects exactly
            // this).
            if libc::setpgid(0, 0) != 0 {
                libc::_exit(127);
            }
            shed_inherited_fds(&[write_fd]);
            // Null stdio BEFORE forking the grandchild.
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if null < 0 {
                libc::_exit(127);
            }
            if libc::dup2(null, 0) < 0 || libc::dup2(null, 1) < 0 || libc::dup2(null, 2) < 0 {
                libc::_exit(127);
            }
            if null > 2 {
                libc::close(null);
            }
            let m2 = libc::fork();
            if m2 == 0 {
                // Grandchild: exec sleep with an EMPTY env.
                let path = c"/bin/sleep".as_ptr();
                let argv0 = c"sleep".as_ptr();
                let argv = [argv0, dur_c.as_ptr(), std::ptr::null()];
                let envp = [std::ptr::null()];
                libc::execve(path, argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
            if m2 < 0 {
                libc::_exit(127);
            }
            // Report the grandchild pid, then pause forever.
            // R21-017: hand-rolled decimal — snprintf is NOT
            // async-signal-safe after a multithreaded fork
            // (inherited libc locks can deadlock); digits
            // reverse into the stack buffer (m2 > 0 here —
            // failure and grandchild branches exited above).
            let mut buf = [0 as libc::c_char; 32];
            let mut value = m2 as u32;
            let mut digits = 0usize;
            // Bounds exclude panic: u32 decimal ≤ 10 digits
            // plus newline < 32 (no heap, no locks — the
            // only failure mode would be an index panic on
            // an unreachable bound).
            loop {
                buf[digits] = (b'0' + (value % 10) as u8) as libc::c_char;
                digits += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            {
                let mut i = 0;
                while i < digits / 2 {
                    let other = digits - 1 - i;
                    buf.swap(i, other);
                    i += 1;
                }
            }
            buf[digits] = b'\n' as libc::c_char;
            digits += 1;
            let len = digits as libc::c_int;
            if len > 0 {
                let mut written = 0;
                while written < len {
                    let got = libc::write(
                        write_fd,
                        buf.as_ptr().add(written as usize) as *const _,
                        (len - written) as usize,
                    );
                    if got <= 0 {
                        break;
                    }
                    written += got as libc::c_int;
                }
            }
            loop {
                libc::pause();
            }
        }
    }
    if m1 < 0 {
        // SAFETY: ends owned by this scope.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return (None, -1, None, None);
    }
    // SAFETY: write end owned by this scope (the middleman
    // holds its own copy).
    unsafe {
        libc::close(write_fd);
    }
    if jam {
        // R21-008 jam: drop the read end before polling
        // (the middleman's report write fails EPIPE —
        // SIGPIPE is ignored process-wide — and it pauses
        // with the grandchild born), birth-gate on the
        // middleman's children file, then run the
        // production tail. The gate is load-bearing: a jam
        // without a born grandchild would be a VACUOUS
        // retirement regression (nothing to retire) — it
        // panics loud instead (m1 wedged pre-fork, or m1
        // self-exited pre-report — diagnosed, never
        // silently passed).
        // SAFETY: end owned by this scope.
        unsafe {
            libc::close(read_fd);
        }
        let gate_end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut born = false;
        // R23-019: the gate's children read already names
        // m2 (m1's only child) — parse it here so the
        // stake below pins the SAME observation (no
        // re-read between gate and stake).
        let mut gated_m2: Option<libc::pid_t> = None;
        let mut gate_corrupt = false;
        while std::time::Instant::now() < gate_end {
            if let Ok(kids) = std::fs::read_to_string(format!("/proc/{m1}/task/{m1}/children")) {
                if let Some(first) = kids.split_whitespace().next() {
                    match first.parse::<libc::pid_t>() {
                        Ok(m2) if m2 > 0 => {
                            gated_m2 = Some(m2);
                            born = true;
                            break;
                        }
                        _ => {
                            gate_corrupt = true;
                            break;
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if gate_corrupt {
            // R22-014 discipline (retire before failing
            // loud — the pausing m1 would strand).
            retire_reportless_middleman(m1);
            panic!("R21008-JAM: children file pid unparsable (kernel shape?) (m1 retired before failing loud)");
        }
        if !born {
            // R22-014: discharge BEFORE failing loud — a
            // wedged middleman pauses indefinitely and the
            // unwind would strand it (no caller holds
            // custody yet — the birth never gated).
            match stat_state_pgrp(m1) {
                Some((st, _)) => {
                    retire_reportless_middleman(m1);
                    panic!("R21008-JAM: birth-gate timed out with m1 {m1} alive-childless (state {st} — wedged pre-fork? box wedged?) (m1 retired before failing loud)")
                }
                None => {
                    reap_child_bounded(m1, "R21008-JAM");
                    panic!("R21008-JAM: birth-gate timed out with m1 {m1} dead pre-report (self-exit? — regression vacuous, failing loud) (corpse reaped before failing loud)")
                }
            }
        }
        // R23-019: stake m2's birth PRE-TAIL (m2 sleeps
        // `dur` — nothing kills it before the tail runs,
        // so a recycle between the gate read and this read
        // is impossible and no R23-009 re-verify is needed;
        // pre-exec is fine — the tick is fork-assigned).
        // The caller proves m2's death by birth-gone AND
        // scan-empty (either channel alone goes blind:
        // the scan under argv-shape lies (pre-exec or
        // exec-away staging — row-errors already panic
        // loud, never vacuous), the birth under same-tick
        // retake — the conjunction fails loud on any
        // single-channel lie).
        let m2 = gated_m2.expect("R21008-JAM: gate passed with no parsed m2 (unreachable)");
        let tick2 = match fork_starttime(m2) {
            Ok(Some(tick2)) => tick2,
            Ok(None) => {
                retire_reportless_middleman(m1);
                panic!("R21008-JAM: m2 {m2} dead before the tail ran (nothing targets it — box wedged?) (pair retired before failing loud)");
            }
            Err(error) => {
                retire_reportless_middleman(m1);
                panic!("R21008-JAM: m2 {m2} birth unreadable pre-tail: {error} (pair retired before failing loud)");
            }
        };
        // R23-019: retain m1's birth pre-tail (the gate
        // proved m1 live — nothing kills it before the
        // tail — so this read names OUR m1; the caller
        // proves m1's reap gone-or-recycled over it).
        let tick1 = match fork_starttime(m1) {
            Ok(Some(tick1)) => tick1,
            Ok(None) => {
                retire_reportless_middleman(m1);
                panic!("R21008-JAM: m1 {m1} dead before the tail ran (nothing targets it — box wedged?) (pair retired before failing loud)");
            }
            Err(error) => {
                retire_reportless_middleman(m1);
                panic!("R21008-JAM: m1 {m1} birth unreadable pre-tail: {error} (pair retired before failing loud)");
            }
        };
        if retire_on_jam {
            retire_reportless_middleman(m1);
        }
        return (None, m1, Some(tick1), Some((m2, tick2)));
    }
    // Bounded report read (the middleman reports in µs).
    let mut poller = libc::pollfd {
        fd: read_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: polls our own pipe end.
    let ready = unsafe { libc::poll(&mut poller, 1, 5000) };
    let mut report = String::new();
    let m2 = if ready > 0 {
        use std::io::BufRead as _;
        // SAFETY: read end owned by this scope (File takes
        // the OwnedFd for its Read impl).
        let owned = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(read_fd) };
        let mut reader = std::io::BufReader::new(std::fs::File::from(owned));
        if reader.read_line(&mut report).is_ok() {
            report.trim().parse::<libc::pid_t>().ok()
        } else {
            None
        }
    } else {
        // SAFETY: end owned by this scope.
        unsafe {
            libc::close(read_fd);
        }
        None
    };
    match m2 {
        // R23-019: the birth observations are JAM-arm
        // products (gated pre-tail) — the report arm names
        // m2's pid but pins no ticks (non-jam callers pin
        // their own; report-time liveness is the report's
        // own claim).
        Some(m2) if m2 > 0 => (Some((m1, m2)), m1, None, None),
        _ => {
            // Report failure: FULL retirement before None
            // (R21-008 — the old kill + single-WNOHANG tail
            // stranded m1 as a zombie and never touched
            // the unknown-pid m2).
            retire_reportless_middleman(m1);
            (None, m1, None, None)
        }
    }
}

/// Read the rendezvous slots. Sound in the forked child (plain atomic
/// loads); the parent must only call this while holding the fork mutex.
pub fn slots() -> (i32, i32, i32) {
    (
        SLOT_A.load(Ordering::Relaxed),
        SLOT_B.load(Ordering::Relaxed),
        SLOT_C.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R22-014: unwind custody for a jammed-spawn pair (m1
    /// known, m2 unknown — the report never arrived). The
    /// drop retires through the production reportless tail
    /// (freeze + group-kill + reap — panic-free and
    /// outage-proof through the fallback), so any pre-tail
    /// staging panic discharges the pausing middleman AND
    /// its unknown-pid sleeper instead of stranding them
    /// (no caller holds custody yet — the birth never
    /// gated). Disarm after the probe's own tail run.
    struct ReportlessPairGuard {
        m1: libc::pid_t,
        disarmed: bool,
    }

    impl ReportlessPairGuard {
        fn armed(m1: libc::pid_t) -> Self {
            ReportlessPairGuard {
                m1,
                disarmed: false,
            }
        }

        fn disarm(&mut self) {
            self.disarmed = true;
        }
    }

    impl Drop for ReportlessPairGuard {
        fn drop(&mut self) {
            if !self.disarmed {
                retire_reportless_middleman(self.m1);
            }
        }
    }

    /// R22-014: single-child unwind custody (fork-local —
    /// audit's `FixtureGuard` is module-private, and this
    /// file's pairs already ride `MiddlemanPairGuard`).
    /// Bare pin at birth: the caller must hold the
    /// unreaped-child reservation (own child, never
    /// reaped — the number cannot have recycled), so the
    /// drop's signal is sound even when the pinning read
    /// failed (falls back to a child-only waitpid probe
    /// first — ECHILD returns without signaling). A
    /// pinned birth re-verifies at drop (gone/recycled
    /// stays silent). Bounded reap (~1 s). Panic-free.
    /// Disarm after the owned reap.
    struct ForkChildGuard {
        pid: libc::pid_t,
        tick: Option<u64>,
        disarmed: bool,
    }

    impl ForkChildGuard {
        fn new(pid: libc::pid_t) -> Self {
            let tick = fork_starttime(pid).ok().flatten();
            ForkChildGuard {
                pid,
                tick,
                disarmed: false,
            }
        }

        /// R23-023 leg seam: an unpinned guard (the
        /// pinning read failed) — the drop must still kill
        /// + reap an owned live child, and must not read
        /// errno after a successful (==0) waitpid probe.
        fn for_test_unpinned(pid: libc::pid_t) -> Self {
            ForkChildGuard {
                pid,
                tick: None,
                disarmed: false,
            }
        }

        fn disarm(&mut self) {
            self.disarmed = true;
        }
    }

    impl Drop for ForkChildGuard {
        fn drop(&mut self) {
            if self.disarmed {
                return;
            }
            if let Some(tick) = self.tick {
                if fork_starttime(self.pid) != Ok(Some(tick)) {
                    return;
                }
                let _ = kill_tick_gated_fork(self.pid, tick);
            } else {
                let mut status = 0;
                // SAFETY: WNOHANG probe of a possibly-owned
                // child; never blocks.
                let got = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
                if got == self.pid {
                    return;
                }
                // R23-023: errno is meaningful only when
                // waitpid FAILED (got < 0) — a 0 (live,
                // unreaped) leaves stale errno behind.
                if got < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                {
                    return;
                }
                // SAFETY: our own unreaped child (the bare
                // reservation — the number cannot have
                // recycled under us).
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                }
            }
            let end = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                let mut status = 0;
                // SAFETY: WNOHANG reap of our own child.
                let got = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
                if got == self.pid
                    || (got < 0
                        && std::io::Error::last_os_error().raw_os_error()
                            == Some(libc::ECHILD))
                {
                    break;
                }
                if std::time::Instant::now() >= end {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }

    /// R23-023: an unpinned guard drop must kill + reap
    /// an owned live child even with stale ECHILD in
    /// errno (waitpid==0 leaves errno untouched — only a
    /// FAILED probe may consult it). RED (old drop: the
    /// stale ECHILD returns early — the child survives).
    #[test]
    fn fork_child_guard_unpinned_ignores_stale_echild() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("2")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sleeper spawns");
        let pid = child.id() as libc::pid_t;
        let tick = fork_starttime(pid)
            .expect("sleeper stat readable")
            .expect("sleeper visible");
        // Plant stale ECHILD immediately before the drop:
        // waitpid on init (never our child) fails ECHILD;
        // nothing between the plant and the drop's probe
        // may run (successful waitpid preserves errno, so
        // the drop's ==0 probe still observes ECHILD —
        // the old drop misread exactly this).
        let mut plant_status = 0;
        // SAFETY: WNOHANG probe of a definite non-child.
        let planted =
            unsafe { libc::waitpid(1, &mut plant_status, libc::WNOHANG) };
        assert_eq!(planted, -1, "init is not our child (errno plant)");
        {
            let _guard = ForkChildGuard::for_test_unpinned(pid);
        }
        assert_ne!(
            fork_starttime(pid),
            Ok(Some(tick)),
            "unpinned drop must kill the owned child despite stale ECHILD"
        );
        assert!(
            child.try_wait().is_err(),
            "unpinned drop must reap the owned child (status collected)"
        );
    }

    /// R22-014: fault-leg duration override — legs
    /// restage under a unique duration (sharing the
    /// GREEN duration would collide under parallel
    /// runs: the leg's sweep would murder the GREEN
    /// sleeper and vice versa). GREEN runs (env absent)
    /// keep the default.
    fn r22014_sleep_dur(default: &'static str) -> String {
        std::env::var("SCOPEBASE_R22014_SLEEP_DUR").unwrap_or_else(|_| default.to_string())
    }

    /// R21-017: call-path audit — no printf-family libc
    /// call in post-fork code (none of it is
    /// async-signal-safe after a multithreaded fork:
    /// inherited libc locks can deadlock). fork.rs is
    /// fork-path-dedicated: the ban covers everything
    /// above this test module (code and docs — the audit
    /// strings themselves live below, parent-side only).
    /// The toolchain twin's fork helpers are pinned by
    /// body extraction. Anti-vacuity: the checked regions
    /// must contain their helpers (markers found), so a
    /// refactor that moves the code fails instead of
    /// passing silently. RED: `snprintf` in both
    /// grandchild reporters. GREEN: hand-rolled decimal
    /// everywhere. The behavioral companion
    /// (`grandchild_reports_under_libc_contention`, both
    /// files) witnesses bounded reporting under libc
    /// hammering; THIS test is the deterministic pin (a
    /// printf deadlock is only probabilistic, so behavior
    /// alone cannot RED it). Full-line comments are
    /// excluded from the scan (they may NAME the ban to
    /// explain it); code lines and trailing remarks are
    /// scanned.
    #[test]
    fn post_fork_code_uses_no_printf_calls() {
        const BANNED: &[&str] = &[
            "snprintf",
            "sprintf(",
            "vsnprintf",
            "dprintf(",
            "vfprintf(",
            "fprintf(",
        ];
        let code_only = |text: &str| {
            text.lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fork_rs = std::fs::read_to_string(root.join("src/fixture/linux/fork.rs"))
            .expect("fork.rs readable");
        let (pre_test, _) = fork_rs
            .split_once("\nmod tests")
            .expect("fork.rs test module marker found");
        assert!(
            pre_test.contains("fn fork_pausing_grandchild_sleep"),
            "audited region must contain the grandchild reporter (anti-vacuity)"
        );
        let pre_test_code = code_only(pre_test);
        for banned in BANNED {
            assert!(
                !pre_test_code.contains(banned),
                "fork.rs post-fork code must not use {banned}"
            );
        }
        let twin = std::fs::read_to_string(root.join("tests/toolchain_invoke.rs"))
            .expect("toolchain twin readable");
        // R21-008: the twin's post-fork code lives in the
        // `_inner` helper now (the public wrapper only
        // delegates) — the pin tracks the audited code,
        // not the name.
        for name in ["fn fork_pauser(", "fn fork_pausing_grandchild_sleep_inner("] {
            let start = twin
                .find(name)
                .unwrap_or_else(|| panic!("twin helper {name} must exist"));
            let rest = &twin[start..];
            let end = rest
                .find("\n}\n")
                .unwrap_or_else(|| panic!("twin helper {name} must end at column 0"));
            let body = code_only(&rest[..end]);
            assert!(
                body.len() > 200 && body.contains("libc::"),
                "twin {name} body must be substantial (anti-vacuity)"
            );
            for banned in BANNED {
                assert!(
                    !body.contains(banned),
                    "twin {name} must not use {banned} post-fork"
                );
            }
        }
    }

    /// R22-008 follow-up: sleep-duration scan keys must be
    /// SUITE-DISJOINT — every `sleep NNN` argv staged by
    /// the fork lib tests, the toolchain twin, and the
    /// audit suite is a global key: a shared key lets one
    /// suite's custody scan see (or tick-gated-KILL)
    /// another suite's sleeper. Found the hard way: the
    /// reportless legs first shipped
    /// 951/953-956/959/963-964, ALL audit-held (re-keyed
    /// to 851/853-856/859/863-864). The 9xx space is ~92%
    /// spent — allocate REPO-WIDE (quoted, shell-embedded
    /// `sleep NNN`, and bare forms) before adding a key;
    /// THIS test enforces the disjointness (fork keys ∩
    /// audit argv = ∅, twin keys ∩ audit argv = ∅, fork
    /// keys ∩ twin keys = ∅). Convention pinned here:
    /// scan keys are 3-digit (the collectors only track
    /// 3-digit argv).
    #[test]
    fn sleep_scan_keys_disjoint_across_suites() {
        use std::collections::BTreeSet;
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fork_rs = std::fs::read_to_string(root.join("src/fixture/linux/fork.rs"))
            .expect("fork.rs readable");
        let twin_rs = std::fs::read_to_string(root.join("tests/toolchain_invoke.rs"))
            .expect("toolchain twin readable");
        let audit_rs = std::fs::read_to_string(root.join("src/fixture/linux/audit.rs"))
            .expect("audit.rs readable");
        // R23-019: first quoted 3-digit literal on a line
        // (publisher positionals put the dur before the
        // mode and envs, so FIRST is the dur; lines
        // without one contribute nothing).
        let first_quoted3 = |line: &str| -> Option<String> {
            let bytes = line.as_bytes();
            let mut i = 0;
            while i + 4 < bytes.len() + 1 {
                if bytes[i] == b'"'
                    && bytes[i + 1].is_ascii_digit()
                    && bytes[i + 2].is_ascii_digit()
                    && bytes[i + 3].is_ascii_digit()
                    && bytes.get(i + 4) == Some(&b'"')
                {
                    return Some(line[i + 1..i + 4].to_string());
                }
                i += 1;
            }
            None
        };
        // R23-019: first dot-arg triple on a line (direct
        // publisher spawns pass dur first, mode second).
        let first_dotarg3 = |line: &str| -> Option<String> {
            let at = line.find(".arg(\"")?;
            let after = &line[at + 6..];
            if after.len() >= 4
                && after.as_bytes()[..3].iter().all(|b| b.is_ascii_digit())
                && after.as_bytes()[3] == b'"'
            {
                Some(after[..3].to_string())
            } else {
                None
            }
        };
        // 3-digit argv at a fork/twin sleep call site:
        // helper-mediated (`*_with_dur("NNN")`,
        // `*noretire("NNN")`, `*jam_report("NNN")`,
        // `*grandchild_sleep("NNN")`) or direct
        // (`Command::new("/bin/sleep")` + `.arg("NNN")`
        // within 3 lines). R23-019: publisher leaf durs
        // too — every publisher spawn births a sleep leaf
        // carrying the publisher's dur, so a scan key
        // matching a publisher dur would read a foreign
        // leaf. The arms below cover the spawn shapes
        // (single-line, multi-line, direct, sh-wrapped,
        // cell-runner, cell-table). Wording here stays
        // trigger-free — this file is scanned text, so
        // doc examples never carry live call shapes.
        let scan_keys = |text: &str| -> BTreeSet<String> {
            let mut keys = BTreeSet::new();
            let lines: Vec<&str> = text.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                for trigger in [
                    "with_dur(\"",
                    "noretire(\"",
                    "jam_report(\"",
                    "grandchild_sleep(\"",
                    // R22-014: duration-override defaults
                    // (same keys, env-relocatable).
                    "sleep_dur(\"",
                    // R23-019 P1: single-line publisher
                    // spawns (the dur literal follows the
                    // call's open paren; multi-line spawns
                    // ride the peer arm below).
                    "publisher(\"",
                ] {
                    let mut rest = *line;
                    while let Some(at) = rest.find(trigger) {
                        let after = &rest[at + trigger.len()..];
                        if after.len() >= 4
                            && after.as_bytes()[..3].iter().all(|b| b.is_ascii_digit())
                            && after.as_bytes()[3] == b'"'
                        {
                            keys.insert(after[..3].to_string());
                        }
                        rest = after
                            .chars()
                            .next()
                            .map(|c| &after[c.len_utf8()..])
                            .unwrap_or("");
                    }
                }
                if line.contains("Command::new(\"/bin/sleep\")") {
                    for peer in lines.iter().skip(index + 1).take(3) {
                        if let Some(at) = peer.find(".arg(\"") {
                            let after = &peer[at + 6..];
                            if after.len() >= 4
                                && after.as_bytes()[..3].iter().all(|b| b.is_ascii_digit())
                                && after.as_bytes()[3] == b'"'
                            {
                                keys.insert(after[..3].to_string());
                            }
                        }
                    }
                }
                // R23-019 P2: multi-line publisher spawn —
                // the dur sits on a following line. The
                // peer scan runs ONLY when this line holds
                // no dur itself, so a following test's
                // literal is never misattributed here.
                if line.contains("publisher(") && first_quoted3(line).is_none() {
                    for peer in lines.iter().skip(index + 1).take(3) {
                        if let Some(dur) = first_quoted3(peer) {
                            keys.insert(dur);
                            break;
                        }
                    }
                }
                // R23-019 P3: direct publisher spawn — the
                // dur is the first dot-arg (variable durs
                // contribute nothing; their default literals
                // ride the override trigger or the table).
                if line.contains("Command::new(pair_publisher_bin())") {
                    for peer in lines.iter().skip(index + 1).take(5) {
                        if let Some(dur) = first_dotarg3(peer) {
                            keys.insert(dur);
                            break;
                        }
                    }
                }
                // R23-019 P4: shell-wrapped publisher spawn
                // (the bin path rides dot-arg — the dur
                // dot-arg follows it).
                if line.contains(".arg(pair_publisher_bin())") {
                    for peer in lines.iter().skip(index + 1).take(2) {
                        if let Some(dur) = first_dotarg3(peer) {
                            keys.insert(dur);
                            break;
                        }
                    }
                }
                // R23-019 P5: cell-runner calls (the secs
                // parameter is second — the step name is
                // never numeric and envs trail secs, so the
                // first triple on these lines is the dur;
                // variable-secs calls contribute nothing —
                // their literals ride the table below).
                if line.contains("run_pub_cell(") {
                    if let Some(dur) = first_quoted3(line) {
                        keys.insert(dur);
                    } else {
                        for peer in lines.iter().skip(index + 1).take(5) {
                            if let Some(dur) = first_quoted3(peer) {
                                keys.insert(dur);
                                break;
                            }
                        }
                    }
                }
                // R23-019 P6: fault-cell table rows —
                // lowercase step names only (uppercase env
                // tuples are excluded by the lowercase
                // gate; a future lowercase triple tuple is
                // collected conservatively — a collision
                // RED means re-key or narrow this arm).
                if let Some(open) = line.find("(\"") {
                    let name_start = open + 2;
                    if let Some(name_end) = line[name_start..].find('"') {
                        let name = &line[name_start..name_start + name_end];
                        if !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase()) {
                            let rest = &line[name_start + name_end + 1..];
                            if let Some(dur) = first_quoted3(rest) {
                                keys.insert(dur);
                            }
                        }
                    }
                }
            }
            keys
        };
        // Audit sleep argv (conservative superset): every
        // quoted 3-digit literal plus every shell-embedded
        // `sleep NNN`. (Counts/ports/bounds ride along —
        // a scan key matching ANY of them is rejected;
        // pick another key.)
        let audit_argv = |text: &str| -> BTreeSet<String> {
            let mut argv = BTreeSet::new();
            for line in text.lines() {
                let bytes = line.as_bytes();
                let mut i = 0;
                while i + 4 < bytes.len() + 1 {
                    if bytes[i] == b'"'
                        && bytes[i + 1].is_ascii_digit()
                        && bytes[i + 2].is_ascii_digit()
                        && bytes[i + 3].is_ascii_digit()
                        && bytes.get(i + 4) == Some(&b'"')
                    {
                        argv.insert(line[i + 1..i + 4].to_string());
                        i += 5;
                    } else {
                        i += 1;
                    }
                }
                let mut rest = line;
                while let Some(at) = rest.find("sleep ") {
                    let after = &rest[at + 6..];
                    let digits: String = after
                        .bytes()
                        .take_while(u8::is_ascii_digit)
                        .map(|b| b as char)
                        .collect();
                    if digits.len() == 3 {
                        argv.insert(digits);
                    }
                    rest = after
                        .chars()
                        .next()
                        .map(|c| &after[c.len_utf8()..])
                        .unwrap_or("");
                }
            }
            argv
        };
        let fork_keys = scan_keys(&fork_rs);
        let twin_keys = scan_keys(&twin_rs);
        let audit_keys = audit_argv(&audit_rs);
        // Anti-vacuity: the collectors find known keys
        // (a refactor that blinds them fails here,
        // never passes silently).
        assert!(
            fork_keys.contains("853"),
            "collector must find fork scan keys (got {fork_keys:?})"
        );
        assert!(
            twin_keys.contains("854"),
            "collector must find twin scan keys (got {twin_keys:?})"
        );
        assert!(
            audit_keys.contains("953"),
            "collector must find audit sleep argv (got {} keys)",
            audit_keys.len()
        );
        // R23-019: the publisher arms find known durs
        // (single-line, multi-line, direct, sh-wrapped,
        // cell single + multi, table).
        for (arm, dur) in [
            ("P1", "829"),
            ("P2", "828"),
            ("P3", "908"),
            ("P4", "105"),
            ("P5-single", "827"),
            ("P5-multi", "822"),
            ("P6-staying", "943"),
            ("P6-moved", "824"),
        ] {
            assert!(
                twin_keys.contains(dur),
                "collector {arm} must find twin publisher dur {dur} (got {twin_keys:?})"
            );
        }
        // R23-019: the cell peer-scan stops at the FIRST
        // triple (the dur precedes the envs — a timeout
        // collection would mean the env leaked in; audit
        // holds that triple, so the leak would also dupe).
        assert!(
            !twin_keys.contains("200"),
            "collector must not collect the cell timeout env (got {twin_keys:?})"
        );
        assert!(fork_keys.len() >= 5, "fork scan-key set implausibly small");
        assert!(twin_keys.len() >= 5, "twin scan-key set implausibly small");
        let fork_audit_dupes: Vec<_> = fork_keys.intersection(&audit_keys).collect();
        assert!(
            fork_audit_dupes.is_empty(),
            "fork scan keys {fork_audit_dupes:?} collide with audit sleep argv (re-key repo-wide)"
        );
        let twin_audit_dupes: Vec<_> = twin_keys.intersection(&audit_keys).collect();
        assert!(
            twin_audit_dupes.is_empty(),
            "twin scan/publisher keys {twin_audit_dupes:?} collide with audit sleep argv (re-key repo-wide)"
        );
        let fork_twin_dupes: Vec<_> = fork_keys.intersection(&twin_keys).collect();
        assert!(
            fork_twin_dupes.is_empty(),
            "scan/publisher keys {fork_twin_dupes:?} shared by fork lib + toolchain twin (re-key repo-wide)"
        );
    }

    /// R22-019: one allocator-hammer body (CPU + allocator
    /// churn while `stop` is clear). Nonblocking — always
    /// exits promptly once stopped.
    fn hammer_body(stop: &std::sync::atomic::AtomicBool) {
        use std::sync::atomic::Ordering;
        let mut n = 0u64;
        while !stop.load(Ordering::Relaxed) {
            let v: Vec<u8> = (0..1000u32).map(|x| (x ^ n as u32) as u8).collect();
            drop(format!("{:?}-{n}", &v[..8]));
            n += 1;
        }
    }

    /// R22-019: RAII contention-hammer set — drop sets stop
    /// and joins every STARTED worker (unwind-safe: a
    /// mid-loop panic stops + joins; a spawn failure
    /// mid-construction drops the partial set and joins
    /// the started subset — no detached burners on any
    /// path). Workers are cooperative (nonblocking
    /// bodies), so the joins always terminate promptly;
    /// panicked workers join as Err (ignored — the stop
    /// is what matters). `done` counts exited workers
    /// (test-observable acknowledgment — join-return is
    /// the primary proof, the counter corroborates).
    struct HammerSet {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        done: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        workers: Vec<std::thread::JoinHandle<()>>,
    }

    impl HammerSet {
        fn spawn(count: usize) -> Self {
            use std::sync::atomic::Ordering;
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            Self::spawn_on(count, stop, done, |stop, done| {
                std::thread::spawn(move || {
                    hammer_body(&stop);
                    done.fetch_add(1, Ordering::Relaxed);
                })
            })
        }

        /// R23-001: injectable spawner (the leg fails a
        /// spawn mid-construction). The set is built
        /// incrementally — a spawn panic drops the partial
        /// Self (stop set, started subset joined), never a
        /// bare Vec of detached handles.
        fn spawn_on(
            count: usize,
            stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
            done: std::sync::Arc<std::sync::atomic::AtomicUsize>,
            mut spawn_one: impl FnMut(
                std::sync::Arc<std::sync::atomic::AtomicBool>,
                std::sync::Arc<std::sync::atomic::AtomicUsize>,
            ) -> std::thread::JoinHandle<()>,
        ) -> Self {
            let mut set = Self {
                stop,
                done,
                workers: Vec::with_capacity(count),
            };
            for _ in 0..count {
                let (stop, done) = (set.stop.clone(), set.done.clone());
                set.workers.push(spawn_one(stop, done));
            }
            set
        }

        fn done_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
            self.done.clone()
        }
    }

    impl Drop for HammerSet {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            self.stop.store(true, Ordering::Relaxed);
            for worker in self.workers.drain(..) {
                let _ = worker.join();
            }
        }
    }

    /// R21-017: behavioral companion — bounded grandchild
    /// reporting under concurrent libc activity. Four
    /// threads hammer the allocator/formatter while five
    /// pairs stage; every report must arrive with valid
    /// pids (a printf-lock deadlock in the child would
    /// surface as report timeouts → `None`). Witness, not
    /// pin: a deadlock is probabilistic, so this passes
    /// pre-fix too — `post_fork_code_uses_no_printf_calls`
    /// is the deterministic pin. Duration 913 is unique to
    /// this test. Cleanup retires every pair (sleeper
    /// death-await, then middleman reaped).
    #[test]
    fn grandchild_reports_under_libc_contention() {
        // RAII hammers (stop + join on drop — success,
        // unwind, and partial-start paths alike).
        let _hammers = HammerSet::spawn(4);
        let retire = |m1: libc::pid_t, m2: libc::pid_t| {
            assert_eq!(
                unsafe { libc::kill(m2, libc::SIGKILL) },
                0,
                "sleeper signaled"
            );
            let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let dead = match std::fs::read_to_string(format!("/proc/{m2}/stat")) {
                    Err(_) => true,
                    Ok(text) => {
                        text.rsplit_once(") ")
                            .and_then(|(_, after)| after.split_whitespace().next())
                            == Some("Z")
                    }
                };
                if dead {
                    break;
                }
                assert!(std::time::Instant::now() < end, "sleeper must die");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert_eq!(
                unsafe { libc::kill(m1, libc::SIGKILL) },
                0,
                "middleman signaled"
            );
            let mut mst = 0;
            let mgot = unsafe { libc::waitpid(m1, &mut mst, 0) };
            assert_eq!(mgot, m1, "middleman status drains to us");
        };
        for _ in 0..5 {
            // SAFETY: multithreaded fork with a
            // syscall-only child (audited above).
            let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("913") }
                .expect("report must arrive bounded");
            // R21-009: guard at birth (the assert below
            // must not strand the pair).
            let mut pair = MiddlemanPairGuard::armed(m1, m2);
            assert!(m1 > 0 && m2 > 0 && m1 != m2, "pids must be valid");
            retire(m1, m2);
            pair.disarm();
        }
        // Hammers stop + join via `_hammers` drop (RAII —
        // same path as unwind and partial start).
        drop(_hammers);
    }

    /// R22-019: contention hammers acknowledge bounded
    /// termination on EVERY exit path — an injected
    /// mid-loop failure (report/retirement-failure shape)
    /// and a partial start (spawn-failure shape) must
    /// still stop + join every STARTED worker. The
    /// done-counter captures the unwind moment (RED: the
    /// manual stop/join-at-the-end shape bypasses the stop
    /// on unwind — handles lost, workers detached, done
    /// stays 0; GREEN: the RAII set joins on drop, so the
    /// counter reads full right after the unwind).
    #[test]
    fn contention_hammers_stop_on_unwind_and_partial_start() {
        use std::sync::atomic::Ordering;
        // Leg 1: injected mid-loop failure (the RAII set
        // drops at unwind — joined before catch returns).
        let set = HammerSet::spawn(4);
        let done = set.done_handle();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _set = set;
            for i in 0..5 {
                if i == 2 {
                    panic!("R22019 injected mid-loop failure");
                }
            }
        }));
        assert!(failed.is_err(), "injection must unwind");
        assert_eq!(
            done.load(Ordering::Relaxed),
            4,
            "every started worker must stop on unwind"
        );
        // Leg 2: partial start (2 workers, then a spawn
        // failure — the started subset must still stop).
        let set = HammerSet::spawn(2);
        let done = set.done_handle();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _set = set;
            panic!("R22019 simulated spawn failure");
        }));
        assert!(failed.is_err(), "spawn failure must unwind");
        assert_eq!(
            done.load(Ordering::Relaxed),
            2,
            "every started worker must stop on partial start"
        );
        // Leg 3 (R23-001): a REAL mid-construction spawn
        // failure — 2 workers start, the 3rd spawn panics
        // INSIDE the constructor. The partial Self must
        // drop (stop set, started subset joined): done
        // reads exactly 2 (RED, old code: the bare Vec
        // drops, handles detach, stop never set, done
        // stays 0).
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut calls = 0u32;
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _set = HammerSet::spawn_on(4, stop, done.clone(), |stop, done| {
                calls += 1;
                if calls == 3 {
                    panic!("R23001 injected mid-construction spawn failure");
                }
                std::thread::spawn(move || {
                    hammer_body(&stop);
                    done.fetch_add(1, Ordering::Relaxed);
                })
            });
        }));
        assert!(failed.is_err(), "spawn failure must unwind");
        assert_eq!(
            done.load(Ordering::Relaxed),
            2,
            "started subset must stop on mid-construction panic"
        );
    }

    /// R21-009: birth guard for a staged middleman pair —
    /// armed at fork (before the fallible stat reads);
    /// drop retires both (m2 blind-killed FIRST while m1
    /// lives — the middleman pauses until signaled, so
    /// m2's number is pinned; then m1 killed + reaped,
    /// bounded). Probe-first: m1 zombie (reaped by the
    /// probe) ⟹ m2 pin-killed via its birth pidfd (R22-007:
    /// m2 may live on — no pdeathsig/EOF; unpinned ⟹ loud
    /// unresolved); m1 gone/ECHILD (reaped by the tail,
    /// which kills m2 first) ⟹ the only sound early
    /// return. Disarm after the explicit tail.
    struct MiddlemanPairGuard {
        m1: libc::pid_t,
        m2: libc::pid_t,
        m2pin: Result<M2Pin, i32>,
        disarmed: bool,
    }

    /// R22-007: pidfd pin on m2's birth (fork-local mirror
    /// of audit's PidfdGuard — closes on drop). The pin
    /// names the BIRTH, not the number: killing through it
    /// can never land on a recycled occupant.
    struct M2Pin(libc::c_int);

    impl Drop for M2Pin {
        fn drop(&mut self) {
            // SAFETY: fd owned by this guard.
            unsafe { libc::close(self.0) };
        }
    }

    impl MiddlemanPairGuard {
        fn armed(m1: libc::pid_t, m2: libc::pid_t) -> Self {
            // Pin m2's birth NOW (infallible: Err(errno) on
            // denial/unsupported — silent here, LOUD if the
            // zombie path ever runs unpinned).
            let m2pin = super::super::seccomp::pidfd_open_raw(m2).map(M2Pin);
            MiddlemanPairGuard {
                m1,
                m2,
                m2pin,
                disarmed: false,
            }
        }
        fn disarm(&mut self) {
            self.disarmed = true;
        }
    }

    impl Drop for MiddlemanPairGuard {
        fn drop(&mut self) {
            if self.disarmed {
                return;
            }
            let mut st = 0;
            // SAFETY: WNOHANG probe of our own child.
            let probed = unsafe { libc::waitpid(self.m1, &mut st, libc::WNOHANG) };
            if probed > 0 {
                // R22-007: m1 ZOMBIE (reaped by the probe) —
                // m2 may LIVE ON as an orphan (no
                // pdeathsig/EOF channel — R21-008 verified;
                // the old "dead-orphaned draining to init"
                // rationale was false). Kill m2 via the
                // birth pin (sound forever — the pin names
                // the birth, not the number, so a recycled
                // occupant is unaddressable; ESRCH ⟹ m2
                // already drained, harmless). Init reaps
                // the orphan (nothing to wait — not ours).
                match &self.m2pin {
                    Ok(pin) => {
                        // SAFETY: pidfd_send_signal to our
                        // pinned grandchild-birth only.
                        let sent = unsafe {
                            libc::syscall(libc::SYS_pidfd_send_signal, pin.0, libc::SIGKILL, 0, 0)
                        };
                        // R23-013: a successful pidfd_open does
                        // not guarantee signaling is permitted
                        // — a denied signal silently abandoned
                        // m2. ESRCH ⟹ m2 already drained
                        // (harmless, silent); anything else
                        // goes loud with m2's identity (the
                        // caller retires the survivor via
                        // transmitted custody).
                        if sent != 0 {
                            let errno = std::io::Error::last_os_error()
                                .raw_os_error()
                                .unwrap_or(-999);
                            if errno != libc::ESRCH {
                                eprintln!(
                                    "R22007-PIN-DENIED middleman m1={} zombie-reaped, m2={} signal denied \
                                     (errno {errno}) — m2 birth surviving, custody unresolved \
                                     (caller owns the residual via transmitted custody)",
                                    self.m1, self.m2
                                );
                            }
                        }
                    }
                    Err(errno) => {
                        eprintln!(
                            "R22007-UNPINNED middleman m1={} zombie-reaped, m2={} unpinned \
                             (pin denied: errno {errno}) — m2 may survive (no safe signal \
                             exists; caller owns the residual)",
                            self.m1, self.m2
                        );
                    }
                }
                return;
            }
            if probed < 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(-999);
                if errno == libc::ECHILD {
                    // m1 gone (reaped by the tail): the ONLY
                    // sound early return — and only because
                    // the tail kills m2 FIRST (tail
                    // contract: m2 already dead).
                    return;
                }
                // Unexpected probe errno (EINTR-ish —
                // WNOHANG barely blocks): m1's state is
                // unknown and its NUMBER is unpinned (never
                // touch it — recycle-murder), but the m2
                // pin (when held) is still sound — kill
                // through it, then report loud.
                // R23-013: same denied-signal discipline as the
                // zombie arm above (this arm is ~unstageable
                // — EINTR-ish waitpid failure — so the leg
                // covers the zombie arm; the shape is shared).
                if let Ok(pin) = &self.m2pin {
                    // SAFETY: pidfd_send_signal to our
                    // pinned grandchild-birth only.
                    let sent = unsafe {
                        libc::syscall(libc::SYS_pidfd_send_signal, pin.0, libc::SIGKILL, 0, 0)
                    };
                    if sent != 0 {
                        let sig_errno = std::io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(-999);
                        if sig_errno != libc::ESRCH {
                            eprintln!(
                                "R22007-PIN-DENIED middleman m1={} probe-error, m2={} signal denied \
                                 (errno {sig_errno}) — m2 birth surviving, custody unresolved \
                                 (caller owns the residual via transmitted custody)",
                                self.m1, self.m2
                            );
                        }
                    }
                }
                eprintln!(
                    "R22007-PROBE m1={} probe failed (errno {errno} — m1 state unknown, \
                     number untouched); m2={} pin-kill attempted when pinned",
                    self.m1, self.m2
                );
                return;
            }
            // m1 live: m2's number is pinned — blind kill
            // sound.
            // SAFETY: signal-only to the pinned grandchild.
            unsafe {
                libc::kill(self.m2, libc::SIGKILL);
            }
            // SAFETY: signal-only to our own child.
            unsafe {
                libc::kill(self.m1, libc::SIGKILL);
            }
            let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                // SAFETY: WNOHANG reap of our own child.
                if unsafe { libc::waitpid(self.m1, &mut st, libc::WNOHANG) } != 0 {
                    return;
                }
                if std::time::Instant::now() >= end {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    /// R20-005: the grandchild helper reports the true
    /// grandchild pid; the grandchild is our non-child
    /// (parented to the live middleman — no subreaper
    /// assumption) with null stdio (it must not inherit
    /// test stdio write ends). Cleanup retires both.
    #[test]
    fn pausing_grandchild_sleep_reports_nonchild() {
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("910") }.expect("grandchild staged");
        // R21-009: guard at birth (before the fallible
        // stat reads below).
        let mut pair = MiddlemanPairGuard::armed(m1, m2);
        // stat fields after ") ": state ppid ... starttime
        // (rsplit: a comm containing ") " must not shift the
        // fields).
        let fields = |pid: libc::pid_t| -> Vec<String> {
            let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat readable");
            let after = text.rsplit_once(") ").map(|x| x.1).expect("comm stripped");
            after.split_whitespace().map(str::to_string).collect()
        };
        let m2fields = fields(m2);
        assert_eq!(
            m2fields[1].parse::<libc::pid_t>().expect("ppid parses"),
            m1,
            "grandchild must be parented to the live middleman"
        );
        // Birth pin for the exec-race retry below.
        let m2tick = fork_starttime(m2)
            .expect("grandchild stat readable")
            .expect("grandchild visible");
        for fd in [0, 1, 2] {
            // The pid report precedes m2's exec — mid-exec
            // m2 is transiently non-dumpable and its fd dir
            // can EACCES. Bounded same-birth retries (a
            // recycled number or persistent denial still
            // fails loud).
            let start = std::time::Instant::now();
            let link = loop {
                match std::fs::read_link(format!("/proc/{m2}/fd/{fd}")) {
                    Ok(link) => break link,
                    Err(error)
                        if error.raw_os_error() == Some(libc::EACCES)
                            && start.elapsed() < std::time::Duration::from_secs(2)
                            && fork_starttime(m2) == Ok(Some(m2tick)) =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!(
                        "stdio readable (fd {fd} of grandchild {m2} under {m1}): {error:?}"
                    ),
                }
            };
            assert_eq!(
                link.to_string_lossy(),
                "/dev/null",
                "grandchild stdio must be null"
            );
        }
        // Non-child: waitpid must refuse (ECHILD), never
        // report status.
        let mut st = 0;
        let got = unsafe { libc::waitpid(m2, &mut st, libc::WNOHANG) };
        assert!(got < 0, "grandchild must not be our child");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "non-child waitpid must refuse ECHILD"
        );
        // Cleanup: the sleeper (signaled by pid — live,
        // verified above), then the middleman (reaped —
        // ours). The sleeper zombifies under the pausing
        // middleman (never reaped until the middleman dies),
        // so death is unreadable-or-Z, not unreadable.
        assert_eq!(
            unsafe { libc::kill(m2, libc::SIGKILL) },
            0,
            "sleeper signaled"
        );
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let dead = match std::fs::read_to_string(format!("/proc/{m2}/stat")) {
                Err(_) => true,
                Ok(text) => {
                    text.rsplit_once(") ")
                        .and_then(|(_, after)| after.split_whitespace().next())
                        == Some("Z")
                }
            };
            if dead {
                break;
            }
            assert!(std::time::Instant::now() < end, "sleeper must die");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            unsafe { libc::kill(m1, libc::SIGKILL) },
            0,
            "middleman signaled"
        );
        let mut mst = 0;
        let mgot = unsafe { libc::waitpid(m1, &mut mst, 0) };
        assert_eq!(mgot, m1, "middleman status drains to us");
        pair.disarm();
    }

    /// R21-008: true when a LIVE (non-zombie) `sleep dur`
    /// exists anywhere in /proc. A zombie sleeper proves
    /// death (accepted — reaping an orphaned-adopted
    /// zombie is init's job, and a subreaper-adopted one
    /// reaps at process exit); only a LIVE sleeper is a
    /// strand. Unreadable /proc or an unreadable stat
    /// fails loud (fail-closed — absence must be proven,
    /// never assumed); a pid vanishing mid-scan is dead
    /// (skipped). R22-016(a): entry / cmdline read errors
    /// other than NotFound fail LOUD too (one free slot
    /// plus EMFILE ⟹ opendir consumes it and every
    /// cmdline read fails — swallowing that is false
    /// absence over live m2). R23-008: ownership-scoped
    /// (euid + session; window off) — absence means OUR
    /// fixture drained.
    fn live_sleep_with_dur(dur: &str) -> bool {
        !sleep_owned_pids_with_dur(dur, 0).is_empty()
    }

    /// R21-008: a jammed report post-second-fork fully
    /// retires before `None` — m1 reaped (/proc absence on
    /// the exposed pid — touch-free, never steals: R22-004)
    /// and the
    /// unknown-pid m2 dead (no LIVE `sleep 957` anywhere
    /// within the bound — absence or zombie both prove
    /// death; 957 is unique to this test, and the 957 s
    /// timeout dwarfs the 10 s bound, so a timely death
    /// proves the kill, never a natural timeout). The
    /// helper birth-gates m2 (panics loud when unborn —
    /// this regression is never vacuous). RED: the old
    /// tail (kill + single WNOHANG, no grouping) strands
    /// m2 live — the scan leg fails. (A RED strand is
    /// inert — m2 holds no test fds (stdio-null,
    /// CLOEXEC'd report) — and self-cleans in ≤957 s;
    /// GREEN never strands.)
    #[test]
    fn jammed_report_retires_both_before_none() {
        let outcome = unsafe { fork_pausing_grandchild_sleep_jam_report("957") };
        assert!(
            outcome.result.is_none(),
            "jammed report must yield None (tail ran)"
        );
        assert!(outcome.m1 > 0, "jam exposes m1 for the reap proof");
        let m1 = outcome.m1;
        // R23-019: the pre-tail births (the gate proved
        // both live — always Some here, panicking rather
        // than returning unstaked).
        let tick1 = outcome
            .tick1
            .expect("jam gate retains m1 pre-tail (staging?)");
        let (m2, tick2) = outcome
            .m2_stake
            .expect("jam gate stakes m2 pre-tail (staging?)");
        // m1 reaped — the INDEPENDENT proof (the tail's
        // own claim is not evidence; gone-or-recycled over
        // the retained birth, never a wait — a recycled
        // sibling zombie would lose its status to a waitpid
        // here: R22-004(a)).
        match prove_reaped_gone_or_recycled(m1, tick1) {
            ReapedProof::Gone | ReapedProof::Recycled(_) => {}
            ReapedProof::StillOurs => panic!(
                "RED: our m1 birth {m1}/{tick1} still present (tail did not reap?)"
            ),
            ReapedProof::Unreadable(error) => {
                panic!("inconclusive (m1 unreadable: {error}) — refusing to certify")
            }
        }
        // m2 dead: poll for no LIVE sleep-957 (bounded —
        // the tail's post-reap probe already proved the
        // group empty; this scan is the independent leg,
        // absorbing init's reap latency either way zombies
        // count for killpg).
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while live_sleep_with_dur("957") {
            assert!(
                std::time::Instant::now() < end,
                "RED: unknown-pid m2 stranded live past the jammed report"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // R23-019: birth-gone (the scan poll above is ONE
        // channel — a scan blinded by argv-shape lies
        // (pre-exec/exec-away) would pass it over a live
        // m2; the gate-staked birth is the second channel).
        // Recorded BEFORE cleanup (a live m2 here is RED —
        // retired below so RED runs stay clean; the verdict
        // judges the recorded proof, never the post-cleanup
        // state).
        let m2_proof = prove_reaped_gone_or_recycled(m2, tick2);
        kill_tick_gated_fork(m2, tick2);
        birth_drained(m2, tick2, std::time::Duration::from_secs(5));
        match m2_proof {
            ReapedProof::Gone | ReapedProof::Recycled(_) => {}
            ReapedProof::StillOurs => panic!(
                "RED: staked m2 birth {m2}/{tick2} still live past the jammed report (scan said empty — blind?)"
            ),
            ReapedProof::Unreadable(error) => panic!(
                "inconclusive (m2 birth unreadable: {error}) — refusing to certify"
            ),
        }
        // R23-019 recycle leg: a different-birth occupant on
        // the freed m1 number keeps retirement evidence valid
        // (the proof reads Recycled) while the vacancy-only
        // check reports inconclusive (never certified, never
        // a cleanup defect).
        let _serial = match fork_steer_hold() {
            Some(guard) => guard,
            None => return,
        };
        let (mut plant, plant_tick) = match fork_plant_sleep_onto(m1, "31", tick1) {
            Some(placed) => placed,
            None => {
                eprintln!("R23019-LEG[957] vacuous (plant contended)");
                return;
            }
        };
        eprintln!("R23019-LEG[957] plant {m1}/{plant_tick} (victim tick {tick1})");
        assert!(
            plant_tick != tick1,
            "staging broken (plant shares the victim tick?)"
        );
        let mut _pguard = ForkChildGuard::new(m1);
        match prove_reaped_gone_or_recycled(m1, tick1) {
            ReapedProof::Recycled(now) if now == plant_tick => {}
            ReapedProof::Recycled(now) => panic!(
                "staging broken (stranger birth {now} on our steered number {m1}?)"
            ),
            ReapedProof::StillOurs => panic!(
                "RED: our reaped birth {m1}/{tick1} reads present (tick collision?)"
            ),
            ReapedProof::Gone => panic!("staging broken (plant vanished?)"),
            ReapedProof::Unreadable(error) => {
                panic!("inconclusive (plant unreadable: {error}) — refusing to certify")
            }
        }
        assert_eq!(
            prove_reaped_by_absence(m1),
            Ok(false),
            "vacancy-only check must read inconclusive over the recycled occupant (never certified, never defect)"
        );
        let _ = plant.kill();
        let _ = plant.wait();
        _pguard.disarm();
    }

    /// R22-008 fallback probe (fresh image): stage the jam
    /// pair healthy (m2 birth-gated), print custody, THEN
    /// exhaust the fd table (stat outage — every
    /// `stat_state_pgrp` reads None) and run the
    /// reportless tail into the 5 s fallback. The fallback
    /// must group-kill UNCONDITIONALLY (m1 is unreaped —
    /// pinned — so group m1 is ours-or-nonexistent and the
    /// killpg is sound either way); the old
    /// `is_some_and(pgrp == m1)` gate re-reads None under
    /// the outage and SUPPRESSES the kill (m1 killed +
    /// reaped, already-born m2 stranded). RED (old gate:
    /// live `sleep 853` survives the probe). Duration 853
    /// is unique to this test.
    fn reportless_fallback_kills_group_unconditionally_probe() {
        let dur = r22014_sleep_dur("853");
        let (m1, m2, tick2) =
            unsafe { fork_pausing_grandchild_sleep_jam_noretire(&dur) }
                .expect("staging broken (pair spawn)");
        let mut _pair = ReportlessPairGuard::armed(m1);
        let tick1 = fork_starttime(m1)
            .expect("staging broken (m1 stat)")
            .expect("staging broken (m1 visible)");
        println!("R22008-M1 {m1} {tick1}");
        // R23-019: the gate-staked m2 birth rides stdout
        // with M1 (pre-outage — the wrapper proves m2's
        // death birth-aware instead of scan-only).
        println!("R22008-M2 {m2} {tick2}");
        std::io::Write::flush(&mut std::io::stdout()).expect("custody line flushed");
        // R22-014 fault leg: staged pre-tail panic (the
        // pair guard must discharge m1+m2 through the
        // unwind — post-print, so the leg names the
        // birth; the pre-print window discharges
        // identically in-probe).
        if std::env::var("SCOPEBASE_R22014_PAIR_PANIC").is_ok() {
            panic!("staged pre-tail panic (R22-014 pair-discharge regression)");
        }
        let hold = OutageHold::exhaust();
        // Anti-vacuity: the outage bites (live m1's stat
        // unreadable — the freeze-await below burns 5 s of
        // None into the fallback, exactly the finding's
        // shape).
        assert!(
            stat_state_pgrp(m1).is_none(),
            "staging broken (stat readable under the hold?)"
        );
        retire_reportless_middleman(m1);
        _pair.disarm();
        drop(hold);
        eprintln!("R22008-DONE");
    }

    /// R22-008 fallback wrapper: the probe runs
    /// fresh-image (the outage is process-global).
    /// Wrapper-side custody (m1 numeric + scan-kill `sleep
    /// 853`) runs BEFORE the verdict asserts so RED runs
    /// stay clean; the tail's own retirement is recorded
    /// BEFORE custody kills (never judged after).
    #[test]
    fn reportless_fallback_kills_group_unconditionally() {
        if std::env::var("SCOPEBASE_R22008_FALLBACK").is_ok() {
            reportless_fallback_kills_group_unconditionally_probe();
            return;
        }
        // R23-008: ownership-window anchor — wrapper entry
        // (before the probe stages anything).
        let anchor = boot_ticks_now().expect("custody anchor needs the boot clock");
        let outcome = run_fresh_probe_collect(
            "SCOPEBASE_R22008_FALLBACK",
            "reportless_fallback_kills_group_unconditionally",
        );
        let stdout = String::from_utf8_lossy(&outcome.out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&outcome.out.stderr).into_owned();
        let (m1, tick1): (libc::pid_t, u64) = stdout
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22008-M1 ")?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
            .expect("staging broken (no m1 line?)");
        // R23-019: the gate-staked m2 birth (printed
        // pre-outage with M1 — present in GREEN and RED;
        // the tail runs after the print either way).
        let (m2, tick2): (libc::pid_t, u64) = stdout
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22008-M2 ")?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
            .expect("staging broken (no m2 line?)");
        // Settle: the tail's kill lands in ms; a stranded
        // m2 (RED) stays live past the bound.
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while live_sleep_with_dur("853") {
            if std::time::Instant::now() >= end {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let retired_by_tail = !live_sleep_with_dur("853");
        // R23-019: the birth channel, recorded BEFORE
        // custody kills (a scan blinded by argv-shape lies
        // would certify a live m2 above — the staked birth
        // refuses that false absence; row-errors already
        // panic loud).
        let m2_proof = prove_reaped_gone_or_recycled(m2, tick2);
        // Custody BEFORE verdicts (RED runs stay clean):
        // m1 tick-gated, then m2 by its STAKED birth (no
        // scan — the stake names the exact birth), then
        // the scan backstop asserting nothing 853 remains.
        kill_tick_gated_fork(m1, tick1);
        assert!(
            birth_drained(m1, tick1, std::time::Duration::from_secs(5)),
            "wrapper must drain m1"
        );
        kill_tick_gated_fork(m2, tick2);
        assert!(
            birth_drained(m2, tick2, std::time::Duration::from_secs(5)),
            "wrapper must drain m2"
        );
        assert!(
            kill_sleep_with_dur("853", anchor),
            "scan backstop must find no residual sleep 853"
        );
        assert!(!outcome.timed_out, "probe must complete\n{stderr}");
        assert!(outcome.out.status.success(), "probe must exit 0\n{stderr}");
        assert!(
            stderr.contains("R21008-FALLBACK"),
            "probe must take the fallback path\n{stderr}"
        );
        assert!(
            retired_by_tail,
            "RED: fallback suppressed the group-kill (live m2 past the tail)"
        );
        match m2_proof {
            ReapedProof::Gone | ReapedProof::Recycled(_) => {}
            ReapedProof::StillOurs => panic!(
                "RED: staked m2 birth {m2}/{tick2} still live past the tail (scan said empty — blind?)"
            ),
            ReapedProof::Unreadable(error) => panic!(
                "inconclusive (m2 birth unreadable: {error}) — refusing to certify"
            ),
        }
        assert!(
            stderr.contains("R22008-DONE"),
            "probe must cite completion\n{stderr}"
        );
        assert!(
            stderr.contains("R22008-ASSUMED-GROUPED"),
            "fallback must cite the assumed-grouped kill\n{stderr}"
        );
    }

    /// R23-008: a STALE unrelated `sleep 871` (born before
    /// the backstop runs) must survive `kill_sleep_with_dur`;
    /// only the fresh fixture birth is retired. RED (old
    /// duration-only scan: the stale sleeper is killed too).
    /// Duration 871 is unique to this test.
    /// R23-008/009: leg-local drop guard (kill-only —
    /// detached reapers or explicit waitpids handle the
    /// reap, so the drop never blocks or panics).
    /// Pre-pin (`None`) the raw kill is still sound: the
    /// target is our own unreaped child (the reservation
    /// holds from spawn).
    struct LegChildGuard {
        pid: libc::pid_t,
        tick: Option<u64>,
        disarmed: bool,
    }
    impl Drop for LegChildGuard {
        fn drop(&mut self) {
            if self.disarmed {
                return;
            }
            match self.tick {
                Some(tick) => {
                    kill_tick_gated_fork(self.pid, tick);
                }
                None => {
                    // SAFETY: signal to our own unreaped
                    // child (or ESRCH nop); errors ignored.
                    unsafe {
                        libc::kill(self.pid, libc::SIGKILL);
                    }
                }
            }
        }
    }

    #[test]
    fn r22008_backstop_spares_stale_unrelated_sleeper() {
        use std::time::Duration;
        // 1. Unrelated FIRST (stale by backstop time — the
        // 25 ms sleep crosses a jiffy boundary, so its tick
        // is strictly below the kill-time anchor). `sleep`
        // (PATH-searched) keeps argv0 bare — the fork
        // scanners match fork-shape-exact argv0.
        let unrelated = std::process::Command::new("sleep")
            .arg("871")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("staging broken (unrelated spawn)");
        let upid = unrelated.id() as libc::pid_t;
        let mut _uguard = LegChildGuard {
            pid: upid,
            tick: None,
            disarmed: false,
        };
        std::thread::spawn(move || {
            let mut status = 0;
            // SAFETY: waitpid on the known own child; errors ignored.
            unsafe {
                libc::waitpid(upid, &mut status, 0);
            }
        });
        let utick = fork_starttime(upid)
            .expect("staging broken (unrelated stat)")
            .expect("staging broken (unrelated visible)");
        _uguard.tick = Some(utick);
        std::thread::sleep(Duration::from_millis(25));
        // Ownership anchor: post-stale-sleep (strictly past
        // the unrelated's tick), pre-fixture (at-or-before
        // the fixture's tick) — deterministic both sides.
        let anchor = boot_ticks_now().expect("staging broken (boot clock)");
        // 2. The faulted fixture: a fresh sleep-871 of
        // unknown birth (the backstop shape — direct, no
        // line).
        let fixture = std::process::Command::new("sleep")
            .arg("871")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("staging broken (fixture spawn)");
        let fpid = fixture.id() as libc::pid_t;
        let mut _fguard = LegChildGuard {
            pid: fpid,
            tick: None,
            disarmed: false,
        };
        std::thread::spawn(move || {
            let mut status = 0;
            // SAFETY: waitpid on the known own child; errors ignored.
            unsafe {
                libc::waitpid(fpid, &mut status, 0);
            }
        });
        let ftick = fork_starttime(fpid)
            .expect("staging broken (fixture stat)")
            .expect("staging broken (fixture visible)");
        _fguard.tick = Some(ftick);
        assert!(
            ftick > utick,
            "staging broken (staleness unreal: {utick} vs {ftick})"
        );
        assert_eq!(
            sleep_pids_with_dur("871").len(),
            2,
            "staging broken (scan must see both sleep-871 births)"
        );
        // 3. The wrapper's backstop path, direct.
        assert!(
            kill_sleep_with_dur("871", anchor),
            "backstop must drain the fixture"
        );
        // 4. Fixture birth drained; unrelated survives as
        // the SAME birth.
        match fork_starttime(fpid) {
            Ok(None) => {}
            Ok(Some(now)) => assert_ne!(now, ftick, "fixture birth must be retired"),
            Err(error) => panic!("fixture drainage unverifiable: {error}"),
        }
        assert_eq!(
            fork_starttime(upid),
            Ok(Some(utick)),
            "stale unrelated sleeper must survive as the same birth"
        );
        // 5. Explicit retire (no litter) + disarm + reap.
        kill_tick_gated_fork(upid, utick);
        assert!(
            birth_drained(upid, utick, Duration::from_secs(5)),
            "unrelated retire must land"
        );
        _uguard.disarmed = true;
        kill_tick_gated_fork(fpid, ftick);
        assert!(
            birth_drained(fpid, ftick, Duration::from_secs(5)),
            "fixture retire must land"
        );
        _fguard.disarmed = true;
    }

    /// R24-001 (fork twin): the ownership-window anchor
    /// must source CLOCK_BOOTTIME (the starttime domain —
    /// MONOTONIC excludes suspend). Source-text leg (see
    /// the audit twin for the rationale): requires the
    /// BOOTTIME constant in `boot_ticks_now`'s body.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r24001_anchor_clock_source_is_boottime() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let src = std::fs::read_to_string(root.join("src/fixture/linux/fork.rs"))
            .expect("own source readable");
        assert_eq!(
            src.match_indices("\n    fn boot_ticks_now").count(),
            1,
            "exactly one anchor fn (rename breaks this leg loudly)"
        );
        let start = src
            .find("\n    fn boot_ticks_now")
            .expect("anchor fn present");
        let rel = src[start..].find('{').expect("anchor body opens");
        let body_start = start + rel;
        let mut depth = 0usize;
        let mut end = None;
        for (i, ch) in src[body_start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(body_start + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &src[body_start..end.expect("anchor body closes")];
        assert!(
            body.contains("CLOCK_BOOTTIME"),
            "anchor must source CLOCK_BOOTTIME (the starttime domain)"
        );
        assert!(
            !body.contains("CLOCK_MONOTONIC"),
            "anchor must not source CLOCK_MONOTONIC (excludes suspend)"
        );
    }

    /// R24-001 (fork twin): synthetic 600 s-lag control —
    /// the lagged anchor admits the stale birth while the
    /// real anchor excludes it; a post-anchor birth
    /// includes. Mirror of the audit leg (bare-`sleep`
    /// argv0, the fork scanner). Duration 801 is unique
    /// to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r24001_lagged_anchor_shape_admits_real_anchor_excludes() {
        use std::time::Duration;
        let stale = std::process::Command::new("sleep")
            .arg("801")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("staging broken (stale spawn)");
        let spid = stale.id() as libc::pid_t;
        let mut _sguard = LegChildGuard {
            pid: spid,
            tick: None,
            disarmed: false,
        };
        // Detached reaper (the drain below polls for
        // tick-gone, but our own children zombie until
        // reaped — same shape as the stale-sleeper leg).
        std::thread::spawn(move || {
            let mut status = 0;
            // SAFETY: waitpid on the known own child; errors ignored.
            unsafe {
                libc::waitpid(spid, &mut status, 0);
            }
        });
        let stick = fork_starttime(spid)
            .expect("staging broken (stale stat)")
            .expect("staging broken (stale visible)");
        _sguard.tick = Some(stick);
        std::thread::sleep(Duration::from_millis(25));
        let anchor = boot_ticks_now().expect("staging broken (boot clock)");
        assert!(
            stick < anchor,
            "staging broken (anchor did not advance past the plant: {stick} vs {anchor})"
        );
        let lagged = anchor.saturating_sub(60_000);
        let admitted: Vec<libc::pid_t> = sleep_owned_pids_with_dur("801", lagged)
            .into_iter()
            .map(|(pid, _)| pid)
            .collect();
        assert!(
            admitted.contains(&spid),
            "lagged anchor must admit the stale birth (control broken?)"
        );
        let excluded: Vec<libc::pid_t> = sleep_owned_pids_with_dur("801", anchor)
            .into_iter()
            .map(|(pid, _)| pid)
            .collect();
        assert!(
            !excluded.contains(&spid),
            "real anchor must exclude the stale birth (anchor lags like post-suspend monotonic?)"
        );
        let fresh = std::process::Command::new("sleep")
            .arg("801")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("staging broken (fresh spawn)");
        let fpid = fresh.id() as libc::pid_t;
        let mut _fguard = LegChildGuard {
            pid: fpid,
            tick: None,
            disarmed: false,
        };
        std::thread::spawn(move || {
            let mut status = 0;
            // SAFETY: waitpid on the known own child; errors ignored.
            unsafe {
                libc::waitpid(fpid, &mut status, 0);
            }
        });
        let included: Vec<libc::pid_t> = sleep_owned_pids_with_dur("801", anchor)
            .into_iter()
            .map(|(pid, _)| pid)
            .collect();
        assert!(
            included.contains(&fpid),
            "post-anchor birth must be included (overcorrection?)"
        );
        assert!(
            !included.contains(&spid),
            "stale birth must stay excluded beside a fresh one"
        );
        kill_tick_gated_fork(spid, stick);
        assert!(
            birth_drained(spid, stick, Duration::from_secs(5)),
            "stale retire must land"
        );
        _sguard.disarmed = true;
        let ftick = fork_starttime(fpid)
            .expect("staging broken (fresh stat)")
            .expect("staging broken (fresh visible)");
        _fguard.tick = Some(ftick);
        kill_tick_gated_fork(fpid, ftick);
        assert!(
            birth_drained(fpid, ftick, Duration::from_secs(5)),
            "fresh retire must land"
        );
        _fguard.disarmed = true;
    }

    /// R23-008 (fork twin): our invocation owns a
    /// DEDICATED session (shared `ensure_dedicated_session`
    /// — same crate, same image as the audit twin).
    /// Mirror of the audit dedication leg.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r23008_session_dedicated_to_invocation() {
        use super::super::DedicatedSession;
        match super::super::ensure_dedicated_session() {
            DedicatedSession::Unavailable | DedicatedSession::SharedWithWrapper => {
                eprintln!("skip: session dedication unavailable (group leader?)");
                return;
            }
            DedicatedSession::BySetsid | DedicatedSession::ByBirth => {}
        }
        // SAFETY: getsid/getpid/getppid queries only.
        let me = unsafe { libc::getpid() };
        let sid = unsafe { libc::getsid(0) };
        let parent = unsafe { libc::getppid() };
        let psid = unsafe { libc::getsid(parent) };
        assert_eq!(
            sid, me,
            "test binary must lead its own session (dedicated by setsid)"
        );
        assert_ne!(
            sid, psid,
            "test session must differ from the invoker's session"
        );
    }

    /// R23-008 (fork twin): a post-anchor UNRELATED birth
    /// in a foreign session must survive the backstop
    /// while our own post-anchor fixture drains. Mirror
    /// of the audit leg (bare-`sleep` argv0, the fork
    /// backstop). Duration 804 is unique to this test.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r23008_backstop_spares_post_anchor_foreign_session_sleeper() {
        use std::os::unix::process::CommandExt as _;
        use std::time::Duration;
        {
            use super::super::DedicatedSession;
            if super::super::ensure_dedicated_session() == DedicatedSession::Unavailable {
                eprintln!("skip: session dedication unavailable (group leader?)");
                return;
            }
        }
        // SAFETY: getsid query only.
        let ours = unsafe { libc::getsid(0) };
        let anchor = boot_ticks_now().expect("staging broken (boot clock)");
        let mut stranger_cmd = std::process::Command::new("sleep");
        stranger_cmd
            .arg("804")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setsid on the forked child pre-exec (not
        // a group leader — inherits ours).
        unsafe {
            stranger_cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let stranger = stranger_cmd.spawn().expect("staging broken (stranger spawn)");
        let spid = stranger.id() as libc::pid_t;
        let mut _sguard = LegChildGuard {
            pid: spid,
            tick: None,
            disarmed: false,
        };
        // SAFETY: getsid queries only.
        let ssid = unsafe { libc::getsid(spid) };
        assert!(
            ssid >= 0 && ssid != ours,
            "staging broken (stranger must sit in a foreign session: {ssid} vs ours {ours})"
        );
        let stick = fork_starttime(spid)
            .expect("staging broken (stranger stat)")
            .expect("staging broken (stranger visible)");
        _sguard.tick = Some(stick);
        assert!(
            stick >= anchor,
            "staging broken (stranger must be post-anchor: {stick} vs {anchor})"
        );
        std::thread::spawn(move || {
            let mut status = 0;
            // SAFETY: waitpid on the known own child; errors ignored.
            unsafe {
                libc::waitpid(spid, &mut status, 0);
            }
        });
        let fixture = std::process::Command::new("sleep")
            .arg("804")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("staging broken (fixture spawn)");
        let fpid = fixture.id() as libc::pid_t;
        let mut _fguard = LegChildGuard {
            pid: fpid,
            tick: None,
            disarmed: false,
        };
        std::thread::spawn(move || {
            let mut status = 0;
            // SAFETY: waitpid on the known own child; errors ignored.
            unsafe {
                libc::waitpid(fpid, &mut status, 0);
            }
        });
        let ftick = fork_starttime(fpid)
            .expect("staging broken (fixture stat)")
            .expect("staging broken (fixture visible)");
        _fguard.tick = Some(ftick);
        // SAFETY: getsid query only.
        assert_eq!(
            unsafe { libc::getsid(fpid) },
            ours,
            "staging broken (fixture must share our session)"
        );
        let seen: Vec<libc::pid_t> = sleep_pids_with_dur("804")
            .into_iter()
            .map(|(pid, _)| pid)
            .collect();
        assert!(
            seen.contains(&fpid),
            "staging broken (oracle must see our fixture)"
        );
        assert!(
            !seen.contains(&spid),
            "staging broken (oracle must not see the foreign stranger)"
        );
        assert!(
            kill_sleep_with_dur("804", anchor),
            "backstop must drain the fixture"
        );
        match fork_starttime(fpid) {
            Ok(None) => {}
            Ok(Some(now)) => assert_ne!(now, ftick, "fixture birth must be retired"),
            Err(error) => panic!("fixture drainage unverifiable: {error}"),
        }
        assert_eq!(
            fork_starttime(spid),
            Ok(Some(stick)),
            "foreign-session stranger must survive as the same birth"
        );
        kill_tick_gated_fork(spid, stick);
        assert!(
            birth_drained(spid, stick, Duration::from_secs(5)),
            "stranger retire must land"
        );
        _sguard.disarmed = true;
        kill_tick_gated_fork(fpid, ftick);
        assert!(
            birth_drained(fpid, ftick, Duration::from_secs(5)),
            "fixture retire must land"
        );
        _fguard.disarmed = true;
    }

    /// R23-009: the scan hook swaps the candidate between
    /// the cmdline and stat reads — the steered
    /// replacement (different birth, nonmatching
    /// `/bin/sleep 31` argv) must be EXCLUDED from the scan
    /// and left untouched by the backstop. RED (no argv
    /// re-verify: the scan authenticates the replacement's
    /// tick with the former occupant's argv and the
    /// backstop kills it). Duration 874 is unique to this
    /// test.
    #[test]
    fn r22008_backstop_binds_argv_to_tick_across_recycle() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;
        use std::time::Duration;
        // Steering serial hold + writability proof (skip
        // when unsteerable — established precedent).
        // R23-019: shared prologue (behavior-identical to
        // the inline shape it replaces).
        let _serial = match fork_steer_hold() {
            Some(guard) => guard,
            None => return,
        };
        // Anchor pre-staging (candidate + replacement both
        // in-window — the window must not interfere with
        // the binding proof).
        let anchor = boot_ticks_now().expect("staging broken (boot clock)");
        // Candidate sleep-874 (bare argv0 — the fork
        // scanners match fork-shape-exact argv0).
        let candidate = std::process::Command::new("sleep")
            .arg("874")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("staging broken (candidate spawn)");
        let cpid = candidate.id() as libc::pid_t;
        let mut _cguard = LegChildGuard {
            pid: cpid,
            tick: None,
            disarmed: false,
        };
        let ctick = fork_starttime(cpid)
            .expect("staging broken (candidate stat)")
            .expect("staging broken (candidate visible)");
        _cguard.tick = Some(ctick);
        // Shared hook state (fire-once).
        let fired = AtomicBool::new(false);
        let skipped = AtomicBool::new(false);
        let placed: Mutex<Option<(std::process::Child, LegChildGuard, u64)>> = Mutex::new(None);
        let hook = |pid: libc::pid_t| {
            if pid != cpid || fired.swap(true, Ordering::SeqCst) {
                return;
            }
            kill_tick_gated_fork(pid, ctick);
            reap_child_bounded(pid, "R23-009");
            match fork_plant_sleep_onto(pid, "31", ctick) {
                Some((kid, retick)) => {
                    let cmd = std::fs::read(format!("/proc/{pid}/cmdline"))
                        .expect("staging broken (replacement cmdline)");
                    assert!(
                        !cmdline_matches_sleep_dur_exact(&cmd, "874"),
                        "staging broken (replacement matches?)"
                    );
                    let rguard = LegChildGuard {
                        pid,
                        tick: Some(retick),
                        disarmed: false,
                    };
                    *placed.lock().unwrap() = Some((kid, rguard, retick));
                }
                None => {
                    skipped.store(true, Ordering::SeqCst);
                }
            }
        };
        // Drive the scan through the seam.
        let found = sleep_owned_pids_with_dur_with_hook("874", anchor, Some(&hook));
        // Contended plant → skip loud (the candidate is
        // already dead + reaped — nothing litters).
        if skipped.load(Ordering::SeqCst) {
            eprintln!("skip: replacement planting contended (retake squatted)");
            _cguard.disarmed = true;
            return;
        }
        assert!(
            fired.load(Ordering::SeqCst),
            "staging broken (hook never fired)"
        );
        let (mut kid, mut rguard, retick) = placed
            .lock()
            .unwrap()
            .take()
            .expect("staging broken (fired but no plant?)");
        // The binding proof: a recycled number whose holder
        // changed argv mid-observation is excluded.
        assert!(
            found.is_empty(),
            "recycled candidate must be excluded, got: {found:?}"
        );
        // End-to-end: the backstop must not touch it
        // either.
        assert!(
            kill_sleep_with_dur("874", anchor),
            "backstop must drain clean (recycled candidate excluded)"
        );
        assert_eq!(
            fork_starttime(cpid),
            Ok(Some(retick)),
            "replacement must survive untouched as the same birth"
        );
        // Explicit retire (no litter) + disarm + reap
        // (reap BEFORE the drain poll — our own child
        // zombies (tick kept) until reaped; no detached
        // reaper runs in this leg).
        kill_tick_gated_fork(cpid, retick);
        let _ = kid.wait();
        assert!(
            birth_drained(cpid, retick, Duration::from_secs(5)),
            "replacement retire must land"
        );
        rguard.disarmed = true;
        _cguard.disarmed = true;
    }

    /// R22-014 fault leg: a pre-tail staging panic must
    /// unwind through the pair guard — m1 AND its
    /// unknown-pid m2 discharged before the panic
    /// propagates. Spawns the fallback probe directly
    /// with the panic env (no wrapper — the leg names
    /// m1's birth from the custody line itself), restaged
    /// under sleep-857 (never the GREEN 853 — parallel
    /// runs would collide). Asserts: probe failed + no
    /// DONE + m1 birth drained (birth-aware) + no live
    /// sleep-857. RED (no guard): m1 pauses forever past
    /// the bound.
    #[test]
    fn r22008_pair_panic_discharges_before_unwind() {
        let exe = std::env::current_exe().expect("own test binary");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("fixture::linux::fork::tests::reportless_fallback_kills_group_unconditionally")
            .arg("--nocapture")
            .env("SCOPEBASE_R22008_FALLBACK", "1")
            .env("SCOPEBASE_R22014_PAIR_PANIC", "1")
            .env("SCOPEBASE_R22014_SLEEP_DUR", "857")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("leg child runs");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            !out.status.success(),
            "leg probe must panic as staged\n{stderr}"
        );
        assert!(
            !stderr.contains("R22008-DONE"),
            "panicking probe must never cite completion\n{stderr}"
        );
        let (m1, tick1): (libc::pid_t, u64) = stdout
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22008-M1 ")?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
            .expect("probe must print custody before panicking");
        match fork_starttime(m1) {
            Ok(None) => {}
            Ok(Some(now)) => assert_ne!(
                now, tick1,
                "m1 birth must be retired (stranded by the pre-tail panic)"
            ),
            Err(error) => panic!("m1 drainage unverifiable: {error}"),
        }
        assert!(
            sleep_pids_with_dur("857").is_empty(),
            "no live sleep-857 may survive the unwind"
        );
    }

    /// R22-009 probe-deny probe (fresh image): stage the
    /// jam pair healthy, print custody, THEN seccomp-deny
    /// negative-pid `kill` (the glibc `killpg` lowering)
    /// with EPERM (positive-pid `kill` stays allowed) and
    /// run the reportless tail. BOTH m2 group-kills fail
    /// silently (fire-and-forget — the probe below is the
    /// backstop) AND the post-reap probe fails EPERM: the
    /// probe must discriminate errno — ESRCH proves
    /// empty; EPERM/other fails LOUD-UNRESOLVED (never an
    /// empty citation). The old `if probed != 0` treats
    /// EVERY failure as ESRCH-empty and falsely certifies
    /// death over the LIVE m2. RED (old probe: "proven
    /// dead" over live `sleep 855`). Duration 855 is
    /// unique to this test.
    fn reportless_probe_denied_stays_unresolved_probe() {
        use super::super::seccomp::{install_deny_kill_negative_pid, DenyAction};
        let (m1, m2, tick2) =
            unsafe { fork_pausing_grandchild_sleep_jam_noretire("855") }
                .expect("staging broken (pair spawn)");
        // Pre-custody unwinds discharge fully (the filter
        // installs after the print); post-print unwinds
        // retire m1 in-probe while the wrapper drains m2 by
        // its staked birth (both lines already flushed).
        let mut _pair = ReportlessPairGuard::armed(m1);
        let tick1 = fork_starttime(m1)
            .expect("staging broken (m1 stat)")
            .expect("staging broken (m1 visible)");
        println!("R22009-M1 {m1} {tick1}");
        // R23-019: the gate-staked m2 birth (the wrapper
        // proves m2's survival birth-aware — the scan
        // presence below is the second channel, not the
        // only one).
        println!("R22009-M2 {m2} {tick2}");
        std::io::Write::flush(&mut std::io::stdout()).expect("custody line flushed");
        // Selective denial: negative-pid kill (the glibc
        // killpg lowering) → EPERM, positive-pid kill
        // allowed (kill/killpg share SYS_kill — a number
        // filter cannot split them).
        // R23-002: `unsupported_arch` skips explicitly
        // (seccomp denial is x86-only — exit 0 with the
        // SKIP marker; the wrapper judges the marker,
        // never the install). Any other install failure
        // is still staging-broken.
        if let Err(error) = install_deny_kill_negative_pid(DenyAction::Eperm) {
            if error.stage() == "unsupported_arch" {
                eprintln!("R22009-SKIP unsupported_arch (seccomp denial unavailable)");
                return;
            }
            panic!("deny installs (staging): {error}");
        }
        // Anti-vacuity: the denial bites (our own live
        // group probes EPERM now) AND positive-pid kill
        // still works (signal-0 self-probe).
        let own = unsafe { libc::getpgid(0) };
        let self_pid = std::process::id() as libc::pid_t;
        assert_eq!(
            unsafe { libc::kill(self_pid, 0) },
            0,
            "staging broken (positive-pid kill denied too?)"
        );
        let probed = unsafe { libc::killpg(own, 0) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!(
            (probed, errno),
            (-1, Some(libc::EPERM)),
            "staging broken (killpg not denied?)"
        );
        retire_reportless_middleman(m1);
        _pair.disarm();
        eprintln!("R22009-DONE");
    }

    /// R22-009 probe-deny wrapper: the probe runs
    /// fresh-image (seccomp is irreversible). m2 is LIVE
    /// by design (both group-kills denied) — the wrapper
    /// proves its survival pre-custody (else the
    /// regression is vacuous), drains it, and only then
    /// judges the probe's evidence (UNRESOLVED, never an
    /// empty citation).
    #[test]
    fn reportless_probe_denied_stays_unresolved() {
        if std::env::var("SCOPEBASE_R22009_DENY_KILLPG").is_ok() {
            reportless_probe_denied_stays_unresolved_probe();
            return;
        }
        // R23-008: ownership-window anchor — wrapper entry
        // (before the probe stages anything).
        let anchor = boot_ticks_now().expect("custody anchor needs the boot clock");
        let outcome = run_fresh_probe_collect(
            "SCOPEBASE_R22009_DENY_KILLPG",
            "reportless_probe_denied_stays_unresolved",
        );
        let stdout = String::from_utf8_lossy(&outcome.out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&outcome.out.stderr).into_owned();
        let (m1, tick1): (libc::pid_t, u64) = stdout
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22009-M1 ")?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
            .expect("staging broken (no m1 line?)");
        // R23-019: the gate-staked m2 birth.
        let (m2, tick2): (libc::pid_t, u64) = stdout
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22009-M2 ")?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
            .expect("staging broken (no m2 line?)");
        // Load-bearing anti-vacuity: m2 SURVIVED the tail
        // (both group-kills denied — nothing else targets
        // it). A dead m2 here would make the probe's
        // evidence untestable. Birth-live is the PRIMARY
        // channel (the staked birth names the exact m2 —
        // a same-dur stranger can't exonerate it); the
        // scan presence below is the second channel.
        assert_eq!(
            fork_starttime(m2),
            Ok(Some(tick2)),
            "staging broken (staked m2 birth {m2}/{tick2} dead pre-custody — the denial staged nothing?)"
        );
        assert!(
            live_sleep_with_dur("855"),
            "staging broken (m2 birth live but scan-blind pre-custody?)"
        );
        // Custody BEFORE verdicts (m2 live by design):
        // m2 by its STAKED birth (no scan — the stake
        // names the exact birth), then the scan backstop.
        kill_tick_gated_fork(m1, tick1);
        assert!(
            birth_drained(m1, tick1, std::time::Duration::from_secs(5)),
            "wrapper must drain m1"
        );
        kill_tick_gated_fork(m2, tick2);
        assert!(
            birth_drained(m2, tick2, std::time::Duration::from_secs(5)),
            "wrapper must drain m2"
        );
        assert!(
            kill_sleep_with_dur("855", anchor),
            "scan backstop must find no residual sleep 855"
        );
        // R23-002: explicit unsupported_arch skip (custody
        // above still proves clean — the probe staged and
        // printed pre-install, then exited 0 — so only the
        // verdicts below are skipped).
        if stderr.contains("R22009-SKIP") {
            eprintln!("skip: seccomp killpg denial unsupported on this arch (see probe stderr)");
            return;
        }
        assert!(!outcome.timed_out, "probe must complete\n{stderr}");
        assert!(outcome.out.status.success(), "probe must exit 0\n{stderr}");
        assert!(
            stderr.contains("grouped at freeze"),
            "probe must take the main grouped path\n{stderr}"
        );
        assert!(
            !stderr.contains("R21008-FALLBACK"),
            "probe must not fall back\n{stderr}"
        );
        assert!(
            stderr.contains("R22009-DONE"),
            "probe must cite completion\n{stderr}"
        );
        assert!(
            !stderr.contains("proven dead"),
            "RED: probe certified death over live m2\n{stderr}"
        );
        assert!(
            stderr.contains("R22009-UNRESOLVED"),
            "probe must cite loud-unresolved on EPERM\n{stderr}"
        );
    }

    /// R22-016(b): TEST-SIDE group re-probe
    /// (post-tail) — `killpg(m1, 0)` with errno
    /// discipline: ESRCH ⟹ empty; 0 ⟹ non-empty; EPERM
    /// (or any other error) ⟹ UNRESOLVED (never an empty
    /// citation — conservative over the unpinned squatter
    /// ambiguity AND over probe denial). The scan cannot
    /// see a pre-exec grandchild (argv0 ≠ `sleep`), so
    /// this re-probe is the only channel that can refuse
    /// the false absence.
    fn reprobe_group_post_tail(m1: libc::pid_t) -> &'static str {
        // SAFETY: signal-0 probe (no delivery).
        let probed = unsafe { libc::killpg(m1, 0) };
        if probed == 0 {
            return "R22016B-REPROBE-NONEMPTY";
        }
        // R22-009 discipline (shared): ESRCH proves
        // empty; any other error is UNRESOLVED (never an
        // empty citation).
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return "R22016B-REPROBE-EMPTY";
        }
        "R22016B-REPROBE-UNRESOLVED"
    }

    /// R22-016(b) pre-exec-stall probe (fresh image):
    /// stage the pre-exec-stall pair (stub fork-proven by
    /// the birth gate, self-stopped before any exec —
    /// argv0 ≠ `sleep`, so the scan is blind to it),
    /// print custody, pin the blindness (no `sleep 863`
    /// visible) + the stub's stopped-grouped state, THEN
    /// seccomp-deny ALL of `kill`/`killpg` (shared number)
    /// and run the tail. NOTHING dies (SIGSTOP denied ⟹
    /// the tail burns into the loud fallback; both kills
    /// denied): m1 lives pausing, the stub lives stopped
    /// (no orphaning — m1 never dies — so no SIGHUP; a
    /// killpg-only denial would orphan-SIGHUP a stopped
    /// stub, which is why the full denial stages the
    /// survivor). The scan still sees nothing — only the
    /// TEST-SIDE group re-probe can refuse the false
    /// absence, and under denial it must say
    /// LOUD-UNRESOLVED (never EMPTY). RED (old `!= 0`
    /// re-probe: EMPTY over two live processes).
    /// Duration 863 is unique to this test.
    fn reportless_preexec_stall_denied_stays_unresolved_probe() {
        use super::super::seccomp::{install_deny_one, DenyAction};
        let (m1, stub) = unsafe { fork_prestall_grandchild_jam_noretire("863") }
            .expect("staging broken (pair spawn)");
        // R23-011: pair custody BEFORE the fallible stat
        // reads below (a pre-custody unwind must retire
        // m1 + the stub, never strand them). Disarmed
        // once custody is published (the wrapper owns
        // post-publication cleanup via the lines).
        let mut _prestall_guard = MiddlemanPairGuard::armed(m1, stub);
        let tick1 = fork_starttime(m1)
            .expect("staging broken (m1 stat)")
            .expect("staging broken (m1 visible)");
        let tick_stub = fork_starttime(stub)
            .expect("staging broken (stub stat)")
            .expect("staging broken (stub visible)");
        println!("R22016B-M1 {m1} {tick1}");
        println!("R22016B-STUB {stub} {tick_stub}");
        std::io::Write::flush(&mut std::io::stdout()).expect("custody lines flushed");
        _prestall_guard.disarm();
        // Scan-blind pin: the stub is pre-exec (argv0 is
        // the inherited image, never `sleep`) — the scan
        // MUST see nothing. (If this ever fires, the stub
        // exec'd — staging broken, never a pass.)
        assert!(
            !live_sleep_with_dur("863"),
            "staging broken (stub exec'd?!)"
        );
        // Stopped-grouped pin: the stub self-stopped (T —
        // its raise ran, so it is past fork and pre-exec)
        // AND grouped under m1 (the group re-probe covers
        // it — an ungrouped stub would make the re-probe's
        // evidence untestable).
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut pinned = false;
        while std::time::Instant::now() < end {
            match stat_state_pgrp(stub) {
                Some((st, pgrp)) if matches!(st, 'T' | 't') && pgrp == m1 => {
                    pinned = true;
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
        assert!(pinned, "staging broken (stub never stopped-grouped?)");
        eprintln!("R22016B-SCAN-BLIND");
        // R23-002: `unsupported_arch` skips explicitly
        // (seccomp denial is x86-only — exit 0 with the
        // SKIP marker; the wrapper judges the marker,
        // never the install). Any other install failure
        // is still staging-broken.
        if let Err(error) = install_deny_one(libc::SYS_kill, DenyAction::Eperm) {
            if error.stage() == "unsupported_arch" {
                eprintln!("R22016B-SKIP unsupported_arch (seccomp denial unavailable)");
                return;
            }
            panic!("deny installs (staging): {error}");
        }
        // Anti-vacuity: the FULL denial bites (numeric
        // self-probe AND group probe both EPERM now).
        let self_pid = std::process::id() as libc::pid_t;
        let probed_self = unsafe { libc::kill(self_pid, 0) };
        let errno_self = std::io::Error::last_os_error().raw_os_error();
        assert_eq!(
            (probed_self, errno_self),
            (-1, Some(libc::EPERM)),
            "staging broken (kill not denied?)"
        );
        let own = unsafe { libc::getpgid(0) };
        let probed = unsafe { libc::killpg(own, 0) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!(
            (probed, errno),
            (-1, Some(libc::EPERM)),
            "staging broken (killpg not denied?)"
        );
        retire_reportless_middleman(m1);
        // TEST-SIDE re-probe (the fix): the tail is over
        // (fallback, both kills denied); the scan says
        // absent (blind) — this probe must refuse to
        // certify.
        eprintln!("{}", reprobe_group_post_tail(m1));
        // Post-tail survival pins (IN-PROBE — the
        // wrapper cannot observe survival: our exit
        // orphans group m1 with a stopped member, so the
        // kernel SIGHUPs m1 + stub before wrapper
        // custody. Both MUST be live here — else the
        // denial staged nothing and the re-probe's
        // evidence is untestable).
        assert_eq!(
            stat_state_pgrp(m1),
            Some(('S', m1)),
            "staging broken (m1 not live-pausing post-tail?)"
        );
        assert_eq!(
            stat_state_pgrp(stub),
            Some(('T', m1)),
            "staging broken (stub not live-stopped-grouped post-tail?)"
        );
        eprintln!("R22016B-SURVIVED");
        eprintln!("R22016B-DONE");
    }

    /// R22-016(b) pre-exec-stall wrapper: the probe runs
    /// fresh-image (seccomp is irreversible). Survival is
    /// pinned IN-PROBE (R22016B-SURVIVED — post-tail m1-S
    /// and stub-T-grouped): the wrapper cannot observe
    /// it (probe exit orphan-SIGHUPs the group before
    /// custody). Wrapper custody is best-effort drain
    /// (the kills may or may not land — SIGHUP races
    /// them); the drain asserts are load-bearing.
    #[test]
    fn reportless_preexec_stall_denied_stays_unresolved() {
        if std::env::var("SCOPEBASE_R22016B_PRESTALL").is_ok() {
            reportless_preexec_stall_denied_stays_unresolved_probe();
            return;
        }
        let outcome = run_fresh_probe_collect(
            "SCOPEBASE_R22016B_PRESTALL",
            "reportless_preexec_stall_denied_stays_unresolved",
        );
        let stdout = String::from_utf8_lossy(&outcome.out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&outcome.out.stderr).into_owned();
        let parse = |tag: &str| -> Option<(libc::pid_t, u64)> {
            stdout.lines().find_map(|line| {
                let rest = line.strip_prefix(tag)?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
        };
        let (m1, tick1): (libc::pid_t, u64) =
            parse("R22016B-M1 ").expect("staging broken (no m1 line?)");
        let (stub, tick_stub): (libc::pid_t, u64) =
            parse("R22016B-STUB ").expect("staging broken (no stub line?)");
        // Custody: best-effort kills (SIGHUP-at-exit
        // races them — survival was pinned in-probe) +
        // load-bearing drains.
        kill_tick_gated_fork(m1, tick1);
        assert!(
            birth_drained(m1, tick1, std::time::Duration::from_secs(5)),
            "wrapper must drain m1"
        );
        kill_tick_gated_fork(stub, tick_stub);
        assert!(
            birth_drained(stub, tick_stub, std::time::Duration::from_secs(5)),
            "wrapper must drain the stub"
        );
        // R23-002: explicit unsupported_arch skip (custody
        // above still proves clean — the probe staged and
        // printed pre-install, then exited 0 — so only the
        // verdicts below are skipped).
        if stderr.contains("R22016B-SKIP") {
            eprintln!("skip: seccomp kill denial unsupported on this arch (see probe stderr)");
            return;
        }
        assert!(!outcome.timed_out, "probe must complete\n{stderr}");
        assert!(outcome.out.status.success(), "probe must exit 0\n{stderr}");
        assert!(
            stderr.contains("R22016B-SCAN-BLIND"),
            "probe must pin scan-blindness\n{stderr}"
        );
        assert!(
            stderr.contains("R22016B-SURVIVED"),
            "probe must pin post-tail survival\n{stderr}"
        );
        assert!(
            stderr.contains("R21008-FALLBACK"),
            "tail must take the fallback path (SIGSTOP denied)\n{stderr}"
        );
        assert!(
            stderr.contains("R22016B-DONE"),
            "probe must cite completion\n{stderr}"
        );
        assert!(
            !stderr.contains("R22016B-REPROBE-EMPTY"),
            "RED: re-probe certified EMPTY over live m1 + live stub\n{stderr}"
        );
        assert!(
            stderr.contains("R22016B-REPROBE-UNRESOLVED"),
            "re-probe must cite loud-unresolved on EPERM\n{stderr}"
        );
    }

    /// R23-011 site 3: the pre-exec birth gate times out —
    /// the helper must retire m1 (alive arm) or reap the
    /// corpse (dead arm) BEFORE failing loud. Fresh-image
    /// probe per arm (5 s gate burn each); the probe
    /// catches the timeout panic, prints its payload, and
    /// marks DISCHARGED only when its own children set
    /// holds no new birth (a live pauser or an unreaped
    /// corpse both fail the mark). RED (old code: both
    /// arms panic with m1 unretired).
    #[test]
    fn prestall_birth_gate_timeout_retires_middleman() {
        if std::env::var("SCOPEBASE_R23011_PRESTALL_TIMEOUT").is_ok() {
            prestall_birth_gate_timeout_retires_middleman_probe();
            return;
        }
        for fault in ["SCOPEBASE_PRESTALL_NO_STUB", "SCOPEBASE_PRESTALL_EXIT_M1"] {
            let exe = std::env::current_exe().expect("own test binary");
            let out = std::process::Command::new(exe)
                .arg("--exact")
                .arg("fixture::linux::fork::tests::prestall_birth_gate_timeout_retires_middleman")
                .arg("--nocapture")
                .env("SCOPEBASE_R23011_PRESTALL_TIMEOUT", "1")
                .env(fault, "1")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .expect("probe runs");
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            assert!(
                out.status.success(),
                "probe must exit 0 (measurement, never verdict)\n{stderr}"
            );
            assert!(
                stdout.contains("R23011-PRESTALL-DISCHARGED"),
                "birth-gate timeout must retire m1 ({fault})\n{stdout}\n{stderr}"
            );
            assert!(
                stdout.contains("R22016B-JAM: birth-gate timed out"),
                "probe must cite the timeout panic ({fault})\n{stdout}"
            );
        }
    }

    /// R23-011 site-3 probe (fresh image): snapshot own
    /// children, run the faulted helper through a caught
    /// unwind, print the panic payload, and mark
    /// DISCHARGED only when no new birth remains.
    fn prestall_birth_gate_timeout_retires_middleman_probe() {
        use std::collections::HashSet;
        use std::panic::AssertUnwindSafe;
        let read_children = || -> HashSet<i32> {
            // Per-task path with the real tid (`self` does
            // not resolve under task/; the per-process
            // children file is absent on some kernels).
            // SAFETY: gettid queries only.
            let tid = unsafe { libc::gettid() };
            // Must SUCCEED (an unreadable children file
            // would vacate the discharge proof).
            std::fs::read_to_string(format!("/proc/self/task/{tid}/children"))
                .expect("staging broken (own children unreadable)")
                .split_whitespace()
                .filter_map(|word| word.parse().ok())
                .collect()
        };
        let before = read_children();
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = unsafe { fork_prestall_grandchild_jam_noretire("850") };
        }));
        assert!(outcome.is_err(), "staging broken (gate must time out)");
        let payload = outcome.unwrap_err();
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".to_string());
        println!("R23011-PRESTALL-PANIC {message}");
        let after = read_children();
        let stranded: Vec<i32> = after.difference(&before).copied().collect();
        if stranded.is_empty() {
            println!("R23011-PRESTALL-DISCHARGED");
        } else {
            println!("R23011-PRESTALL-STRANDED {stranded:?}");
        }
    }

    /// R22-016(a) scan-outage probe (fresh image): stage
    /// the REPORTED pair (m1 pauses, m2 sleeps `859` —
    /// both kept alive, never retired), print custody,
    /// THEN exhaust the fd table to exactly ONE free
    /// slot and run the live-sleeper scan. opendir
    /// consumes the last slot, so EVERY cmdline read
    /// fails EMFILE over the LIVE m2: the scan must fail
    /// LOUD (NotFound — vanished — skips; any other read
    /// error panics — the stat arm's existing
    /// discipline). The old scan swallows entry/cmdline
    /// errors (`Err(_) => continue`) and reports false
    /// absence over live m2. RED (old scan: the probe's
    /// own assert fails WITHOUT the mid-scan marker).
    /// Duration 859 is unique to this test.
    fn scan_outage_over_live_sleeper_fails_loud_probe() {
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("859") }.expect("pair staged");
        // Rides every exit (no disarm — the probe panics by
        // design at THE scan): pre-custody unwinds
        // discharge fully in-probe; post-print unwinds
        // retire here AND through the wrapper backstop
        // (idempotent — the pair is already dead). Drop
        // order (hold first) restores fds before the
        // retire runs.
        let _pair = ReportlessPairGuard::armed(m1);
        let tick1 = fork_starttime(m1)
            .expect("staging broken (m1 stat)")
            .expect("staging broken (m1 visible)");
        let tick2 = fork_starttime(m2)
            .expect("staging broken (m2 stat)")
            .expect("staging broken (m2 visible)");
        println!("R22016A-M1 {m1} {tick1}");
        println!("R22016A-M2 {m2} {tick2}");
        std::io::Write::flush(&mut std::io::stdout()).expect("custody lines flushed");
        // Sanity (pre-outage): the scan sees the live m2
        // (else the staging is vacuous).
        assert!(
            live_sleep_with_dur("859"),
            "staging broken (scan blind pre-outage?)"
        );
        let mut hold = OutageHold::exhaust();
        hold.release_one();
        // THE scan: m2 is LIVE; every cmdline read fails
        // EMFILE. New code panics loud (mid-scan marker);
        // old code returns false (this assert fails
        // WITHOUT the marker — RED).
        assert!(
            live_sleep_with_dur("859"),
            "staging broken (scan false over live m2?)"
        );
        drop(hold);
        eprintln!("R22016A-DONE");
    }

    /// R22-016(a) scan-outage wrapper: the probe runs
    /// fresh-image (the outage is process-global) and is
    /// EXPECTED TO FAIL (the loud scan-panic is the
    /// verdict). Wrapper-side custody (m1 + m2 numeric,
    /// both live-orphaned) runs BEFORE the verdict
    /// asserts so RED runs stay clean.
    #[test]
    fn scan_outage_over_live_sleeper_fails_loud() {
        if std::env::var("SCOPEBASE_R22016A_OUTAGE").is_ok() {
            scan_outage_over_live_sleeper_fails_loud_probe();
            return;
        }
        let outcome = run_fresh_probe_collect(
            "SCOPEBASE_R22016A_OUTAGE",
            "scan_outage_over_live_sleeper_fails_loud",
        );
        let stdout = String::from_utf8_lossy(&outcome.out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&outcome.out.stderr).into_owned();
        let parse = |tag: &str| -> Option<(libc::pid_t, u64)> {
            stdout.lines().find_map(|line| {
                let rest = line.strip_prefix(tag)?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
        };
        let (m1, tick1): (libc::pid_t, u64) =
            parse("R22016A-M1 ").expect("staging broken (no m1 line?)");
        let (m2, tick2): (libc::pid_t, u64) =
            parse("R22016A-M2 ").expect("staging broken (no m2 line?)");
        // Custody BEFORE verdicts (both live by design —
        // the probe never retires).
        kill_tick_gated_fork(m1, tick1);
        assert!(
            birth_drained(m1, tick1, std::time::Duration::from_secs(5)),
            "wrapper must drain m1"
        );
        kill_tick_gated_fork(m2, tick2);
        assert!(
            birth_drained(m2, tick2, std::time::Duration::from_secs(5)),
            "wrapper must drain m2"
        );
        assert!(!outcome.timed_out, "probe must complete\n{stderr}");
        assert!(
            !outcome.out.status.success(),
            "probe must FAIL (the loud scan-panic is the verdict)\n{stderr}"
        );
        assert!(
            stderr.contains("mid-scan"),
            "RED: scan swallowed the outage (no loud mid-scan failure over live m2)\n{stderr}"
        );
    }

    /// R22-004(a): the absence-proof never waits — live
    /// occupant ⟹ unproven (then cleaned by us); zombie
    /// occupant ⟹ unproven AND the owner retains the
    /// status (the proof consumes nothing — a waitpid
    /// inside would steal it); freed number ⟹ reaped.
    /// RED (neuter: waitpid inside the proof — the zombie
    /// leg loses its status). Durations 979 (live) and
    /// 980 (zombie, then freed) are unique to this test.
    #[test]
    fn reap_proof_by_absence_never_steals() {
        // Live leg: present ⟹ unproven.
        let mut live = std::process::Command::new("/bin/sleep")
            .arg("979")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("live spawns");
        let live_pid = live.id() as libc::pid_t;
        let mut _lguard = ForkChildGuard::new(live_pid);
        assert_eq!(
            prove_reaped_by_absence(live_pid),
            Ok(false),
            "live occupant must read unproven (never reaped)"
        );
        let _ = live.kill();
        let _ = live.wait();
        _lguard.disarm();
        // Zombie leg: present ⟹ unproven, status retained.
        let mut zombie = std::process::Command::new("/bin/sleep")
            .arg("980")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("zombie spawns");
        let zombie_pid = zombie.id() as libc::pid_t;
        let mut _zguard = ForkChildGuard::new(zombie_pid);
        // R23-019: retain the victim birth (the post-reap
        // proof is gone-or-recycled over THIS tick).
        let zombie_tick = fork_starttime(zombie_pid)
            .expect("zombie stat readable")
            .expect("zombie visible");
        let _ = zombie.kill();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let state = std::fs::read_to_string(format!("/proc/{zombie_pid}/stat"))
                .ok()
                .and_then(|text| {
                    text.rsplit_once(") ")
                        .and_then(|(_, after)| after.split_whitespace().next().map(str::to_string))
                });
            if state.as_deref() == Some("Z") {
                break;
            }
            assert!(
                std::time::Instant::now() < end,
                "staging broken (sleeper never zombified)"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            prove_reaped_by_absence(zombie_pid),
            Ok(false),
            "zombie occupant must read unproven (never certified)"
        );
        // R23-019: the tick-aware proof reads our unreaped
        // birth StillOurs (present + same tick ⟹ NOT
        // reaped — the RED shape).
        assert!(
            matches!(
                prove_reaped_gone_or_recycled(zombie_pid, zombie_tick),
                ReapedProof::StillOurs
            ),
            "unreaped zombie birth must read StillOurs (never Gone/Recycled)"
        );
        match zombie.try_wait() {
            Ok(Some(status)) => assert!(!status.success(), "zombie must be our SIGKILLed sleeper"),
            other => panic!("proof stole the zombie's status?! got {other:?}"),
        }
        _zguard.disarm();
        // Absent leg: freed number ⟹ reaped (gone-or-recycled —
        // a different-birth occupant keeps the evidence valid).
        match prove_reaped_gone_or_recycled(zombie_pid, zombie_tick) {
            ReapedProof::Gone | ReapedProof::Recycled(_) => {}
            ReapedProof::StillOurs => panic!(
                "RED: our zombie birth {zombie_pid}/{zombie_tick} still present after the owned reap"
            ),
            ReapedProof::Unreadable(error) => panic!(
                "inconclusive (freed number unreadable: {error}) — refusing to certify"
            ),
        }
        // R23-019 recycle leg: a different-birth occupant on
        // the freed number keeps retirement evidence valid
        // (the proof reads Recycled) while the vacancy-only
        // check reports inconclusive (never certified, never
        // a cleanup defect).
        let _serial = match fork_steer_hold() {
            Some(guard) => guard,
            None => return,
        };
        let (mut plant, plant_tick) = match fork_plant_sleep_onto(zombie_pid, "31", zombie_tick) {
            Some(placed) => placed,
            None => {
                eprintln!("R23019-LEG vacuous (plant contended)");
                return;
            }
        };
        eprintln!("R23019-LEG[self] plant {zombie_pid}/{plant_tick} (victim tick {zombie_tick})");
        assert!(
            plant_tick != zombie_tick,
            "staging broken (plant shares the victim tick?)"
        );
        let mut _pguard = ForkChildGuard::new(zombie_pid);
        match prove_reaped_gone_or_recycled(zombie_pid, zombie_tick) {
            ReapedProof::Recycled(now) if now == plant_tick => {}
            ReapedProof::Recycled(now) => panic!(
                "staging broken (stranger birth {now} on our steered number {zombie_pid}?)"
            ),
            ReapedProof::StillOurs => panic!(
                "RED: our reaped birth {zombie_pid}/{zombie_tick} reads present (tick collision?)"
            ),
            ReapedProof::Gone => panic!("staging broken (plant vanished?)"),
            ReapedProof::Unreadable(error) => {
                panic!("inconclusive (plant unreadable: {error}) — refusing to certify")
            }
        }
        assert_eq!(
            prove_reaped_by_absence(zombie_pid),
            Ok(false),
            "vacancy-only check must read inconclusive over the recycled occupant (never certified, never defect)"
        );
        let _ = plant.kill();
        let _ = plant.wait();
        _pguard.disarm();
    }

    /// R22-007: settle to zombie (staging — the guard's
    /// probe must see Z (zombie path), not a dying-R
    /// (which takes the live path and would make the leg
    /// vacuous)).
    fn settle_zombie(pid: libc::pid_t) {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|text| {
                    text.rsplit_once(") ")
                        .and_then(|(_, after)| after.split_whitespace().next().map(str::to_string))
                });
            if state.as_deref() == Some("Z") {
                return;
            }
            assert!(
                std::time::Instant::now() < end,
                "staging broken (never zombified)"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// R22-007: poll tick-aware absence (gone or recycled ⟹
    /// OUR birth drained). True when drained within the
    /// bound; loud on an unreadable stat.
    fn birth_drained(pid: libc::pid_t, tick: u64, timeout: std::time::Duration) -> bool {
        let end = std::time::Instant::now() + timeout;
        loop {
            match fork_starttime(pid) {
                Ok(None) => return true,
                Ok(Some(now)) if now != tick => return true,
                Ok(Some(_)) => {}
                Err(error) => panic!("staging broken (stat unreadable: {error})"),
            }
            if std::time::Instant::now() >= end {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// R22-007: tick-gated kill (fork-local — audit's
    /// helper is out of reach). True when the signal
    /// landed on OUR birth.
    fn kill_tick_gated_fork(pid: libc::pid_t, tick: u64) -> bool {
        match fork_starttime(pid) {
            Ok(Some(now)) if now == tick => unsafe { libc::kill(pid, libc::SIGKILL) == 0 },
            _ => false,
        }
    }

    /// R22-007: the zombie-m1 path retires m2 via the pin —
    /// kill m1 (no reap), settle Z, unwind past a simulated
    /// observation failure; the probe reaps m1 and the pin
    /// kills the orphaned m2 (init drains it). Both births
    /// retire. RED (old code: the probe reaps m1 and
    /// returns — m2 abandoned live). Duration 988 is unique
    /// to this test.
    #[test]
    fn middleman_guard_zombie_m1_retires_m2_via_pin() {
        use std::panic::AssertUnwindSafe;
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("988") }.expect("pair staged");
        // R23-011: arm BEFORE the stat read (a failing
        // observation must unwind through the guard, never
        // strand the pair).
        let _pair = MiddlemanPairGuard::armed(m1, m2);
        // R23-019: retain the m1 birth (the post-unwind
        // proof is gone-or-recycled over THIS tick).
        let tick1 = fork_starttime(m1)
            .expect("m1 stat readable")
            .expect("m1 visible");
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            assert_eq!(
                unsafe { libc::kill(m1, libc::SIGKILL) },
                0,
                "staging broken (m1 kill)"
            );
            settle_zombie(m1);
            panic!("simulated observation failure");
        }));
        drop(_pair);
        assert!(outcome.is_err(), "staging broken (must unwind)");
        // R23-019: gone-or-recycled (a different-birth
        // occupant keeps the evidence valid).
        match prove_reaped_gone_or_recycled(m1, tick1) {
            ReapedProof::Gone | ReapedProof::Recycled(_) => {}
            ReapedProof::StillOurs => {
                panic!("RED: our m1 birth {m1}/{tick1} still present (guard did not reap?)")
            }
            ReapedProof::Unreadable(error) => {
                panic!("inconclusive (m1 unreadable: {error}) — refusing to certify")
            }
        }
        let retired = birth_drained(m2, tick2, std::time::Duration::from_secs(5));
        // RED-safe cleanup (tick-gated — the verdict above
        // is already recorded).
        kill_tick_gated_fork(m2, tick2);
        birth_drained(m2, tick2, std::time::Duration::from_secs(5));
        assert!(retired, "m2 must retire via the pin (abandoned?!)");
        // R23-019 recycle leg: a different-birth occupant on
        // the freed m1 number keeps retirement evidence valid
        // (the proof reads Recycled) while the vacancy-only
        // check reports inconclusive (never certified, never
        // a cleanup defect).
        let _serial = match fork_steer_hold() {
            Some(guard) => guard,
            None => return,
        };
        let (mut plant, plant_tick) = match fork_plant_sleep_onto(m1, "31", tick1) {
            Some(placed) => placed,
            None => {
                eprintln!("R23019-LEG[988] vacuous (plant contended)");
                return;
            }
        };
        eprintln!("R23019-LEG[988] plant {m1}/{plant_tick} (victim tick {tick1})");
        assert!(
            plant_tick != tick1,
            "staging broken (plant shares the victim tick?)"
        );
        let mut _pguard = ForkChildGuard::new(m1);
        match prove_reaped_gone_or_recycled(m1, tick1) {
            ReapedProof::Recycled(now) if now == plant_tick => {}
            ReapedProof::Recycled(now) => panic!(
                "staging broken (stranger birth {now} on our steered number {m1}?)"
            ),
            ReapedProof::StillOurs => panic!(
                "RED: our reaped birth {m1}/{tick1} reads present (tick collision?)"
            ),
            ReapedProof::Gone => panic!("staging broken (plant vanished?)"),
            ReapedProof::Unreadable(error) => {
                panic!("inconclusive (plant unreadable: {error}) — refusing to certify")
            }
        }
        assert_eq!(
            prove_reaped_by_absence(m1),
            Ok(false),
            "vacancy-only check must read inconclusive over the recycled occupant (never certified, never defect)"
        );
        let _ = plant.kill();
        let _ = plant.wait();
        _pguard.disarm();
    }

    /// R22-007: the ECHILD path (tail-honored contract —
    /// m2 dead FIRST, then m1 reaped) returns clean: no
    /// hang, nothing touched, both births gone.
    /// CHARACTERIZATION (passes old+new — locks the
    /// tail-contract path through the rework). Duration 989
    /// is unique to this test.
    #[test]
    fn middleman_guard_echild_after_tail_returns_clean() {
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("989") }.expect("pair staged");
        // R23-011: arm BEFORE the stat read (a failing
        // observation must unwind through the guard).
        let pair = MiddlemanPairGuard::armed(m1, m2);
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        // The tail's contract: m2 dead first (zombie under
        // the live middleman — never reaped until it dies).
        assert_eq!(
            unsafe { libc::kill(m2, libc::SIGKILL) },
            0,
            "staging broken (m2 kill)"
        );
        settle_zombie(m2);
        // Then m1 killed + reaped (raw waitpid — the tail
        // holds no handle).
        assert_eq!(
            unsafe { libc::kill(m1, libc::SIGKILL) },
            0,
            "staging broken (m1 kill)"
        );
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut st = 0;
            // SAFETY: WNOHANG reap of our own child.
            let got = unsafe { libc::waitpid(m1, &mut st, libc::WNOHANG) };
            if got == m1 {
                break;
            }
            assert!(
                std::time::Instant::now() < end,
                "staging broken (m1 never reaped)"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Drop WITHOUT disarming: the probe sees ECHILD
        // (m1 gone) — the only sound early return.
        drop(pair);
        assert_eq!(fork_starttime(m1), Ok(None), "m1 must stay reaped");
        assert!(
            birth_drained(m2, tick2, std::time::Duration::from_secs(5)),
            "m2 must drain via init"
        );
    }

    /// R22-007: the unpinned zombie path degrades loud —
    /// forged pin denial (simulated seccomp), zombie-m1,
    /// unwind; m2 SURVIVES (no safe signal exists) and the
    /// test retires it via the known birth. CHARACTERIZATION
    /// of the degraded SHAPE (passes old+new — both abandon;
    /// the LOUDNESS delta is eyeballed here and asserted
    /// for real by the fresh-image leg). Duration 990 is
    /// unique to this test.
    #[test]
    fn middleman_guard_unpinned_zombie_leaves_m2_for_caller() {
        use std::panic::AssertUnwindSafe;
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("990") }.expect("pair staged");
        // R23-011: arm BEFORE the stat read (a failing
        // observation must unwind through the guard).
        let mut pair = MiddlemanPairGuard::armed(m1, m2);
        pair.m2pin = Err(libc::EPERM);
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            assert_eq!(
                unsafe { libc::kill(m1, libc::SIGKILL) },
                0,
                "staging broken (m1 kill)"
            );
            settle_zombie(m1);
            panic!("simulated observation failure");
        }));
        drop(pair);
        assert!(outcome.is_err(), "staging broken (must unwind)");
        // Survives (nothing killed it — the only killer in
        // this leg is the pin, which is denied).
        // SAFETY: signal 0 probes only.
        assert_eq!(
            unsafe { libc::kill(m2, 0) },
            0,
            "m2 must survive unpinned (loud, then test-cleaned)"
        );
        assert_eq!(
            fork_starttime(m2),
            Ok(Some(tick2)),
            "survivor must be OUR birth"
        );
        kill_tick_gated_fork(m2, tick2);
        assert!(
            birth_drained(m2, tick2, std::time::Duration::from_secs(5)),
            "test must retire the survivor"
        );
    }

    /// R22-007: run a fresh-image probe child with a bounded
    /// wait (60s — a hung child is killed loud) and collect
    /// its output. Fork-local twin of audit's helper (same
    /// pipe rule: no live descendant may hold the probe's
    /// pipes — the survivor's stdio is null, never piped).
    fn run_fresh_probe_bounded(env: &str, test: &str) -> std::process::Output {
        let exe = std::env::current_exe().expect("own test binary");
        let mut child = std::process::Command::new(exe)
            .arg("--exact")
            .arg(format!("fixture::linux::fork::tests::{test}"))
            .arg("--nocapture")
            .env(env, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("probe child spawns");
        // Covers the timeout-panic below (the child is
        // killed but unreaped there — the drop reaps it).
        let mut _cguard = ForkChildGuard::new(child.id() as libc::pid_t);
        let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if child.try_wait().expect("child waitable").is_some() {
                break;
            }
            if std::time::Instant::now() >= end {
                let _ = child.kill();
                panic!("probe child {test} hung past 60s (killed loud)");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let out = child.wait_with_output().expect("probe output readable");
        _cguard.disarm();
        out
    }

    /// R22-008: timeout-COLLECTING fresh-image probe run —
    /// the reportless fault probes own forever-pausing
    /// middlemen, so a timeout must still collect the
    /// pipes (early-flushed pid lines survive the kill)
    /// for wrapper-side custody — never panic away the
    /// output (the plain runner's shape would strand m1
    /// forever on a wedged-box timeout).
    struct ProbeOutcome {
        timed_out: bool,
        out: std::process::Output,
    }

    /// R22-008: run a fresh-image probe child, collecting
    /// its output EVEN on timeout (kill + reap + read the
    /// pipes to EOF — early-flushed custody lines survive;
    /// the pipe rule holds: survivors' stdio is null, so
    /// EOF follows the kill). The wrapper judges
    /// completion via `timed_out` + a DONE marker, never
    /// by output presence alone.
    fn run_fresh_probe_collect(env: &str, test: &str) -> ProbeOutcome {
        let exe = std::env::current_exe().expect("own test binary");
        let mut child = std::process::Command::new(exe)
            .arg("--exact")
            .arg(format!("fixture::linux::fork::tests::{test}"))
            .arg("--nocapture")
            .env(env, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("probe child spawns");
        let mut _cguard = ForkChildGuard::new(child.id() as libc::pid_t);
        let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut timed_out = false;
        loop {
            if child.try_wait().expect("child waitable").is_some() {
                break;
            }
            if std::time::Instant::now() >= end {
                let _ = child.kill();
                timed_out = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let out = child.wait_with_output().expect("probe output readable");
        _cguard.disarm();
        ProbeOutcome { timed_out, out }
    }

    /// R23-008: boot-clock ticks now (CLOCK_BOOTTIME
    /// → jiffies) — the ownership-window anchor. R24-001:
    /// BOOTTIME, not MONOTONIC (starttime counts suspend;
    /// MONOTONIC excludes it — a monotonic anchor admits
    /// pre-anchor sleepers after any suspend). Ported
    /// from the toolchain twin (`boot_ticks_now`,
    /// crates/scopebase-testkit/tests/toolchain_invoke.rs:882-898
    /// at f614a4d — same source as the audit copy).
    fn boot_ticks_now() -> Option<u64> {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime with a valid out-pointer.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
            return None;
        }
        // SAFETY: sysconf with a valid name.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            return None;
        }
        let hz = hz as u64;
        Some(now.tv_sec as u64 * hz + (now.tv_nsec as u64 * hz) / 1_000_000_000)
    }

    /// R23-008: ownership predicate for custody-scan
    /// candidates — mirror of the audit helper (our euid
    /// AND our session; fail-closed on unreadable
    /// evidence).
    fn task_owned_by_us(pid: libc::pid_t) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        // R23-008: dedicate our session first (once per
        // image — same-shell strangers then fail the
        // session check below even post-anchor).
        // x86-only (the dedication helper is x86-gated;
        // other arches run undedicated).
        #[cfg(target_arch = "x86_64")]
        let _ = super::super::ensure_dedicated_session();
        // SAFETY: geteuid/getsid query only.
        let euid = unsafe { libc::geteuid() };
        let ours = unsafe { libc::getsid(0) };
        if ours < 0 {
            return false;
        }
        let meta = match std::fs::metadata(format!("/proc/{pid}")) {
            Ok(meta) => meta,
            Err(_) => return false,
        };
        if meta.uid() != euid {
            return false;
        }
        // SAFETY: getsid queries only (ESRCH on raced
        // exit returns -1, never our session).
        unsafe { libc::getsid(pid) == ours }
    }

    /// R22-008: oracle scan — every LIVE (non-zombie)
    /// `sleep dur` in /proc that WE own (euid + session;
    /// window off — anchor 0).
    fn sleep_pids_with_dur(dur: &str) -> Vec<(libc::pid_t, u64)> {
        sleep_owned_pids_with_dur(dur, 0)
    }

    /// R23-009: fork-side pid-placement serial
    /// (in-process half — POSIX fcntl placement locks
    /// merge same-process, so each steering test file
    /// holds its own; cross-file contention degrades to
    /// retries and skip-loud, never wrongness — every
    /// plant verifies pid + different-tick).
    static FORK_STEER_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// R23-009: cross-process placement lock — lean twin
    /// of audit's `NsLastPidFlock` (audit.rs, R12-005):
    /// POSIX fcntl (NOT flock — flock leaks into
    /// fork-only children), SAME lockfile path (kept in
    /// sync by hand). NEVER NEST (same-process POSIX
    /// locks merge).
    struct ForkPidFlock {
        fd: libc::c_int,
    }

    /// R23-009: take the cross-process placement lock
    /// (blocking; held for milliseconds across one
    /// steer-then-spawn placement loop).
    fn fork_pid_flock() -> ForkPidFlock {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::env::temp_dir().join("scopebase-ns-last-pid.lock");
        let bytes = path.as_os_str().as_bytes();
        let cpath = std::ffi::CString::new(bytes).expect("lock path c-str");
        // SAFETY: valid path pointer with O_CLOEXEC (out
        // of exec'd children's fd tables).
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
        ForkPidFlock { fd }
    }

    impl Drop for ForkPidFlock {
        fn drop(&mut self) {
            // SAFETY: unlock-then-close an owned fd (never
            // nest: releasing here releases the process's
            // lock).
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

    /// R23-019: steering prologue — fork twin of
    /// audit's `steer_hold`: whole-test in-process serial
    /// hold plus ns_last_pid writability proof. Returns the
    /// held guard (keeps serializing for the caller's whole
    /// test) or None after printing the skip reason (caller
    /// returns).
    fn fork_steer_hold() -> Option<std::sync::MutexGuard<'static, ()>> {
        let serial = FORK_STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = match std::fs::read_to_string(last_path) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                eprintln!("skip: ns_last_pid unreadable (no reuse control)");
                return None;
            }
        };
        {
            // Writability probe (locked steer + restore —
            // the restore is best-effort, never load-bearing).
            let _probe = fork_pid_flock();
            if !fork_steer_next_pid_unlocked(last_before.parse::<i32>().unwrap_or(0) + 1) {
                eprintln!("skip: ns_last_pid unwritable (no reuse control)");
                return None;
            }
            let _ = std::fs::write(last_path, &last_before);
        }
        Some(serial)
    }

    /// R23-009: unlocked allocator steer — port of
    /// audit's `audit_steer_next_pid_unlocked` (audit.rs,
    /// R13-009): direct write, sudo fallback. Call ONLY
    /// under a held placement guard or via a
    /// locked-steer-then-restore probe.
    fn fork_steer_next_pid_unlocked(want: libc::pid_t) -> bool {
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

    /// R23-009: steer a fresh `sleep <dur>` onto the freed
    /// `want` with a DIFFERENT tick than `orig_tick` —
    /// lean twin of audit's `steer_sleep_onto` +
    /// `plant_replacement` (R16-003/R17-003), except
    /// same-tick plants retry inside the loop (a fast
    /// plant usually shares the victim's jiffy — bailing
    /// there would skip most runs). Caller holds
    /// [`FORK_STEER_SERIAL`]. None when contended (100
    /// misses — caller skips loud) or the hint is
    /// unwritable. Restores the hint either way.
    fn fork_plant_sleep_onto(
        want: libc::pid_t,
        dur: &str,
        orig_tick: u64,
    ) -> Option<(std::process::Child, u64)> {
        let last_path = "/proc/sys/kernel/ns_last_pid";
        let last_before = std::fs::read_to_string(last_path).unwrap_or_default();
        let found = {
            let _flock = fork_pid_flock();
            let mut found = None;
            for _ in 0..100 {
                if !fork_steer_next_pid_unlocked(want) {
                    break;
                }
                let mut kid = std::process::Command::new("/bin/sleep")
                    .arg(dur)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("standin spawns");
                if kid.id() as libc::pid_t != want {
                    let _ = kid.kill();
                    let _ = kid.wait();
                    continue;
                }
                match fork_starttime(want) {
                    Ok(Some(tick)) if tick != orig_tick => {
                        found = Some((kid, tick));
                        break;
                    }
                    _ => {
                        let _ = kid.kill();
                        let _ = kid.wait();
                        continue;
                    }
                }
            }
            found
        };
        {
            // Fresh guard (the loop guard dropped above —
            // never nest).
            let _restore = fork_pid_flock();
            let _ = std::fs::write(last_path, last_before.trim());
        }
        found
    }

    /// R23-009: argv predicate — fork-shape-exact
    /// `sleep <dur>` (bare argv0 only, never a path —
    /// shared by the match and the post-stat re-verify so
    /// the two can never drift apart).
    fn cmdline_matches_sleep_dur_exact(cmdline: &[u8], dur: &str) -> bool {
        let mut args = cmdline.split(|b| *b == 0);
        let argv0 = args.next().unwrap_or_default();
        let argv1 = args.next().unwrap_or_default();
        argv0 == b"sleep" && argv1 == dur.as_bytes()
    }

    /// R23-008: ownership-scoped scan — the oracle shape
    /// plus the birth window (`tick >= anchor`). Kill
    /// paths pass a kill-time anchor. Read-error
    /// discipline mirrors `live_sleep_with_dur`
    /// (R22-016(a)): NotFound (vanished) skips; any other
    /// read error fails LOUD (a custody scan must never
    /// certify absence over unreadable entries).
    /// Production callers use this (no hook); the R23-009
    /// regression uses
    /// [`sleep_owned_pids_with_dur_with_hook`].
    fn sleep_owned_pids_with_dur(dur: &str, anchor: u64) -> Vec<(libc::pid_t, u64)> {
        sleep_owned_pids_with_dur_with_hook(dur, anchor, None)
    }

    /// R23-009: seam for the recycle regression — `hook`
    /// runs after an argv match and before the stat read
    /// (the finding's window). Production callers pass
    /// `None` (see [`sleep_owned_pids_with_dur`]).
    fn sleep_owned_pids_with_dur_with_hook(
        dur: &str,
        anchor: u64,
        hook: Option<&dyn Fn(libc::pid_t)>,
    ) -> Vec<(libc::pid_t, u64)> {
        let mut found = Vec::new();
        let entries = std::fs::read_dir("/proc").expect("/proc readable");
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("custody scan: readdir mid-scan failed: {error}"),
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let cmdline = match std::fs::read(format!("/proc/{name}/cmdline")) {
                Ok(c) => c,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    panic!("custody scan: /proc/{name}/cmdline unreadable mid-scan: {error}")
                }
            };
            if !cmdline_matches_sleep_dur_exact(&cmdline, dur) {
                continue;
            }
            let pid: libc::pid_t = match name.parse() {
                Ok(pid) => pid,
                Err(_) => continue,
            };
            if let Some(hook) = hook {
                hook(pid);
            }
            match fork_starttime(pid) {
                Ok(Some(tick)) => {
                    // R23-009: bind the argv to the tick — a
                    // recycle between the cmdline and stat
                    // reads shows the replacement's argv here;
                    // nonmatching ⟹ skip (the old code
                    // authenticated the replacement's tick
                    // with the former occupant's argv, then
                    // killed it). Read-error discipline as
                    // above (NotFound skips; else LOUD).
                    let cmdline2 = match std::fs::read(format!("/proc/{pid}/cmdline")) {
                        Ok(cmdline2) => cmdline2,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => panic!(
                            "custody scan: /proc/{pid}/cmdline unreadable on re-verify: {error}"
                        ),
                    };
                    if !cmdline_matches_sleep_dur_exact(&cmdline2, dur) {
                        continue;
                    }
                    if tick < anchor {
                        continue;
                    }
                    if !task_owned_by_us(pid) {
                        continue;
                    }
                    let live = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                        .ok()
                        .and_then(|text| {
                            text.rsplit_once(") ").and_then(|(_, after)| {
                                after.split_whitespace().next().map(str::to_string)
                            })
                        });
                    if live.as_deref() != Some("Z") {
                        found.push((pid, tick));
                    }
                }
                Ok(None) => continue,
                Err(error) => panic!("custody scan: stat unreadable mid-scan: {error}"),
            }
        }
        found
    }

    /// R22-008: wrapper-side custody for an unknown-pid m2
    /// — tick-gated SIGKILL per scanned birth, then a
    /// bounded tick-aware drain per birth. True when no
    /// LIVE `sleep dur` remains within the bound. A re-scan
    /// after the drain catches births raced past the first
    /// scan (none expected — the middleman is dead — but
    /// custody never trusts a single pass).
    fn kill_sleep_with_dur(dur: &str, anchor: u64) -> bool {
        // R23-008: the anchor is captured by the CALLER
        // (wrapper entry / pre-staging — a kill-time anchor
        // lands a jiffy past births staged ms earlier and
        // would exclude our own fixture).
        for (pid, tick) in sleep_owned_pids_with_dur(dur, anchor) {
            kill_tick_gated_fork(pid, tick);
            if !birth_drained(pid, tick, std::time::Duration::from_secs(5)) {
                return false;
            }
        }
        sleep_owned_pids_with_dur(dur, anchor).is_empty()
    }

    /// R22-007 denied-pin probe (fresh image): seccomp-deny
    /// `pidfd_open` in SELF (the pin genuinely fails —
    /// realistic denial plumbing, not a forged `None`),
    /// then zombie-m1 + unwind; the drop must go LOUD
    /// (R22007-UNPINNED) and m2 survives for the parent
    /// (its stdio is null — no pipe is held, so the output
    /// read cannot wedge). RED (old code: silent return —
    /// no marker). Duration 991 is unique to this test.
    fn middleman_guard_denied_pin_reports_unpinned_probe() {
        use super::super::seccomp::{install_deny_one, DenyAction};
        use std::panic::AssertUnwindSafe;
        // R23-002: `unsupported_arch` skips explicitly
        // (seccomp denial is x86-only — exit 0 with the
        // SKIP marker; the wrapper judges the marker,
        // never the install). Any other install failure
        // is still staging-broken.
        if let Err(error) = install_deny_one(libc::SYS_pidfd_open, DenyAction::Eperm) {
            if error.stage() == "unsupported_arch" {
                eprintln!("R22007-SKIP unsupported_arch (seccomp denial unavailable)");
                return;
            }
            panic!("deny installs (staging): {error}");
        }
        // Anti-vacuity: the denial bites (self-probe on our
        // own live pid).
        assert_eq!(
            super::super::seccomp::pidfd_open_raw(std::process::id() as libc::pid_t),
            Err(libc::EPERM),
            "staging broken (pidfd_open not denied?)"
        );
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("991") }.expect("pair staged");
        // R23-011: arm BEFORE the stat read (a failing
        // observation must unwind through the guard).
        let _pair = MiddlemanPairGuard::armed(m1, m2);
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        println!("R22007-M2 {m2} {tick2}");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            assert_eq!(
                unsafe { libc::kill(m1, libc::SIGKILL) },
                0,
                "staging broken (m1 kill)"
            );
            settle_zombie(m1);
            panic!("simulated observation failure");
        }));
        drop(_pair);
        assert!(outcome.is_err(), "staging broken (must unwind)");
        eprintln!("R22007-PIN-DONE");
    }

    /// R22-007 denied-pin wrapper: the probe runs
    /// fresh-image (seccomp is irreversible). Cleanup rides
    /// the printed birth (tick-gated) and runs BEFORE the
    /// verdict asserts so RED runs stay clean.
    #[test]
    fn middleman_guard_denied_pin_reports_unpinned() {
        if std::env::var("SCOPEBASE_R22007_DENY_PIN").is_ok() {
            middleman_guard_denied_pin_reports_unpinned_probe();
            return;
        }
        let out = run_fresh_probe_bounded(
            "SCOPEBASE_R22007_DENY_PIN",
            "middleman_guard_denied_pin_reports_unpinned",
        );
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        // R23-002: explicit unsupported_arch skip (the
        // probe stages nothing on this path — no custody
        // to run — so the check precedes the M2 parse).
        if stderr.contains("R22007-SKIP") {
            eprintln!(
                "skip: seccomp pidfd_open denial unsupported on this arch (see probe stderr)"
            );
            return;
        }
        let (m2, tick2): (libc::pid_t, u64) = stdout
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22007-M2 ")?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
            .expect("staging broken (no m2 line?)");
        kill_tick_gated_fork(m2, tick2);
        assert!(
            birth_drained(m2, tick2, std::time::Duration::from_secs(5)),
            "parent must retire the survivor"
        );
        assert!(out.status.success(), "probe must complete\n{stderr}");
        assert!(
            stderr.contains("R22007-PIN-DONE"),
            "probe must cite completion\n{stderr}"
        );
        assert!(
            stderr.contains("R22007-UNPINNED"),
            "drop must go loud when unpinned\n{stderr}"
        );
    }

    /// R23-013 denied-signal probe (fresh image): mirror of
    /// the denied-pin probe — seccomp-deny
    /// `pidfd_send_signal` in SELF (the pin genuinely
    /// acquires — realistic denial plumbing, not a forged
    /// failure), then zombie-m1 + unwind; the drop must go
    /// LOUD (R22007-PIN-DENIED naming m2) and m2 survives
    /// for the parent (wrapper custody via the transmitted
    /// birth). RED (old code: bare signal, result ignored —
    /// no marker, silent abandon). Duration 996 is unique
    /// to this test.
    fn middleman_guard_denied_signal_reports_unresolved_probe() {
        use super::super::seccomp::{install_deny_one, DenyAction};
        use std::panic::AssertUnwindSafe;
        // R23-002: `unsupported_arch` skips explicitly
        // (seccomp denial is x86-only — exit 0 with the
        // SKIP marker; the wrapper judges the marker,
        // never the install). Any other install failure
        // is still staging-broken.
        if let Err(error) = install_deny_one(libc::SYS_pidfd_send_signal, DenyAction::Eperm) {
            if error.stage() == "unsupported_arch" {
                eprintln!("R22007-SKIP unsupported_arch (seccomp denial unavailable)");
                return;
            }
            panic!("deny installs (staging): {error}");
        }
        // Anti-vacuity: the pin ACQUIRES (open allowed) but
        // the signal is DENIED (self-probe, signal 0 —
        // queries only, sends nothing).
        let selfpin =
            super::super::seccomp::pidfd_open_raw(std::process::id() as libc::pid_t)
                .expect("staging broken (pin acquisition must be allowed)");
        // SAFETY: signal 0 queries only (denial probe).
        let sent = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, selfpin, 0, 0, 0) };
        let denied_errno = std::io::Error::last_os_error().raw_os_error();
        // SAFETY: fd owned by this probe.
        unsafe { libc::close(selfpin) };
        assert_eq!(
            (sent, denied_errno),
            (-1, Some(libc::EPERM)),
            "staging broken (send-signal not denied?)"
        );
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("996") }.expect("pair staged");
        // R23-011: arm BEFORE the stat read (a failing
        // observation must unwind through the guard).
        let _pair = MiddlemanPairGuard::armed(m1, m2);
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        println!("R22007-M2 {m2} {tick2}");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            assert_eq!(
                unsafe { libc::kill(m1, libc::SIGKILL) },
                0,
                "staging broken (m1 kill)"
            );
            settle_zombie(m1);
            panic!("simulated observation failure");
        }));
        drop(_pair);
        assert!(outcome.is_err(), "staging broken (must unwind)");
        eprintln!("R22007-PIN-DONE");
    }

    /// R23-013 denied-signal wrapper: mirror of the
    /// denied-pin wrapper (fresh image; cleanup before
    /// verdict).
    #[test]
    fn middleman_guard_denied_signal_reports_unresolved() {
        if std::env::var("SCOPEBASE_R23013_DENY_SIGNAL").is_ok() {
            middleman_guard_denied_signal_reports_unresolved_probe();
            return;
        }
        let out = run_fresh_probe_bounded(
            "SCOPEBASE_R23013_DENY_SIGNAL",
            "middleman_guard_denied_signal_reports_unresolved",
        );
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        // R23-002: explicit unsupported_arch skip (the
        // probe stages nothing on this path — no custody
        // to run — so the check precedes the M2 parse).
        if stderr.contains("R22007-SKIP") {
            eprintln!(
                "skip: seccomp send-signal denial unsupported on this arch (see probe stderr)"
            );
            return;
        }
        let (m2, tick2): (libc::pid_t, u64) = stdout
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22007-M2 ")?;
                let (pid, tick) = rest.split_once(' ')?;
                Some((pid.parse().ok()?, tick.parse().ok()?))
            })
            .expect("staging broken (no m2 line?)");
        kill_tick_gated_fork(m2, tick2);
        assert!(
            birth_drained(m2, tick2, std::time::Duration::from_secs(5)),
            "parent must retire the survivor"
        );
        assert!(out.status.success(), "probe must complete\n{stderr}");
        assert!(
            stderr.contains("R22007-PIN-DONE"),
            "probe must cite completion\n{stderr}"
        );
        assert!(
            stderr.contains("R22007-PIN-DENIED"),
            "drop must go loud when the pin signal is denied\n{stderr}"
        );
    }

    /// R23-011 site 1: the grandchild stat read fails (fd
    /// outage) AFTER the pair guard armed — the unwind
    /// must discharge the pair (m1 reaped by the drop, m2
    /// killed, orphan drained via init). Fresh-image probe
    /// (the outage is process-global); the probe runs
    /// twice — the unguarded bad control (must STRAND,
    /// proving the leg discriminates — swept loud after)
    /// and the guarded shape (must discharge clean).
    /// Duration 878 is unique to this test.
    #[test]
    fn r22007_stat_failure_discharges_through_guard() {
        if std::env::var("SCOPEBASE_R23011_STAT_OUTAGE").is_ok() {
            r22007_stat_failure_discharges_through_guard_probe();
            return;
        }
        // R23-008: ownership-window anchor — wrapper entry
        // (before either probe stages anything).
        let anchor = boot_ticks_now().expect("custody anchor needs the boot clock");
        for no_arm in [true, false] {
            let exe = std::env::current_exe().expect("own test binary");
            let mut cmd = std::process::Command::new(exe);
            cmd.arg("--exact")
                .arg("fixture::linux::fork::tests::r22007_stat_failure_discharges_through_guard")
                .arg("--nocapture")
                .env("SCOPEBASE_R23011_STAT_OUTAGE", "1")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if no_arm {
                cmd.env("SCOPEBASE_R23011_NO_ARM", "1");
            }
            let out = cmd.output().expect("probe runs");
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            assert!(
                out.status.success(),
                "probe must exit 0 (measurement, never verdict)\n{stderr}"
            );
            let (m1, tick1, m2, tick2): (libc::pid_t, u64, libc::pid_t, u64) = stdout
                .lines()
                .find_map(|line| {
                    let rest = line.strip_prefix("R23011-PAIR ")?;
                    let mut words = rest.split_whitespace();
                    Some((
                        words.next()?.parse().ok()?,
                        words.next()?.parse().ok()?,
                        words.next()?.parse().ok()?,
                        words.next()?.parse().ok()?,
                    ))
                })
                .expect("probe must print custody");
            let marked = if stdout.contains("R23011-DISCHARGED") {
                true
            } else {
                assert!(
                    stdout.contains("R23011-STRANDED"),
                    "probe must mark the outcome\n{stdout}"
                );
                false
            };
            if no_arm {
                // Bad control: unguarded MUST strand (else
                // the leg is vacuous) — then sweep loud.
                assert!(!marked, "bad control must strand (vacuous otherwise)");
                kill_tick_gated_fork(m1, tick1);
                assert!(
                    birth_drained(m1, tick1, std::time::Duration::from_secs(5)),
                    "wrapper must drain the stranded m1"
                );
                assert!(
                    kill_sleep_with_dur("878", anchor),
                    "wrapper must drain the stranded sleep 878"
                );
                eprintln!("R23011: bad control stranded + swept as designed");
            } else {
                // Guarded: must discharge — wrapper
                // re-verifies birth-aware (absent OR
                // different-birth — never vacancy-only).
                assert!(marked, "guarded probe must discharge\n{stdout}\n{stderr}");
                match fork_starttime(m1) {
                    Ok(Some(now)) => assert_ne!(now, tick1, "m1 birth must be retired"),
                    Ok(None) => {}
                    Err(error) => panic!("m1 drainage unverifiable: {error}"),
                }
                match fork_starttime(m2) {
                    Ok(Some(now)) => assert_ne!(now, tick2, "m2 birth must be retired"),
                    Ok(None) => {}
                    Err(error) => panic!("m2 drainage unverifiable: {error}"),
                }
                assert!(
                    !live_sleep_with_dur("878"),
                    "no live sleep-878 may survive the guarded probe"
                );
            }
        }
    }

    /// R23-011 site-1 probe (fresh image): stage the pair,
    /// arm unless the bad-control env is set, transmit
    /// custody, exhaust fds, and fail the grandchild stat
    /// read through a caught unwind (the guard drops
    /// during the unwind — the outage hold drops first,
    /// so the drop's verify reads work). Marks
    /// DISCHARGED/STRANDED after a settle (init latency);
    /// exits 0 either way (the wrapper judges).
    fn r22007_stat_failure_discharges_through_guard_probe() {
        use std::panic::AssertUnwindSafe;
        use std::time::{Duration, Instant};
        let no_arm = std::env::var("SCOPEBASE_R23011_NO_ARM").is_ok();
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("878") }.expect("pair staged");
        let tick1 = fork_starttime(m1)
            .expect("staging broken (m1 stat)")
            .expect("staging broken (m1 visible)");
        let tick2 = fork_starttime(m2)
            .expect("staging broken (m2 stat)")
            .expect("staging broken (m2 visible)");
        println!("R23011-PAIR {m1} {tick1} {m2} {tick2}");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            // Guard BEFORE the hold (unwind drops the hold
            // first, then the guard with working fds).
            let _pair = (!no_arm).then(|| MiddlemanPairGuard::armed(m1, m2));
            let _hold = OutageHold::exhaust();
            // Anti-vacuity: the outage bites exactly here.
            assert!(
                fork_starttime(m2).is_err(),
                "staging broken (stat readable under hold?)"
            );
            fork_starttime(m2)
                .expect("m2 stat readable")
                .expect("m2 visible");
        }));
        assert!(outcome.is_err(), "staging broken (stat must fail under outage)");
        // Settle + mark (m2 orphans to init on discharge —
        // init latency, polled; a strand stays live past
        // the bound).
        let end = Instant::now() + Duration::from_secs(5);
        let (mut m1gone, mut m2gone) = (false, false);
        while Instant::now() < end {
            m1gone = fork_starttime(m1) != Ok(Some(tick1));
            m2gone = fork_starttime(m2) != Ok(Some(tick2));
            if m1gone && m2gone {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if m1gone && m2gone {
            println!("R23011-DISCHARGED");
        } else {
            println!("R23011-STRANDED");
        }
    }

    /// R22-004(a): reap proof by /proc ABSENCE —
    /// zombies retain /proc entries, so absence ⟹ reaped
    /// (no waitpid — a wait would steal a recycled sibling
    /// zombie's status: R21-001-class). `Ok(true)` = absent
    /// ⟹ reaped; `Ok(false)` = present ⟹ UNPROVEN (our
    /// unreaped zombie (RED) or a recycled occupant — both
    /// fail closed, never certify); `Err` = outage (fails
    /// loud, never certifies). The `Err` arm is a 1-line
    /// mapping with no cheap fault (a non-NotFound /proc
    /// read error needs EMFILE — fresh-image-only per
    /// R22-012); the absence/presence/no-steal legs carry
    /// the regression below. R23-019: vacancy-only — a
    /// recycled occupant reads `Ok(false)` (inconclusive,
    /// never a cleanup defect); post-reap retirement
    /// claims use [`prove_reaped_gone_or_recycled`]
    /// (tick-aware — a different-birth occupant keeps the
    /// evidence valid instead of failing the test).
    fn prove_reaped_by_absence(pid: libc::pid_t) -> Result<bool, String> {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.to_string()),
            Ok(_) => Ok(false),
        }
    }

    /// R23-019: tick-aware reap proof — the vacancy-only
    /// bool above fails a correctly retired birth when a
    /// different-birth occupant reuses the number. `Gone`
    /// = absent ⟹ reaped; `Recycled` = a different birth
    /// holds the number ⟹ OUR birth reaped (retirement
    /// valid, vacancy unproven); `StillOurs` = our birth
    /// present ⟹ NOT reaped (RED); `Unreadable` = outage
    /// ⟹ inconclusive (loud, never certified). Callers
    /// match explicitly (never `== Gone` — a recycled
    /// occupant must keep the evidence valid, and an
    /// unreadable birth must refuse to certify).
    enum ReapedProof {
        Gone,
        Recycled(u64),
        StillOurs,
        Unreadable(String),
    }

    /// R23-019: prove the `tick` birth on `pid` reaped
    /// (gone-or-recycled — see [`ReapedProof`]). No
    /// waitpid (same R21-001-class no-steal contract as
    /// [`prove_reaped_by_absence`]).
    fn prove_reaped_gone_or_recycled(pid: libc::pid_t, tick: u64) -> ReapedProof {
        match fork_starttime(pid) {
            Ok(None) => ReapedProof::Gone,
            Ok(Some(now)) if now == tick => ReapedProof::StillOurs,
            Ok(Some(now)) => ReapedProof::Recycled(now),
            Err(error) => ReapedProof::Unreadable(error),
        }
    }

    /// R21-009: tight EMFILE hold (confine soft NOFILE
    /// to 4096 + fill, restores on drop). R22-012:
    /// FRESH-IMAGE CHILDREN ONLY — never in the suite
    /// process (a held table breaks descriptor siblings,
    /// and this bookkeeping bypasses audit's confinement
    /// bookkeeping — interleaved holds corrupt RLIMIT.
    /// Single-hold-per-child only; concurrent holds in one
    /// process are forbidden). Never raises on confine,
    /// never lowers on restore.
    struct OutageHold {
        previous_cur: Option<libc::rlim_t>,
        _held: Vec<std::fs::File>,
    }

    impl OutageHold {
        fn exhaust() -> Self {
            // SAFETY: getrlimit/setrlimit with a valid local rlimit.
            let previous_cur = unsafe {
                let mut limit: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    None
                } else {
                    let original = limit.rlim_cur;
                    let cap = original.min(4096);
                    if cap < original {
                        limit.rlim_cur = cap;
                        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                            return OutageHold {
                                previous_cur: None,
                                _held: Self::fill(),
                            };
                        }
                    }
                    Some(original)
                }
            };
            OutageHold {
                previous_cur,
                _held: Self::fill(),
            }
        }
        fn fill() -> Vec<std::fs::File> {
            let mut held = Vec::new();
            while let Ok(file) = std::fs::File::open("/dev/null") {
                held.push(file);
            }
            assert!(!held.is_empty(), "exhaustion must consume fds");
            held
        }
        /// R22-016(a): release exactly one held fd (the
        /// one-free-slot staging — opendir consumes it,
        /// every later open fails EMFILE).
        fn release_one(&mut self) {
            assert!(self._held.pop().is_some(), "staging broken (hold empty?)");
        }
    }

    impl Drop for OutageHold {
        fn drop(&mut self) {
            if let Some(previous) = self.previous_cur {
                // SAFETY: getrlimit/setrlimit with a valid local rlimit.
                unsafe {
                    let mut limit: libc::rlimit = std::mem::zeroed();
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0
                        && limit.rlim_cur < previous
                    {
                        limit.rlim_cur = previous;
                        libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
                    }
                }
            }
        }
    }

    /// R22-012: env flag selecting the fault-child branch
    /// (fresh image) of the pair-guard test below.
    const R22012_FAULT_ENV: &str = "SCOPEBASE_R22012_FAULT";

    /// R22-012: one hammered sibling fd-op (pipe + open),
    /// retry-bounded. Retries distinguish transient
    /// exogenous µs-holds (pre-existing audit exhausters —
    /// FLAKE01's family, 1ms apart they pass through)
    /// from a WIDE regression (the fault moved back
    /// in-process and held open — all retries fail). The
    /// strict discrimination lives in the holder-pid
    /// assert (structural); this hammer is pressure, not
    /// proof.
    fn hammer_sibling_fd_op() -> std::io::Result<()> {
        // R24-005 fault hook (unset = no-op): fail the
        // hammer (parent-side failure with the probe
        // GO-blocked — the unwind must retire the pair,
        // never just the probe).
        if std::env::var("SCOPEBASE_R24005_FAIL_HAMMER").is_ok() {
            return Err(std::io::Error::other("R24005 fault: hammer fails"));
        }
        let mut last = std::io::Error::other("unreached");
        for _ in 0..3 {
            let attempt = (|| -> std::io::Result<()> {
                let (read, write) = std::io::pipe()?;
                drop((read, write));
                let file = std::fs::File::open("/dev/null")?;
                drop(file);
                Ok(())
            })();
            match attempt {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last = error;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
        Err(last)
    }

    /// R22-012: current NOFILE soft limit (rlimit-preserved
    /// assert — the fault must not leak a confine).
    fn nofile_soft_limit() -> u64 {
        // SAFETY: getrlimit with a valid local rlimit.
        unsafe {
            let mut limit: libc::rlimit = std::mem::zeroed();
            assert_eq!(
                libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit),
                0,
                "own rlimit readable"
            );
            limit.rlim_cur as u64
        }
    }

    /// R21-009: a failed FIRST observation over a staged
    /// middleman pair must unwind through the birth guard —
    /// both retired before the panic propagates. R22-012:
    /// the fault scenario runs in a FRESH-IMAGE child
    /// (in-process EMFILE breaks descriptor siblings and
    /// bypasses audit's confinement bookkeeping — the hold
    /// must never live in the suite process). The wrapper
    /// spawns self `--exact` with the env flag, rendezvouses
    /// (R23-020: ENTER when the child opens the fault window,
    /// exactly 101 sibling fd-ops INSIDE it, GO to release —
    /// overlap by construction, never by scheduling luck),
    /// then asserts exit 0 + discharge markers + holder-pid !=
    /// self (STRUCTURAL: an in-process reintroduction
    /// fails here deterministically) + GO-MISSING absent
    /// (the child saw the hammered window) + the child's
    /// own rlimit-restore marker (R23-021: the confine lives
    /// in the child — proven there, where no sibling can
    /// interleave; the old parent-side equality
    /// misattributed concurrent sibling transitions).
    /// The child stages its OWN pair (it is the parent —
    /// kill+reap both work there), arms the guard, blocks on
    /// GO inside its EMFILE hold, faults the first read,
    /// then proves both original births drained
    /// (birth-aware; unreadable fails) and its rlimit
    /// restored. Duration 108 is unique to this test. Pre-fix
    /// RED (unguarded): the pair strands (m1 pausing, m2
    /// sleeping) — proven by neutering the guard line.
    /// R22-014: the fault child rides a birth guard (a
    /// hammer-loop panic retires it — no orphan transient;
    /// the child is additionally self-sufficient: it
    /// retires its own pair and exits alone in ms).
    /// R24-005: the wrapper also arms parent-side pair
    /// guards from the child's PAIR line (a parent-side
    /// failure retires the pair, never just the probe)
    /// and restages via SCOPEBASE_R22012_SLEEP_DUR
    /// (fault legs drive it as a child under parallel
    /// runs — never share 108).
    #[test]
    fn middleman_pair_guard_discharges_on_first_read_failure() {
        if std::env::var(R22012_FAULT_ENV).is_ok() {
            r22012_fault_child_scenario();
            return;
        }
        let me = std::process::id();
        let exe = std::env::current_exe().expect("own test binary");
        // R23-020: stdin piped (the GO byte rides it — the
        // child blocks in the fault window until the parent
        // has hammered INSIDE it).
        let mut child = std::process::Command::new(exe)
            .arg("--exact")
            .arg("fixture::linux::fork::tests::middleman_pair_guard_discharges_on_first_read_failure")
            .arg("--nocapture")
            .env(R22012_FAULT_ENV, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("fault child spawns");
        let mut _cguard = ForkChildGuard::new(child.id() as libc::pid_t);
        // R24-006: forward the probe birth AT SPAWN (the
        // deny leg's child dies pre-ENTER — before any
        // other forward — the leg still names it).
        {
            let probe = child.id() as libc::pid_t;
            let probe_tick = fork_starttime(probe)
                .expect("staging broken (probe stat)")
                .expect("staging broken (probe visible)");
            eprintln!("R22012-PROBE child={probe} ctick={probe_tick}");
        }
        let mut child_stdin = child.stdin.take().expect("fault child stdin piped");
        let mut child_stdout = child.stdout.take().expect("fault child stdout piped");
        let child_stderr = child.stderr.take().expect("fault child stderr piped");
        // SAFETY: fcntl O_NONBLOCK on our own pipe fd only.
        use std::os::unix::io::AsRawFd as _;
        let flags = unsafe { libc::fcntl(child_stderr.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "stderr fcntl F_GETFL failed");
        assert_eq!(
            unsafe { libc::fcntl(child_stderr.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0,
            "stderr fcntl O_NONBLOCK failed"
        );
        use std::io::BufRead as _;
        let mut stderr_lines = std::io::BufReader::new(child_stderr);
        let mut stderr = String::new();
        // R23-020 phase 1: ENTER (the child staged its pair
        // and opened the fault window — hold alive, pair
        // guarded, blocked on our GO). EOF/deadline fail
        // loud (a child that never ENTERs never runs the
        // hammered window — never a silent pass).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if stderr.contains("R22012-FAULT-ENTER") {
                break;
            }
            let mut chunk = String::new();
            match stderr_lines.read_line(&mut chunk) {
                Ok(0) => {
                    let _ = child.wait();
                    _cguard.disarm();
                    panic!("fault child died before ENTER\n{stderr}");
                }
                Ok(_) => stderr.push_str(&chunk),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        panic!("fault child hung pre-ENTER past 60 s (killed loud)");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("fault child stderr unreadable: {error}"),
            }
        }
        // R24-005: pair custody from the child's PAIR
        // line (transmitted pre-query — present whenever
        // ENTER is). Arm parent-side guards BEFORE
        // hammering (a hammer failure unwinds through
        // them — the pair retires, never just the probe)
        // + forward the custody (fault legs prove
        // retirement from it).
        let (m1, t1, m2, t2): (libc::pid_t, u64, libc::pid_t, u64) = stderr
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22012-PAIR ")?;
                let mut words = rest.split_whitespace();
                Some((
                    words.next()?.strip_prefix("m1=")?.parse().ok()?,
                    words.next()?.strip_prefix("t1=")?.parse().ok()?,
                    words.next()?.strip_prefix("m2=")?.parse().ok()?,
                    words.next()?.strip_prefix("t2=")?.parse().ok()?,
                ))
            })
            .unwrap_or_else(|| panic!("staging broken (child PAIR line missing)\n{stderr}"));
        let mut _m1guard = LegChildGuard {
            pid: m1,
            tick: Some(t1),
            disarmed: false,
        };
        let mut _m2guard = LegChildGuard {
            pid: m2,
            tick: Some(t2),
            disarmed: false,
        };
        let cpid = child.id() as libc::pid_t;
        let ctick = fork_starttime(cpid)
            .expect("staging broken (child stat)")
            .expect("staging broken (child visible)");
        eprintln!("R22012-PAIR m1={m1} t1={t1} m2={m2} t2={t2} child={cpid} ctick={ctick}");
        // R24-005 fault hook (unset = no-op): SIGSTOP the
        // probe NOW (frozen mid-GO-wait — its self-retire
        // can't race the parent's unwind).
        if std::env::var("SCOPEBASE_R24005_STOP_AFTER_ENTER").is_ok() {
            // SAFETY: SIGSTOP to our own staged child.
            unsafe {
                libc::kill(cpid, libc::SIGSTOP);
            }
        }
        // R23-020: the hammer lands INSIDE the window by
        // construction (the child is blocked on our GO
        // below — overlap needs no scheduling luck). The
        // count is exact (tripwire against loop edits).
        let mut hammered = 0u64;
        for _ in 0..101 {
            hammer_sibling_fd_op().expect("sibling fd-op succeeds during fresh-image fault");
            hammered += 1;
        }
        assert!(
            hammered > 100,
            "hammer must pressure the fault window (got {hammered})"
        );
        // R23-020 phase 2: GO (the child faults + discharges)
        // then EOF (markers collected above + below).
        use std::io::Write as _;
        child_stdin
            .write_all(b"G")
            .expect("GO lands");
        drop(child_stdin);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let mut chunk = String::new();
            match stderr_lines.read_line(&mut chunk) {
                Ok(0) => break,
                Ok(_) => stderr.push_str(&chunk),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        panic!("fault child hung mid-scenario past 60 s (killed loud)");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("fault child stderr unreadable: {error}"),
            }
        }
        // Harness chatter (small — EOF already, drains at once).
        let mut _stdout_buf = Vec::new();
        use std::io::Read as _;
        child_stdout
            .read_to_end(&mut _stdout_buf)
            .expect("stdout drains");
        let status = child.wait().expect("child reaps");
        _cguard.disarm();
        assert!(status.success(), "fault child must exit 0\n{stderr}");
        assert!(
            stderr.contains("R22012-DISCHARGED"),
            "discharge marker\n{stderr}"
        );
        // R24-005: the child proved pair retirement
        // (DISCHARGED) — parent-side custody ends here
        // (any earlier unwind retires through the guards
        // above).
        _m1guard.disarmed = true;
        _m2guard.disarmed = true;
        assert!(
            !stderr.contains("R22012-GO-MISSING"),
            "GO must land (the child saw the hammered window)\n{stderr}"
        );
        // R23-020 (reopened): the child must READ the GO
        // (overlap proof — the write landing in the pipe
        // buffer proves nothing about the child; deleting
        // the child's GO-read block fails here).
        assert!(
            stderr.contains("R22012-GO-READ"),
            "GO must be READ (a written-but-unread GO never passes)\n{stderr}"
        );
        // R23-021: the confine lives in the CHILD (proven by
        // its own marker below) — the old parent-side exact
        // equality misattributed concurrent sibling
        // transitions to this child (a sibling hold between
        // the snapshots fails it with no fault at all).
        // Child non-interference stays pinned structurally
        // (holder != self here — a separate image cannot
        // touch our rlimit).
        assert!(
            stderr.contains("R22012-RLIMIT-OK"),
            "rlimit-restore marker\n{stderr}"
        );
        let holder: u32 = stderr
            .lines()
            .find_map(|line| {
                line.strip_prefix("R22012-HOLDER pid=")
                    .and_then(|pid| pid.trim().parse().ok())
            })
            .expect("holder marker\n{stderr}");
        assert_ne!(
            holder, me,
            "fault must run in the child image (in-process reintroduction fails here)"
        );
    }

    /// R24-005: a parent-side failure with the probe
    /// GO-blocked must retire the PAIR, never just the
    /// probe. Drives the REAL wrapper as a child with
    /// STOP_AFTER_ENTER (the probe freezes mid-GO-wait —
    /// its self-retire can't race the unwind) +
    /// FAIL_HAMMER (the parent's hammer panics): the
    /// child MUST fail citing the hammer fault, and BOTH
    /// staged pair births (forwarded custody) plus the
    /// probe MUST be retired (gone-or-recycled —
    /// birth-aware, never vacancy-only). RED (no
    /// parent-side pair guards): the probe dies but m1
    /// pauses and the sleeper survives. Duration 110
    /// (restaged child — never the GREEN 108).
    #[test]
    fn r24005_rendezvous_failure_retires_pair_not_just_probe() {
        let exe = std::env::current_exe().expect("own test binary");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("fixture::linux::fork::tests::middleman_pair_guard_discharges_on_first_read_failure")
            .arg("--nocapture")
            .env("SCOPEBASE_R24005_STOP_AFTER_ENTER", "1")
            .env("SCOPEBASE_R24005_FAIL_HAMMER", "1")
            .env("SCOPEBASE_R22012_SLEEP_DUR", "110")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("wrapper child runs");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        // (a) The wrapper failed ON the hammer fault (the
        // forced parent-side failure — staging proof; a
        // staging flake fails here instead).
        assert!(
            !out.status.success(),
            "wrapper must fail on the forced hammer fault\n{stderr}"
        );
        assert!(
            stderr.contains("R24005 fault: hammer fails"),
            "wrapper must cite the hammer fault\n{stderr}"
        );
        // (b) Custody (the wrapper's forward — proves IT
        // parsed the pair before failing).
        let (m1, t1, m2, t2, cpid, ctick): (
            libc::pid_t,
            u64,
            libc::pid_t,
            u64,
            libc::pid_t,
            u64,
        ) = stderr
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22012-PAIR ")?;
                let mut words = rest.split_whitespace();
                Some((
                    words.next()?.strip_prefix("m1=")?.parse().ok()?,
                    words.next()?.strip_prefix("t1=")?.parse().ok()?,
                    words.next()?.strip_prefix("m2=")?.parse().ok()?,
                    words.next()?.strip_prefix("t2=")?.parse().ok()?,
                    words.next()?.strip_prefix("child=")?.parse().ok()?,
                    words.next()?.strip_prefix("ctick=")?.parse().ok()?,
                ))
            })
            .unwrap_or_else(|| panic!("wrapper must forward pair custody\n{stderr}"));
        // (c) BOTH pair births retired (birth-aware —
        // never vacancy-only) + the probe retired (not
        // merely the probe — the finding's bar).
        // N4 (R1): independent expected-identity
        // backstops (a mutant-RED StillOurs unwinds
        // through them — the failure records, nothing
        // strands; disarmed once all three prove
        // retired — AFTER the judge below, never
        // before).
        let mut _b1 = LegChildGuard {
            pid: m1,
            tick: Some(t1),
            disarmed: false,
        };
        let mut _b2 = LegChildGuard {
            pid: m2,
            tick: Some(t2),
            disarmed: false,
        };
        let mut _b3 = LegChildGuard {
            pid: cpid,
            tick: Some(ctick),
            disarmed: false,
        };
        // N5 (R1): bounded birth-aware SETTLE before
        // each verdict read (a correctly-retired orphan
        // may still be an unreaped zombie — a single
        // read would misjudge it StillOurs; the bool
        // only hurries — the proof below judges);
        // verdicts COLLECTED under settle, then judged
        // in order (first failure panics — the backstops
        // above retire every survivor on unwind).
        let mut verdicts = Vec::new();
        for (pid, tick, who) in [
            (m1, t1, "m1"),
            (m2, t2, "sleeper"),
            (cpid, ctick, "probe"),
        ] {
            let _ = birth_drained(pid, tick, std::time::Duration::from_secs(5));
            verdicts.push((who, pid, tick, prove_reaped_gone_or_recycled(pid, tick)));
        }
        for (who, pid, tick, proof) in verdicts {
            match proof {
                ReapedProof::Gone | ReapedProof::Recycled(_) => {}
                ReapedProof::StillOurs => panic!(
                    "R24005: {who} {pid}/{tick} survives the rendezvous failure \
                     (unwind retired the probe only?)"
                ),
                ReapedProof::Unreadable(error) => panic!(
                    "inconclusive ({who} unreadable: {error}) — refusing to certify"
                ),
            }
        }
        _b1.disarmed = true;
        _b2.disarmed = true;
        _b3.disarmed = true;
    }

    /// R24-006: a denied rlimit snapshot must retire
    /// BOTH staged births before probe termination (the
    /// snapshot sits between the outer disarm and the
    /// inner arm — denying it used to panic with NEITHER
    /// guard armed). Drives the REAL wrapper as a child
    /// with DENY_RLIMIT (the probe denies prlimit64 —
    /// the syscall glibc's getrlimit actually issues —
    /// then snapshots): the child MUST die pre-ENTER
    /// citing the deny, and BOTH pair births (custody
    /// out pre-query) plus the probe MUST be retired
    /// (gone-or-recycled — birth-aware). Nothing else
    /// retires (init only reaps — reaping never kills) —
    /// observed-retired proves the unwinding outer guard
    /// killed pre-exit. RED (pre-fix handoff): the pair
    /// strands (m1 pausing, sleeper live). Duration 111
    /// (restaged child — never the GREEN 108).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn r24006_denied_rlimit_snapshot_retires_pair_before_probe_exit() {
        let exe = std::env::current_exe().expect("own test binary");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("fixture::linux::fork::tests::middleman_pair_guard_discharges_on_first_read_failure")
            .arg("--nocapture")
            .env("SCOPEBASE_R24006_DENY_RLIMIT", "1")
            .env("SCOPEBASE_R22012_SLEEP_DUR", "111")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("wrapper child runs");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        // (a) The probe died pre-ENTER on the DENY (the
        // forced fault — staging proof; a staging flake
        // fails here instead).
        assert!(
            !out.status.success(),
            "wrapper must fail (probe dies pre-ENTER)\n{stderr}"
        );
        assert!(
            stderr.contains("died before ENTER"),
            "probe must die pre-ENTER\n{stderr}"
        );
        assert!(
            stderr.contains("R22012-RLIMIT-DENIED"),
            "deny must fire before the snapshot\n{stderr}"
        );
        // (b) Custody (the child's PAIR — out pre-query —
        // rides the wrapper's panic stderr; the probe
        // birth rides the wrapper's spawn forward).
        let (m1, t1, m2, t2): (libc::pid_t, u64, libc::pid_t, u64) = stderr
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22012-PAIR ")?;
                let mut words = rest.split_whitespace();
                Some((
                    words.next()?.strip_prefix("m1=")?.parse().ok()?,
                    words.next()?.strip_prefix("t1=")?.parse().ok()?,
                    words.next()?.strip_prefix("m2=")?.parse().ok()?,
                    words.next()?.strip_prefix("t2=")?.parse().ok()?,
                ))
            })
            .unwrap_or_else(|| panic!("child PAIR line missing\n{stderr}"));
        let (cpid, ctick): (libc::pid_t, u64) = stderr
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("R22012-PROBE ")?;
                let mut words = rest.split_whitespace();
                Some((
                    words.next()?.strip_prefix("child=")?.parse().ok()?,
                    words.next()?.strip_prefix("ctick=")?.parse().ok()?,
                ))
            })
            .unwrap_or_else(|| panic!("wrapper PROBE forward missing\n{stderr}"));
        // (c) BOTH staged births retired pre-exit +
        // the probe retired (birth-aware — never
        // vacancy-only).
        // N4 (R1): independent expected-identity
        // backstops (see the 005 leg — a mutant-RED
        // StillOurs unwinds through them; disarmed
        // AFTER the judge, never before).
        let mut _b1 = LegChildGuard {
            pid: m1,
            tick: Some(t1),
            disarmed: false,
        };
        let mut _b2 = LegChildGuard {
            pid: m2,
            tick: Some(t2),
            disarmed: false,
        };
        let mut _b3 = LegChildGuard {
            pid: cpid,
            tick: Some(ctick),
            disarmed: false,
        };
        // N5 (R1): bounded birth-aware SETTLE before
        // each verdict read (see the 005 leg);
        // verdicts COLLECTED, then judged.
        let mut verdicts = Vec::new();
        for (pid, tick, who) in [
            (m1, t1, "m1"),
            (m2, t2, "sleeper"),
            (cpid, ctick, "probe"),
        ] {
            let _ = birth_drained(pid, tick, std::time::Duration::from_secs(5));
            verdicts.push((who, pid, tick, prove_reaped_gone_or_recycled(pid, tick)));
        }
        for (who, pid, tick, proof) in verdicts {
            match proof {
                ReapedProof::Gone | ReapedProof::Recycled(_) => {}
                ReapedProof::StillOurs => panic!(
                    "R24006: {who} {pid}/{tick} survives the denied snapshot \
                     (outer guard disarmed too early?)"
                ),
                ReapedProof::Unreadable(error) => panic!(
                    "inconclusive ({who} unreadable: {error}) — refusing to certify"
                ),
            }
        }
        _b1.disarmed = true;
        _b2.disarmed = true;
        _b3.disarmed = true;
    }

    /// R22-012: env flag selecting the hold
    /// characterization child branch (fresh image).
    const R22012_CHAR_ENV: &str = "SCOPEBASE_R22012_CHAR";

    /// R22-012 characterization (PERMANENT — passes
    /// always): a held EMFILE table breaks descriptor
    /// siblings BY DESIGN (pipe + open fail under the
    /// hold, succeed after the drop; the rlimit restores
    /// exactly). This is WHY fault holds live in
    /// fresh-image children only — an in-process hold is a
    /// suite-wide outage. The hold ITSELF runs in the
    /// child (what it characterizes); the wrapper asserts
    /// markers + its own rlimit untouched.
    #[test]
    fn outage_hold_breaks_siblings_by_design() {
        if std::env::var(R22012_CHAR_ENV).is_ok() {
            let before = nofile_soft_limit();
            let hold = OutageHold::exhaust();
            assert!(
                std::io::pipe().is_err(),
                "sibling pipe must fail under the hold (EMFILE)"
            );
            assert!(
                std::fs::File::open("/dev/null").is_err(),
                "sibling open must fail under the hold (EMFILE)"
            );
            drop(hold);
            assert!(
                std::io::pipe().is_ok(),
                "sibling pipe must succeed after the drop"
            );
            assert!(
                std::fs::File::open("/dev/null").is_ok(),
                "sibling open must succeed after the drop"
            );
            assert_eq!(
                nofile_soft_limit(),
                before,
                "single hold must restore the rlimit exactly"
            );
            eprintln!("R22012-CHAR-OK");
            return;
        }
        let limit_before = nofile_soft_limit();
        let exe = std::env::current_exe().expect("own test binary");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("fixture::linux::fork::tests::outage_hold_breaks_siblings_by_design")
            .arg("--nocapture")
            .env(R22012_CHAR_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("characterization child runs");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "child must exit 0\n{stderr}");
        assert!(
            stderr.contains("R22012-CHAR-OK"),
            "characterization marker\n{stderr}"
        );
        assert_eq!(
            nofile_soft_limit(),
            limit_before,
            "wrapper rlimit untouched by the child hold"
        );
    }

    /// R22-012 child scenario (lib): the R21-009 fault
    /// (pair staging + guard + own-table EMFILE + faulted
    /// first read + birth-aware drain proof), run ONLY in
    /// the fresh-image child. Markers on stderr; any
    /// assert-fail exits nonzero (parent fails).
    fn r22012_fault_child_scenario() {
        eprintln!("R22012-HOLDER pid={}", std::process::id());
        // R24-005: restageable duration (fault legs drive
        // this scenario as a child under parallel runs —
        // sharing 108 would collide; GREEN keeps the
        // default).
        let dur = std::env::var("SCOPEBASE_R22012_SLEEP_DUR").unwrap_or_else(|_| "108".to_string());
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep(&dur) }.expect("pair staged");
        // R22-014 guard-handoff: the OUTER guard covers the
        // setup reads (they can fail — outage — before any
        // inner scope exists); disarmed once the INNER
        // guard (the R21-009 guard under test — the fault
        // unwind must pass THROUGH it) arms. The handoff
        // gap holds only infallible ops (catch setup), so
        // no panic path strands.
        let mut outer = MiddlemanPairGuard::armed(m1, m2);
        // Births captured healthy first (the faulted read
        // below cannot name them).
        let t1 = fork_starttime(m1)
            .expect("middleman stat readable")
            .expect("middleman visible");
        let t2 = fork_starttime(m2)
            .expect("grandchild stat readable")
            .expect("grandchild visible");
        // R24-005: transmit pair custody BEFORE the fault
        // window (the parent arms its own guards from this
        // line — a parent-side failure then retires the
        // pair, never just the probe). Printed pre-query
        // (R24-006's deny panics before ENTER — custody
        // must already be out).
        eprintln!("R22012-PAIR m1={m1} t1={t1} m2={m2} t2={t2}");
        // R24-006 fault hook (unset = no-op): deny the
        // rlimit query's actual syscall (prlimit64 —
        // glibc's getrlimit issues no getrlimit; verified
        // by strace on glibc 2.43). A denied query panics
        // below — covered by the STILL-ARMED outer (the
        // deny leg proves both births retire).
        if std::env::var("SCOPEBASE_R24006_DENY_RLIMIT").is_ok() {
            use super::super::seccomp::{install_deny_one, DenyAction};
            install_deny_one(libc::SYS_prlimit64, DenyAction::Eperm).expect("deny installs");
            eprintln!("R22012-RLIMIT-DENIED");
        }
        // R23-021: snapshot OUR rlimit (the confine lives in
        // THIS image — the restore is proven here, where no
        // sibling can interleave). Covered by the OUTER
        // guard (R24-006: the disarm moved inside the catch —
        // a denied query used to panic with NEITHER guard
        // armed).
        let rlim_before = nofile_soft_limit();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _pair = MiddlemanPairGuard::armed(m1, m2);
            // R24-006: handoff INSIDE (inner armed —
            // overlap, never gap; the two ops are
            // infallible — no panic path double-arms).
            outer.disarm();
            let _hold = OutageHold::exhaust();
            // R23-020: rendezvous — the fault window is OPEN
            // (hold alive, pair guarded); the parent hammers
            // INSIDE it (101 ops between this line and the GO
            // below — overlap by construction, never by
            // scheduling luck). The stdin read needs no new
            // fd (holds under EMFILE); EOF (parent died
            // pre-hammer) marks GO-MISSING (the parent
            // asserts the marker absent — a missing GO never
            // passes silently).
            eprintln!("R22012-FAULT-ENTER");
            let mut go = [0u8; 1];
            if std::io::Read::read_exact(&mut std::io::stdin().lock(), &mut go).is_err() {
                eprintln!("R22012-GO-MISSING");
                panic!("staging broken (GO unreadable — parent died pre-hammer?)");
            }
            // R23-020 (reopened): content-checked + READ
            // marker — the parent asserts GO-READ present
            // (overlap proof: a written-but-unread GO
            // never passes — deleting this block escapes
            // nothing). The content assert pins the byte
            // (a read-deleting mutant keeps go==[0] and
            // panics here instead of passing silently).
            assert_eq!(go, [b'G'], "staging broken (GO byte wrong?)");
            eprintln!("R22012-GO-READ");
            std::fs::read_to_string(format!("/proc/{m2}/stat")).expect("first read");
        }));
        assert!(failed.is_err(), "faulted first read must panic");
        for (pid, birth, who) in [(m1, t1, "middleman"), (m2, t2, "grandchild")] {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match fork_starttime(pid) {
                    Ok(Some(now)) if now == birth => {}
                    Ok(_) => break,
                    Err(error) => panic!("{who} {pid} drainage unverifiable: {error}"),
                }
                assert!(
                    std::time::Instant::now() < end,
                    "{who} {pid} stranded by the failed first read (guard must retire)"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        // R23-021: the hold applied + restored between OUR
        // snapshots (the controlled transition the parent
        // cannot observe attribution-correctly — fresh
        // image, no siblings: deterministic).
        let rlim_after = nofile_soft_limit();
        assert_eq!(
            rlim_after, rlim_before,
            "rlimit must restore across the fault (in-child confine leaked?)"
        );
        eprintln!("R22012-RLIMIT-OK {rlim_before} {rlim_after}");
        eprintln!("R22012-DISCHARGED");
    }
}
