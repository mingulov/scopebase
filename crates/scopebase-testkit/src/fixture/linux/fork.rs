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
/// tail. Returns the helper result (None — the tail ran)
/// plus m1 for the caller's INDEPENDENT reap proof
/// (waitpid-ECHILD — the tail's own claim is not
/// evidence). m2's pid stays unknown by design (the
/// finding's contract — the caller proves m2's death by
/// scanning for the unique sleep duration).
///
/// # Safety
///
/// Same fork contract as
/// [`fork_pausing_grandchild_sleep`].
#[cfg(test)]
pub unsafe fn fork_pausing_grandchild_sleep_jam_report(
    dur: &str,
) -> (Option<(libc::pid_t, libc::pid_t)>, libc::pid_t) {
    // SAFETY: same contract as the inner helper.
    unsafe { fork_pausing_grandchild_sleep_inner(dur, true, true) }
}

/// R22-008/009: jammed-report SPAWN ONLY — the jam arm's
/// spawn + birth-gate WITHOUT the production tail (fault
/// probes stage the pair healthy, print custody, THEN
/// inject the fault before running the tail themselves).
/// Returns `Some(m1)` (m2 born-proven, pids unknown) or
/// `None` on spawn failure; the birth-gate still panics
/// loud on an unborn m2 (never a vacuous staging).
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
pub unsafe fn fork_pausing_grandchild_sleep_jam_noretire(dur: &str) -> Option<libc::pid_t> {
    // SAFETY: same contract as the inner helper.
    let (_, m1) = unsafe { fork_pausing_grandchild_sleep_inner(dur, true, false) };
    (m1 > 0).then_some(m1)
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
    // SAFETY: fork itself is always safe; both children
    // uphold the syscall-only contract below.
    let m1 = unsafe { libc::fork() };
    if m1 == 0 {
        unsafe {
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
                    panic!("R22016B-JAM: birth-gate timed out with m1 {m1} alive-childless (state {st} — wedged pre-fork? box wedged?)")
                }
                None => {
                    panic!("R22016B-JAM: birth-gate timed out with m1 {m1} dead pre-stub (self-exit? — regression vacuous, failing loud)")
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
) -> (Option<(libc::pid_t, libc::pid_t)>, libc::pid_t) {
    use std::os::unix::io::FromRawFd as _;
    // Report pipe (CLOEXEC — out of the exec'd grandchild).
    let mut pipe = [0; 2];
    // SAFETY: pipe2 fills both ends.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return (None, -1);
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
            return (None, -1);
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
        return (None, -1);
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
        while std::time::Instant::now() < gate_end {
            if let Ok(kids) = std::fs::read_to_string(format!("/proc/{m1}/task/{m1}/children")) {
                if !kids.split_whitespace().next().is_none() {
                    born = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
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
        if retire_on_jam {
            retire_reportless_middleman(m1);
        }
        return (None, m1);
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
        Some(m2) if m2 > 0 => (Some((m1, m2)), m1),
        _ => {
            // Report failure: FULL retirement before None
            // (R21-008 — the old kill + single-WNOHANG tail
            // stranded m1 as a zombie and never touched
            // the unknown-pid m2).
            retire_reportless_middleman(m1);
            (None, m1)
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
        // 3-digit argv at a fork/twin sleep call site:
        // helper-mediated (`*_with_dur("NNN")`,
        // `*noretire("NNN")`, `*jam_report("NNN")`,
        // `*grandchild_sleep("NNN")`) or direct
        // (`Command::new("/bin/sleep")` + `.arg("NNN")`
        // within 3 lines).
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
            "twin scan keys {twin_audit_dupes:?} collide with audit sleep argv (re-key repo-wide)"
        );
        let fork_twin_dupes: Vec<_> = fork_keys.intersection(&twin_keys).collect();
        assert!(
            fork_twin_dupes.is_empty(),
            "scan keys {fork_twin_dupes:?} shared by fork lib + toolchain twin (re-key repo-wide)"
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
                        unsafe {
                            libc::syscall(libc::SYS_pidfd_send_signal, pin.0, libc::SIGKILL, 0, 0);
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
                if let Ok(pin) = &self.m2pin {
                    // SAFETY: pidfd_send_signal to our
                    // pinned grandchild-birth only.
                    unsafe {
                        libc::syscall(libc::SYS_pidfd_send_signal, pin.0, libc::SIGKILL, 0, 0);
                    }
                }
                eprintln!(
                    "R22007-PROBE m1={} probe failed (errno {errno} — m1 state unknown, \
                     number untouched); m2={} pin-killed when pinned",
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
        for fd in [0, 1, 2] {
            let link = std::fs::read_link(format!("/proc/{m2}/fd/{fd}")).expect("stdio readable");
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
    /// absence over live m2).
    fn live_sleep_with_dur(dur: &str) -> bool {
        let entries = std::fs::read_dir("/proc").expect("/proc readable");
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("readdir mid-scan failed: {error}"),
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let cmdline = match std::fs::read(format!("/proc/{name}/cmdline")) {
                Ok(c) => c,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("/proc/{name}/cmdline unreadable mid-scan: {error}"),
            };
            let mut args = cmdline.split(|b| *b == 0);
            let argv0 = args.next().unwrap_or_default();
            let argv1 = args.next().unwrap_or_default();
            if argv0 != b"sleep" || argv1 != dur.as_bytes() {
                continue;
            }
            // Candidate: live or zombie?
            match std::fs::read_to_string(format!("/proc/{name}/stat")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("/proc/{name}/stat unreadable mid-scan: {error}"),
                Ok(text) => {
                    let state = text
                        .rsplit_once(") ")
                        .and_then(|(_, after)| after.split_whitespace().next());
                    if state != Some("Z") {
                        return true;
                    }
                }
            }
        }
        false
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
        let (result, m1) = unsafe { fork_pausing_grandchild_sleep_jam_report("957") };
        assert!(result.is_none(), "jammed report must yield None (tail ran)");
        assert!(m1 > 0, "jam exposes m1 for the reap proof");
        // m1 reaped — the INDEPENDENT proof (the tail's
        // own claim is not evidence; /proc absence, never
        // a wait — a recycled sibling zombie would lose
        // its status to a waitpid here: R22-004(a)).
        assert_eq!(
            prove_reaped_by_absence(m1),
            Ok(true),
            "m1 must be reaped already (/proc gone — present means our unreaped zombie (RED) or a recycled occupant (unproven))"
        );
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
        let m1 = unsafe { fork_pausing_grandchild_sleep_jam_noretire(&dur) }
            .expect("staging broken (pair spawn)");
        let mut _pair = ReportlessPairGuard::armed(m1);
        let tick1 = fork_starttime(m1)
            .expect("staging broken (m1 stat)")
            .expect("staging broken (m1 visible)");
        println!("R22008-M1 {m1} {tick1}");
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
        // Custody BEFORE verdicts (RED runs stay clean).
        kill_tick_gated_fork(m1, tick1);
        assert!(
            birth_drained(m1, tick1, std::time::Duration::from_secs(5)),
            "wrapper must drain m1"
        );
        assert!(
            kill_sleep_with_dur("853"),
            "wrapper must drain the residual sleep 853"
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
        assert!(
            stderr.contains("R22008-DONE"),
            "probe must cite completion\n{stderr}"
        );
        assert!(
            stderr.contains("R22008-ASSUMED-GROUPED"),
            "fallback must cite the assumed-grouped kill\n{stderr}"
        );
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
        let m1 = unsafe { fork_pausing_grandchild_sleep_jam_noretire("855") }
            .expect("staging broken (pair spawn)");
        // Pre-custody unwinds discharge fully (the filter
        // installs after the print); post-print unwinds
        // retire m1 in-probe while the wrapper sweeps m2 by
        // duration (the M1 line is already flushed).
        let mut _pair = ReportlessPairGuard::armed(m1);
        let tick1 = fork_starttime(m1)
            .expect("staging broken (m1 stat)")
            .expect("staging broken (m1 visible)");
        println!("R22009-M1 {m1} {tick1}");
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
        // Load-bearing anti-vacuity: m2 SURVIVED the tail
        // (both group-kills denied — nothing else targets
        // it). A dead m2 here would make the probe's
        // evidence untestable.
        assert!(
            live_sleep_with_dur("855"),
            "staging broken (m2 dead pre-custody — the denial staged nothing?)"
        );
        // Custody BEFORE verdicts (m2 live by design).
        kill_tick_gated_fork(m1, tick1);
        assert!(
            birth_drained(m1, tick1, std::time::Duration::from_secs(5)),
            "wrapper must drain m1"
        );
        assert!(
            kill_sleep_with_dur("855"),
            "wrapper must drain the live sleep 855"
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
        let tick1 = fork_starttime(m1)
            .expect("staging broken (m1 stat)")
            .expect("staging broken (m1 visible)");
        let tick_stub = fork_starttime(stub)
            .expect("staging broken (stub stat)")
            .expect("staging broken (stub visible)");
        println!("R22016B-M1 {m1} {tick1}");
        println!("R22016B-STUB {stub} {tick_stub}");
        std::io::Write::flush(&mut std::io::stdout()).expect("custody lines flushed");
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
        match zombie.try_wait() {
            Ok(Some(status)) => assert!(!status.success(), "zombie must be our SIGKILLed sleeper"),
            other => panic!("proof stole the zombie's status?! got {other:?}"),
        }
        _zguard.disarm();
        // Absent leg: freed number ⟹ reaped.
        assert_eq!(
            prove_reaped_by_absence(zombie_pid),
            Ok(true),
            "freed number must read reaped"
        );
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
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _pair = MiddlemanPairGuard::armed(m1, m2);
            assert_eq!(
                unsafe { libc::kill(m1, libc::SIGKILL) },
                0,
                "staging broken (m1 kill)"
            );
            settle_zombie(m1);
            panic!("simulated observation failure");
        }));
        assert!(outcome.is_err(), "staging broken (must unwind)");
        assert_eq!(
            fork_starttime(m1),
            Ok(None),
            "m1 must be reaped by the probe"
        );
        let retired = birth_drained(m2, tick2, std::time::Duration::from_secs(5));
        // RED-safe cleanup (tick-gated — the verdict above
        // is already recorded).
        kill_tick_gated_fork(m2, tick2);
        birth_drained(m2, tick2, std::time::Duration::from_secs(5));
        assert!(retired, "m2 must retire via the pin (abandoned?!)");
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
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        let pair = MiddlemanPairGuard::armed(m1, m2);
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
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let mut pair = MiddlemanPairGuard::armed(m1, m2);
            pair.m2pin = Err(libc::EPERM);
            assert_eq!(
                unsafe { libc::kill(m1, libc::SIGKILL) },
                0,
                "staging broken (m1 kill)"
            );
            settle_zombie(m1);
            panic!("simulated observation failure");
        }));
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

    /// R22-008: collect (pid, starttime-tick) of every
    /// LIVE (non-zombie) `sleep dur` in /proc — the
    /// reportless fault probes' m2 has an unknown pid, so
    /// wrapper-side custody rides this scan (tick-gated
    /// kill + drain per birth). Read-error discipline
    /// mirrors `live_sleep_with_dur` (R22-016(a)):
    /// NotFound (vanished) skips; any other read error
    /// fails LOUD (a custody scan must never certify
    /// absence over unreadable entries).
    fn sleep_pids_with_dur(dur: &str) -> Vec<(libc::pid_t, u64)> {
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
            let mut args = cmdline.split(|b| *b == 0);
            let argv0 = args.next().unwrap_or_default();
            let argv1 = args.next().unwrap_or_default();
            if argv0 != b"sleep" || argv1 != dur.as_bytes() {
                continue;
            }
            let pid: libc::pid_t = match name.parse() {
                Ok(pid) => pid,
                Err(_) => continue,
            };
            match fork_starttime(pid) {
                Ok(Some(tick)) => {
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
    fn kill_sleep_with_dur(dur: &str) -> bool {
        for (pid, tick) in sleep_pids_with_dur(dur) {
            kill_tick_gated_fork(pid, tick);
            if !birth_drained(pid, tick, std::time::Duration::from_secs(5)) {
                return false;
            }
        }
        !live_sleep_with_dur(dur)
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
        let tick2 = fork_starttime(m2)
            .expect("m2 stat readable")
            .expect("m2 visible");
        println!("R22007-M2 {m2} {tick2}");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _pair = MiddlemanPairGuard::armed(m1, m2);
            assert_eq!(
                unsafe { libc::kill(m1, libc::SIGKILL) },
                0,
                "staging broken (m1 kill)"
            );
            settle_zombie(m1);
            panic!("simulated observation failure");
        }));
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

    /// R22-004(a): reap proof by /proc ABSENCE —
    /// zombies retain /proc entries, so absence ⟺ reaped
    /// (no waitpid — a wait would steal a recycled sibling
    /// zombie's status: R21-001-class). `Ok(true)` = absent
    /// ⟹ reaped; `Ok(false)` = present ⟹ UNPROVEN (our
    /// unreaped zombie (RED) or a recycled occupant — both
    /// fail closed, never certify); `Err` = outage (fails
    /// loud, never certifies). The `Err` arm is a 1-line
    /// mapping with no cheap fault (a non-NotFound /proc
    /// read error needs EMFILE — fresh-image-only per
    /// R22-012); the absence/presence/no-steal legs carry
    /// the regression below.
    fn prove_reaped_by_absence(pid: libc::pid_t) -> Result<bool, String> {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.to_string()),
            Ok(_) => Ok(false),
        }
    }

    /// R21-009: starttime read for the regression's
    /// birth-aware checks (fork-local — audit's helper is
    /// out of reach). `Ok(None)` is proven absence
    /// (ENOENT); anything else unreadable is `Err`.
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
    /// spawns self `--exact` with the env flag, hammers
    /// sibling fd-ops while the child runs (all must
    /// succeed — the child's table is its own), then
    /// asserts exit 0 + discharge markers + holder-pid !=
    /// self (STRUCTURAL: an in-process reintroduction
    /// fails here deterministically) + rlimit preserved.
    /// The child stages its OWN pair (it is the parent —
    /// kill+reap both work there), arms the guard, faults
    /// the first read under its own EMFILE hold (inside
    /// catch_unwind), then proves both original births
    /// drained (birth-aware; unreadable fails). Duration
    /// 108 is unique to this test. Pre-fix RED
    /// (unguarded): the pair strands (m1 pausing, m2
    /// sleeping) — proven by neutering the guard line.
    /// R22-014: the fault child rides a birth guard (a
    /// hammer-loop panic retires it — no orphan transient;
    /// the child is additionally self-sufficient: it
    /// retires its own pair and exits alone in ms).
    #[test]
    fn middleman_pair_guard_discharges_on_first_read_failure() {
        if std::env::var(R22012_FAULT_ENV).is_ok() {
            r22012_fault_child_scenario();
            return;
        }
        let me = std::process::id();
        let limit_before = nofile_soft_limit();
        let exe = std::env::current_exe().expect("own test binary");
        let mut child = std::process::Command::new(exe)
            .arg("--exact")
            .arg("fixture::linux::fork::tests::middleman_pair_guard_discharges_on_first_read_failure")
            .arg("--nocapture")
            .env(R22012_FAULT_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("fault child spawns");
        let mut _cguard = ForkChildGuard::new(child.id() as libc::pid_t);
        // Sibling hammer while the child runs (bounded
        // 60 s — a hung child is killed loud, never an
        // unbounded hang).
        let mut hammered = 0u64;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if child.try_wait().expect("child waitable").is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("fault child hung past 60 s (killed loud)");
            }
            hammer_sibling_fd_op().expect("sibling fd-op succeeds during fresh-image fault");
            hammered += 1;
        }
        assert!(
            hammered > 100,
            "hammer must pressure the fault window (got {hammered})"
        );
        let out = child.wait_with_output().expect("child reaps");
        _cguard.disarm();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "fault child must exit 0\n{stderr}");
        assert!(
            stderr.contains("R22012-DISCHARGED"),
            "discharge marker\n{stderr}"
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
        assert_eq!(
            nofile_soft_limit(),
            limit_before,
            "rlimit preserved across the fault"
        );
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
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("108") }.expect("pair staged");
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
        outer.disarm();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _pair = MiddlemanPairGuard::armed(m1, m2);
            let _hold = OutageHold::exhaust();
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
        eprintln!("R22012-DISCHARGED");
    }
}
