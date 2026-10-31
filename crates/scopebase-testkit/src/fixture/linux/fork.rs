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
/// (m1 unfreezable for 5 s) m1 could fork m2 between the
/// best-effort pgrp read and its death — µs-narrow, gated
/// behind a wedged box, and loud.
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
        if stat_state_pgrp(m1).is_some_and(|(_, g)| g == m1) {
            // SAFETY: pinned group — ours by construction.
            unsafe {
                libc::killpg(m1, libc::SIGKILL);
            }
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
                eprintln!("R21008: group {m1} empty post-reap — m2 proven dead");
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
    unsafe { fork_pausing_grandchild_sleep_inner(dur, false).0 }
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
    unsafe { fork_pausing_grandchild_sleep_inner(dur, true) }
}

#[cfg(test)]
unsafe fn fork_pausing_grandchild_sleep_inner(
    dur: &str,
    jam: bool,
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
            match stat_state_pgrp(m1) {
                Some((st, _)) => {
                    panic!("R21008-JAM: birth-gate timed out with m1 {m1} alive-childless (state {st} — wedged pre-fork? box wedged?)")
                }
                None => {
                    panic!("R21008-JAM: birth-gate timed out with m1 {m1} dead pre-report (self-exit? — regression vacuous, failing loud)")
                }
            }
        }
        retire_reportless_middleman(m1);
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
            let mut workers = Vec::with_capacity(count);
            for _ in 0..count {
                let (stop, done) = (stop.clone(), done.clone());
                workers.push(std::thread::spawn(move || {
                    hammer_body(&stop);
                    done.fetch_add(1, Ordering::Relaxed);
                }));
            }
            Self {
                stop,
                done,
                workers,
            }
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
    }

    /// R21-009: birth guard for a staged middleman pair —
    /// armed at fork (before the fallible stat reads);
    /// drop retires both (m2 blind-killed FIRST while m1
    /// lives — the middleman pauses until signaled, so
    /// m2's number is pinned; then m1 killed + reaped,
    /// bounded). Probe-first: an already-reaped m1 (unwind
    /// past the tail's reap) means m2 is dead-orphaned
    /// draining to init — nothing owed. Disarm after the
    /// explicit tail.
    struct MiddlemanPairGuard {
        m1: libc::pid_t,
        m2: libc::pid_t,
        disarmed: bool,
    }

    impl MiddlemanPairGuard {
        fn armed(m1: libc::pid_t, m2: libc::pid_t) -> Self {
            MiddlemanPairGuard {
                m1,
                m2,
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
            if unsafe { libc::waitpid(self.m1, &mut st, libc::WNOHANG) } != 0 {
                // m1 zombie (reaped by the probe) or gone
                // (reaped by the tail): m2 is dead-orphaned
                // draining to init — nothing owed.
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
    /// (skipped).
    fn live_sleep_with_dur(dur: &str) -> bool {
        let entries = std::fs::read_dir("/proc").expect("/proc readable");
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let cmdline = match std::fs::read(format!("/proc/{name}/cmdline")) {
                Ok(c) => c,
                Err(_) => continue,
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
    /// retires before `None` — m1 reaped (waitpid-ECHILD on
    /// the exposed pid — specific, never steals) and the
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
        // own claim is not evidence; waitpid on the
        // specific pid cannot steal a sibling's child).
        let mut st = 0;
        let got = unsafe { libc::waitpid(m1, &mut st, libc::WNOHANG) };
        assert_eq!(got, -1, "m1 must be reaped already (no status left)");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "reaped m1 must refuse ECHILD"
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

    /// R21-009: tight in-process EMFILE hold (confine soft
    /// NOFILE to 4096 + fill, restores on drop). Never
    /// raises on confine, never lowers on restore (safe
    /// under nesting with a sibling's hold). Process-global
    /// while held — keep the hold to microseconds (the
    /// single faulted read).
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

    /// R21-009: a failed FIRST observation over a staged
    /// middleman pair must unwind through the birth guard —
    /// both retired before the panic propagates. Stages the
    /// pair, arms the guard, faults the first read under a
    /// tight in-process EMFILE hold (inside catch_unwind),
    /// then proves both original births drained
    /// (birth-aware — absence alone proves nothing when
    /// parallel siblings reuse numbers; unreadable fails).
    /// Duration 108 is unique to this test. Pre-fix RED
    /// (unguarded): the pair strands (m1 pausing, m2
    /// sleeping) — proven by neutering the guard line.
    #[test]
    fn middleman_pair_guard_discharges_on_first_read_failure() {
        let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("108") }.expect("pair staged");
        // Births captured healthy first (the faulted read
        // below cannot name them).
        let t1 = fork_starttime(m1)
            .expect("middleman stat readable")
            .expect("middleman visible");
        let t2 = fork_starttime(m2)
            .expect("grandchild stat readable")
            .expect("grandchild visible");
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
    }
}
