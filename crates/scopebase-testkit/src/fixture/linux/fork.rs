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

/// R20-005: fork a pausing middleman that forks an
/// exec'd grandchild sleep and reports its pid through a
/// pipe. Returns the (middleman, grandchild) pids, or
/// None when staging fails (fork/report error — never
/// strands: a report failure kills + reaps the middleman
/// before returning).
///
/// The grandchild's parent is the LIVE middleman — hence
/// our non-child whatever subreaper state we hold (no
/// prctl games). The middleman sheds everything but the
/// report write end, nulls stdio (dup2 /dev/null — the
/// grandchild must not inherit test stdio write ends),
/// forks, reports via hand-rolled-decimal+write, and pauses
/// forever.
/// The grandchild execs /bin/sleep with an EMPTY env (no
/// post-fork environ race). The report read is poll-bounded
/// (5s) — a wedged middleman fails loud, never hangs the
/// suite.
///
/// # Safety
///
/// Fork in a multithreaded context: the middleman runs
/// syscalls only (shed + dup2 + fork + manual decimal +
/// write + pause) plus read-only inherited stack memory,
/// and never returns; the parent must retire both children
/// (the middleman pauses until signaled, the grandchild
/// sleeps until signaled).
#[cfg(test)]
pub unsafe fn fork_pausing_grandchild_sleep(dur: &str) -> Option<(libc::pid_t, libc::pid_t)> {
    use std::os::unix::io::FromRawFd as _;
    // Report pipe (CLOEXEC — out of the exec'd grandchild).
    let mut pipe = [0; 2];
    // SAFETY: pipe2 fills both ends.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return None;
    }
    let (read_fd, write_fd) = (pipe[0], pipe[1]);
    assert!(
        read_fd >= 3 && write_fd >= 3,
        "report pipe must clear stdio (else the middleman's stdio-nulling clobbers it)"
    );
    let dur_c = std::ffi::CString::new(dur).ok()?;
    // SAFETY: fork itself is always safe; the middleman
    // upholds the syscall-only contract documented above.
    let m1 = unsafe { libc::fork() };
    if m1 == 0 {
        unsafe {
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
        return None;
    }
    // SAFETY: write end owned by this scope (the middleman
    // holds its own copy).
    unsafe {
        libc::close(write_fd);
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
        Some(m2) if m2 > 0 => Some((m1, m2)),
        _ => {
            // Report failure: retire the middleman (best
            // effort) so None never strands.
            unsafe {
                libc::kill(m1, libc::SIGKILL);
                let mut st = 0;
                libc::waitpid(m1, &mut st, libc::WNOHANG);
            }
            None
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
        for name in ["fn fork_pauser(", "fn fork_pausing_grandchild_sleep("] {
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
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let mut hammers = Vec::new();
        for _ in 0..4 {
            let stop = stop.clone();
            hammers.push(std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let v: Vec<u8> = (0..1000u32).map(|x| (x ^ n as u32) as u8).collect();
                    drop(format!("{:?}-{}", &v[..8], n));
                    n += 1;
                }
            }));
        }
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
            assert!(m1 > 0 && m2 > 0 && m1 != m2, "pids must be valid");
            retire(m1, m2);
        }
        stop.store(true, Ordering::Relaxed);
        for hammer in hammers {
            let _ = hammer.join();
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
    }
}
