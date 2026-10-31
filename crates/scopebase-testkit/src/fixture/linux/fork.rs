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

/// Read the rendezvous slots. Sound in the forked child (plain atomic
/// loads); the parent must only call this while holding the fork mutex.
pub fn slots() -> (i32, i32, i32) {
    (
        SLOT_A.load(Ordering::Relaxed),
        SLOT_B.load(Ordering::Relaxed),
        SLOT_C.load(Ordering::Relaxed),
    )
}
