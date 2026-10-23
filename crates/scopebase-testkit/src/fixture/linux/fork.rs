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

/// Read the rendezvous slots. Sound in the forked child (plain atomic
/// loads); the parent must only call this while holding the fork mutex.
pub fn slots() -> (i32, i32, i32) {
    (
        SLOT_A.load(Ordering::Relaxed),
        SLOT_B.load(Ordering::Relaxed),
        SLOT_C.load(Ordering::Relaxed),
    )
}
