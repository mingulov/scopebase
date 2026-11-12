// SPDX-License-Identifier: Apache-2.0
//! TT03 owned Linux fixture first increment: worker, wire codec, session
//! admission/finalizer and ported donor oracle facets.
//!
//! Binding authority: `docs/superpowers/specs/2026-10-22-scopebase-tt03-linux-fixture.md`.
//! Covers the ordinary-host worker core (boot/resume Hello, ready,
//! capture_raw, set_tricky_comm, blob upload, file create/offer, close, real
//! exec round-trip/failure/nonleader exec, real sibling spawn plus
//! leader-only exit with handover), the exact public
//! session/custody/finalizer API with native TT02 prepare/collect wiring,
//! third-slot descriptor inventory, the runner-deadline hold and worker-death
//! outage injection (real mid-protocol death, orphaned retirement with
//! retained evidence, partial-file detection), plus ported donor facets.
//! Snapshot full-schema conformance, F rows, the strict materializer and
//! final-index joint compatibility are documented follow-ups, not claimed
//! here.
// S78-round4: under the seccomp-only feature the linux surface is
// just `seccomp` (libc-only, no scopebase-linux edge); everything
// else stays behind `linux-fixtures`.
#[cfg(feature = "linux-fixtures")]
pub mod audit;
#[cfg(feature = "linux-fixtures")]
mod creator;
#[cfg(feature = "linux-fixtures")]
mod driver;
#[cfg(feature = "linux-fixtures")]
pub(crate) mod fork;
#[cfg(feature = "linux-fixtures")]
mod manifest;
#[cfg(feature = "linux-fixtures")]
mod oracle;
#[cfg(feature = "linux-fixtures")]
mod phase;
pub mod seccomp;
#[cfg(feature = "linux-fixtures")]
mod session;
#[cfg(feature = "linux-fixtures")]
pub mod target;
#[cfg(feature = "linux-fixtures")]
pub mod wire;

/// R23-008: dedicated-session outcome for the test
/// invocation (shared by the audit + fork custody
/// scanners — same crate, same process; the toolchain
/// twin mirrors this privately).
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DedicatedSession {
    /// setsid() succeeded — we lead a fresh session
    /// containing only our tree (nothing outside it can
    /// share our session id).
    BySetsid,
    /// Already a session leader at first call — our
    /// session likewise contains only our tree (setsid
    /// would EPERM; nothing to do).
    ByBirth,
    /// setsid() failed (process-group leader — e.g. a
    /// direct foreground run) — proceeding in the shared
    /// session (window+shape still filter; same-shell
    /// post-anchor strangers are admitted — legs
    /// requiring dedication skip loud).
    Unavailable,
    /// Re-exec'd probe image (parent re-exec'd this same
    /// executable) — deliberately shares the wrapper's
    /// session (never dedicates): the wrapper
    /// custody-scans the probe's fixtures, so those must
    /// be born in the wrapper's session. Legs requiring
    /// dedication treat this like `Unavailable` (skip —
    /// sharing is not dedication).
    SharedWithWrapper,
}

/// R23-008: claim a dedicated session for this test
/// image, once per process. DEDICATED AT IMAGE LOAD (see
/// `DEDICATE_SESSION_AT_LOAD` below) — lazily calling
/// this from the first ownership check poisoned same-image
/// scans (C8 proof: the first check's setsid froze every
/// earlier-born fixture in the old session — the R24-001
/// control's plant scanned `owned=false` with mismatched
/// sids). Idempotent (OnceLock) and safe to call from any
/// test thread: the load-time call wins, the rest observe.
/// Called at the top of every custody-scan ownership
/// check (consultation — the value is already decided),
/// so all current and future sweeps run dedicated where
/// available. New sessions detach the controlling
/// terminal (stdio still flows over cargo's pipes); a
/// Ctrl-C'd cargo kills us by pid (no orphaned suite).
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
pub(crate) fn ensure_dedicated_session() -> DedicatedSession {
    static DEDICATED: std::sync::OnceLock<DedicatedSession> = std::sync::OnceLock::new();
    *DEDICATED.get_or_init(|| {
        // HUP-001 + XRV1-R24: no-op SIGHUP
        // handler in EVERY image (suite AND
        // probes — installed BEFORE the
        // probe branch). Probes share the
        // suite group by R23-008 design and
        // default disposition dies on a
        // group-HUP (the 4-pack killer —
        // proven by bpftrace: external
        // killpg HUP+CONT). A HANDLER (exec
        // resets it) not SIG_IGN (exec
        // preserves it — exec'd fixtures
        // keep default HUP-death either way
        // (reset is per-exec, not per-image):
        // the orphan-retirement path is
        // unaffected; fork-only children
        // inherit the no-op in-suite (P3)
        // and now in-probe (parity).
        // The dedicated session/group orphans on
        // protector-exit (gate proof: self-grouped
        // python probe + H joining our group +
        // probe exiting at once + a stopped
        // co-resident ⟹ kernel HUPs our group);
        // default disposition dies (6 gate
        // deaths), the handler survives
        // (SA_RESTART — no EINTR spill).
        // SAFETY: sigaction-set with a stack
        // action (zeroed mask/flags-then-set);
        // glibc supplies SA_RESTORER (wrapper
        // contract, no pre-main dependence
        // beyond open/stat already used here).
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = orphan_hup_noop as *const () as usize;
        act.sa_flags = libc::SA_RESTART;
        let set = unsafe { libc::sigaction(libc::SIGHUP, &act, std::ptr::null_mut()) };
        debug_assert_eq!(set, 0, "HUP-001 handler install must succeed");
        // Cycle 2: probes stay in the wrapper's session.
        if running_as_probe() {
            return DedicatedSession::SharedWithWrapper;
        }
        // SAFETY: getsid/getpid queries only.
        let me = unsafe { libc::getpid() };
        let sid = unsafe { libc::getsid(0) };
        if sid == me {
            return DedicatedSession::ByBirth;
        }
        // SAFETY: setsid on self only (new session +
        // group, controlling terminal detached).
        if unsafe { libc::setsid() } < 0 {
            return DedicatedSession::Unavailable;
        }
        DedicatedSession::BySetsid
    })
}

/// HUP-001 no-op (the handler the suite
/// installs at load — a HANDLER (exec resets
/// it to default for fixtures) NOT SIG_IGN
/// (exec preserves ignored — fixtures must
/// keep default HUP-death: the orphan-
/// retirement path relies on it)).
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
pub(crate) extern "C" fn orphan_hup_noop(_sig: libc::c_int) {}

/// HUP-001 + XRV1-R24: query our own SIGHUP
/// disposition (pins only — every image
/// load-installs the no-op (suite AND
/// probes); exec'd grandchildren reset to
/// default across exec; fork-only children
/// inherit the handler). Returns the raw
/// handler addr — None when the query fails.
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
pub(crate) fn hup_disposition_for_test() -> Option<usize> {
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: sigaction-get writes old only.
    if unsafe { libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut old) } != 0 {
        return None;
    }
    Some(old.sa_sigaction)
}

/// XRV1-R26 L147: post-exec SIGHUP
/// disposition snapshot (0 = unsampled,
/// 1 = SIG_DFL, 2 = SIG_IGN, 3 =
/// caught). Written once by the
/// `.init_array.00000` sampler BEFORE
/// the 00001 handler install: in a
/// seam-armed probe it reads 2 (IGN
/// survives exec — the window is
/// closed); unarmed it reads 1 (exec
/// reset to default — the window is
/// open). Misordering (sampler at/after
/// the install) reads 3 — the pin REDs,
/// so the ordering is self-policing.
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
static HUP_WINDOW_DISPOSITION: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// XRV1-R26 L147: read the window
/// snapshot (pins only). None when
/// unsampled (no sampler entry linked).
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
pub(crate) fn hup_window_disposition_for_test() -> Option<u8> {
    match HUP_WINDOW_DISPOSITION.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

/// R23-008-fix (C8, cycle 2): are we a re-exec'd probe?
/// Fresh-image probes (spawned from `current_exe` by a
/// wrapper in this same image) must NOT dedicate — the
/// wrapper custody-scans their fixtures, so those must be
/// born in the wrapper's session. Detected without any
/// per-spawn flag: our parent's argv0 names the same
/// executable (dev+ino comparison — immune to
/// relative-vs-absolute argv0). Probe-spawn invariants
/// (verified by grep over all `current_exe` sites — a
/// violation fails closed to dedicate): probes always
/// pass absolute `current_exe`, never wrap in shell, never
/// set cwd. Fail-closed: any read failure (no /proc,
/// raced parent exit, truncated cmdline, unstatable path)
/// returns false (dedicate — normal images must dedicate;
/// only positive parent==self evidence skips).
/// Pre-main-safe: raw syscalls only, stack buffers, no
/// allocation, no std locks — callable from the
/// `.init_array` entry and from normal code alike.
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
fn running_as_probe() -> bool {
    // SAFETY: all calls below are raw queries with
    // caller-owned stack buffers; every return checked.
    unsafe {
        let ppid = libc::getppid();
        if ppid <= 0 {
            return false;
        }
        // "/proc/<ppid>/cmdline\0" without allocation.
        let mut path = [0u8; 64];
        path[..6].copy_from_slice(b"/proc/");
        let mut len = 6usize;
        let mut rev = [0u8; 10];
        let mut rlen = 0usize;
        let mut n = ppid as u32;
        loop {
            rev[rlen] = b'0' + (n % 10) as u8;
            rlen += 1;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        for i in (0..rlen).rev() {
            path[len] = rev[i];
            len += 1;
        }
        path[len..len + 9].copy_from_slice(b"/cmdline\0");
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC,
        );
        if fd < 0 {
            return false;
        }
        let mut buf = [0u8; 1024];
        let got = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        libc::close(fd);
        if got <= 0 {
            return false;
        }
        // argv0 = bytes up to the first NUL; a missing NUL
        // means argv0 overran the buffer (unprovable).
        let mut argv0len = None;
        for (i, byte) in buf[..got as usize].iter().enumerate() {
            if *byte == 0 {
                argv0len = Some(i);
                break;
            }
        }
        match argv0len {
            Some(0) | None => return false,
            Some(_) => {}
        }
        // buf holds argv0 NUL-terminated in place.
        let mut parent_stat: libc::stat = std::mem::zeroed();
        if libc::stat(buf.as_ptr() as *const libc::c_char, &mut parent_stat) != 0 {
            return false;
        }
        let mut self_stat: libc::stat = std::mem::zeroed();
        if libc::stat(
            b"/proc/self/exe\0".as_ptr() as *const libc::c_char,
            &mut self_stat,
        ) != 0 {
            return false;
        }
        parent_stat.st_dev == self_stat.st_dev && parent_stat.st_ino == self_stat.st_ino
    }
}

/// R23-008-fix (C8): dedicate at IMAGE LOAD. A lazily
/// dedicated session poisons its own image (the first
/// ownership check's setsid freezes every earlier-born
/// fixture — even ones born milliseconds before in the
/// same test — in the old session, permanently invisible
/// to later scans). Load-time dedication precedes every
/// fixture, so no birth can predate it. Stable-Rust
/// `.init_array` (no `ctor` dependency): the linker calls
/// the pointer before `main`/libtest. Re-exec'd probes
/// skip (see `running_as_probe` — they share the
/// wrapper's session by design).
/// XRV1-R26 L147: snapshot the post-exec
/// SIGHUP disposition BEFORE the 00001
/// handler install (the linker runs
/// `.init_array.NNNNN` entries in
/// numeric order). Pre-main-safe:
/// sigaction-get (raw syscall, stack
/// struct) + one relaxed atomic store —
/// no allocation, no locks, no libc-init
/// dependence.
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
extern "C" fn sample_hup_window_disposition_at_load() {
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: sigaction-get writes old only.
    let class = if unsafe { libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut old) } != 0 {
        0u8
    } else if old.sa_sigaction == libc::SIG_DFL as usize {
        1u8
    } else if old.sa_sigaction == libc::SIG_IGN as usize {
        2u8
    } else {
        3u8
    };
    HUP_WINDOW_DISPOSITION.store(class, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
#[used]
#[link_section = ".init_array.00000"]
static SAMPLE_HUP_WINDOW_AT_LOAD: extern "C" fn() = sample_hup_window_disposition_at_load;

#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
#[used]
#[link_section = ".init_array.00001"]
static DEDICATE_SESSION_AT_LOAD: extern "C" fn() = dedicate_session_at_load;

/// Pre-main entry for `DEDICATE_SESSION_AT_LOAD`.
/// Pre-main-safe: single-threaded (no threads exist, so
/// the OnceLock is uncontended) and the init path uses
/// raw syscalls only (getpid/getsid/setsid — no libc-init
/// dependence, no allocation, no std locks), so it is
/// safe regardless of init ordering.
#[cfg(all(test, feature = "linux-fixtures", target_arch = "x86_64"))]
extern "C" fn dedicate_session_at_load() {
    ensure_dedicated_session();
}

#[cfg(feature = "linux-fixtures")]
pub use driver::{
    launch_pair, CleanupProof, DeadlineHoldReport, DrainedRecord, DriverError, DriverErrorKind,
    InventoryRecord, LaunchConfig, LivePair, ReapedExit, Scenario, ScenarioStep, ShutdownReport,
};
#[cfg(feature = "linux-fixtures")]
pub use manifest::{control_pairing_applies, Control};
#[cfg(feature = "linux-fixtures")]
pub use oracle::{
    clean_shutdown_gate, exited_unreaped_owned, generation_of, gone_from_result,
    parse_stat_comm_state_starttime, stat_is_zombie, verify_retirement_exactly_once,
    verify_unknown_sticky, CustodyClaim, GenerationState, OracleError, TRICKY_COMM,
    TRICKY_COMM_HEX,
};
#[cfg(feature = "linux-fixtures")]
pub use phase::{LinuxPhaseError, LinuxProcessFixture};
#[cfg(feature = "linux-fixtures")]
pub use session::{
    LinuxFixtureAdmissionCleanupReport, LinuxFixtureAdmissionCustody, LinuxFixtureAdmissionFailure,
    LinuxFixtureFiles, LinuxFixtureSession, LinuxOuterCleanupAdmissionError,
    LinuxOuterCleanupAdmissionErrorKind, LinuxOuterCleanupBudget, LinuxOuterCleanupReport,
};
#[cfg(feature = "linux-fixtures")]
pub use wire::{Action, Actor};
