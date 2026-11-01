// SPDX-License-Identifier: Apache-2.0
//! F-row seccomp helper: install a deny-one (+1) filter in the caller.
//!
//! ADAPT P `p11scope/.superpowers/sdd/2026-09-17-privmin-research/h4/seccomp-run.c`
//! @`7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4` lines 14-33 (install idiom:
//! arch-checked classic-BPF program, `PR_SET_NO_NEW_PRIVS` then
//! `PR_SET_SECCOMP/SECCOMP_MODE_FILTER`). The donor file is user-owned
//! p11scope research, git-ignored at capture (`/.superpowers/` in
//! `.gitignore`); frozen bytes sha256
//! `21b24b9f35a5752ee67261806e355d96a00e7f62de4eb75ea123bed048e4d184`.
//! Grant: OWNER-2026-10-23. Adapted from an allowlist child-runner to a
//! deny-one in-process filter for the TT03 F seccomp strict-denial
//! populations; the BPF encoding below was validated by a live C probe
//! on this host (pre-filter success, exact post-filter errno, stat
//! still allowed), not copied from third-party headers.
//!
//! The filter denies exactly one syscall number with `EPERM` or `ENOSYS`
//! and allows everything else; a non-x86_64 arch fails closed with
//! `ENOSYS`. Installing is irreversible for the calling thread's
//! process and must run only in a fresh confined helper, never in a
//! test process or the fixture parent.
use std::fmt;
use std::os::fd::RawFd;

/// What the denied syscall does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAction {
    /// `SECCOMP_RET_ERRNO | EPERM`.
    Eperm,
    /// `SECCOMP_RET_ERRNO | ENOSYS`.
    Enosys,
    /// `SECCOMP_RET_KILL_PROCESS`: attempting the syscall kills the
    /// caller with SIGSYS. Used only to prove a cleanup path never
    /// issues the syscall (S68-round4): survival is the assertion.
    Kill,
}

impl DenyAction {
    fn ret(self) -> u32 {
        match self {
            DenyAction::Eperm => SECCOMP_RET_ERRNO | libc::EPERM as u32,
            DenyAction::Enosys => SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
            DenyAction::Kill => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

/// Filter-install failure with the exact stage and errno.
#[derive(Debug, Clone)]
pub struct SeccompError {
    stage: &'static str,
    errno: i32,
}

impl SeccompError {
    /// The install stage that failed (`no_new_privs`, `install_filter`,
    /// or `unsupported_arch`).
    pub fn stage(&self) -> &'static str {
        self.stage
    }

    /// The errno observed at the failing stage (`ENOSYS` from the kernel
    /// means seccomp filtering is unavailable, not a logic failure).
    pub fn errno(&self) -> i32 {
        self.errno
    }
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seccomp {} failed: errno {}", self.stage, self.errno)
    }
}

impl std::error::Error for SeccompError {}

// Classic-BPF instruction encodings (stable kernel UAPI, validated by
// the live C probe; see module docs).
const BPF_LD_ABS_W: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
// `struct seccomp_data` field offsets: nr (int) at 0, arch (__u32) at 4,
// args[0] (u64) at 16 (the ptrace request rides in its low word).
const SECCOMP_DATA_NR_OFF: u32 = 0;
const SECCOMP_DATA_ARCH_OFF: u32 = 4;
const SECCOMP_DATA_ARG0_OFF: u32 = 16;
// `AUDIT_ARCH_X86_64` from linux/audit.h.
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

/// Install a deny-one filter on the calling process: syscall `nr` fails
/// with the action errno, every other syscall is allowed.
///
/// The caller must be a fresh confined helper: the filter is
/// irreversible, and `PR_SET_NO_NEW_PRIVS` is latched first per the
/// donor install idiom. Only `x86_64` is supported; other arches get
/// `unsupported_arch` without touching process state.
#[cfg(target_arch = "x86_64")]
pub fn install_deny_one(nr: libc::c_long, action: DenyAction) -> Result<(), SeccompError> {
    let deny = action.ret();
    let program = [
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARCH_OFF),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR_OFF),
        jump(BPF_JEQ_K, nr as u32, 0, 1),
        stmt(BPF_RET_K, deny),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];
    install_program(&program)
}

/// S05/S31: deny one ptrace `request` (e.g. `PTRACE_GETREGS`) with
/// the action errno while every other ptrace request — TRACEME,
/// SETOPTIONS, SYSCALL included — stays allowed. Same confined-helper
/// contract as [`install_deny_one`].
#[cfg(target_arch = "x86_64")]
pub fn install_deny_ptrace_request(
    request: libc::c_uint,
    action: DenyAction,
) -> Result<(), SeccompError> {
    let deny = action.ret();
    let program = [
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARCH_OFF),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR_OFF),
        jump(BPF_JEQ_K, libc::SYS_ptrace as u32, 0, 3),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARG0_OFF),
        jump(BPF_JEQ_K, request, 0, 1),
        stmt(BPF_RET_K, deny),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];
    install_program(&program)
}

/// S52-round5: deny only BLOCKING `wait4` (options word zero) with
/// the action errno while `WNOHANG` (and every other flag word)
/// stays allowed. All real wait flags live in the low word, so a
/// zero low word is exactly the blocking-equivalent set. Same
/// confined-helper contract as [`install_deny_one`].
#[cfg(target_arch = "x86_64")]
pub fn install_deny_wait_blocking(action: DenyAction) -> Result<(), SeccompError> {
    let deny = action.ret();
    // wait4(pid, status, options, rusage): options is args[2], a
    // u64 at offset 32; the low word is compared.
    const SECCOMP_DATA_ARG2_OFF: u32 = 32;
    let program = [
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARCH_OFF),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR_OFF),
        jump(BPF_JEQ_K, libc::SYS_wait4 as u32, 0, 3),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARG2_OFF),
        jump(BPF_JEQ_K, 0, 0, 1),
        stmt(BPF_RET_K, deny),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];
    install_program(&program)
}

/// R22-009: deny only NEGATIVE-pid `kill` (the glibc
/// `killpg` lowering — kill and killpg share `SYS_kill`,
/// so a syscall-number filter cannot split them) with
/// the action errno, while positive-pid `kill` stays
/// allowed. Signed-negative is detected on the arg0 LOW
/// word (offset 16): low >= 0x80000000 ⟺ bit 31 set (the
/// high word carries 32-bit-arg garbage — comparing it
/// would miss every real negative pid).
///
/// Boundary (documented, not a hole on the staged
/// paths): `kill(0, …)` (own-group) stays ALLOWED — only
/// the negative-pid (explicit-group) form is denied. The
/// reportless tail never issues `kill(0, …)` (its group
/// signals all ride `killpg(m1, …)` = `kill(-m1, …)`).
/// Same confined-helper contract as [`install_deny_one`].
#[cfg(target_arch = "x86_64")]
pub fn install_deny_kill_negative_pid(action: DenyAction) -> Result<(), SeccompError> {
    let deny = action.ret();
    let program = [
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARCH_OFF),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR_OFF),
        jump(BPF_JEQ_K, libc::SYS_kill as u32, 0, 3),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARG0_OFF),
        jump(BPF_JGE_K, 0x8000_0000, 0, 1),
        stmt(BPF_RET_K, deny),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];
    install_program(&program)
}

/// Latch `NO_NEW_PRIVS` and install one classic-BPF program.
#[cfg(target_arch = "x86_64")]
fn install_program(program: &[libc::sock_filter]) -> Result<(), SeccompError> {
    // SAFETY: `prctl` with explicit `c_ulong` arguments; the program
    // array outlives the synchronous install call.
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
        return Err(SeccompError {
            stage: "no_new_privs",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        });
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
        return Err(SeccompError {
            stage: "install_filter",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        });
    }
    Ok(())
}

/// Non-x86_64 builds refuse without touching process state.
#[cfg(not(target_arch = "x86_64"))]
pub fn install_deny_one(_nr: libc::c_long, _action: DenyAction) -> Result<(), SeccompError> {
    Err(SeccompError {
        stage: "unsupported_arch",
        errno: libc::ENOSYS,
    })
}

/// Non-x86_64 builds refuse without touching process state.
#[cfg(not(target_arch = "x86_64"))]
pub fn install_deny_ptrace_request(
    _request: libc::c_uint,
    _action: DenyAction,
) -> Result<(), SeccompError> {
    Err(SeccompError {
        stage: "unsupported_arch",
        errno: libc::ENOSYS,
    })
}

/// Non-x86_64 builds refuse without touching process state.
#[cfg(not(target_arch = "x86_64"))]
pub fn install_deny_kill_negative_pid(_action: DenyAction) -> Result<(), SeccompError> {
    Err(SeccompError {
        stage: "unsupported_arch",
        errno: libc::ENOSYS,
    })
}

/// Non-x86_64 builds refuse without touching process state.
#[cfg(not(target_arch = "x86_64"))]
pub fn install_deny_wait_blocking(_action: DenyAction) -> Result<(), SeccompError> {
    Err(SeccompError {
        stage: "unsupported_arch",
        errno: libc::ENOSYS,
    })
}

/// Raw `pidfd_open` canary: the filtered syscall invoked directly, with
/// no libc wrapper between the caller and the filter. Returns the new
/// pidfd or the exact errno observed.
pub fn pidfd_open_raw(pid: libc::pid_t) -> Result<RawFd, i32> {
    // SAFETY: direct syscall with a PID and zero flags; returns a new
    // owned fd or -1 with errno set.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
    if fd < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    } else {
        Ok(fd as RawFd)
    }
}

/// R21-004: raw `pidfd_getfd` — duplicate the target's fd
/// `target` through its pidfd (the SAME open file
/// description: identity+mode observed on our dup are one
/// description's, atomically — slot swaps only change
/// WHICH description the grab sees). Returns the new dup
/// or the exact errno observed (EBADF: slot closed
/// mid-scan; EPERM: Yama/permission/denial; ENOSYS: old
/// kernel — all mean unobservable to the caller, never a
/// fallback to racy slot reads).
pub fn pidfd_getfd_raw(pidfd: RawFd, target: libc::c_int) -> Result<RawFd, i32> {
    // SAFETY: direct syscall with owned pidfd, target fd,
    // zero flags; returns a new owned fd or -1 with errno
    // set.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            pidfd as libc::c_long,
            target as libc::c_long,
            0 as libc::c_long,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    } else {
        Ok(fd as RawFd)
    }
}
