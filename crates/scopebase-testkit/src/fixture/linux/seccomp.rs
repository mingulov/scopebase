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

/// Which strict errno the denied syscall reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAction {
    /// `SECCOMP_RET_ERRNO | EPERM`.
    Eperm,
    /// `SECCOMP_RET_ERRNO | ENOSYS`.
    Enosys,
}

impl DenyAction {
    fn errno(self) -> u32 {
        match self {
            DenyAction::Eperm => libc::EPERM as u32,
            DenyAction::Enosys => libc::ENOSYS as u32,
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
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
// `struct seccomp_data` field offsets: nr (int) at 0, arch (__u32) at 4.
const SECCOMP_DATA_NR_OFF: u32 = 0;
const SECCOMP_DATA_ARCH_OFF: u32 = 4;
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
    let deny = SECCOMP_RET_ERRNO | (action.errno() & 0xffff);
    let program = [
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARCH_OFF),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR_OFF),
        jump(BPF_JEQ_K, nr as u32, 0, 1),
        stmt(BPF_RET_K, deny),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];
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
