// SPDX-License-Identifier: Apache-2.0
//! TT03 F-row seccomp probe: a fresh confined helper that reports raw
//! strict-denial observations for the test oracle to judge.
//!
//! Usage: scopebase-tt03-seccomp-probe (eperm|enosys) <target-pid>
//!
//! The probe pidfd_opens the live target BEFORE installing the deny-one
//! filter, installs the filter via
//! `scopebase_testkit::fixture::linux::seccomp`, then pidfd_opens the
//! target again, re-stats the retained pre-filter pidfd, and stats a
//! procfs path. It prints one `k=v` observation line on stdout and
//! exits 0 whenever the full sequence is observed (unexpected VALUES
//! are the test's verdict, not a probe failure). Exit 1 reports that
//! observation itself was impossible; exit 2 is usage.
//!
//! NEW for the TT03 F seccomp populations; the install idiom is adapted
//! from user-owned p11scope research (see the `seccomp` module docs).
//! Grant: OWNER-2026-10-23.
use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, pidfd_open_raw, DenyAction};
use std::os::fd::{FromRawFd as _, RawFd};

fn usage() -> ! {
    eprintln!("usage: scopebase-tt03-seccomp-probe (eperm|enosys) <target-pid>");
    std::process::exit(2);
}

fn fstat_ok(fd: RawFd) -> String {
    // SAFETY: fd names a live pidfd owned by this process for the call.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut stat) };
    if rc == 0 {
        "ok".to_string()
    } else {
        format!(
            "e{}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        )
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() != 3 {
        usage();
    }
    let (mode, action) = match argv[1].as_str() {
        "eperm" => ("eperm", DenyAction::Eperm),
        "enosys" => ("enosys", DenyAction::Enosys),
        _ => usage(),
    };
    let pid: libc::pid_t = argv[2].parse().unwrap_or_else(|_| usage());

    let (pre_fd, pre_errno) = match pidfd_open_raw(pid) {
        Ok(fd) => (fd as i64, 0),
        Err(errno) => (-1, errno),
    };
    let prefix_fstat = if pre_fd >= 0 {
        fstat_ok(pre_fd as RawFd)
    } else {
        "skip".to_string()
    };

    if let Err(e) = install_deny_one(libc::SYS_pidfd_open, action) {
        // EINVAL/ENOSYS from the install prctl means the kernel has no
        // seccomp filter mode: capability absent, never a denial result.
        if e.stage() == "install_filter" && (e.errno() == libc::EINVAL || e.errno() == libc::ENOSYS)
        {
            eprintln!(
                "TT03-F-INSTALL-UNAVAILABLE: {} errno {}",
                e.stage(),
                e.errno()
            );
        } else {
            eprintln!("TT03-F-INSTALL-FAILED: {e}");
        }
        std::process::exit(1);
    }
    // SAFETY: read-only prctl querying the latched privilege state.
    let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };

    let post_errno = match pidfd_open_raw(pid) {
        Ok(fd) => {
            // SAFETY: a filter that lets pidfd_open through is the test's
            // verdict; close the unexpected fd exactly once here.
            unsafe { libc::close(fd) };
            0
        }
        Err(errno) => errno,
    };
    let retained_fstat = if pre_fd >= 0 {
        fstat_ok(pre_fd as RawFd)
    } else {
        "skip".to_string()
    };
    let stat_ok = if std::fs::metadata("/proc/self/stat").is_ok() {
        1
    } else {
        0
    };
    if pre_fd >= 0 {
        // The retained pre-filter owner closes exactly once, after its
        // post-filter usability was witnessed.
        unsafe { std::fs::File::from_raw_fd(pre_fd as RawFd) };
    }
    println!(
        "mode={mode} pre_fd={pre_fd} pre_errno={pre_errno} prefix_fstat={prefix_fstat} \
         install=ok nnp={nnp} post_errno={post_errno} retained_fstat={retained_fstat} \
         stat_ok={stat_ok}"
    );
}
