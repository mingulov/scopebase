// SPDX-License-Identifier: Apache-2.0
//! TT04 FS10 audit denial driver: run one syscall audit with a single
//! ptrace request denied, reporting the outcome for the test oracle.
//!
//! Usage: scopebase-tt04-audit-denial (getregs|eventmsg|waitpid) --target PATH
//!   --timeout SEC -- <subject> <args...>
//!
//! S05/S31: the driver preflights ptraceability, installs an
//! arg-selective seccomp filter denying only the named request
//! (TRACEME, SETOPTIONS and SYSCALL stay allowed), then audits the
//! subject argv. The S32 `waitpid` mode instead denies the whole
//! wait4 syscall with EPERM, so every observation wait fails loud.
//! Prints one `verdict=...` line and exits 0 whenever
//! the audit ran (an `err` verdict is the oracle's expectation, not
//! a driver failure). Exit 2 is usage/setup; exit 3 is environmental
//! (preflight or filter install refused: skip, never fail).
//!
//! The confined-helper contract follows the TT03 seccomp probe: the
//! filter is irreversible and inherited by the subject, which never
//! calls ptrace itself.
use scopebase_testkit::cli;
use scopebase_testkit::fixture::linux::audit::{self, AuditConfig};
use scopebase_testkit::fixture::linux::seccomp::{install_deny_ptrace_request, DenyAction};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

fn usage() -> ! {
    cli::err_line(
        "usage: scopebase-tt04-audit-denial (getregs|eventmsg|waitpid) --target PATH \
         --timeout SEC -- <subject> <args...>",
    );
    std::process::exit(2);
}

fn flag_value(argv: &[String], name: &str) -> Option<String> {
    argv.windows(2).find_map(|pair| {
        if pair[0] == name {
            Some(pair[1].clone())
        } else {
            None
        }
    })
}

fn main() {
    let argv = match cli::argv_strings() {
        Some(argv) => argv,
        None => {
            cli::err_line("argv is not valid Unicode");
            usage();
        }
    };
    if argv.len() < 7 || argv[1] != "getregs" && argv[1] != "eventmsg" && argv[1] != "waitpid" {
        usage();
    }
    let waitpid_mode = argv[1] == "waitpid";
    let request = if argv[1] == "getregs" {
        libc::PTRACE_GETREGS
    } else {
        libc::PTRACE_GETEVENTMSG
    };
    let target = flag_value(&argv, "--target").unwrap_or_else(|| usage());
    let timeout: u64 = flag_value(&argv, "--timeout")
        .and_then(|text| text.parse().ok())
        .unwrap_or_else(|| usage());
    let dash = argv.iter().position(|arg| arg == "--").unwrap_or_else(|| {
        cli::err_line("missing -- before subject argv");
        usage();
    });
    if dash + 1 >= argv.len() {
        usage();
    }
    let meta = std::fs::metadata(&target).unwrap_or_else(|_| {
        cli::err_line("audit denial setup failed at target stat");
        usage();
    });
    if audit::preflight().is_err() {
        println!("setup=preflight-refused");
        std::process::exit(3);
    }
    // S32: deny the wait syscall itself (EPERM, never ECHILD), so
    // every observation wait exercises the non-ECHILD custody path.
    // The ptrace requests stay allowed in this mode.
    if waitpid_mode {
        if let Err(error) = scopebase_testkit::fixture::linux::seccomp::install_deny_one(
            libc::SYS_wait4,
            DenyAction::Eperm,
        ) {
            println!("setup=seccomp-{}-{}", error.stage(), error.errno());
            std::process::exit(3);
        }
    } else if let Err(error) =
        install_deny_ptrace_request(request as libc::c_uint, DenyAction::Eperm)
    {
        println!("setup=seccomp-{}-{}", error.stage(), error.errno());
        std::process::exit(3);
    }
    let config = AuditConfig {
        target_dev: meta.dev() as u64,
        target_ino: meta.ino(),
        max_entries: 4096,
        timeout: std::time::Duration::from_secs(timeout),
    };
    let subject = Path::new(&argv[dash + 1]);
    let args: Vec<String> = argv[dash + 2..].to_vec();
    match audit::audit_subject(subject, &args, &config) {
        Ok(report) => println!(
            "verdict=ok exit={:?} mmaps={} unattributed={} threads={}",
            report.exit_code,
            report.mmaps.len(),
            report.unattributed_mmaps().len(),
            report.threads_seen,
        ),
        Err(error) => println!("verdict=err {error}"),
    }
}
