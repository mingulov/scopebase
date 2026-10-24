// SPDX-License-Identifier: Apache-2.0
//! TT04 FS10 audit denial driver: run one syscall audit with a single
//! ptrace request denied, reporting the outcome for the test oracle.
//!
//! Usage: scopebase-tt04-audit-denial (getregs|getregs-exit|eventmsg|waitpid) --target PATH
//!   --timeout SEC -- <subject> <args...>
//!
//! S05/S31: the driver preflights ptraceability, installs an
//! arg-selective seccomp filter denying only the named request
//! (TRACEME, SETOPTIONS and SYSCALL stay allowed), then audits the
//! subject argv. The S32 `waitpid` mode instead denies the whole
//! wait4 syscall with EPERM, so every observation wait fails loud.
//! The S05-round3 `getregs-exit` mode installs nothing upfront: the
//! GETREGS denial arms after the first recorded mmap-family entry,
//! so the matching EXIT sample is the failure under test.
//! Prints one `verdict=...` line and exits 0 whenever
//! the audit ran (an `err` verdict is the oracle's expectation, not
//! a driver failure). Exit 2 is usage/setup; exit 3 is environmental
//! (preflight or filter install refused: skip, never fail); exit 4
//! is report failure (stdout refused the response: never panic).
//!
//! The confined-helper contract follows the TT03 seccomp probe: the
//! filter is irreversible and inherited by the subject, which never
//! calls ptrace itself.
use scopebase_testkit::cli;
use scopebase_testkit::fixture::linux::audit::{self, AuditConfig};
use scopebase_testkit::fixture::linux::seccomp::{
    install_deny_one, install_deny_ptrace_request, install_deny_wait_blocking, DenyAction,
};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

fn usage() -> ! {
    cli::err_line(
        "usage: scopebase-tt04-audit-denial (getregs|getregs-exit|eventmsg|waitpid) --target PATH \
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

/// S53: ptrace request denied for a driver mode. x86_64-only
/// constants live behind the arch gate; anywhere else (or for an
/// unknown mode) there is no request to deny.
#[cfg(target_arch = "x86_64")]
fn denial_request(mode: &str) -> Option<libc::c_uint> {
    match mode {
        "getregs" => Some(libc::PTRACE_GETREGS),
        "eventmsg" => Some(libc::PTRACE_GETEVENTMSG),
        "preflight-cont" => Some(libc::PTRACE_CONT),
        _ => None,
    }
}

/// S53: non-x86_64 builds never name the x86_64-only requests.
#[cfg(not(target_arch = "x86_64"))]
fn denial_request(_mode: &str) -> Option<libc::c_uint> {
    None
}

/// S54: every driver response goes through the fallible stdout
/// helper. A dead stdout (EPIPE, ENOSPC on /dev/full) exits 4
/// instead of panicking in `println!`.
fn emit(line: &str, code: i32) -> ! {
    if !cli::put_line(line) {
        cli::err_line("audit denial report write failed");
        std::process::exit(4);
    }
    std::process::exit(code);
}

fn main() {
    let argv = match cli::argv_strings() {
        Some(argv) => argv,
        None => {
            cli::err_line("argv is not valid Unicode");
            usage();
        }
    };
    // S55-round4: forced setup probe for the exit-3 control below.
    // Always emits the documented environmental-refusal response so
    // the harness path is exercised deterministically.
    if argv.len() >= 2 && argv[1] == "setup-probe" {
        emit("setup=forced-probe", 3);
    }
    // S52: preflight-denial modes install the filter FIRST and run
    // only the preflight, so a denied resume or wait inside the
    // probe itself is exercised. They take no other arguments.
    if argv.len() >= 2
        && (argv[1] == "preflight-cont"
            || argv[1] == "preflight-wait"
            || argv[1] == "preflight-contkill"
            || argv[1] == "preflight-autoreap"
            || argv[1] == "preflight-autoreap-nocldwait"
            || argv[1] == "preflight-waitstop"
            || argv[1] == "preflight-nopidfd")
    {
        if argv[1] == "preflight-cont"
            || argv[1] == "preflight-contkill"
            || argv[1] == "preflight-nopidfd"
        {
            let cont = match denial_request("preflight-cont") {
                Some(request) => request,
                None => emit("setup=arch-or-mode-unsupported", 3),
            };
            if let Err(error) =
                install_deny_ptrace_request(cont, DenyAction::Eperm)
            {
                emit(
                    &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                    3,
                );
            }
        }
        // S52-round4: combined CONT + signaling denial. Both kill
        // routes fail, so retirement must report unresolved custody
        // instead of claiming the EPERM-probed child gone.
        if argv[1] == "preflight-contkill" {
            for nr in [libc::SYS_kill, libc::SYS_pidfd_send_signal] {
                if let Err(error) = install_deny_one(nr, DenyAction::Eperm) {
                    emit(
                        &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                        3,
                    );
                }
            }
        }
        // S68-round4: auto-reap plus a kill tripwire. TRACEME denied
        // leaves the child untraced (a traced exit still reports to
        // the tracer despite `SIGCHLD=SIG_IGN`), so `SIGCHLD=SIG_IGN`
        // reaps it on exit and the probe's wait reports ECHILD over
        // an unreserved number; any cleanup signal then kills the
        // driver with SIGSYS instead of risking a recycled same-UID
        // process.
        if argv[1] == "preflight-autoreap" || argv[1] == "preflight-autoreap-nocldwait" {
            if argv[1] == "preflight-autoreap" {
                // SAFETY: SIG_IGN for SIGCHLD in a single-threaded driver.
                unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
            } else {
                // S68-round6: SA_NOCLDWAIT auto-reap without SIG_IGN
                // (the configuration the round-5 predicate missed).
                // SAFETY: sigaction install in a single-threaded driver.
                unsafe {
                    let mut act: libc::sigaction = std::mem::zeroed();
                    act.sa_sigaction = libc::SIG_DFL;
                    act.sa_flags = libc::SA_NOCLDWAIT;
                    libc::sigemptyset(&mut act.sa_mask);
                    libc::sigaction(libc::SIGCHLD, &act, std::ptr::null_mut());
                }
            }
            if let Err(error) =
                install_deny_ptrace_request(libc::PTRACE_TRACEME, DenyAction::Eperm)
            {
                emit(
                    &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                    3,
                );
            }
            for nr in [libc::SYS_kill, libc::SYS_pidfd_send_signal] {
                if let Err(error) = install_deny_one(nr, DenyAction::Kill) {
                    emit(
                        &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                        3,
                    );
                }
            }
        }
        if argv[1] == "preflight-wait" {
            if let Err(error) = install_deny_one(libc::SYS_wait4, DenyAction::Eperm) {
                emit(
                    &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                    3,
                );
            }
        }
        // S52-round5: flags-selective wait denial — blocking
        // waits fail while WNOHANG stays allowed — plus both
        // kill routes denied. Retirement must consume the
        // queued TRACEME stop WITHOUT reporting retired, fail
        // to signal, and report unresolved custody for the
        // still-stopped child.
        if argv[1] == "preflight-waitstop" {
            if let Err(error) = install_deny_wait_blocking(DenyAction::Eperm) {
                emit(
                    &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                    3,
                );
            }
            for nr in [libc::SYS_kill, libc::SYS_pidfd_send_signal] {
                if let Err(error) = install_deny_one(nr, DenyAction::Eperm) {
                    emit(
                        &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                        3,
                    );
                }
            }
        }
        // S68-round5: pidfd authority denied (plus CONT, to force
        // a retirement). Signaling must report Uncertain and reap
        // without signaling — never a numeric SIGKILL — so the
        // stopped survivor reports unresolved custody.
        if argv[1] == "preflight-nopidfd" {
            if let Err(error) = install_deny_one(libc::SYS_pidfd_open, DenyAction::Eperm) {
                emit(
                    &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                    3,
                );
            }
        }
        match audit::preflight() {
            Ok(note) => emit(&format!("verdict=ok {note}"), 0),
            Err(error) => emit(&format!("verdict=err {error}"), 0),
        }
    }
    if argv.len() < 7
        || argv[1] != "getregs"
            && argv[1] != "getregs-exit"
            && argv[1] != "eventmsg"
            && argv[1] != "waitpid"
    {
        usage();
    }
    let waitpid_mode = argv[1] == "waitpid";
    // S05-round3: deferred denial — installed by the entry hook
    // mid-audit, never upfront.
    let deferred_mode = argv[1] == "getregs-exit";
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
        emit("setup=preflight-refused", 3);
    }
    // S32: deny the wait syscall itself (EPERM, never ECHILD), so
    // every observation wait exercises the non-ECHILD custody path.
    // The ptrace requests stay allowed in this mode.
    if waitpid_mode {
        if let Err(error) = scopebase_testkit::fixture::linux::seccomp::install_deny_one(
            libc::SYS_wait4,
            DenyAction::Eperm,
        ) {
            emit(
                &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                3,
            );
        }
    } else if deferred_mode {
        // S05-round3: nothing upfront; the arm hook below denies
        // GETREGS after the first recorded mmap-family entry. The
        // request still resolves here so an unsupported arch
        // reports setup (exit 3, skip) before the audit runs.
        if denial_request("getregs").is_none() {
            emit("setup=arch-or-mode-unsupported", 3);
        }
    } else {
        // S53: the denied requests are x86_64-only constants;
        // resolve them behind the same compile-time gate as the
        // tracer so this binary builds where they do not exist.
        // (waitpid mode denies the wait syscall above instead.)
        let request = match denial_request(&argv[1]) {
            Some(request) => request,
            None => emit("setup=arch-or-mode-unsupported", 3),
        };
        if let Err(error) =
            install_deny_ptrace_request(request, DenyAction::Eperm)
        {
            emit(
                &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                3,
            );
        }
    }
    let config = AuditConfig {
        target_dev: meta.dev() as u64,
        target_ino: meta.ino(),
        max_entries: 4096,
        timeout: std::time::Duration::from_secs(timeout),
    };
    let subject = Path::new(&argv[dash + 1]);
    let args: Vec<String> = argv[dash + 2..].to_vec();
    // S05-round3: the deferred arm denies GETREGS from inside the
    // tracer thread, right after the first recorded mmap-family
    // entry. An install failure records itself instead of killing
    // the audit mid-loop; the outcome below reports setup (exit 3,
    // skip), never a verdict the denial did not cause.
    let arm_failed = std::sync::atomic::AtomicBool::new(false);
    let outcome = if deferred_mode {
        // Proven Some by the upfront check; re-resolved for type.
        let request = match denial_request("getregs") {
            Some(request) => request,
            None => emit("setup=arch-or-mode-unsupported", 3),
        };
        audit::audit_subject_with_entry_hook(subject, &args, &config, &|| {
            if install_deny_ptrace_request(request, DenyAction::Eperm).is_err() {
                arm_failed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        })
    } else {
        audit::audit_subject(subject, &args, &config)
    };
    if deferred_mode && arm_failed.load(std::sync::atomic::Ordering::SeqCst) {
        emit("setup=seccomp-arm-refused", 3);
    }
    match outcome {
        Ok(report) => emit(
            &format!(
                "verdict=ok exit={:?} mmaps={} unattributed={} threads={}",
                report.exit_code,
                report.mmaps.len(),
                report.unattributed_mmaps().len(),
                report.threads_seen,
            ),
            0,
        ),
        Err(error) => emit(&format!("verdict=err {error}"), 0),
    }
}
