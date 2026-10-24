// SPDX-License-Identifier: Apache-2.0
//! TC02 invoke denial driver: run one closure-pinned tool with the
//! `waitid` observation denied, reporting the outcome for the test
//! oracle.
//!
//! Usage: scopebase-tc02-invoke-denial --tool PATH --closure PATH
//!   --timeout MS [--gate-pidfile PATH] [--deny-signal |
//!   --deny-signal-only | --auto-reap] [--deny-waitid] [--trap-signal]
//!   -- <tool args...>
//!
//! S67-round4: the driver installs an arg-blind seccomp filter
//! denying only `SYS_waitid` (reap via `waitpid` and signaling stay
//! allowed), then runs the tool through [`run_pinned`]. A caller
//! filter can deny the WNOWAIT observation exactly this way, so the
//! observation failure must still retire the tool and settle the
//! readers — never drop a live child and two reader handles.
//!
//! S86-round5 `--deny-signal`: additionally deny the signal routes
//! (`kill`, `tkill`, `tgkill`, `pidfd_send_signal` — the last covers
//! `Child::kill` when std holds a pidfd). With the observation
//! denied and signals refused but reaping allowed, retirement must
//! stay deadline-bounded and report the refused signal instead of
//! blocking past the configured timeout.
//!
//! S86-round6 `--deny-signal-only`: deny the signal routes but LEAVE
//! `waitid` allowed, so the overrun and wall-clock-timeout branches
//! (unreachable when the first observation fails) face denied
//! signals deterministically. Under plain `--deny-signal` the EPERM
//! observation always wins the first loop iteration, so those
//! branches never run there.
//!
//! S85-round5 `--auto-reap`: skip the waitid filter and set
//! `SIGCHLD` to `SIG_IGN` instead, so the tool is auto-reaped on
//! exit. S85-round6: the run refuses up front (group reservation is
//! unprovable under auto-reap), so `--deny-waitid` re-adds the
//! waitid filter for the combined auto-reap/denial case and
//! `--trap-signal` turns any `SYS_kill` attempt (`kill` and `killpg`
//! share the number) into a fatal SIGSYS — survival is the
//! no-signal oracle. The disposition and filters are confined to
//! this helper process.
//!
//! Prints one `verdict=...` line (plus `children_after=N`, the live
//! plus unreaped children left behind, and `survivors=` with their
//! `pid:starttime` identities for verified test cleanup) and exits
//! 0 whenever the tool ran. Exit
//! 3 is environmental (filter install refused: skip, never fail);
//! exit 4 is report failure (stdout refused the response: never
//! panic).
//!
//! The confined-helper contract follows the TT03 seccomp probe: the
//! filter is irreversible and installed before the tool spawns.
use scopebase_bpf::Limits;
use scopebase_testkit::cli;
use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};
use scopebase_testkit::toolchain::{run_pinned_with_builders, CompilerClosure, NestedBounds};

fn usage() -> ! {
    cli::err_line(
        "usage: scopebase-tc02-invoke-denial --tool PATH --closure PATH \
         --timeout MS [--gate-pidfile PATH] [--deny-signal | \
         --deny-signal-only | --auto-reap] [--deny-waitid] [--trap-signal] \
         -- <tool args...>",
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

fn emit(line: &str, code: i32) -> ! {
    if !cli::put_line(line) {
        cli::err_line("invoke denial report write failed");
        std::process::exit(4);
    }
    std::process::exit(code);
}

/// S98-round6: starttime of a live task (field 22 of
/// `/proc/PID/stat`). `None` when the task is gone or the row is
/// unreadable — a child that exits between the listing and this
/// read needs no cleanup entry.
fn child_starttime(pid: u32) -> Option<u64> {
    let row = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = row.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Live plus unreaped children of this process, across every thread
/// (detached reader threads keep their own task rows; the union is
/// what matters).
fn children_after() -> Vec<u32> {
    let mut out = std::collections::BTreeSet::new();
    let tasks = std::fs::read_dir("/proc/self/task").into_iter().flatten();
    for task in tasks.flatten() {
        let kids = std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
        for word in kids.split_whitespace() {
            if let Ok(pid) = word.parse::<u32>() {
                out.insert(pid);
            }
        }
    }
    out.into_iter().collect()
}

fn main() {
    let argv = match cli::argv_strings() {
        Some(argv) => argv,
        None => {
            cli::err_line("argv is not valid Unicode");
            usage();
        }
    };
    let tool = flag_value(&argv, "--tool").unwrap_or_else(|| usage());
    let closure_path = flag_value(&argv, "--closure").unwrap_or_else(|| usage());
    let timeout: u64 = flag_value(&argv, "--timeout")
        .and_then(|text| text.parse().ok())
        .unwrap_or_else(|| usage());
    let dash = argv.iter().position(|arg| arg == "--").unwrap_or_else(|| {
        cli::err_line("missing -- before tool argv");
        usage();
    });
    let args: Vec<std::ffi::OsString> = argv[dash + 1..]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();
    // Driver flags live before `--`; tool argv after it must not be
    // mistaken for flags.
    let flags = &argv[1..dash];
    let deny_signal = flags.iter().any(|arg| arg == "--deny-signal");
    let deny_signal_only = flags.iter().any(|arg| arg == "--deny-signal-only");
    let auto_reap = flags.iter().any(|arg| arg == "--auto-reap");
    let deny_waitid = flags.iter().any(|arg| arg == "--deny-waitid");
    let trap_signal = flags.iter().any(|arg| arg == "--trap-signal");
    if [deny_signal, deny_signal_only, auto_reap]
        .iter()
        .filter(|picked| **picked)
        .count()
        > 1
    {
        cli::err_line("deny-signal, deny-signal-only and auto-reap are exclusive modes");
        usage();
    }
    // S85-round6: --deny-waitid re-adds the waitid filter that
    // auto-reap mode skips by default (the combined case); anywhere
    // else the filter is already the default (plain/deny-signal) or
    // contradicts the mode (deny-signal-only), so the combination
    // is refused rather than silently shadowed.
    if deny_waitid && !auto_reap {
        cli::err_line("deny-waitid requires auto-reap");
        usage();
    }
    // S85-round6: the trap must see attempts: under an EPERM signal
    // denial the trap would shadow (newest filter wins) or be
    // shadowed, so the combination is refused.
    if trap_signal && (deny_signal || deny_signal_only) {
        cli::err_line("trap-signal is exclusive with signal denial");
        usage();
    }
    if auto_reap {
        // SAFETY: `signal` with a valid disposition constant; the
        // disposition is confined to this helper process.
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        }
    }
    // Deny the WNOWAIT observation before the tool exists, unless a
    // mode keeps it: the S67 default (plain and --deny-signal),
    // re-added under --auto-reap only by --deny-waitid.
    if (!auto_reap && !deny_signal_only) || deny_waitid {
        if let Err(error) = install_deny_one(libc::SYS_waitid, DenyAction::Eperm) {
            emit(
                &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                3,
            );
        }
    }
    // S86-round5: deny every signal route (`kill`, `tkill`,
    // `tgkill`, `pidfd_send_signal` — the last covers `Child::kill`
    // when std holds a pidfd). Seccomp filters stack, so each
    // deny-one program layers onto the waitid denial above when one
    // is installed. Reaping stays allowed.
    if deny_signal || deny_signal_only {
        for nr in [
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_pidfd_send_signal,
        ] {
            if let Err(error) = install_deny_one(nr, DenyAction::Eperm) {
                emit(
                    &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                    3,
                );
            }
        }
    }
    // S85-round6: any SYS_kill attempt (kill and killpg share the
    // number) kills this helper with SIGSYS. Survival is the
    // no-signal oracle for the combined auto-reap/denial case.
    if trap_signal {
        if let Err(error) = install_deny_one(libc::SYS_kill, DenyAction::Kill) {
            emit(
                &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
                3,
            );
        }
    }
    let closure_bytes = std::fs::read(&closure_path).unwrap_or_else(|_| {
        cli::err_line("invoke denial setup failed at closure read");
        usage();
    });
    let limits = Limits {
        input_bytes: 1 << 20,
        retained_bytes: 1 << 20,
        work_steps: 1 << 20,
        sites: 64,
        live_links: 64,
        pending_retirements: 64,
    };
    let closure = CompilerClosure::from_json(&closure_bytes, &limits).unwrap_or_else(|_| {
        cli::err_line("invoke denial setup failed at closure parse");
        usage();
    });
    let bounds = NestedBounds {
        max_stdout_bytes: 1 << 20,
        max_stderr_bytes: 1 << 20,
        timeout_ms: timeout,
        max_args: 64,
        max_env: 64,
    };
    // S67-round4: when the tool records a descendant pidfile, wait
    // for the recorded sleeper RUNNING before the first (denied)
    // observation — the denial branch then faces a proven-live
    // descendant, and the test's grandchild-dead assertion is a
    // closed chain, never a startup race.
    let gate_path = flag_value(&argv, "--gate-pidfile");
    let observe_gate = gate_path.map(|path| {
        let gate: Box<dyn FnOnce() + Send> = Box::new(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                let running = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| text.trim().parse::<i32>().ok())
                    .and_then(|pid| std::fs::read(format!("/proc/{pid}/cmdline")).ok())
                    .map(|bytes| bytes.starts_with(b"sleep"))
                    .unwrap_or(false);
                if running {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        gate
    });
    let outcome = run_pinned_with_builders(
        &closure,
        "llvm-23.1.2-source",
        std::path::Path::new(&tool),
        &args,
        &[],
        &bounds,
        std::thread::Builder::new().name("invoke-stdout".to_string()),
        std::thread::Builder::new().name("invoke-stderr".to_string()),
        None,
        observe_gate,
    );
    let kids = children_after();
    // S86-round5: surviving pids for test cleanup (a kill-proof
    // tool outlives the run by design); empty when none survive.
    // S98-round6: each entry pins `pid:starttime`, the stable
    // cross-process identity the test re-verifies before signaling
    // — a raw pid could name a recycled stranger by cleanup time.
    // A child that exits between the listing and the starttime read
    // is already gone and earns no entry.
    let survivors = kids
        .iter()
        .filter_map(|pid| child_starttime(*pid).map(|started| format!("{pid}:{started}")))
        .collect::<Vec<_>>()
        .join(",");
    match outcome {
        Ok(output) => emit(
            &format!(
                "verdict=ok code={:?} survivors={} children_after={}",
                output.code(),
                survivors,
                kids.len()
            ),
            0,
        ),
        Err(error) => {
            // The full source chain, so retirement fallout
            // ("tool retirement failed", "output reader
            // unsettled") is visible, not just the kind/stage.
            let mut chain = vec![error.to_string()];
            let mut next = std::error::Error::source(&error);
            while let Some(source) = next {
                chain.push(source.to_string());
                next = std::error::Error::source(source);
            }
            emit(
                &format!(
                    "verdict=err kind={:?} stage={:?} errno={:?} detail={} survivors={} children_after={}",
                    error.kind(),
                    error.stage(),
                    error.raw_os_error(),
                    chain.join(" | "),
                    survivors,
                    kids.len()
                ),
                0,
            );
        }
    }
}
