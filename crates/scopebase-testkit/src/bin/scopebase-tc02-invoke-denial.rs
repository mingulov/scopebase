// SPDX-License-Identifier: Apache-2.0
//! TC02 invoke denial driver: run one closure-pinned tool with the
//! `waitid` observation denied, reporting the outcome for the test
//! oracle.
//!
//! Usage: scopebase-tc02-invoke-denial --tool PATH --closure PATH
//!   --timeout MS [--gate-pidfile PATH] -- <tool args...>
//!
//! S67-round4: the driver installs an arg-blind seccomp filter
//! denying only `SYS_waitid` (reap via `waitpid` and signaling stay
//! allowed), then runs the tool through [`run_pinned`]. A caller
//! filter can deny the WNOWAIT observation exactly this way, so the
//! observation failure must still retire the tool and settle the
//! readers — never drop a live child and two reader handles.
//! Prints one `verdict=...` line (plus `children_after=N`, the live
//! plus unreaped children left behind) and exits 0 whenever the
//! tool ran. Exit 3 is environmental (filter install refused: skip,
//! never fail); exit 4 is report failure (stdout refused the
//! response: never panic).
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
         --timeout MS [--gate-pidfile PATH] -- <tool args...>",
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
    let args: Vec<std::ffi::OsString> = argv[dash + 1..].iter().map(std::ffi::OsString::from).collect();
    // Deny the WNOWAIT observation before the tool exists. Reap and
    // signaling stay allowed: the failure under test is the
    // observation alone.
    if let Err(error) = install_deny_one(libc::SYS_waitid, DenyAction::Eperm) {
        emit(
            &format!("setup=seccomp-{}-{}", error.stage(), error.errno()),
            3,
        );
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
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(10);
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
    match outcome {
        Ok(output) => emit(
            &format!(
                "verdict=ok code={:?} children_after={}",
                output.code(),
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
                    "verdict=err kind={:?} stage={:?} errno={:?} detail={} children_after={}",
                    error.kind(),
                    error.stage(),
                    error.raw_os_error(),
                    chain.join(" | "),
                    kids.len()
                ),
                0,
            );
        }
    }
}
