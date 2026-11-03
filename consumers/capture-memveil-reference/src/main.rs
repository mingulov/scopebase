// SPDX-License-Identifier: Apache-2.0
//! MemVeil-shaped reference consumer binary: prints its subject binding
//! and runs two smoke scenarios through the product-shaped reducer.
//! NEW (CP11): reference-only; no donor lines copied.
//!
//! S204: every failure below is a message plus an exit code, never a
//! panic — mirroring the linux mains (R04): all output is fallible
//! (`put_line`/`err_line`); a dead stdout exits 1, and adapter setup
//! failure exits 1 with a stderr report instead of `expect`-panicking.
use capture_memveil_reference::adapter::{run_scenario, MemveilReferenceAdapter};
use scopebase_testkit::cli;
use scopebase_testkit::ConformanceAdapter;

/// Report a failed stdout write; always exits 1 however stderr fares.
fn output_failed() -> i32 {
    cli::err_line("output write failed");
    1
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let adapter = match MemveilReferenceAdapter::new() {
        Ok(adapter) => adapter,
        Err(error) => {
            cli::err_line(&format!("adapter builds: {error}"));
            return 1;
        }
    };
    let subject = adapter.subject();
    if !cli::put_line(&format!(
        "subject: {} {} consumer={}",
        subject.package_name(),
        subject.package_version(),
        subject.consumer().name()
    )) {
        return output_failed();
    }
    let mut failed = false;
    for (op, case, expected) in [
        ("facts", "ok", "match=true;generation=1;"),
        (
            "views",
            "partial-then-final",
            "first=consumed-loss+query-partial;second=consumed-loss;",
        ),
    ] {
        match run_scenario(op, case) {
            Some(Ok(body)) => {
                if !cli::put_line(&format!("{op}/{case}: {body}")) {
                    return output_failed();
                }
                if body != expected {
                    failed = true;
                }
            }
            other => {
                if !cli::put_line(&format!("{op}/{case}: unexpected {other:?}")) {
                    return output_failed();
                }
                failed = true;
            }
        }
    }
    i32::from(failed)
}
