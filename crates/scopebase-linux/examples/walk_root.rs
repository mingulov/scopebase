// SPDX-License-Identifier: Apache-2.0
//! Walk one explicit root with generous ceilings, printing sorted entries.
//! Usage: walk_root ROOT.
//! NEW (LX11): reference-only; no donor lines copied.
use scopebase_linux::{
    conformance::{refusal_of, ExpectedLedger},
    control::OperationControl,
    walk::{walk, HeldDirectory, WalkBudget, WalkEpoch, WalkLimits, WalkPolicy},
};
use scopebase_testkit::cli;
use std::path::Path;

fn main() {
    // R03: non-UTF-8 argv refuses with usage, never panics in args().
    let args = match cli::argv_strings() {
        Some(args) => args,
        None => {
            cli::err_line("argv is not valid Unicode");
            cli::err_line("usage: walk_root ROOT");
            std::process::exit(2);
        }
    };
    let root = args.get(1).unwrap_or_else(|| {
        cli::err_line("usage: walk_root ROOT");
        std::process::exit(2);
    });
    // R04: every ledger/refusal line is fallible; a dead stdout
    // exits 1 instead of panicking in `println!`.
    let emit = |line: &str| {
        if !cli::put_line(line) {
            std::process::exit(1);
        }
    };
    let limits = WalkLimits {
        max_entries_visited: 1024,
        max_entries_queued: 256,
        max_depth: 16,
        max_path_bytes: 1 << 20,
        max_read_bytes: 1 << 20,
        max_output_bytes: 1 << 20,
        max_open_fds: 64,
        max_stat_calls: 4096,
        max_read_calls: 4096,
    };
    let epoch = WalkEpoch::new();
    let mut budget = WalkBudget::new(limits, limits, &epoch).unwrap_or_else(|error| {
        emit(&refusal_of(&error));
        std::process::exit(1);
    });
    let root =
        HeldDirectory::open(Path::new(&root), WalkPolicy::StayOnMount).unwrap_or_else(|error| {
            emit(&refusal_of(&error));
            std::process::exit(1);
        });
    let control = OperationControl::unlimited();
    let mut paths = Vec::new();
    loop {
        match walk(&root, &mut budget, &control) {
            Ok(batch) => {
                for entry in batch.entries() {
                    paths.push(entry.path().to_string_lossy().into_owned());
                }
                if batch.is_done() {
                    break;
                }
            }
            Err(failure) => {
                emit(&refusal_of(failure.error()));
                std::process::exit(1);
            }
        }
    }
    let mut ledger = ExpectedLedger::new();
    ledger.record("entries", &paths.join(","));
    emit(&ledger.render());
}
