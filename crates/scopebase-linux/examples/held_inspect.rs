// SPDX-License-Identifier: Apache-2.0
//! Open, stat and bounded-read one explicit path, printing the conformance
//! ledger (or the typed refusal). Usage: held_inspect PATH.
//! NEW (LX11): reference-only; no donor lines copied.
use scopebase_linux::{
    conformance::{refusal_of, ExpectedLedger},
    control::OperationControl,
    file::{HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy},
};
use scopebase_testkit::cli;
use std::path::Path;

fn main() {
    // R03: non-UTF-8 argv refuses with usage, never panics in args().
    let args = match cli::argv_strings() {
        Some(args) => args,
        None => {
            cli::err_line("argv is not valid Unicode");
            cli::err_line("usage: held_inspect PATH");
            std::process::exit(2);
        }
    };
    let path = args.get(1).unwrap_or_else(|| {
        cli::err_line("usage: held_inspect PATH");
        std::process::exit(2);
    });
    // R04: every ledger/refusal line is fallible; a dead stdout
    // exits 1 instead of panicking in `println!`.
    let emit = |line: &str| {
        if !cli::put_line(line) {
            std::process::exit(1);
        }
    };
    let resolver = ProcFdResolver::open_self().unwrap_or_else(|error| {
        emit(&refusal_of(&error));
        std::process::exit(1);
    });
    let held = HeldFile::open(Path::new(&path), &resolver, SymlinkPolicy::RejectFinal)
        .unwrap_or_else(|error| {
            emit(&refusal_of(&error));
            std::process::exit(1);
        });
    let stat = held.stat().unwrap_or_else(|error| {
        emit(&refusal_of(&error));
        std::process::exit(1);
    });
    let read = held
        .read_all(
            ReadLimits {
                max_bytes: 1 << 20,
                max_read_calls: 64,
                max_buffer_capacity: 1 << 20,
            },
            &OperationControl::unlimited(),
        )
        .unwrap_or_else(|error| {
            emit(&refusal_of(&error));
            std::process::exit(1);
        });
    let mut ledger = ExpectedLedger::new();
    ledger.record("stat", &format!("len:{}", stat.len()));
    ledger.record("bytes", &read.bytes().len().to_string());
    ledger.record("calls", &read.charges().read_calls().to_string());
    emit(&ledger.render());
}
