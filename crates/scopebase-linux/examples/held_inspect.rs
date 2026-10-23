// SPDX-License-Identifier: Apache-2.0
//! Open, stat and bounded-read one explicit path, printing the conformance
//! ledger (or the typed refusal). Usage: held_inspect PATH.
//! NEW (LX11): reference-only; no donor lines copied.
use scopebase_linux::{
    conformance::{refusal_of, ExpectedLedger},
    control::OperationControl,
    file::{HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy},
};
use std::path::Path;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: held_inspect PATH");
        std::process::exit(2);
    });
    let resolver = ProcFdResolver::open_self().unwrap_or_else(|error| {
        println!("{}", refusal_of(&error));
        std::process::exit(1);
    });
    let held = HeldFile::open(Path::new(&path), &resolver, SymlinkPolicy::RejectFinal)
        .unwrap_or_else(|error| {
            println!("{}", refusal_of(&error));
            std::process::exit(1);
        });
    let stat = held.stat().unwrap_or_else(|error| {
        println!("{}", refusal_of(&error));
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
            println!("{}", refusal_of(&error));
            std::process::exit(1);
        });
    let mut ledger = ExpectedLedger::new();
    ledger.record("stat", &format!("len:{}", stat.len()));
    ledger.record("bytes", &read.bytes().len().to_string());
    ledger.record("calls", &read.charges().read_calls().to_string());
    println!("{}", ledger.render());
}
