// SPDX-License-Identifier: Apache-2.0
//! Acquire and verify the observer's own process, then report relational
//! maps facts (never absolute counts). Prints the conformance ledger.
//! NEW (LX11): reference-only; no donor lines copied.
use scopebase_linux::{
    conformance::{refusal_of, ExpectedLedger},
    control::OperationControl,
    process::{ObserverEpoch, Pid, ProcLimits, ProcessObservation},
    procfs::ParseLimits,
};

fn main() {
    let limits = ProcLimits {
        parse: ParseLimits {
            max_bytes: 1 << 20,
            max_entries: 1 << 16,
            max_line_bytes: 1 << 16,
        },
        max_read_calls: 4096,
        max_metadata_bytes: 1 << 20,
    };
    let control = OperationControl::unlimited();
    let epoch = ObserverEpoch::new(limits, &control).unwrap_or_else(|error| {
        println!("{}", refusal_of(&error));
        std::process::exit(1);
    });
    let pid = Pid::new(std::process::id() as i32).expect("own pid is valid");
    let observation =
        ProcessObservation::acquire(pid, &epoch, limits, &control).unwrap_or_else(|error| {
            println!("{}", refusal_of(&error));
            std::process::exit(1);
        });
    let birth = observation.verify_birth(&control).unwrap_or_else(|error| {
        println!("{}", refusal_of(&error));
        std::process::exit(1);
    });
    let maps = observation
        .read_maps(limits, &control)
        .unwrap_or_else(|error| {
            println!("{}", refusal_of(&error));
            std::process::exit(1);
        });
    let probe = 0u8;
    let addr = std::ptr::addr_of!(probe) as u64;
    let mut ledger = ExpectedLedger::new();
    ledger.record("birth", &format!("{:?}", birth.status()));
    ledger.record(
        "nonempty",
        &(maps.snapshot().entries().len() > 0).to_string(),
    );
    ledger.record(
        "self_containing",
        &maps.snapshot().containing(addr).is_some().to_string(),
    );
    println!("{}", ledger.render());
}
