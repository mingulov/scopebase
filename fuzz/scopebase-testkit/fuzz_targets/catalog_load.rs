// SPDX-License-Identifier: Apache-2.0
//! TT06 first fuzz target: `CaseCatalog::load` byte robustness.
//!
//! `fuzz_one` is the shared input handler for both engines:
//!
//! * Stable smoke engine (`main` below, no extra dependencies): walks the
//!   seed corpus plus a fixed deterministic fan-out per seed and reports
//!   through the TT06 target protocol. This is what the shipped
//!   `catalog-fuzz-smoke` campaign executes.
//! * libFuzzer engine (`#[cfg(fuzzing)]` entry): requires `cargo-fuzz` and a
//!   `libfuzzer-sys` admission that is NOT bound yet (see
//!   docs/issues/qualification/dependency-choice.md). Building with
//!   `--cfg fuzzing` today fails on the missing crate, which the campaign
//!   runner records as PREREQUISITE_UNMET rather than coverage.
//!
//! Oracle: no input may panic, and every verdict must be deterministic
//! across repeated loads. Accept and reject are both legal verdicts for
//! arbitrary bytes; the directed accept/reject contracts live in the
//! state model (tests/models) instead.

use scopebase_testkit::{CaseCatalog, CatalogErrorKind, CatalogLimits};
use std::io::Write;

#[cfg(fuzzing)]
#[macro_use]
extern crate libfuzzer_sys;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    fuzz_one(data);
});

fn verdict_of(bytes: &[u8]) -> Result<(), CatalogErrorKind> {
    match CaseCatalog::load(bytes, CatalogLimits::default()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.kind()),
    }
}

/// Shared handler: returns a failure description, or None when the input is
/// panic-free and deterministic.
pub fn fuzz_one(data: &[u8]) -> Option<String> {
    let first = verdict_of(data);
    let second = verdict_of(data);
    if first != second {
        return Some(format!("nondeterministic verdict: {first:?} then {second:?}"));
    }
    None
}

/// Fixed deterministic fan-out per seed: original plus truncations and
/// single-byte damage. Counted uniformly as one work item per input.
fn fan_out(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![seed.to_vec()];
    if seed.is_empty() {
        return out;
    }
    for frac in [2usize, 4] {
        out.push(seed[..seed.len() - seed.len() / frac].to_vec());
    }
    out.push(seed[..seed.len() - 1].to_vec());
    for pos in [0, seed.len() / 2, seed.len() - 1] {
        let mut damaged = seed.to_vec();
        damaged[pos] ^= 0xFF;
        out.push(damaged);
    }
    let mut extended = seed.to_vec();
    extended.push(0x7D);
    out.push(extended);
    out
}

fn usage() -> ! {
    eprintln!("usage: catalog_load --corpus DIR --result PATH");
    std::process::exit(2);
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(not(fuzzing))]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut corpus: Option<String> = None;
    let mut result: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                corpus = Some(args[i].clone());
            }
            "--result" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                result = Some(args[i].clone());
            }
            _ => usage(),
        }
        i += 1;
    }
    let (corpus, result) = match (corpus, result) {
        (Some(c), Some(r)) => (c, r),
        _ => usage(),
    };
    let mut seeds: Vec<std::path::PathBuf> = match std::fs::read_dir(&corpus) {
        Ok(entries) => entries.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_file()).collect(),
        Err(e) => {
            write_final(&result, false, "error", 0, &format!("corpus unreadable: {e}"));
            return;
        }
    };
    if seeds.is_empty() {
        write_final(&result, false, "error", 0, "corpus holds no seed files");
        return;
    }
    seeds.sort();
    // Partial record proves valid setup before the bounded walk starts.
    write_final(&result, true, "error", 0, &format!("setup: {} seeds; walking", seeds.len()));
    let mut work_items = 0usize;
    let mut first_failure: Option<String> = None;
    for seed_path in &seeds {
        let bytes = match std::fs::read(seed_path) {
            Ok(b) => b,
            Err(e) => {
                first_failure = Some(format!("seed {} unreadable: {e}", seed_path.display()));
                break;
            }
        };
        for input in fan_out(&bytes) {
            work_items += 1;
            if first_failure.is_none() {
                if let Some(detail) = fuzz_one(&input) {
                    first_failure = Some(format!("seed {}: {detail}", seed_path.display()));
                }
            }
        }
    }
    let (assertion, detail) = match first_failure {
        None => ("pass", format!("{} seeds, {work_items} inputs, no panic, deterministic", seeds.len())),
        Some(f) => ("fail", f),
    };
    write_final(&result, true, assertion, work_items, &detail);
}

fn write_final(path: &str, setup_ok: bool, assertion: &str, work_items: usize, detail: &str) {
    let body = format!(
        "{{\"setup_ok\": {setup_ok}, \"assertion\": \"{assertion}\", \"work_items\": {work_items}, \"detail\": \"{}\"}}\n",
        json_escape(&detail.chars().take(1024).collect::<String>()),
        setup_ok = if setup_ok { "true" } else { "false" },
    );
    let mut file = std::fs::File::create(path).expect("result path must be writable");
    file.write_all(body.as_bytes()).expect("result write must succeed");
}
