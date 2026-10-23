// SPDX-License-Identifier: Apache-2.0
//! TT09 contract-cost bench: deterministic cap/capability assertions gate the
//! run; wall-time distributions are reported, never gating.
//!
//! NEW (no donor slice): see `src/resource.rs`.
//!
//! Workloads (fixed parameters, frozen by profiles/performance-v1.json):
//! - `bounds_check`: 512 mixed samples x `reps` bound evaluations.
//! - `ledger_cycle`: 5_000 single-consumer reserve/settle/charge/refund cycles.
//! - `ledger_concurrent`: 8 consumers x 1_000 cycles on one shared ledger.
//!
//! Usage: `cargo bench -p scopebase-testkit --bench contract_costs --
//! [--reps 21] [--workload all|bounds|ledger|concurrent] [--out report.json]`
//!
//! Exit 0: every deterministic assertion held (timing always reported).
//! Exit 1: a deterministic assertion failed; the report names it.

use scopebase_testkit::resource::{
    check_bounds, violations, DomainBounds, DomainId, Ledger, ResourceSample, ResourceSampleValues,
};
use std::sync::Arc;
use std::time::Instant;

const BOUNDS_ITEMS: usize = 512;
const LEDGER_CYCLES: usize = 5_000;
const CONC_CONSUMERS: usize = 8;
const CONC_CYCLES: usize = 1_000;

fn bounds_fixture() -> (DomainBounds, Vec<ResourceSample>) {
    let bounds = DomainBounds::new(
        DomainId::new("bench").expect("domain"),
        10_000,
        500,
        20_000,
        1_000,
    );
    let mut items = Vec::with_capacity(BOUNDS_ITEMS);
    for i in 0..BOUNDS_ITEMS {
        let i = i as u64;
        // Deterministic mixed population: every 7th overruns bytes, every 11th
        // overruns work, every 13th overruns memory; time held at cap.
        let retained = if i % 7 == 6 { 9_000 } else { 1_000 };
        let working = if i % 7 == 6 { 2_000 } else { 500 };
        let attempts = if i % 11 == 10 { 501 } else { 100 };
        let peak = if i % 13 == 12 { 20_001 } else { 8_000 };
        items.push(
            ResourceSample::new(ResourceSampleValues {
                epoch: i,
                retained_bytes: retained,
                working_bytes: working,
                attempts,
                peak_bytes: peak,
                ..Default::default()
            })
            .expect("valid sample"),
        );
    }
    (bounds, items)
}

fn run_bounds(reps: usize) -> (u64, Vec<u128>, String) {
    let (bounds, items) = bounds_fixture();
    // Deterministic oracle: first rep fixes the expected violation count and
    // per-item check/violations agreement; later reps must match exactly.
    let expected: u64 = items
        .iter()
        .map(|s| violations(s, &bounds, 1_000).len() as u64)
        .sum();
    assert!(
        expected > 0 && (expected as usize) < items.len() * 4,
        "mixed population required"
    );
    for s in &items {
        assert_eq!(
            check_bounds(s, &bounds, 1_000).is_ok(),
            violations(s, &bounds, 1_000).is_empty()
        );
    }
    let mut times = Vec::with_capacity(reps);
    for _ in 0..reps {
        let start = Instant::now();
        let mut total = 0u64;
        for s in &items {
            total += violations(s, &bounds, 1_000).len() as u64;
        }
        times.push(start.elapsed().as_nanos());
        assert_eq!(total, expected, "bounds evaluation must be deterministic");
    }
    let detail =
        format!("items={BOUNDS_ITEMS} violations_per_rep={expected} agreement=check==violations");
    (expected, times, detail)
}

fn cycle_bytes(i: usize) -> u64 {
    ((i * 31) % 97 + 1) as u64
}

fn run_ledger(reps: usize) -> (u64, Vec<u128>, String) {
    // Independent oracle: expected settled bytes recomputed arithmetically.
    let expected: u64 = (0..LEDGER_CYCLES).map(cycle_bytes).sum();
    let mut times = Vec::with_capacity(reps);
    for _ in 0..reps {
        let ledger = Ledger::new(1, u64::MAX);
        let id = ledger.register().expect("register");
        let start = Instant::now();
        for i in 0..LEDGER_CYCLES {
            let t = ledger.reserve(id, cycle_bytes(i)).expect("reserve");
            ledger.settle(id, &t).expect("settle");
            ledger.charge_work(id, &t, 1).expect("charge");
            ledger.refund(id, &t).expect("refund");
        }
        times.push(start.elapsed().as_nanos());
        let audit = ledger.audit();
        assert!(audit.is_conservative(), "ledger must conserve");
        assert_eq!(audit.settled(), expected, "settled bytes must match oracle");
        assert_eq!(
            audit.refunded(),
            expected,
            "refunded bytes must match oracle"
        );
        assert_eq!(
            ledger.consumer_work(id).expect("work"),
            LEDGER_CYCLES as u64
        );
        ledger.retire_consumer(id).expect("retire");
    }
    let detail =
        format!("cycles={LEDGER_CYCLES} settled={expected} refunded={expected} conservative=true");
    (expected, times, detail)
}

fn run_concurrent(reps: usize) -> (u64, Vec<u128>, String) {
    let per_consumer: u64 = (0..CONC_CYCLES).map(cycle_bytes).sum();
    let expected = per_consumer * CONC_CONSUMERS as u64;
    let mut times = Vec::with_capacity(reps);
    for _ in 0..reps {
        let ledger = Arc::new(Ledger::new(CONC_CONSUMERS as u32, u64::MAX));
        let sentinel = Arc::new(std::sync::Mutex::new(0x5EEDu64));
        let mut ids = Vec::new();
        for _ in 0..CONC_CONSUMERS {
            ids.push(ledger.register().expect("register"));
        }
        let start = Instant::now();
        let mut handles = Vec::new();
        for id in ids.clone() {
            let ledger = Arc::clone(&ledger);
            let sentinel = Arc::clone(&sentinel);
            handles.push(std::thread::spawn(move || {
                for i in 0..CONC_CYCLES {
                    let t = ledger.reserve(id, cycle_bytes(i)).expect("reserve");
                    ledger.settle(id, &t).expect("settle");
                    ledger.charge_work(id, &t, 1).expect("charge");
                    ledger.refund(id, &t).expect("refund");
                }
                assert_eq!(*sentinel.lock().expect("sentinel"), 0x5EEDu64);
            }));
        }
        for h in handles {
            h.join().expect("join");
        }
        times.push(start.elapsed().as_nanos());
        assert_eq!(
            *sentinel.lock().expect("sentinel"),
            0x5EEDu64,
            "sentinel preserved"
        );
        let audit = ledger.audit();
        assert!(audit.is_conservative(), "concurrent ledger must conserve");
        assert_eq!(
            audit.settled(),
            expected,
            "concurrent settled must match oracle"
        );
        assert_eq!(
            audit.refunded(),
            expected,
            "concurrent refunded must match oracle"
        );
    }
    let detail = format!(
        "consumers={CONC_CONSUMERS} cycles_each={CONC_CYCLES} settled={expected} sentinel=preserved"
    );
    (expected, times, detail)
}

fn summarize(mut times: Vec<u128>) -> (u128, u128, f64, u128) {
    times.sort_unstable();
    let min = times[0];
    let median = times[times.len() / 2];
    let max = *times.last().expect("nonempty");
    let mean = times.iter().sum::<u128>() as f64 / times.len() as f64;
    (min, median, mean, max)
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut reps = 21usize;
    let mut workload = "all".to_string();
    let mut out: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--reps" => {
                reps = args
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("contract_costs: --reps needs a positive integer");
                        std::process::exit(2);
                    });
                if reps == 0 {
                    eprintln!("contract_costs: --reps must be >= 1");
                    std::process::exit(2);
                }
                i += 2;
            }
            "--workload" => {
                workload = args.get(i + 1).cloned().unwrap_or_default();
                if !["all", "bounds", "ledger", "concurrent"].contains(&workload.as_str()) {
                    eprintln!("contract_costs: unknown workload {workload}");
                    std::process::exit(2);
                }
                i += 2;
            }
            "--out" => {
                out = args.get(i + 1).cloned();
                if out.is_none() {
                    eprintln!("contract_costs: --out needs a path");
                    std::process::exit(2);
                }
                i += 2;
            }
            // `cargo bench` appends `--bench` for harness=false targets too.
            "--bench" => {
                i += 1;
            }
            other => {
                eprintln!("contract_costs: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    let selected = ["bounds", "ledger", "concurrent"]
        .into_iter()
        .filter(|w| workload == "all" || workload == *w)
        .collect::<Vec<_>>();

    let mut sections = Vec::new();
    for name in selected {
        let (oracle, times, detail) = match name {
            "bounds" => run_bounds(reps),
            "ledger" => run_ledger(reps),
            _ => run_concurrent(reps),
        };
        let ops = match name {
            "bounds" => BOUNDS_ITEMS as u128,
            "ledger" => LEDGER_CYCLES as u128,
            _ => (CONC_CONSUMERS * CONC_CYCLES) as u128,
        };
        let (min, median, mean, max) = summarize(times);
        let ops_per_sec = ops as f64 / (mean / 1e9);
        println!(
            "{name}: oracle={oracle} reps={reps} ns(min={min} median={median} mean={mean:.0} max={max}) ops_per_sec={ops_per_sec:.0} [{detail}]"
        );
        sections.push(format!(
            "\"{name}\":{{\"oracle\":{oracle},\"reps\":{reps},\"ops_per_rep\":{ops},\
             \"timing_ns\":{{\"min\":{min},\"median\":{median},\"mean\":{mean:.0},\"max\":{max}}},\
             \"ops_per_sec\":{ops_per_sec:.0},\"deterministic\":\"{}\"}}",
            json_escape(&detail)
        ));
    }

    if let Some(path) = out {
        let parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0);
        let report = format!(
            "{{\"schema\":\"tt09-bench-v1\",\"workloads\":{{{}}},\
             \"environment\":{{\"target_arch\":\"{}\",\"target_os\":\"{}\",\"parallelism\":{}}}}}",
            sections.join(","),
            std::env::consts::ARCH,
            std::env::consts::OS,
            parallelism
        );
        if let Err(e) = std::fs::write(&path, &report) {
            eprintln!("contract_costs: cannot write {path}: {e}");
            std::process::exit(1);
        }
    }
}
