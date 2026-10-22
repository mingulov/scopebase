// SPDX-License-Identifier: Apache-2.0
//! `catalog_model` campaign target: runs the seeded catalog-load suite and
//! reports through the TT06 target protocol.
//!
//! Usage: catalog_model --seed N --cases N --result PATH [--mutant]
//!
//! The result file receives a partial `{"setup_ok": true, ...}` record
//! immediately after valid setup, then the final record. Exit 0 covers both
//! passing and assertion-failing runs (the assertion field carries the
//! verdict); nonzero exits mean crash or IO failure only.

use scopebase_catalog_model::{check_setup, run_suite, ModelConfig};
use std::io::Write;

fn usage() -> ! {
    eprintln!("usage: catalog_model --seed N --cases N --result PATH [--mutant]");
    std::process::exit(2);
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn write_result(path: &str, setup_ok: bool, assertion: &str, work_items: usize, detail: &str) {
    let body = format!(
        "{{\"setup_ok\": {setup_ok}, \"assertion\": \"{assertion}\", \"work_items\": {work_items}, \"detail\": \"{}\"}}\n",
        json_escape(&detail.chars().take(1024).collect::<String>()),
        setup_ok = if setup_ok { "true" } else { "false" },
    );
    let mut file = std::fs::File::create(path).expect("result path must be writable");
    file.write_all(body.as_bytes()).expect("result write must succeed");
    file.sync_all().expect("result sync must succeed");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut seed: Option<u64> = None;
    let mut cases: Option<usize> = None;
    let mut result: Option<String> = None;
    let mut mutant = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                seed = args[i].parse().ok();
            }
            "--cases" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                cases = args[i].parse().ok();
            }
            "--result" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                result = Some(args[i].clone());
            }
            "--mutant" => mutant = true,
            _ => usage(),
        }
        i += 1;
    }
    let (seed, cases, result) = match (seed, cases, result) {
        (Some(seed), Some(cases), Some(result)) if cases > 0 => (seed, cases, result),
        _ => usage(),
    };

    let setup_detail = match check_setup() {
        Ok(detail) => detail,
        Err(detail) => {
            write_result(&result, false, "error", 0, &detail);
            return;
        }
    };
    // Partial record proves valid setup before the bounded run starts, so a
    // later timeout still reports TIME_BOUNDED with setup_ok instead of an
    // undifferentiated crash.
    write_result(&result, true, "error", 0, &format!("{setup_detail}; running"));
    let config = if mutant {
        ModelConfig::mutant(seed, cases)
    } else {
        ModelConfig::new(seed, cases)
    };
    let outcome = run_suite(&config);
    let (assertion, detail) = if outcome.passed() {
        ("pass", format!("seed={seed} cases={} pass; {setup_detail}", outcome.cases_run))
    } else {
        let first = outcome
            .failures
            .first()
            .map(|f| format!("case {} [{}]: {}", f.index, f.mutation, f.detail))
            .unwrap_or_else(|| "no case detail".to_string());
        ("fail", format!("seed={seed} cases={} failures={} mutant={mutant}; {first}", outcome.cases_run, outcome.failures.len()))
    };
    write_result(&result, outcome.setup_ok, assertion, outcome.cases_run, &detail);
}
