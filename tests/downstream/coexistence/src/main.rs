// SPDX-License-Identifier: Apache-2.0
//! TT09 standalone consumer pair: two independent consumers share one ledger
//! while a foreign sentinel file proves no cross-consumer cleanup touches
//! outside custody. Prints a JSON receipt; exit 0 iff every deterministic
//! assertion held, exit 1 naming the violation otherwise.
//!
//! NEW (no donor slice): see scopebase-testkit `src/resource.rs`.

use scopebase_testkit::resource::{Ledger, LedgerErrorKind};
use std::io::Write;

fn fail(receipt: &mut String, violation: &str) -> ! {
    receipt.push_str(&format!("\"violation\":\"{violation}\""));
    println!("{receipt}}}");
    std::process::exit(1);
}

fn main() {
    let mut receipt = String::from("{\"schema\":\"tt09-coexistence-v1\",");
    // Foreign sentinel: a real file outside ledger custody. Any cleanup path
    // touching it is interference; the ledger has no path to it.
    let sentinel_path = std::env::temp_dir().join(format!("tt09-sentinel-{}", std::process::id()));
    if std::fs::write(&sentinel_path, b"SENTINEL-v1").is_err() {
        fail(&mut receipt, "sentinel_unwritable");
    }
    let ledger = Ledger::new(2, 10_000);
    let a = ledger
        .register()
        .unwrap_or_else(|_| fail(&mut receipt, "register_a"));
    let b = ledger
        .register()
        .unwrap_or_else(|_| fail(&mut receipt, "register_b"));

    // Consumer A: full lifecycle with a work charge.
    let ta = ledger
        .reserve(a, 500)
        .unwrap_or_else(|_| fail(&mut receipt, "reserve_a"));
    ledger
        .settle(a, &ta)
        .unwrap_or_else(|_| fail(&mut receipt, "settle_a"));
    ledger
        .charge_work(a, &ta, 3)
        .unwrap_or_else(|_| fail(&mut receipt, "charge_a"));

    // Consumer B: reserve/settle, then attempt interference on A's ticket.
    let tb = ledger
        .reserve(b, 300)
        .unwrap_or_else(|_| fail(&mut receipt, "reserve_b"));
    ledger
        .settle(b, &tb)
        .unwrap_or_else(|_| fail(&mut receipt, "settle_b"));
    match ledger.refund(b, &ta) {
        Err(e) if e.kind() == LedgerErrorKind::ForeignRetirement => {}
        _ => fail(&mut receipt, "interference_not_detected"),
    }

    // Reservation transfer A -> B conserves exactly.
    ledger
        .transfer(a, b, &ta)
        .unwrap_or_else(|_| fail(&mut receipt, "transfer"));
    if ledger.consumer_outstanding(a).unwrap_or(u64::MAX) != 0 {
        fail(&mut receipt, "transfer_source_not_zero");
    }

    // Failed retire preserves: B still holds two tickets.
    match ledger.retire_consumer(b) {
        Err(e) if e.kind() == LedgerErrorKind::OutstandingAtRetire => {}
        _ => fail(&mut receipt, "retire_should_block"),
    }
    ledger
        .refund(b, &ta)
        .unwrap_or_else(|_| fail(&mut receipt, "refund_transferred"));
    ledger
        .refund(b, &tb)
        .unwrap_or_else(|_| fail(&mut receipt, "refund_b"));
    ledger
        .retire_consumer(a)
        .unwrap_or_else(|_| fail(&mut receipt, "retire_a"));
    ledger
        .retire_consumer(b)
        .unwrap_or_else(|_| fail(&mut receipt, "retire_b"));

    let audit = ledger.audit();
    if !audit.is_conservative() || audit.settled() != 800 || audit.refunded() != 800 {
        fail(&mut receipt, "not_conservative");
    }
    let sentinel = std::fs::read(&sentinel_path).unwrap_or_default();
    let _ = std::fs::remove_file(&sentinel_path);
    if sentinel != b"SENTINEL-v1" {
        fail(&mut receipt, "sentinel_modified");
    }
    receipt.push_str("\"conservative\":true,\"settled\":800,\"refunded\":800,");
    receipt.push_str("\"transferred\":500,\"sentinel_preserved\":true,");
    receipt.push_str("\"interference_detected\":true}");
    println!("{receipt}");
    let _ = std::io::stdout().flush();
}
