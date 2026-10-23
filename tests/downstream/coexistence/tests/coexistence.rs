// SPDX-License-Identifier: Apache-2.0
//! TT09 downstream coexistence: supported observers coexist with exact per-
//! consumer accounting, interference is detected (never silent), and a foreign
//! sentinel proves no cross-consumer cleanup. Uses only scopebase-testkit's
//! public API, as any downstream consumer would.
//!
//! NEW (no donor slice): see scopebase-testkit `src/resource.rs`.

use scopebase_testkit::resource::{
    check_bounds, BoundKind, DomainBounds, DomainId, Ledger, LedgerErrorKind, ResourceSample,
    ResourceSampleValues,
};

fn sentinel_path(tag: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("tt09-coex-{}-{}-{stamp}", std::process::id(), tag))
}

#[test]
fn two_consumers_coexist_with_exact_accounting() {
    let ledger = Ledger::new(2, 4096);
    let a = ledger.register().expect("a");
    let b = ledger.register().expect("b");
    for round in 0..50u64 {
        let ta = ledger.reserve(a, 10 + round).expect("reserve a");
        let tb = ledger.reserve(b, 5).expect("reserve b");
        ledger.settle(a, &ta).expect("settle a");
        ledger.settle(b, &tb).expect("settle b");
        ledger.charge_work(a, &ta, 1).expect("charge a");
        ledger.refund(a, &ta).expect("refund a");
        ledger.refund(b, &tb).expect("refund b");
    }
    assert_eq!(ledger.consumer_outstanding(a).expect("out a"), 0);
    assert_eq!(ledger.consumer_outstanding(b).expect("out b"), 0);
    assert_eq!(ledger.consumer_work(a).expect("work a"), 50);
    assert_eq!(ledger.consumer_work(b).expect("work b"), 0);
    let audit = ledger.audit();
    assert!(audit.is_conservative());
    assert_eq!(audit.settled(), audit.refunded());
    ledger.retire_consumer(a).expect("retire a");
    ledger.retire_consumer(b).expect("retire b");
}

#[test]
fn interference_detected_and_victim_whole() {
    let ledger = Ledger::new(2, 4096);
    let a = ledger.register().expect("a");
    let b = ledger.register().expect("b");
    let ta = ledger.reserve(a, 77).expect("reserve");
    ledger.settle(a, &ta).expect("settle");
    // Mutant control: B attempts every cross-consumer path; each must fail
    // at its intended typed assertion, never succeed silently.
    let err = ledger.refund(b, &ta).expect_err("foreign refund");
    assert_eq!(err.kind(), LedgerErrorKind::ForeignRetirement);
    let err = ledger.settle(b, &ta).expect_err("foreign settle");
    assert_eq!(err.kind(), LedgerErrorKind::ForeignTicket);
    let err = ledger.charge_work(b, &ta, 1).expect_err("foreign charge");
    assert_eq!(err.kind(), LedgerErrorKind::ForeignTicket);
    let err = ledger.quarantine(b, &ta).expect_err("foreign quarantine");
    assert_eq!(err.kind(), LedgerErrorKind::ForeignRetirement);
    // Victim whole: exact balances, clean retire.
    assert_eq!(ledger.consumer_outstanding(a).expect("out"), 77);
    ledger.refund(a, &ta).expect("victim refund");
    ledger.retire_consumer(a).expect("retire a");
    ledger.retire_consumer(b).expect("retire b");
    assert!(ledger.audit().is_conservative());
}

#[test]
fn foreign_sentinel_file_preserved_across_full_scenario() {
    let path = sentinel_path("sentinel");
    std::fs::write(&path, b"FOREIGN-SENTINEL").expect("write sentinel");
    let ledger = Ledger::new(4, 200);
    let ids: Vec<_> = (0..4)
        .map(|_| ledger.register().expect("register"))
        .collect();
    let mut tickets = Vec::new();
    for (i, id) in ids.iter().copied().enumerate() {
        let t = ledger.reserve(id, 20 + i as u64).expect("reserve");
        ledger.settle(id, &t).expect("settle");
        tickets.push((id, t));
    }
    // Park one ticket in quarantine, transfer one, refund the rest, retire.
    ledger
        .quarantine(ids[0], &tickets[0].1)
        .expect("quarantine 20");
    ledger
        .transfer(ids[2], ids[3], &tickets[2].1)
        .expect("transfer");
    ledger.refund(ids[1], &tickets[1].1).expect("refund");
    ledger
        .refund(ids[3], &tickets[2].1)
        .expect("refund transferred");
    ledger.refund(ids[3], &tickets[3].1).expect("refund own");
    ledger
        .retire_consumer(ids[0])
        .expect("retire with quarantined-only");
    ledger.retire_consumer(ids[1]).expect("retire");
    ledger.retire_consumer(ids[2]).expect("retire");
    ledger.retire_consumer(ids[3]).expect("retire");
    assert!(ledger.audit().is_conservative());
    let bytes = std::fs::read(&path).expect("read sentinel");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        bytes, b"FOREIGN-SENTINEL",
        "sentinel must be byte-identical"
    );
}

#[test]
fn per_domain_bounds_asserted_separately() {
    // Same sample shape, different per-domain caps: an overrun in one domain
    // is invisible to the others, and each failure is typed by dimension.
    let sample = ResourceSample::new(ResourceSampleValues {
        retained_bytes: 900,
        working_bytes: 200,
        attempts: 50,
        peak_bytes: 1500,
        ..Default::default()
    })
    .expect("sample");
    let linux = DomainBounds::new(DomainId::new("linux").expect("d"), 1100, 50, 1500, 100);
    let bpf = DomainBounds::new(DomainId::new("bpf").expect("d"), 1000, 100, 2000, 100);
    assert!(check_bounds(&sample, &linux, 10).is_ok());
    let err = check_bounds(&sample, &bpf, 10).expect_err("bpf bytes must overrun");
    assert_eq!(err.kind(), BoundKind::Bytes);
    assert_eq!(err.domain().as_str(), "bpf");
    // Time overrun in linux does not change the bpf byte verdict or vice versa.
    let err = check_bounds(&sample, &linux, 101).expect_err("linux time must overrun");
    assert_eq!(err.kind(), BoundKind::Time);
    assert!(check_bounds(&sample, &bpf, 10).is_err());
}

#[test]
fn repeated_failed_cleanup_preserves_state() {
    let ledger = Ledger::new(1, 64);
    let a = ledger.register().expect("a");
    let t = ledger.reserve(a, 40).expect("reserve");
    ledger.settle(a, &t).expect("settle");
    for _ in 0..3 {
        let err = ledger.retire_consumer(a).expect_err("retire must block");
        assert_eq!(err.kind(), LedgerErrorKind::OutstandingAtRetire);
    }
    assert_eq!(ledger.consumer_outstanding(a).expect("out"), 40);
    ledger
        .quarantine(a, &t)
        .expect("quarantine after failed retires");
    ledger.retire_consumer(a).expect("retire once parked");
    assert_eq!(ledger.quarantined_bytes(), 40);
    assert!(ledger.audit().is_conservative());
}

#[test]
fn standalone_receipt_binary_passes() {
    let exe = env!("CARGO_BIN_EXE_tt09-coexistence");
    let output = std::process::Command::new(exe)
        .output()
        .expect("run receipt binary");
    assert!(
        output.status.success(),
        "receipt binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 receipt");
    for key in [
        "\"conservative\":true",
        "\"settled\":800",
        "\"sentinel_preserved\":true",
        "\"interference_detected\":true",
    ] {
        assert!(stdout.contains(key), "receipt lacks {key}: {stdout}");
    }
}
