// SPDX-License-Identifier: Apache-2.0
//! TT09 resource, performance and concurrent-consumer qualification.
//!
//! NEW (no donor slice): no donor project carries a cross-domain resource/
//! performance qualification harness with per-domain byte/work/memory/time
//! bounds and N-consumer isolation accounting, so this suite freezes that
//! contract here. Per-domain baselines are measured on the executor machine
//! (see profiles/performance-v1.json); unmeasurable cells stay UNBUILT.

use scopebase_testkit::resource::{
    check_bounds, collect_sample, violations, BoundKind, ConsumerId, DomainBounds, DomainId,
    Ledger, LedgerErrorKind, PeakTracker, ResourceSample, ResourceSampleValues, SampleErrorKind,
};
use std::sync::Arc;

fn sample_with(v: ResourceSampleValues) -> ResourceSample {
    ResourceSample::new(v).expect("valid sample")
}

fn bounds_for(
    domain: &str,
    byte_cap: u64,
    work_cap: u64,
    mem_cap: u64,
    time_cap: u64,
) -> DomainBounds {
    DomainBounds::new(
        DomainId::new(domain).expect("valid domain"),
        byte_cap,
        work_cap,
        mem_cap,
        time_cap,
    )
}

// --- Domain identity ---

#[test]
fn domain_rejects_empty_and_overslong() {
    assert!(DomainId::new("").is_err());
    assert!(DomainId::new(&"d".repeat(65)).is_err());
    assert!(DomainId::new("linux").is_ok());
    assert!(DomainId::new("tt03-fixture").is_ok());
}

// --- Per-dimension N / N+1 ---

#[test]
fn bytes_n_passes_nplus1_fails_typed() {
    let b = bounds_for("linux", 100, u64::MAX, u64::MAX, u64::MAX);
    let ok = sample_with(ResourceSampleValues {
        retained_bytes: 60,
        working_bytes: 40,
        ..Default::default()
    });
    assert!(check_bounds(&ok, &b, 0).is_ok());
    let over = sample_with(ResourceSampleValues {
        retained_bytes: 61,
        working_bytes: 40,
        ..Default::default()
    });
    let err = check_bounds(&over, &b, 0).expect_err("101 bytes must overrun cap 100");
    assert_eq!(err.kind(), BoundKind::Bytes);
    assert_eq!(err.observed(), 101);
    assert_eq!(err.cap(), 100);
    assert_eq!(err.domain().as_str(), "linux");
}

#[test]
fn work_n_passes_nplus1_fails_typed() {
    let b = bounds_for("linux", u64::MAX, 7, u64::MAX, u64::MAX);
    let ok = sample_with(ResourceSampleValues {
        attempts: 7,
        ..Default::default()
    });
    assert!(check_bounds(&ok, &b, 0).is_ok());
    let over = sample_with(ResourceSampleValues {
        attempts: 8,
        ..Default::default()
    });
    let err = check_bounds(&over, &b, 0).expect_err("8 attempts must overrun cap 7");
    assert_eq!(err.kind(), BoundKind::Work);
    assert_eq!(err.observed(), 8);
}

#[test]
fn memory_peak_n_passes_nplus1_fails_typed() {
    let b = bounds_for("capture", u64::MAX, u64::MAX, 4096, u64::MAX);
    let ok = sample_with(ResourceSampleValues {
        peak_bytes: 4096,
        ..Default::default()
    });
    assert!(check_bounds(&ok, &b, 0).is_ok());
    let over = sample_with(ResourceSampleValues {
        peak_bytes: 4097,
        ..Default::default()
    });
    let err = check_bounds(&over, &b, 0).expect_err("peak 4097 must overrun cap 4096");
    assert_eq!(err.kind(), BoundKind::Memory);
}

#[test]
fn time_n_passes_nplus1_fails_typed_and_is_separate() {
    let b = bounds_for("bpf", u64::MAX, u64::MAX, u64::MAX, 50);
    let s = sample_with(ResourceSampleValues::default());
    assert!(check_bounds(&s, &b, 50).is_ok());
    let err = check_bounds(&s, &b, 51).expect_err("51ms must overrun cap 50ms");
    assert_eq!(err.kind(), BoundKind::Time);
    // A time overrun is not a byte/work/memory verdict: only Time is listed.
    let all = violations(&s, &b, 51);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].kind(), BoundKind::Time);
}

#[test]
fn violations_lists_each_dimension_separately() {
    let b = bounds_for("fixture", 10, 10, 10, 10);
    let s = sample_with(ResourceSampleValues {
        retained_bytes: 9,
        working_bytes: 9,
        attempts: 11,
        peak_bytes: 11,
        ..Default::default()
    });
    let all = violations(&s, &b, 11);
    let kinds: Vec<BoundKind> = all.iter().map(|v| v.kind()).collect();
    assert_eq!(
        kinds,
        vec![
            BoundKind::Bytes,
            BoundKind::Work,
            BoundKind::Memory,
            BoundKind::Time
        ]
    );
    assert!(check_bounds(&s, &b, 11).is_err());
}

#[test]
fn byte_sum_overflow_fails_typed_never_wraps() {
    // True sum (2^64) is unrepresentable: saturation reports MAX, and overflow
    // itself overruns even a MAX cap. A wrapping add would report 0 (silent pass).
    let b = bounds_for("linux", u64::MAX, u64::MAX, u64::MAX, u64::MAX);
    let s = sample_with(ResourceSampleValues {
        retained_bytes: u64::MAX,
        working_bytes: 1,
        ..Default::default()
    });
    let err = check_bounds(&s, &b, 0).expect_err("overflowing byte sum must overrun");
    assert_eq!(err.kind(), BoundKind::Bytes);
    assert_eq!(err.observed(), u64::MAX);
}

#[test]
fn sample_rejects_peak_below_current() {
    let bad = ResourceSampleValues {
        current_fds: 5,
        peak_fds: 4,
        ..Default::default()
    };
    let err = ResourceSample::new(bad).expect_err("peak < current must be rejected");
    assert_eq!(err.kind(), SampleErrorKind::InconsistentPeak);
    let bad = ResourceSampleValues {
        current_links: 2,
        peak_links: 1,
        ..Default::default()
    };
    assert_eq!(
        ResourceSample::new(bad).expect_err("link peak").kind(),
        SampleErrorKind::InconsistentPeak
    );
}

#[test]
fn sampler_error_never_synthesizes_sample() {
    let err = collect_sample(7, |_| {
        Err(scopebase_testkit::resource::SampleError::io(
            "proc unavailable",
        ))
    })
    .expect_err("sampler failure must propagate, never synthesize");
    assert_eq!(err.kind(), SampleErrorKind::Io);
    assert!(err.detail().contains("proc unavailable"));
}

// --- Peak tracker ---

#[test]
fn peak_realloc_records_transient_sum() {
    let mut p = PeakTracker::new();
    p.observe(100);
    p.realloc(100, 200).expect("fits");
    // Transient holds old + new during reallocation.
    assert_eq!(p.peak(), 300);
}

#[test]
fn peak_realloc_overflow_fails_typed() {
    let mut p = PeakTracker::new();
    let err = p
        .realloc(u64::MAX, 1)
        .expect_err("transient sum overflow must be typed");
    assert_eq!(
        err.kind(),
        scopebase_testkit::resource::PeakErrorKind::Overflow
    );
    assert_eq!(p.peak(), 0, "failed realloc must not move the peak");
}

#[test]
fn peak_clone_records_double_and_never_decreases() {
    let mut p = PeakTracker::new();
    p.clone_from(500).expect("fits");
    assert_eq!(p.peak(), 1000);
    p.observe(10);
    assert_eq!(p.peak(), 1000, "peak is monotonic");
    p.observe(2000);
    assert_eq!(p.peak(), 2000);
}

// --- Consumer ledger: caps and exact accounting ---

#[test]
fn consumer_cap_n_nplus1() {
    let ledger = Ledger::new(2, 1024);
    let _a = ledger.register().expect("consumer 1");
    let _b = ledger.register().expect("consumer 2");
    let err = ledger
        .register()
        .expect_err("third consumer must exceed cap 2");
    assert_eq!(err.kind(), LedgerErrorKind::ConsumerCap);
}

#[test]
fn reserve_settle_charge_refund_is_exact() {
    let ledger = Ledger::new(4, 4096);
    let a = ledger.register().expect("a");
    let t = ledger.reserve(a, 128).expect("reserve");
    ledger.settle(a, &t).expect("settle");
    ledger.charge_work(a, &t, 9).expect("charge once");
    assert_eq!(ledger.consumer_outstanding(a).expect("out"), 128);
    assert_eq!(ledger.consumer_work(a).expect("work"), 9);
    ledger.refund(a, &t).expect("refund");
    assert_eq!(ledger.consumer_outstanding(a).expect("out"), 0);
    let audit = ledger.audit();
    assert!(audit.is_conservative());
    assert_eq!(audit.settled(), 128);
    assert_eq!(audit.refunded(), 128);
}

#[test]
fn early_refund_detected_never_silent() {
    let ledger = Ledger::new(4, 4096);
    let a = ledger.register().expect("a");
    let t = ledger.reserve(a, 64).expect("reserve");
    let err = ledger
        .refund(a, &t)
        .expect_err("refund before settle must fail");
    assert_eq!(err.kind(), LedgerErrorKind::EarlyRefund);
    assert_eq!(ledger.consumer_outstanding(a).expect("out"), 0);
}

#[test]
fn double_refund_fails_typed() {
    let ledger = Ledger::new(4, 4096);
    let a = ledger.register().expect("a");
    let t = ledger.reserve(a, 64).expect("reserve");
    ledger.settle(a, &t).expect("settle");
    ledger.refund(a, &t).expect("first refund");
    let err = ledger.refund(a, &t).expect_err("second refund must fail");
    assert_eq!(err.kind(), LedgerErrorKind::DoubleRefund);
    let audit = ledger.audit();
    assert!(audit.is_conservative());
    assert_eq!(audit.refunded(), 64, "no double credit");
}

#[test]
fn double_charge_rejected_at_intended_assertion() {
    let ledger = Ledger::new(4, 4096);
    let a = ledger.register().expect("a");
    let t = ledger.reserve(a, 32).expect("reserve");
    ledger.settle(a, &t).expect("settle");
    ledger.charge_work(a, &t, 5).expect("first charge");
    let err = ledger
        .charge_work(a, &t, 5)
        .expect_err("second charge must fail");
    assert_eq!(err.kind(), LedgerErrorKind::DoubleCharge);
    assert_eq!(ledger.consumer_work(a).expect("work"), 5, "no double debit");
}

#[test]
fn foreign_ticket_refund_detected_and_owner_untouched() {
    let ledger = Ledger::new(4, 4096);
    let a = ledger.register().expect("a");
    let b = ledger.register().expect("b");
    let t = ledger.reserve(a, 48).expect("reserve");
    ledger.settle(a, &t).expect("settle");
    let err = ledger
        .refund(b, &t)
        .expect_err("cross-consumer refund must fail");
    assert_eq!(err.kind(), LedgerErrorKind::ForeignRetirement);
    assert_eq!(ledger.consumer_outstanding(a).expect("a out"), 48);
    assert_eq!(ledger.consumer_outstanding(b).expect("b out"), 0);
    assert!(ledger.audit().is_conservative());
}

#[test]
fn transfer_conserves_exact_bytes() {
    let ledger = Ledger::new(4, 4096);
    let a = ledger.register().expect("a");
    let b = ledger.register().expect("b");
    let t = ledger.reserve(a, 100).expect("reserve");
    ledger.settle(a, &t).expect("settle");
    ledger.transfer(a, b, &t).expect("transfer");
    assert_eq!(ledger.consumer_outstanding(a).expect("a"), 0);
    assert_eq!(ledger.consumer_outstanding(b).expect("b"), 100);
    let audit = ledger.audit();
    assert!(audit.is_conservative());
    assert_eq!(audit.transferred(), 100);
    // New owner retires; old owner cannot.
    let err = ledger
        .refund(a, &t)
        .expect_err("old owner refund must fail after transfer");
    assert_eq!(err.kind(), LedgerErrorKind::ForeignRetirement);
    ledger.refund(b, &t).expect("new owner refund");
    assert!(ledger.audit().is_conservative());
}

#[test]
fn retire_with_outstanding_fails_and_preserves_on_repeat() {
    let ledger = Ledger::new(4, 4096);
    let a = ledger.register().expect("a");
    let t = ledger.reserve(a, 25).expect("reserve");
    ledger.settle(a, &t).expect("settle");
    let first = ledger
        .retire_consumer(a)
        .expect_err("outstanding must block retire");
    assert_eq!(first.kind(), LedgerErrorKind::OutstandingAtRetire);
    let second = ledger
        .retire_consumer(a)
        .expect_err("repeat must fail identically");
    assert_eq!(second.kind(), LedgerErrorKind::OutstandingAtRetire);
    assert_eq!(
        ledger.consumer_outstanding(a).expect("out"),
        25,
        "no partial effect"
    );
    assert!(ledger.audit().is_conservative());
    ledger.refund(a, &t).expect("refund");
    ledger.retire_consumer(a).expect("retire once clear");
}

#[test]
fn quarantine_is_bounded_overflow_typed() {
    let ledger = Ledger::new(4, 100);
    let a = ledger.register().expect("a");
    let t1 = ledger.reserve(a, 60).expect("r1");
    ledger.settle(a, &t1).expect("s1");
    let t2 = ledger.reserve(a, 50).expect("r2");
    ledger.settle(a, &t2).expect("s2");
    ledger.quarantine(a, &t1).expect("quarantine 60 of cap 100");
    assert_eq!(ledger.quarantined_bytes(), 60);
    let err = ledger
        .quarantine(a, &t2)
        .expect_err("60+50 must overflow cap 100");
    assert_eq!(err.kind(), LedgerErrorKind::QuarantineOverflow);
    assert_eq!(
        ledger.quarantined_bytes(),
        60,
        "failed quarantine adds nothing"
    );
    assert!(ledger.audit().is_conservative());
}

#[test]
fn concurrent_consumers_isolated_and_exact() {
    const N: usize = 8;
    const OPS: usize = 200;
    let ledger = Arc::new(Ledger::new(N as u32, u64::MAX));
    // Foreign sentinel: never registered with the ledger; any cleanup touching
    // it is interference. The ledger has no path to it, asserted below.
    let sentinel = Arc::new(std::sync::Mutex::new(0x5EEDu64));
    let mut ids = Vec::new();
    for _ in 0..N {
        ids.push(ledger.register().expect("register"));
    }
    assert_ids_unique(&ids);
    let mut handles = Vec::new();
    for (i, id) in ids.iter().copied().enumerate() {
        let ledger = Arc::clone(&ledger);
        let sentinel = Arc::clone(&sentinel);
        handles.push(std::thread::spawn(move || {
            for op in 0..OPS {
                let bytes = ((i * OPS + op) % 97 + 1) as u64;
                let t = ledger.reserve(id, bytes).expect("reserve");
                ledger.settle(id, &t).expect("settle");
                ledger.charge_work(id, &t, 1).expect("charge");
                ledger.refund(id, &t).expect("refund");
            }
            assert_eq!(*sentinel.lock().expect("sentinel"), 0x5EEDu64);
        }));
    }
    for h in handles {
        h.join().expect("worker joins");
    }
    assert_eq!(
        *sentinel.lock().expect("sentinel"),
        0x5EEDu64,
        "sentinel preserved"
    );
    for id in &ids {
        assert_eq!(ledger.consumer_outstanding(*id).expect("out"), 0);
        assert_eq!(ledger.consumer_work(*id).expect("work"), OPS as u64);
    }
    let audit = ledger.audit();
    assert!(audit.is_conservative());
    assert_eq!(audit.refunded(), audit.settled());
    assert!(audit.settled() > 0);
}

fn assert_ids_unique(ids: &[ConsumerId]) {
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        assert!(seen.insert(id.get()), "duplicate consumer id");
    }
}

#[test]
fn s223_bytes_peak_is_an_independent_channel() {
    // S223: peak_bytes is NOT dominated by retained/working. It is an
    // independent high-water channel (PeakTracker-fed); the Bytes
    // dimension verdicts retained+working while Memory verdicts the
    // peak alone. A sampler that accounts bytes but observes no peak
    // (peak 0, working nonzero) is coherent, not broken — the
    // InconsistentPeak guard covers counter/peak pairs only. This pins
    // the exclusion so a future guard extension breaks loudly.
    let s = ResourceSample::new(ResourceSampleValues {
        retained_bytes: 10,
        working_bytes: 10,
        peak_bytes: 0,
        ..Default::default()
    })
    .expect("bytes without peak must be admitted");
    assert_eq!(s.peak_bytes(), 0);
    // And the reverse: a peak with no current byte holding is the
    // normal post-release high-water reading.
    ResourceSample::new(ResourceSampleValues {
        peak_bytes: 4096,
        ..Default::default()
    })
    .expect("peak without current bytes must be admitted");
}
