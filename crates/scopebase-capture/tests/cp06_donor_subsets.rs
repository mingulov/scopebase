// SPDX-License-Identifier: Apache-2.0
//! Narrow adapted regression vectors, not executions of donor reducers.
//! K d153f3a / M 8307a17 / O 4bcb24c; complete source receipts are root-owned.
#[path = "support/cp06_cases.rs"]
mod cases;
use cases::*;
use scopebase_capture::{
    correction::*, feeds::FeedRegistry, generation::ObjectKey, loss::*, view::*, ContractError,
};
fn ledger() -> ClaimLedger {
    ClaimLedger::new(
        epoch(),
        LedgerLimits {
            claims: 2,
            reasons_per_claim: 2,
            loss_facts: 8,
        },
    )
    .unwrap()
}
fn read(l: &ClaimLedger, partial: bool) -> Vec<ClaimAssessment> {
    let ids = if partial {
        vec![claim(1), claim(2)]
    } else {
        vec![]
    };
    l.snapshot(&[claim(1), claim(2)], &QueryOverlay::new(&ids, 2).unwrap())
        .unwrap()
}
// Supplied scalar facts stay in this caller; the ledger never computes DMA metrics.
#[derive(Debug, PartialEq, Eq)]
struct Metrics {
    copy: u64,
    occupancy: u64,
    shared: u64,
    pool: u64,
}
fn metrics() -> Metrics {
    Metrics {
        copy: 512,
        occupancy: 4096,
        shared: 8192,
        pool: 3,
    }
}
#[test]
fn m_s01_copy_loss_preserves_valued_occupancy() {
    let mut l = ledger();
    let values = metrics();
    l.record_loss(&fact(0, LossMagnitude::Unknown), &[claim(1)])
        .unwrap();
    let v = read(&l, false);
    assert_eq!(v[0].reasons(), [QualityReason::ConsumedLoss]);
    assert_eq!(v[1].reasons(), [], "CP06:M-S01 occupancy quality");
    assert_eq!((values.copy, values.occupancy), (512, 4096));
}
#[test]
fn m_s02_mapping_loss_preserves_copy512() {
    let mut l = ledger();
    let values = metrics();
    l.record_loss(&fact(0, LossMagnitude::Unknown), &[claim(2)])
        .unwrap();
    let v = read(&l, false);
    assert_eq!(v[0].reasons(), [], "CP06:M-S02 copy quality");
    assert_eq!(values.copy, 512);
    assert_eq!(v[1].reasons(), [QualityReason::ConsumedLoss]);
}
#[test]
fn m_s03_snapshot_finish_equivalence() {
    let l = ledger();
    assert_eq!(
        read(&l, false),
        read(&l, false),
        "CP06:M-S03 plain equivalent"
    );
}
#[test]
fn m_s04_partial_preserves_original4096_8192_pool3() {
    let l = ledger();
    let values = metrics();
    assert_eq!(read(&l, true)[0].reasons(), [QualityReason::QueryPartial]);
    assert_eq!(
        read(&l, false),
        read(&ledger(), false),
        "CP06:M-S04 later fresh truth"
    );
    assert_eq!(
        values,
        Metrics {
            copy: 512,
            occupancy: 4096,
            shared: 8192,
            pool: 3
        }
    );
}
#[test]
fn m_s05_repeated_partial_views_leave_facts() {
    let mut l = ledger();
    let mut values = metrics();
    values.pool = 2;
    for p in [true, false, true] {
        let _ = read(&l, p);
    }
    l.record_loss(&exact(0, 0), &[claim(1)]).unwrap();
    values.pool += 1;
    let _ = read(&l, true);
    assert_eq!(read(&l, false), read(&ledger(), false));
    assert_eq!(
        (values.occupancy, values.shared, values.pool),
        (4096, 8192, 3),
        "CP06:M-S05 caller facts survive"
    );
}
#[test]
fn m_s06_consumed_gap_stays_degraded() {
    let mut l = ledger();
    l.record_loss(&fact(0, LossMagnitude::Unknown), &[claim(1), claim(2)])
        .unwrap();
    let _ = read(&l, true);
    let _ = read(&l, false);
    let values = Metrics {
        pool: 1,
        ..metrics()
    };
    assert_eq!(read(&l, false)[0].reasons(), [QualityReason::ConsumedLoss]);
    assert_eq!(values.pool, 1);
}
#[test]
fn m_s07_gap_between_views_stays_degraded() {
    let mut l = ledger();
    let _ = read(&l, true);
    l.record_loss(&fact(0, LossMagnitude::Unknown), &[claim(2)])
        .unwrap();
    let _ = read(&l, false);
    assert_eq!(
        read(&l, false)[1].reasons(),
        [QualityReason::ConsumedLoss],
        "CP06:M-S07 gap persists"
    );
}
#[test]
fn m_s08_post_gap_caller_pool_run_one_to_three() {
    let mut l = ledger();
    l.record_loss(&fact(0, LossMagnitude::Unknown), &[claim(2)])
        .unwrap();
    let mut samples = 1;
    let _ = read(&l, false);
    samples += 2;
    let _ = read(&l, true);
    let _ = read(&l, false);
    assert_eq!(
        samples, 3,
        "CP06:M-S08 query does not replay loss into caller"
    );
}
#[test]
fn k_s01_shared11_5_has_no_backend_contribution() {
    let mut r = FeedRegistry::new(epoch(), &[channel(0), channel(1)], 2).unwrap();
    let (mut accepted, backend, skipped) = ((0, 0), (0, 0), 0);
    r.feed(&exact(0, 11)).unwrap();
    accepted.0 = 11;
    r.feed(&exact(1, 5)).unwrap();
    accepted.1 = 5;
    assert_eq!(r.finish(), Ok(()));
    assert_eq!(
        (accepted, backend, skipped),
        ((11, 5), (0, 0), 0),
        "CP06:K-S01 disjoint numeric facts"
    );
}
#[test]
fn k_s02_shared_first_feed_accrues_once() {
    let mut r = FeedRegistry::new(epoch(), &[channel(0)], 1).unwrap();
    let mut accepted = None;
    if r.feed(&exact(0, 11)).is_ok() {
        accepted = Some((11, 5));
    }
    assert_eq!(accepted, Some((11, 5)));
    assert_eq!(r.finish(), Ok(()));
}
#[test]
fn k_s03_duplicate100_100_cannot_replace11_5() {
    let mut r = FeedRegistry::new(epoch(), &[channel(0)], 1).unwrap();
    r.feed(&exact(0, 11)).unwrap();
    let mut accepted = (11, 5);
    let duplicate = r.feed(&exact(0, 100));
    if duplicate.is_ok() {
        accepted = (100, 100);
    }
    assert_eq!(duplicate, Err(ContractError::DuplicateFeed));
    assert_eq!(accepted, (11, 5), "CP06:K-S03 first numbers stand");
}
#[test]
fn k_s04_missing_strict_feed_refuses() {
    let r = FeedRegistry::new(epoch(), &[channel(0)], 1).unwrap();
    assert_eq!(
        r.finish(),
        Err(ContractError::MissingFeed),
        "CP06:K-S04 no lenient total"
    );
}
#[derive(Clone, PartialEq, Eq)]
struct Key {
    namespace: u32,
    device: u32,
    token: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    outcome: &'static str,
    by_seq: Option<u64>,
    op: u32,
}
struct Entry {
    key: ObjectKey<Key>,
    value: Option<Versioned<Verdict>>,
}
fn key(token: u64) -> ObjectKey<Key> {
    ObjectKey::new(
        epoch(),
        Key {
            namespace: 1,
            device: 2,
            token,
        },
        0,
    )
}
fn complete() -> Verdict {
    Verdict {
        outcome: "Complete",
        by_seq: None,
        op: 7,
    }
}
fn replacement() -> Verdict {
    Verdict {
        outcome: "Tainted",
        by_seq: Some(1),
        op: 0,
    }
}
fn route(entries: &mut [Entry], target: Option<&ObjectKey<Key>>) -> Result<(), &'static str> {
    let target = target.ok_or("unknown")?;
    if target.epoch() != &epoch() {
        return Err("foreign");
    }
    let mut indices = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| e.key.matches(target).then_some(i));
    let index = indices.next().ok_or("missing")?;
    if indices.next().is_some() {
        return Err("ambiguous");
    }
    let holder = entries[index].value.take().ok_or("missing holder")?;
    match holder.apply(Correction::new(epoch(), Revision::new(0), replacement()).unwrap()) {
        Ok(v) => {
            entries[index].value = Some(v);
            Ok(())
        }
        Err((v, _)) => {
            entries[index].value = Some(v);
            Err("incomplete")
        }
    }
}
fn entry(n: u64) -> Entry {
    Entry {
        key: key(n),
        value: Some(Versioned::new(epoch(), complete())),
    }
}
#[test]
fn o_s01_consumed_complete_replaced_wholly() {
    let mut report = vec![entry(0)];
    assert_eq!(*report[0].value.as_ref().unwrap().value(), complete());
    route(&mut report, Some(&key(0))).unwrap();
    assert_eq!(
        *report[0].value.as_ref().unwrap().value(),
        Verdict {
            outcome: "Tainted",
            by_seq: Some(1),
            op: 0
        },
        "CP06:O-S01 consumed replacement outcome+op"
    );
}
#[test]
fn o_s02_complete_key_routes_replacement() {
    let mut report = vec![entry(0), entry(1)];
    for field in 0..4 {
        let bad = ObjectKey::new(
            epoch(),
            Key {
                namespace: if field == 0 { 9 } else { 1 },
                device: if field == 1 { 9 } else { 2 },
                token: if field == 2 { 9 } else { 0 },
            },
            if field == 3 { 1 } else { 0 },
        );
        assert_eq!(route(&mut report, Some(&bad)), Err("missing"));
    }
    assert_eq!(route(&mut report, None), Err("unknown"));
    let foreign = ObjectKey::new(
        foreign_epochs()[0].clone(),
        Key {
            namespace: 1,
            device: 2,
            token: 0,
        },
        0,
    );
    assert_eq!(route(&mut report, Some(&foreign)), Err("foreign"));
    route(&mut report, Some(&key(0))).unwrap();
    assert_eq!(
        *report[0].value.as_ref().unwrap().value(),
        Verdict {
            outcome: "Tainted",
            by_seq: Some(1),
            op: 0
        }
    );
    assert_eq!(
        *report[1].value.as_ref().unwrap().value(),
        complete(),
        "CP06:O-S02 unrelated unchanged"
    );
    let mut duplicate = vec![entry(0), entry(0)];
    assert_eq!(route(&mut duplicate, Some(&key(0))), Err("ambiguous"));
}
#[test]
fn o_s03_tail_updates_both_original_holders() {
    let mut report = vec![entry(0), entry(1)];
    let mut export = vec![entry(0), entry(1)];
    report.push(entry(2));
    export.push(entry(2));
    route(&mut report, Some(&key(0))).unwrap();
    route(&mut export, Some(&key(0))).unwrap();
    for holder in [&report, &export] {
        assert_eq!(
            *holder[0].value.as_ref().unwrap().value(),
            Verdict {
                outcome: "Tainted",
                by_seq: Some(1),
                op: 0
            },
            "CP06:both original holders corrected"
        );
        assert_eq!(
            holder[0].value.as_ref().unwrap().revision(),
            Revision::new(1)
        );
        assert_eq!(*holder[1].value.as_ref().unwrap().value(), complete());
        assert_eq!(*holder[2].value.as_ref().unwrap().value(), complete());
    }
    assert_eq!(route(&mut report, Some(&key(0))), Err("incomplete"));
    assert_eq!(
        *report[0].value.as_ref().unwrap().value(),
        Verdict {
            outcome: "Tainted",
            by_seq: Some(1),
            op: 0
        }
    );
}
#[test]
fn stable_inventory() {
    assert_eq!(CASES.len(), 25);
    assert_eq!(ORIGINAL_SUBSETS.len(), 15);
}

#[test]
fn one_holder_refusal_retains_pending_complete_key() {
    let mut report = vec![entry(0)];
    route(&mut report, Some(&key(0))).unwrap();
    let mut export = vec![entry(0)];
    let pending = key(0);
    let a = route(&mut report, Some(&pending));
    let b = route(&mut export, Some(&pending));
    assert_eq!(
        (a, b),
        (Err("incomplete"), Ok(())),
        "CP06:one-holder failure is explicit"
    );
    assert!(pending.matches(&key(0)));
    for holder in [&report, &export] {
        assert_eq!(
            *holder[0].value.as_ref().unwrap().value(),
            Verdict {
                outcome: "Tainted",
                by_seq: Some(1),
                op: 0
            }
        );
    }
}
