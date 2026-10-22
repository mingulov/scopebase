// SPDX-License-Identifier: Apache-2.0
#[path = "support/cp06_cases.rs"]
mod cases;
use cases::*;
use scopebase_capture::{loss::*, quantity::*, view::*, ContractError};
fn ledger(c: usize, r: usize, f: usize) -> ClaimLedger {
    ClaimLedger::new(
        epoch(),
        LedgerLimits {
            claims: c,
            reasons_per_claim: r,
            loss_facts: f,
        },
    )
    .unwrap()
}
fn plain(l: &ClaimLedger) -> Vec<ClaimAssessment> {
    l.snapshot(&[claim(1), claim(2)], &QueryOverlay::new(&[], 2).unwrap())
        .unwrap()
}
#[test]
fn partial_snapshot_does_not_poison_later_view() {
    let l = ledger(2, 2, 5);
    let a = l
        .snapshot(
            &[claim(1), claim(2)],
            &QueryOverlay::new(&[claim(1)], 2).unwrap(),
        )
        .unwrap();
    let b = plain(&l);
    assert_eq!(
        a[0].reasons(),
        [QualityReason::QueryPartial],
        "CP06:partial is local"
    );
    assert_eq!(a[1].reasons(), []);
    assert_eq!(b[0].reasons(), [], "CP06:plain stays pristine");
    assert_eq!(b[1].reasons(), []);
    assert_eq!(
        a[0].reasons(),
        [QualityReason::QueryPartial],
        "CP06:old view immutable"
    );
}
#[test]
fn consumed_loss_stays_in_epoch() {
    let mut l = ledger(2, 2, 5);
    l.record_loss(&exact(0, 1), &[claim(2)]).unwrap();
    for p in [true, false, true, false] {
        let ids = if p { vec![claim(2)] } else { vec![] };
        let v = l
            .snapshot(&[claim(2)], &QueryOverlay::new(&ids, 2).unwrap())
            .unwrap();
        let want = if p {
            vec![QualityReason::ConsumedLoss, QualityReason::QueryPartial]
        } else {
            vec![QualityReason::ConsumedLoss]
        };
        assert_eq!(v[0].reasons(), want, "CP06:consumed stays");
    }
    assert_eq!(plain(&l)[0].reasons(), []);
    let fresh = ClaimLedger::new(
        epoch().successor().unwrap(),
        LedgerLimits {
            claims: 2,
            reasons_per_claim: 2,
            loss_facts: 5,
        },
    )
    .unwrap();
    assert_eq!(plain(&fresh)[1].reasons(), []);
}
#[test]
fn independent_fact_claim_survives_relationship_loss() {
    for (affected, unaffected, value) in [(2, 1, 512), (1, 2, 4096)] {
        let mut l = ledger(2, 2, 5);
        l.record_loss(&fact(0, LossMagnitude::Unknown), &[claim(affected)])
            .unwrap();
        let v = plain(&l);
        assert_eq!(
            v[(unaffected - 1) as usize].reasons(),
            [],
            "CP06:independent claim survives"
        );
        assert_eq!(
            v[(affected - 1) as usize].reasons(),
            [QualityReason::ConsumedLoss]
        );
        assert_eq!(value, if unaffected == 1 { 512 } else { 4096 });
    }
}
#[test]
fn capacity_refusal_preserves_ledger() {
    let mut l = ledger(2, 2, 1);
    l.record_loss(&exact(0, 1), &[claim(1)]).unwrap();
    let before = plain(&l);
    error(
        l.record_loss(&exact(0, 1), &[claim(1), claim(2)]),
        ContractError::CapacityExceeded,
    );
    assert_eq!(plain(&l), before, "CP06:capacity preserves");
    error(
        l.record_loss(&exact(0, 1), &[claim(1), claim(1)]),
        ContractError::DuplicateKey,
    );
    assert_eq!(plain(&l), before);
}
#[test]
fn loss_magnitudes_and_signal_units_remain_distinct() {
    for (m, bad) in [
        (LossMagnitude::Exact(Count::new(0)), false),
        (LossMagnitude::Exact(Count::new(1)), true),
        (LossMagnitude::Exact(Count::new(u64::MAX)), true),
        (LossMagnitude::AtLeast(Count::new(0)), true),
        (LossMagnitude::AtLeast(Count::new(1)), true),
        (LossMagnitude::Unknown, true),
    ] {
        let mut l = ledger(2, 2, 1);
        l.record_loss(&fact(0, m), &[claim(1)]).unwrap();
        assert_eq!(
            plain(&l)[0].reasons(),
            if bad {
                &[QualityReason::ConsumedLoss][..]
            } else {
                &[]
            },
            "CP06:magnitude truth"
        );
    }
    for n in [0, 1, 255] {
        let mut l = ledger(2, 2, 1);
        l.record_signal(
            &CappedLossSignal::new(source(epoch()), channel(0), n, 255).unwrap(),
            &[claim(1)],
        )
        .unwrap();
        assert_eq!(
            plain(&l)[0].reasons(),
            if n != 0 {
                &[QualityReason::ConsumedLoss][..]
            } else {
                &[]
            },
            "CP06:signal truth"
        );
    }
}
#[test]
fn selected_overlay_and_output_bounds() {
    let mut l = ledger(2, 2, 2);
    let v = l
        .snapshot(
            &[claim(2), claim(1)],
            &QueryOverlay::new(&[claim(1), claim(3)], 2).unwrap(),
        )
        .unwrap();
    assert_eq!(
        v.iter().map(ClaimAssessment::claim).collect::<Vec<_>>(),
        [claim(2), claim(1)],
        "CP06:selected order"
    );
    assert_eq!(v[0].reasons(), []);
    assert_eq!(v[1].reasons(), [QualityReason::QueryPartial]);
    error(
        QueryOverlay::new(&[claim(3), claim(3)], 2),
        ContractError::DuplicateKey,
    );
    error(
        QueryOverlay::new(&[claim(1), claim(1), claim(0)], 2),
        ContractError::CapacityExceeded,
    );
    error(
        l.snapshot(&[claim(1), claim(1)], &QueryOverlay::new(&[], 0).unwrap()),
        ContractError::DuplicateKey,
    );
    l.record_loss(&exact(0, 0), &[claim(0), claim(2)]).unwrap();
    l.record_loss(&exact(0, 1), &[claim(0)]).unwrap();
}
#[test]
fn foreign_epoch_refuses_without_mutation() {
    let mut l = ledger(2, 2, 1);
    l.record_loss(&exact(0, 1), &[claim(1)]).unwrap();
    let before = plain(&l);
    for e in foreign_epochs() {
        let f = LossFact::<Events>::new(
            source(e),
            channel(0),
            LossKind::Transport,
            LossMagnitude::Unknown,
        )
        .unwrap();
        error(
            l.record_loss(&f, &[claim(1), claim(1), claim(2)]),
            ContractError::DomainMismatch,
        );
        let s = CappedLossSignal::new(f.source().clone(), channel(0), 1, 255).unwrap();
        error(
            l.record_signal(&s, &[claim(1), claim(1)]),
            ContractError::DomainMismatch,
        );
        assert_eq!(plain(&l), before, "CP06:foreign preserves");
    }
}
#[test]
fn ledger_checks_full_epoch_before_duplicates() {
    let mut l = ledger(2, 2, 5);
    l.record_loss(&exact(0, 1), &[claim(1)]).unwrap();
    let before = plain(&l);
    // Same ordinal, different capture: an ordinal-only comparison would admit
    // this fact and then fail on the deliberate duplicate keys instead.
    let f = LossFact::<Events>::new(
        source(foreign_epochs()[0].clone()),
        channel(0),
        LossKind::Transport,
        LossMagnitude::Unknown,
    )
    .unwrap();
    assert_eq!(
        l.record_loss(&f, &[claim(1), claim(1), claim(2)]).err(),
        Some(ContractError::DomainMismatch),
        "CP06:ledger full epoch first"
    );
    assert_eq!(plain(&l), before, "CP06:foreign preserves");
}
#[test]
fn snapshot_refuses_combined_reasons_as_whole() {
    let mut l = ledger(2, 1, 1);
    l.record_loss(&exact(0, 1), &[claim(1)]).unwrap();
    let before = plain(&l);
    assert_eq!(
        l.snapshot(&[claim(1)], &QueryOverlay::new(&[claim(1)], 1).unwrap())
            .err(),
        Some(ContractError::CapacityExceeded),
        "CP06:combined reasons refuse whole"
    );
    assert_eq!(plain(&l), before, "CP06:dual reason refuses");
}
#[test]
fn zero_budgets_and_snapshot_reason_capacity() {
    let mut l = ledger(0, 0, 1);
    l.record_loss(&exact(0, 1), &[]).unwrap();
    error(
        l.record_loss(&exact(0, 0), &[]),
        ContractError::CapacityExceeded,
    );
    assert_eq!(
        l.snapshot(&[], &QueryOverlay::new(&[], 0).unwrap())
            .unwrap(),
        []
    );
    let mut l = ledger(1, 0, 1);
    error(
        l.record_loss(&exact(0, 1), &[claim(1)]),
        ContractError::CapacityExceeded,
    );
    l.record_loss(&exact(0, 0), &[claim(1)]).unwrap();
    error(
        l.snapshot(&[claim(1)], &QueryOverlay::new(&[claim(1)], 1).unwrap()),
        ContractError::CapacityExceeded,
    );
    let mut l = ledger(2, 1, 1);
    l.record_loss(&exact(0, 1), &[claim(1)]).unwrap();
    error(
        l.snapshot(&[claim(1)], &QueryOverlay::new(&[claim(1)], 1).unwrap()),
        ContractError::CapacityExceeded,
    );
    assert_eq!(
        plain(&l)[0].reasons(),
        [QualityReason::ConsumedLoss],
        "CP06:dual reason refuses"
    );
    assert!(ClaimLedger::new(
        epoch(),
        LedgerLimits {
            claims: usize::MAX,
            reasons_per_claim: usize::MAX,
            loss_facts: usize::MAX
        }
    )
    .is_ok());
}
#[test]
fn occurrence_journal_all_9331_scripts() {
    let (mut count, mut actions) = (0, 0);
    scripts(6, 5, |s| {
        count += 1;
        actions += s.len();
        let mut l = ledger(2, 2, 5);
        let mut occurrences = Vec::new();
        for (i, &a) in s.iter().enumerate() {
            match a {
                0 => {
                    l.record_loss(&fact(0, LossMagnitude::Unknown), &[claim(1)])
                        .unwrap();
                    occurrences.push((i, 1));
                }
                1 => {
                    l.record_loss(&exact(0, 1), &[claim(2)]).unwrap();
                    occurrences.push((i, 2));
                }
                2 => l.record_loss(&exact(0, 0), &[claim(1)]).unwrap(),
                3..=5 => {
                    let ids = match a {
                        3 => vec![claim(1)],
                        4 => vec![],
                        5 => vec![claim(1), claim(2)],
                        _ => unreachable!(),
                    };
                    let v = l
                        .snapshot(&[claim(1), claim(2)], &QueryOverlay::new(&ids, 2).unwrap())
                        .unwrap();
                    for n in 1..=2 {
                        let mut expected = Vec::new();
                        if occurrences.iter().any(|&(at, c)| at < i && c == n) {
                            expected.push(QualityReason::ConsumedLoss);
                        }
                        if a == 5 || (a == 3 && n == 1) {
                            expected.push(QualityReason::QueryPartial);
                        }
                        assert_eq!(
                            v[n as usize - 1].reasons(),
                            expected,
                            "CP06:journal reasons script={s:?} at={i}"
                        );
                    }
                }
                _ => unreachable!(),
            }
        }
    });
    assert_eq!((count, actions), (9331, 44790));
}

#[test]
fn library_owned_state_has_ordinary_send_sync() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<ClaimLedger>();
    send_sync::<QueryOverlay>();
    send_sync::<ClaimAssessment>();
}
