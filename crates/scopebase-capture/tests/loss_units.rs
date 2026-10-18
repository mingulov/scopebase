// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::{
    domain::{BindingId, CaptureId, ChannelId, Epoch, Origin, ProducerId, SourceRef},
    loss::{fold_capped_signals, CappedLossSignal, LossFact, LossKind, LossMagnitude},
    quantity::{
        Attempts, Bytes, Count, DiagnosticSignals, Events, Nonexecutions, Objects, Records, Unit,
    },
    ContractError,
};
fn source() -> SourceRef {
    SourceRef::new(
        Epoch::new(
            CaptureId::new([1; 16]).unwrap(),
            ProducerId::new([2; 16]).unwrap(),
            0,
        ),
        BindingId::new([3; 32]).unwrap(),
        Origin::Synthetic,
    )
}
#[test]
fn kinds_units_and_magnitudes_are_retained() {
    fn check<U: Unit>() {
        for kind in [
            LossKind::Discovery,
            LossKind::Transport,
            LossKind::KernelNonexecution,
            LossKind::Attribution,
            LossKind::QueueOverflow,
            LossKind::MalformedInput,
            LossKind::DiagnosticTruncation,
        ] {
            for magnitude in [
                LossMagnitude::Exact(Count::<U>::new(0)),
                LossMagnitude::Exact(Count::new(7)),
                LossMagnitude::AtLeast(Count::new(0)),
                LossMagnitude::AtLeast(Count::new(7)),
                LossMagnitude::Unknown,
            ] {
                let fact =
                    LossFact::new(source(), ChannelId::new(9), kind, magnitude.clone()).unwrap();
                assert_eq!(fact.source(), &source());
                assert_eq!(fact.channel(), ChannelId::new(9));
                assert_eq!(fact.kind(), kind);
                assert_eq!(fact.magnitude(), &magnitude, "loss-magnitude-retention");
                assert_eq!(fact, fact.clone());
                assert_eq!(magnitude, magnitude.clone());
                let debug = format!("{fact:?}");
                assert!(debug.contains("<redacted>"));
                assert!(!debug.contains("[1, 1, 1,"));
                assert_ne!(
                    fact,
                    LossFact::new(source(), ChannelId::new(10), kind, magnitude.clone()).unwrap()
                );
                let changed = SourceRef::new(
                    source().epoch().clone(),
                    source().binding(),
                    Origin::Replayed,
                );
                assert_ne!(
                    fact,
                    LossFact::new(changed, ChannelId::new(9), kind, magnitude.clone()).unwrap()
                );
                if kind != LossKind::Discovery {
                    assert_ne!(
                        fact,
                        LossFact::new(source(), ChannelId::new(9), LossKind::Discovery, magnitude)
                            .unwrap()
                    );
                }
            }
        }
        assert_ne!(
            LossMagnitude::<U>::Unknown,
            LossMagnitude::Exact(Count::new(0))
        );
        assert_ne!(
            LossMagnitude::<U>::AtLeast(Count::new(7)),
            LossMagnitude::Exact(Count::new(7))
        );
    }
    check::<Events>();
    check::<Records>();
    check::<Bytes>();
    check::<Objects>();
    check::<Attempts>();
    check::<Nonexecutions>();
    check::<DiagnosticSignals>();
}
#[test]
fn capped_signal_is_not_exact_events() {
    let signal = CappedLossSignal::new(source(), ChannelId::new(9), 255, 255).unwrap();
    assert_eq!(signal.source(), &source());
    assert_eq!(signal.channel(), ChannelId::new(9));
    assert_eq!(signal.observed(), 255);
    assert_eq!(signal.cap(), 255);
    assert_eq!(signal, signal.clone());
    assert!(format!("{signal:?}").contains("<redacted>"));
    assert!(CappedLossSignal::new(source(), ChannelId::new(0), 0, 255).is_ok());
    assert_eq!(
        CappedLossSignal::new(source(), ChannelId::new(0), 0, 0),
        Err(ContractError::InvalidSample)
    );
    assert_eq!(
        CappedLossSignal::new(source(), ChannelId::new(0), 11, 10),
        Err(ContractError::InvalidSample)
    );
    let events = LossFact::new(
        source(),
        ChannelId::new(0),
        LossKind::Transport,
        LossMagnitude::<Events>::Exact(Count::new(3)),
    )
    .unwrap();
    assert_eq!(
        events.magnitude(),
        &LossMagnitude::Exact(Count::new(3)),
        "diagnostic-is-not-exact-events"
    );
    assert_eq!(signal.observed(), 255);
}
#[test]
fn k_lanes_cap_and_remain_independent() {
    // ADAPT K kcrypto_who.rs 862..954; CPU/program lanes and capped diagnostics.
    for (lanes, cap, want) in [
        (vec![], 255, 0),
        (vec![0, 0], 255, 0),
        (vec![1, 1], 255, 2),
        (vec![1, 1, 1, 1], 255, 4),
        (vec![1, 1, 1], 255, 3),
        (vec![254, 4, 0], 255, 255),
        (vec![255, 1], 255, 255),
        (vec![2, 2], 3, 3),
    ] {
        assert_eq!(
            fold_capped_signals(&lanes, cap),
            Ok(want),
            "diagnostic-lanes-{lanes:?}-{cap}"
        );
    }
    // Original K300-attempt and already-capped lane vectors. This supplies
    // pre-capped bytes only; it does not implement or qualify producer storage.
    let attempts = vec![(); 300];
    let lane = attempts.len().min(255) as u8;
    assert_eq!(fold_capped_signals(&[lane], 255), Ok(255));
    let after_more = (u32::from(lane) + 10).min(255) as u8;
    assert_eq!(fold_capped_signals(&[after_more], 255), Ok(255));
    let signal = CappedLossSignal::new(source(), ChannelId::new(1), 255, 255).unwrap();
    let records = LossFact::new(
        source(),
        ChannelId::new(2),
        LossKind::Transport,
        LossMagnitude::<Records>::Exact(Count::new(3)),
    )
    .unwrap();
    assert_eq!(signal.observed(), 255);
    assert_eq!(records.magnitude(), &LossMagnitude::Exact(Count::new(3)));
    // O loss/activity 1 versus999 stays separate; K transport saturation and queue40+2.
    let activity = Count::<Objects>::new(999);
    let event_loss = LossFact::new(
        source(),
        ChannelId::new(3),
        LossKind::Transport,
        LossMagnitude::<Events>::Exact(Count::new(1)),
    )
    .unwrap();
    assert_eq!(activity.get(), 999);
    assert_eq!(event_loss.magnitude(), &LossMagnitude::Exact(Count::new(1)));
    let capped = LossFact::new(
        source(),
        ChannelId::new(4),
        LossKind::Transport,
        LossMagnitude::<Events>::AtLeast(Count::new(u64::MAX)),
    )
    .unwrap();
    let queue = Count::<Records>::new(40)
        .checked_add(Count::new(2))
        .unwrap();
    assert_eq!(
        capped.magnitude(),
        &LossMagnitude::AtLeast(Count::new(u64::MAX))
    );
    assert_eq!(queue.get(), 42);
}
#[test]
fn invalid_late_lane_is_not_hidden() {
    assert_eq!(
        fold_capped_signals(&[], 0),
        Err(ContractError::InvalidSample)
    );
    assert_eq!(
        fold_capped_signals(&[11], 10),
        Err(ContractError::InvalidSample)
    );
    assert_eq!(
        fold_capped_signals(&[10, 11], 10),
        Err(ContractError::InvalidSample),
        "late-lane-must-be-validated"
    );
    assert_eq!(fold_capped_signals(&[10, 10], 10), Ok(10));
}
#[test]
fn diagnostic_exhaustive_pairs() {
    let mut cases = 0u64;
    for cap in 1u32..=255 {
        for a in 0..=cap {
            for b in 0..=cap {
                // Independent wide sum, clamped once; production accumulates each lane.
                let want = (a + b).min(cap) as u8;
                assert_eq!(
                    fold_capped_signals(&[a as u8, b as u8], cap as u8),
                    Ok(want),
                    "diagnostic-pair-{cap}-{a}-{b}"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 5_625_215);
}
