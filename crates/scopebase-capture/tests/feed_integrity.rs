// SPDX-License-Identifier: Apache-2.0
#[path = "support/cp06_cases.rs"]
mod cases;
use cases::*;
use scopebase_capture::{feeds::FeedRegistry, loss::*, quantity::*, ContractError};
#[test]
fn zero_feed_is_not_missing() {
    let mut r = FeedRegistry::new(epoch(), &[channel(0), channel(1)], 2).unwrap();
    assert_eq!(
        r.finish(),
        Err(ContractError::MissingFeed),
        "CP06:missing is not zero"
    );
    r.feed(&exact(0, 0)).unwrap();
    assert_eq!(r.finish(), Err(ContractError::MissingFeed));
    r.feed(&exact(1, 0)).unwrap();
    assert_eq!(r.finish(), Ok(()));
}
#[test]
fn second_feed_refuses() {
    let mut r = FeedRegistry::new(epoch(), &[channel(0), channel(1)], 2).unwrap();
    r.feed(&exact(0, 11)).unwrap();
    assert_eq!(
        r.feed(&exact(0, 100)),
        Err(ContractError::DuplicateFeed),
        "CP06:first feed stands"
    );
    let f = LossFact::<Bytes>::new(
        source(epoch()),
        channel(0),
        LossKind::Discovery,
        LossMagnitude::Unknown,
    )
    .unwrap();
    assert_eq!(r.feed(&f), Err(ContractError::DuplicateFeed));
    assert_eq!(r.finish(), Err(ContractError::MissingFeed));
    r.feed(&exact(1, 5)).unwrap();
    assert_eq!(r.finish(), Ok(()));
}
#[test]
fn required_declarations_are_bounded() {
    error(
        FeedRegistry::new(epoch(), &[channel(0), channel(1)], 1),
        ContractError::CapacityExceeded,
    );
    error(
        FeedRegistry::new(epoch(), &[channel(0), channel(0)], 2),
        ContractError::DuplicateKey,
    );
    assert_eq!(FeedRegistry::new(epoch(), &[], 0).unwrap().finish(), Ok(()));
    let mut r = FeedRegistry::new(epoch(), &[channel(0)], 1).unwrap();
    assert_eq!(
        r.feed(&exact(2, 0)),
        Err(ContractError::InvalidId),
        "CP06:undeclared refuses"
    );
}
#[test]
fn feed_error_order_and_atomicity() {
    let mut r = FeedRegistry::new(epoch(), &[channel(0), channel(1)], 2).unwrap();
    r.feed(&exact(0, 0)).unwrap();
    for e in foreign_epochs() {
        for n in [0, 1, 2] {
            let f = LossFact::<Events>::new(
                source(e.clone()),
                channel(n),
                LossKind::Transport,
                LossMagnitude::Unknown,
            )
            .unwrap();
            assert_eq!(
                r.feed(&f),
                Err(ContractError::DomainMismatch),
                "CP06:feed full epoch first"
            );
        }
    }
    assert_eq!(r.finish(), Err(ContractError::MissingFeed));
    r.feed(&exact(1, 0)).unwrap();
    assert_eq!(r.finish(), Ok(()));
}
#[test]
fn finish_is_observational() {
    let mut r = FeedRegistry::new(epoch(), &[channel(0)], 1).unwrap();
    assert_eq!(r.finish(), Err(ContractError::MissingFeed));
    assert_eq!(
        r.feed(&fact(0, LossMagnitude::Unknown)),
        Ok(()),
        "CP06:finish leaves valid feed open"
    );
    assert_eq!(r.finish(), Ok(()), "CP06:finish recovers");
    assert_eq!(r.finish(), Ok(()));
    assert_eq!(r.feed(&exact(0, 0)), Err(ContractError::DuplicateFeed));
}
#[test]
fn inventory_all_1364_scripts() {
    let (mut count, mut actions) = (0, 0);
    for required in [vec![], vec![0], vec![1], vec![0, 1]] {
        scripts(4, 4, |s| {
            count += 1;
            actions += s.len();
            let mut r = FeedRegistry::new(
                epoch(),
                &required.iter().map(|&n| channel(n)).collect::<Vec<_>>(),
                2,
            )
            .unwrap();
            let mut accepted = Vec::new();
            for (i, &a) in s.iter().enumerate() {
                if a == 3 {
                    let expected = if required
                        .iter()
                        .all(|n| accepted.iter().any(|&(_, c)| c == *n))
                    {
                        Ok(())
                    } else {
                        Err(ContractError::MissingFeed)
                    };
                    assert_eq!(r.finish(), expected, "CP06:inventory finish {s:?} {i}");
                } else {
                    let n = if a == 2 { 1 } else { 0 };
                    let expected = if !required.contains(&n) {
                        Err(ContractError::InvalidId)
                    } else if accepted.iter().any(|&(_, c)| c == n) {
                        Err(ContractError::DuplicateFeed)
                    } else {
                        accepted.push((i, n));
                        Ok(())
                    };
                    let f = match a {
                        0 => exact(0, 0),
                        1 => exact(0, 11),
                        2 => fact(1, LossMagnitude::Unknown),
                        _ => unreachable!(),
                    };
                    assert_eq!(r.feed(&f), expected, "CP06:inventory feed {s:?} {i}");
                }
            }
        });
    }
    assert_eq!((count, actions), (1364, 5008));
}

#[test]
fn feed_state_has_ordinary_send_sync() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<FeedRegistry>();
}

#[test]
fn same_epoch_schema_diversity_is_caller_policy() {
    use scopebase_capture::domain::{BindingId, Origin, SourceRef};
    let mut registry = FeedRegistry::new(epoch(), &[channel(0), channel(1)], 2).unwrap();
    registry.feed(&exact(0, 11)).unwrap();
    let different = SourceRef::new(epoch(), BindingId::new([99; 32]).unwrap(), Origin::Replayed);
    let duplicate = LossFact::<Bytes>::new(
        different.clone(),
        channel(0),
        LossKind::Discovery,
        LossMagnitude::Unknown,
    )
    .unwrap();
    assert_eq!(registry.feed(&duplicate), Err(ContractError::DuplicateFeed));
    let accepted = LossFact::<Objects>::new(
        different,
        channel(1),
        LossKind::Attribution,
        LossMagnitude::AtLeast(Count::new(0)),
    )
    .unwrap();
    assert_eq!(
        registry.feed(&accepted),
        Ok(()),
        "CP06:same epoch schema diversity remains distinct caller policy"
    );
    assert_eq!(registry.finish(), Ok(()));
}
