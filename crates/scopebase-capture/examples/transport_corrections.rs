// SPDX-License-Identifier: Apache-2.0
//! Independent shared-transport accounting plus explicit report/export routing.
use scopebase_capture::{
    correction::*, domain::*, feeds::FeedRegistry, generation::ObjectKey, loss::*, quantity::*,
    ContractError,
};
#[derive(Clone, PartialEq, Eq)]
struct Invocation {
    namespace: u32,
    device: u64,
    token: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    outcome: &'static str,
    by_seq: Option<u64>,
    op: u32,
}
struct Entry {
    key: ObjectKey<Invocation>,
    value: Option<Versioned<Verdict>>,
}
#[derive(Debug, PartialEq, Eq)]
enum RouteError {
    Unknown,
    Foreign,
    Missing,
    Ambiguous,
    Incomplete,
}
fn epoch() -> Epoch {
    Epoch::new(
        CaptureId::new([5; 16]).unwrap(),
        ProducerId::new([6; 16]).unwrap(),
        0,
    )
}
fn key(token: u64) -> ObjectKey<Invocation> {
    ObjectKey::new(
        epoch(),
        Invocation {
            namespace: 1,
            device: 2,
            token,
        },
        0,
    )
}
fn original() -> Verdict {
    Verdict {
        outcome: "Complete",
        by_seq: None,
        op: 17,
    }
}
fn replacement() -> Verdict {
    Verdict {
        outcome: "Tainted",
        by_seq: Some(1),
        op: 0,
    }
}
fn entry(token: u64) -> Entry {
    Entry {
        key: key(token),
        value: Some(Versioned::new(epoch(), original())),
    }
}
fn fact(channel: u32, n: u64) -> LossFact<Events> {
    LossFact::new(
        SourceRef::new(epoch(), BindingId::new([7; 32]).unwrap(), Origin::Synthetic),
        ChannelId::new(channel),
        LossKind::Transport,
        LossMagnitude::Exact(Count::new(n)),
    )
    .unwrap()
}
fn route(entries: &mut [Entry], target: Option<&ObjectKey<Invocation>>) -> Result<(), RouteError> {
    let target = target.ok_or(RouteError::Unknown)?;
    if target.epoch() != &epoch() {
        return Err(RouteError::Foreign);
    }
    let mut found = None;
    for (i, e) in entries.iter().enumerate() {
        if e.key.matches(target) {
            if found.is_some() {
                return Err(RouteError::Ambiguous);
            }
            found = Some(i);
        }
    }
    let i = found.ok_or(RouteError::Missing)?;
    let old = entries[i].value.take().ok_or(RouteError::Incomplete)?;
    match old.apply(Correction::new(epoch(), Revision::new(0), replacement()).unwrap()) {
        Ok(new) => {
            entries[i].value = Some(new);
            Ok(())
        }
        Err((old, _)) => {
            entries[i].value = Some(old);
            Err(RouteError::Incomplete)
        }
    }
}
fn main() {
    let mut feeds = FeedRegistry::new(epoch(), &[ChannelId::new(0), ChannelId::new(1)], 2).unwrap();
    assert_eq!(feeds.finish(), Err(ContractError::MissingFeed));
    let mut totals = [0, 0];
    for (channel, n) in [(0, 11), (1, 5), (0, 100), (1, 100)] {
        let result = feeds.feed(&fact(channel, n));
        if result.is_ok() {
            totals[channel as usize] += n;
        } else {
            assert_eq!(result, Err(ContractError::DuplicateFeed));
        }
    }
    assert_eq!(totals, [11, 5], "CP06:transport first11/5 stands");
    assert_eq!(feeds.finish(), Ok(()));
    let backend = [0, 0];
    let skip = 0;
    assert_eq!((backend, skip), ([0, 0], 0));
    let mut report = vec![entry(0), entry(1)];
    let mut export = vec![entry(0), entry(1)];
    let target = key(0);
    assert_eq!(route(&mut report, None), Err(RouteError::Unknown));
    assert_eq!(route(&mut report, Some(&key(99))), Err(RouteError::Missing));
    for raw in [
        Invocation {
            namespace: 9,
            device: 2,
            token: 0,
        },
        Invocation {
            namespace: 1,
            device: 9,
            token: 0,
        },
    ] {
        assert_eq!(
            route(&mut report, Some(&ObjectKey::new(epoch(), raw, 0))),
            Err(RouteError::Missing),
            "CP06:complete client key routes"
        );
    }
    assert_eq!(
        route(
            &mut report,
            Some(&ObjectKey::new(
                epoch(),
                Invocation {
                    namespace: 1,
                    device: 2,
                    token: 0
                },
                1
            ))
        ),
        Err(RouteError::Missing),
        "CP06:complete client key routes"
    );
    let bad = ObjectKey::new(
        epoch().successor().unwrap(),
        Invocation {
            namespace: 1,
            device: 2,
            token: 0,
        },
        0,
    );
    assert_eq!(route(&mut report, Some(&bad)), Err(RouteError::Foreign));
    let mut duplicate = vec![entry(0), entry(0)];
    assert_eq!(
        route(&mut duplicate, Some(&target)),
        Err(RouteError::Ambiguous)
    );
    // A finish/salvage tail appends new values before correcting held originals.
    report.push(entry(2));
    export.push(entry(2));
    route(&mut report, Some(&target)).unwrap(); // CP06_REPORT_UPDATE
    route(&mut export, Some(&target)).unwrap(); // CP06_EXPORT_UPDATE
    for holder in [&report, &export] {
        assert_eq!(
            holder[0].value.as_ref().unwrap().value(),
            &Verdict {
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
        assert_eq!(
            holder[1].value.as_ref().unwrap().value(),
            &original(),
            "CP06:unrelated holder unchanged"
        );
        assert_eq!(holder[2].value.as_ref().unwrap().value(), &original());
    }
    // One holder has already advanced: preserve its owner and explicit pending
    // target when propagation refuses. There is no atomic multi-holder broadcast.
    let pending = target.clone();
    let a = route(&mut report, Some(&target));
    let b = route(&mut export, Some(&target));
    assert_eq!(
        (a, b),
        (Err(RouteError::Incomplete), Err(RouteError::Incomplete))
    );
    assert!(pending.matches(&target));
    // Exactly one holder refuses while the other advances. Keep the full
    // pending key and report incomplete propagation; do not roll back success.
    let mut advanced = vec![entry(0)];
    route(&mut advanced, Some(&target)).unwrap();
    let mut waiting = vec![entry(0)];
    let pending = Some(target.clone());
    let a = route(&mut advanced, Some(&target));
    let b = route(&mut waiting, Some(&target));
    assert_eq!(
        (a, b),
        (Err(RouteError::Incomplete), Ok(())),
        "CP06:one-holder failure is explicit"
    );
    assert!(pending.as_ref().unwrap().matches(&target));
    for holder in [&advanced, &waiting] {
        assert_eq!(
            holder[0].value.as_ref().unwrap().value(),
            &Verdict {
                outcome: "Tainted",
                by_seq: Some(1),
                op: 0
            }
        );
    }
    println!("CP06 transport reporter: shared11/5; both full original holders/tail/key routes and explicit incomplete propagation verified");
}
