// SPDX-License-Identifier: Apache-2.0
//! T0/T1 host contracts; no live scheduler, raw decoder or producer qualification.
#[path = "support/cp04_model.rs"]
mod model;
use model::*;
use scopebase_capture::{
    provenance::*,
    quantity::{Count, Events, Unit},
    ContractError as E,
};
fn lane(id: Option<u64>, n: u64) -> ProvenanceLane<u64, Events> {
    ProvenanceLane::new(
        id.map_or(LaneIdentity::Secondary, LaneIdentity::InsertionOwner),
        Count::new(n),
    )
}
fn result(lanes: &[ProvenanceLane<u64, Events>]) -> Result<(u64, u64), E> {
    fold_insertion_identity(lanes).map(|v| (*v.identity(), v.total().get()))
}
fn saturation(id: Option<u64>) -> ProvenanceLane<u64, Events> {
    ProvenanceLane::saturated(id.map_or(LaneIdentity::Secondary, LaneIdentity::InsertionOwner))
}
#[test]
fn migration_keeps_inserting_identity() {
    let mut m = ProvenanceModel::new(2);
    m.insert(0, identity_fixture());
    m.hit(0, 4243, [b'c'; 16], 100, 1);
    assert_eq!(
        m.lanes[1],
        RawLane::default(),
        "kernel zeroes non-inserting lanes"
    );
    m.hit(1, 4243, [b'c'; 16], 200, 1);
    assert_eq!(
        m.fold().map(|f| (*f.identity(), f.total().get())),
        Ok((identity_fixture(), 2)),
        "insertion tuple survives migration"
    );
    assert_eq!((m.display().2, m.display().3), (100, 200));
}
#[test]
fn single_cpu_control_keeps_identity() {
    let mut m = ProvenanceModel::new(2);
    m.insert(0, identity_fixture());
    m.hit(0, 4243, [b'c'; 16], 100, 1);
    m.hit(0, 4243, [b'c'; 16], 200, 1);
    assert_eq!(
        m.fold().map(|f| (*f.identity(), f.total().get())),
        Ok((identity_fixture(), 2))
    );
    assert_eq!(m.lanes[1], RawLane::default());
    assert_eq!(m.display(), (4243, [b'c'; 16], 100, 200, 1));
}
#[test]
fn migration_under_change_keeps_insertion_identity() {
    let mut m = ProvenanceModel::new(2);
    m.insert(0, identity_fixture());
    m.hit(0, 4243, [b'c'; 16], 100, 1);
    m.hit(1, 4244, [b'w'; 16], 200, 99);
    assert_eq!(m.display(), (4244, [b'w'; 16], 100, 200, 99));
    assert_eq!(
        m.fold().map(|f| (*f.identity(), f.total().get())),
        Ok((identity_fixture(), 2)),
        "display changes never refresh insertion identity"
    );
}
#[test]
fn race_loser_never_marks() {
    let mut m = ProvenanceModel::new(2);
    m.race_insert(0, 1, identity_fixture());
    m.hit(0, 4243, [b'c'; 16], 100, 1);
    m.hit(1, 4243, [b'c'; 16], 200, 1);
    assert_eq!(
        m.lanes[1].marked, false,
        "loser lane stays unmarked after hit"
    );
    assert_eq!(
        m.fold().map(|f| (*f.identity(), f.total().get())),
        Ok((identity_fixture(), 2))
    );
}
#[test]
fn unrelated_secondary_zero_does_not_replace_identity() {
    let mut m = ProvenanceModel::new(4);
    m.insert(0, identity_fixture());
    for i in 0..4 {
        m.hit(i, 4243, [b'c'; 16], 100 * (i as u64 + 1), 1);
    }
    for l in &m.lanes[1..] {
        assert_eq!((l.identity.4, l.marked), (0, false));
    }
    assert_eq!(
        m.fold().map(|f| (*f.identity(), f.total().get())),
        Ok((identity_fixture(), 4))
    );
    assert_eq!((m.display().2, m.display().3), (100, 400));
}
#[test]
fn zero_identity_is_known() {
    assert_eq!(
        result(&[lane(None, 7), lane(Some(0), 3)]),
        Ok((0, 10)),
        "zero is a known identity"
    );
    assert_eq!(result(&[lane(None, 3)]), Err(E::MissingProvenance));
    let mut m = ProvenanceModel::new(2);
    let root = (0, 5, 0, [b's'; 16], 0);
    m.insert(0, root);
    m.hit(0, 1, [b'i'; 16], 100, 0);
    m.hit(1, 1, [b'i'; 16], 200, 0);
    assert_eq!(
        m.fold().map(|f| (*f.identity(), f.total().get())),
        Ok((root, 2)),
        "marked uid0 and stack0 qualify"
    );
    assert_eq!(ObservedIdentity::Known(0u64), ObservedIdentity::Known(0));
}
#[test]
fn missing_owner_refuses() {
    for ls in [
        vec![],
        vec![lane(None, 0)],
        vec![lane(None, 3), lane(None, 2)],
        vec![saturation(None)],
        vec![lane(None, u64::MAX), lane(None, 1)],
    ] {
        assert_eq!(result(&ls), Err(E::MissingProvenance));
    }
    let mut m = ProvenanceModel::new(2);
    m.hit(0, 1, [0; 16], 100, 0);
    m.hit(1, 1, [0; 16], 200, 0);
    assert_eq!(m.fold().err(), Some(E::MissingProvenance));
}
#[test]
fn two_equal_owners_still_conflict() {
    for second in [0, 7] {
        for ls in [
            vec![lane(Some(0), 1), lane(Some(second), 2)],
            vec![saturation(Some(0)), lane(Some(second), 1)],
            vec![lane(Some(0), u64::MAX), lane(Some(second), 1)],
        ] {
            assert_eq!(result(&ls), Err(E::ConflictingProvenance));
        }
    }
    let mut m = ProvenanceModel::new(2);
    m.insert(0, identity_fixture());
    m.insert(1, identity_fixture());
    assert_eq!(m.fold().err(), Some(E::ConflictingProvenance));
}
#[test]
fn secondary_counts_are_conserved() {
    for owner in 0..4 {
        for owner_count in [0, 3] {
            let mut ls = (0..4).map(|_| lane(None, 7)).collect::<Vec<_>>();
            ls[owner] = lane(Some(7), owner_count);
            assert_eq!(
                result(&ls),
                Ok((7, 21 + owner_count)),
                "all lanes counted including a zero-count owner"
            );
        }
    }
    assert_eq!(
        result(&[lane(None, 3), lane(Some(7), 0)]),
        Ok((7, 3)),
        "owner may be last"
    );
}
#[test]
fn explicit_saturation_and_exact_max_are_distinct() {
    let max = u64::MAX;
    for ls in [
        vec![lane(Some(7), max)],
        vec![lane(Some(7), max), lane(None, 0)],
        vec![lane(Some(7), max - 1), lane(None, 1)],
    ] {
        assert_eq!(result(&ls), Ok((7, max)), "exact MAX is an exact count");
    }
    assert_eq!(
        result(&[lane(Some(7), max - 1), lane(None, 2)]),
        Err(E::ArithmeticOverflow)
    );
    for ls in [
        vec![saturation(Some(7))],
        vec![lane(Some(7), 1), saturation(None)],
    ] {
        assert_eq!(result(&ls), Err(E::SaturatedCount));
    }
    for ls in [
        vec![raw_lane(LaneIdentity::InsertionOwner(7), max)],
        vec![
            raw_lane(LaneIdentity::InsertionOwner(7), 1),
            raw_lane(LaneIdentity::Secondary, max),
        ],
    ] {
        assert_eq!(result(&ls), Err(E::SaturatedCount), "raw MAX is nonexact");
    }
    assert_eq!(
        result(&[
            raw_lane(LaneIdentity::InsertionOwner(7), max - 1),
            raw_lane(LaneIdentity::Secondary, 1)
        ]),
        Ok((7, max))
    );
    assert_eq!(
        result(&[
            raw_lane(LaneIdentity::InsertionOwner(7), 1),
            raw_lane(LaneIdentity::Secondary, 5)
        ]),
        Ok((7, 6))
    );
    assert_eq!(
        result(&[
            raw_lane(LaneIdentity::InsertionOwner(7), max - 1),
            raw_lane(LaneIdentity::Secondary, 5)
        ]),
        Err(E::ArithmeticOverflow)
    );
}
#[test]
fn owner_errors_precede_count_errors() {
    for owners in 0..=2 {
        for profile in 0..3 {
            let ls = (0..3)
                .map(|i| {
                    let id = if i < owners { Some(7) } else { None };
                    match profile {
                        1 if i == 0 => saturation(id),
                        2 if i == 0 => lane(id, u64::MAX),
                        _ => lane(id, 1),
                    }
                })
                .collect::<Vec<_>>();
            let expected = match owners {
                0 => Err(E::MissingProvenance),
                2 => Err(E::ConflictingProvenance),
                _ => match profile {
                    1 => Err(E::SaturatedCount),
                    2 => Err(E::ArithmeticOverflow),
                    _ => Ok((7, 3)),
                },
            };
            assert_eq!(result(&ls), expected);
        }
    }
}
#[test]
fn count_errors_follow_lane_order() {
    assert_eq!(
        result(&[lane(Some(7), u64::MAX), lane(None, 1), saturation(None)]),
        Err(E::ArithmeticOverflow)
    );
    assert_eq!(
        result(&[saturation(None), lane(Some(7), u64::MAX), lane(None, 1)]),
        Err(E::SaturatedCount)
    );
}
#[test]
fn independent_owner_and_u128_oracle() {
    // Each digit independently selects marker (Secondary/Owner0/Owner7) and count0/1/2.
    for n in 0..=4 {
        for encoded in 0..9usize.pow(n) {
            let mut v = encoded;
            let mut meta = Vec::new();
            for _ in 0..n {
                let d = v % 9;
                v /= 9;
                meta.push((d / 3, d % 3));
            }
            let owners = meta
                .iter()
                .enumerate()
                .filter(|(_, v)| v.0 > 0)
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            let sum: u128 = meta.iter().map(|v| v.1 as u128).sum();
            let expected = match owners.len() {
                0 => Err(E::MissingProvenance),
                1 => Ok((if meta[owners[0]].0 == 1 { 0 } else { 7 }, sum as u64)),
                _ => Err(E::ConflictingProvenance),
            };
            let lanes = meta
                .iter()
                .map(|v| {
                    lane(
                        match v.0 {
                            0 => None,
                            1 => Some(0),
                            _ => Some(7),
                        },
                        v.1 as u64,
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(result(&lanes), expected);
        }
    }
    for (a, b, want) in [
        (0, 0, Ok((7, 0))),
        (u64::MAX, 0, Ok((7, u64::MAX))),
        (u64::MAX - 1, 1, Ok((7, u64::MAX))),
        (u64::MAX, 1, Err(E::ArithmeticOverflow)),
        (u64::MAX - 1, 2, Err(E::ArithmeticOverflow)),
    ] {
        for owner in 0..2 {
            let ls = [
                lane((owner == 0).then_some(7), a),
                lane((owner == 1).then_some(7), b),
            ];
            assert_eq!(result(&ls), want);
            let sum = u128::from(a) + u128::from(b);
            assert_eq!(sum > u128::from(u64::MAX), want.is_err());
        }
    }
}
#[test]
fn payload_clone_and_equality_contract() {
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    struct Payload {
        clones: Rc<Cell<usize>>,
        panic: bool,
    }
    impl Clone for Payload {
        fn clone(&self) -> Self {
            self.clones.set(self.clones.get() + 1);
            if self.panic {
                panic!("caller clone panic");
            }
            Self {
                clones: self.clones.clone(),
                panic: self.panic,
            }
        }
    }
    impl PartialEq for Payload {
        fn eq(&self, _: &Self) -> bool {
            panic!("fold must never call Eq")
        }
    }
    impl Eq for Payload {}
    let c = Rc::new(Cell::new(0));
    let owner = |panic| {
        LaneIdentity::InsertionOwner(Payload {
            clones: c.clone(),
            panic,
        })
    };
    let good = [ProvenanceLane::<_, Events>::new(
        owner(false),
        Count::new(3),
    )];
    assert_eq!(c.get(), 0, "constructors move payloads");
    let folded = fold_insertion_identity(&good).unwrap();
    assert_eq!(c.get(), 1, "success clones once");
    assert_eq!(folded.total().get(), 3);
    for ls in [
        vec![],
        vec![ProvenanceLane::new(LaneIdentity::Secondary, Count::new(2))],
        vec![
            ProvenanceLane::new(owner(false), Count::new(0)),
            ProvenanceLane::new(owner(false), Count::new(0)),
        ],
        vec![ProvenanceLane::saturated(owner(false))],
        vec![
            ProvenanceLane::new(owner(false), Count::new(u64::MAX)),
            ProvenanceLane::new(LaneIdentity::Secondary, Count::new(1)),
        ],
    ] {
        c.set(0);
        assert_eq!(fold_insertion_identity::<_, Events>(&ls).is_err(), true);
        assert_eq!(c.get(), 0, "refusal clones zero times");
    }
    c.set(0);
    let panicking = [ProvenanceLane::<_, Events>::new(
        owner(true),
        Count::new(17),
    )];
    let before = format!("{:?}", panicking);
    assert!(catch_unwind(AssertUnwindSafe(|| fold_insertion_identity(&panicking))).is_err());
    assert_eq!(c.get(), 1, "caller interior mutation survives panic");
    assert_eq!(
        format!("{:?}", panicking),
        before,
        "library wrapper/count unchanged and borrowed input accessible"
    );
}
#[test]
fn generic_traits_and_redacted_debug() {
    #[derive(Clone, PartialEq, Eq)]
    struct NoDebug(u64);
    fn generic<U: Unit>() {
        let a =
            ProvenanceLane::<_, U>::new(LaneIdentity::InsertionOwner(NoDebug(9)), Count::new(3));
        let b = a.clone();
        assert_eq!(a, b);
        let f = fold_insertion_identity(&[a]).unwrap();
        assert_eq!(f, f.clone());
        let _ = format!("{:?}", f);
    }
    generic::<Events>();
    let secret = 986543210123456789u64;
    for text in [
        format!("{:?}", ObservedIdentity::Known(secret)),
        format!("{:?}", LaneIdentity::InsertionOwner(secret)),
        format!("{:?}", lane(Some(secret), 1)),
        format!(
            "{:?}",
            fold_insertion_identity(&[lane(Some(secret), 1)]).unwrap()
        ),
    ] {
        assert_eq!(
            text.contains(&secret.to_string()),
            false,
            "identity payload is redacted"
        );
    }
    struct PanicDebug;
    impl std::fmt::Debug for PanicDebug {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("payload formatting forbidden")
        }
    }
    let _ = format!("{:?}", ObservedIdentity::Known(PanicDebug));
    let _ = format!("{:?}", LaneIdentity::InsertionOwner(PanicDebug));
    let _ = format!(
        "{:?}",
        ProvenanceLane::<_, Events>::saturated(LaneIdentity::InsertionOwner(PanicDebug))
    );
    for a in [
        IdentityUnknown::NotObserved,
        IdentityUnknown::Ambiguous,
        IdentityUnknown::Exhausted,
    ] {
        for b in [
            IdentityUnknown::NotObserved,
            IdentityUnknown::Ambiguous,
            IdentityUnknown::Exhausted,
        ] {
            assert_eq!(
                ObservedIdentity::<u64>::Unknown(a) == ObservedIdentity::Unknown(b),
                a == b
            );
        }
    }
    assert_ne!(
        ObservedIdentity::Known(0),
        ObservedIdentity::Unknown(IdentityUnknown::NotObserved)
    );
    assert_ne!(lane(Some(7), u64::MAX), saturation(Some(7)));
    assert_ne!(lane(Some(7), 0), lane(None, 0));
}
