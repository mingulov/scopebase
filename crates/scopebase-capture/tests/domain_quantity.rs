// SPDX-License-Identifier: Apache-2.0
//! Selected donor representation regressions; full application tests remain with CP05–CP11.
use scopebase_capture::{
    conservation::{check_conservation, ScopePartition},
    domain::*,
    quantity::*,
    ContractError,
};
use std::collections::{BTreeSet, HashSet};
use std::fmt::Debug;

fn capture(n: u8) -> CaptureId {
    CaptureId::new([n; 16]).unwrap()
}
fn producer(n: u8) -> ProducerId {
    ProducerId::new([n; 16]).unwrap()
}
fn binding(n: u8) -> BindingId {
    BindingId::new([n; 32]).unwrap()
}
fn epoch() -> Epoch {
    Epoch::new(capture(1), producer(2), 0)
}
fn c(n: u64) -> Count<Events> {
    Count::new(n)
}

#[test]
fn zero_numeric_ids_but_not_absent_domains() {
    assert_eq!(CaptureId::new([0; 16]), Err(ContractError::InvalidId));
    assert_eq!(ProducerId::new([0; 16]), Err(ContractError::InvalidId));
    assert_eq!(BindingId::new([0; 32]), Err(ContractError::InvalidId));
    assert_eq!(ClockDomain::new([0; 16]), Err(ContractError::InvalidId));
    for i in 0..16 {
        let mut bytes = [0; 16];
        bytes[i] = 1;
        assert!(CaptureId::new(bytes).is_ok());
        assert!(ProducerId::new(bytes).is_ok());
        assert!(ClockDomain::new(bytes).is_ok());
    }
    for i in 0..32 {
        let mut bytes = [0; 32];
        bytes[i] = 1;
        assert!(BindingId::new(bytes).is_ok());
    }
    assert_eq!(ChannelId::new(0), ChannelId::new(0));
    assert_eq!(ClaimId::new(0), ClaimId::new(0));
    assert_eq!(PhysicalSiteId::new(0), PhysicalSiteId::new(0));
    assert_ne!(ChannelId::new(0), ChannelId::new(1));
    assert_ne!(ClaimId::new(0), ClaimId::new(1));
    assert_ne!(PhysicalSiteId::new(0), PhysicalSiteId::new(1));
    assert_eq!(epoch().ordinal(), 0);
    fn id_traits<T: Copy + Debug + Ord + std::hash::Hash>(a: T, b: T) {
        assert_ne!(a, b);
        assert!(a < b);
        assert_eq!(HashSet::from([a, b, a]).len(), 2);
        assert_eq!(BTreeSet::from([a, b, a]).len(), 2);
    }
    id_traits(capture(1), capture(2));
    id_traits(producer(1), producer(2));
    id_traits(binding(1), binding(2));
    id_traits(
        ClockDomain::new([1; 16]).unwrap(),
        ClockDomain::new([2; 16]).unwrap(),
    );
    id_traits(ChannelId::new(0), ChannelId::new(1));
    id_traits(ClaimId::new(0), ClaimId::new(1));
    id_traits(PhysicalSiteId::new(0), PhysicalSiteId::new(1));
}
#[test]
fn epoch_exhaustion_refuses() {
    let before = Epoch::new(capture(1), producer(2), u64::MAX - 1);
    let last = before.successor().unwrap();
    assert_eq!(last.ordinal() as u128, (u64::MAX as u128 - 1) + 1);
    assert_eq!(last.capture(), capture(1));
    assert_eq!(last.producer(), producer(2));
    assert_eq!(last.successor(), Err(ContractError::EpochExhausted));
    assert_eq!(last.ordinal(), u64::MAX);
    assert_eq!(before.ordinal(), u64::MAX - 1);
}
#[test]
fn source_domains_and_origins_stay_distinct() {
    let e = epoch();
    assert_ne!(e, Epoch::new(capture(3), producer(2), 0));
    assert_ne!(e, Epoch::new(capture(1), producer(3), 0));
    assert_ne!(e, e.successor().unwrap());
    let s = SourceRef::new(e.clone(), binding(4), Origin::AdapterReported);
    assert_eq!(s.epoch(), &e);
    assert_eq!(s.binding(), binding(4));
    assert_eq!(s.origin(), Origin::AdapterReported);
    assert_ne!(
        s,
        SourceRef::new(e.clone(), binding(5), Origin::AdapterReported)
    );
    for origin in [Origin::AdapterReported, Origin::Synthetic, Origin::Replayed] {
        let a = SourceRef::new(e.clone(), binding(4), origin);
        assert_eq!(a.origin(), origin);
        assert_eq!(a == s, origin == Origin::AdapterReported);
    }
    assert_ne!(
        SourceRef::new(e.clone(), binding(4), Origin::Synthetic),
        SourceRef::new(e, binding(4), Origin::Replayed)
    );
}
#[test]
fn all_units_have_unconditional_value_traits() {
    fn traits<T: Debug + Clone + PartialEq + Eq>(_: &T) {}
    fn generic<U: Unit>() {
        let a = Count::<U>::new(3);
        let b = a;
        let d = a;
        assert_eq!(b, d);
        traits(&a);
        let bounds = CountBounds::new(a, Some(a)).unwrap();
        traits(&bounds);
        assert_eq!(bounds, bounds.clone());
        let partition = ScopePartition::new(a, a, Count::new(0), Count::new(0)).unwrap();
        traits(&partition);
        assert_eq!(partition, partition.clone());
    }
    generic::<Events>();
    generic::<Records>();
    generic::<Bytes>();
    generic::<Objects>();
    generic::<Attempts>();
    generic::<Nonexecutions>();
    generic::<DiagnosticSignals>();
}
#[test]
fn units_and_checked_partitions() {
    let p = ScopePartition::new(c(9), c(2), c(3), c(4)).unwrap();
    assert_eq!(
        (
            p.total().get(),
            p.matched().get(),
            p.nonmatched().get(),
            p.unknown().get()
        ),
        (9, 2, 3, 4)
    );
    assert_eq!(
        ScopePartition::new(c(8), c(2), c(3), c(4)),
        Err(ContractError::ConservationMismatch)
    );
    assert_eq!(
        ScopePartition::new(c(0), c(u64::MAX), c(1), c(0)),
        Err(ContractError::ArithmeticOverflow)
    );
    for a in 0..=7 {
        for b in 0..=7 {
            for d in 0..=7 {
                for total in 0..=22 {
                    let sum = a as u128 + b as u128 + d as u128;
                    let got = ScopePartition::new(c(total), c(a), c(b), c(d));
                    if sum == total as u128 {
                        let p = got.unwrap();
                        assert_eq!(
                            (p.matched().get(), p.nonmatched().get(), p.unknown().get()),
                            (a, b, d)
                        );
                    } else {
                        assert_eq!(got, Err(ContractError::ConservationMismatch));
                    }
                }
            }
        }
    }
    for a in [0, 1, u64::MAX - 1, u64::MAX] {
        for b in [0, 1, u64::MAX - 1, u64::MAX] {
            for d in [0, 1, u64::MAX - 1, u64::MAX] {
                let sum = a as u128 + b as u128 + d as u128;
                let got = ScopePartition::new(c(0), c(a), c(b), c(d));
                let want = if sum > u64::MAX as u128 {
                    Err(ContractError::ArithmeticOverflow)
                } else if sum != 0 {
                    Err(ContractError::ConservationMismatch)
                } else {
                    Ok(())
                };
                assert_eq!(got.map(|_| ()), want);
            }
        }
    }
}
// K d153f3a scope.rs:313–334. Wire decoding itself remains CP10.
#[test]
fn k_partition_invariant_holds() {
    let p = ScopePartition::new(c(100), c(70), c(20), c(10)).unwrap();
    assert_eq!(
        (
            p.total().get(),
            p.matched().get(),
            p.nonmatched().get(),
            p.unknown().get()
        ),
        (100, 70, 20, 10)
    );
}
#[test]
fn k_zero_population_is_valid() {
    assert_eq!(
        ScopePartition::new(c(0), c(0), c(0), c(0)).unwrap().total(),
        c(0)
    );
}
#[test]
fn k_deserialization_overflow_vector_refuses() {
    assert_eq!(
        ScopePartition::new(c(0), c(u64::MAX), c(1), c(0)),
        Err(ContractError::ArithmeticOverflow)
    );
}
#[test]
fn checked_count_edges_preserve_inputs() {
    for a in [0, 1, 2, u64::MAX - 1, u64::MAX] {
        for b in [0, 1, 2, u64::MAX - 1, u64::MAX] {
            let x = c(a);
            let y = c(b);
            let sum = a as u128 + b as u128;
            assert_eq!(
                x.checked_add(y).map(|v| v.get()),
                if sum > u64::MAX as u128 {
                    Err(ContractError::ArithmeticOverflow)
                } else {
                    Ok(sum as u64)
                }
            );
            assert_eq!(
                x.checked_sub(y).map(|v| v.get()),
                if a < b {
                    Err(ContractError::ArithmeticOverflow)
                } else {
                    Ok((a as u128 - b as u128) as u64)
                }
            );
            assert_eq!((x.get(), y.get()), (a, b));
        }
    }
}
// M 8307a17 test_mappings.mojo:599–607,768–783: arithmetic vectors only.
#[test]
fn m_mapped_bytes_overflow_vector_refuses() {
    let mapped = Count::<Bytes>::new(u64::MAX);
    assert_eq!(
        mapped.checked_add(Count::new(1)),
        Err(ContractError::ArithmeticOverflow)
    );
    assert_eq!(mapped.get(), u64::MAX);
}
#[test]
fn m_unpaired_copy_overflow_vector_refuses() {
    let copied = Count::<Bytes>::new(u64::MAX);
    assert_eq!(
        copied.checked_add(Count::new(1)),
        Err(ContractError::ArithmeticOverflow)
    );
    assert_eq!(copied.get(), u64::MAX);
}
#[test]
fn bounds_preserve_unknown_upper() {
    let unknown = CountBounds::new(c(0), None).unwrap();
    let zero = CountBounds::new(c(0), Some(c(0))).unwrap();
    assert_eq!(unknown.upper(), None);
    assert_ne!(unknown, zero);
    assert_eq!(zero.upper(), Some(c(0)));
    assert_eq!(
        CountBounds::new(c(2), Some(c(1))),
        Err(ContractError::ReversedBounds)
    );
    let max = CountBounds::new(c(u64::MAX), Some(c(u64::MAX))).unwrap();
    assert_eq!(max.lower().get(), u64::MAX);
    assert_eq!(max.upper(), Some(c(u64::MAX)));
}
// O 4bcb24c evidence_model.rs:108–129,590–607. No site/rule evaluation here.
#[test]
fn o_seven_call_bounds_representation() {
    for (lo, hi) in [(0, Some(7)), (7, Some(7))] {
        let b = CountBounds::new(c(lo), hi.map(c)).unwrap();
        assert_eq!((b.lower().get(), b.upper().map(|v| v.get())), (lo, hi));
    }
}
#[test]
fn o_zero_call_bounds_representation() {
    let b = CountBounds::new(c(0), Some(c(0))).unwrap();
    assert_eq!((b.lower().get(), b.upper().map(|v| v.get())), (0, Some(0)));
}
// L ff6ea50 ring_conformance.c:536–538/572–574. Portable vectors, not native adapters.
#[test]
fn l_conservation_session_vector() {
    let parts = [2, 0, 2, 1].map(Count::<Records>::new);
    assert_eq!(check_conservation(Count::new(5), &parts), Ok(()));
    assert_eq!(
        check_conservation(Count::new(5), &parts[..3]),
        Err(ContractError::ConservationMismatch)
    );
    assert_eq!(
        check_conservation(
            Count::new(5),
            &[parts[0], parts[1], parts[2], parts[3], parts[3]]
        ),
        Err(ContractError::ConservationMismatch)
    );
}
#[test]
fn l_conservation_buffer_vector() {
    let parts = [2, 0, 2, 1].map(Count::<Records>::new);
    assert_eq!(check_conservation(Count::new(5), &parts), Ok(()));
    assert_eq!(
        check_conservation(Count::new(5), &parts[..3]),
        Err(ContractError::ConservationMismatch)
    );
    assert_eq!(
        check_conservation(
            Count::new(5),
            &[parts[0], parts[1], parts[2], parts[3], parts[3]]
        ),
        Err(ContractError::ConservationMismatch)
    );
}
#[test]
fn conservation_empty_and_overflow_precedence() {
    assert_eq!(check_conservation(c(0), &[]), Ok(()));
    assert_eq!(
        check_conservation(c(1), &[]),
        Err(ContractError::ConservationMismatch)
    );
    let parts = [c(u64::MAX), c(1)];
    assert_eq!(
        check_conservation(c(0), &parts),
        Err(ContractError::ArithmeticOverflow)
    );
    assert_eq!(parts, [c(u64::MAX), c(1)]);
    assert_eq!(check_conservation(c(0), &[c(0), c(0)]), Ok(()));
    for a in 0..=7 {
        for b in 0..=7 {
            for total in 0..=15 {
                assert_eq!(
                    check_conservation(c(total), &[c(a), c(0), c(b)]),
                    if total as u128 == a as u128 + b as u128 {
                        Ok(())
                    } else {
                        Err(ContractError::ConservationMismatch)
                    }
                );
            }
        }
    }
}
