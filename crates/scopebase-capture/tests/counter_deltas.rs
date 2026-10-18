// SPDX-License-Identifier: Apache-2.0
//! CP03 pure protocol checks; no producer, clock read or live ordering authority.
use scopebase_capture::{
    counter::{sample_delta, AdvanceBound, CounterPolicy, Delta, DeltaUnknown, Sample},
    domain::{BindingId, CaptureId, ChannelId, ClockDomain, Epoch, Origin, ProducerId, SourceRef},
    quantity::{Count, Events, Unit},
    time::{TimeInterval, Timestamp},
    ContractError,
};

// Each dimension is independently different but valid; policy width16 retains 250/3.
fn sample<U: Unit>(
    dimension: usize,
    policy: CounterPolicy,
    start: u64,
    end: u64,
    value: u64,
) -> Sample<U> {
    let source = SourceRef::new(
        Epoch::new(
            CaptureId::new([if dimension == 1 { 5 } else { 1 }; 16]).unwrap(),
            ProducerId::new([if dimension == 2 { 6 } else { 2 }; 16]).unwrap(),
            u64::from(dimension == 3),
        ),
        BindingId::new([if dimension == 4 { 7 } else { 3 }; 32]).unwrap(),
        if dimension == 5 {
            Origin::Replayed
        } else {
            Origin::Synthetic
        },
    );
    let clock = ClockDomain::new([if dimension == 8 { 8 } else { 4 }; 16]).unwrap();
    Sample::new(
        source,
        ChannelId::new(u32::from(dimension == 6)),
        if dimension == 7 {
            CounterPolicy::Modulo { width: 16 }
        } else {
            policy
        },
        TimeInterval::new(Timestamp::new(clock, start), Timestamp::new(clock, end)).unwrap(),
        Count::new(value),
    )
    .unwrap()
}
fn pair(policy: CounterPolicy, b: u64, c: u64) -> (Sample<Events>, Sample<Events>) {
    (sample(0, policy, 0, 1, b), sample(0, policy, 2, 3, c))
}
fn exact(value: u64) -> Result<Delta<Events>, ContractError> {
    Ok(Delta::Exact(Count::new(value)))
}
fn unknown(reason: DeltaUnknown) -> Result<Delta<Events>, ContractError> {
    Ok(Delta::Unknown(reason))
}

#[test]
fn missing_baseline_is_unknown() {
    let (b, c) = pair(CounterPolicy::Monotonic, 10, 13);
    assert_eq!(
        sample_delta(None, &c, None),
        unknown(DeltaUnknown::MissingBaseline),
        "missing-is-not-zero"
    );
    assert_eq!(sample_delta(Some(&b), &c, None), exact(3));
    assert_eq!(
        sample_delta(
            Some(&b),
            &sample(0, CounterPolicy::Monotonic, 2, 3, 10),
            None
        ),
        exact(0)
    );
    let (z, _) = pair(CounterPolicy::Monotonic, 0, 0);
    assert_eq!(
        sample_delta(None, &z, None),
        unknown(DeltaUnknown::MissingBaseline)
    );
    assert_eq!(
        sample_delta(
            Some(&z),
            &sample(0, CounterPolicy::Monotonic, 2, 3, 0),
            None
        ),
        exact(0)
    );
}
#[test]
fn sample_constructor_ranges() {
    let seed = sample::<Events>(0, CounterPolicy::Monotonic, 0, 1, 0);
    let make = |p, v| {
        Sample::new(
            seed.source().clone(),
            seed.channel(),
            p,
            seed.interval().clone(),
            Count::<Events>::new(v),
        )
    };
    for v in [0, u64::MAX] {
        assert!(make(CounterPolicy::Monotonic, v).is_ok());
    }
    for (p, v) in [
        (CounterPolicy::Saturating { maximum: 0 }, 0),
        (CounterPolicy::Saturating { maximum: 255 }, 256),
        (CounterPolicy::Modulo { width: 0 }, 0),
        (CounterPolicy::Modulo { width: 65 }, 0),
        (CounterPolicy::Modulo { width: 1 }, 2),
    ] {
        assert_eq!(
            make(p, v),
            Err(ContractError::InvalidSample),
            "range-refusal {p:?} {v}"
        );
    }
    for v in [0, 1] {
        assert!(make(CounterPolicy::Modulo { width: 1 }, v).is_ok());
    }
    assert!(make(CounterPolicy::Modulo { width: 64 }, u64::MAX).is_ok());
}
#[test]
fn monotonic_and_reset() {
    for (b, c, want) in [
        (7, 12, exact(5)),
        (12, 7, unknown(DeltaUnknown::ResetOrWrap)),
        (u64::MAX, 0, unknown(DeltaUnknown::ResetOrWrap)),
        (7, 7, exact(0)),
    ] {
        let (b, c) = pair(CounterPolicy::Monotonic, b, c);
        assert_eq!(
            sample_delta(Some(&b), &c, None),
            want,
            "decrease-not-unsigned-delta"
        );
    }
}
#[test]
fn source_context_precedes_arithmetic() {
    let p = CounterPolicy::Modulo { width: 8 };
    let b = sample::<Events>(0, p, 10, 20, 7);
    let c = sample::<Events>(0, p, 20, 25, 12);
    for dimension in 1..=8 {
        let foreign = sample::<Events>(dimension, p, 15, 25, 7);
        assert_eq!(
            sample_delta(Some(&b), &foreign, None),
            Err(ContractError::DomainMismatch),
            "context-dimension-{dimension}"
        );
        assert_eq!(
            sample_delta(Some(&foreign), &c, None),
            Err(ContractError::DomainMismatch)
        );
    }
    let (b, c) = pair(CounterPolicy::Monotonic, 7, 12);
    assert_eq!(sample_delta(Some(&b), &c, None), exact(5));
}
#[test]
fn ordered_read_intervals() {
    let p = CounterPolicy::Monotonic;
    let b = sample::<Events>(0, p, 10, 20, 7);
    for (s, e, v, want) in [
        (15, 25, 12, unknown(DeltaUnknown::PartialRead)),
        (20, 25, 12, exact(5)),
        (9, 25, 12, Err(ContractError::InvalidSample)),
        (15, 25, 1, unknown(DeltaUnknown::PartialRead)),
    ] {
        assert_eq!(
            sample_delta(Some(&b), &sample(0, p, s, e, v), None),
            want,
            "ordered-read-{s}-{v}"
        );
    }
    assert_eq!(
        sample_delta(
            Some(&sample(0, p, 20, 20, 7)),
            &sample(0, p, 20, 20, 12),
            None
        ),
        exact(5)
    );
}
#[test]
fn saturation_is_lower_bound() {
    // ADAPT K integrity.rs saturation/rollup vectors; no rollup or feed implementation.
    for (maximum, b, c, want) in [
        (255, 250, 254, exact(4)),
        (255, 250, 255, Ok(Delta::AtLeast(Count::new(5)))),
        (255, 255, 255, unknown(DeltaUnknown::Saturated)),
        (255, 255, 1, unknown(DeltaUnknown::ResetOrWrap)),
        (
            u64::MAX,
            u64::MAX - 2,
            u64::MAX,
            Ok(Delta::AtLeast(Count::new(2))),
        ),
    ] {
        let (b, c) = pair(CounterPolicy::Saturating { maximum }, b, c);
        assert_eq!(
            sample_delta(Some(&b), &c, None),
            want,
            "saturation-{maximum}"
        );
    }
}
#[test]
fn bound_constructor_contract() {
    let p = CounterPolicy::Modulo { width: 8 };
    let (b, c) = pair(p, 250, 3);
    for maximum in [0, 8, 12, 256, u64::MAX] {
        let bound = AdvanceBound::new(&b, &c, Count::new(maximum)).unwrap();
        assert_eq!(bound.baseline(), &b);
        assert_eq!(bound.current(), &c);
        assert_eq!(bound.maximum().get(), maximum);
    }
    for dimension in 1..=8 {
        let foreign = sample::<Events>(dimension, p, 0, 1, 3);
        assert_eq!(
            AdvanceBound::new(&b, &foreign, Count::new(12)),
            Err(ContractError::DomainMismatch),
            "bound-constructor-context-{dimension}"
        );
    }
    let (mono_b, mono_c) = pair(CounterPolicy::Monotonic, 250, 3);
    assert_eq!(
        AdvanceBound::new(&mono_b, &mono_c, Count::new(12)),
        Err(ContractError::InvalidSample)
    );
    let foreign = sample::<Events>(1, CounterPolicy::Monotonic, 0, 1, 3);
    assert_eq!(
        AdvanceBound::new(&mono_c, &foreign, Count::new(12)),
        Err(ContractError::DomainMismatch)
    );
    assert_eq!(
        AdvanceBound::new(&c, &b, Count::new(12)),
        Err(ContractError::InvalidSample)
    );
    let b = sample::<Events>(0, p, 10, 20, 250);
    let c = sample::<Events>(0, p, 15, 25, 3);
    let admitted = AdvanceBound::new(&b, &c, Count::new(8));
    assert_eq!(
        admitted.as_ref().map(|_| ()),
        Ok(()),
        "forward-overlap-is-admitted"
    );
    let bound = admitted.unwrap();
    assert_eq!(
        sample_delta(Some(&b), &c, Some(&bound)),
        unknown(DeltaUnknown::PartialRead)
    );
}
#[test]
fn bound_current_pair_reuse_refuses() {
    let p = CounterPolicy::Modulo { width: 8 };
    let (b, c) = pair(p, 250, 3);
    let bound = AdvanceBound::new(&b, &c, Count::new(12)).unwrap();
    for dimension in 1..=8 {
        let alternate_b = sample::<Events>(dimension, p, 0, 1, 250);
        let alternate_c = sample::<Events>(dimension, p, 2, 3, 3);
        assert_eq!(
            sample_delta(Some(&alternate_b), &alternate_c, Some(&bound)),
            Err(ContractError::DomainMismatch),
            "bound-current-context-{dimension}"
        );
        let fresh = AdvanceBound::new(&alternate_b, &alternate_c, Count::new(12)).unwrap();
        let expected = if dimension == 7 {
            Err(ContractError::InvalidSample)
        } else {
            exact(9)
        };
        assert_eq!(
            sample_delta(Some(&alternate_b), &alternate_c, Some(&fresh)),
            expected
        );
        // width16 is valid but 12 contradicts its 65289 advance; a sufficient bound is its positive twin.
        if dimension == 7 {
            let fresh = AdvanceBound::new(&alternate_b, &alternate_c, Count::new(65289)).unwrap();
            assert_eq!(
                sample_delta(Some(&alternate_b), &alternate_c, Some(&fresh)),
                exact(65289)
            );
        }
    }
    for (s, e, v) in [(1, 3, 3), (2, 4, 3), (2, 3, 4)] {
        let changed = sample::<Events>(0, p, s, e, v);
        assert_eq!(
            sample_delta(Some(&b), &changed, Some(&bound)),
            Err(ContractError::InvalidSample),
            "bound-current-endpoint-{s}-{e}-{v}"
        );
        let fresh = AdvanceBound::new(&b, &changed, Count::new(12)).unwrap();
        assert_eq!(
            sample_delta(Some(&b), &changed, Some(&fresh)),
            exact(if v == 4 { 10 } else { 9 })
        );
    }
    assert_eq!(
        sample_delta(Some(&b.clone()), &c.clone(), Some(&bound)),
        exact(9)
    );
}
#[test]
fn bound_baseline_pair_reuse_refuses() {
    let p = CounterPolicy::Modulo { width: 8 };
    let (b, c) = pair(p, 250, 3);
    let bound = AdvanceBound::new(&b, &c, Count::new(12)).unwrap();
    for dimension in 1..=8 {
        let changed = sample::<Events>(dimension, p, 0, 1, 250);
        assert_eq!(
            sample_delta(Some(&changed), &c, Some(&bound)),
            Err(ContractError::DomainMismatch),
            "bound-baseline-context-{dimension}"
        );
    }
    for (s, e, v) in [(1, 1, 250), (0, 2, 250), (0, 1, 249)] {
        let changed = sample::<Events>(0, p, s, e, v);
        assert_eq!(
            sample_delta(Some(&changed), &c, Some(&bound)),
            Err(ContractError::InvalidSample),
            "bound-baseline-endpoint-{s}-{e}-{v}"
        );
        let fresh = AdvanceBound::new(&changed, &c, Count::new(12)).unwrap();
        assert_eq!(
            sample_delta(Some(&changed), &c, Some(&fresh)),
            exact(if v == 249 { 10 } else { 9 })
        );
    }
    assert_eq!(
        sample_delta(Some(&c), &b, Some(&bound)),
        Err(ContractError::InvalidSample)
    );
    assert_eq!(sample_delta(Some(&b.clone()), &c, Some(&bound)), exact(9));
}
#[test]
fn bound_missing_baseline_and_precedence() {
    let p = CounterPolicy::Modulo { width: 8 };
    let (b, c) = pair(p, 250, 3);
    let bound = AdvanceBound::new(&b, &c, Count::new(12)).unwrap();
    assert_eq!(
        sample_delta(None, &c, Some(&bound)),
        unknown(DeltaUnknown::MissingBaseline),
        "explicit-baseline-required"
    );
    let wrong_value = sample::<Events>(0, p, 2, 3, 4);
    let foreign = sample::<Events>(5, p, 0, 1, 250);
    assert_eq!(
        sample_delta(None, &wrong_value, Some(&bound)),
        Err(ContractError::InvalidSample)
    );
    assert_eq!(
        sample_delta(None, &sample(5, p, 2, 3, 3), Some(&bound)),
        Err(ContractError::DomainMismatch)
    );
    assert_eq!(
        sample_delta(Some(&foreign), &wrong_value, Some(&bound)),
        Err(ContractError::InvalidSample)
    );
    assert_eq!(
        sample_delta(Some(&foreign), &c, Some(&bound)),
        Err(ContractError::DomainMismatch)
    );
    assert_eq!(
        sample_delta(
            None,
            &sample(0, CounterPolicy::Monotonic, 2, 3, 3),
            Some(&bound)
        ),
        Err(ContractError::DomainMismatch)
    );
}
#[test]
fn bound_owns_exact_pair_without_marker_traits() {
    fn traits<U: Unit>(value: &Sample<U>, bound: &AdvanceBound<U>, delta: &Delta<U>) {
        assert_eq!(value, &value.clone());
        assert_eq!(bound, &bound.clone());
        assert_eq!(delta, &delta.clone());
        let debug = format!("{value:?} {bound:?} {delta:?}");
        assert!(debug.contains("<redacted>"));
        for byte in [1, 2, 3, 4] {
            assert!(!debug.contains(&format!("[{byte}, {byte}, {byte},")));
        }
    }
    let bound = {
        let (b, c) = pair(CounterPolicy::Modulo { width: 8 }, 250, 3);
        AdvanceBound::new(&b, &c, Count::new(12)).unwrap()
    };
    assert_eq!(bound.baseline().value().get(), 250);
    assert_eq!(bound.current().value().get(), 3);
    assert_eq!(
        bound.baseline().source(),
        &sample::<Events>(0, CounterPolicy::Modulo { width: 8 }, 0, 1, 250)
            .source()
            .clone()
    );
    traits(
        bound.baseline(),
        &bound,
        &sample_delta(Some(bound.baseline()), bound.current(), Some(&bound)).unwrap(),
    );
}
#[test]
fn modulo_bound_is_checked() {
    let (b, c) = pair(CounterPolicy::Modulo { width: 8 }, 250, 3);
    for (maximum, want) in [
        (12, exact(9)),
        (8, Err(ContractError::InvalidSample)),
        (256, unknown(DeltaUnknown::UnboundedWrap)),
    ] {
        let bound = AdvanceBound::new(&b, &c, Count::new(maximum)).unwrap();
        assert_eq!(
            sample_delta(Some(&b), &c, Some(&bound)),
            want,
            "bound-maximum-{maximum}"
        );
    }
    assert_eq!(
        sample_delta(Some(&b), &c, None),
        unknown(DeltaUnknown::UnboundedWrap)
    );
    for (b, c, want) in [(0, 0, exact(0)), (0, 1, Err(ContractError::InvalidSample))] {
        let (b, c) = pair(CounterPolicy::Modulo { width: 8 }, b, c);
        let bound = AdvanceBound::new(&b, &c, Count::new(0)).unwrap();
        assert_eq!(sample_delta(Some(&b), &c, Some(&bound)), want);
    }
    let (b, c) = pair(CounterPolicy::Modulo { width: 8 }, 1, 2);
    assert_eq!(
        sample_delta(Some(&b), &c, None),
        unknown(DeltaUnknown::UnboundedWrap)
    );
}
#[test]
fn width64_uses_u128() {
    for (b, c, max, want) in [
        (u64::MAX, 0, 1, 1),
        (0, u64::MAX, u64::MAX, u64::MAX),
        (u64::MAX, u64::MAX, 0, 0),
    ] {
        let (b, c) = pair(CounterPolicy::Modulo { width: 64 }, b, c);
        let bound = AdvanceBound::new(&b, &c, Count::new(max)).unwrap();
        assert_eq!(
            sample_delta(Some(&b), &c, Some(&bound)),
            exact(want),
            "width64-residue"
        );
    }
}
#[test]
fn independent_four_bit_population() {
    let mut cases = 0;
    let mut unbounded = 0;
    for b in 0u128..16 {
        for c in 0u128..16 {
            let (baseline, current) = pair(CounterPolicy::Modulo { width: 4 }, b as u64, c as u64);
            assert_eq!(
                sample_delta(Some(&baseline), &current, None),
                unknown(DeltaUnknown::UnboundedWrap)
            );
            unbounded += 1;
            for maximum in 0u128..=16 {
                // Independent candidate population, never production residue subtraction.
                let advances: Vec<_> = (0..=maximum).filter(|a| (b + a) % 16 == c).collect();
                let want = if maximum == 16 {
                    unknown(DeltaUnknown::UnboundedWrap)
                } else if advances.len() == 1 {
                    exact(advances[0] as u64)
                } else {
                    assert!(advances.is_empty());
                    Err(ContractError::InvalidSample)
                };
                let bound =
                    AdvanceBound::new(&baseline, &current, Count::new(maximum as u64)).unwrap();
                assert_eq!(
                    sample_delta(Some(&baseline), &current, Some(&bound)),
                    want,
                    "enumerated b={b} c={c} maximum={maximum}"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 4352);
    assert_eq!(unbounded, 256);
}
#[test]
fn independent_four_bit_trace_population() {
    let next = [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0];
    assert_eq!(next[15], 0);
    let mut cases = 0;
    for b in 0..16 {
        let mut trace = vec![b];
        for step in 0..16 {
            trace.push(next[trace[step]]);
        }
        if b == 15 {
            assert_eq!(trace[1], 0);
        }
        if b == 0 {
            assert_eq!(trace[0], 0);
            assert_eq!(trace[16], 0);
        }
        for state in 0..16 {
            assert_eq!(trace[..16].iter().filter(|&&v| v == state).count(), 1);
        }
        for c in 0..16 {
            for maximum in 0..=16 {
                // Independent literal transition walk: no modulo, subtraction or first oracle.
                let elapsed: Vec<_> = trace
                    .iter()
                    .enumerate()
                    .take(maximum + 1)
                    .filter_map(|(step, &state)| if state == c { Some(step as u128) } else { None })
                    .collect();
                let want = if maximum == 16 {
                    unknown(DeltaUnknown::UnboundedWrap)
                } else if elapsed.len() == 1 {
                    exact(elapsed[0] as u64)
                } else {
                    assert!(elapsed.is_empty());
                    Err(ContractError::InvalidSample)
                };
                let (baseline, current) =
                    pair(CounterPolicy::Modulo { width: 4 }, b as u64, c as u64);
                let bound =
                    AdvanceBound::new(&baseline, &current, Count::new(maximum as u64)).unwrap();
                assert_eq!(
                    sample_delta(Some(&baseline), &current, Some(&bound)),
                    want,
                    "trace b={b} c={c} maximum={maximum}"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 4352);
}
