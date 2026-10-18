// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::{domain::*, time::*, ContractError};
fn clock(n: u8) -> ClockDomain {
    ClockDomain::new([n; 16]).unwrap()
}
fn t(n: u64) -> Timestamp {
    Timestamp::new(clock(1), n)
}
#[test]
fn half_open_zero_and_clock_mismatch() {
    for (start, end, duration) in [(0, 0, 0), (5, 5, 0), (5, 6, 1), (0, u64::MAX, u64::MAX)] {
        let a = t(start);
        let b = t(end);
        let interval = TimeInterval::new(a.clone(), b.clone()).unwrap();
        assert_eq!(interval.duration_ns(), duration);
        assert_eq!(interval.start(), &a);
        assert_eq!(interval.end(), &b);
        assert_eq!(a.clock(), clock(1));
        assert_eq!(a.ticks(), start);
        assert_eq!(b.ticks(), end);
    }
    assert_eq!(
        TimeInterval::new(t(6), t(5)),
        Err(ContractError::InvalidInterval)
    );
    assert_eq!(
        TimeInterval::new(t(5), Timestamp::new(clock(2), 5)),
        Err(ContractError::DomainMismatch)
    );
    assert_eq!(
        TimeInterval::new(t(6), Timestamp::new(clock(2), 5)),
        Err(ContractError::DomainMismatch)
    );
    for start in 0..=12 {
        for end in 0..=12 {
            let got = TimeInterval::new(t(start), t(end));
            if end >= start {
                assert_eq!(
                    got.unwrap().duration_ns() as u128,
                    end as u128 - start as u128
                );
            } else {
                assert_eq!(got, Err(ContractError::InvalidInterval));
            }
        }
    }
}
#[test]
fn k_reversed_interval_vectors_refuse() {
    // K d153f3a evidence.rs:324–349,462–482 constructs inclusive reversed
    // intervals, then refuses evidence validation. Our constructor refuses now.
    assert_eq!(
        TimeInterval::new(t(200), t(100)),
        Err(ContractError::InvalidInterval)
    );
    assert_eq!(
        TimeInterval::new(t(100), t(200)).unwrap().duration_ns(),
        100
    );
}
#[test]
fn inclusive_donor_and_half_open_membership_are_distinct() {
    // Test-only conversion: discrete ns, explicitly same clock and no suspend conversion.
    fn converted(a: u64, b: u64) -> Result<TimeInterval, ContractError> {
        let end = b.checked_add(1).ok_or(ContractError::ArithmeticOverflow)?;
        TimeInterval::new(t(a), t(end))
    }
    let singleton = converted(5, 5).unwrap();
    assert_eq!(singleton.duration_ns(), 1);
    let points: Vec<_> = (0..=10).filter(|x| 5 <= *x && *x <= 5).collect();
    assert_eq!(points, vec![5]);
    let converted_points: Vec<_> = (0..=10)
        .filter(|x| singleton.start().ticks() <= *x && *x < singleton.end().ticks())
        .collect();
    assert_eq!(converted_points, points);
    assert_eq!(
        converted(0, u64::MAX),
        Err(ContractError::ArithmeticOverflow)
    );
    let inclusive_shared: Vec<_> = (0..=10)
        .filter(|x| 2 <= *x && *x <= 5 && 5 <= *x && *x <= 8)
        .collect();
    assert_eq!(inclusive_shared, vec![5]);
    let a = TimeInterval::new(t(2), t(5)).unwrap();
    let b = TimeInterval::new(t(5), t(8)).unwrap();
    let shared: Vec<_> = (0..=10)
        .filter(|x| {
            a.start().ticks() <= *x
                && *x < a.end().ticks()
                && b.start().ticks() <= *x
                && *x < b.end().ticks()
        })
        .collect();
    assert!(shared.is_empty());
    for a in 0..=7 {
        for b in a..=7 {
            let interval = converted(a, b).unwrap();
            let inclusive: Vec<_> = (0..=8).filter(|x| a <= *x && *x <= b).collect();
            let half_open: Vec<_> = (0..=8)
                .filter(|x| interval.start().ticks() <= *x && *x < interval.end().ticks())
                .collect();
            assert_eq!(half_open, inclusive);
            assert_eq!(interval.duration_ns() as usize, inclusive.len());
        }
    }
}
#[test]
fn debug_redacts_nested_identity_payloads() {
    let c = CaptureId::new([171; 16]).unwrap();
    let p = ProducerId::new([205; 16]).unwrap();
    let b = BindingId::new([239; 32]).unwrap();
    let clock = ClockDomain::new([183; 16]).unwrap();
    let epoch = Epoch::new(c, p, 7);
    let source = SourceRef::new(epoch.clone(), b, Origin::Synthetic);
    let timestamp = Timestamp::new(clock, 11);
    let interval = TimeInterval::new(timestamp.clone(), Timestamp::new(clock, 12)).unwrap();
    let values: [(&dyn std::fmt::Debug, &str); 8] = [
        (&c, "CaptureId"),
        (&p, "ProducerId"),
        (&b, "BindingId"),
        (&clock, "ClockDomain"),
        (&epoch, "Epoch"),
        (&source, "SourceRef"),
        (&timestamp, "Timestamp"),
        (&interval, "TimeInterval"),
    ];
    for (value, kind) in values {
        let text = format!("{value:?}");
        assert!(text.contains(kind));
        for sentinel in [
            "171", "205", "239", "183", "0xab", "0xcd", "0xef", "0xb7", "[",
        ] {
            assert!(
                !text.to_lowercase().contains(sentinel),
                "opaque payload disclosed: {text}"
            );
        }
        assert!(text.len() < 512);
    }
    assert_eq!(format!("{c:?}"), "CaptureId(<redacted>)");
    assert_eq!(format!("{p:?}"), "ProducerId(<redacted>)");
    assert_eq!(format!("{b:?}"), "BindingId(<redacted>)");
    assert_eq!(format!("{clock:?}"), "ClockDomain(<redacted>)");
}
