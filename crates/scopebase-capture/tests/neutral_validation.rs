// SPDX-License-Identifier: Apache-2.0
//! CP10 neutral validation: canonical v1 semantics without JSON.
#[path = "support/cp10_cases.rs"]
mod cases;
use cases::*;
use scopebase_capture::{
    neutral::{
        parse_count_u64, validate_v1, NeutralClaim, NeutralCorrection, NeutralLimits,
        NeutralMagnitude, NeutralPartition, NeutralPolicy, NeutralReason, NeutralSignal,
        NeutralUnit,
    },
    ContractError,
};

#[test]
fn neutral_known_zero_and_unknown_differ() {
    let mut obs = observation();
    obs.losses.push(neutral_loss(1));
    obs.losses.push({
        let mut loss = neutral_loss(2);
        loss.magnitude = NeutralMagnitude::Unknown;
        loss
    });
    obs.losses.push({
        let mut loss = neutral_loss(3);
        loss.magnitude = NeutralMagnitude::AtLeast(0);
        loss
    });
    let validated = validate_v1(&obs, NeutralLimits::default()).unwrap();
    let magnitudes: Vec<NeutralMagnitude> = validated
        .losses()
        .iter()
        .map(|loss| loss.magnitude())
        .collect();
    assert_eq!(
        magnitudes,
        [
            NeutralMagnitude::Exact(0),
            NeutralMagnitude::Unknown,
            NeutralMagnitude::AtLeast(0)
        ],
        "CP10:known zero, unknown and lower-bound zero stay distinct"
    );
    assert_ne!(
        NeutralMagnitude::Exact(0),
        NeutralMagnitude::Unknown,
        "CP10:must not conflate known zero with unknown"
    );
}

#[test]
fn neutral_count_limit_precedes_clone() {
    let mut obs = observation();
    obs.counters.push(neutral_counter(8));
    obs.counters.push(neutral_counter(9));
    let before = obs.clone();
    let tight = NeutralLimits {
        counters: 2,
        claims: 4096,
        reasons_per_claim: 16,
    };
    assert_eq!(
        validate_v1(&obs, tight),
        Err(ContractError::CapacityExceeded),
        "CP10:counter cardinality refuses before any clone"
    );
    assert_eq!(
        obs, before,
        "CP10:refusal leaves the borrowed input untouched"
    );
    let mut obs = observation();
    obs.claims.push(NeutralClaim {
        claim: 1,
        reasons: Vec::new(),
    });
    obs.claims.push(NeutralClaim {
        claim: 2,
        reasons: Vec::new(),
    });
    let tight = NeutralLimits {
        counters: 4096,
        claims: 1,
        reasons_per_claim: 16,
    };
    assert_eq!(
        validate_v1(&obs, tight),
        Err(ContractError::CapacityExceeded),
        "CP10:claim cardinality refuses"
    );
    let mut obs = observation();
    obs.claims.push(NeutralClaim {
        claim: 1,
        reasons: vec![NeutralReason::QueryPartial, NeutralReason::Ambiguous],
    });
    let tight = NeutralLimits {
        counters: 4096,
        claims: 4096,
        reasons_per_claim: 1,
    };
    assert_eq!(
        validate_v1(&obs, tight),
        Err(ContractError::CapacityExceeded),
        "CP10:reason cardinality refuses"
    );
    for limits in [
        NeutralLimits {
            counters: 4097,
            claims: 4096,
            reasons_per_claim: 16,
        },
        NeutralLimits {
            counters: 4096,
            claims: 4097,
            reasons_per_claim: 16,
        },
        NeutralLimits {
            counters: 4096,
            claims: 4096,
            reasons_per_claim: 17,
        },
    ] {
        assert_eq!(
            validate_v1(&observation(), limits),
            Err(ContractError::CapacityExceeded),
            "CP10:limits above the hard maxima refuse"
        );
    }
    assert_eq!(
        NeutralLimits::default(),
        NeutralLimits {
            counters: 4096,
            claims: 4096,
            reasons_per_claim: 16
        },
        "CP10:default limits are the hard maxima"
    );
    let exact = NeutralLimits {
        counters: 1,
        claims: 0,
        reasons_per_claim: 0,
    };
    assert!(
        validate_v1(&observation(), exact).is_ok(),
        "CP10:exactly-at-limit input succeeds"
    );
}

#[test]
fn duplicate_channels_claims_or_reasons_refuse() {
    let mut obs = observation();
    obs.counters.push(neutral_counter(7));
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::DuplicateKey),
        "CP10:duplicate counter channel refuses"
    );
    let mut obs = observation();
    obs.losses.push(neutral_loss(4));
    obs.losses.push(neutral_loss(4));
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::DuplicateKey),
        "CP10:duplicate loss channel refuses"
    );
    let mut obs = observation();
    obs.signals.push(neutral_signal(5));
    obs.signals.push(neutral_signal(5));
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::DuplicateKey),
        "CP10:duplicate signal channel refuses"
    );
    let mut obs = observation();
    for _ in 0..2 {
        obs.claims.push(NeutralClaim {
            claim: 3,
            reasons: Vec::new(),
        });
    }
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::DuplicateKey),
        "CP10:duplicate claim refuses"
    );
    let mut obs = observation();
    obs.claims.push(NeutralClaim {
        claim: 3,
        reasons: vec![NeutralReason::Capacity, NeutralReason::Capacity],
    });
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::DuplicateKey),
        "CP10:duplicate reason refuses"
    );
}

#[test]
fn signal_unit_mismatch_refuses() {
    let mut obs = observation();
    obs.signals.push(NeutralSignal {
        channel: 6,
        observed: 1,
        cap: 9,
        unit: NeutralUnit::Events,
    });
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::DomainMismatch),
        "CP10:signal outside diagnostic-signals refuses"
    );
    let mut obs = observation();
    obs.signals.push(neutral_signal(6));
    let validated = validate_v1(&obs, NeutralLimits::default()).unwrap();
    assert_eq!(
        validated.signals()[0].observed(),
        1 - 1,
        "CP10:twin keeps zero"
    );
    let mut obs = observation();
    obs.counters[0].unit = NeutralUnit::Records;
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::DomainMismatch),
        "CP10:counter outside the document unit refuses"
    );
}

#[test]
fn precision_u64_max_and_overflow() {
    for (text, want) in [
        ("0", 0u64),
        ("42", 42u64),
        ("9007199254740993", 9_007_199_254_740_993u64),
        ("18446744073709551615", u64::MAX),
    ] {
        assert_eq!(
            parse_count_u64(text),
            Ok(want),
            "CP10:canonical {text} parses exactly"
        );
    }
    assert_eq!(
        parse_count_u64("9007199254740993").unwrap(),
        9_007_199_254_740_993u64,
        "CP10:2^53+1 survives without float coercion"
    );
    for bad in [
        "",
        "00",
        "01",
        "+1",
        "-1",
        " 42",
        "42 ",
        "4x",
        "0x1A",
        "18446744073709551616",
        "99999999999999999999999",
        "111111111111111111111",
    ] {
        assert_eq!(
            parse_count_u64(bad),
            Err(ContractError::InvalidSample),
            "CP10:non-canonical {bad:?} refuses"
        );
    }
    let mut obs = observation();
    obs.counters[0].value = u64::MAX;
    let validated = validate_v1(&obs, NeutralLimits::default()).unwrap();
    assert_eq!(
        validated.counters()[0].value(),
        u64::MAX,
        "CP10:exact MAX is a valid count"
    );
    let obs = NeutralPartition {
        total: u64::MAX,
        parts: vec![u64::MAX, 1],
        unit: NeutralUnit::Events,
    };
    let mut full = observation();
    full.partitions.push(obs);
    assert_eq!(
        validate_v1(&full, NeutralLimits::default()),
        Err(ContractError::ArithmeticOverflow),
        "CP10:part-sum overflow refuses before comparison"
    );
}

#[test]
fn neutral_partitions_and_corrections_use_constructors() {
    let mut obs = observation();
    obs.partitions.push(NeutralPartition {
        total: 9,
        parts: vec![2, 3, 5],
        unit: NeutralUnit::Events,
    });
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::ConservationMismatch),
        "CP10:partition 9!=2+3+5 refuses"
    );
    let mut obs = observation();
    obs.partitions.push(NeutralPartition {
        total: 10,
        parts: vec![2, 3, 5],
        unit: NeutralUnit::Events,
    });
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default())
            .unwrap()
            .partition_count(),
        1,
        "CP10:conserving partition is admitted"
    );
    let mut obs = observation();
    obs.corrections.push(NeutralCorrection { from: 0, to: 2 });
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::StaleRevision),
        "CP10:correction 0->2 refuses"
    );
    let mut obs = observation();
    obs.corrections.push(NeutralCorrection { from: 0, to: 1 });
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default())
            .unwrap()
            .correction_count(),
        1,
        "CP10:single-step correction is admitted"
    );
}

#[test]
fn neutral_policy_and_interval_refusals_match_constructors() {
    let mut obs = observation();
    obs.counters[0].policy = NeutralPolicy::Saturating { maximum: 4 };
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::InvalidSample),
        "CP10:value above saturating maximum refuses"
    );
    let mut obs = observation();
    obs.counters[0].policy = NeutralPolicy::Modulo { width: 0 };
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::InvalidSample),
        "CP10:modulo width zero refuses"
    );
    let mut obs = observation();
    obs.counters[0].start = 10;
    obs.counters[0].end = 9;
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::InvalidInterval),
        "CP10:reversed interval refuses"
    );
    let mut obs = observation();
    obs.signals.push(NeutralSignal {
        channel: 6,
        observed: 2,
        cap: 0,
        unit: NeutralUnit::DiagnosticSignals,
    });
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::InvalidSample),
        "CP10:zero signal cap refuses"
    );
    let mut obs = observation();
    obs.signals.push(NeutralSignal {
        channel: 6,
        observed: 10,
        cap: 9,
        unit: NeutralUnit::DiagnosticSignals,
    });
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::InvalidSample),
        "CP10:observed beyond cap refuses"
    );
}

#[test]
fn synthetic_origin_cannot_promote() {
    use scopebase_capture::domain::Origin;
    let validated = validate_v1(&observation(), NeutralLimits::default()).unwrap();
    assert_eq!(
        validated.source().origin(),
        Origin::Synthetic,
        "CP10:synthetic stays synthetic"
    );
    for (origin, want) in [
        (
            scopebase_capture::neutral::NeutralOrigin::AdapterReported,
            Origin::AdapterReported,
        ),
        (
            scopebase_capture::neutral::NeutralOrigin::Replayed,
            Origin::Replayed,
        ),
    ] {
        let mut obs = observation();
        obs.source.origin = origin;
        let validated = validate_v1(&obs, NeutralLimits::default()).unwrap();
        assert_eq!(
            validated.source().origin(),
            want,
            "CP10:origin is preserved"
        );
    }
    let mut obs = observation();
    obs.source.capture = [0; 16];
    assert_eq!(
        validate_v1(&obs, NeutralLimits::default()),
        Err(ContractError::InvalidId),
        "CP10:all-zero capture id refuses while ordinal zero stays valid"
    );
}
