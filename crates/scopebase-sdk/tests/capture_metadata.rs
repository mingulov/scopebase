// SPDX-License-Identifier: Apache-2.0
//! SDK03 capture-metadata tests: bounded immutable snapshots of validated
//! neutral observations. Unknown magnitudes and query-partial reasons are
//! preserved exactly, distinct epochs stay in distinct contexts, one context
//! holds at most one snapshot, and snapshot payload shares the binding
//! `retained_bytes` allowance under deterministic N/N+1 accounting. Capture
//! never moves admission and mints no closure authority.
//!
//! Fixture inputs below are independently authored literals; expected values
//! are asserted from those same literals, never derived from production
//! encoding helpers.

#![cfg(feature = "capture")]

use scopebase_capture::neutral::{
    validate_v1, NeutralClaim, NeutralCounter, NeutralLimits, NeutralLoss, NeutralMagnitude,
    NeutralObservationV1, NeutralOrigin, NeutralPolicy, NeutralReason, NeutralSource, NeutralUnit,
};
use scopebase_capture::ContractError;
use scopebase_sdk::context::{
    AppContext, ComponentBinding, ContextError, CAPTURE_CLAIM_BYTES, CAPTURE_COUNTER_BYTES,
    CAPTURE_REASON_BYTES, CAPTURE_SNAPSHOT_BASE_BYTES,
};
use scopebase_sdk::limits::Limits;
use scopebase_sdk::profile::{Admission, CapabilityObservation, CapabilityRequirement, Profile};
use std::time::Duration;

const CAPTURE_ID: [u8; 16] = [0x11; 16];
const PRODUCER_ID: [u8; 16] = [0x22; 16];
const BINDING_ID: [u8; 32] = [0x33; 32];
const CLOCK_ID: [u8; 16] = [0x44; 16];

fn test_limits(retained_bytes: u64) -> Limits {
    Limits {
        input_bytes: 65_536,
        retained_bytes,
        work_items: 64,
        live_owners: 8,
        diagnostic_count: 32,
        diagnostic_bytes: 65_536,
        wait: Duration::from_secs(2),
    }
}

fn test_profile() -> Profile {
    Profile::new("capture", vec![], vec![]).expect("valid profile")
}

fn binding() -> ComponentBinding {
    ComponentBinding {
        package: "scopebase-capture".to_owned(),
        version: "0.1.0".to_owned(),
        features: Vec::new(),
        backend: None,
        artifact_sha256: Some([0x42; 32]),
    }
}

fn source(ordinal: u64) -> NeutralSource {
    NeutralSource {
        capture: CAPTURE_ID,
        producer: PRODUCER_ID,
        ordinal,
        binding: BINDING_ID,
        origin: NeutralOrigin::AdapterReported,
    }
}

fn counter(channel: u32, value: u64) -> NeutralCounter {
    NeutralCounter {
        channel,
        policy: NeutralPolicy::Monotonic,
        clock: CLOCK_ID,
        start: 0,
        end: 1,
        value,
        unit: NeutralUnit::Events,
    }
}

/// Minimal coherent observation: one monotonic counter, epoch 1.
fn minimal_obs() -> NeutralObservationV1 {
    NeutralObservationV1 {
        source: source(1),
        unit: NeutralUnit::Events,
        counters: vec![counter(1, 10)],
        losses: Vec::new(),
        signals: Vec::new(),
        claims: Vec::new(),
        partitions: Vec::new(),
        corrections: Vec::new(),
    }
}

#[test]
fn unknown_stays_unknown() {
    // An unknown loss magnitude is retained as unknown: it must never read
    // back as a measured zero. Source, units and channels are unchanged.
    let mut raw = minimal_obs();
    raw.losses.push(NeutralLoss {
        channel: 7,
        kind: scopebase_capture::neutral::NeutralLossKind::Transport,
        magnitude: NeutralMagnitude::Unknown,
        unit: NeutralUnit::Events,
    });
    let validated = validate_v1(&raw, NeutralLimits::default()).expect("valid fixture");
    let mut context = AppContext::new(test_profile(), test_limits(65_536)).expect("valid context");
    context.capture(&validated).expect("snapshot fits");

    let snapshot = context.capture_snapshot().expect("snapshot retained");
    assert_eq!(snapshot.losses().len(), 1);
    let loss = &snapshot.losses()[0];
    assert_eq!(loss.channel(), 7);
    assert_eq!(loss.magnitude(), NeutralMagnitude::Unknown);
    assert_ne!(
        loss.magnitude(),
        NeutralMagnitude::Exact(0),
        "unknown must not become measured zero"
    );
    assert_eq!(loss.unit(), NeutralUnit::Events);
    // The borrowed report sees the same retained snapshot.
    assert_eq!(context.report().capture, Some(snapshot));
    // Counter, source and epoch survive alongside the loss.
    assert_eq!(snapshot.counters().len(), 1);
    assert_eq!(snapshot.counters()[0].value(), 10);
    assert_eq!(snapshot.unit(), NeutralUnit::Events);
    assert_eq!(snapshot.source().epoch().ordinal(), 1);
}

#[test]
fn query_partial_does_not_become_consumed_loss() {
    // Query-partial is a local report quality marker; retaining the snapshot
    // must not rewrite it into consumed loss or drop sibling reasons.
    let mut raw = minimal_obs();
    raw.claims.push(NeutralClaim {
        claim: 3,
        reasons: vec![NeutralReason::QueryPartial],
    });
    raw.claims.push(NeutralClaim {
        claim: 5,
        reasons: vec![NeutralReason::MissingEvidence, NeutralReason::Ambiguous],
    });
    let validated = validate_v1(&raw, NeutralLimits::default()).expect("valid fixture");
    let mut context = AppContext::new(test_profile(), test_limits(65_536)).expect("valid context");
    context.capture(&validated).expect("snapshot fits");

    let snapshot = context.capture_snapshot().expect("snapshot retained");
    assert_eq!(snapshot.claims().len(), 2);
    assert_eq!(snapshot.claims()[0].claim(), 3);
    assert_eq!(
        snapshot.claims()[0].reasons(),
        &[NeutralReason::QueryPartial]
    );
    assert_eq!(snapshot.claims()[1].claim(), 5);
    assert_eq!(
        snapshot.claims()[1].reasons(),
        &[NeutralReason::MissingEvidence, NeutralReason::Ambiguous]
    );
    assert!(
        !snapshot.claims()[0]
            .reasons()
            .contains(&NeutralReason::ConsumedLoss),
        "query-partial must not become consumed loss"
    );
}

#[test]
fn distinct_epochs_remain_distinct_contexts() {
    // Two coherent observations in different epochs are each valid standalone
    // metadata; each context retains its own epoch, and attempting to combine
    // a second snapshot into an occupied context is refused.
    let mut first = minimal_obs();
    first.source.ordinal = 5;
    let mut second = minimal_obs();
    second.source.ordinal = 6;
    let validated_first = validate_v1(&first, NeutralLimits::default()).expect("epoch 5 valid");
    let validated_second = validate_v1(&second, NeutralLimits::default()).expect("epoch 6 valid");

    let mut left = AppContext::new(test_profile(), test_limits(65_536)).expect("valid context");
    let mut right = AppContext::new(test_profile(), test_limits(65_536)).expect("valid context");
    left.capture(&validated_first).expect("first snapshot");
    right.capture(&validated_second).expect("second snapshot");
    assert_eq!(
        left.capture_snapshot()
            .expect("left")
            .source()
            .epoch()
            .ordinal(),
        5
    );
    assert_eq!(
        right
            .capture_snapshot()
            .expect("right")
            .source()
            .epoch()
            .ordinal(),
        6
    );
    // An attempted incompatible combination is refused by the owning capture
    // operation with its typed variant, keeping the first snapshot.
    assert_eq!(
        left.capture(&validated_second),
        Err(ContextError::CaptureAlreadyPresent)
    );
    assert_eq!(
        left.capture_snapshot()
            .expect("kept")
            .source()
            .epoch()
            .ordinal(),
        5
    );
}

#[test]
fn snapshot_cannot_mint_closure() {
    // Capturing a snapshot never moves admission: an incomplete context stays
    // incomplete (no synthesized quiescence) and a ready context stays ready.
    // The snapshot is an immutable validated copy, independent of later raw
    // input mutation.
    let profile = Profile::new(
        "closure",
        vec![CapabilityRequirement {
            id: "owned-files",
            required: true,
        }],
        vec![],
    )
    .expect("valid profile");
    let mut context = AppContext::new(profile, test_limits(65_536)).expect("valid context");
    context
        .observe(CapabilityObservation {
            id: "owned-files",
            state: scopebase_sdk::profile::CapabilityState::Supported,
            source: "capture-fixture",
        })
        .expect("declared observation");
    // Zero bindings: incomplete before capture.
    assert_eq!(context.admission(), Admission::Incomplete);

    let mut raw = minimal_obs();
    let validated = validate_v1(&raw, NeutralLimits::default()).expect("valid fixture");
    context.capture(&validated).expect("snapshot fits");
    assert_eq!(
        context.admission(),
        Admission::Incomplete,
        "capture must not complete a binding-less context"
    );

    context.bind(binding()).expect("exact binding");
    assert_eq!(context.admission(), Admission::Ready);
    assert_eq!(
        context.capture(&validated),
        Err(ContextError::CaptureAlreadyPresent)
    );
    assert_eq!(context.admission(), Admission::Ready);

    // Mutating the raw input after validation+capture cannot reach the
    // retained immutable copy.
    raw.counters[0].value = 999;
    raw.source.ordinal = 999;
    let snapshot = context.capture_snapshot().expect("snapshot retained");
    assert_eq!(snapshot.counters()[0].value(), 10);
    assert_eq!(snapshot.source().epoch().ordinal(), 1);
}

#[test]
fn snapshot_retained_n_and_n_plus_one() {
    // Deterministic payload accounting: 128 + 32*counters + 8*claims +
    // 4*reasons. Two counters plus one claim with three reasons costs
    // 128 + 64 + 8 + 12 = 212 bytes: retained_bytes 212 fits, 211 refuses
    // with Capacity and stores nothing.
    assert_eq!(CAPTURE_SNAPSHOT_BASE_BYTES, 128);
    assert_eq!(CAPTURE_COUNTER_BYTES, 32);
    assert_eq!(CAPTURE_CLAIM_BYTES, 8);
    assert_eq!(CAPTURE_REASON_BYTES, 4);
    let raw = NeutralObservationV1 {
        source: source(2),
        unit: NeutralUnit::Events,
        counters: vec![counter(1, 5), counter(2, 6)],
        losses: Vec::new(),
        signals: Vec::new(),
        claims: vec![NeutralClaim {
            claim: 9,
            reasons: vec![
                NeutralReason::ConsumedLoss,
                NeutralReason::QueryPartial,
                NeutralReason::Capacity,
            ],
        }],
        partitions: Vec::new(),
        corrections: Vec::new(),
    };
    // Keep the literal shape above honest if helpers drift.
    assert_eq!(raw.counters.len(), 2);
    assert_eq!(raw.claims.len(), 1);
    assert_eq!(raw.claims[0].reasons.len(), 3);
    let validated = validate_v1(&raw, NeutralLimits::default()).expect("valid fixture");
    let exact: u64 = CAPTURE_SNAPSHOT_BASE_BYTES
        + 2 * CAPTURE_COUNTER_BYTES
        + CAPTURE_CLAIM_BYTES
        + 3 * CAPTURE_REASON_BYTES;
    assert_eq!(exact, 212);

    let mut fits = AppContext::new(test_profile(), test_limits(exact)).expect("valid context");
    fits.capture(&validated).expect("exact budget fits");
    assert!(fits.capture_snapshot().is_some());

    let mut short = AppContext::new(test_profile(), test_limits(exact - 1)).expect("valid context");
    assert_eq!(short.capture(&validated), Err(ContextError::Capacity));
    assert_eq!(short.capture_snapshot(), None);
    assert_eq!(short.report().capture, None);
    // The failed capture stored nothing, so a retry against the same short
    // budget fails identically.
    assert_eq!(short.capture(&validated), Err(ContextError::Capacity));
}

#[test]
fn binding_and_snapshot_share_payload_allowance() {
    // Binding string payload and the one snapshot cost share a single
    // retained_bytes allowance with checked arithmetic before cloning. The
    // binding below costs 17 + 5 = 22 bytes; the snapshot costs 212 bytes.
    let validated = validate_v1(&minimal_obs(), NeutralLimits::default()).expect("valid fixture");
    let snapshot_cost: u64 = CAPTURE_SNAPSHOT_BASE_BYTES + CAPTURE_COUNTER_BYTES;
    assert_eq!(snapshot_cost, 160);
    let binding_cost: u64 = "scopebase-capture".len() as u64 + "0.1.0".len() as u64;
    assert_eq!(binding_cost, 22);

    // Exact combined budget fits in bind-then-capture order.
    let mut combined = AppContext::new(test_profile(), test_limits(binding_cost + snapshot_cost))
        .expect("valid context");
    combined.bind(binding()).expect("binding fits");
    combined
        .capture(&validated)
        .expect("snapshot fits remainder");
    assert_eq!(combined.report().bindings.len(), 1);
    assert!(combined.capture_snapshot().is_some());

    // One byte short: the second operation refuses and the first is kept.
    let mut short = AppContext::new(
        test_profile(),
        test_limits(binding_cost + snapshot_cost - 1),
    )
    .expect("valid context");
    short.bind(binding()).expect("binding fits");
    assert_eq!(short.capture(&validated), Err(ContextError::Capacity));
    assert_eq!(short.report().bindings.len(), 1);
    assert_eq!(short.capture_snapshot(), None);

    // Capture-then-bind order shares the same allowance symmetrically.
    let mut reversed = AppContext::new(
        test_profile(),
        test_limits(binding_cost + snapshot_cost - 1),
    )
    .expect("valid context");
    reversed.capture(&validated).expect("snapshot fits");
    assert_eq!(reversed.bind(binding()), Err(ContextError::Capacity));
    assert_eq!(reversed.report().bindings.len(), 0);
    assert!(reversed.capture_snapshot().is_some());
}

#[test]
fn second_capture_snapshot_refused() {
    // At most one snapshot per context: a repeat -- identical or
    // different-epoch -- is refused typed, keeping the original.
    let validated = validate_v1(&minimal_obs(), NeutralLimits::default()).expect("valid fixture");
    let mut other = minimal_obs();
    other.source.ordinal = 77;
    let validated_other = validate_v1(&other, NeutralLimits::default()).expect("valid fixture");

    let mut context = AppContext::new(test_profile(), test_limits(65_536)).expect("valid context");
    context.capture(&validated).expect("first snapshot");
    assert_eq!(
        context.capture(&validated),
        Err(ContextError::CaptureAlreadyPresent)
    );
    assert_eq!(
        context.capture(&validated_other),
        Err(ContextError::CaptureAlreadyPresent)
    );
    let kept = context.capture_snapshot().expect("original kept");
    assert_eq!(kept.source().epoch().ordinal(), 1);
    assert_eq!(kept.counters()[0].value(), 10);
}

#[test]
fn hard_maxima_refused_before_capture() {
    // CP10 hard maxima stay hard: 4,096 counters and 4,096 claims validate;
    // 4,097 of either is refused typed by validate_v1 before the SDK ever
    // sees a snapshot. Sixteen reasons per claim is the code maximum.
    assert_eq!(scopebase_capture::neutral::NEUTRAL_MAX_COUNTERS, 4096);
    assert_eq!(scopebase_capture::neutral::NEUTRAL_MAX_CLAIMS, 4096);
    assert_eq!(
        scopebase_capture::neutral::NEUTRAL_MAX_REASONS_PER_CLAIM,
        16
    );

    let mut full = NeutralObservationV1 {
        source: source(3),
        unit: NeutralUnit::Events,
        counters: (0..4096)
            .map(|channel| counter(channel, u64::from(channel)))
            .collect(),
        losses: Vec::new(),
        signals: Vec::new(),
        claims: (0..4096)
            .map(|claim| NeutralClaim {
                claim,
                reasons: Vec::new(),
            })
            .collect(),
        partitions: Vec::new(),
        corrections: Vec::new(),
    };
    let validated = validate_v1(&full, NeutralLimits::default()).expect("maxima valid");
    assert_eq!(validated.counters().len(), 4096);
    assert_eq!(validated.claims().len(), 4096);
    // The maxima snapshot still fits its exact deterministic cost.
    let cost: u64 =
        CAPTURE_SNAPSHOT_BASE_BYTES + 4096 * CAPTURE_COUNTER_BYTES + 4096 * CAPTURE_CLAIM_BYTES;
    let mut context = AppContext::new(test_profile(), test_limits(cost)).expect("valid context");
    context.capture(&validated).expect("maxima snapshot fits");

    full.counters.push(counter(4096, 0));
    assert_eq!(
        validate_v1(&full, NeutralLimits::default()),
        Err(ContractError::CapacityExceeded)
    );
    full.counters.pop();
    full.claims.push(NeutralClaim {
        claim: 4096,
        reasons: Vec::new(),
    });
    assert_eq!(
        validate_v1(&full, NeutralLimits::default()),
        Err(ContractError::CapacityExceeded)
    );
}
