// SPDX-License-Identifier: Apache-2.0
//! SDK03 consumer-linked conformance: the SDK proves it validates what it
//! consumes. The [`consumer`] adapter binds the actual production component,
//! validates raw input through CP10 `validate_v1`, and retains the snapshot;
//! the independent oracle below holds literal expected digests and summary
//! bytes without calling the adapter. Mismatched metadata, an unconformant
//! consumer that skips validation, and a wrong production build digest each
//! fail with a distinct typed failure.

#![cfg(feature = "capture")]

#[path = "adapters/consumer.rs"]
mod consumer;

use consumer::{
    check_conformance, check_observation_bytes, ConformanceFailure, ConsumerAdapter, ConsumerError,
    OracleExpectation, CONSUME_SCHEMA_ID, CONSUME_SCHEMA_REVISION, CONSUME_STEP_ID,
};
use scopebase_capture::domain::{BindingId, CaptureId, Origin, ProducerId};
use scopebase_capture::neutral::{
    NeutralClaim, NeutralCounter, NeutralLoss, NeutralLossKind, NeutralMagnitude,
    NeutralObservationV1, NeutralOrigin, NeutralPolicy, NeutralReason, NeutralSignal,
    NeutralSource, NeutralUnit,
};
use scopebase_capture::ContractError;
use scopebase_sdk::context::{AppContext, ComponentBinding};
use scopebase_sdk::limits::Limits;
use scopebase_sdk::profile::Profile;
use scopebase_testkit::Digest256;
use std::time::Duration;

// --- Independently authored fixture literals. ---

const CAPTURE_ID: [u8; 16] = [0xA1; 16];
const PRODUCER_ID: [u8; 16] = [0xB2; 16];
const ARTIFACT_BINDING: [u8; 32] = [0xC3; 32];
const CLOCK_ID: [u8; 16] = [0xD4; 16];
const ARTIFACT_DIGEST: [u8; 32] = [0x42; 32];
const WRONG_DIGEST: [u8; 32] = [0x43; 32];

fn test_limits() -> Limits {
    Limits {
        input_bytes: 65_536,
        retained_bytes: 65_536,
        work_items: 64,
        live_owners: 8,
        diagnostic_count: 32,
        diagnostic_bytes: 65_536,
        wait: Duration::from_secs(2),
    }
}

fn binding_with_digest(digest: Option<[u8; 32]>) -> ComponentBinding {
    ComponentBinding {
        package: "scopebase-capture".to_owned(),
        version: "0.1.0".to_owned(),
        features: vec!["capture".to_owned()],
        backend: None,
        artifact_sha256: digest,
    }
}

/// Raw observation literals: epoch 9, synthetic origin, records unit, one
/// saturating counter (value 42), one transport at-least loss, one discovery
/// unknown loss, one capped signal, and one claim with query-partial plus
/// ambiguous reasons.
fn raw_observation() -> NeutralObservationV1 {
    NeutralObservationV1 {
        source: NeutralSource {
            capture: CAPTURE_ID,
            producer: PRODUCER_ID,
            ordinal: 9,
            binding: ARTIFACT_BINDING,
            origin: NeutralOrigin::Synthetic,
        },
        unit: NeutralUnit::Records,
        counters: vec![NeutralCounter {
            channel: 1,
            policy: NeutralPolicy::Saturating { maximum: 100 },
            clock: CLOCK_ID,
            start: 5,
            end: 10,
            value: 42,
            unit: NeutralUnit::Records,
        }],
        losses: vec![
            NeutralLoss {
                channel: 2,
                kind: NeutralLossKind::Transport,
                magnitude: NeutralMagnitude::AtLeast(3),
                unit: NeutralUnit::Records,
            },
            NeutralLoss {
                channel: 4,
                kind: NeutralLossKind::Discovery,
                magnitude: NeutralMagnitude::Unknown,
                unit: NeutralUnit::Records,
            },
        ],
        signals: vec![NeutralSignal {
            channel: 3,
            observed: 2,
            cap: 5,
            unit: NeutralUnit::DiagnosticSignals,
        }],
        claims: vec![NeutralClaim {
            claim: 7,
            reasons: vec![NeutralReason::QueryPartial, NeutralReason::Ambiguous],
        }],
        partitions: Vec::new(),
        corrections: Vec::new(),
    }
}

/// Independent oracle encoding of the fixture above, written literally from
/// the adapter's documented layout: magic, ordinal 9, synthetic origin,
/// records unit, the exact counter/loss/signal/claim rows, and zero
/// partition/correction counts. This never calls the adapter.
fn oracle_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"SDK03C1\0");
    out.extend_from_slice(&9u64.to_le_bytes());
    out.push(2); // Synthetic
    out.push(2); // Records
    out.extend_from_slice(&1u32.to_le_bytes()); // one counter
    out.extend_from_slice(&1u32.to_le_bytes()); // channel
    out.push(2); // Saturating
    out.extend_from_slice(&100u64.to_le_bytes()); // maximum
    out.extend_from_slice(&5u64.to_le_bytes()); // start
    out.extend_from_slice(&10u64.to_le_bytes()); // end
    out.extend_from_slice(&42u64.to_le_bytes()); // value
    out.extend_from_slice(&2u32.to_le_bytes()); // two losses
    out.extend_from_slice(&2u32.to_le_bytes()); // channel
    out.push(2); // Transport
    out.push(2); // AtLeast
    out.extend_from_slice(&3u64.to_le_bytes()); // magnitude
    out.extend_from_slice(&4u32.to_le_bytes()); // channel
    out.push(1); // Discovery
    out.push(0); // Unknown
    out.extend_from_slice(&0u64.to_le_bytes()); // no magnitude
    out.extend_from_slice(&1u32.to_le_bytes()); // one signal
    out.extend_from_slice(&3u32.to_le_bytes()); // channel
    out.push(2); // observed
    out.push(5); // cap
    out.extend_from_slice(&1u32.to_le_bytes()); // one claim
    out.extend_from_slice(&7u32.to_le_bytes()); // claim id
    out.extend_from_slice(&2u32.to_le_bytes()); // two reasons
    out.push(3); // QueryPartial
    out.push(4); // Ambiguous
    out.extend_from_slice(&0u32.to_le_bytes()); // partitions
    out.extend_from_slice(&0u32.to_le_bytes()); // corrections
    out
}

fn digest_of(bytes: &[u8; 32]) -> Digest256 {
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap());
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap());
    }
    Digest256::parse(&hex).expect("valid digest hex")
}

fn oracle_with_digest(digest: [u8; 32]) -> OracleExpectation {
    OracleExpectation {
        expected_digest: digest_of(&digest),
        expected_bytes: oracle_bytes(),
    }
}

fn attach(digest: Option<[u8; 32]>) -> ConsumerAdapter {
    let profile = Profile::new("consumer", vec![], vec![]).expect("valid profile");
    let context = AppContext::new(profile, test_limits()).expect("valid context");
    ConsumerAdapter::attach(context, binding_with_digest(digest)).expect("binds")
}

// --- The unconformant consumer: encodes raw rows without validating. ---

/// A consumer that skips `validate_v1` and summarizes raw rows directly. For
/// coherent input its bytes must equal the validating adapter's (proving the
/// mirror differs only by skipping validation); for incoherent input it
/// happily encodes rows the validator refuses, so conformance must fail it.
struct UnvalidatedConsumer;

impl UnvalidatedConsumer {
    fn origin_tag(origin: NeutralOrigin) -> u8 {
        match origin {
            NeutralOrigin::AdapterReported => 1,
            NeutralOrigin::Synthetic => 2,
            NeutralOrigin::Replayed => 3,
        }
    }

    fn unit_tag(unit: NeutralUnit) -> u8 {
        match unit {
            NeutralUnit::Events => 1,
            NeutralUnit::Records => 2,
            NeutralUnit::Bytes => 3,
            NeutralUnit::Objects => 4,
            NeutralUnit::Attempts => 5,
            NeutralUnit::Nonexecutions => 6,
            NeutralUnit::DiagnosticSignals => 7,
        }
    }

    fn observe_raw(raw: &NeutralObservationV1) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"SDK03C1\0");
        out.extend_from_slice(&raw.source.ordinal.to_le_bytes());
        out.push(Self::origin_tag(raw.source.origin));
        out.push(Self::unit_tag(raw.unit));
        out.extend_from_slice(&(raw.counters.len() as u32).to_le_bytes());
        for counter in &raw.counters {
            out.extend_from_slice(&counter.channel.to_le_bytes());
            let (tag, param) = match counter.policy {
                NeutralPolicy::Monotonic => (1, 0),
                NeutralPolicy::Saturating { maximum } => (2, maximum),
                NeutralPolicy::Modulo { width } => (3, u64::from(width)),
            };
            out.push(tag);
            out.extend_from_slice(&param.to_le_bytes());
            out.extend_from_slice(&counter.start.to_le_bytes());
            out.extend_from_slice(&counter.end.to_le_bytes());
            out.extend_from_slice(&counter.value.to_le_bytes());
        }
        out.extend_from_slice(&(raw.losses.len() as u32).to_le_bytes());
        for loss in &raw.losses {
            out.extend_from_slice(&loss.channel.to_le_bytes());
            out.push(match loss.kind {
                NeutralLossKind::Discovery => 1,
                NeutralLossKind::Transport => 2,
                NeutralLossKind::KernelNonexecution => 3,
                NeutralLossKind::Attribution => 4,
                NeutralLossKind::QueueOverflow => 5,
                NeutralLossKind::MalformedInput => 6,
                NeutralLossKind::DiagnosticTruncation => 7,
            });
            let (tag, value) = match loss.magnitude {
                NeutralMagnitude::Unknown => (0, 0),
                NeutralMagnitude::Exact(value) => (1, value),
                NeutralMagnitude::AtLeast(value) => (2, value),
            };
            out.push(tag);
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&(raw.signals.len() as u32).to_le_bytes());
        for signal in &raw.signals {
            out.extend_from_slice(&signal.channel.to_le_bytes());
            out.push(signal.observed);
            out.push(signal.cap);
        }
        out.extend_from_slice(&(raw.claims.len() as u32).to_le_bytes());
        for claim in &raw.claims {
            out.extend_from_slice(&claim.claim.to_le_bytes());
            out.extend_from_slice(&(claim.reasons.len() as u32).to_le_bytes());
            for reason in &claim.reasons {
                out.push(match reason {
                    NeutralReason::ConsumedLoss => 1,
                    NeutralReason::MissingEvidence => 2,
                    NeutralReason::QueryPartial => 3,
                    NeutralReason::Ambiguous => 4,
                    NeutralReason::Capacity => 5,
                });
            }
        }
        out.extend_from_slice(&(raw.partitions.len() as u32).to_le_bytes());
        out.extend_from_slice(&(raw.corrections.len() as u32).to_le_bytes());
        out
    }
}

#[test]
fn conformant_consumer_passes_conformance() {
    // The validating consumer binds the actual component, consumes the raw
    // fixture, and matches the independent oracle on both digest and bytes.
    let mut adapter = attach(Some(ARTIFACT_DIGEST));
    adapter
        .consume(&raw_observation())
        .expect("valid consumption");

    let oracle = oracle_with_digest(ARTIFACT_DIGEST);
    assert_eq!(check_conformance(&adapter, &oracle), Ok(()));

    // The subject carries the actual production coordinate verbatim.
    let subject = adapter.subject().expect("exact binding subjects");
    assert_eq!(subject.package_name(), "scopebase-capture");
    assert_eq!(subject.package_version(), "0.1.0");
    assert_eq!(subject.features(), &vec!["capture".to_owned()]);
    assert!(subject.backend().is_none());
    assert_eq!(*subject.source_sha256(), digest_of(&ARTIFACT_DIGEST));

    // The observation is schema-tagged bounded bytes with its consume step.
    let observation = adapter.observation().expect("snapshot observes");
    assert_eq!(observation.schema_id().as_str(), CONSUME_SCHEMA_ID);
    assert_eq!(*observation.schema_revision(), CONSUME_SCHEMA_REVISION);
    assert_eq!(
        observation
            .completed_steps()
            .iter()
            .map(|step| step.as_str())
            .collect::<Vec<_>>(),
        vec![CONSUME_STEP_ID]
    );
    assert_eq!(observation.bytes().as_slice(), oracle_bytes().as_slice());

    // Opaque identities are preserved exactly through validation+retention.
    let snapshot = adapter.context().capture_snapshot().expect("snapshot");
    assert_eq!(
        snapshot.source().epoch().capture(),
        CaptureId::new(CAPTURE_ID).expect("nonzero fixture id")
    );
    assert_eq!(
        snapshot.source().epoch().producer(),
        ProducerId::new(PRODUCER_ID).expect("nonzero fixture id")
    );
    assert_eq!(
        snapshot.source().binding(),
        BindingId::new(ARTIFACT_BINDING).expect("nonzero fixture id")
    );
    assert_eq!(snapshot.source().origin(), Origin::Synthetic);
    // The unknown loss magnitude survives the full validate-retain path.
    assert_eq!(snapshot.losses().len(), 2);
    assert_eq!(snapshot.losses()[1].magnitude(), NeutralMagnitude::Unknown);
}

#[test]
fn metadata_consumed_mismatch_refused_typed() {
    // Incoherent raw input is refused typed at consumption, before anything
    // is retained: a duplicate counter channel keeps its CP10 DuplicateKey.
    let mut adapter = attach(Some(ARTIFACT_DIGEST));
    let mut incoherent = raw_observation();
    incoherent.counters.push(incoherent.counters[0].clone());
    match adapter.consume(&incoherent) {
        Err(ConsumerError::Contract(ContractError::DuplicateKey)) => {}
        other => panic!("expected typed DuplicateKey refusal, got {other:?}"),
    }
    assert!(!adapter.has_snapshot());
    assert_eq!(
        check_conformance(&adapter, &oracle_with_digest(ARTIFACT_DIGEST)),
        Err(ConformanceFailure::AdapterIncomplete {
            snapshot_present: false
        })
    );

    // A consumed snapshot that disagrees with the oracle fails typed with
    // the exact first differing offset: value byte 51 (oracle 43 vs 42).
    let mut adapter = attach(Some(ARTIFACT_DIGEST));
    adapter
        .consume(&raw_observation())
        .expect("valid consumption");
    let mut wrong_value = oracle_bytes();
    assert_eq!(wrong_value[51], 42, "pin the value offset");
    wrong_value[51] = 43;
    assert_eq!(
        check_conformance(
            &adapter,
            &OracleExpectation {
                expected_digest: digest_of(&ARTIFACT_DIGEST),
                expected_bytes: wrong_value,
            }
        ),
        Err(ConformanceFailure::ObservationMismatch {
            expected_len: oracle_bytes().len(),
            found_len: oracle_bytes().len(),
            first_diff: Some(51),
        })
    );

    // A rewritten claim reason fails at its own offset: reason byte 113
    // (oracle ConsumedLoss vs retained QueryPartial).
    let mut wrong_reason = oracle_bytes();
    assert_eq!(wrong_reason[113], 3, "pin the reason offset");
    wrong_reason[113] = 1;
    assert_eq!(
        check_conformance(
            &adapter,
            &OracleExpectation {
                expected_digest: digest_of(&ARTIFACT_DIGEST),
                expected_bytes: wrong_reason,
            }
        ),
        Err(ConformanceFailure::ObservationMismatch {
            expected_len: oracle_bytes().len(),
            found_len: oracle_bytes().len(),
            first_diff: Some(113),
        })
    );
}

#[test]
fn unconformant_consumer_fails_conformance() {
    // The validation-skipping mirror agrees with the validating adapter on
    // coherent input, proving it differs only by skipping validation.
    let mut adapter = attach(Some(ARTIFACT_DIGEST));
    adapter
        .consume(&raw_observation())
        .expect("valid consumption");
    let observed = adapter.observation().expect("snapshot observes");
    assert_eq!(
        UnvalidatedConsumer::observe_raw(&raw_observation()).as_slice(),
        observed.bytes().as_slice(),
        "mirror must match on coherent input"
    );

    // For incoherent input the conformant path refuses typed while the
    // unvalidated mirror encodes the refused rows anyway: its bytes carry
    // two counter rows where the oracle expects one, so conformance fails
    // it at the counter-count field (offset 18) with a longer body.
    let mut incoherent = raw_observation();
    incoherent.counters.push(incoherent.counters[0].clone());
    let mut refusing = attach(Some(ARTIFACT_DIGEST));
    match refusing.consume(&incoherent) {
        Err(ConsumerError::Contract(ContractError::DuplicateKey)) => {}
        other => panic!("expected typed DuplicateKey refusal, got {other:?}"),
    }
    let forged = UnvalidatedConsumer::observe_raw(&incoherent);
    let oracle = oracle_bytes();
    assert_ne!(forged.len(), oracle.len());
    assert_eq!(forged[18], 2, "forged count carries both rows");
    assert_eq!(oracle[18], 1, "oracle count carries one row");
    match check_observation_bytes(&forged, &oracle) {
        Err(ConformanceFailure::ObservationMismatch {
            expected_len,
            found_len,
            first_diff,
        }) => {
            assert_eq!(expected_len, oracle.len());
            assert_eq!(found_len, forged.len());
            assert_eq!(first_diff, Some(18));
        }
        other => panic!("expected typed observation mismatch, got {other:?}"),
    }
}

#[test]
fn wrong_production_build_digest_rejected() {
    // The adapter consumes fine against its actual build, but conformance
    // against an oracle expecting a different production digest fails typed.
    // The subject reports the actual digest, never the oracle's wish.
    let mut adapter = attach(Some(WRONG_DIGEST));
    adapter
        .consume(&raw_observation())
        .expect("valid consumption");
    let oracle = oracle_with_digest(ARTIFACT_DIGEST);
    assert_eq!(
        check_conformance(&adapter, &oracle),
        Err(ConformanceFailure::DigestMismatch {
            expected: digest_of(&ARTIFACT_DIGEST),
            found: digest_of(&WRONG_DIGEST),
        })
    );
    let subject = adapter.subject().expect("wrong but exact binding subjects");
    assert_eq!(*subject.source_sha256(), digest_of(&WRONG_DIGEST));

    // A digest-less binding stores honestly but cannot supply an exact
    // subject side, so conformance reports adapter-incomplete typed.
    let mut undigested = attach(None);
    undigested
        .consume(&raw_observation())
        .expect("valid consumption");
    assert!(matches!(
        undigested.subject(),
        Err(ConsumerError::MissingDigest)
    ));
    assert_eq!(
        check_conformance(&undigested, &oracle),
        Err(ConformanceFailure::AdapterIncomplete {
            snapshot_present: true
        })
    );
}
