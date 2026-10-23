// SPDX-License-Identifier: Apache-2.0
//! Strict replay: neutral validation always; byte decode under `json`.
//! Truncation and duplicate-member mutants refuse; only the full valid
//! vector is admitted. NEW (CP11): reference-only; no donor lines copied.
use scopebase_capture::{
    neutral::{
        validate_v1, NeutralCounter, NeutralLoss, NeutralLossKind, NeutralMagnitude,
        NeutralObservationV1, NeutralOrigin, NeutralPolicy, NeutralSource, NeutralUnit,
    },
    ContractError,
};

fn observation() -> NeutralObservationV1 {
    NeutralObservationV1 {
        source: NeutralSource {
            capture: [61; 16],
            producer: [62; 16],
            ordinal: 0,
            binding: [63; 32],
            origin: NeutralOrigin::Synthetic,
        },
        unit: NeutralUnit::Events,
        counters: vec![NeutralCounter {
            channel: 0,
            policy: NeutralPolicy::Monotonic,
            clock: [64; 16],
            start: 0,
            end: 1,
            value: 5,
            unit: NeutralUnit::Events,
        }],
        losses: vec![NeutralLoss {
            channel: 1,
            kind: NeutralLossKind::Transport,
            magnitude: NeutralMagnitude::Exact(2),
            unit: NeutralUnit::Events,
        }],
        signals: Vec::new(),
        claims: Vec::new(),
        partitions: Vec::new(),
        corrections: Vec::new(),
    }
}

#[cfg(feature = "json")]
fn byte_replay() -> Result<(), scopebase_capture::replay::ReplayError> {
    use scopebase_capture::{
        neutral::{NeutralSource, NeutralUnit},
        replay::{
            decode, encode, ReplayDocument, ReplayLimits, ReplayRecord, ReplayTerminal, ReplayValue,
        },
    };
    let source = NeutralSource {
        capture: [61; 16],
        producer: [62; 16],
        ordinal: 0,
        binding: [63; 32],
        origin: scopebase_capture::neutral::NeutralOrigin::Synthetic,
    };
    let text = |value: &str| ReplayValue::Text(value.to_string());
    let records = vec![ReplayRecord::new(
        "counter",
        0,
        vec![
            ("channel".to_string(), text("0")),
            ("policy".to_string(), text("monotonic")),
            ("clock".to_string(), text(&"04".repeat(16))),
            ("start".to_string(), text("0")),
            ("end".to_string(), text("1")),
            ("value".to_string(), text("5")),
            ("unit".to_string(), text("events")),
        ],
    )];
    let terminal = ReplayTerminal::new(0, 1, 0, 0, 0, 0, 0);
    let document = ReplayDocument::new(source, NeutralUnit::Events, records, terminal)?;
    assert_eq!(document.validated().counters().len(), 1);
    let bytes = encode(&document)?;
    let roundtrip = decode(&bytes, ReplayLimits::default())?;
    assert_eq!(roundtrip.validated().counters().len(), 1);
    assert_eq!(roundtrip.validated().counters()[0].value(), 5);
    println!("replay admits {} bytes", bytes.len());
    // Truncation refuses: only the full vector is valid.
    let cut = bytes.len() - 10;
    let refused = decode(&bytes[..cut], ReplayLimits::default()).expect_err("truncation refuses");
    println!("truncated replay refuses with {:?}", refused.kind());
    // A duplicate member refuses before any semantic walk runs.
    let body = String::from_utf8(bytes).expect("canonical bytes are utf-8");
    let doubled = body.replacen(
        "\"channel\":\"0\"",
        "\"channel\":\"0\",\"channel\":\"0\"",
        1,
    );
    let refused =
        decode(doubled.as_bytes(), ReplayLimits::default()).expect_err("duplicate refuses");
    assert_eq!(
        refused.kind(),
        scopebase_capture::replay::ReplayErrorKind::DuplicateMember
    );
    println!("duplicate member refuses with DuplicateMember");
    Ok(())
}

#[cfg(not(feature = "json"))]
fn byte_replay() -> Result<(), ContractError> {
    println!("byte replay needs --features json; neutral validation above still ran");
    Ok(())
}

fn main() -> Result<(), ContractError> {
    let validated = validate_v1(
        &observation(),
        scopebase_capture::neutral::NeutralLimits::default(),
    )?;
    assert_eq!(validated.counters().len(), 1);
    assert_eq!(validated.counters()[0].value(), 5);
    assert_eq!(validated.losses().len(), 1);
    println!(
        "neutral: {} counter(s), {} loss(es)",
        validated.counters().len(),
        validated.losses().len()
    );
    #[cfg(feature = "json")]
    byte_replay().map_err(|_| ContractError::InvalidReplay)?;
    #[cfg(not(feature = "json"))]
    byte_replay()?;
    Ok(())
}
