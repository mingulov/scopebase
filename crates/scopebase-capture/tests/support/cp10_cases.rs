// SPDX-License-Identifier: Apache-2.0
//! Shared CP10 raw-input builders. No serde use: safe for no-default builds.
#![allow(dead_code)]
use scopebase_capture::neutral::{
    NeutralCounter, NeutralLoss, NeutralLossKind, NeutralMagnitude, NeutralObservationV1,
    NeutralOrigin, NeutralPolicy, NeutralSignal, NeutralSource, NeutralUnit,
};

pub const CAPTURE_HEX: &str = "0102030405060708090a0b0c0d0e0f10";
pub const PRODUCER_HEX: &str = "1112131415161718191a1b1c1d1e1f20";
pub const BINDING_HEX: &str = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
pub const CLOCK_HEX: &str = "4142434445464748494a4b4c4d4e4f50";

pub fn hex_bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2, "CP10:hex length");
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}

pub fn neutral_source() -> NeutralSource {
    NeutralSource {
        capture: hex_bytes(CAPTURE_HEX),
        producer: hex_bytes(PRODUCER_HEX),
        ordinal: 0,
        binding: hex_bytes(BINDING_HEX),
        origin: NeutralOrigin::Synthetic,
    }
}

pub fn neutral_counter(channel: u32) -> NeutralCounter {
    NeutralCounter {
        channel,
        policy: NeutralPolicy::Monotonic,
        clock: hex_bytes(CLOCK_HEX),
        start: 0,
        end: 9,
        value: 5,
        unit: NeutralUnit::Events,
    }
}

pub fn neutral_loss(channel: u32) -> NeutralLoss {
    NeutralLoss {
        channel,
        kind: NeutralLossKind::Transport,
        magnitude: NeutralMagnitude::Exact(0),
        unit: NeutralUnit::Events,
    }
}

pub fn neutral_signal(channel: u32) -> NeutralSignal {
    NeutralSignal {
        channel,
        observed: 0,
        cap: 9,
        unit: NeutralUnit::DiagnosticSignals,
    }
}

/// Minimal valid observation: one counter, document unit events.
pub fn observation() -> NeutralObservationV1 {
    NeutralObservationV1 {
        source: neutral_source(),
        unit: NeutralUnit::Events,
        counters: vec![neutral_counter(7)],
        losses: Vec::new(),
        signals: Vec::new(),
        claims: Vec::new(),
        partitions: Vec::new(),
        corrections: Vec::new(),
    }
}
