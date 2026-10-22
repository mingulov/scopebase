// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{assess_filter_probe, CapabilityState, ProbePopulation};
fn main() {
    let owned = ProbePopulation {
        expected_owned_hits: 2,
        observed_owned_hits: 2,
        independently_executed_excluded: 1,
        observed_excluded_hits: 0,
    };
    assert_eq!(
        assess_filter_probe(&owned).unwrap(),
        CapabilityState::Supported
    );
    let excluded = ProbePopulation {
        observed_excluded_hits: 1,
        ..owned
    };
    assert_eq!(
        assess_filter_probe(&excluded).unwrap(),
        CapabilityState::Incompatible
    );
    let silent = ProbePopulation {
        observed_owned_hits: 0,
        ..owned
    };
    assert_eq!(
        assess_filter_probe(&silent).unwrap(),
        CapabilityState::Unknown
    );
    println!("supplied-count model: supported, incompatible, unknown; actual environment unknown");
}
