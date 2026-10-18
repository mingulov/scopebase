// SPDX-License-Identifier: Apache-2.0
//! Distinct cache policy: finite details, retry hits and exact aggregate totals.
use scopebase_capture::{
    loss::fold_capped_signals,
    provenance::*,
    quantity::{Count, Objects},
};
use std::collections::BTreeMap;
fn main() {
    // The attempted-key ledger is independent of retained details/diagnostics.
    let attempts = ["alpha", "beta", "alpha", "gamma", "beta"];
    let expected_failed = [1usize, 3, 4];
    let mut details = BTreeMap::new();
    let mut aggregate = 0u64;
    let mut signals = [0u8; 2];
    for (index, key) in attempts.into_iter().enumerate() {
        aggregate += 1;
        let retained = if let Some(count) = details.get_mut(key) {
            *count += 1;
            true
        } else if details.len() < 1 {
            details.insert(key, 1u64);
            true
        } else {
            signals[index % 2] = signals[index % 2].saturating_add(1);
            false
        };
        assert_eq!(!retained, expected_failed.contains(&index));
    }
    assert_eq!(aggregate, 5);
    assert_eq!(details.get("alpha"), Some(&2));
    assert_eq!(details.len(), 1);
    assert_eq!(fold_capped_signals(&signals, 255).unwrap(), 3);
    let summary = [ProvenanceLane::<_, Objects>::new(
        LaneIdentity::InsertionOwner(String::from("cache-generation-4")),
        Count::new(aggregate),
    )];
    let folded = fold_insertion_identity(&summary).unwrap();
    assert_eq!(folded.identity(), "cache-generation-4");
    assert_eq!(folded.total().get(), 5);
    let boundary = fold_insertion_identity(&[ProvenanceLane::<_, Objects>::new(
        LaneIdentity::InsertionOwner(String::from("exact-summary")),
        Count::new(u64::MAX),
    )])
    .unwrap();
    assert_eq!(boundary.total().get(), u64::MAX);
    println!("cache-attribution: attempts5 retained-alpha2 detail-failures3 exact-MAX-valid");
}
