// SPDX-License-Identifier: Apache-2.0
//! A finite insertion/hit journal, with display policy kept local.
use scopebase_capture::{
    provenance::*,
    quantity::{Count, Events},
    ContractError,
};
fn exact_or_raw_saturated(
    identity: LaneIdentity<(u32, u64, i32)>,
    raw: u64,
) -> ProvenanceLane<(u32, u64, i32), Events> {
    if raw == u64::MAX {
        ProvenanceLane::saturated(identity)
    } else {
        ProvenanceLane::new(identity, Count::new(raw))
    }
}
fn main() {
    // Independent journal: insert on CPU1, hit CPU1, migrate/hit CPU0.
    let journal = [(1usize, 4243u32, 7u64), (0, 4244, 99)];
    let mut words = [0u64; 2];
    let owner_cpu = 1;
    let identity = (1000, 123, 7);
    let mut latest_display = 0;
    for (cpu, _thread, display) in journal {
        words[cpu] += 1;
        latest_display = display;
    }
    let lanes: Vec<_> = words
        .iter()
        .enumerate()
        .map(|(cpu, &raw)| {
            exact_or_raw_saturated(
                if cpu == owner_cpu {
                    LaneIdentity::InsertionOwner(identity)
                } else {
                    LaneIdentity::Secondary
                },
                raw,
            )
        })
        .collect();
    let folded = fold_insertion_identity(&lanes).unwrap();
    assert_eq!(*folded.identity(), (1000, 123, 7));
    assert_eq!(folded.total().get(), 2);
    assert_eq!(latest_display, 99);
    let zero = fold_insertion_identity(&[
        exact_or_raw_saturated(LaneIdentity::InsertionOwner((0, 0, 0)), 3),
        exact_or_raw_saturated(LaneIdentity::Secondary, 7),
    ])
    .unwrap();
    assert_eq!(*zero.identity(), (0, 0, 0));
    assert_eq!(zero.total().get(), 10);
    assert_eq!(
        fold_insertion_identity(&[exact_or_raw_saturated(
            LaneIdentity::InsertionOwner(identity),
            u64::MAX
        )])
        .err(),
        Some(ContractError::SaturatedCount)
    );
    println!("insertion-journal: owner1000 total2 zero-known total10 raw-saturation-refused");
}
