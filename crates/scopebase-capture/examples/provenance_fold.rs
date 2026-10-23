// SPDX-License-Identifier: Apache-2.0
//! Insertion-owner folds: exact totals, unknown identities, saturation refusals.
//! NEW (CP11): reference-only; no donor lines copied.
use scopebase_capture::{
    provenance::{
        fold_insertion_identity, IdentityUnknown, LaneIdentity, ObservedIdentity, ProvenanceLane,
    },
    quantity::{Count, Events},
    ContractError,
};

fn main() -> Result<(), ContractError> {
    let lanes = vec![
        ProvenanceLane::new(LaneIdentity::InsertionOwner(7u64), Count::new(6)),
        ProvenanceLane::new(LaneIdentity::Secondary, Count::<Events>::new(4)),
    ];
    let fold = fold_insertion_identity(&lanes)?;
    assert_eq!(fold.total(), Count::new(10));
    assert_eq!(*fold.identity(), 7);
    println!("fold total: {:?} owner: {}", fold.total(), fold.identity());
    // An unobserved mapping identity stays unknown: it never becomes zero.
    let unknown: ObservedIdentity<u64> = ObservedIdentity::Unknown(IdentityUnknown::NotObserved);
    assert!(matches!(unknown, ObservedIdentity::Unknown(_)));
    println!("mapping identity: {unknown:?}");
    // A saturated lane refuses instead of contributing a silent zero.
    let saturated = vec![
        ProvenanceLane::<u64, Events>::saturated(LaneIdentity::InsertionOwner(7u64)),
        ProvenanceLane::new(LaneIdentity::Secondary, Count::new(4)),
    ];
    assert_eq!(
        fold_insertion_identity(&saturated).expect_err("saturated lane refuses"),
        ContractError::SaturatedCount
    );
    println!("saturated lane refuses with SaturatedCount");
    // Two owners conflict: insertion identity must be unique.
    let dueling = vec![
        ProvenanceLane::new(LaneIdentity::InsertionOwner(7u64), Count::<Events>::new(6)),
        ProvenanceLane::new(LaneIdentity::InsertionOwner(8u64), Count::<Events>::new(4)),
    ];
    assert_eq!(
        fold_insertion_identity(&dueling).expect_err("dueling owners refuse"),
        ContractError::ConflictingProvenance
    );
    println!("dueling owners refuse with ConflictingProvenance");
    Ok(())
}
