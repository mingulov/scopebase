// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::{
    provenance::{fold_insertion_identity, LaneIdentity, ProvenanceLane},
    quantity::{Count, Events},
};
fn main() {
    let lane = ProvenanceLane::<u64, Events>::new(LaneIdentity::InsertionOwner(0), Count::new(3));
    let total: Count<Events> = fold_insertion_identity(&[lane]).unwrap().total();
    assert_eq!(total.get(), 3);
}
