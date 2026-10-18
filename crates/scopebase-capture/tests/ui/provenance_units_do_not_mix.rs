// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::{
    provenance::{LaneIdentity, ProvenanceLane},
    quantity::{Count, Events, Objects},
};
fn main() {
    let count = Count::<Objects>::new(3);
    let _ = ProvenanceLane::<u64, Events>::new(LaneIdentity::InsertionOwner(0), count);
}
