// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::*;
fn wrong(observation: &mut CapabilityObservation) {
    let _ = ValidatedMap::lookup(observation, &[0]);
} // BP03_NATIVE_RECEIVER
fn main() {}
