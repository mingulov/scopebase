// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::*;
fn cloned(v: &CapabilityObservation) {
    let _: CapabilityObservation = v.clone();
} // BP03_NO_CLONE
fn fields(v: &mut CapabilityObservation) {
    v.state = CapabilityState::Supported;
} // BP03_PRIVATE
fn unchecked() {
    let _ = ProfileId(String::from("invalid/unchecked"));
} // BP03_UNCHECKED
fn main() {}
fn no_hash<T: std::hash::Hash>() {}
fn reject_hash() {
    no_hash::<CapabilityObservation>();
} // BP03_NO_HASH
fn input_debug(value: CapabilityObservationInput<'_>) {
    let _ = format!("{value:?}");
} // BP03_INPUT_NO_DEBUG
