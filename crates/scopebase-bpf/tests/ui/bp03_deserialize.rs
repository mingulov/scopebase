// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::CapabilityObservation;
fn main() {
    let _: CapabilityObservation = serde_json::from_slice(b"{}").unwrap();
}
fn no_serialize(value: &CapabilityObservation) {
    let _ = serde_json::to_vec(value);
} // BP03_NO_SERIALIZE
