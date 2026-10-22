// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::*;
fn lookup(map: &mut ValidatedMap) -> Result<Option<Vec<u8>>, OperationError> {
    ValidatedMap::lookup(map, &[0])
}
fn traits() {
    fn copy<T: Copy + Eq + Send + Sync>() {}
    fn clone<T: Clone + Eq + Send + Sync>() {}
    fn plain<T: Eq + Send + Sync>() {}
    copy::<CapabilityState>();
    copy::<EvidenceStage>();
    copy::<HazardState>();
    copy::<ProbePopulation>();
    copy::<OperationErrorSnapshot>();
    clone::<ProfileId>();
    clone::<ProbeContext>();
    plain::<CapabilityObservation>();
}
fn main() {
    traits();
    let _ = lookup;
}
