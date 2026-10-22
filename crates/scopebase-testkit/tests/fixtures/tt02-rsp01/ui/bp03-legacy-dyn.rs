// SPDX-License-Identifier: Apache-2.0
//! UI fixture: dyn legacy trait object rejects the strict adapter.
//! EXPECT: FAIL.
//!
//! Coercing `&mut BpfHostAdapter` to `&mut dyn ConformanceAdapter` must fail:
//! the strict adapter has no borrowed total `execute`, so no dynamic legacy
//! dispatch can observe it.

use scopebase_testkit::bpf::BpfHostAdapter;

fn main() {
    let mut adapter = unimplemented_adapter();
    // ERROR: the trait bound `BpfHostAdapter: ConformanceAdapter` is not met.
    let _legacy: &mut dyn scopebase_testkit::ConformanceAdapter = &mut adapter;
}

fn unimplemented_adapter() -> BpfHostAdapter {
    panic!("fixture")
}
