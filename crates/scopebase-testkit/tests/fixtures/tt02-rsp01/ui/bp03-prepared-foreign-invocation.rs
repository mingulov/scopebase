// SPDX-License-Identifier: Apache-2.0
//! UI fixture: one adapter serves one consuming call at a time.
//! EXPECT: FAIL.
//!
//! A prepared call holds `&mut` the exact adapter. Preparing a second call
//! for a foreign invocation while the first is alive would interleave two
//! admissions on one adapter, so the second borrow is refused.

use scopebase_testkit::bpf::BpfHostAdapter;
use scopebase_testkit::ResponsePreparedAdapter;

fn main() {
    let mut adapter = unimplemented_adapter();
    let first = unimplemented_invocation();
    let second = unimplemented_invocation();
    let call = adapter.prepare_response(&first).unwrap();
    // ERROR: cannot borrow `adapter` as mutable more than once.
    let _other = adapter.prepare_response(&second).unwrap();
    drop(call);
}

fn unimplemented_adapter() -> BpfHostAdapter {
    panic!("fixture")
}

fn unimplemented_invocation() -> scopebase_testkit::CaseInvocation {
    panic!("fixture")
}
