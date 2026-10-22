// SPDX-License-Identifier: Apache-2.0
//! UI fixture: the prepared call has no public construction. EXPECT: FAIL.
//!
//! All storage and both borrows are private. Naming the fields or using a
//! struct literal must fail; only `prepare_response` creates a call.

use scopebase_testkit::bpf::BpfPreparedCall;

fn main() {
    let mut adapter = unimplemented_adapter();
    let invocation = unimplemented_invocation();
    // ERROR: cannot create non-exhaustive struct / field `adapter` is private.
    let _call = BpfPreparedCall {
        adapter: &mut adapter,
        invocation: &invocation,
    };
}

fn unimplemented_adapter() -> scopebase_testkit::bpf::BpfHostAdapter {
    panic!("fixture")
}

fn unimplemented_invocation() -> scopebase_testkit::CaseInvocation {
    panic!("fixture")
}
