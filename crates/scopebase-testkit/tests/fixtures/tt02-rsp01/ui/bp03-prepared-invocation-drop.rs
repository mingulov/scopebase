// SPDX-License-Identifier: Apache-2.0
//! UI fixture: dropping the invocation drops the call's authority.
//! EXPECT: FAIL.
//!
//! The call borrows the exact immutable invocation. Moving the invocation
//! out while the call is alive ends the admitted key's owner.

use scopebase_testkit::bpf::BpfHostAdapter;
use scopebase_testkit::{PreparedExecution, ResponsePreparedAdapter};

fn main() {
    let mut adapter = unimplemented_adapter();
    let invocation = unimplemented_invocation();
    let fixture = unimplemented_fixture();
    let call = adapter.prepare_response(&invocation).unwrap();
    // ERROR: cannot move out of `invocation` because it is borrowed.
    drop(invocation);
    let _ = call.execute(&fixture);
}

fn unimplemented_adapter() -> BpfHostAdapter {
    panic!("fixture")
}

fn unimplemented_invocation() -> scopebase_testkit::CaseInvocation {
    panic!("fixture")
}

fn unimplemented_fixture() -> &'static scopebase_testkit::FixtureAccess<'static> {
    panic!("fixture")
}
