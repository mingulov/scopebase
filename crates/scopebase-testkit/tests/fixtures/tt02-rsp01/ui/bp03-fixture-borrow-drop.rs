// SPDX-License-Identifier: Apache-2.0
//! UI fixture: the fixture access must outlive the consuming call.
//! EXPECT: FAIL.
//!
//! `execute` takes the fixture by shared borrow. Dropping the fixture
//! access first moves it, so borrowing it for execution fails.

use scopebase_testkit::bpf::BpfHostAdapter;
use scopebase_testkit::{PreparedExecution, ResponsePreparedAdapter};

fn main() {
    let mut adapter = unimplemented_adapter();
    let invocation = unimplemented_invocation();
    let fixture = unimplemented_fixture();
    let call = adapter.prepare_response(&invocation).unwrap();
    // ERROR: cannot move out of `fixture` because it is borrowed.
    drop(fixture);
    let _ = call.execute(&fixture);
}

fn unimplemented_adapter() -> BpfHostAdapter {
    panic!("fixture")
}

fn unimplemented_invocation() -> scopebase_testkit::CaseInvocation {
    panic!("fixture")
}

fn unimplemented_fixture() -> scopebase_testkit::FixtureAccess<'static> {
    panic!("fixture")
}
