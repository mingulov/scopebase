// SPDX-License-Identifier: Apache-2.0
//! UI fixture: a prepared call cannot execute twice. EXPECT: FAIL.
//!
//! `PreparedExecution::execute` consumes the call. A second execution would
//! reuse admitted response storage after handoff, so the moved value cannot
//! be used again.

use scopebase_testkit::bpf::{BpfHostAdapter, BpfPreparedCall};
use scopebase_testkit::{PreparedExecution, ResponsePreparedAdapter};

fn main() {
    let mut adapter = unimplemented_adapter();
    let invocation = unimplemented_invocation();
    let fixture = unimplemented_fixture();
    let call: BpfPreparedCall<'_> = adapter.prepare_response(&invocation).unwrap();
    let _ = call.execute(&fixture);
    // ERROR: use of moved value `call`.
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
