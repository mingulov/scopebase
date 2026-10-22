// SPDX-License-Identifier: Apache-2.0
//! UI fixture: retiring while a call owns the adapter is refused.
//! EXPECT: FAIL.
//!
//! `retire` takes `&mut self`. While a prepared call holds the adapter's
//! mutable borrow, no retirement hook can run on it.

use scopebase_testkit::bpf::BpfHostAdapter;
use scopebase_testkit::ResponsePreparedAdapter;

fn main() {
    let mut adapter = unimplemented_adapter();
    let invocation = unimplemented_invocation();
    let call = adapter.prepare_response(&invocation).unwrap();
    // ERROR: cannot borrow `adapter` as mutable more than once.
    let _ = adapter.retire(&unimplemented_request());
    drop(call);
}

fn unimplemented_adapter() -> BpfHostAdapter {
    panic!("fixture")
}

fn unimplemented_invocation() -> scopebase_testkit::CaseInvocation {
    panic!("fixture")
}

fn unimplemented_request() -> scopebase_testkit::RetireRequest {
    panic!("fixture")
}
