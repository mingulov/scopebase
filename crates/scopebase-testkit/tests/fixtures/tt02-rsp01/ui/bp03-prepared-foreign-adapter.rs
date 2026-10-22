// SPDX-License-Identifier: Apache-2.0
//! UI fixture: a prepared call is not an adapter. EXPECT: FAIL.
//!
//! The opaque call owns admitted storage for one invocation; it cannot be
//! passed back into the runner as if it were a foreign adapter.

use scopebase_testkit::bpf::BpfPreparedCall;
use scopebase_testkit::ResponsePreparedAdapter;

fn takes_adapter<A: ResponsePreparedAdapter>(_: &mut A) {}

fn main() {
    let mut call = unimplemented_call();
    // ERROR: `BpfPreparedCall` does not implement `ResponsePreparedAdapter`.
    takes_adapter(&mut call);
}

fn unimplemented_call() -> BpfPreparedCall<'static> {
    panic!("fixture")
}
