// SPDX-License-Identifier: Apache-2.0
//! UI fixture: the prepared call is not Clone. EXPECT: FAIL.
//!
//! Cloning a call would duplicate the owned admitted response context and
//! allow two executions of one admission. The type is intentionally
//! non-cloneable.

use scopebase_testkit::bpf::BpfPreparedCall;

fn main() {
    let call = unimplemented_call();
    // ERROR: no method named `clone` / `BpfPreparedCall` does not implement `Clone`.
    let _ = call.clone();
}

fn unimplemented_call() -> BpfPreparedCall<'static> {
    panic!("fixture")
}
