// SPDX-License-Identifier: Apache-2.0
//! UI fixture: the prepared call is not Default. EXPECT: FAIL.
//!
//! A default call would own no adapter, no invocation and no admitted
//! response storage. Calls exist only through fallible admission.

use scopebase_testkit::bpf::BpfPreparedCall;

fn main() {
    // ERROR: no function or associated item named `default` / no `Default` impl.
    let _call: BpfPreparedCall<'_> = BpfPreparedCall::default();
}
