// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::process::ObserverEpoch;
fn check(value: &ObserverEpoch) {
    let _ = &value.marker;
}
fn main() {}
