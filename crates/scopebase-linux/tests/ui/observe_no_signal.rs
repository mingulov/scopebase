// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::process::ProcessObservation;
fn check(value: ProcessObservation) {
    let _ = value.signal(9);
}
fn main() {}
