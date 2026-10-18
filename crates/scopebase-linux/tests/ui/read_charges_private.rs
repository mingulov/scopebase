// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::file::ReadCharges;
fn test(value: ReadCharges) {
    let _ = value.read_calls;
}
fn main() {}
