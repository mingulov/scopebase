// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::file::ReadLimits;
fn test(value: ReadLimits) {
    needs_default::<ReadLimits>();
}
fn needs_default<T: Default>() {}
fn main() {}
