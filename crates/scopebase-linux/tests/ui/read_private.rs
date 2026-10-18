// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::file::FileRead;
fn test(value: FileRead) {
    let _ = value.data;
}
fn main() {}
