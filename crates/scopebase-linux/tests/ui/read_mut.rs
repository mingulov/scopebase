// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::file::FileRead;
fn test(value: FileRead) {
    value.bytes()[0] = 3;
}
fn main() {}
