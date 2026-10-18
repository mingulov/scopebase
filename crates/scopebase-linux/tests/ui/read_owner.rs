// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::file::FileRead;
fn test(value: FileRead) {
    let _: scopebase_linux::file::HeldFile = value.into();
}
fn main() {}
