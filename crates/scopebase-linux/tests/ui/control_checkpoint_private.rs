// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::control::OperationControl;
fn main() {
    let _ = OperationControl::unlimited().checkpoint();
}
