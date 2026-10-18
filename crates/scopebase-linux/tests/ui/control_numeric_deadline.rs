// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::control::{CancelToken, OperationControl};
fn main() {
    let _ = OperationControl::new(Some(17_u64), CancelToken::new());
}
