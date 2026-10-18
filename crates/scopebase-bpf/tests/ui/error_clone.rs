// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{ErrorKind, OperationError, Stage};
fn main() {
    let error = OperationError::new(ErrorKind::Backend, Stage::Read, None, None);
    let _ = error.clone();
}
