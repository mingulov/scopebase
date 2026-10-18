// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::control::{CancelToken, MonotonicDeadline, OperationControl};
fn main() {
    fn shared<T: Send + Sync + Clone>() {}
    shared::<CancelToken>(); shared::<OperationControl>(); shared::<MonotonicDeadline>();
    let token = CancelToken::new();
    let deadline = MonotonicDeadline::after(std::time::Duration::from_secs(1)).unwrap();
    let copy = deadline; let _still_usable = deadline;
    let _control = OperationControl::new(Some(copy), token.clone());
    token.cancel();
    let _unlimited = OperationControl::unlimited();
}
