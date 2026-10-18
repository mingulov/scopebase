// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::control::CancelToken;
fn main() {
    let _ = CancelToken { cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)) };
}
