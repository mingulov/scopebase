// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
fn main() {
    let caps = Limits {
        input_bytes: 0,
        retained_bytes: 0,
        work_steps: 0,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    };
    caps.validate().unwrap();
    let error = OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        Some(13),
        Some(Box::new(std::io::Error::from_raw_os_error(13))),
    );
    let moved = error;
    match moved.kind() {
        ErrorKind::Backend => (),
        _ => (),
    }
    match moved.stage() {
        Stage::Execute => (),
        _ => (),
    }
    fn send_sync<T: Send + Sync>() {}
    send_sync::<OperationError>();
    send_sync::<Limits>();
}
