// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{ErrorKind, Stage};
fn kind(v: ErrorKind) {
    match v {
        ErrorKind::InvalidInput
        | ErrorKind::Malformed
        | ErrorKind::Incompatible
        | ErrorKind::Unsupported
        | ErrorKind::Denied
        | ErrorKind::Disappeared
        | ErrorKind::Changed
        | ErrorKind::LimitExceeded
        | ErrorKind::Overflow
        | ErrorKind::Backend
        | ErrorKind::Poisoned => (),
    }
}
fn stage(v: Stage) {
    match v {
        Stage::Admission
        | Stage::Metadata
        | Stage::Allocate
        | Stage::Read
        | Stage::Attach
        | Stage::Drain
        | Stage::Retire
        | Stage::BtfQuery
        | Stage::Compile
        | Stage::Inspect
        | Stage::Execute => (),
    }
}
fn main() {
    kind(ErrorKind::Backend);
    stage(Stage::Execute);
}
