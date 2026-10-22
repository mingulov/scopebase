// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::correction::{Correction, Versioned};
fn needs_send<T: Send>() {}
fn needs_sync<T: Sync>() {}
fn main() {
    needs_send::<Versioned<u8>>();
    needs_send::<Correction<u8>>();
    needs_sync::<Versioned<u8>>();
    needs_sync::<Correction<u8>>();
}
