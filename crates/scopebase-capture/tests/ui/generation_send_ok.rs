// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::{
    domain::{CaptureId, Epoch, ProducerId},
    generation::ObjectKey,
};
fn main() {
    let epoch = Epoch::new(
        CaptureId::new([1; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        0,
    );
    let key = ObjectKey::new(epoch, 7u64, 0);
    std::thread::spawn(move || drop(key)).join().unwrap(); // CP05_UI_SEND
}
