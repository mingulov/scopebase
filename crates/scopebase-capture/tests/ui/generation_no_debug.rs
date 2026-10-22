// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::{
    domain::{CaptureId, Epoch, ProducerId},
    generation::ObjectKey,
};
struct NoDebug;
fn main() {
    let epoch = Epoch::new(
        CaptureId::new([1; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        0,
    );
    let key = ObjectKey::new(epoch, NoDebug, 0);
    let _ = key.raw();
    let _text = format!("{:?}", key); // CP05_UI_DEBUG
}
