// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::{correction::*, domain::*};
fn main() {
    let epoch = Epoch::new(
        CaptureId::new([1; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        0,
    );
    let _ = Correction {
        epoch,
        from: Revision::new(0),
        to: Revision::new(9),
        replacement: (),
    };
}
