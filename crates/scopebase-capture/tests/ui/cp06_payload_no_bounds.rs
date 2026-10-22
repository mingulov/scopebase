// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::{correction::*, domain::*};
fn epoch() -> Epoch {
    Epoch::new(
        CaptureId::new([1; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        0,
    )
}
struct Payload<'a>(&'a mut u8);
fn main() {
    let (mut a, mut b) = (1, 2);
    let v = Versioned::new(epoch(), Payload(&mut a));
    let c = Correction::new(epoch(), Revision::new(0), Payload(&mut b)).unwrap();
    let v = match v.apply(c) {
        Ok(v) => v,
        Err(_) => panic!("metadata"),
    };
    assert_eq!(*v.value().0, 2);
}
