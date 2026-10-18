// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use scopebase_capture::{
    counter::{sample_delta, AdvanceBound, Delta, Sample},
    loss::{CappedLossSignal, LossFact, LossMagnitude},
    quantity::{Events, Records, Unit},
};
fn matching<U: Unit>(
    b: &Sample<U>,
    c: &Sample<U>,
    bound: &AdvanceBound<U>,
    fact: &LossFact<U>,
    magnitude: &LossMagnitude<U>,
    delta: &Delta<U>,
) {
    assert_eq!(b, &b.clone());
    assert_eq!(bound, &bound.clone());
    assert_eq!(fact, &fact.clone());
    assert_eq!(magnitude, &magnitude.clone());
    assert_eq!(delta, &delta.clone());
    let _ = format!("{b:?} {bound:?} {fact:?} {magnitude:?} {delta:?}");
    let _ = sample_delta(Some(b), c, Some(bound));
}
fn concrete(
    b: &Sample<Events>,
    c: &Sample<Events>,
    r: &Sample<Records>,
    signal: CappedLossSignal,
    fact: LossMagnitude<Events>,
) {
    let _ = sample_delta(Some(b), c, None);
    let _ = sample_delta(Some(r), r, None);
    let _: CappedLossSignal = signal;
    let _: LossMagnitude<Events> = fact;
}
fn main() {}
