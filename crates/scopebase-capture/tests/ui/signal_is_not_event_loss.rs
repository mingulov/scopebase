// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use scopebase_capture::{
    loss::{CappedLossSignal, LossMagnitude},
    quantity::Events,
};
fn events_only(_: LossMagnitude<Events>) {}
fn wrong_units(signal: CappedLossSignal) {
    events_only(signal);
}
fn main() {}
