// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use scopebase_capture::{
    counter::{sample_delta, Sample},
    quantity::{Events, Records},
};
fn wrong_units(baseline: &Sample<Events>, current: &Sample<Records>) {
    let _ = sample_delta(Some(baseline), current, None);
}
fn main() {}
