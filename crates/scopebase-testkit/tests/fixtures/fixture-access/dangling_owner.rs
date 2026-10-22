// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::{EffectBatch, FixtureAccess, FixtureError, FixtureInput, FixtureResource, Label, RunLimits};
use std::any::Any;
struct Owner { token: String }
fn check(access: &FixtureAccess<'_>, owner: &Owner) {
    assert_eq!(access.input(&Label::parse("operands").unwrap()), Some(&b"retained-input"[..]));
    let found = access.resource::<Owner>(&Label::parse("actual-owner").unwrap()).unwrap();
    assert!(std::ptr::eq(found, owner));
    assert_eq!(found.token, "actual-retained-owner");
    assert!(*access.effects().complete());
    println!("PASS: actual input bytes, actual Any owner pointer/token, and checked effect batch");
}
fn forbidden<'a>(bytes: &'a [u8]) -> Result<FixtureAccess<'a>, FixtureError> {
    let limits = RunLimits::default();
    let owner = Owner { token: "actual-retained-owner".to_owned() };
    let inputs = [FixtureInput::new(Label::parse("operands").unwrap(), bytes)];
    let resources = [FixtureResource::new(Label::parse("actual-owner").unwrap(), &owner)];
    FixtureAccess::new(&inputs, &resources, EffectBatch::empty(&limits), &limits)
}
fn main() {}
