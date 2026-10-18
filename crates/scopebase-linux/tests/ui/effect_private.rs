// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{file::{HeldFile, ProcFdResolver}, identity::{StatFileKey, StatObservation}, error::{LinuxError, EffectSummary, ResourceCharges}};
fn check(value: &EffectSummary) {
    let _ = &value.attempted;
}
fn main() {}
