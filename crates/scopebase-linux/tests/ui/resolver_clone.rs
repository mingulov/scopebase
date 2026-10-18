// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{file::{HeldFile, ProcFdResolver}, identity::{StatFileKey, StatObservation}, error::{LinuxError, EffectSummary, ResourceCharges}};
fn needs_clone<T: Clone>() {}
fn check() {
    needs_clone::<ProcFdResolver>();
}
fn main() {}
