// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{file::{HeldFile, ProcFdResolver}, identity::{StatFileKey, StatObservation}, error::{LinuxError, EffectSummary, ResourceCharges}};
fn check(value: &ResourceCharges) {
    let _ = &value.syscalls;
}
fn main() {}
