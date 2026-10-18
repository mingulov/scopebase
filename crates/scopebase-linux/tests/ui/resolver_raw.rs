// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{file::{HeldFile, ProcFdResolver}, identity::{StatFileKey, StatObservation}, error::{LinuxError, EffectSummary, ResourceCharges}};
use std::os::fd::IntoRawFd;
fn check(value: ProcFdResolver) {
    let _ = value.into_raw_fd();
}
fn main() {}
