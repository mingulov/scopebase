// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{file::{HeldFile, ProcFdResolver}, identity::{StatFileKey, StatObservation}, error::{LinuxError, EffectSummary, ResourceCharges}};
use std::os::fd::{AsFd, AsRawFd};
fn check(value: HeldFile) {
    let borrow = value.as_fd();
    drop(value);
    let _ = borrow.as_raw_fd();
}
fn main() {}
