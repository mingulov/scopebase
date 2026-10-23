// SPDX-License-Identifier: Apache-2.0
//! TT03 Linux process fixture: exact pid/descriptive-TID/advance API over a
//! live driver pair. `nonleader_tid` is None outside the validated sibling
//! phase; the sibling phase itself is a follow-up, so increment 1 always
//! reports None after validating the underlying live barrier state.
use super::driver::{advance_a_step, nonleader_tid_of, DriverErrorKind, SharedPair};
use crate::*;

#[derive(Debug)]
pub struct LinuxProcessFixture {
    inner: SharedPair,
    pid: u32,
}

impl LinuxProcessFixture {
    pub(crate) fn bind(inner: SharedPair, pid: u32) -> Self {
        Self { inner, pid }
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn nonleader_tid(&self) -> Option<u32> {
        nonleader_tid_of(&self.inner)
    }
    pub fn advance(&self, step_id: &Label) -> Result<(), LinuxPhaseError> {
        advance_a_step(&self.inner, step_id.as_str()).map_err(|e| {
            let category = match e.kind() {
                DriverErrorKind::Protocol => FixtureErrorCategory::InvalidProtocol,
                DriverErrorKind::Io => FixtureErrorCategory::Io,
                DriverErrorKind::Timeout => FixtureErrorCategory::TimedOut,
                DriverErrorKind::Refused => FixtureErrorCategory::Denied,
                DriverErrorKind::Cancelled => FixtureErrorCategory::Cancelled,
                DriverErrorKind::Deferred => FixtureErrorCategory::Other,
            };
            LinuxPhaseError {
                category,
                errno: e.errno(),
                step_id: step_id.clone(),
                diagnostic: e.diagnostic_bytes().to_vec(),
            }
        })
    }
}

#[derive(Debug)]
pub struct LinuxPhaseError {
    category: FixtureErrorCategory,
    errno: Option<i32>,
    step_id: Label,
    diagnostic: Vec<u8>,
}

impl LinuxPhaseError {
    pub fn category(&self) -> FixtureErrorCategory {
        self.category
    }
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }
    pub fn step_id(&self) -> &Label {
        &self.step_id
    }
    pub fn diagnostic_bytes(&self) -> &[u8] {
        &self.diagnostic
    }
}
