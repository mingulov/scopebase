// SPDX-License-Identifier: Apache-2.0
//! TT03 Linux process fixture: exact pid/descriptive-TID/advance API over a
//! live driver pair. `nonleader_tid` is Some(actual sibling GETTID) only
//! while the validated sibling barrier is held (start through pre-exec) and
//! None otherwise, including on the excluded B fixture, which never advances.
use super::driver::{advance_a_step, nonleader_tid_of, DriverErrorKind, SharedPair};
use crate::*;

#[derive(Debug)]
pub struct LinuxProcessFixture {
    inner: SharedPair,
    pid: u32,
    excluded: bool,
}

impl LinuxProcessFixture {
    pub(crate) fn bind(inner: SharedPair, pid: u32) -> Self {
        Self { inner, pid, excluded: false }
    }
    pub(crate) fn bind_excluded(inner: SharedPair, pid: u32) -> Self {
        Self { inner, pid, excluded: true }
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn nonleader_tid(&self) -> Option<u32> {
        if self.excluded {
            return None;
        }
        nonleader_tid_of(&self.inner)
    }
    pub fn advance(&self, step_id: &Label) -> Result<(), LinuxPhaseError> {
        if self.excluded {
            return Err(LinuxPhaseError {
                category: FixtureErrorCategory::Denied,
                errno: None,
                step_id: step_id.clone(),
                diagnostic: b"excluded fixture does not advance".to_vec(),
            });
        }
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
