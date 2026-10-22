// SPDX-License-Identifier: Apache-2.0
//! Structured acquisition and control errors. Diagnostic formatting omits raw source text.
use std::{fmt, io};
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Stage {
    ResolveProc,
    AcquirePath,
    ValidateFile,
    ReopenHeld,
    ConfigureControl,
    ReadFile,
    ParseMaps,
    ParseMounts,
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Reason {
    InvalidInput,
    NonRegular,
    Unreadable,
    Denied,
    Unavailable,
    Disappeared,
    ChangedSource,
    WrongContext,
    Malformed,
    Inconclusive,
    Cancelled,
    Deadline,
    Allocation,
    LimitExceeded(LimitKind),
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LimitKind {
    InputBytes,
    ReadCalls,
    BufferCapacity,
    Entries,
    LineBytes,
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CleanupDisposition {
    NotNeeded,
    Complete,
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DescriptorFlagEffect {
    NotAttempted,
    Unchanged,
    CloexecSet,
    Unknown,
}
/// Incurred operations; successful predicates that later refuse remain charged.
pub struct EffectSummary {
    pub(crate) attempted: u64,
    pub(crate) completed: u64,
    pub(crate) cleanup: CleanupDisposition,
    pub(crate) flags: DescriptorFlagEffect,
}
impl EffectSummary {
    pub fn attempted_operations(&self) -> u64 {
        self.attempted
    }
    pub fn completed_operations(&self) -> u64 {
        self.completed
    }
    pub fn target_mappings_created(&self) -> u64 {
        0
    }
    pub fn target_mappings_retired(&self) -> u64 {
        0
    }
    pub fn cleanup(&self) -> CleanupDisposition {
        self.cleanup
    }
    pub fn descriptor_flags(&self) -> DescriptorFlagEffect {
        self.flags
    }
}
/// Explicit syscall attempts and newly acquired descriptors, excluding RAII close.
pub struct ResourceCharges {
    pub(crate) syscalls: u64,
    pub(crate) acquired: u64,
    pub(crate) peak: u64,
    pub(crate) read: Option<crate::file::ReadCharges>,
    pub(crate) parse: Option<crate::procfs::ParseCharges>,
}
impl ResourceCharges {
    pub fn parse(&self) -> Option<crate::procfs::ParseCharges> {
        self.parse
    }
    pub fn read(&self) -> Option<crate::file::ReadCharges> {
        self.read
    }
    pub fn syscall_attempts(&self) -> u64 {
        self.syscalls
    }
    pub fn fd_acquisitions(&self) -> u64 {
        self.acquired
    }
    pub fn peak_new_fds(&self) -> u64 {
        self.peak
    }
}
#[non_exhaustive]
pub struct LinuxError {
    pub(crate) stage: Stage,
    pub(crate) parse_line: Option<usize>,
    pub(crate) reason: Reason,
    pub(crate) source: Option<io::Error>,
    pub(crate) effect: EffectSummary,
    pub(crate) charges: ResourceCharges,
}
impl LinuxError {
    pub fn parse_line(&self) -> Option<usize> {
        self.parse_line
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn reason(&self) -> Reason {
        self.reason
    }
    pub fn source(&self) -> Option<&io::Error> {
        self.source.as_ref()
    }
    pub fn effect(&self) -> &EffectSummary {
        &self.effect
    }
    pub fn charges(&self) -> &ResourceCharges {
        &self.charges
    }
}
impl fmt::Display for LinuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LinuxError {{ stage: {:?}, reason: {:?}, errno: {:?}, flags: {:?} }}",
            self.stage,
            self.reason,
            self.source.as_ref().and_then(io::Error::raw_os_error),
            self.effect.flags
        )
    }
}
impl fmt::Debug for LinuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for LinuxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}
impl fmt::Debug for EffectSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EffectSummary")
    }
}
impl fmt::Debug for ResourceCharges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResourceCharges")
    }
}
