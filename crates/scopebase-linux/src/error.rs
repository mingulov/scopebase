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
    WalkDirectory,
    ConfigureProcess,
    AcquireProcRoot,
    AuthenticateProcView,
    OpenPidfd,
    AcquireProcess,
    OpenProcMember,
    ReadProc,
    ParseProcStat,
    ParseProcStatus,
    CheckProcessNamespace,
    PollPidfd,
    VerifyBirth,
    ConfigureMapping,
    ObserveMapping,
    MapCalibration,
    RetireMapping,
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
    QueuedEntries,
    PathBytes,
    ReadBytes,
    OutputBytes,
    OpenFds,
    StatCalls,
    MetadataBytes,
    Mappings,
    MappedBytes,
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CleanupDisposition {
    NotNeeded,
    Complete,
    Unresolved,
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
#[derive(Clone)]
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
#[derive(Clone)]
pub struct ResourceCharges {
    pub(crate) syscalls: u64,
    pub(crate) acquired: u64,
    pub(crate) peak: u64,
    pub(crate) read: Option<crate::file::ReadCharges>,
    pub(crate) parse: Option<crate::procfs::ParseCharges>,
    #[cfg(feature = "process")]
    pub(crate) process: Option<ProcCharges>,
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
    #[cfg(feature = "process")]
    pub fn process(&self) -> Option<ProcCharges> {
        self.process
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
    #[cfg(feature = "process")]
    pub(crate) process: Option<ProcessErrorContext>,
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
    #[cfg(feature = "process")]
    pub fn process_context(&self) -> Option<&ProcessErrorContext> {
        self.process.as_ref()
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

/// Outer process operation retained on nested creator/birth/view guard errors.
#[cfg(feature = "process")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProcOperation {
    CreateEpoch,
    Acquire,
    VerifyBirth,
    ReadMaps,
    ReadMountinfo,
    ReadMapFiles,
}
/// Namespace domain of an authenticated handle: PID or mount only.
#[cfg(feature = "process")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProcNamespaceKind {
    Pid,
    Mount,
}
/// Typed retained proc member; never a caller-provided path.
#[cfg(feature = "process")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProcMember {
    Root,
    SelfLink,
    CreatorPidfd,
    Pidfd,
    ObserverDirectory,
    ObserverStatus,
    ObserverPidNamespace,
    TargetDirectory,
    TargetStatus,
    TargetStat,
    TargetPidNamespace,
    TargetMountNamespace,
    Maps,
    Mountinfo,
    MapFiles,
}
/// Raw pidfd poll evidence: ready count and revents, no invented errno.
#[cfg(feature = "process")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PidfdPollEvidence {
    pub(crate) ready: usize,
    pub(crate) revents: i16,
}
#[cfg(feature = "process")]
impl PidfdPollEvidence {
    pub fn ready_descriptors(&self) -> usize {
        self.ready
    }
    pub fn revents(&self) -> i16 {
        self.revents
    }
}
/// Descriptive process error context; no raw target bytes or FDs.
#[cfg(feature = "process")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProcessErrorContext {
    pub(crate) operation: ProcOperation,
    pub(crate) member: Option<ProcMember>,
    pub(crate) poll: Option<PidfdPollEvidence>,
    pub(crate) kind_expected: Option<ProcNamespaceKind>,
    pub(crate) kind_observed: Option<i32>,
    pub(crate) flags_observed: Option<u32>,
    pub(crate) retained_ticks: Option<u64>,
    pub(crate) sampled_ticks: Option<u64>,
    pub(crate) leader_state: Option<u8>,
}
#[cfg(feature = "process")]
impl ProcessErrorContext {
    pub(crate) fn new(operation: ProcOperation, member: Option<ProcMember>) -> Self {
        Self {
            operation,
            member,
            poll: None,
            kind_expected: None,
            kind_observed: None,
            flags_observed: None,
            retained_ticks: None,
            sampled_ticks: None,
            leader_state: None,
        }
    }
    pub fn operation(&self) -> ProcOperation {
        self.operation
    }
    pub fn member(&self) -> Option<ProcMember> {
        self.member
    }
    pub fn poll(&self) -> Option<PidfdPollEvidence> {
        self.poll
    }
    pub fn namespace_kind_expected(&self) -> Option<ProcNamespaceKind> {
        self.kind_expected
    }
    pub fn namespace_kind_observed(&self) -> Option<i32> {
        self.kind_observed
    }
    pub fn descriptor_flags_observed(&self) -> Option<u32> {
        self.flags_observed
    }
    pub fn retained_start_ticks(&self) -> Option<u64> {
        self.retained_ticks
    }
    pub fn sampled_start_ticks(&self) -> Option<u64> {
        self.sampled_ticks
    }
    pub fn leader_state(&self) -> Option<u8> {
        self.leader_state
    }
}
/// Process transport counters; parse/syscall/FD totals stay in siblings.
#[cfg(feature = "process")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProcCharges {
    pub(crate) read_calls: u64,
    pub(crate) metadata_bytes: u64,
    pub(crate) body_bytes: u64,
    pub(crate) requested_transport: usize,
    pub(crate) peak_granted_transport: usize,
    pub(crate) retained_transport: usize,
}
#[cfg(feature = "process")]
impl ProcCharges {
    pub fn read_calls(&self) -> u64 {
        self.read_calls
    }
    pub fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }
    pub fn body_bytes(&self) -> u64 {
        self.body_bytes
    }
    pub fn requested_transport_capacity_bytes(&self) -> usize {
        self.requested_transport
    }
    pub fn peak_granted_transport_capacity_bytes(&self) -> usize {
        self.peak_granted_transport
    }
    pub fn retained_transport_capacity_bytes(&self) -> usize {
        self.retained_transport
    }
}
