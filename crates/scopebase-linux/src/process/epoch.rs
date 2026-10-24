// SPDX-License-Identifier: Apache-2.0
// Strict observer epochs and creator guards (LX08 bounded slice).
use super::native;
use super::{
    checked_open_at2, checked_proc_root, current_pid, map_errno, namespace_sample,
    parse_own_status, pid_name, poll_pidfd, read_link_exact, read_metadata_eof, transport_vec,
    validate_limits, NsKey, Pid, PollClass, ProcLimits, ProcOps,
};
use crate::{
    control::OperationControl,
    error::{
        EffectSummary, LinuxError, ProcMember, ProcNamespaceKind, ProcOperation,
        ProcessErrorContext, Reason, ResourceCharges, Stage,
    },
    identity::ObservationInterval,
};
use std::{
    fmt,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::Arc,
    time::Instant,
};

/// Real creator authority: checked creator PID, original creator pidfd and
/// authenticated active-PID namespace handle/key. Shared by epoch clones;
/// cloning never dups either FD.
struct Authority {
    creator: Pid,
    pidfd: OwnedFd,
    // Retained authority handle: prevents key recycling, never re-queried.
    #[allow(dead_code)]
    ns: OwnedFd,
    key: NsKey,
}

/// Strict observer epoch: private authority Arc plus an FD-free marker Arc.
/// Equality uses marker identity, never a numeric PID, inode or FD number.
pub struct ObserverEpoch {
    authority: Arc<Authority>,
    marker: Arc<()>,
    interval: ObservationInterval,
    charges: ResourceCharges,
    effects: EffectSummary,
}
impl ObserverEpoch {
    /// Capture real creator authority: counted getpid, fresh checked /proc
    /// root with procfs proof, exact self link, current numeric observer
    /// directory with complete Own status, authenticated active-PID namespace
    /// and one nonterminal original-creator pidfd poll. Final refusal returns
    /// no epoch; RAII relinquishes every acquired FD.
    pub fn new(limits: ProcLimits, control: &OperationControl) -> Result<Self, LinuxError> {
        let started = Instant::now();
        let mut ops = ProcOps::new(ProcOperation::CreateEpoch, limits);
        ops.check(control, Stage::ConfigureProcess)?;
        validate_limits(limits)?;
        let mut meta = transport_vec(&mut ops, limits.max_metadata_bytes, Stage::ConfigureProcess)?;
        let creator = current_pid(&mut ops, control)?;
        let root = checked_proc_root(&mut ops, control)?;
        let (pidfd, ns, key) =
            Self::authenticate_creator(&mut ops, control, &root, creator, &mut meta)?;
        ops.fd_released(1);
        drop(root);
        drop(meta);
        ops.post(control, Stage::ConfigureProcess)?;
        let finished = Instant::now();
        ops.fd_released(2);
        Ok(Self {
            authority: Arc::new(Authority {
                creator,
                pidfd,
                ns,
                key,
            }),
            marker: Arc::new(()),
            interval: ObservationInterval::new(started, finished),
            charges: ops.charges(),
            effects: ops.effects(),
        })
    }

    /// Steps 2-4 shared shape: self/Own/namespace proof plus creator pidfd.
    /// Returns the two authority FDs; the caller transfers them to the owner.
    fn authenticate_creator(
        ops: &mut ProcOps,
        control: &OperationControl,
        root: &OwnedFd,
        creator: Pid,
        meta: &mut Vec<u8>,
    ) -> Result<(OwnedFd, OwnedFd, NsKey), LinuxError> {
        self_proof(ops, control, root.as_fd(), creator)?;
        let obsdir = open_observer_dir(ops, control, root.as_fd(), creator)?;
        read_own_status(ops, control, obsdir.as_fd(), creator, meta)?;
        let (ns, key) = namespace_sample(
            ops,
            control,
            obsdir.as_fd(),
            c"pid",
            b"pid:[",
            ProcNamespaceKind::Pid,
            native::CLONE_NEWPID,
            ProcMember::ObserverPidNamespace,
        )?;
        ops.fd_released(1);
        drop(obsdir);
        let pidfd = open_pidfd(ops, control, creator, ProcMember::CreatorPidfd)?;
        let sample = poll_pidfd(ops, control, pidfd.as_fd(), ProcMember::CreatorPidfd)?;
        if sample.class == PollClass::Terminal {
            ops.fd_released(2);
            let mut context =
                ProcessErrorContext::new(ops.operation, Some(ProcMember::CreatorPidfd));
            context.poll = Some(sample.evidence);
            return Err(ops.fail_with(
                Stage::ConfigureProcess,
                Reason::WrongContext,
                None,
                context,
            ));
        }
        Ok((pidfd, ns, key))
    }

    pub fn creation_interval(&self) -> &ObservationInterval {
        &self.interval
    }
    pub fn creation_charges(&self) -> &ResourceCharges {
        &self.charges
    }
    pub fn creation_effects(&self) -> &EffectSummary {
        &self.effects
    }
    pub(crate) fn creator(&self) -> Pid {
        self.authority.creator
    }
    pub(crate) fn creator_pidfd(&self) -> BorrowedFd<'_> {
        self.authority.pidfd.as_fd()
    }
    pub(crate) fn creator_key(&self) -> NsKey {
        self.authority.key
    }
    pub(crate) fn marker(&self) -> &Arc<()> {
        &self.marker
    }
}

#[cfg(test)]
impl ObserverEpoch {
    /// Forge a post-fork epoch: identical authority handles, foreign
    /// creator. Reproduces exactly the guard state a forked child
    /// observes (`creator != getpid`) without forking: forked children
    /// of the multithreaded test binary may only run syscalls, never
    /// lib code, so a real fork cannot drive `observe_mapping`. The
    /// guard decides on the pid comparison alone and fails before
    /// touching the cloned handles.
    pub(crate) fn forge_post_fork_creator(&self, creator: Pid) -> Self {
        Self {
            authority: Arc::new(Authority {
                creator,
                pidfd: self
                    .authority
                    .pidfd
                    .try_clone()
                    .expect("clone authority pidfd"),
                ns: self.authority.ns.try_clone().expect("clone authority ns"),
                key: self.authority.key,
            }),
            marker: Arc::clone(&self.marker),
            interval: self.interval,
            charges: self.charges.clone(),
            effects: self.effects.clone(),
        }
    }
}
impl Clone for ObserverEpoch {
    fn clone(&self) -> Self {
        Self {
            authority: Arc::clone(&self.authority),
            marker: Arc::clone(&self.marker),
            interval: self.interval,
            charges: self.charges.clone(),
            effects: EffectSummary {
                attempted: self.effects.attempted_operations(),
                completed: self.effects.completed_operations(),
                cleanup: self.effects.cleanup(),
                flags: self.effects.descriptor_flags(),
            },
        }
    }
}
impl PartialEq for ObserverEpoch {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.marker, &other.marker)
    }
}
impl Eq for ObserverEpoch {}
impl fmt::Debug for ObserverEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObserverEpoch")
    }
}

/// Fresh-root creator guard for acquire: getpid comparison, original creator
/// poll, then a new authenticated root/self/Own/namespace sample compared to
/// the epoch. Completes before any target probe. Returns the new root and
/// observer namespace for the six returned owner FDs.
pub(crate) fn guard_acquire(
    epoch: &ObserverEpoch,
    ops: &mut ProcOps,
    control: &OperationControl,
    meta: &mut Vec<u8>,
) -> Result<(OwnedFd, OwnedFd), LinuxError> {
    guard_creator_live(epoch, ops, control)?;
    let root = checked_proc_root(ops, control)?;
    self_proof(ops, control, root.as_fd(), epoch.creator())?;
    let obsdir = open_observer_dir(ops, control, root.as_fd(), epoch.creator())?;
    read_own_status(ops, control, obsdir.as_fd(), epoch.creator(), meta)?;
    let (ns, key) = namespace_sample(
        ops,
        control,
        obsdir.as_fd(),
        c"pid",
        b"pid:[",
        ProcNamespaceKind::Pid,
        native::CLONE_NEWPID,
        ProcMember::ObserverPidNamespace,
    )?;
    ops.fd_released(1);
    drop(obsdir);
    if key != epoch.creator_key() {
        ops.fd_released(2);
        return Err(ops.fail(Stage::CheckProcessNamespace, Reason::WrongContext, None));
    }
    Ok((root, ns))
}

/// Retained-root creator guard for read/verify: getpid, creator poll, dynamic
/// self/Own/namespace proof through the observation's root. Closes all four
/// temporary FDs before any target work. No fresh global /proc reopen.
pub(crate) fn guard_retained(
    epoch: &ObserverEpoch,
    root: BorrowedFd<'_>,
    ops: &mut ProcOps,
    control: &OperationControl,
    meta: &mut Vec<u8>,
) -> Result<(), LinuxError> {
    guard_creator_live(epoch, ops, control)?;
    self_proof(ops, control, root, epoch.creator())?;
    let obsdir = open_observer_dir(ops, control, root, epoch.creator())?;
    read_own_status(ops, control, obsdir.as_fd(), epoch.creator(), meta)?;
    let (ns, key) = namespace_sample(
        ops,
        control,
        obsdir.as_fd(),
        c"pid",
        b"pid:[",
        ProcNamespaceKind::Pid,
        native::CLONE_NEWPID,
        ProcMember::ObserverPidNamespace,
    )?;
    ops.fd_released(2);
    drop(obsdir);
    drop(ns);
    if key != epoch.creator_key() {
        return Err(ops.fail(Stage::CheckProcessNamespace, Reason::WrongContext, None));
    }
    Ok(())
}

/// Counted getpid comparison plus one original-creator nonterminal poll. A
/// valid terminal creator poll is ConfigureProcess/WrongContext, never a
/// target Exited result. No target work is performed here.
fn guard_creator_live(
    epoch: &ObserverEpoch,
    ops: &mut ProcOps,
    control: &OperationControl,
) -> Result<(), LinuxError> {
    let current = current_pid(ops, control)?;
    if current != epoch.creator() {
        // S11: the post-fork creator mismatch is observer-side (our
        // authentication broke; no target work ran). current_pid
        // clears ops.member, so tag the creator origin explicitly —
        // a memberless WrongContext would route as a target
        // ViewChanged mismatch instead of an observer failure.
        let context =
            ProcessErrorContext::new(ops.operation, Some(ProcMember::CreatorPidfd));
        return Err(ops.fail_with(
            Stage::ConfigureProcess,
            Reason::WrongContext,
            None,
            context,
        ));
    }
    let sample = poll_pidfd(
        ops,
        control,
        epoch.creator_pidfd(),
        ProcMember::CreatorPidfd,
    )?;
    if sample.class == PollClass::Terminal {
        let mut context = ProcessErrorContext::new(ops.operation, Some(ProcMember::CreatorPidfd));
        context.poll = Some(sample.evidence);
        return Err(ops.fail_with(Stage::ConfigureProcess, Reason::WrongContext, None, context));
    }
    Ok(())
}

/// Exact dynamic self link through `root`: it must name this creator.
fn self_proof(
    ops: &mut ProcOps,
    control: &OperationControl,
    root: BorrowedFd<'_>,
    creator: Pid,
) -> Result<(), LinuxError> {
    ops.member = Some(ProcMember::SelfLink);
    let link = read_link_exact(ops, control, root, c"self", Stage::AuthenticateProcView)?;
    if link.as_bytes() != creator.as_raw().to_string().as_bytes() {
        return Err(ops.fail(Stage::AuthenticateProcView, Reason::WrongContext, None));
    }
    Ok(())
}

/// Complete Own status through one already-open observer directory. Releases
/// only the status FD; the directory stays live for the namespace sample.
fn read_own_status(
    ops: &mut ProcOps,
    control: &OperationControl,
    obsdir: BorrowedFd<'_>,
    creator: Pid,
    meta: &mut Vec<u8>,
) -> Result<(), LinuxError> {
    ops.member = Some(ProcMember::ObserverStatus);
    let status = checked_open_at2(
        ops,
        control,
        obsdir,
        c"status",
        false,
        Stage::OpenProcMember,
    )?;
    read_metadata_eof(ops, control, status.as_fd(), meta, Stage::ReadProc)?;
    ops.fd_released(1);
    drop(status);
    if parse_own_status(meta, creator).is_err() {
        let reason = match own_status_fault(meta, creator) {
            OwnFault::NonLeader => Reason::InvalidInput,
            OwnFault::Other => Reason::WrongContext,
        };
        return Err(ops.fail(Stage::AuthenticateProcView, reason, None));
    }
    Ok(())
}

/// Strict current numeric observer directory under `root`.
fn open_observer_dir(
    ops: &mut ProcOps,
    control: &OperationControl,
    root: BorrowedFd<'_>,
    creator: Pid,
) -> Result<OwnedFd, LinuxError> {
    ops.member = Some(ProcMember::ObserverDirectory);
    let mut scratch = [0u8; 12];
    // Borrow ends before the open call issues; name bytes stay on our stack.
    let fd = {
        let name = pid_name(creator, &mut scratch);
        checked_open_at2(ops, control, root, name, true, Stage::AuthenticateProcView)?
    };
    Ok(fd)
}

/// Checked original pidfd plus CLOEXEC proof, without fallback or fixup.
pub(crate) fn open_pidfd(
    ops: &mut ProcOps,
    control: &OperationControl,
    pid: Pid,
    member: ProcMember,
) -> Result<OwnedFd, LinuxError> {
    let stage = Stage::OpenPidfd;
    ops.member = Some(member);
    ops.check(control, stage)?;
    let target = pid.rustix();
    let fd =
        ops.syscall(|| rustix::process::pidfd_open(target, rustix::process::PidfdFlags::empty()));
    let fd = match fd {
        Ok(fd) => fd,
        Err(errno) => return Err(ops.fail(stage, map_errno(errno), Some(errno.into()))),
    };
    ops.fd_acquired();
    if let Err(error) = ops.post(control, stage) {
        ops.fd_released(1);
        return Err(error);
    }
    super::check_cloexec(ops, control, &fd, stage)?;
    Ok(fd)
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum OwnFault {
    NonLeader,
    Other,
}

/// Diagnose an Own-status refusal: nonleader `Tgid != Pid` is InvalidInput,
/// every other structural mismatch is WrongContext.
fn own_status_fault(input: &[u8], me: Pid) -> OwnFault {
    let text = match core::str::from_utf8(input) {
        Ok(text) => text,
        Err(_) => return OwnFault::Other,
    };
    let canonical = me.as_raw().to_string();
    let (mut pids, mut tgids) = (Vec::new(), Vec::new());
    for line in text.split('\n') {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let mut fields = values.split_whitespace();
        let (Some(first), None) = (fields.next(), fields.next()) else {
            continue;
        };
        match name {
            "Pid" => pids.push(first.to_string()),
            "Tgid" => tgids.push(first.to_string()),
            _ => {}
        }
    }
    if pids.len() == 1 && tgids.len() == 1 && pids[0] == canonical && tgids[0] != canonical {
        OwnFault::NonLeader
    } else {
        OwnFault::Other
    }
}

/// Diagnose a target-status refusal with the same nonleader rule.
pub(crate) fn target_status_fault(input: &[u8], target: Pid) -> OwnFault {
    own_status_fault(input, target)
}

pub(crate) fn is_nonleader(fault: OwnFault) -> bool {
    fault == OwnFault::NonLeader
}

#[cfg(test)]
mod tests {
    use super::super::{creator_pid_refused, ProcLimits};
    use super::*;
    use crate::{control::OperationControl, procfs::ParseLimits};
    use std::os::unix::process::CommandExt as _;

    fn limits() -> ProcLimits {
        ProcLimits {
            parse: ParseLimits {
                max_bytes: 1 << 20,
                max_entries: 1 << 16,
                max_line_bytes: 1 << 16,
            },
            max_read_calls: 4096,
            max_metadata_bytes: 1 << 20,
        }
    }

    #[test]
    fn same_process_creator_comparison_accepts() {
        let _guard = crate::FD_TABLE.lock().unwrap();
        let epoch = ObserverEpoch::new(limits(), &OperationControl::unlimited()).unwrap();
        assert!(!creator_pid_refused(epoch.creator()));
    }

    /// Stale-epoch refusal in a real forked child: the child runs only the
    /// allocation-free creator predicate (vDSO getpid + integer comparison)
    /// inside pre_exec, then reports one byte through a pipe. No heap, no
    /// locks, no epoch Arc is touched post-fork.
    #[test]
    fn forked_child_creator_guard_refuses() {
        let _guard = crate::FD_TABLE.lock().unwrap();
        let epoch = ObserverEpoch::new(limits(), &OperationControl::unlimited()).unwrap();
        let creator = epoch.creator();
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut child = std::process::Command::new("/bin/true");
        unsafe {
            child.pre_exec(move || {
                let refused = creator_pid_refused(creator);
                let byte: &[u8] = if refused { b"R" } else { b"A" };
                rustix::io::write(&writer, byte)
                    .map(|_| ())
                    .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
            });
        }
        let mut child = child.spawn().expect("spawn /bin/true fixture");
        // The closure-owned write end stays open in the parent until the
        // Command drops; the one-byte read still completes on arrival.
        let mut verdict = [0u8; 1];
        rustix::io::read(&reader, &mut verdict).expect("read child verdict");
        let status = child.wait().expect("reap fixture");
        assert!(status.success());
        assert_eq!(verdict, [b'R'], "forked child must refuse the parent epoch");
        // The parent epoch is unaffected and still authoritative here.
        assert!(!creator_pid_refused(epoch.creator()));
    }
}
