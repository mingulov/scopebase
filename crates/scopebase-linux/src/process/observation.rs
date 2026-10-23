// SPDX-License-Identifier: Apache-2.0
// Acquired process observations, birth verification and bounded body reads.
use super::epoch::ObserverEpoch;
use super::{
    checked_open_at2,
    epoch::{guard_acquire, guard_retained, is_nonleader, open_pidfd, target_status_fault},
    map_errno, namespace_sample, native, parse_stat, parse_target_status, pid_name, poll_pidfd,
    read_metadata_eof, transport_vec, validate_limits, NsKey, Pid, PollClass, ProcLimits, ProcOps,
};
#[cfg(feature = "mapping")]
use super::{map_files_name, MAP_FILES_NAME_LEN};
use crate::{
    control::OperationControl,
    error::{
        EffectSummary, LimitKind, LinuxError, ProcMember, ProcNamespaceKind, ProcOperation,
        ProcessErrorContext, Reason, ResourceCharges, Stage,
    },
    identity::{MountViewId, ObservationInterval, ProcViewId, TaskBirthObservation},
    procfs::{parse_maps, parse_mountinfo, MapsSnapshot, MountTableSnapshot},
};
use std::{
    fmt,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::Instant,
};

/// Birth/liveness verdict over the ORIGINAL pidfd owner. Never SameImage:
/// exec, failed exec and A-to-B-to-A at unchanged birth may still verify
/// AliveSameBirth. A Changed report carries the retained view marker with
/// different ticks: a contradiction report, not new authority.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BirthStatus {
    AliveSameBirth,
    Exited,
    Changed,
    Inconclusive,
}

/// Descriptive birth verification: values and markers only, no descriptors.
pub struct BirthVerification {
    status: BirthStatus,
    retained: TaskBirthObservation,
    sampled: Option<TaskBirthObservation>,
    leader: Option<u8>,
    interval: ObservationInterval,
    charges: ResourceCharges,
    effects: EffectSummary,
}
impl BirthVerification {
    pub fn status(&self) -> BirthStatus {
        self.status
    }
    pub fn retained_birth(&self) -> &TaskBirthObservation {
        &self.retained
    }
    pub fn sampled_birth(&self) -> Option<&TaskBirthObservation> {
        self.sampled.as_ref()
    }
    pub fn leader_state(&self) -> Option<u8> {
        self.leader
    }
    pub fn interval(&self) -> &ObservationInterval {
        &self.interval
    }
    pub fn charges(&self) -> &ResourceCharges {
        &self.charges
    }
    pub fn effects(&self) -> &EffectSummary {
        &self.effects
    }
}
impl fmt::Debug for BirthVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BirthVerification")
    }
}

/// Retained process observation: a real epoch authority clone plus its own six
/// FDs (proc root, observer PID namespace, original target pidfd, target proc
/// directory, target PID namespace, target mount namespace). No signal, wait,
/// adoption, raw pidfd export or descriptor borrow exists at this type.
pub struct ProcessObservation {
    pid: Pid,
    epoch: ObserverEpoch,
    birth: TaskBirthObservation,
    proc_view: ProcViewId,
    mount_view: MountViewId,
    root: OwnedFd,
    // Retained authority handles: three of the six owner FDs, kept alive for
    // provenance/lifetime, never re-queried after their authenticated capture.
    #[allow(dead_code)]
    obs_ns: OwnedFd,
    pidfd: OwnedFd,
    dir: OwnedFd,
    #[allow(dead_code)]
    pid_ns: OwnedFd,
    #[allow(dead_code)]
    mnt_ns: OwnedFd,
    pid_key: NsKey,
    mnt_key: NsKey,
    verify_limits: ProcLimits,
    interval: ObservationInterval,
    charges: ResourceCharges,
    effects: EffectSummary,
}
impl ProcessObservation {
    /// Six-step strict acquisition: fresh-root creator guard, descriptive
    /// target pre-sample, original target pidfd with nonterminal poll,
    /// retained directory with three independent poll brackets and
    /// pre/retained tick agreement, target namespace capture, full view
    /// guard, then fresh FD-free markers. Exited/Changed/Inconclusive and
    /// view changes refuse; no owner or snapshot returns on any error.
    pub fn acquire(
        pid: Pid,
        epoch: &ObserverEpoch,
        limits: ProcLimits,
        control: &OperationControl,
    ) -> Result<Self, LinuxError> {
        let started = Instant::now();
        let mut ops = ProcOps::new(ProcOperation::Acquire, limits);
        ops.check(control, Stage::ConfigureProcess)?;
        validate_limits(limits)?;
        let mut meta = transport_vec(&mut ops, limits.max_metadata_bytes, Stage::ConfigureProcess)?;
        let (root, obs_ns) = guard_acquire(epoch, &mut ops, control, &mut meta)?;
        let pre_ticks = pre_sample(&mut ops, control, root.as_fd(), pid, &mut meta)?;
        let pidfd = open_pidfd(&mut ops, control, pid, ProcMember::Pidfd)?;
        let first = poll_pidfd(&mut ops, control, pidfd.as_fd(), ProcMember::Pidfd)?;
        if first.class == PollClass::Terminal {
            return Err(exited_error(&ops, None));
        }
        let mut scratch = [0u8; 12];
        let (dir, ticks, state) = {
            let name = pid_name(pid, &mut scratch);
            ops.member = Some(ProcMember::TargetDirectory);
            let dir = checked_open_at2(
                &mut ops,
                control,
                root.as_fd(),
                name,
                true,
                Stage::AcquireProcess,
            )?;
            let second = poll_pidfd(&mut ops, control, pidfd.as_fd(), ProcMember::Pidfd)?;
            if second.class == PollClass::Terminal {
                return Err(exited_error(&ops, None));
            }
            let sample = read_target_stat(&mut ops, control, dir.as_fd(), pid, &mut meta)?;
            if sample.ticks != pre_ticks {
                return Err(changed_error(&ops, pre_ticks, &sample));
            }
            let third = poll_pidfd(&mut ops, control, pidfd.as_fd(), ProcMember::Pidfd)?;
            if third.class == PollClass::Terminal {
                return Err(exited_error(&ops, Some((pre_ticks, &sample))));
            }
            read_target_status(&mut ops, control, dir.as_fd(), pid, &mut meta)?;
            (dir, sample.ticks, sample.state)
        };
        let _ = state;
        let (pid_ns, pid_key) = namespace_sample(
            &mut ops,
            control,
            dir.as_fd(),
            c"pid",
            b"pid:[",
            ProcNamespaceKind::Pid,
            native::CLONE_NEWPID,
            ProcMember::TargetPidNamespace,
        )?;
        let (mnt_ns, mnt_key) = namespace_sample(
            &mut ops,
            control,
            dir.as_fd(),
            c"mnt",
            b"mnt:[",
            ProcNamespaceKind::Mount,
            native::CLONE_NEWNS,
            ProcMember::TargetMountNamespace,
        )?;
        view_guard(
            &mut ops,
            control,
            dir.as_fd(),
            pidfd.as_fd(),
            pid,
            ticks,
            &pid_key,
            &mnt_key,
            &mut meta,
        )?;
        let proc_view = ProcViewId::fresh(epoch.marker());
        let mount_view = MountViewId::fresh(&proc_view);
        let birth = TaskBirthObservation::new(pid, ticks, proc_view.clone());
        ops.post(control, Stage::AcquireProcess)?;
        let finished = Instant::now();
        ops.fd_released(6);
        drop(meta);
        Ok(Self {
            pid,
            epoch: epoch.clone(),
            birth,
            proc_view,
            mount_view,
            root,
            obs_ns,
            pidfd,
            dir,
            pid_ns,
            mnt_ns,
            pid_key,
            mnt_key,
            verify_limits: limits,
            interval: ObservationInterval::new(started, finished),
            charges: ops.charges(),
            effects: ops.effects(),
        })
    }

    /// Fresh-budget birth verification under the stored acquire ceilings. Runs
    /// the full retained-root creator guard, then original-target poll, stat
    /// sample and second poll. Terminal first poll yields Exited with no
    /// sample and no target stat attempt; creator costs remain charged.
    pub fn verify_birth(
        &self,
        control: &OperationControl,
    ) -> Result<BirthVerification, LinuxError> {
        let started = Instant::now();
        let mut ops = ProcOps::new(ProcOperation::VerifyBirth, self.verify_limits);
        ops.check(control, Stage::ConfigureProcess)?;
        validate_limits(self.verify_limits)?;
        let mut meta = transport_vec(
            &mut ops,
            self.verify_limits.max_metadata_bytes,
            Stage::ConfigureProcess,
        )?;
        guard_retained(&self.epoch, self.root.as_fd(), &mut ops, control, &mut meta)?;
        let outcome = birth_check(
            &mut ops,
            control,
            self.dir.as_fd(),
            self.pidfd.as_fd(),
            self.pid,
            self.birth.start_ticks(),
            &mut meta,
        )?;
        ops.post(control, Stage::VerifyBirth)?;
        let finished = Instant::now();
        drop(meta);
        let (status, sampled, leader) = match outcome {
            BirthOutcome::Alive(sample) => (
                BirthStatus::AliveSameBirth,
                Some(TaskBirthObservation::new(
                    self.pid,
                    sample.ticks,
                    self.proc_view.clone(),
                )),
                Some(sample.state),
            ),
            BirthOutcome::Exited(None) => (BirthStatus::Exited, None, None),
            BirthOutcome::Exited(Some(sample)) => (
                BirthStatus::Exited,
                Some(TaskBirthObservation::new(
                    self.pid,
                    sample.ticks,
                    self.proc_view.clone(),
                )),
                Some(sample.state),
            ),
            BirthOutcome::Changed(sample) => (
                BirthStatus::Changed,
                Some(TaskBirthObservation::new(
                    self.pid,
                    sample.ticks,
                    self.proc_view.clone(),
                )),
                Some(sample.state),
            ),
            BirthOutcome::Inconclusive(sample) => (
                BirthStatus::Inconclusive,
                Some(TaskBirthObservation::new(
                    self.pid,
                    sample.ticks,
                    self.proc_view.clone(),
                )),
                Some(sample.state),
            ),
        };
        Ok(BirthVerification {
            status,
            retained: self.birth.clone(),
            sampled,
            leader,
            interval: ObservationInterval::new(started, finished),
            charges: ops.charges(),
            effects: ops.effects(),
        })
    }

    pub fn read_maps(
        &self,
        limits: ProcLimits,
        control: &OperationControl,
    ) -> Result<MapsObservation, LinuxError> {
        let (snapshot, interval, charges, effects) = self.read_body(
            limits,
            control,
            ProcOperation::ReadMaps,
            c"maps",
            ProcMember::Maps,
            BodyKind::Maps,
            default_hook(),
        )?;
        Ok(MapsObservation {
            snapshot: match snapshot {
                BodySnapshot::Maps(snapshot) => snapshot,
                BodySnapshot::Mounts(_) => unreachable!("maps body kind"),
            },
            birth: self.birth.clone(),
            proc_view: self.proc_view.clone(),
            mount_view: self.mount_view.clone(),
            interval,
            charges,
            effects,
        })
    }

    pub fn read_mountinfo(
        &self,
        limits: ProcLimits,
        control: &OperationControl,
    ) -> Result<MountObservation, LinuxError> {
        let (snapshot, interval, charges, effects) = self.read_body(
            limits,
            control,
            ProcOperation::ReadMountinfo,
            c"mountinfo",
            ProcMember::Mountinfo,
            BodyKind::Mounts,
            default_hook(),
        )?;
        Ok(MountObservation {
            snapshot: match snapshot {
                BodySnapshot::Mounts(snapshot) => snapshot,
                BodySnapshot::Maps(_) => unreachable!("mount body kind"),
            },
            birth: self.birth.clone(),
            proc_view: self.proc_view.clone(),
            mount_view: self.mount_view.clone(),
            interval,
            charges,
            effects,
        })
    }

    /// Test-only read with the actual-native EOF hook armed: the hook runs
    /// after a native body read returns zero, before that post-read poll or
    /// EOF interpretation. Production passes no hook.
    #[cfg(test)]
    pub(crate) fn read_maps_with_hook(
        &self,
        limits: ProcLimits,
        control: &OperationControl,
        hook: EofHook,
    ) -> Result<MapsObservation, LinuxError> {
        let (snapshot, interval, charges, effects) = self.read_body(
            limits,
            control,
            ProcOperation::ReadMaps,
            c"maps",
            ProcMember::Maps,
            BodyKind::Maps,
            hook,
        )?;
        Ok(MapsObservation {
            snapshot: match snapshot {
                BodySnapshot::Maps(snapshot) => snapshot,
                BodySnapshot::Mounts(_) => unreachable!("maps body kind"),
            },
            birth: self.birth.clone(),
            proc_view: self.proc_view.clone(),
            mount_view: self.mount_view.clone(),
            interval,
            charges,
            effects,
        })
    }

    /// Retained-root creator guard, target view guard, bracketed body read to
    /// required EOF, unchanged LX05 parse, second view guard, publication.
    /// No prefix returns on any error; a failed final guard keeps reached
    /// parser charges but returns no observation.
    fn read_body(
        &self,
        limits: ProcLimits,
        control: &OperationControl,
        operation: ProcOperation,
        name: &std::ffi::CStr,
        member: ProcMember,
        kind: BodyKind,
        hook: EofHook,
    ) -> Result<
        (
            BodySnapshot,
            ObservationInterval,
            ResourceCharges,
            EffectSummary,
        ),
        LinuxError,
    > {
        let started = Instant::now();
        let mut ops = ProcOps::new(operation, limits);
        ops.check(control, Stage::ConfigureProcess)?;
        validate_limits(limits)?;
        let mut meta = transport_vec(&mut ops, limits.max_metadata_bytes, Stage::ConfigureProcess)?;
        let mut body = transport_vec(&mut ops, limits.parse.max_bytes, Stage::ConfigureProcess)?;
        guard_retained(&self.epoch, self.root.as_fd(), &mut ops, control, &mut meta)?;
        view_guard(
            &mut ops,
            control,
            self.dir.as_fd(),
            self.pidfd.as_fd(),
            self.pid,
            self.birth.start_ticks(),
            &self.pid_key,
            &self.mnt_key,
            &mut meta,
        )?;
        ops.member = Some(member);
        let file = checked_open_at2(
            &mut ops,
            control,
            self.dir.as_fd(),
            name,
            false,
            Stage::OpenProcMember,
        )?;
        let initial = poll_pidfd(&mut ops, control, self.pidfd.as_fd(), ProcMember::Pidfd)?;
        if initial.class == PollClass::Terminal {
            return Err(exited_error(&ops, None));
        }
        read_body_loop(
            &mut ops,
            control,
            file.as_fd(),
            self.pidfd.as_fd(),
            &mut body,
            limits,
            member,
            hook,
        )?;
        ops.fd_released(1);
        drop(file);
        let snapshot = match kind {
            BodyKind::Maps => parse_maps(&body, limits.parse)
                .map(BodySnapshot::Maps)
                .map_err(|error| adopt_parser_refusal(&mut ops, &error, member))?,
            BodyKind::Mounts => parse_mountinfo(&body, limits.parse)
                .map(BodySnapshot::Mounts)
                .map_err(|error| adopt_parser_refusal(&mut ops, &error, member))?,
        };
        view_guard(
            &mut ops,
            control,
            self.dir.as_fd(),
            self.pidfd.as_fd(),
            self.pid,
            self.birth.start_ticks(),
            &self.pid_key,
            &self.mnt_key,
            &mut meta,
        )?;
        ops.post(control, Stage::VerifyBirth)?;
        let finished = Instant::now();
        drop(meta);
        drop(body);
        Ok((
            snapshot,
            ObservationInterval::new(started, finished),
            ops.charges(),
            ops.effects(),
        ))
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }
    pub fn epoch(&self) -> &ObserverEpoch {
        &self.epoch
    }
    pub fn birth(&self) -> &TaskBirthObservation {
        &self.birth
    }
    pub fn proc_view(&self) -> &ProcViewId {
        &self.proc_view
    }
    pub fn mount_view(&self) -> &MountViewId {
        &self.mount_view
    }
    pub fn acquisition_interval(&self) -> &ObservationInterval {
        &self.interval
    }
    pub fn acquisition_charges(&self) -> &ResourceCharges {
        &self.charges
    }
    pub fn acquisition_effects(&self) -> &EffectSummary {
        &self.effects
    }
}
impl fmt::Debug for ProcessObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessObservation")
    }
}

/// Parsed maps plus descriptive provenance; owns the snapshot, no FDs.
pub struct MapsObservation {
    snapshot: MapsSnapshot,
    birth: TaskBirthObservation,
    proc_view: ProcViewId,
    mount_view: MountViewId,
    interval: ObservationInterval,
    charges: ResourceCharges,
    effects: EffectSummary,
}
impl MapsObservation {
    pub fn snapshot(&self) -> &MapsSnapshot {
        &self.snapshot
    }
    pub fn birth(&self) -> &TaskBirthObservation {
        &self.birth
    }
    pub fn proc_view(&self) -> &ProcViewId {
        &self.proc_view
    }
    pub fn mount_view(&self) -> &MountViewId {
        &self.mount_view
    }
    pub fn interval(&self) -> &ObservationInterval {
        &self.interval
    }
    pub fn charges(&self) -> &ResourceCharges {
        &self.charges
    }
    pub fn effects(&self) -> &EffectSummary {
        &self.effects
    }
}
impl fmt::Debug for MapsObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapsObservation")
    }
}

/// Parsed mount table plus descriptive provenance; owns the snapshot, no FDs.
pub struct MountObservation {
    snapshot: MountTableSnapshot,
    birth: TaskBirthObservation,
    proc_view: ProcViewId,
    mount_view: MountViewId,
    interval: ObservationInterval,
    charges: ResourceCharges,
    effects: EffectSummary,
}
impl MountObservation {
    pub fn snapshot(&self) -> &MountTableSnapshot {
        &self.snapshot
    }
    pub fn birth(&self) -> &TaskBirthObservation {
        &self.birth
    }
    pub fn proc_view(&self) -> &ProcViewId {
        &self.proc_view
    }
    pub fn mount_view(&self) -> &MountViewId {
        &self.mount_view
    }
    pub fn interval(&self) -> &ObservationInterval {
        &self.interval
    }
    pub fn charges(&self) -> &ResourceCharges {
        &self.charges
    }
    pub fn effects(&self) -> &EffectSummary {
        &self.effects
    }
}
impl fmt::Debug for MountObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MountObservation")
    }
}

/// Physical identity of one mapped file as `stat` through its
/// `/proc/<pid>/map_files/<start>-<end>` link reports it (ADAPT P
/// src/discovery/instances.rs `MappedFileIdentity` @2c2713e6, lines 144-148).
/// Compares like-for-like with a held descriptor's fstat `(st_dev, st_ino)`,
/// never with a maps-device tuple.
#[cfg(feature = "mapping")]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct MapFilesIdentity {
    device: u64,
    inode: u64,
}

#[cfg(feature = "mapping")]
impl MapFilesIdentity {
    pub fn device(&self) -> u64 {
        self.device
    }
    pub fn inode(&self) -> u64 {
        self.inode
    }
}

#[cfg(feature = "mapping")]
impl fmt::Debug for MapFilesIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapFilesIdentity")
    }
}

/// One bracketed map_files association plus its interval and charges. The
/// mapped object's own descriptor stays open in the observation (F14):
/// identity is read from the held object, and both descriptors are alive
/// while the caller compares.
#[cfg(feature = "mapping")]
pub struct MapFilesObservation {
    identity: MapFilesIdentity,
    interval: ObservationInterval,
    charges: ResourceCharges,
    effects: EffectSummary,
    object: OwnedFd,
}

#[cfg(feature = "mapping")]
impl MapFilesObservation {
    pub fn identity(&self) -> MapFilesIdentity {
        self.identity
    }

    /// The retained mapped-object descriptor behind [`Self::identity`].
    pub fn object(&self) -> BorrowedFd<'_> {
        self.object.as_fd()
    }
    pub fn interval(&self) -> &ObservationInterval {
        &self.interval
    }
    pub fn charges(&self) -> &ResourceCharges {
        &self.charges
    }
    pub fn effects(&self) -> &EffectSummary {
        &self.effects
    }
}

#[cfg(feature = "mapping")]
impl fmt::Debug for MapFilesObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapFilesObservation")
    }
}

#[cfg(feature = "mapping")]
impl ProcessObservation {
    /// Stat one map_files entry relative to the retained target directory:
    /// retained-root creator guard, full target view guard, held map_files
    /// directory open, one following `statat` of the rendered
    /// `{start:x}-{end:x}` name (ADAPT P src/discovery/identity.rs
    /// `MapFilesDir::identity` @2c2713e6), then a final nonterminal pidfd
    /// poll. A missing entry (changed VMA) is Disappeared; denial keeps its
    /// actual errno; a terminal final poll is Exited, never an identity.
    pub fn read_map_files_identity(
        &self,
        start: u64,
        end: u64,
        limits: ProcLimits,
        control: &OperationControl,
    ) -> Result<MapFilesObservation, LinuxError> {
        let started = Instant::now();
        let mut ops = ProcOps::new(ProcOperation::ReadMapFiles, limits);
        ops.check(control, Stage::ConfigureProcess)?;
        validate_limits(limits)?;
        let mut meta = transport_vec(&mut ops, limits.max_metadata_bytes, Stage::ConfigureProcess)?;
        guard_retained(&self.epoch, self.root.as_fd(), &mut ops, control, &mut meta)?;
        view_guard(
            &mut ops,
            control,
            self.dir.as_fd(),
            self.pidfd.as_fd(),
            self.pid,
            self.birth.start_ticks(),
            &self.pid_key,
            &self.mnt_key,
            &mut meta,
        )?;
        ops.member = Some(ProcMember::MapFiles);
        let dir = checked_open_at2(
            &mut ops,
            control,
            self.dir.as_fd(),
            c"map_files",
            true,
            Stage::OpenProcMember,
        )?;
        ops.check(control, Stage::ReadProc)?;
        let mut scratch = [0u8; MAP_FILES_NAME_LEN];
        let name = map_files_name(start, end, &mut scratch);
        // F14: open the VMA's own file and read identity from the held
        // object. The entry is a kernel-rendered symlink, so plain
        // openat follows it (openat2's NO_SYMLINKS would refuse); the
        // name is hex-and-dash only and the parent dir is strictly bound.
        let object = ops.syscall(|| {
            rustix::fs::openat(
                dir.as_fd(),
                name,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
        });
        let object = match object {
            Ok(object) => object,
            Err(errno) => {
                ops.fd_released(1);
                return Err(ops.fail(Stage::ReadProc, map_errno(errno), Some(errno.into())));
            }
        };
        ops.fd_acquired();
        if let Err(error) = super::check_cloexec(&mut ops, control, &object, Stage::ReadProc) {
            // The helper released the object; the directory drops here too.
            ops.fd_released(1);
            return Err(error);
        }
        let stat = ops.syscall(|| rustix::fs::fstat(&object));
        let stat = match stat {
            Ok(stat) => stat,
            Err(errno) => {
                ops.fd_released(2);
                return Err(ops.fail(Stage::ReadProc, map_errno(errno), Some(errno.into())));
            }
        };
        ops.post(control, Stage::ReadProc)?;
        ops.fd_released(1);
        drop(dir);
        let last = poll_pidfd(&mut ops, control, self.pidfd.as_fd(), ProcMember::Pidfd)?;
        if last.class == PollClass::Terminal {
            return Err(exited_error(&ops, None));
        }
        let device = u64::try_from(stat.st_dev as i128)
            .map_err(|_| ops.fail(Stage::ReadProc, Reason::Malformed, None))?;
        let inode = u64::try_from(stat.st_ino as i128)
            .map_err(|_| ops.fail(Stage::ReadProc, Reason::Malformed, None))?;
        ops.post(control, Stage::VerifyBirth)?;
        let finished = Instant::now();
        drop(meta);
        Ok(MapFilesObservation {
            identity: MapFilesIdentity { device, inode },
            interval: ObservationInterval::new(started, finished),
            charges: ops.charges(),
            effects: ops.effects(),
            object,
        })
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum BodyKind {
    Maps,
    Mounts,
}
enum BodySnapshot {
    Maps(MapsSnapshot),
    Mounts(MountTableSnapshot),
}

/// Actual-native EOF hook: call-local, test-only. Production has no hook.
#[cfg(test)]
pub(crate) type EofHook = Option<fn()>;
#[cfg(not(test))]
type EofHook = ();
#[cfg(test)]
fn default_hook() -> EofHook {
    None
}
#[cfg(not(test))]
fn default_hook() -> EofHook {}
fn run_hook(hook: EofHook) {
    #[cfg(test)]
    if let Some(hook) = hook {
        hook();
    }
    #[cfg(not(test))]
    let _ = hook;
}

/// Descriptive target pre-sample under a temporary directory: stat ticks plus
/// Pid/Tgid status. Proves nothing alone; the retained brackets decide.
fn pre_sample(
    ops: &mut ProcOps,
    control: &OperationControl,
    root: BorrowedFd<'_>,
    pid: Pid,
    meta: &mut Vec<u8>,
) -> Result<u64, LinuxError> {
    let mut scratch = [0u8; 12];
    let name = pid_name(pid, &mut scratch);
    ops.member = Some(ProcMember::TargetDirectory);
    let dir = checked_open_at2(ops, control, root, name, true, Stage::AcquireProcess)?;
    // NUL-terminated scratch outlives the open above; re-derive is needless.
    let sample = read_target_stat(ops, control, dir.as_fd(), pid, meta)?;
    read_target_status(ops, control, dir.as_fd(), pid, meta)?;
    ops.fd_released(1);
    drop(dir);
    Ok(sample.ticks)
}

pub(crate) struct BirthSample {
    pub(crate) ticks: u64,
    pub(crate) state: u8,
}

/// Complete retained-relative stat sample: open, EOF read, strict parse.
fn read_target_stat(
    ops: &mut ProcOps,
    control: &OperationControl,
    dir: BorrowedFd<'_>,
    pid: Pid,
    meta: &mut Vec<u8>,
) -> Result<BirthSample, LinuxError> {
    ops.member = Some(ProcMember::TargetStat);
    let stat = checked_open_at2(ops, control, dir, c"stat", false, Stage::OpenProcMember)?;
    read_metadata_eof(ops, control, stat.as_fd(), meta, Stage::ReadProc)?;
    ops.fd_released(1);
    drop(stat);
    parse_stat(meta, pid)
        .map(|parsed| BirthSample {
            ticks: parsed.start_ticks,
            state: parsed.state,
        })
        .map_err(|_| ops.fail(Stage::ParseProcStat, Reason::Malformed, None))
}

/// Complete target status with strict Pid/Tgid proof; nonleader is InvalidInput.
fn read_target_status(
    ops: &mut ProcOps,
    control: &OperationControl,
    dir: BorrowedFd<'_>,
    pid: Pid,
    meta: &mut Vec<u8>,
) -> Result<(), LinuxError> {
    ops.member = Some(ProcMember::TargetStatus);
    let status = checked_open_at2(ops, control, dir, c"status", false, Stage::OpenProcMember)?;
    read_metadata_eof(ops, control, status.as_fd(), meta, Stage::ReadProc)?;
    ops.fd_released(1);
    drop(status);
    if parse_target_status(meta, pid).is_err() {
        let reason = if is_nonleader(target_status_fault(meta, pid)) {
            Reason::InvalidInput
        } else {
            Reason::WrongContext
        };
        return Err(ops.fail(Stage::AuthenticateProcView, reason, None));
    }
    Ok(())
}

pub(crate) enum BirthOutcome {
    Alive(BirthSample),
    Exited(Option<BirthSample>),
    Changed(BirthSample),
    Inconclusive(BirthSample),
}

/// Leader states that prove sampled original-owner birth/liveness. Every other
/// alphabetic state (including Z/X/x) is valid but insufficient observation.
fn state_proves_alive(state: u8) -> bool {
    matches!(state, b'R' | b'S' | b'D' | b'T' | b't' | b'I')
}

/// Pure birth verdict over poll brackets and one stat sample. Terminal
/// pre-poll exits with no sample; terminal post-poll exits with the sample
/// retained; differing ticks contradict; unrecognized alpha states are
/// insufficient. No namespace change is encoded here.
pub(crate) fn classify_birth(
    pre_terminal: bool,
    sampled: Option<BirthSample>,
    post_terminal: bool,
    retained: u64,
) -> BirthOutcome {
    if pre_terminal {
        return BirthOutcome::Exited(None);
    }
    let Some(sample) = sampled else {
        // Unreachable through birth_check: a nonterminal pre-poll always
        // attempts the stat sample, and stat failure is a typed error, not a
        // verdict. Treat a missing sample as insufficient, never alive.
        return BirthOutcome::Inconclusive(BirthSample {
            ticks: retained,
            state: b'?',
        });
    };
    if post_terminal {
        return BirthOutcome::Exited(Some(sample));
    }
    if sample.ticks != retained {
        return BirthOutcome::Changed(sample);
    }
    if state_proves_alive(sample.state) {
        BirthOutcome::Alive(sample)
    } else {
        BirthOutcome::Inconclusive(sample)
    }
}

/// Internal birth check in the current operation's aggregate budget: target
/// pre-poll, complete stat sample, target post-poll. Stat open/read failure
/// (even ENOENT/ESRCH) is a typed member error, not terminal proof; a valid
/// sampled stat cannot erase a poll failure.
fn birth_check(
    ops: &mut ProcOps,
    control: &OperationControl,
    dir: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    pid: Pid,
    retained: u64,
    meta: &mut Vec<u8>,
) -> Result<BirthOutcome, LinuxError> {
    let pre = poll_pidfd(ops, control, pidfd, ProcMember::Pidfd)?;
    if pre.class == PollClass::Terminal {
        return Ok(BirthOutcome::Exited(None));
    }
    let sample = read_target_stat(ops, control, dir, pid, meta)?;
    let post = poll_pidfd(ops, control, pidfd, ProcMember::Pidfd)?;
    Ok(classify_birth(
        false,
        Some(sample),
        post.class == PollClass::Terminal,
        retained,
    ))
}

/// Full target view guard, 23 fixed non-data attempts: internal birth check
/// requiring AliveSameBirth, fresh PID and mount namespace samples compared
/// to the retained keys, then one final nonterminal pidfd poll.
fn view_guard(
    ops: &mut ProcOps,
    control: &OperationControl,
    dir: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    pid: Pid,
    retained: u64,
    pid_key: &NsKey,
    mnt_key: &NsKey,
    meta: &mut Vec<u8>,
) -> Result<(), LinuxError> {
    match birth_check(ops, control, dir, pidfd, pid, retained, meta)? {
        BirthOutcome::Alive(_) => {}
        BirthOutcome::Exited(_) => return Err(exited_error(ops, None)),
        BirthOutcome::Changed(sample) => return Err(changed_error(ops, retained, &sample)),
        BirthOutcome::Inconclusive(sample) => {
            return Err(inconclusive_error(ops, retained, &sample))
        }
    }
    let (fresh_pid, key) = namespace_sample(
        ops,
        control,
        dir,
        c"pid",
        b"pid:[",
        ProcNamespaceKind::Pid,
        native::CLONE_NEWPID,
        ProcMember::TargetPidNamespace,
    )?;
    ops.fd_released(1);
    drop(fresh_pid);
    if key != *pid_key {
        return Err(ops.fail(Stage::CheckProcessNamespace, Reason::ChangedSource, None));
    }
    let (fresh_mnt, key) = namespace_sample(
        ops,
        control,
        dir,
        c"mnt",
        b"mnt:[",
        ProcNamespaceKind::Mount,
        native::CLONE_NEWNS,
        ProcMember::TargetMountNamespace,
    )?;
    ops.fd_released(1);
    drop(fresh_mnt);
    if key != *mnt_key {
        return Err(ops.fail(Stage::CheckProcessNamespace, Reason::ChangedSource, None));
    }
    let last = poll_pidfd(ops, control, pidfd, ProcMember::Pidfd)?;
    if last.class == PollClass::Terminal {
        return Err(exited_error(ops, None));
    }
    Ok(())
}

/// Translate a valid Exited birth result into an acquire/read refusal:
/// VerifyBirth/Disappeared at Pidfd. No target work follows.
fn exited_error(ops: &ProcOps, sampled: Option<(u64, &BirthSample)>) -> LinuxError {
    let mut context = ProcessErrorContext::new(ops.operation, Some(ProcMember::Pidfd));
    if let Some((retained, sample)) = sampled {
        context.retained_ticks = Some(retained);
        context.sampled_ticks = Some(sample.ticks);
        context.leader_state = Some(sample.state);
    }
    ops.fail_with(Stage::VerifyBirth, Reason::Disappeared, None, context)
}

/// Changed contradiction at TargetStat with retained/sampled evidence.
fn changed_error(ops: &ProcOps, retained: u64, sampled: &BirthSample) -> LinuxError {
    let mut context = ProcessErrorContext::new(ops.operation, Some(ProcMember::TargetStat));
    context.retained_ticks = Some(retained);
    context.sampled_ticks = Some(sampled.ticks);
    context.leader_state = Some(sampled.state);
    ops.fail_with(Stage::VerifyBirth, Reason::ChangedSource, None, context)
}

/// Inconclusive leader observation at TargetStat with reached evidence.
fn inconclusive_error(ops: &ProcOps, retained: u64, sampled: &BirthSample) -> LinuxError {
    let mut context = ProcessErrorContext::new(ops.operation, Some(ProcMember::TargetStat));
    context.retained_ticks = Some(retained);
    context.sampled_ticks = Some(sampled.ticks);
    context.leader_state = Some(sampled.state);
    ops.fail_with(Stage::VerifyBirth, Reason::Inconclusive, None, context)
}

/// Bracketed body read to required EOF: an original-pidfd poll before each
/// actual read attempt and after successful reads, retryable EINTR and EOF.
/// A non-retryable read error stops before a second poll with its actual
/// errno. Every attempt preflights the shared R; body bytes share B with a
/// one-byte refusal witness. Body oversize refuses InputBytes: the body is
/// parser input bounded by parse.max_bytes.
fn read_body_loop(
    ops: &mut ProcOps,
    control: &OperationControl,
    file: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    body: &mut Vec<u8>,
    limits: ProcLimits,
    member: ProcMember,
    hook: EofHook,
) -> Result<(), LinuxError> {
    let bound = limits.parse.max_bytes as u64;
    body.clear();
    loop {
        ops.member = Some(ProcMember::Pidfd);
        let pre = poll_pidfd(ops, control, pidfd, ProcMember::Pidfd)?;
        if pre.class == PollClass::Terminal {
            ops.member = Some(member);
            return Err(exited_error(ops, None));
        }
        ops.member = Some(member);
        ops.check(control, Stage::ReadProc)?;
        ops.preflight_read(Stage::ReadProc)?;
        let spare = body.capacity().saturating_sub(body.len()).min(4096);
        if spare == 0 {
            return Err(ops.fail(
                Stage::ReadProc,
                Reason::LimitExceeded(LimitKind::InputBytes),
                None,
            ));
        }
        let base = body.len();
        body.resize(base + spare, 0);
        let slot = &mut body[base..];
        let got = ops.syscall(|| rustix::io::read(file, slot));
        match got {
            Err(rustix::io::Errno::INTR) => {
                body.truncate(base);
                ops.read_calls += 1;
                ops.post(control, Stage::ReadProc)?;
                let post = poll_pidfd(ops, control, pidfd, ProcMember::Pidfd)?;
                if post.class == PollClass::Terminal {
                    ops.member = Some(member);
                    return Err(exited_error(ops, None));
                }
                ops.member = Some(member);
                continue;
            }
            Err(errno) => {
                body.truncate(base);
                ops.read_calls += 1;
                return Err(ops.fail(Stage::ReadProc, map_errno(errno), Some(errno.into())));
            }
            Ok(0) => {
                body.truncate(base);
                ops.read_calls += 1;
                ops.post(control, Stage::ReadProc)?;
                run_hook(hook);
                let post = poll_pidfd(ops, control, pidfd, ProcMember::Pidfd)?;
                if post.class == PollClass::Terminal {
                    ops.member = Some(member);
                    return Err(exited_error(ops, None));
                }
                ops.member = Some(member);
                return Ok(());
            }
            Ok(n) => {
                body.truncate(base + n);
                ops.read_calls += 1;
                ops.body_bytes += n as u64;
                ops.post(control, Stage::ReadProc)?;
                let post = poll_pidfd(ops, control, pidfd, ProcMember::Pidfd)?;
                if post.class == PollClass::Terminal {
                    ops.member = Some(member);
                    return Err(exited_error(ops, None));
                }
                ops.member = Some(member);
                if ops.body_bytes > bound {
                    return Err(ops.fail(
                        Stage::ReadProc,
                        Reason::LimitExceeded(LimitKind::InputBytes),
                        None,
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{control::OperationControl, procfs::ParseLimits};

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

    fn sample(ticks: u64, state: u8) -> Option<BirthSample> {
        Some(BirthSample { ticks, state })
    }

    /// Deterministic identity-change injection: every status-table row is
    /// covered independent of PID-reuse luck (the plan's required control).
    #[test]
    fn birth_classifier_covers_every_status_row() {
        // Terminal pre-poll exits with no sample, whatever follows.
        assert!(matches!(
            classify_birth(true, None, false, 11),
            BirthOutcome::Exited(None)
        ));
        // Terminal post-poll exits with the sample retained, even on
        // same-birth zombies or contradictory ticks.
        assert!(matches!(
            classify_birth(false, sample(11, b'R'), true, 11),
            BirthOutcome::Exited(Some(_))
        ));
        assert!(matches!(
            classify_birth(false, sample(12, b'Z'), true, 11),
            BirthOutcome::Exited(Some(_))
        ));
        // Same ticks + recognized leader states verify alive.
        for state in [b'R', b'S', b'D', b'T', b't', b'I'] {
            assert!(
                matches!(
                    classify_birth(false, sample(11, state), false, 11),
                    BirthOutcome::Alive(_)
                ),
                "{state}"
            );
        }
        // Differing ticks contradict, at any leader state.
        for state in [b'R', b'S', b'Z', b'X', b'x'] {
            assert!(
                matches!(
                    classify_birth(false, sample(12, state), false, 11),
                    BirthOutcome::Changed(_)
                ),
                "{state}"
            );
        }
        // Same ticks + Z/X/x/other alpha states are insufficient.
        for state in [b'Z', b'X', b'x', b'K', b'W', b'P'] {
            assert!(
                matches!(
                    classify_birth(false, sample(11, state), false, 11),
                    BirthOutcome::Inconclusive(_)
                ),
                "{state}"
            );
        }
    }

    struct Reaped(std::process::Child);
    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Actual native read/death trigger (ADAPT P process.rs
    /// original_pin_death_during_actual_maps_read_refuses 1003-1033): the
    /// owned child is killed and reaped exactly at body EOF through the
    /// call-local hook, so the post-EOF poll is deterministically terminal
    /// and the read refuses Disappeared instead of publishing a dead
    /// snapshot. The hook never runs in production (default None).
    #[test]
    fn death_at_body_eof_refuses_without_snapshot() {
        static VICTIM: std::sync::Mutex<Option<std::process::Child>> = std::sync::Mutex::new(None);
        fn kill_victim() {
            let mut victim = VICTIM.lock().unwrap().take().expect("armed victim");
            victim.kill().expect("kill victim at EOF");
            victim.wait().expect("reap victim at EOF");
        }
        struct ReapArmed;
        impl Drop for ReapArmed {
            fn drop(&mut self) {
                if let Some(mut victim) = VICTIM.lock().unwrap().take() {
                    let _ = victim.kill();
                    let _ = victim.wait();
                }
            }
        }
        let _armed = ReapArmed;
        let _guard = crate::FD_TABLE.lock().unwrap();
        let epoch = ObserverEpoch::new(limits(), &OperationControl::unlimited()).unwrap();
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn owned child");
        let pid = Pid::new(child.id() as i32).unwrap();
        let observation =
            ProcessObservation::acquire(pid, &epoch, limits(), &OperationControl::unlimited())
                .expect("acquire live child");
        *VICTIM.lock().unwrap() = Some(child);
        let error = observation
            .read_maps_with_hook(limits(), &OperationControl::unlimited(), Some(kill_victim))
            .unwrap_err();
        assert!(VICTIM.lock().unwrap().is_none(), "hook ran and reaped");
        assert_eq!(
            error.stage(),
            Stage::VerifyBirth,
            "reason {:?}",
            error.reason()
        );
        assert_eq!(error.reason(), Reason::Disappeared);
        let context = error.process_context().expect("process context");
        assert_eq!(context.operation(), ProcOperation::ReadMaps);
        assert_eq!(context.member(), Some(ProcMember::Pidfd));
    }
}

/// Adopt an LX05 parser refusal unchanged in stage/reason/line, with reached
/// process cost: our effects/charges (parse charges equal the reached
/// parser's actual charges) plus the outer operation context.
fn adopt_parser_refusal(ops: &mut ProcOps, error: &LinuxError, member: ProcMember) -> LinuxError {
    ops.parse = error.charges().parse;
    ops.member = Some(member);
    LinuxError {
        parse_line: error.parse_line(),
        stage: error.stage(),
        reason: error.reason(),
        source: None,
        effect: ops.effects(),
        charges: ops.charges(),
        #[cfg(feature = "process")]
        process: Some(ProcessErrorContext::new(ops.operation, Some(member))),
    }
}
