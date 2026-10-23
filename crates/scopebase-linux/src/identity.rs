// SPDX-License-Identifier: Apache-2.0
//! Descriptor stat observations, separate from maps, mounts and content identity.
use std::fmt;
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct StatFileKey {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}
impl StatFileKey {
    pub fn device_raw(&self) -> u64 {
        self.device
    }
    pub fn inode(&self) -> u64 {
        self.inode
    }
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct StatObservation {
    key: StatFileKey,
    len: u64,
    mtime: (i64, u32),
    ctime: (i64, u32),
}
impl StatObservation {
    pub fn key(&self) -> StatFileKey {
        self.key
    }
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn mtime(&self) -> (i64, u32) {
        self.mtime
    }
    pub fn ctime(&self) -> (i64, u32) {
        self.ctime
    }
    pub(crate) fn from_stat(s: &rustix::fs::Stat) -> Option<Self> {
        Self::convert(
            s.st_dev as i128,
            s.st_ino as i128,
            s.st_size as i128,
            s.st_mtime as i128,
            s.st_mtime_nsec as i128,
            s.st_ctime as i128,
            s.st_ctime_nsec as i128,
        )
    }
    fn convert(
        device: i128,
        inode: i128,
        len: i128,
        ms: i128,
        mn: i128,
        cs: i128,
        cn: i128,
    ) -> Option<Self> {
        let nanos = |v| u32::try_from(v).ok().filter(|v| *v < 1_000_000_000);
        Some(Self {
            key: StatFileKey {
                device: device.try_into().ok()?,
                inode: inode.try_into().ok()?,
            },
            len: len.try_into().ok()?,
            mtime: (ms.try_into().ok()?, nanos(mn)?),
            ctime: (cs.try_into().ok()?, nanos(cn)?),
        })
    }
}
impl fmt::Debug for StatFileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StatFileKey")
    }
}
impl fmt::Debug for StatObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StatObservation")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conversion_boundaries_preserve_signed_seconds() {
        let s = StatObservation::convert(
            u64::MAX as i128,
            u64::MAX as i128,
            u64::MAX as i128,
            -1,
            999_999_999,
            i64::MIN as i128,
            0,
        )
        .unwrap();
        assert_eq!(s.mtime(), (-1, 999_999_999));
        assert_eq!(s.ctime(), (i64::MIN, 0));
        assert_eq!(s.len(), u64::MAX);
        let good = [1, 2, 3, 4, 5, 6, 7];
        for (index, bad) in [
            (0, -1),
            (0, u64::MAX as i128 + 1),
            (1, -1),
            (1, u64::MAX as i128 + 1),
            (2, -1),
            (2, u64::MAX as i128 + 1),
            (3, i64::MAX as i128 + 1),
            (3, i64::MIN as i128 - 1),
            (4, -1),
            (4, 1_000_000_000),
            (5, i64::MAX as i128 + 1),
            (6, -1),
            (6, 1_000_000_000),
        ] {
            let mut v = good;
            v[index] = bad;
            assert!(
                StatObservation::convert(v[0], v[1], v[2], v[3], v[4], v[5], v[6]).is_none(),
                "{index}"
            );
        }
    }
}

/// Lexical maps tuple only; never a physical-file identity or stat device.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct MapsFileKey {
    pub(crate) major: u64,
    pub(crate) minor: u64,
    pub(crate) inode: u64,
}
impl MapsFileKey {
    pub fn device_major(&self) -> u64 {
        self.major
    }
    pub fn device_minor(&self) -> u64 {
        self.minor
    }
    pub fn inode(&self) -> u64 {
        self.inode
    }
}
impl fmt::Debug for MapsFileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapsFileKey")
    }
}
/// Decimal mountinfo device components, with no cross-domain conversion.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct MountDevice {
    pub(crate) major: u64,
    pub(crate) minor: u64,
}
impl MountDevice {
    pub fn major(&self) -> u64 {
        self.major
    }
    pub fn minor(&self) -> u64 {
        self.minor
    }
}
impl fmt::Debug for MountDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MountDevice")
    }
}

/// Descriptive FD-free marker for one acquired proc view. Retains only the
/// epoch marker provenance, never authority or target FDs. Distinct markers
/// never compare equal, even for identical raw PID/tick/namespace values.
#[cfg(feature = "process")]
#[derive(Clone)]
pub struct ProcViewId {
    // Retained provenance only: keeps the epoch marker alive, never read.
    #[allow(dead_code)]
    pub(crate) epoch: std::sync::Arc<()>,
    pub(crate) view: std::sync::Arc<()>,
}
#[cfg(feature = "process")]
impl ProcViewId {
    pub(crate) fn fresh(epoch: &std::sync::Arc<()>) -> Self {
        Self {
            epoch: std::sync::Arc::clone(epoch),
            view: std::sync::Arc::new(()),
        }
    }
}
#[cfg(feature = "process")]
impl PartialEq for ProcViewId {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.view, &other.view)
    }
}
#[cfg(feature = "process")]
impl Eq for ProcViewId {}
#[cfg(feature = "process")]
impl fmt::Debug for ProcViewId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcViewId")
    }
}
/// Descriptive FD-free marker for retained mount-namespace provenance of one
/// view. Not a mount-table version; retains no authority or FDs.
#[cfg(feature = "process")]
#[derive(Clone)]
pub struct MountViewId {
    // Retained provenance only: keeps the proc view alive, never read.
    #[allow(dead_code)]
    pub(crate) proc_view: ProcViewId,
    pub(crate) mount: std::sync::Arc<()>,
}
#[cfg(feature = "process")]
impl MountViewId {
    pub(crate) fn fresh(proc_view: &ProcViewId) -> Self {
        Self {
            proc_view: proc_view.clone(),
            mount: std::sync::Arc::new(()),
        }
    }
}
#[cfg(feature = "process")]
impl PartialEq for MountViewId {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.mount, &other.mount)
    }
}
#[cfg(feature = "process")]
impl Eq for MountViewId {}
#[cfg(feature = "process")]
impl fmt::Debug for MountViewId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MountViewId")
    }
}
/// Descriptive birth sample: PID, start ticks, retained proc-view marker. No
/// image/mm identity; ticks alone are never a task key.
#[cfg(feature = "process")]
#[derive(Clone)]
pub struct TaskBirthObservation {
    pub(crate) pid: crate::process::Pid,
    pub(crate) ticks: u64,
    pub(crate) view: ProcViewId,
}
#[cfg(feature = "process")]
impl TaskBirthObservation {
    pub(crate) fn new(pid: crate::process::Pid, ticks: u64, view: ProcViewId) -> Self {
        Self { pid, ticks, view }
    }
    pub fn pid(&self) -> crate::process::Pid {
        self.pid
    }
    pub fn start_ticks(&self) -> u64 {
        self.ticks
    }
    pub fn proc_view(&self) -> &ProcViewId {
        &self.view
    }
}
#[cfg(feature = "process")]
impl PartialEq for TaskBirthObservation {
    fn eq(&self, other: &Self) -> bool {
        self.pid == other.pid && self.ticks == other.ticks && self.view == other.view
    }
}
#[cfg(feature = "process")]
impl Eq for TaskBirthObservation {}
#[cfg(feature = "process")]
impl fmt::Debug for TaskBirthObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskBirthObservation")
    }
}
/// Operation chronology only; never event authority.
#[cfg(feature = "process")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ObservationInterval {
    pub(crate) started: std::time::Instant,
    pub(crate) finished: std::time::Instant,
}
#[cfg(feature = "process")]
impl ObservationInterval {
    pub(crate) fn new(started: std::time::Instant, finished: std::time::Instant) -> Self {
        Self { started, finished }
    }
    pub fn started_at(&self) -> std::time::Instant {
        self.started
    }
    pub fn finished_at(&self) -> std::time::Instant {
        self.finished
    }
}
