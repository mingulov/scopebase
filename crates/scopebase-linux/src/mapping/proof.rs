// SPDX-License-Identifier: Apache-2.0
// LX06 mapping proofs, key verdicts and retained-proof rechecks.
//
// Proof shape follows the frozen LX06 contract. The key mechanics ADAPT P
// @2c2713e6: `ranges_for` selection by maps-visible key with the inode != 0
// rule (src/discovery/instances.rs, lines 110-135) and the non-unique-key
// doctrine that only the map_files route associates exactly
// (src/discovery/instances.rs, lines 137-168; src/attach/image_query.rs,
// lines 592-600). No donor slice implements retained cross-observation proof
// reuse with filesystem allowlists; the recheck order and ext4-only reuse
// are new vocabulary the contract requires. D03 scoped grant (2026-10-23)
// covers GPL-source to Apache-2.0 destination inside this library; donor
// files/terms untouched.
//
// Verdict ladder: raw-key equality (however established) can at most yield
// `KeyCompatible`. `ExactRange` additionally requires the independent
// per-range map_files association against the original retained descriptor
// with both descriptors alive through the comparison.
use super::MapRange;
use crate::{
    error::{LinuxError, Reason, ResourceCharges, Stage},
    file::HeldFile,
    identity::{
        MapsFileKey, MountViewId, ObservationInterval, StatObservation, TaskBirthObservation,
    },
    process::{ObserverEpoch, ProcessObservation},
    procfs::MapsEntry,
};
use std::{fmt, sync::Arc};

/// Kernel filesystem magic for ext4 (linux/magic.h `EXT4_SUPER_MAGIC`, stable
/// ABI). The initial retained-reuse allowlist names exactly this value.
const EXT4_SUPER_MAGIC: u64 = 0xEF53;

/// How the proof's key relation was established. Every method authorizes only
/// its documented key relation; none implies uniqueness across all files.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProofMethod {
    /// Independent per-range map_files association (exact path only).
    MapFiles,
    /// Held-object key resolved through fdinfo plus the target mount table.
    MountResolved,
    /// Kernel-rendered key from an explicit one-page calibration mapping.
    Calibrated,
    /// Key carried from an eligible retained proof, rechecked and re-observed.
    Retained,
}

/// Filesystem classification of the held object from an error-bearing
/// fstatfs. Only `Ext4` is eligible for retained-key reuse; `Unknown` (a
/// failed fstatfs) never counts as ordinary.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FsClass {
    Ext4,
    Other { magic: u64 },
    Unknown,
}

impl FsClass {
    pub fn retained_reuse_eligible(&self) -> bool {
        matches!(self, FsClass::Ext4)
    }
    pub(crate) fn from_magic(magic: u64) -> Self {
        if magic == EXT4_SUPER_MAGIC {
            FsClass::Ext4
        } else {
            FsClass::Other { magic }
        }
    }
}

/// Opaque retained key-relation proof: the original held owner, current stat,
/// kernel-rendered maps key, filesystem class, birth/mount view, source
/// method, observed range, caller epoch, observation interval and per-stage
/// charges. Cloning shares the retained values; serializing them (if a caller
/// ever does) carries no proof authority. `Send + Sync` for pool-adjacent use.
#[derive(Clone)]
pub struct MappingProof {
    held: Arc<HeldFile>,
    stat: StatObservation,
    key: MapsFileKey,
    fs: FsClass,
    birth: TaskBirthObservation,
    mount_view: MountViewId,
    method: ProofMethod,
    range: MapRange,
    epoch: ObserverEpoch,
    interval: ObservationInterval,
    charges: Vec<ResourceCharges>,
}

impl MappingProof {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        held: Arc<HeldFile>,
        stat: StatObservation,
        key: MapsFileKey,
        fs: FsClass,
        birth: TaskBirthObservation,
        mount_view: MountViewId,
        method: ProofMethod,
        range: MapRange,
        epoch: ObserverEpoch,
        interval: ObservationInterval,
        charges: Vec<ResourceCharges>,
    ) -> Self {
        Self {
            held,
            stat,
            key,
            fs,
            birth,
            mount_view,
            method,
            range,
            epoch,
            interval,
            charges,
        }
    }

    pub fn held(&self) -> &Arc<HeldFile> {
        &self.held
    }
    pub fn stat(&self) -> StatObservation {
        self.stat
    }
    pub fn maps_key(&self) -> MapsFileKey {
        self.key
    }
    pub fn filesystem(&self) -> FsClass {
        self.fs
    }
    pub fn method(&self) -> ProofMethod {
        self.method
    }
    pub fn range(&self) -> MapRange {
        self.range
    }
    pub fn epoch(&self) -> &ObserverEpoch {
        &self.epoch
    }
    pub fn birth(&self) -> &TaskBirthObservation {
        &self.birth
    }
    pub fn mount_view(&self) -> &MountViewId {
        &self.mount_view
    }
    pub fn interval(&self) -> &ObservationInterval {
        &self.interval
    }
    pub fn stage_charges(&self) -> &[ResourceCharges] {
        &self.charges
    }
}

impl fmt::Debug for MappingProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MappingProof")
    }
}

/// Exact per-range association: the key proof plus the map_files identity the
/// independent route confirmed against the original retained descriptor.
#[derive(Clone)]
pub struct MapRangeProof {
    proof: MappingProof,
    map_files: (u64, u64),
}

impl MapRangeProof {
    pub(crate) fn new(proof: MappingProof, map_files: (u64, u64)) -> Self {
        Self { proof, map_files }
    }
    pub fn proof(&self) -> &MappingProof {
        &self.proof
    }
    pub fn range(&self) -> MapRange {
        self.proof.range()
    }
    /// The confirmed `(st_dev, st_ino)` of the VMA's own file.
    pub fn map_files_identity(&self) -> (u64, u64) {
        self.map_files
    }
}

impl fmt::Debug for MapRangeProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapRangeProof")
    }
}

/// Observed contradiction: the requested relation does not hold.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MismatchKind {
    /// No maps line covers the requested range.
    RangeUnmapped,
    /// The rendered line names a different object than the held one.
    KeyMismatch,
    /// The named range, offset or permissions changed between bracket reads.
    RangeChanged,
    /// Target birth changed across the observation.
    BirthChanged,
    /// Target view changed across the observation.
    ViewChanged,
    /// A retained source changed under its observation.
    SourceChanged,
}

/// No relation established and none contradicted: authority was missing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InconclusiveKind {
    /// The held object is empty: nothing to map or compare.
    EmptyFile,
    /// The calibration cap is below one page-granularity mapping.
    CapBelowPage,
    /// The held mount did not resolve in the target table (after refresh).
    MountUnresolved,
    /// A target read was denied.
    TargetDenied,
    /// The target disappeared mid-observation.
    TargetDisappeared,
    /// The target had exited before authority was established.
    TargetExited,
    /// Target birth/liveness could not be established.
    BirthUnclear,
}

/// A mismatch verdict plus its reached stage charges.
#[derive(Clone, Debug)]
pub struct MismatchEvidence {
    kind: MismatchKind,
    charges: Vec<ResourceCharges>,
}

impl MismatchEvidence {
    pub(crate) fn new(kind: MismatchKind, charges: Vec<ResourceCharges>) -> Self {
        Self { kind, charges }
    }
    pub fn kind(&self) -> MismatchKind {
        self.kind
    }
    pub fn stage_charges(&self) -> &[ResourceCharges] {
        &self.charges
    }
}

/// An inconclusive verdict plus its reached stage charges.
#[derive(Clone, Debug)]
pub struct InconclusiveReason {
    kind: InconclusiveKind,
    charges: Vec<ResourceCharges>,
}

impl InconclusiveReason {
    pub(crate) fn new(kind: InconclusiveKind, charges: Vec<ResourceCharges>) -> Self {
        Self { kind, charges }
    }
    pub fn kind(&self) -> InconclusiveKind {
        self.kind
    }
    pub fn stage_charges(&self) -> &[ResourceCharges] {
        &self.charges
    }
}

/// Key-relation verdict over one rendered line and one held-object key.
/// `Compatible` feeds `KeyCompatible` only; exact association is decided
/// elsewhere and never by this function.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum KeyVerdict {
    Compatible,
    Mismatch,
}

pub(crate) fn key_verdict(line: MapsFileKey, held: MapsFileKey) -> KeyVerdict {
    // The donor `ranges_for` rule: inode 0 (anonymous, vsyscall-style or
    // empty-invalid lines) never selects, even against a zero held key.
    if line.inode() == 0 {
        return KeyVerdict::Mismatch;
    }
    if line.device_major() == held.device_major()
        && line.device_minor() == held.device_minor()
        && line.inode() == held.inode()
    {
        KeyVerdict::Compatible
    } else {
        KeyVerdict::Mismatch
    }
}

/// The retained shape of one rendered line: bounds, file offset, permissions
/// and key. Before/after reads must retain all of it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct LineShape {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) offset: u64,
    pub(crate) perms: [u8; 4],
    pub(crate) key: MapsFileKey,
}

pub(crate) fn shape_of(entry: &MapsEntry<'_>) -> LineShape {
    LineShape {
        start: entry.start(),
        end: entry.end(),
        offset: entry.file_offset(),
        perms: entry.permissions(),
        key: entry.file_key(),
    }
}

pub(crate) fn shape_retained(before: &LineShape, after: &LineShape) -> bool {
    before == after
}

pub(crate) fn stat_equal(first: &StatObservation, second: &StatObservation) -> bool {
    first.key() == second.key()
        && first.len() == second.len()
        && first.mtime() == second.mtime()
        && first.ctime() == second.ctime()
}

/// Recheck a retained proof against the current request before any target
/// work or calibration effect. Owner continuity, current metadata, caller
/// epoch, birth, mount view and observed range must all still name this
/// request; the filesystem class must allow retained-key reuse. Refusals are
/// pre-effect `ConfigureMapping` errors: changed metadata is `ChangedSource`,
/// a foreign owner/epoch/birth/view/range is `WrongContext`, and an
/// ineligible filesystem class is `InvalidInput`.
pub(crate) fn recheck_retained(
    proof: &MappingProof,
    held: &Arc<HeldFile>,
    current: &StatObservation,
    process: &ProcessObservation,
    range: MapRange,
) -> Result<(), LinuxError> {
    let refuse = |reason: Reason| {
        super::pool::pool_error(
            Stage::ConfigureMapping,
            reason,
            crate::error::CleanupDisposition::NotNeeded,
        )
    };
    if !Arc::ptr_eq(proof.held(), held) {
        return Err(refuse(Reason::WrongContext));
    }
    if !stat_equal(&proof.stat(), current) {
        return Err(refuse(Reason::ChangedSource));
    }
    if proof.epoch() != process.epoch() {
        return Err(refuse(Reason::WrongContext));
    }
    if proof.birth() != process.birth() {
        return Err(refuse(Reason::WrongContext));
    }
    if proof.mount_view() != process.mount_view() {
        return Err(refuse(Reason::WrongContext));
    }
    if proof.range() != range {
        return Err(refuse(Reason::WrongContext));
    }
    if !proof.filesystem().retained_reuse_eligible() {
        return Err(refuse(Reason::InvalidInput));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::{parse_maps, ParseLimits};

    fn key(major: u64, minor: u64, inode: u64) -> MapsFileKey {
        // MapsFileKey has no public constructor; parse one line per key.
        let input = format!("1000-2000 r--p 00000000 {major:02x}:{minor:02x} {inode} /x\n");
        let limits = ParseLimits {
            max_bytes: 1 << 20,
            max_entries: 1 << 16,
            max_line_bytes: 1 << 16,
        };
        let snapshot = parse_maps(input.as_bytes(), limits).unwrap();
        let mut entries = snapshot.entries();
        let entry = entries.next().unwrap();
        let key = entry.file_key();
        assert_eq!(
            (key.device_major(), key.device_minor(), key.inode()),
            (major, minor, inode)
        );
        key
    }

    #[test]
    fn equal_raw_keys_yield_at_most_key_compatible() {
        // Equal keys are Compatible (the KeyCompatible ceiling); the exact
        // route decides separately and never consults this verdict.
        assert_eq!(
            key_verdict(key(0, 35, 7), key(0, 35, 7)),
            KeyVerdict::Compatible
        );
        // Every differing component mismatches.
        assert_eq!(
            key_verdict(key(0, 35, 7), key(1, 35, 7)),
            KeyVerdict::Mismatch
        );
        assert_eq!(
            key_verdict(key(0, 35, 7), key(0, 36, 7)),
            KeyVerdict::Mismatch
        );
        assert_eq!(
            key_verdict(key(0, 35, 7), key(0, 35, 8)),
            KeyVerdict::Mismatch
        );
    }

    #[test]
    fn zero_inode_lines_never_select() {
        // Two unrelated anonymous lines share (0,0,0); they must not compare
        // compatible (donor `ranges_for` inode != 0 rule).
        assert_eq!(
            key_verdict(key(0, 0, 0), key(0, 0, 0)),
            KeyVerdict::Mismatch
        );
        assert_eq!(
            key_verdict(key(0, 0, 0), key(0, 35, 7)),
            KeyVerdict::Mismatch
        );
    }

    #[test]
    fn filesystem_allowlist_is_ext4_only() {
        assert!(FsClass::from_magic(0xEF53).retained_reuse_eligible());
        // btrfs, overlayfs, tmpfs, xfs magics: classified, never eligible.
        for magic in [
            0x9123_683Eu64,
            0x794C_7630,
            0x0102_1994,
            0x5846_5342,
            0x6969,
        ] {
            let class = FsClass::from_magic(magic);
            assert_eq!(class, FsClass::Other { magic });
            assert!(!class.retained_reuse_eligible());
        }
        // A failed fstatfs never counts as ordinary.
        assert!(!FsClass::Unknown.retained_reuse_eligible());
    }

    #[test]
    fn line_shape_retention_compares_every_field() {
        let base = LineShape {
            start: 0x1000,
            end: 0x2000,
            offset: 0,
            perms: *b"r--p",
            key: key(0, 35, 7),
        };
        assert!(shape_retained(&base, &base));
        let variants = [
            LineShape {
                start: 0x2000,
                ..base
            },
            LineShape {
                end: 0x3000,
                ..base
            },
            LineShape {
                offset: 0x1000,
                ..base
            },
            LineShape {
                perms: *b"r-xp",
                ..base
            },
            LineShape {
                key: key(0, 35, 8),
                ..base
            },
        ];
        for variant in variants {
            assert!(!shape_retained(&base, &variant));
        }
    }
}
