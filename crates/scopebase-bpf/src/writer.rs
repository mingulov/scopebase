// SPDX-License-Identifier: Apache-2.0
//! Program/CPU writer ownership and insertion provenance (pure host arithmetic).
//!
//! ADAPT KryProbe d153f3aa `kryprobe/crates/kryprobe-abi/src/kcrypto_agg.rs:75-108`
//! (program ordinals, `N_KPROGS = 9`, `KDROPS` slot = ordinal x 8 + site) and
//! `:508-560`/`:825-868` (`VWho` insertion marker, `try_fold_vwho` unique-mark
//! discipline, zero payload valid, saturated/overflowing counts refuse).
//! ADAPT BPF writer discipline from KryProbe d153f3aa
//! `kryprobe/crates/bpf-kcrypto/src/bin/kcrypto.rs:813-841` (guard admission:
//! a reentrant same-program entry skips instead of racing) and `:1013-1177`
//! (only the `BPF_NOEXIST` inserting lane marks; secondary lanes stay
//! unmarked even after count updates).
//! Rationale: KryProbe `docs/decisions/ADR-0013.md:13-45` (shared per-CPU
//! slots lose cross-program increments; disjoint per-program slots restore
//! exactness; misses surface on their own channel).
//! Grant: OWNER-2026-10-23 + D03 (user-owned GPL donor, library destination).
//! Product key/UID/cgroup/stack state stays in the donor; only the generic
//! slot arithmetic, marker discipline and miss ledger port. No BPF toolchain,
//! privileged setup or live kernel is needed; live discrimination cells stay
//! with the TT05 live binding (recorded follow-up, not implemented here).

use crate::maps::CpuTopology;
use crate::{ErrorKind as K, OperationError, Stage as S};

fn invalid() -> OperationError {
    OperationError::new(K::InvalidInput, S::Admission, None, None)
}

fn malformed() -> OperationError {
    OperationError::new(K::Malformed, S::Admission, None, None)
}

fn overflow() -> OperationError {
    OperationError::new(K::Overflow, S::Admission, None, None)
}

/// Declared writer partition: program ordinals times sites per program.
///
/// Both dimensions are nonzero; slot arithmetic stays checked against the
/// live lane count in [`writer_slot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterPartition {
    programs: u32,
    sites_per_program: u32,
}

impl WriterPartition {
    /// Admit a nonzero partition shape. A zero dimension is not a writer.
    pub fn new(programs: u32, sites_per_program: u32) -> Result<Self, OperationError> {
        if programs == 0 || sites_per_program == 0 {
            return Err(invalid());
        }
        Ok(Self {
            programs,
            sites_per_program,
        })
    }

    /// The admitted program-ordinal count.
    pub fn programs(&self) -> u32 {
        self.programs
    }

    /// The admitted per-program site count.
    pub fn sites_per_program(&self) -> u32 {
        self.sites_per_program
    }

    /// The checked program-times-site slot count (lanes multiply separately).
    pub fn slots(&self) -> Result<usize, OperationError> {
        (self.programs as usize)
            .checked_mul(self.sites_per_program as usize)
            .ok_or_else(overflow)
    }
}

/// Writer instruction-set domain. Only x86-64 carries the production
/// exclusivity argument (the donor proof assumes x86-64 TSO and explicitly
/// does not cover other architectures); any other value refuses as
/// unsupported rather than silently sharing the claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterArch(pub u32);

impl WriterArch {
    /// The single supported writer domain.
    pub const X86_64: WriterArch = WriterArch(0);

    /// True only for the supported domain.
    pub fn is_supported(&self) -> bool {
        *self == Self::X86_64
    }
}

/// Same-program reentry discipline for one writer.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardKind {
    /// Disjoint slots are the protection; admission never consults the guard.
    Unguarded,
    /// A reentrant entry while busy refuses and counts a ledger miss.
    Guarded,
}

/// One named writer: program ordinal, drop site, CPU lane, guard and arch.
///
/// Ownership names all five; construction alone validates nothing, so
/// fixtures can carry invalid declarations and [`writer_slot`] refuses them
/// loudly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterDeclaration {
    program: u32,
    site: u32,
    cpu: u32,
    guard: GuardKind,
    arch: WriterArch,
}

impl WriterDeclaration {
    /// Name a writer. Admission checks run in [`writer_slot`]/[`guard_admit`].
    pub fn new(program: u32, site: u32, cpu: u32, guard: GuardKind, arch: WriterArch) -> Self {
        Self {
            program,
            site,
            cpu,
            guard,
            arch,
        }
    }

    /// The program ordinal.
    pub fn program(&self) -> u32 {
        self.program
    }

    /// The per-program site.
    pub fn site(&self) -> u32 {
        self.site
    }

    /// The CPU id (resolved against topology lanes, never used raw).
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// The reentry discipline.
    pub fn guard(&self) -> GuardKind {
        self.guard
    }

    /// The instruction-set domain.
    pub fn arch(&self) -> WriterArch {
        self.arch
    }
}

/// Map a writer to its exclusive slot: every (program, site, CPU lane)
/// triple owns a distinct index.
///
/// Refusals: unsupported arch, out-of-partition program/site, CPU absent
/// from the topology, or overflowing slot arithmetic. Per-CPU alone never
/// implies exclusivity: different programs on one CPU map apart.
pub fn writer_slot(
    declaration: &WriterDeclaration,
    partition: &WriterPartition,
    topology: &CpuTopology,
) -> Result<usize, OperationError> {
    if !declaration.arch.is_supported() {
        return Err(OperationError::new(
            K::Unsupported,
            S::Admission,
            None,
            None,
        ));
    }
    if declaration.program >= partition.programs || declaration.site >= partition.sites_per_program
    {
        return Err(invalid());
    }
    let lane = topology
        .ids()
        .binary_search(&declaration.cpu)
        .map_err(|_| invalid())?;
    let base = (declaration.program as usize)
        .checked_mul(partition.sites_per_program as usize)
        .and_then(|slot| slot.checked_add(declaration.site as usize))
        .ok_or_else(overflow)?;
    base.checked_mul(topology.count())
        .and_then(|slot| slot.checked_add(lane))
        .ok_or_else(overflow)
}

/// Independent guard-miss ledger: one exact counter per (program, lane).
///
/// Misses live outside the data slots, so a refused writer can neither move
/// a slot nor vanish into an admission total. Counters are exact and refuse
/// on overflow rather than wrapping a busy writer back to clean.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissLedger {
    programs: u32,
    lanes: usize,
    misses: Vec<u64>,
}

impl MissLedger {
    /// Allocate an exact zeroed ledger. Zero programs or lanes refuse; a
    /// failed allocation refuses without a half-built ledger.
    pub fn new(programs: u32, lanes: usize) -> Result<Self, OperationError> {
        if programs == 0 || lanes == 0 {
            return Err(invalid());
        }
        let len = (programs as usize)
            .checked_mul(lanes)
            .ok_or_else(overflow)?;
        let mut misses = Vec::new();
        misses
            .try_reserve_exact(len)
            .map_err(|_| OperationError::new(K::LimitExceeded, S::Allocate, None, None))?;
        misses.resize(len, 0);
        Ok(Self {
            programs,
            lanes,
            misses,
        })
    }

    fn index(&self, program: u32, lane: usize) -> Result<usize, OperationError> {
        if program >= self.programs || lane >= self.lanes {
            return Err(invalid());
        }
        // Bounds above plus the checked constructor product keep this exact.
        Ok(program as usize * self.lanes + lane)
    }

    /// Count one guard miss. Unknown writers refuse; a saturated counter
    /// refuses rather than wrapping.
    pub fn record_miss(&mut self, program: u32, lane: usize) -> Result<(), OperationError> {
        self.record_many(program, lane, 1)
    }

    /// Count an exact batch of misses with the same refusal discipline.
    pub fn record_many(
        &mut self,
        program: u32,
        lane: usize,
        count: u64,
    ) -> Result<(), OperationError> {
        let at = self.index(program, lane)?;
        let next = self.misses[at].checked_add(count).ok_or_else(overflow)?;
        self.misses[at] = next;
        Ok(())
    }

    /// Read one exact miss counter. Unknown writers refuse.
    pub fn misses(&self, program: u32, lane: usize) -> Result<u64, OperationError> {
        let at = self.index(program, lane)?;
        Ok(self.misses[at])
    }

    /// Sum every miss counter exactly. An overflowing total refuses.
    pub fn total_misses(&self) -> Result<u64, OperationError> {
        let mut total = 0u64;
        for &miss in &self.misses {
            total = total.checked_add(miss).ok_or_else(overflow)?;
        }
        Ok(total)
    }
}

/// Decide one guarded entry: a busy guarded writer refuses (counting its
/// miss) while every other writer admits.
///
/// The writer is authenticated first: unknown program ordinals and lanes
/// refuse even when idle, so a foreign writer can never slip into another
/// writer's slot. Returns `false` for a counted refusal, `true` for admission.
pub fn guard_admit(
    declaration: &WriterDeclaration,
    lane: usize,
    busy: bool,
    ledger: &mut MissLedger,
) -> Result<bool, OperationError> {
    if declaration.program >= ledger.programs || lane >= ledger.lanes {
        return Err(invalid());
    }
    if matches!(declaration.guard, GuardKind::Guarded) && busy {
        ledger.record_miss(declaration.program, lane)?;
        return Ok(false);
    }
    Ok(true)
}

/// Insertion marker: the lane whose insert created the key carries this
/// value; every other lane carries 0 (kernel-zeroed, never marked by the
/// hit path, including a losing insert racer's lane).
pub const IDENTITY_PRESENT: u32 = 1;

/// One per-CPU insertion lane: provenance marker, observation count and an
/// opaque identity payload. Product key/UID/cgroup/stack fields stay local
/// to their owners; the fold only needs marker, magnitude and bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityLane<'a> {
    marker: u32,
    count: u64,
    identity: &'a [u8],
}

impl<'a> IdentityLane<'a> {
    /// Carry one lane. Marker discipline is enforced by the fold, not here.
    pub fn new(marker: u32, count: u64, identity: &'a [u8]) -> Self {
        Self {
            marker,
            count,
            identity,
        }
    }

    /// The provenance marker (`IDENTITY_PRESENT` or 0).
    pub fn marker(&self) -> u32 {
        self.marker
    }

    /// The lane observation count.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The opaque identity payload.
    pub fn identity(&self) -> &'a [u8] {
        self.identity
    }
}

/// Find the inserting lane: the unique `IDENTITY_PRESENT` marker owns, even
/// with an all-zero payload; unmarked lanes contribute counts only.
///
/// Refusals: no lanes, no marker, conflicting markers, or a marker value
/// outside {0, 1}. An unmarked numeric zero is never an observed identity.
pub fn insertion_owner(lanes: &[IdentityLane]) -> Result<usize, OperationError> {
    if lanes.is_empty() {
        return Err(invalid());
    }
    let mut marked: Option<usize> = None;
    for (index, lane) in lanes.iter().enumerate() {
        if lane.marker == IDENTITY_PRESENT {
            if marked.is_some() {
                return Err(malformed());
            }
            marked = Some(index);
        } else if lane.marker != 0 {
            return Err(malformed());
        }
    }
    marked.ok_or_else(malformed)
}

/// Sum every lane count exactly, marked or not.
///
/// A saturated input word or an overflowing sum refuses: magnitudes that do
/// not fit are reported, never wrapped or saturated into a clean total.
pub fn insertion_total(lanes: &[IdentityLane]) -> Result<u64, OperationError> {
    let mut total = 0u64;
    for lane in lanes {
        if lane.count == u64::MAX {
            return Err(overflow());
        }
        total = total.checked_add(lane.count).ok_or_else(overflow)?;
    }
    Ok(total)
}

/// One folded insertion record: owner lane, insertion-frozen identity
/// payload and the exact cross-lane total.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insertion<'a> {
    owner: usize,
    identity: &'a [u8],
    total: u64,
}

impl<'a> Insertion<'a> {
    /// The owning lane index.
    pub fn owner(&self) -> usize {
        self.owner
    }

    /// The insertion-frozen identity payload from the owning lane.
    pub fn identity(&self) -> &'a [u8] {
        self.identity
    }

    /// The exact cross-lane observation total.
    pub fn total(&self) -> u64 {
        self.total
    }
}

/// Fold insertion provenance: unique-mark ownership plus the exact total.
///
/// Marker discipline refuses before magnitudes are summed, so a provenance
/// gap is never masked by a plausible count.
pub fn fold_insertion<'a>(lanes: &'a [IdentityLane<'a>]) -> Result<Insertion<'a>, OperationError> {
    let owner = insertion_owner(lanes)?;
    let total = insertion_total(lanes)?;
    let identity = lanes
        .get(owner)
        .map(|lane| lane.identity)
        .ok_or_else(malformed)?;
    Ok(Insertion {
        owner,
        identity,
        total,
    })
}
