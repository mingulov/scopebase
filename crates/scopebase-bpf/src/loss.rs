// SPDX-License-Identifier: Apache-2.0
//! Full-map diagnostics and capped degradation signals (pure host values).
//!
//! ADAPT KryProbe d153f3aa `kryprobe/crates/kryprobe-abi/src/kcrypto_agg.rs:132-160`
//! (`KATTRLOSS` preallocated per-program/per-CPU array independent of the
//! identity maps that may fill; `kattrloss_fold` saturating cap-255 fold
//! that is a nonzero degradation indication, NEVER an exact lost-call
//! count) and BPF lane discipline from KryProbe d153f3aa
//! `kryprobe/crates/bpf-kcrypto/src/bin/kcrypto.rs:782-811` (per-lane
//! increments saturate at 255; loss rides its own fixed-capacity map so a
//! full identity gate can no longer hide insertion loss).
//! ADAPT vectors from KryProbe d153f3aa
//! `kryprobe/crates/kryprobe-privilege/tests/kcrypto_who.rs:698-780`
//! (finite-capacity gate/`BPF_NOEXIST` model, slot-major oracle) and
//! `:783-1021` (full-map survival, below-capacity twin, preexisting loss,
//! saturation, cross-CPU/cross-program folds, independent KCTX channel).
//! Grant: OWNER-2026-10-23 + D03 (user-owned GPL donor, library destination).
//! Capture's general loss types stay independent: this module owns only the
//! BPF lane/grid fold, epoch reset discipline and typed full-map proof. Live
//! producer races/loss cells stay with the TT05 live binding (recorded
//! follow-up, not implemented here).

use crate::{ErrorKind as K, OperationError, Stage as S};

/// Degradation saturation cap: every fold saturates here. A folded 255 is a
/// nonzero degradation indication, never the exact omitted-event count.
pub const DEGRADATION_CAP: u8 = 255;

/// A capped degradation indication, never an exact omitted-event count.
///
/// The byte exposes [`DiagnosticFlag::value`] (the raw indication),
/// [`DiagnosticFlag::is_degraded`] (nonzero means loss occurred) and
/// [`DiagnosticFlag::is_capped`] (the indication saturated). There is
/// deliberately no conversion into an exact count: the compile-fail guard
/// below pins that absence, so a future `From`/`Into` addition breaks the
/// build loudly instead of silently minting exactness.
///
/// ```compile_fail
/// use scopebase_bpf::loss::DiagnosticFlag;
/// fn as_exact_count(flag: DiagnosticFlag) -> u64 { flag.into() }
/// ```
///
/// ```
/// use scopebase_bpf::loss::fold_degradation_255;
/// let flag = fold_degradation_255(&[250, 10]);
/// assert!(flag.is_capped());
/// assert_eq!(flag.value(), 255);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticFlag(u8);

impl DiagnosticFlag {
    /// The raw capped indication byte (0..=255). A degradation signal, not
    /// an omitted-event count: 255 may hide arbitrarily many more failures.
    pub fn value(&self) -> u8 {
        self.0
    }

    /// True when any loss was observed (nonzero indication).
    pub fn is_degraded(&self) -> bool {
        self.0 != 0
    }

    /// True when the indication saturated at [`DEGRADATION_CAP`].
    pub fn is_capped(&self) -> bool {
        self.0 == DEGRADATION_CAP
    }
}

/// Fold degradation lanes into one capped indication: saturating
/// accumulation capped at [`DEGRADATION_CAP`].
///
/// Total over any lane vector (an empty fold reads clean): magnitude never
/// refuses here, it saturates. Shape discipline (full grid, epoch) lives in
/// [`LossGrid`], which calls this fold only after its checks pass.
pub fn fold_degradation_255(lanes: &[u8]) -> DiagnosticFlag {
    let mut total = 0u16;
    for &lane in lanes {
        total = (total + u16::from(lane)).min(u16::from(DEGRADATION_CAP));
    }
    DiagnosticFlag(total as u8)
}

/// Declared loss-grid shape: programs times lanes per program.
///
/// A fold must observe every lane of every program slot: partial reads and
/// foreign accounting shapes refuse instead of producing an understated
/// indication that could pass as clean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossGrid {
    programs: u32,
    lanes_per_program: usize,
}

impl LossGrid {
    /// Admit a nonzero grid shape.
    pub fn new(programs: u32, lanes_per_program: usize) -> Result<Self, OperationError> {
        if programs == 0 || lanes_per_program == 0 {
            return Err(OperationError::new(
                K::InvalidInput,
                S::Admission,
                None,
                None,
            ));
        }
        Ok(Self {
            programs,
            lanes_per_program,
        })
    }

    /// The admitted program-slot count.
    pub fn programs(&self) -> u32 {
        self.programs
    }

    /// The admitted lanes per program slot.
    pub fn lanes_per_program(&self) -> usize {
        self.lanes_per_program
    }

    /// The checked full-grid lane count every fold must observe.
    pub fn expected_lanes(&self) -> Result<usize, OperationError> {
        (self.programs as usize)
            .checked_mul(self.lanes_per_program)
            .ok_or_else(|| OperationError::new(K::Overflow, S::Admission, None, None))
    }

    /// Fold a full grid read. A short, long or foreign-shaped vector
    /// refuses: only a complete observation folds.
    pub fn fold(&self, lanes: &[u8]) -> Result<DiagnosticFlag, OperationError> {
        if lanes.len() != self.expected_lanes()? {
            return Err(OperationError::new(
                K::InvalidInput,
                S::Admission,
                None,
                None,
            ));
        }
        Ok(fold_degradation_255(lanes))
    }

    /// Fold one epoch-stamped grid read. Epochs order map lifetimes: a
    /// stale epoch refuses (it must never overwrite a newer read), an
    /// advanced epoch folds only its own lanes (a map replacement carries
    /// no prior loss forward), and a same-epoch re-read folds idempotently.
    pub fn fold_epoch(
        &self,
        epoch: u64,
        prior: Option<&LossEpoch>,
        lanes: &[u8],
    ) -> Result<LossEpoch, OperationError> {
        if prior.is_some_and(|seen| epoch < seen.epoch) {
            return Err(OperationError::new(K::Changed, S::Admission, None, None));
        }
        let flag = self.fold(lanes)?;
        Ok(LossEpoch { epoch, flag })
    }
}

/// One epoch-stamped degradation read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossEpoch {
    epoch: u64,
    flag: DiagnosticFlag,
}

impl LossEpoch {
    /// The map-lifetime epoch this read belongs to.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The folded degradation indication for that epoch.
    pub fn flag(&self) -> DiagnosticFlag {
        self.flag
    }
}

/// Typed full-map diagnostic with an occupancy proof: capacity, exactly
/// that many admitted entries, and at least one observed refusal.
///
/// Construction enforces the proof shape, so a `FullMap` value always
/// witnesses a genuinely full map plus a genuinely observed refusal:
/// below-capacity occupancy, zero refusals (the silent-drop shape),
/// over-capacity occupancy and zero capacity all refuse. Recording a
/// refusal is checked: a saturated refusal counter refuses rather than
/// wrapping back to a clean-looking zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullMap {
    capacity: u64,
    admitted: u64,
    refused: u64,
}

impl FullMap {
    /// Build the typed proof. Every non-proof shape refuses loudly.
    pub fn new(capacity: u64, admitted: u64, refused: u64) -> Result<Self, OperationError> {
        if capacity == 0 || admitted != capacity || refused == 0 {
            return Err(OperationError::new(
                K::InvalidInput,
                S::Admission,
                None,
                None,
            ));
        }
        Ok(Self {
            capacity,
            admitted,
            refused,
        })
    }

    /// The proven map capacity.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// The admitted entries (always exactly the capacity).
    pub fn admitted(&self) -> u64 {
        self.admitted
    }

    /// The observed refused inserts (always at least one: never silent).
    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// The exact attempted inserts (admitted + refused), checked.
    pub fn attempted(&self) -> Result<u64, OperationError> {
        self.admitted
            .checked_add(self.refused)
            .ok_or_else(|| OperationError::new(K::Overflow, S::Admission, None, None))
    }

    /// Record one more refused insert. A saturated counter refuses and the
    /// proof keeps its previous exact counts.
    pub fn record_refusal(&mut self) -> Result<(), OperationError> {
        let next = self
            .refused
            .checked_add(1)
            .ok_or_else(|| OperationError::new(K::Overflow, S::Admission, None, None))?;
        self.refused = next;
        Ok(())
    }
}
