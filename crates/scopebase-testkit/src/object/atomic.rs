// SPDX-License-Identifier: Apache-2.0
//! TC04: atomic RMW old/new-value oracle, RMW shape checker and AtomicLoad
//! selector rules over the TC03 inspection inventory.
//!
//! Donor mechanism (p11scope-ws w000 @ 6f97aa47, frozen tree; fresh Rust
//! implementation, no donor lines copied):
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py` lines
//! 15-25 (per-width initial/operand and wrapping update arithmetic), lines
//! 26-40 (live/dead old/new retval-bit bodies), lines 41-59 (CAS comparator
//! and load rows), `cases.json` lines 1-142 (28-case matrix),
//! `llvm-bpf-toolchain-experiment.md` lines 55-70 (seven H29 wrong-old-value
//! cases: live 32-bit add/sub/and/or/xor plus live 64-bit add/sub),
//! `llvm-bpf-atomic-load-report.md` lines 62-73 (9-row AtomicLoad selection
//! matrix). Atomic opcode numbers are cited from the pinned kernel UAPI
//! headers recorded in `fixtures/bpf/isa/expected.json` (hashes only, no
//! lines copied); fetch-bit emission was confirmed against llc 21.1.8 output
//! frozen in `fixtures/bpf/isa/objects-atomic/`. Grant: OWNER-2026-10-23.
//!
//! Scope: stack-memory single-run semantics only. Concurrent shared-map
//! RMW/CAS linearization schedules and memory-order tests are TC07 work;
//! unsupported orderings stay unclaimed here.
use scopebase_bpf::{ErrorKind, OperationError, Stage};

use super::inspect::{FamilySpan, RuleViolation};

#[derive(Debug)]
struct Tc04Msg(&'static str);

impl std::fmt::Display for Tc04Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc04 atomic: {}", self.0)
    }
}

impl std::error::Error for Tc04Msg {}

fn tc04_refuse(kind: ErrorKind, message: &'static str) -> OperationError {
    OperationError::new(
        kind,
        Stage::Admission,
        None,
        Some(Box::new(Tc04Msg(message))),
    )
}

// ---------------------------------------------------------------------------
// Pure old/new-value oracle
// ---------------------------------------------------------------------------

/// Atomic RMW operations covered by the H29 regression matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Xchg,
    Cas,
}

/// Atomic cell widths. Half-word and byte atomics are not valid widths and
/// refuse at decode; they have no representation here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicWidth {
    W32,
    W64,
}

impl AtomicWidth {
    fn mask(self) -> u64 {
        match self {
            Self::W32 => u64::from(u32::MAX),
            Self::W64 => u64::MAX,
        }
    }

    fn bytes(self) -> u8 {
        match self {
            Self::W32 => 4,
            Self::W64 => 8,
        }
    }
}

/// One oracle case: independent reference arithmetic outside generated BPF
/// source. `comparator` applies to [`AtomicOp::Cas`] only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicCase {
    pub op: AtomicOp,
    pub width: AtomicWidth,
    pub initial: u64,
    pub operand: u64,
    pub comparator: u64,
    pub live: bool,
}

/// Reference old (returned) and new (stored) values for a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicExpected {
    pub old: u64,
    pub new: u64,
}

/// Width-masked wrapping reference arithmetic for one atomic case.
///
/// Signed/unsigned boundary and overflow cases use wrapping bit semantics.
/// Operands that do not fit the case width refuse admission instead of
/// silently masking, so a harness mistake cannot masquerade as a target bug.
pub fn atomic_reference(case: &AtomicCase) -> Result<AtomicExpected, OperationError> {
    let mask = case.width.mask();
    for value in [case.initial, case.operand] {
        if value & !mask != 0 {
            return Err(tc04_refuse(
                ErrorKind::InvalidInput,
                "operand outside case width",
            ));
        }
    }
    if case.op == AtomicOp::Cas && case.comparator & !mask != 0 {
        return Err(tc04_refuse(
            ErrorKind::InvalidInput,
            "comparator outside case width",
        ));
    }
    let old = case.initial & mask;
    let new = match case.op {
        AtomicOp::Add => case.initial.wrapping_add(case.operand) & mask,
        AtomicOp::Sub => case.initial.wrapping_sub(case.operand) & mask,
        AtomicOp::And => case.initial & case.operand,
        AtomicOp::Or => case.initial | case.operand,
        AtomicOp::Xor => case.initial ^ case.operand,
        AtomicOp::Xchg => case.operand & mask,
        AtomicOp::Cas => {
            if case.comparator == case.initial {
                case.operand & mask
            } else {
                old
            }
        }
    };
    Ok(AtomicExpected { old, new })
}

/// One observed execution outcome: the returned old value (absent when the
/// result is unused) and the stored new value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedOutcome {
    pub old: Option<u64>,
    pub new: u64,
}

/// Old/new verdict with the exact expected and observed values. Old and new
/// are asserted separately: a non-fetch H29 mutant fails the old assertion
/// while its stored value stays correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeVerdict {
    Pass,
    OldMismatch { expected: u64, observed: u64 },
    NewMismatch { expected: u64, observed: u64 },
}

/// Check one observed outcome against the independent reference.
///
/// Live cases require an observed old value; dead (unused-result) cases
/// verify the stored value only and refuse a supplied old as a harness
/// mistake. Observed values compare under the case width mask.
pub fn verify_outcome(
    case: &AtomicCase,
    observed: &ObservedOutcome,
) -> Result<OutcomeVerdict, OperationError> {
    let expected = atomic_reference(case)?;
    let mask = case.width.mask();
    if case.live {
        let old = observed
            .old
            .ok_or_else(|| tc04_refuse(ErrorKind::InvalidInput, "live case lacks observed old"))?;
        if old & mask != expected.old {
            return Ok(OutcomeVerdict::OldMismatch {
                expected: expected.old,
                observed: old & mask,
            });
        }
    } else if observed.old.is_some() {
        return Err(tc04_refuse(
            ErrorKind::InvalidInput,
            "dead case supplies observed old",
        ));
    }
    if observed.new & mask != expected.new {
        return Ok(OutcomeVerdict::NewMismatch {
            expected: expected.new,
            observed: observed.new & mask,
        });
    }
    Ok(OutcomeVerdict::Pass)
}

// ---------------------------------------------------------------------------
// Decoded RMW shape inventory
// ---------------------------------------------------------------------------

/// One decoded atomic RMW slot: width, operation, fetch bit and cell access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicInsn {
    pub width: AtomicWidth,
    pub op: AtomicOp,
    pub fetch: bool,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

/// Atomic shape classification. [`AtomicDecodeError::NotAtomic`] covers both
/// non-atomic slots and acquire/release-marked slots, which belong to the
/// load/store selector rather than the RMW decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicDecodeError {
    NotAtomic,
    WrongWidth,
    UnknownOp,
    Misaligned,
}

/// Decode one raw slot as an atomic RMW.
///
/// The width/op/fetch facts follow the pinned UAPI opcode numbers: STX class
/// with ATOMIC mode, W/DW sizes only, fetch in imm bit 0, and the six
/// op nibbles (ADD/OR/AND/XOR/XCHG/CMPXCHG). Half-word/byte sizes refuse
/// [`AtomicDecodeError::WrongWidth`], undefined op encodings refuse
/// [`AtomicDecodeError::UnknownOp`], and off-alignment refuses
/// [`AtomicDecodeError::Misaligned`] per width.
pub fn decode_atomic(
    code: u8,
    off: i16,
    imm: i32,
    regs: u8,
) -> Result<AtomicInsn, AtomicDecodeError> {
    const STX: u8 = 0x03;
    const ATOMIC: u8 = 0xc0;
    const LOAD_ACQ: i32 = 0x100;
    const STORE_REL: i32 = 0x110;
    if code & 0x07 != STX || code & 0xe0 != ATOMIC {
        return Err(AtomicDecodeError::NotAtomic);
    }
    if imm == LOAD_ACQ || imm == STORE_REL {
        return Err(AtomicDecodeError::NotAtomic);
    }
    let width = match code & 0x18 {
        0x00 => AtomicWidth::W32,
        0x18 => AtomicWidth::W64,
        _ => return Err(AtomicDecodeError::WrongWidth),
    };
    let imm_bits = imm as u32;
    let op = match imm_bits {
        0x00 | 0x01 => AtomicOp::Add,
        0x40 | 0x41 => AtomicOp::Or,
        0x50 | 0x51 => AtomicOp::And,
        0xa0 | 0xa1 => AtomicOp::Xor,
        0xe0 | 0xe1 => AtomicOp::Xchg,
        0xf0 | 0xf1 => AtomicOp::Cas,
        _ => return Err(AtomicDecodeError::UnknownOp),
    };
    let align = i32::from(width.bytes());
    if i32::from(off) % align != 0 {
        return Err(AtomicDecodeError::Misaligned);
    }
    Ok(AtomicInsn {
        width,
        op,
        fetch: imm_bits & 0x01 != 0,
        dst: regs & 0x0f,
        src: regs >> 4,
        off,
        imm,
    })
}

/// One decoded plain (non-atomic) memory access: base register, offset,
/// width and direction. ST/STX use dst as the base; LDX uses src.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainAccess {
    pub base: u8,
    pub off: i16,
    pub width_bytes: u8,
    pub write: bool,
}

/// Decode one raw slot as a plain base+offset memory access, or `None` when
/// the slot is not one. Atomic RMW slots, acquire/release-marked slots,
/// absolute/indirect loads and 16-byte load-immediates are not plain
/// accesses. Signed LDX forms count as reads: non-atomic aliasing does not
/// depend on sign extension.
pub fn decode_plain_access(code: u8, off: i16, imm: i32, regs: u8) -> Option<PlainAccess> {
    const LDX: u8 = 0x01;
    const ST: u8 = 0x02;
    const STX: u8 = 0x03;
    const MEM: u8 = 0x60;
    const MEMSX: u8 = 0x80;
    const ATOMIC: u8 = 0xc0;
    const LOAD_ACQ: i32 = 0x100;
    const STORE_REL: i32 = 0x110;
    if imm == LOAD_ACQ || imm == STORE_REL {
        return None;
    }
    let width_bytes = match code & 0x18 {
        0x00 => 4,
        0x08 => 2,
        0x10 => 1,
        _ => 8,
    };
    let class = code & 0x07;
    let mode = code & 0xe0;
    match (class, mode) {
        (STX, MEM) => Some(PlainAccess {
            base: regs & 0x0f,
            off,
            width_bytes,
            write: true,
        }),
        (ST, MEM) => Some(PlainAccess {
            base: regs & 0x0f,
            off,
            width_bytes,
            write: true,
        }),
        (LDX, MEM | MEMSX) => Some(PlainAccess {
            base: regs >> 4,
            off,
            width_bytes,
            write: false,
        }),
        (STX, ATOMIC) | (_, _) => None,
    }
}

/// One declared atomic cell: base register, offset and width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicCell {
    pub base: u8,
    pub off: i16,
    pub width_bytes: u8,
}

fn ranges_overlap(off_a: i16, width_a: u8, off_b: i16, width_b: u8) -> bool {
    let start_a = i32::from(off_a);
    let start_b = i32::from(off_b);
    let end_a = start_a + i32::from(width_a);
    let end_b = start_b + i32::from(width_b);
    start_a.max(start_b) < end_a.min(end_b)
}

fn atomic_violation(rule: &str, span: &FamilySpan) -> RuleViolation {
    RuleViolation {
        rule_id: rule.to_owned(),
        section: Some(span.section.clone()),
        offset: Some(span.offset),
        kind: ErrorKind::InvalidInput,
    }
}

/// Check decoded spans against one declared atomic cell and its case.
///
/// Findings, each a located [`RuleViolation`]: `atomic.wrong-width`,
/// `atomic.unknown-op` and `atomic.misaligned` for malformed RMW shapes;
/// `atomic.undeclared-cell` when an RMW touches any cell other than the
/// declared one; `atomic.missing-fetch` when a used result (or an xchg/CAS,
/// which always fetches) carries no fetch bit — the H29 accepted-but-wrong
/// shape; and `atomic.plain-alias` for every plain access overlapping the
/// declared cell outside `allowed_plain` (the case's recorded init/verify
/// traffic). Well-formed dead (unused-result) controls and fetch-carrying
/// xchg/CAS controls check clean.
pub fn check_atomics(
    spans: &[FamilySpan],
    live: bool,
    cell: &AtomicCell,
    allowed_plain: &[AtomicCell],
) -> Vec<RuleViolation> {
    let mut violations = Vec::new();
    for span in spans {
        match decode_atomic(span.code, span.off, span.imm, span.regs) {
            Ok(insn) => {
                if insn.dst != cell.base
                    || insn.off != cell.off
                    || insn.width.bytes() != cell.width_bytes
                {
                    violations.push(atomic_violation("atomic.undeclared-cell", span));
                    continue;
                }
                let fetch_required = live || insn.op == AtomicOp::Xchg || insn.op == AtomicOp::Cas;
                if fetch_required && !insn.fetch {
                    violations.push(atomic_violation("atomic.missing-fetch", span));
                }
            }
            Err(AtomicDecodeError::NotAtomic) => {
                let Some(access) = decode_plain_access(span.code, span.off, span.imm, span.regs)
                else {
                    continue;
                };
                if access.base != cell.base {
                    continue;
                }
                if !ranges_overlap(access.off, access.width_bytes, cell.off, cell.width_bytes) {
                    continue;
                }
                let allowed = allowed_plain.iter().any(|allow| {
                    allow.base == access.base
                        && allow.off == access.off
                        && allow.width_bytes == access.width_bytes
                });
                if !allowed {
                    violations.push(atomic_violation("atomic.plain-alias", span));
                }
            }
            Err(AtomicDecodeError::WrongWidth) => {
                violations.push(atomic_violation("atomic.wrong-width", span));
            }
            Err(AtomicDecodeError::UnknownOp) => {
                violations.push(atomic_violation("atomic.unknown-op", span));
            }
            Err(AtomicDecodeError::Misaligned) => {
                violations.push(atomic_violation("atomic.misaligned", span));
            }
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// AtomicLoad selector
// ---------------------------------------------------------------------------

/// Atomic load ordering relevant to lowering selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadOrdering {
    Monotonic,
    Acquire,
}

/// Backend generations from the donor selection matrix. LLVM before 21
/// refuses AtomicLoad on every CPU; LLVM 21+ (including Rust's LLVM 22)
/// lowers at v4 only; bpf-linker 0.10.4 additionally rejects `--cpu v4` in
/// its own CLI parser before LLVM runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendClass {
    LlvmPre21,
    LlvmModern,
    BpfLinker,
}

/// CPU presets relevant to lowering selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuClass {
    Generic,
    V3,
    V4,
}

impl CpuClass {
    /// Parse a CPU preset name; `none` (no claim) stays distinct from every
    /// named preset. Unknown names refuse instead of guessing a bundle.
    pub fn parse(text: &str) -> Result<Option<Self>, OperationError> {
        match text {
            "none" => Ok(None),
            "generic" => Ok(Some(Self::Generic)),
            "v3" => Ok(Some(Self::V3)),
            "v4" => Ok(Some(Self::V4)),
            _ => Err(tc04_refuse(ErrorKind::InvalidInput, "unknown cpu preset")),
        }
    }
}

/// Why compilation refuses an atomic load. A linker CLI rejection and a
/// backend-generation gap are distinct from an LLVM selection failure, and
/// no compiler refusal is ever labeled a verifier rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadRefusalReason {
    BackendGeneration,
    LlvmSelection,
    LinkerCli,
}

/// AtomicLoad lowering expectation: compile refusal, ordinary u64 load, or
/// acquire load under explicit CPU/feature masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicLoadOutcome {
    CompileRefusal(LoadRefusalReason),
    OrdinaryLoad,
    AcquireLoad,
}

/// Select the AtomicLoad lowering for an explicit backend/CPU/feature mask.
///
/// LLVM before 21 refuses on every CPU. At LLVM 21+, only v4 with the
/// acquire/release feature lowers: monotonic loads become ordinary u64 loads
/// and acquire loads become acquire opcodes; every other combination fails
/// instruction selection. The bpf-linker class additionally refuses v4 in
/// its own CLI parser before LLVM runs.
pub fn select_atomic_load(
    backend: BackendClass,
    cpu: Option<CpuClass>,
    acqrel: bool,
    ordering: LoadOrdering,
) -> AtomicLoadOutcome {
    if backend == BackendClass::BpfLinker && cpu == Some(CpuClass::V4) {
        return AtomicLoadOutcome::CompileRefusal(LoadRefusalReason::LinkerCli);
    }
    if backend == BackendClass::LlvmPre21 {
        return AtomicLoadOutcome::CompileRefusal(LoadRefusalReason::BackendGeneration);
    }
    if backend == BackendClass::BpfLinker || cpu != Some(CpuClass::V4) || !acqrel {
        return AtomicLoadOutcome::CompileRefusal(LoadRefusalReason::LlvmSelection);
    }
    match ordering {
        LoadOrdering::Monotonic => AtomicLoadOutcome::OrdinaryLoad,
        LoadOrdering::Acquire => AtomicLoadOutcome::AcquireLoad,
    }
}

/// Check decoded spans against a load-lowering expectation.
///
/// With `expect_acquire` false, every acquire-opcode span violates
/// `atomic-load.unexpected-acquire` (a successful ordinary load must not be
/// labeled an acquire-opcode requirement); with it true, the absence of any
/// acquire span violates `atomic-load.unexpected-ordinary`. Compile-refusal
/// expectations carry no object and have no checker input.
pub fn check_load_selector(spans: &[FamilySpan], expect_acquire: bool) -> Vec<RuleViolation> {
    if expect_acquire {
        if spans.iter().any(|span| span.family == "acqrel") {
            Vec::new()
        } else {
            vec![RuleViolation {
                rule_id: "atomic-load.unexpected-ordinary".to_owned(),
                section: None,
                offset: None,
                kind: ErrorKind::InvalidInput,
            }]
        }
    } else {
        spans
            .iter()
            .filter(|span| span.family == "acqrel")
            .map(|span| atomic_violation("atomic-load.unexpected-acquire", span))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_compares_ranges_not_points() {
        assert!(ranges_overlap(-8, 8, -8, 8));
        assert!(ranges_overlap(-8, 8, -4, 4));
        assert!(ranges_overlap(-4, 4, -8, 8));
        assert!(ranges_overlap(-8, 4, -6, 4));
        assert!(!ranges_overlap(-8, 4, -4, 4));
        assert!(!ranges_overlap(-4, 4, -8, 4));
        assert!(!ranges_overlap(0, 8, 8, 8));
    }
}
