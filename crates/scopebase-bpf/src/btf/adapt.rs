// SPDX-License-Identifier: Apache-2.0
//! Bounded narrow preflight around the locked btf-rs parser.
//!
//! btf-rs 2.0.0 materializes eagerly with no caller budget, so every byte
//! passes through this preflight first: header bounds, per-record shape
//! rules, population caps and work accounting. The preflight allocates
//! nothing beyond the per-record facts vector (bounded by the caller type
//! cap), runs a single forward pass with no backtracking, and records the
//! exact INT aux words the parser API does not expose. Behavior reference
//! (no lines copied): KryProbe `btf.rs` strict walk at frozen
//! `d153f3aaf9a3931337b47c9e1b046c692da55083`; record layout itself follows
//! the kernel UAPI (`linux/btf.h`).
//!
//! Charging schedule (pinned by white-box tests): parse admission 1 step,
//! then per image 1 header step, per record 1 step plus aux units (fixed
//! aux records cost 1, each struct/union/datasec/enum64 member, enum value
//! and prototype parameter costs 1), then 1 closeout step.

use crate::btf::domain::BtfLimits;
use crate::{ErrorKind, OperationError, Stage};

/// Minimum BTF header length: magic + version/flags + five u32 fields.
const HEADER_MIN: usize = 24;
/// BTF magic bytes in little-endian order.
const MAGIC: [u8; 2] = [0x9F, 0xEB];
/// BTF version written by every supported emitter.
const VERSION: u8 = 1;
/// Highest assigned BTF kind (ENUM64); kinds run contiguously from INT.
const KIND_MAX: u8 = 19;

/// Exact per-record facts captured by the preflight walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecFacts {
    /// Stored kind id (1..=19).
    pub kind: u8,
    /// Declared name offset (base-biased for module images).
    pub name_off: u32,
    /// First aux word (INT data, ARRAY element, VAR linkage, tag index).
    pub aux0: u32,
    /// Second aux word (ARRAY index type).
    pub aux1: u32,
    /// Third aux word (ARRAY element count).
    pub aux2: u32,
}

/// Admitted single-image facts: ordered records plus string extent.
pub(crate) struct Preflight {
    /// Records in id order; `facts[i]` describes global id `i + 1`
    /// relative to the image (module ids relocate at view assembly).
    pub facts: Vec<RecFacts>,
    /// String-section length in bytes.
    pub str_len: usize,
}

/// Remaining per-call work budget.
pub(crate) struct WorkBudget {
    remaining: u64,
}

impl WorkBudget {
    pub(crate) fn new(limits: &BtfLimits) -> Self {
        Self {
            remaining: limits.work_steps,
        }
    }

    /// Consume `steps`, refusing when the budget is exhausted.
    pub(crate) fn consume(&mut self, stage: Stage, steps: u64) -> Result<(), OperationError> {
        if self.remaining < steps {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                stage,
                None,
                None,
            ));
        }
        self.remaining -= steps;
        Ok(())
    }
}

fn malformed() -> OperationError {
    OperationError::new(ErrorKind::Malformed, Stage::Admission, None, None)
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, OperationError> {
    bytes
        .get(at..at.saturating_add(4))
        .filter(|window| window.len() == 4)
        .map(|window| u32::from_le_bytes([window[0], window[1], window[2], window[3]]))
        .ok_or_else(malformed)
}

/// Aux length and aux-unit cost for one validated record header.
fn aux_rule(kind: u8, vlen: u32) -> Result<(usize, u64), OperationError> {
    let fixed = |want: usize| {
        if vlen == 0 {
            Ok((want, u64::from(want != 0)))
        } else {
            Err(malformed())
        }
    };
    let linkage = |want: usize| {
        if vlen <= 1 {
            Ok((want, u64::from(want != 0)))
        } else {
            Err(malformed())
        }
    };
    match kind {
        1 => fixed(4),
        2 | 7 | 8 | 9 | 10 | 11 | 16 | 18 => fixed(0),
        12 => linkage(0),
        14 => linkage(4),
        3 => fixed(12),
        4 | 5 | 15 | 19 => {
            let units = u64::from(vlen);
            let len = (vlen as usize).checked_mul(12).ok_or_else(malformed)?;
            Ok((len, units))
        }
        6 | 13 => {
            let units = u64::from(vlen);
            let len = (vlen as usize).checked_mul(8).ok_or_else(malformed)?;
            Ok((len, units))
        }
        17 => fixed(4),
        _ => Err(malformed()),
    }
}

/// Validate one image without materializing parser state.
///
/// `base_str_len` is zero for base images; for module images it is the
/// admitted base string length, since module name offsets live in the
/// concatenated base++module string space.
pub(crate) fn preflight(
    bytes: &[u8],
    base_str_len: usize,
    limits: &BtfLimits,
    budget: &mut WorkBudget,
) -> Result<Preflight, OperationError> {
    budget.consume(Stage::Admission, 1)?;
    if bytes.len() < HEADER_MIN {
        return Err(malformed());
    }
    if bytes[0..2] != MAGIC {
        return Err(malformed());
    }
    if bytes[2] != VERSION || bytes[3] != 0 {
        return Err(malformed());
    }
    let hdr_len = read_u32(bytes, 4)? as usize;
    if hdr_len < HEADER_MIN {
        return Err(malformed());
    }
    let range = |off_at: usize, len_at: usize| -> Result<(usize, usize), OperationError> {
        let off = read_u32(bytes, off_at)? as usize;
        let len = read_u32(bytes, len_at)? as usize;
        let start = hdr_len.checked_add(off).ok_or_else(malformed)?;
        let end = start.checked_add(len).ok_or_else(malformed)?;
        if end > bytes.len() {
            return Err(malformed());
        }
        Ok((start, len))
    };
    let (type_at, type_len) = range(8, 12)?;
    let (_, str_len) = range(16, 20)?;
    if str_len == 0 {
        return Err(malformed());
    }
    if str_len > limits.strings {
        return Err(OperationError::new(
            ErrorKind::LimitExceeded,
            Stage::Admission,
            None,
            None,
        ));
    }
    // Total string space visible to this image's name offsets.
    let str_space = base_str_len.checked_add(str_len).ok_or_else(malformed)?;
    let type_end = type_at.checked_add(type_len).ok_or_else(malformed)?;
    let mut facts = Vec::new();
    let mut pos = type_at;
    while pos < type_end {
        if facts.len() >= limits.types {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Admission,
                None,
                None,
            ));
        }
        let head_end = pos.checked_add(12).ok_or_else(malformed)?;
        if head_end > type_end {
            return Err(malformed());
        }
        let name_off = read_u32(bytes, pos)?;
        let info = read_u32(bytes, pos + 4)?;
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = info & 0xFFFF;
        if kind == 0 || kind > KIND_MAX {
            return Err(malformed());
        }
        if (name_off as u64) >= (str_space as u64) {
            return Err(malformed());
        }
        let (aux_len, aux_units) = aux_rule(kind, vlen)?;
        let aux_at = head_end;
        let next = aux_at.checked_add(aux_len).ok_or_else(malformed)?;
        if next > type_end {
            return Err(malformed());
        }
        budget.consume(Stage::Admission, 1 + aux_units)?;
        let word = |index: usize| -> u32 {
            let at = aux_at.saturating_add(index.saturating_mul(4));
            bytes
                .get(at..at.saturating_add(4))
                .filter(|window| window.len() == 4 && at.saturating_add(4) <= next)
                .map(|window| u32::from_le_bytes([window[0], window[1], window[2], window[3]]))
                .unwrap_or(0)
        };
        facts.push(RecFacts {
            kind,
            name_off,
            aux0: word(0),
            aux1: word(1),
            aux2: word(2),
        });
        pos = next;
    }
    budget.consume(Stage::Admission, 1)?;
    Ok(Preflight { facts, str_len })
}

/// Map a parser failure raised while admitting bytes.
pub(crate) fn map_parse_error(error: btf_rs::Error) -> OperationError {
    match error {
        btf_rs::Error::IO(_) => malformed(),
        btf_rs::Error::Format(_) => malformed(),
        btf_rs::Error::OpNotSupp(_) => {
            OperationError::new(ErrorKind::Unsupported, Stage::Admission, None, None)
        }
        btf_rs::Error::InvalidType(_) | btf_rs::Error::InvalidString(_) => malformed(),
        // Unknown future variants fail closed: the image admits no reading.
        _ => malformed(),
    }
}

/// Map a parser failure raised while querying an admitted view.
///
/// Out-of-range caller ids never reach the parser (they refuse as
/// `InvalidInput` first), so dangling internal references here mean the
/// admitted image is corrupt.
pub(crate) fn map_query_error(error: btf_rs::Error) -> OperationError {
    match error {
        btf_rs::Error::IO(_) => {
            OperationError::new(ErrorKind::Backend, Stage::BtfQuery, None, None)
        }
        btf_rs::Error::Format(_) => {
            OperationError::new(ErrorKind::Malformed, Stage::BtfQuery, None, None)
        }
        btf_rs::Error::OpNotSupp(_) => {
            OperationError::new(ErrorKind::InvalidInput, Stage::BtfQuery, None, None)
        }
        btf_rs::Error::InvalidType(_) | btf_rs::Error::InvalidString(_) => {
            OperationError::new(ErrorKind::Malformed, Stage::BtfQuery, None, None)
        }
        // Unknown future variants fail closed rather than guessing.
        _ => OperationError::new(ErrorKind::Malformed, Stage::BtfQuery, None, None),
    }
}
