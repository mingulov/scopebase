// SPDX-License-Identifier: Apache-2.0
//! Bounded domain-aware BTF parsing over the locked btf-rs 2.0.0 parser.
//!
//! The parser is pinned in Cargo.toml to retis-org/btf-rs revision
//! `0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0` with default features off
//! (no ELF, compression or regex backends); only the byte-slice
//! constructors are used, never file or mmap inputs. btf-rs has no
//! internal budget, so [`BtfView::parse`] runs the narrow [`adapt`]
//! preflight first: byte/type/string/work caps are enforced before the
//! parser materializes anything, hostile bytes fail typed, and the parser
//! never sees an image the preflight refused.
//!
//! B04 trial corpus slice binding (executor choice): T1 rival-name
//! base/split twins, T2 the admitted BP02 `btf-u32-u64.bin` linkage image,
//! T3 authored shape/hostile graphs; see `fixtures/btf-v1/README.md`.
//! Behavior reference (no lines copied): KryProbe `btf.rs` at frozen
//! `d153f3aaf9a3931337b47c9e1b046c692da55083` (header/record walk 79-151,
//! aux shapes 1780-1809, wrapper chase 43-45 + 202-221, split routing
//! 1331-1351 + 1362-1371 + 1420-1433).

pub mod adapt;
pub mod domain;
pub mod query;

pub use domain::{BtfDomainId, BtfLimits, TypeRef};
pub use query::{FuncLinkage, FunctionShape, MemberExtent, TypeKind, TypeShape};

use adapt::{map_parse_error, preflight, Preflight, RecFacts, WorkBudget};

use crate::{ErrorKind, OperationError, Stage};

/// Initial-profile ceiling per image, independent of caller budgets.
///
/// The locked parser materializes eagerly, so the initial profile
/// declines images above this size as `Unsupported` before any parse
/// work, regardless of the caller `image_bytes` budget. The value covers
/// real vmlinux images with headroom while bounding eager allocation.
pub const BTF_PROFILE_MAX_IMAGE_BYTES: usize = 16 << 20;

/// Declared image byte order. The initial profile parses little-endian
/// images only; [`ByteOrder::Big`] refuses as `Unsupported`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// Little-endian BTF (the only admitted profile).
    Little,
    /// Big-endian BTF (refused until a separate profile qualifies it).
    Big,
}

/// Candidate images for one admission.
#[derive(Clone, Copy, Debug)]
pub struct BtfImages<'a> {
    /// Standalone base image bytes.
    pub base: &'a [u8],
    /// Optional split module image bytes, resolved against `base`.
    pub module: Option<&'a [u8]>,
    /// Declared byte order of both images.
    pub byte_order: ByteOrder,
}

/// Owned view over admitted base (and optional module) BTF images.
///
/// The view owns the parser state, the preflight facts and the domain id;
/// borrowed input bytes are copied by the parser backend, so inputs may
/// be released after `parse` returns. Views are immutable values and
/// `Send + Sync`; they confer no loader, kernel or runtime authority.
pub struct BtfView {
    pub(crate) parser: btf_rs::Btf,
    pub(crate) domain: BtfDomainId,
    pub(crate) limits: BtfLimits,
    pub(crate) facts: Vec<RecFacts>,
    pub(crate) base_count: u32,
}

impl core::fmt::Debug for BtfView {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BtfView")
            .field("domain", &self.domain)
            .field("types", &self.facts.len())
            .field("base_count", &self.base_count)
            .finish()
    }
}

impl BtfView {
    /// Admit and parse one base image plus an optional split module.
    ///
    /// Order of checks: byte order and empty input gate first, then the
    /// profile ceiling (`Unsupported`), caller budgets (`LimitExceeded`),
    /// structural preflight (`Malformed`), and finally parser admission
    /// with a parser/preflight agreement check. Module name offsets
    /// resolve in concatenated base++module string space.
    pub fn parse(images: BtfImages<'_>, limits: BtfLimits) -> Result<Self, OperationError> {
        if matches!(images.byte_order, ByteOrder::Big) {
            return Err(OperationError::new(
                ErrorKind::Unsupported,
                Stage::Admission,
                None,
                None,
            ));
        }
        if images.base.is_empty() {
            return Err(OperationError::new(
                ErrorKind::InvalidInput,
                Stage::Admission,
                None,
                None,
            ));
        }
        if images.base.len() > BTF_PROFILE_MAX_IMAGE_BYTES
            || images.module.map(|module| module.len()).unwrap_or(0) > BTF_PROFILE_MAX_IMAGE_BYTES
        {
            return Err(OperationError::new(
                ErrorKind::Unsupported,
                Stage::Admission,
                None,
                None,
            ));
        }
        if images.base.len() > limits.image_bytes
            || images.module.map(|module| module.len()).unwrap_or(0) > limits.image_bytes
        {
            return Err(OperationError::new(
                ErrorKind::LimitExceeded,
                Stage::Admission,
                None,
                None,
            ));
        }
        let mut budget = WorkBudget::new(&limits);
        budget.consume(Stage::Admission, 1)?;
        let base_flight: Preflight = preflight(images.base, 0, &limits, &mut budget)?;
        debug_assert!(base_flight.facts.len() <= images.base.len() / 12);
        let base_count = base_flight.facts.len() as u32;
        let base_str_len = base_flight.str_len;
        let mut facts = base_flight.facts;
        let parser = match images.module {
            None => btf_rs::Btf::from_bytes(images.base).map_err(map_parse_error)?,
            Some(module) => {
                if module.is_empty() {
                    return Err(OperationError::new(
                        ErrorKind::InvalidInput,
                        Stage::Admission,
                        None,
                        None,
                    ));
                }
                let module_flight = preflight(module, base_str_len, &limits, &mut budget)?;
                let base_btf = btf_rs::Btf::from_bytes(images.base).map_err(map_parse_error)?;
                let split =
                    btf_rs::Btf::from_split_bytes(module, &base_btf).map_err(map_parse_error)?;
                facts.extend(module_flight.facts);
                split
            }
        };
        check_parser_agreement(&parser, images.module.is_some(), base_count, &facts)?;
        Ok(Self {
            parser,
            domain: domain_id(images.base, images.module),
            limits,
            facts,
            base_count,
        })
    }

    /// Return the domain id binding the exact admitted bytes.
    pub fn domain_id(&self) -> BtfDomainId {
        self.domain
    }

    /// Preflight facts for one range-checked global id.
    pub(crate) fn facts_for(&self, id: u32) -> Option<RecFacts> {
        id.checked_sub(1)
            .and_then(|index| self.facts.get(index as usize))
            .copied()
    }
}

/// Refuse unless the parser sections agree with the preflight counts.
///
/// Base ids run `1..=base_count` (plus parser id `0` for void); module
/// ids relocate directly above the base population.
fn check_parser_agreement(
    parser: &btf_rs::Btf,
    split: bool,
    base_count: u32,
    facts: &[RecFacts],
) -> Result<(), OperationError> {
    let disagree = || OperationError::new(ErrorKind::Malformed, Stage::Admission, None, None);
    let (start, end) = parser.base().type_id_range();
    if start != 0 || end != base_count {
        return Err(disagree());
    }
    let module_count = facts.len() as u32 - base_count;
    match (split, parser.split()) {
        (false, None) => {
            if module_count != 0 {
                return Err(disagree());
            }
        }
        (true, Some(section)) => {
            let (start, end) = section.type_id_range();
            if start != base_count.saturating_add(1)
                || end != base_count.saturating_add(module_count)
            {
                return Err(disagree());
            }
        }
        _ => return Err(disagree()),
    }
    Ok(())
}

/// Bind the exact admitted bytes into a domain id.
fn domain_id(base: &[u8], module: Option<&[u8]>) -> BtfDomainId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"scopebase-btf-domain-v1");
    hasher.update((base.len() as u64).to_le_bytes());
    hasher.update(base);
    match module {
        None => hasher.update([0u8]),
        Some(bytes) => {
            hasher.update([1u8]);
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
    }
    BtfDomainId(hasher.finalize().into())
}
