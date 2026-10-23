// SPDX-License-Identifier: Apache-2.0
//! TC05: ELF/BTF relocation, call graph and metadata preservation.
//!
//! Three inspectors over TC03-admitted objects ([`ObjectContract`],
//! [`FinalObjectManifest`] binding at the call site) and BP09 [`BtfView`]
//! queries with exact domains:
//!
//! - [`apply_relocations`] resolves and writes every REL entry: exact
//!   section-offset map definitions with an unsigned 32-bit addend, named
//!   maps, whole-section global-data fallback, absolute data and call
//!   relocations; `.BTF`/`.BTF.ext` NODYLD entries are preserved, never
//!   resolved. Overflow, dangling symbols and unrecognized forms refuse
//!   typed; the report carries pre/post hashes plus every applied action.
//! - [`extract_call_graph`] links helper and subprogram calls to complete
//!   aligned function extents, reports cycles, and bounds traversal by the
//!   caller work budget. [`verify_callbacks`] resolves expected callback
//!   names through BTF FUNC/FUNC_PROTO linkage.
//! - [`snapshot_metadata`] records section digests plus required map
//!   key/value linkage and named-type populations; [`diff_metadata`]
//!   reports dropped, changed, lost and relinked entries between two
//!   snapshots. Verdicts derive from bytes, never from an exit status.
//!
//! ADAPT (mechanism + vectors, user-owned donor lines only):
//! p11scope-ws p11scope w001 @ 7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4,
//! `third-party/patches/aya-obj-0.3.0/aya-obj-map-relocation.patch` `+`
//! lines only: error variants 9-25, exact-offset/unsigned-addend/checked
//! resolution 47-92, section fallback 99-101, unit vectors 110-220,
//! rationale 227-256. Distinct-sentinel check:
//! `tests/bpf_map_contracts.rs` lines 61-107. Refusal-matrix shape:
//! `tests/python/test_bpf_map_defs.py` lines 133-163. Exit-zero lesson:
//! p11scope-ws w000 @ 6f97aa47, `llvm-bpf-toolchain-experiment.md` lines
//! 153-171 and 196-200. Record facts follow the URL the donor patch cites
//! (docs.kernel.org/bpf/llvm_reloc.html); pseudo values ride TC03 UAPI
//! pins. Grant: OWNER-2026-10-23.
use scopebase_bpf::{
    btf::{BtfView, TypeRef},
    ErrorKind, Limits, OperationError, Stage,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::{inspect::RuleViolation, manifest::ArtifactId, ObjectContract};

/// Relocation types (donor-cited docs.kernel.org/bpf/llvm_reloc.html).
const R_BPF_NONE: u32 = 0;
const R_BPF_64_64: u32 = 1;
const R_BPF_64_ABS64: u32 = 2;
const R_BPF_64_ABS32: u32 = 3;
const R_BPF_64_NODYLD32: u32 = 4;
const R_BPF_64_32: u32 = 10;

const EM_BPF: u16 = 247;
const SHF_EXECINSTR: u64 = 0x4;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;

const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STB_GLOBAL: u8 = 1;

/// Loader pseudo-field values (TC03 UAPI pins): map fd, map value.
const PSEUDO_MAP_FD: u8 = 1;
const PSEUDO_MAP_VALUE: u8 = 2;

#[derive(Debug)]
struct Tc05Msg(&'static str);

impl std::fmt::Display for Tc05Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc05 graph inspection: {}", self.0)
    }
}

impl std::error::Error for Tc05Msg {}

fn refuse(kind: ErrorKind, message: &'static str) -> OperationError {
    OperationError::new(kind, Stage::Inspect, None, Some(Box::new(Tc05Msg(message))))
}

fn limited() -> OperationError {
    OperationError::new(ErrorKind::LimitExceeded, Stage::Inspect, None, None)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Data {
    Little,
    Big,
}

impl Data {
    fn u16(self, bytes: &[u8]) -> u16 {
        let pair = [bytes[0], bytes[1]];
        match self {
            Self::Little => u16::from_le_bytes(pair),
            Self::Big => u16::from_be_bytes(pair),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let quad = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Little => u32::from_le_bytes(quad),
            Self::Big => u32::from_be_bytes(quad),
        }
    }

    fn u64(self, bytes: &[u8]) -> u64 {
        let mut wide = [0u8; 8];
        wide.copy_from_slice(&bytes[..8]);
        match self {
            Self::Little => u64::from_le_bytes(wide),
            Self::Big => u64::from_be_bytes(wide),
        }
    }

    fn write_u32(self, out: &mut [u8], value: u32) {
        let encoded = match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        };
        out[..4].copy_from_slice(&encoded);
    }

    fn write_u64(self, out: &mut [u8], value: u64) {
        let encoded = match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        };
        out[..8].copy_from_slice(&encoded);
    }
}

fn slice_at(bytes: &[u8], offset: u64, len: u64) -> Result<&[u8], OperationError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "truncated object"))?;
    if end > bytes.len() as u64 {
        return Err(refuse(ErrorKind::Malformed, "truncated object"));
    }
    let start = offset as usize;
    Ok(&bytes[start..start + len as usize])
}

struct Section {
    index: usize,
    name: Option<String>,
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
}

impl Section {
    fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("section#{}", self.index))
    }
}

fn section_name(table: &[u8], at: u32) -> Result<Option<String>, OperationError> {
    let start =
        usize::try_from(at).map_err(|_| refuse(ErrorKind::Malformed, "bad section name"))?;
    if start >= table.len() {
        return Err(refuse(ErrorKind::Malformed, "bad section name"));
    }
    let end = table[start..]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "bad section name"))?;
    let name = &table[start..start + end];
    if name.is_empty() {
        return Ok(None);
    }
    std::str::from_utf8(name)
        .map(|text| Some(text.to_owned()))
        .map_err(|_| refuse(ErrorKind::Malformed, "bad section name"))
}

struct Symbol {
    name: Option<String>,
    bind: u8,
    kind: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

struct Image<'a> {
    bytes: &'a [u8],
    data: Data,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
}

impl<'a> Image<'a> {
    fn body(&self, section: &Section) -> Result<&'a [u8], OperationError> {
        slice_at(self.bytes, section.offset, section.size)
    }
}

/// Decode ELF64 BPF structure shared by all three inspectors: target
/// admission mirrors TC03 (endianness and machine refuse typed), then
/// section, name and first-symtab decoding under caller bounds.
fn decode<'a>(
    bytes: &'a [u8],
    contract: &ObjectContract,
    limits: &Limits,
    work: &mut u64,
) -> Result<Image<'a>, OperationError> {
    limits.validate()?;
    if bytes.len() > limits.input_bytes || bytes.len() > limits.retained_bytes {
        return Err(limited());
    }
    let mut charge = |steps: u64| -> Result<(), OperationError> {
        if *work < steps {
            return Err(limited());
        }
        *work -= steps;
        Ok(())
    };
    if bytes.len() < 64 {
        return Err(refuse(ErrorKind::Malformed, "truncated elf header"));
    }
    if bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(refuse(ErrorKind::Malformed, "not an elf object"));
    }
    if bytes[4] != 2 {
        return Err(refuse(ErrorKind::Malformed, "not a 64-bit object"));
    }
    let data = match bytes[5] {
        1 => Data::Little,
        2 => Data::Big,
        _ => return Err(refuse(ErrorKind::Malformed, "unknown elf data encoding")),
    };
    let contract_little = match contract.endian() {
        "little" => true,
        "big" => false,
        _ => return Err(refuse(ErrorKind::InvalidInput, "contract endian")),
    };
    if (data == Data::Little) != contract_little {
        return Err(refuse(
            ErrorKind::Incompatible,
            "object endianness contradicts contract",
        ));
    }
    match data.u16(&bytes[0x10..0x12]) {
        1 | 2 => {}
        _ => {
            return Err(refuse(
                ErrorKind::InvalidInput,
                "not a relocatable or executable object",
            ))
        }
    }
    if data.u16(&bytes[0x12..0x14]) != EM_BPF {
        return Err(refuse(
            ErrorKind::Incompatible,
            "object machine contradicts bpf contract",
        ));
    }
    let shoff = data.u64(&bytes[0x28..0x30]);
    let shentsize = data.u16(&bytes[0x3a..0x3c]);
    let shnum = data.u16(&bytes[0x3c..0x3e]);
    let shstrndx = data.u16(&bytes[0x3e..0x40]);
    if shnum == 0 {
        return Err(refuse(ErrorKind::Malformed, "object without sections"));
    }
    if shentsize != 64 {
        return Err(refuse(
            ErrorKind::Malformed,
            "unsupported section header size",
        ));
    }
    if usize::from(shnum) > limits.sites {
        return Err(limited());
    }
    let table_len = u64::from(shnum) * 64;
    let table_end = shoff
        .checked_add(table_len)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "truncated section table"))?;
    if table_end > bytes.len() as u64 {
        return Err(refuse(ErrorKind::Malformed, "truncated section table"));
    }
    let mut sections = Vec::with_capacity(usize::from(shnum));
    for index in 0..shnum {
        charge(1)?;
        let at = shoff + u64::from(index) * 64;
        let header = slice_at(bytes, at, 64)?;
        let kind = data.u32(&header[4..8]);
        let flags = data.u64(&header[8..16]);
        let offset = data.u64(&header[24..32]);
        let size = data.u64(&header[32..40]);
        let link = data.u32(&header[40..44]);
        let info = data.u32(&header[44..48]);
        offset
            .checked_add(size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or_else(|| refuse(ErrorKind::Malformed, "section outside file"))?;
        sections.push(Section {
            index: usize::from(index),
            name: None,
            kind,
            flags,
            offset,
            size,
            link,
            info,
        });
    }
    let names: Vec<Option<String>> = if shstrndx == 0 {
        vec![None; sections.len()]
    } else {
        if shstrndx >= shnum {
            return Err(refuse(ErrorKind::Malformed, "bad section-name index"));
        }
        let table_section = &sections[usize::from(shstrndx)];
        if table_section.size > limits.retained_bytes as u64 {
            return Err(limited());
        }
        let table = slice_at(bytes, table_section.offset, table_section.size)?;
        let mut names = Vec::with_capacity(sections.len());
        for index in 0..shnum {
            charge(1)?;
            let at = shoff + u64::from(index) * 64;
            let header = slice_at(bytes, at, 64)?;
            names.push(section_name(table, data.u32(&header[0..4]))?);
        }
        names
    };
    for (section, name) in sections.iter_mut().zip(names) {
        section.name = name;
    }
    // First symtab wins; objects without one carry no symbols.
    let mut symbols = Vec::new();
    if let Some(symtab) = sections.iter().find(|section| section.kind == SHT_SYMTAB) {
        let strings = sections
            .get(symtab.link as usize)
            .filter(|section| section.index != symtab.index)
            .ok_or_else(|| refuse(ErrorKind::Malformed, "bad symtab strings link"))?;
        if symtab.size % 24 != 0 {
            return Err(refuse(ErrorKind::Malformed, "truncated symbol table"));
        }
        let body = slice_at(bytes, symtab.offset, symtab.size)?;
        let table = slice_at(bytes, strings.offset, strings.size)?;
        for (index, entry) in body.chunks_exact(24).enumerate() {
            charge(1)?;
            let name_at = data.u32(&entry[0..4]);
            let info = entry[4];
            let shndx = data.u16(&entry[6..8]);
            let value = data.u64(&entry[8..16]);
            let size = data.u64(&entry[16..24]);
            let name = if index == 0 {
                None
            } else {
                let start = usize::try_from(name_at)
                    .map_err(|_| refuse(ErrorKind::Malformed, "bad symbol name"))?;
                if start >= table.len() {
                    return Err(refuse(ErrorKind::Malformed, "bad symbol name"));
                }
                let end = table[start..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| refuse(ErrorKind::Malformed, "bad symbol name"))?;
                let raw = &table[start..start + end];
                if raw.is_empty() {
                    None
                } else {
                    Some(
                        std::str::from_utf8(raw)
                            .map_err(|_| refuse(ErrorKind::Malformed, "bad symbol name"))?
                            .to_owned(),
                    )
                }
            };
            symbols.push(Symbol {
                name,
                bind: info >> 4,
                kind: info & 0x0f,
                shndx,
                value,
                size,
            });
        }
    }
    Ok(Image {
        bytes,
        data,
        sections,
        symbols,
    })
}

fn digest_of(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn artifact_id(sha256: [u8; 32]) -> ArtifactId {
    let id = sha256.iter().map(|byte| format!("{byte:02x}")).collect();
    ArtifactId::new(id, sha256)
}

// ---------------------------------------------------------------------------
// Relocation application
// ---------------------------------------------------------------------------

/// Caller-supplied descriptor tables. Map names resolve to sentinel FDs;
/// whole-section entries cover global-data sections without per-symbol
/// definitions. Nothing is invented: unlisted names refuse.
pub struct RelocationInputs<'a> {
    /// Named map (`symbol name -> sentinel fd`).
    pub named_maps: &'a BTreeMap<String, i32>,
    /// Whole-section global-data map (`section name -> sentinel fd`).
    pub section_maps: &'a BTreeMap<String, i32>,
}

/// One applied relocation action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocationAction {
    /// LD_imm64 now loads a map fd (`src` = 1, second slot zeroed).
    MapFd {
        /// Resolved map definition name.
        name: String,
        /// Assigned sentinel fd.
        fd: i32,
    },
    /// LD_imm64 now loads a whole-section value pointer (`src` = 2,
    /// value offset in the second slot).
    MapValue {
        /// Resolved section-map name.
        name: String,
        /// Assigned sentinel fd.
        fd: i32,
        /// Value offset carried in the second slot.
        value_offset: u64,
    },
    /// 64-bit absolute value written.
    Abs64 {
        /// Written value.
        value: u64,
    },
    /// 32-bit absolute value written.
    Abs32 {
        /// Written value.
        value: u32,
    },
    /// Call target resolved to a function start; slot imm holds
    /// `(target - 8) / 8` per the `(S + A) / 8 - 1` rule.
    Call {
        /// Resolved section-relative target.
        target: u64,
    },
    /// NODYLD entry in `.BTF`/`.BTF.ext` left byte-identical.
    PreservedNodyld,
}

/// One applied relocation with its location and resolved symbol.
#[derive(Debug, Clone)]
pub struct AppliedRelocation {
    section: String,
    offset: u64,
    symbol: String,
    addend: u64,
    action: RelocationAction,
}

impl AppliedRelocation {
    /// Relocated section label.
    pub fn section(&self) -> &str {
        &self.section
    }

    /// Section-relative byte offset of the patched slot.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Resolved symbol or section name.
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Implicit addend read from the image.
    pub fn addend(&self) -> u64 {
        self.addend
    }

    /// What was written (or preserved).
    pub fn action(&self) -> &RelocationAction {
        &self.action
    }
}

/// Relocated image plus its application report.
#[derive(Debug, Clone)]
pub struct RelocatedObject {
    object_id: ArtifactId,
    bytes: Vec<u8>,
    output_sha256: [u8; 32],
    applied: Vec<AppliedRelocation>,
}

impl RelocatedObject {
    /// Identity of the input bytes.
    pub fn object_id(&self) -> &ArtifactId {
        &self.object_id
    }

    /// Relocated image bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Hash of the relocated image (pre/post comparison).
    pub fn output_sha256(&self) -> &[u8; 32] {
        &self.output_sha256
    }

    /// Applied relocations in section/entry order.
    pub fn applied(&self) -> &[AppliedRelocation] {
        &self.applied
    }
}

/// Apply every REL relocation and return the relocated image plus report.
///
/// Map/data references (`R_BPF_64_64`) against a section symbol resolve to
/// the unique OBJECT definition at exactly `symbol + u32(addend)`; missing
/// and ambiguous boundaries refuse, and overflow refuses. Named symbols
/// resolve through the caller map table; sections without definitions fall
/// back to the caller section table as whole-section value pointers.
/// Absolute and call relocations use checked arithmetic; NODYLD entries
/// outside `.BTF`/`.BTF.ext`, RELA sections and unknown types refuse.
pub fn apply_relocations(
    bytes: &[u8],
    contract: &ObjectContract,
    inputs: &RelocationInputs<'_>,
    limits: &Limits,
) -> Result<RelocatedObject, OperationError> {
    let mut work = limits.work_steps;
    let image = decode(bytes, contract, limits, &mut work)?;
    if image
        .sections
        .iter()
        .any(|section| section.kind == SHT_RELA)
    {
        return Err(refuse(ErrorKind::Unsupported, "rela sections unsupported"));
    }
    let mut out = bytes.to_vec();
    let mut applied = Vec::new();
    let rel_sections: Vec<usize> = image
        .sections
        .iter()
        .filter(|section| section.kind == SHT_REL)
        .map(|section| section.index)
        .collect();
    for rel_index in rel_sections {
        let rel = &image.sections[rel_index];
        let target_index = rel.info as usize;
        if target_index >= image.sections.len() {
            return Err(refuse(
                ErrorKind::Malformed,
                "relocation without target section",
            ));
        }
        let target = &image.sections[target_index];
        let body = image.body(rel)?;
        if body.len() % 16 != 0 {
            return Err(refuse(ErrorKind::Malformed, "truncated relocation section"));
        }
        for entry in body.chunks_exact(16) {
            if work == 0 {
                return Err(limited());
            }
            work -= 1;
            let offset = image.data.u64(&entry[0..8]);
            let info = image.data.u64(&entry[8..16]);
            let sym_index = (info >> 32) as u32;
            let rtype = (info & 0xffff_ffff) as u32;
            if rtype == R_BPF_NONE {
                continue;
            }
            let symbol = image
                .symbols
                .get(sym_index as usize)
                .ok_or_else(|| refuse(ErrorKind::InvalidInput, "dangling relocation symbol"))?;
            if sym_index == 0 {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    "dangling relocation symbol",
                ));
            }
            let action = apply_entry(&image, target, symbol, offset, rtype, inputs, &mut out)?;
            let symbol_name = symbol
                .name
                .clone()
                .or_else(|| {
                    image
                        .sections
                        .get(symbol.shndx as usize)
                        .and_then(|section| section.name.clone())
                })
                .unwrap_or_else(|| format!("symbol#{sym_index}"));
            applied.push(AppliedRelocation {
                section: target.label(),
                offset,
                symbol: symbol_name,
                addend: last_addend(&image, target, offset, rtype)?,
                action,
            });
        }
    }
    let output_sha256 = digest_of(&out);
    Ok(RelocatedObject {
        object_id: artifact_id(digest_of(bytes)),
        bytes: out,
        output_sha256,
        applied,
    })
}

/// Re-read the implicit addend for the report after application.
fn last_addend(
    image: &Image<'_>,
    target: &Section,
    offset: u64,
    rtype: u32,
) -> Result<u64, OperationError> {
    let body = image.body(target)?;
    let at = offset as usize;
    match rtype {
        R_BPF_64_64 | R_BPF_64_32 => {
            if at + 8 > body.len() {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    "relocation outside section",
                ));
            }
            Ok(u64::from(image.data.u32(&body[at + 4..at + 8])))
        }
        R_BPF_64_ABS64 => {
            if at + 8 > body.len() {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    "relocation outside section",
                ));
            }
            Ok(image.data.u64(&body[at..at + 8]))
        }
        R_BPF_64_ABS32 | R_BPF_64_NODYLD32 => {
            if at + 4 > body.len() {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    "relocation outside section",
                ));
            }
            Ok(u64::from(image.data.u32(&body[at..at + 4])))
        }
        _ => Err(refuse(ErrorKind::InvalidInput, "unknown relocation type")),
    }
}

fn apply_entry(
    image: &Image<'_>,
    target: &Section,
    symbol: &Symbol,
    offset: u64,
    rtype: u32,
    inputs: &RelocationInputs<'_>,
    out: &mut [u8],
) -> Result<RelocationAction, OperationError> {
    match rtype {
        R_BPF_64_64 => apply_map(image, target, symbol, offset, inputs, out),
        R_BPF_64_ABS64 => {
            let (value, at) = absolute(image, target, symbol, offset, 8)?;
            image.data.write_u64(&mut out[at..at + 8], value);
            Ok(RelocationAction::Abs64 { value })
        }
        R_BPF_64_ABS32 => {
            let (wide, at) = absolute(image, target, symbol, offset, 4)?;
            let value = u32::try_from(wide)
                .map_err(|_| refuse(ErrorKind::Overflow, "32-bit relocation overflow"))?;
            image.data.write_u32(&mut out[at..at + 4], value);
            Ok(RelocationAction::Abs32 { value })
        }
        R_BPF_64_NODYLD32 => {
            if !matches!(target.name.as_deref(), Some(".BTF" | ".BTF.ext")) {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    "nodyld relocation outside btf sections",
                ));
            }
            let body = image.body(target)?;
            if offset + 4 > body.len() as u64 {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    "relocation outside section",
                ));
            }
            Ok(RelocationAction::PreservedNodyld)
        }
        R_BPF_64_32 => apply_call(image, target, symbol, offset, out),
        _ => Err(refuse(ErrorKind::InvalidInput, "unknown relocation type")),
    }
}

/// Read `S + A` for absolute relocations with a checked add.
fn absolute(
    image: &Image<'_>,
    target: &Section,
    symbol: &Symbol,
    offset: u64,
    width: u64,
) -> Result<(u64, usize), OperationError> {
    let body = image.body(target)?;
    if offset + width > body.len() as u64 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "relocation outside section",
        ));
    }
    let at = offset as usize;
    let addend = match width {
        8 => image.data.u64(&body[at..at + 8]),
        _ => u64::from(image.data.u32(&body[at..at + 4])),
    };
    let value = symbol
        .value
        .checked_add(addend)
        .ok_or_else(|| refuse(ErrorKind::Overflow, "absolute relocation overflow"))?;
    let file = target
        .offset
        .checked_add(offset)
        .ok_or_else(|| refuse(ErrorKind::Overflow, "absolute relocation overflow"))?;
    Ok((value, file as usize))
}

/// Resolve one `R_BPF_64_64` map/data reference and patch its LD_imm64.
fn apply_map(
    image: &Image<'_>,
    target: &Section,
    symbol: &Symbol,
    offset: u64,
    inputs: &RelocationInputs<'_>,
    out: &mut [u8],
) -> Result<RelocationAction, OperationError> {
    let body = image.body(target)?;
    if offset + 16 > body.len() as u64 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "relocation outside section",
        ));
    }
    if offset % 8 != 0 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "misaligned relocation slot",
        ));
    }
    let at = offset as usize;
    if body[at] != 0x18 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "map relocation against non-ldimm64 slot",
        ));
    }
    let addend = u64::from(image.data.u32(&body[at + 4..at + 8]));
    let file = (target.offset + offset) as usize;
    if symbol.kind == STT_SECTION {
        let section_index = symbol.shndx as usize;
        if section_index >= image.sections.len() {
            return Err(refuse(
                ErrorKind::InvalidInput,
                "dangling relocation symbol",
            ));
        }
        let address = symbol
            .value
            .checked_add(addend)
            .ok_or_else(|| refuse(ErrorKind::Overflow, "map relocation address overflow"))?;
        // Exact-definition boundary over caller-known maps in the section.
        let mut matched: Option<&str> = None;
        let mut has_definitions = false;
        for candidate in &image.symbols {
            if candidate.kind != STT_OBJECT || candidate.shndx as usize != section_index {
                continue;
            }
            let Some(name) = candidate.name.as_deref() else {
                continue;
            };
            if !inputs.named_maps.contains_key(name) {
                continue;
            }
            has_definitions = true;
            if candidate.value == address {
                if matched.replace(name).is_some() {
                    return Err(refuse(
                        ErrorKind::InvalidInput,
                        "ambiguous map at section offset",
                    ));
                }
            }
        }
        if let Some(name) = matched {
            let fd = inputs.named_maps[name];
            patch_ldimm64(image.data, out, file, PSEUDO_MAP_FD, fd, 0);
            return Ok(RelocationAction::MapFd {
                name: name.to_owned(),
                fd,
            });
        }
        if has_definitions {
            return Err(refuse(
                ErrorKind::InvalidInput,
                "map at section offset not found",
            ));
        }
        let section_name = image.sections[section_index].label();
        if let Some(fd) = inputs.section_maps.get(&section_name).copied() {
            patch_ldimm64(image.data, out, file, PSEUDO_MAP_VALUE, fd, addend as u32);
            return Ok(RelocationAction::MapValue {
                name: section_name,
                fd,
                value_offset: addend,
            });
        }
        return Err(refuse(
            ErrorKind::InvalidInput,
            "map section without definitions or assignment",
        ));
    }
    let Some(name) = symbol.name.as_deref() else {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "anonymous map relocation symbol",
        ));
    };
    if symbol.kind != STT_OBJECT {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "map relocation against symbol",
        ));
    }
    let Some(fd) = inputs.named_maps.get(name).copied() else {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "named map without assigned descriptor",
        ));
    };
    patch_ldimm64(image.data, out, file, PSEUDO_MAP_FD, fd, 0);
    Ok(RelocationAction::MapFd {
        name: name.to_owned(),
        fd,
    })
}

fn patch_ldimm64(data: Data, out: &mut [u8], file: usize, pseudo: u8, fd: i32, second: u32) {
    out[file + 1] = (out[file + 1] & 0x0f) | (pseudo << 4);
    data.write_u32(&mut out[file + 4..file + 8], fd as u32);
    data.write_u32(&mut out[file + 12..file + 16], second);
}

/// Resolve one `R_BPF_64_32` call relocation to a function start.
fn apply_call(
    image: &Image<'_>,
    target: &Section,
    symbol: &Symbol,
    offset: u64,
    out: &mut [u8],
) -> Result<RelocationAction, OperationError> {
    let body = image.body(target)?;
    if offset + 8 > body.len() as u64 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "relocation outside section",
        ));
    }
    if offset % 8 != 0 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "misaligned relocation slot",
        ));
    }
    let at = offset as usize;
    if body[at] != 0x85 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "call relocation against non-call slot",
        ));
    }
    let addend = u64::from(image.data.u32(&body[at + 4..at + 8]));
    let resolved = symbol
        .value
        .checked_add(addend)
        .ok_or_else(|| refuse(ErrorKind::Overflow, "call relocation overflow"))?;
    if resolved % 8 != 0 {
        return Err(refuse(ErrorKind::InvalidInput, "call target not aligned"));
    }
    let is_start = image.symbols.iter().any(|candidate| {
        candidate.kind == STT_FUNC
            && candidate.shndx as usize == target.index
            && candidate.value == resolved
            && candidate.size > 0
    });
    if !is_start {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "call target is not a function",
        ));
    }
    let slots = resolved / 8;
    let imm = i32::try_from(slots as i64 - 1)
        .map_err(|_| refuse(ErrorKind::Overflow, "call relocation overflow"))?;
    let file = (target.offset + offset) as usize;
    image
        .data
        .write_u32(&mut out[file + 4..file + 8], imm as u32);
    Ok(RelocationAction::Call { target: resolved })
}

// ---------------------------------------------------------------------------
// Call graph extraction
// ---------------------------------------------------------------------------

/// One function node: an aligned, contained `STT_FUNC` extent.
#[derive(Debug, Clone)]
pub struct FunctionNode {
    name: String,
    section: String,
    section_index: usize,
    start: u64,
    len: u64,
    global: bool,
}

impl FunctionNode {
    /// Function symbol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Containing code section label.
    pub fn section(&self) -> &str {
        &self.section
    }

    /// Section-relative start byte.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Extent length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the symbol has global binding.
    pub fn global(&self) -> bool {
        self.global
    }
}

/// One resolved call target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallTarget {
    /// Subprogram call to a function node.
    Local {
        /// Index into [`CallGraph::functions`].
        function: usize,
    },
    /// Helper call by id.
    Helper {
        /// Helper number from the call imm field.
        id: u32,
    },
}

/// One call edge inside a function extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallEdge {
    caller: usize,
    offset: u64,
    target: CallTarget,
}

impl CallEdge {
    /// Index of the calling function.
    pub fn caller(&self) -> usize {
        self.caller
    }

    /// Section-relative byte offset of the call slot.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Resolved target.
    pub fn target(&self) -> CallTarget {
        self.target
    }
}

/// Extracted call graph with cycle report and rule violations.
#[derive(Debug, Clone)]
pub struct CallGraph {
    functions: Vec<FunctionNode>,
    edges: Vec<CallEdge>,
    has_cycle: bool,
    cycle_path: Vec<usize>,
    violations: Vec<RuleViolation>,
}

impl CallGraph {
    /// Function nodes in symbol order.
    pub fn functions(&self) -> &[FunctionNode] {
        &self.functions
    }

    /// Resolved edges in function/slot order.
    pub fn edges(&self) -> &[CallEdge] {
        &self.edges
    }

    /// Whether local edges contain a cycle (recursion terminates here).
    pub fn has_cycle(&self) -> bool {
        self.has_cycle
    }

    /// One cycle path as function indices, empty when acyclic.
    pub fn cycle_path(&self) -> &[usize] {
        &self.cycle_path
    }

    /// Per-rule violations; empty means the graph decoded cleanly.
    pub fn violations(&self) -> &[RuleViolation] {
        &self.violations
    }

    /// Whether extraction produced no violations.
    pub fn conforms(&self) -> bool {
        self.violations.is_empty()
    }
}

fn call_violation(rule: &str, section: Option<String>, offset: Option<u64>) -> RuleViolation {
    RuleViolation {
        rule_id: rule.to_owned(),
        section,
        offset,
        kind: ErrorKind::InvalidInput,
    }
}

/// Extract the call graph: helper and subprogram edges over complete
/// aligned function extents, with bounded cycle detection.
///
/// Pseudo-calls must target exact function starts in the same section;
/// dangling, interior, unaligned and truncated forms become violations.
/// Traversal charges the caller work budget, so cyclic or large graphs
/// refuse [`ErrorKind::LimitExceeded`] instead of hanging.
pub fn extract_call_graph(
    bytes: &[u8],
    contract: &ObjectContract,
    limits: &Limits,
) -> Result<CallGraph, OperationError> {
    let mut work = limits.work_steps;
    let image = decode(bytes, contract, limits, &mut work)?;
    let mut functions = Vec::new();
    let mut violations = Vec::new();
    let mut walkable: Vec<bool> = Vec::new();
    for symbol in image
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == STT_FUNC)
    {
        if work == 0 {
            return Err(limited());
        }
        work -= 1;
        let section_index = symbol.shndx as usize;
        let section = image.sections.get(section_index);
        let name = symbol
            .name
            .clone()
            .unwrap_or_else(|| format!("func#{}", functions.len()));
        let Some(section) = section else {
            violations.push(call_violation(
                "call.function-outside-section",
                None,
                Some(symbol.value),
            ));
            continue;
        };
        let node = FunctionNode {
            name,
            section: section.label(),
            section_index,
            start: symbol.value,
            len: symbol.size,
            global: symbol.bind == STB_GLOBAL,
        };
        if section.flags & SHF_EXECINSTR == 0 {
            violations.push(call_violation(
                "call.function-not-executable",
                Some(node.section.clone()),
                Some(node.start),
            ));
            functions.push(node);
            walkable.push(false);
            continue;
        }
        if section.kind != SHT_PROGBITS {
            violations.push(call_violation(
                "call.unsupported-section",
                Some(node.section.clone()),
                Some(node.start),
            ));
            functions.push(node);
            walkable.push(false);
            continue;
        }
        if symbol.value % 8 != 0 || symbol.size % 8 != 0 || symbol.size == 0 {
            violations.push(call_violation(
                "call.unaligned-function",
                Some(node.section.clone()),
                Some(node.start),
            ));
            functions.push(node);
            walkable.push(false);
            continue;
        }
        if symbol.value + symbol.size > section.size {
            violations.push(call_violation(
                "call.function-outside-section",
                Some(node.section.clone()),
                Some(node.start),
            ));
            functions.push(node);
            walkable.push(false);
            continue;
        }
        if functions.iter().any(|seen: &FunctionNode| {
            seen.section_index == section_index && seen.start == symbol.value
        }) {
            violations.push(call_violation(
                "call.duplicate-function",
                Some(node.section.clone()),
                Some(node.start),
            ));
            functions.push(node);
            walkable.push(false);
            continue;
        }
        if symbol.name.is_none() {
            violations.push(call_violation(
                "call.anonymous-function",
                Some(node.section.clone()),
                Some(node.start),
            ));
        }
        functions.push(node);
        walkable.push(true);
    }
    let mut edges = Vec::new();
    for (index, function) in functions.iter().enumerate() {
        if !walkable[index] {
            continue;
        }
        let section = &image.sections[function.section_index];
        let body = image.body(section)?;
        let slots = function.len / 8;
        let mut slot = function.start / 8;
        let mut skip_next = false;
        while slot < function.start / 8 + slots {
            if work == 0 {
                return Err(limited());
            }
            work -= 1;
            let at = (slot * 8) as usize;
            slot += 1;
            if skip_next {
                skip_next = false;
                continue;
            }
            let code = body[at];
            if code == 0x18 {
                if slot == function.start / 8 + slots {
                    violations.push(call_violation(
                        "call.truncated-stream",
                        Some(function.section.clone()),
                        Some((slot - 1) * 8),
                    ));
                } else {
                    skip_next = true;
                }
                continue;
            }
            if code != 0x85 {
                continue;
            }
            let source = body[at + 1] >> 4;
            let imm = image.data.u32(&body[at + 4..at + 8]) as i32;
            let offset = (slot - 1) * 8;
            if source == 0 {
                edges.push(CallEdge {
                    caller: index,
                    offset,
                    target: CallTarget::Helper { id: imm as u32 },
                });
                continue;
            }
            if source != 1 {
                violations.push(call_violation(
                    "call.unknown-form",
                    Some(function.section.clone()),
                    Some(offset),
                ));
                continue;
            }
            let target_slot = (slot as i64 - 1) + 1 + i64::from(imm);
            if target_slot < 0 {
                violations.push(call_violation(
                    "call.dangling-target",
                    Some(function.section.clone()),
                    Some(offset),
                ));
                continue;
            }
            let target_byte = target_slot as u64 * 8;
            if let Some(target) = functions.iter().position(|candidate| {
                candidate.section_index == function.section_index && candidate.start == target_byte
            }) {
                edges.push(CallEdge {
                    caller: index,
                    offset,
                    target: CallTarget::Local { function: target },
                });
                continue;
            }
            let interior = functions.iter().any(|candidate| {
                candidate.section_index == function.section_index
                    && target_byte > candidate.start
                    && target_byte < candidate.start + candidate.len
            });
            violations.push(call_violation(
                if interior {
                    "call.interior-target"
                } else {
                    "call.dangling-target"
                },
                Some(function.section.clone()),
                Some(offset),
            ));
        }
    }
    let (has_cycle, cycle_path) = find_cycle(&functions, &edges, &mut work)?;
    Ok(CallGraph {
        functions,
        edges,
        has_cycle,
        cycle_path,
        violations,
    })
}

/// Iterative depth-first cycle search over local edges; each visit
/// charges work so adversarial graphs exhaust the budget instead of time.
fn find_cycle(
    functions: &[FunctionNode],
    edges: &[CallEdge],
    work: &mut u64,
) -> Result<(bool, Vec<usize>), OperationError> {
    let mut outgoing: Vec<Vec<usize>> = vec![Vec::new(); functions.len()];
    for edge in edges {
        if let CallTarget::Local { function } = edge.target {
            if function < functions.len() {
                outgoing[edge.caller].push(function);
            }
        }
    }
    // 0 = unvisited, 1 = on stack, 2 = settled.
    let mut color = vec![0u8; functions.len()];
    for root in 0..functions.len() {
        if color[root] != 0 {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        color[root] = 1;
        let mut path = vec![root];
        while let Some((node, next)) = stack.pop() {
            if *work == 0 {
                return Err(limited());
            }
            *work -= 1;
            if next < outgoing[node].len() {
                stack.push((node, next + 1));
                let target = outgoing[node][next];
                if color[target] == 1 {
                    let start = path.iter().position(|seen| *seen == target).unwrap_or(0);
                    return Ok((true, path[start..].to_vec()));
                }
                if color[target] == 0 {
                    color[target] = 1;
                    path.push(target);
                    stack.push((target, 0));
                }
                continue;
            }
            color[node] = 2;
            path.pop();
        }
    }
    Ok((false, Vec::new()))
}

// ---------------------------------------------------------------------------
// Callback FUNC/FUNC_PROTO linkage
// ---------------------------------------------------------------------------

/// One expected callback by name; linkage resolves through the BTF view.
#[derive(Debug, Clone)]
pub struct CallbackSpec {
    /// Callback function name.
    pub name: String,
}

/// One resolved callback with its validated prototype shape.
#[derive(Debug, Clone)]
pub struct CallbackLink {
    name: String,
    func: TypeRef,
    result: TypeRef,
    parameters: Vec<TypeRef>,
    variadic: bool,
}

impl CallbackLink {
    /// Callback name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Resolved FUNC type.
    pub fn func(&self) -> TypeRef {
        self.func
    }

    /// Prototype return type.
    pub fn result(&self) -> TypeRef {
        self.result
    }

    /// Prototype parameter types in order.
    pub fn parameters(&self) -> &[TypeRef] {
        &self.parameters
    }

    /// Whether the prototype is variadic.
    pub fn variadic(&self) -> bool {
        self.variadic
    }
}

/// Callback linkage report.
#[derive(Debug, Clone)]
pub struct CallbackReport {
    links: Vec<CallbackLink>,
    violations: Vec<RuleViolation>,
}

impl CallbackReport {
    /// Resolved callbacks in expectation order.
    pub fn links(&self) -> &[CallbackLink] {
        &self.links
    }

    /// Linkage violations in expectation order.
    pub fn violations(&self) -> &[RuleViolation] {
        &self.violations
    }
}

/// Resolve expected callbacks to unique FUNC types with valid prototypes.
///
/// Missing names, non-function types and ambiguous rivals become
/// violations; only budget exhaustion refuses typed.
pub fn verify_callbacks(
    btf: &BtfView,
    expected: &[CallbackSpec],
) -> Result<CallbackReport, OperationError> {
    let mut links = Vec::with_capacity(expected.len());
    let mut violations = Vec::new();
    for spec in expected {
        let candidates = btf.types_named(&spec.name).map_err(|error| {
            if error.kind() == ErrorKind::LimitExceeded {
                error
            } else {
                refuse(ErrorKind::InvalidInput, "callback query failed")
            }
        })?;
        if candidates.is_empty() {
            violations.push(call_violation("callback.missing", None, None));
            continue;
        }
        let mut resolved = None;
        let mut ambiguous = false;
        let mut bad_proto = false;
        for candidate in candidates {
            match btf.function(candidate) {
                Ok(shape) => {
                    if resolved.replace((candidate, shape)).is_some() {
                        ambiguous = true;
                        break;
                    }
                }
                Err(error) if error.kind() == ErrorKind::Incompatible => continue,
                Err(error) if error.kind() == ErrorKind::LimitExceeded => return Err(error),
                Err(_) => {
                    bad_proto = true;
                }
            }
        }
        if ambiguous {
            violations.push(call_violation("callback.ambiguous", None, None));
        } else if let Some((func, shape)) = resolved {
            links.push(CallbackLink {
                name: spec.name.clone(),
                func,
                result: shape.result,
                parameters: shape.parameters,
                variadic: shape.variadic,
            });
        } else if bad_proto {
            violations.push(call_violation("callback.bad-prototype", None, None));
        } else {
            violations.push(call_violation("callback.not-function", None, None));
        }
    }
    Ok(CallbackReport { links, violations })
}

// ---------------------------------------------------------------------------
// Metadata preservation
// ---------------------------------------------------------------------------

/// One section digest: name, size and exact content hash.
#[derive(Debug, Clone)]
pub struct SectionDigest {
    name: String,
    size: u64,
    sha256: [u8; 32],
}

impl SectionDigest {
    /// Section label.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Section size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Content hash.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// One required map with its linked key/value types.
#[derive(Debug, Clone)]
pub struct MapLinkage {
    name: String,
    key: TypeRef,
    value: TypeRef,
}

impl MapLinkage {
    /// Map name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Linked key type.
    pub fn key(&self) -> TypeRef {
        self.key
    }

    /// Linked value type.
    pub fn value(&self) -> TypeRef {
        self.value
    }
}

/// One required named-type population.
#[derive(Debug, Clone)]
pub struct NamedTypes {
    name: String,
    ids: Vec<u32>,
}

impl NamedTypes {
    /// Type name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Admitted ids in ascending order (empty when the name is gone).
    pub fn ids(&self) -> &[u32] {
        &self.ids
    }
}

/// Metadata snapshot: section inventory plus required BTF linkage.
#[derive(Debug, Clone)]
pub struct MetadataSnapshot {
    object_id: ArtifactId,
    sections: Vec<SectionDigest>,
    maps: Vec<MapLinkage>,
    types: Vec<NamedTypes>,
}

impl MetadataSnapshot {
    /// Identity of the snapshotted bytes.
    pub fn object_id(&self) -> &ArtifactId {
        &self.object_id
    }

    /// Section digests in section order.
    pub fn sections(&self) -> &[SectionDigest] {
        &self.sections
    }

    /// Required map linkage in request order.
    pub fn maps(&self) -> &[MapLinkage] {
        &self.maps
    }

    /// Required named-type populations in request order.
    pub fn types(&self) -> &[NamedTypes] {
        &self.types
    }
}

/// Metadata snapshot inputs: the object bytes carry sections while the
/// caller-parsed BTF view answers type queries; both must be supplied
/// together or neither, and a view requires a `.BTF` section to bind to.
pub struct MetadataInputs<'a> {
    /// Parsed BTF view answering map/type queries, if any.
    pub btf: Option<&'a BtfView>,
    /// Map names whose key/value linkage is recorded (refuses typed on
    /// unlinked, valueless or void-pointed definitions).
    pub required_maps: &'a [&'a str],
    /// Type names whose id populations are recorded (empty when lost).
    pub required_types: &'a [&'a str],
}

/// Snapshot section digests plus required BTF map/type linkage.
///
/// Map linkage errors (including the same-size map with zero key/value
/// ids) refuse typed; a supplied view without a `.BTF` section refuses as
/// unbound.
pub fn snapshot_metadata(
    bytes: &[u8],
    contract: &ObjectContract,
    inputs: &MetadataInputs<'_>,
    limits: &Limits,
) -> Result<MetadataSnapshot, OperationError> {
    let mut work = limits.work_steps;
    let image = decode(bytes, contract, limits, &mut work)?;
    let has_btf = image
        .sections
        .iter()
        .any(|section| section.name.as_deref() == Some(".BTF"));
    if inputs.btf.is_some() && !has_btf {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "btf view without object btf section",
        ));
    }
    if inputs.btf.is_none()
        && (!inputs.required_maps.is_empty() || !inputs.required_types.is_empty())
    {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "required metadata without btf view",
        ));
    }
    let mut sections = Vec::new();
    for section in image.sections.iter().skip(1) {
        let body = image.body(section)?;
        if work < 1 + body.len() as u64 {
            return Err(limited());
        }
        work -= 1 + body.len() as u64;
        sections.push(SectionDigest {
            name: section.label(),
            size: section.size,
            sha256: digest_of(body),
        });
    }
    let mut maps = Vec::with_capacity(inputs.required_maps.len());
    if let Some(btf) = inputs.btf {
        for name in inputs.required_maps {
            let (key, value) = btf.map_types(name)?;
            maps.push(MapLinkage {
                name: (*name).to_owned(),
                key,
                value,
            });
        }
    }
    let mut types = Vec::with_capacity(inputs.required_types.len());
    if let Some(btf) = inputs.btf {
        for name in inputs.required_types {
            let refs = btf.types_named(name)?;
            types.push(NamedTypes {
                name: (*name).to_owned(),
                ids: refs.iter().map(|r| r.id).collect(),
            });
        }
    }
    Ok(MetadataSnapshot {
        object_id: artifact_id(digest_of(bytes)),
        sections,
        maps,
        types,
    })
}

/// One detected metadata loss between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLoss {
    kind: String,
    detail: String,
}

impl MetadataLoss {
    /// Loss kind (`section.dropped`, `map.relinked`, ...).
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Human-readable detail naming the entry.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

fn loss(kind: &str, detail: String) -> MetadataLoss {
    MetadataLoss {
        kind: kind.to_owned(),
        detail,
    }
}

/// Diff two snapshots; empty means the transformation preserved
/// everything recorded. Sections compare by digest, maps by linked
/// key/value ids, named types by id population.
pub fn diff_metadata(before: &MetadataSnapshot, after: &MetadataSnapshot) -> Vec<MetadataLoss> {
    let mut out = Vec::new();
    for section in &before.sections {
        match after.sections.iter().find(|seen| seen.name == section.name) {
            None => out.push(loss(
                "section.dropped",
                format!(
                    "section {} dropped (was {} bytes)",
                    section.name, section.size
                ),
            )),
            Some(seen) if seen.size != section.size || seen.sha256 != section.sha256 => {
                out.push(loss(
                    "section.changed",
                    format!(
                        "section {} changed ({} to {} bytes)",
                        section.name, section.size, seen.size
                    ),
                ));
            }
            Some(_) => {}
        }
    }
    for section in &after.sections {
        if !before.sections.iter().any(|seen| seen.name == section.name) {
            out.push(loss(
                "section.added",
                format!("section {} added", section.name),
            ));
        }
    }
    for map in &before.maps {
        match after.maps.iter().find(|seen| seen.name == map.name) {
            None => out.push(loss("map.missing", format!("map {} missing", map.name))),
            Some(seen) if seen.key != map.key || seen.value != map.value => {
                out.push(loss(
                    "map.relinked",
                    format!(
                        "map {} relinked key {}->{} value {}->{}",
                        map.name, map.key.id, seen.key.id, map.value.id, seen.value.id
                    ),
                ));
            }
            Some(_) => {}
        }
    }
    for name in &before.types {
        let current = after.types.iter().find(|seen| seen.name == name.name);
        match current {
            None => out.push(loss("type.lost", format!("type {} lost", name.name))),
            Some(seen) if seen.ids.is_empty() && !name.ids.is_empty() => {
                out.push(loss("type.lost", format!("type {} lost", name.name)));
            }
            Some(seen) if seen.ids != name.ids => {
                out.push(loss("type.changed", format!("type {} changed", name.name)));
            }
            Some(_) => {}
        }
    }
    for name in &after.types {
        if !before.types.iter().any(|seen| seen.name == name.name) {
            out.push(loss("type.added", format!("type {} added", name.name)));
        }
    }
    out
}
