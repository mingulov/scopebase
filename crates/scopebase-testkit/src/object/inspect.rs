// SPDX-License-Identifier: Apache-2.0
//! TC03: final-object inspection. Decodes linked/relocatable ELF64 BPF
//! objects over the contract target (endianness and machine refuse typed),
//! classifies every instruction into an explicit ISA family, and reports the
//! runtime license declaration. Unknown encodings and malformed declarations
//! become per-rule violations; only structural truncation, target
//! contradiction and bound exhaustion refuse with typed errors.
//!
//! Opcode numbers are cited from the pinned kernel UAPI headers recorded in
//! `fixtures/bpf/isa/expected.json` (`bpf.h` 16-62 @ b75746f4…,
//! `bpf_common.h` 8-60 @ 7475540d…; hashes only, no lines copied). Emission
//! behavior (off-field SDIV/SMOD/MOVSX, imm-field acquire, per-CPU gating)
//! was confirmed against llc 21.1.8 output frozen in
//! `fixtures/bpf/isa/objects/`. The JMP `JA|X` (0x0d) indirect-jump rule is a
//! design-frozen classification pending the TC07 live gate. Donor H30 preset
//! warning: p11scope-ws w000 @ 6f97aa47, `llvm-bpf-toolchain-experiment.md`
//! lines 77-100 (user-authored). Grant: OWNER-2026-10-23.
//!
//! TC04 appends the raw slot fields ([`FamilySpan::code`], `regs`, `off`,
//! `imm`) so the atomic checker decodes RMW shapes over this inventory
//! without re-parsing ELF. Classification behavior is unchanged.
use scopebase_bpf::{ErrorKind, Limits, OperationError};
use sha2::{Digest, Sha256};

use super::manifest::{ArtifactId, ObjectKind};
use super::{limited, tc03_refuse, ObjectContract};

const EM_BPF: u16 = 247;
const SHF_EXECINSTR: u64 = 0x4;
const SHT_PROGBITS: u32 = 1;
const MAX_LICENSE_BYTES: usize = 128;

/// One rule finding with location and category (spec shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleViolation {
    /// Stable rule id, e.g. `isa.unknown-opcode`.
    pub rule_id: String,
    /// Section name (or `section#i` when names are unavailable), if located.
    pub section: Option<String>,
    /// Section-relative byte offset, if located.
    pub offset: Option<u64>,
    /// Violation category.
    pub kind: ErrorKind,
}

/// One decoded instruction: its ISA family and location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilySpan {
    /// Classified ISA family.
    pub family: String,
    /// Section name (or `section#i` when names are unavailable).
    pub section: String,
    /// Section-relative byte offset of the 8-byte slot.
    pub offset: u64,
    /// Raw opcode byte (TC04: atomic/plain shape decode over this inventory).
    pub code: u8,
    /// Raw register byte: low nibble dst, high nibble src.
    pub regs: u8,
    /// Decoded 16-bit offset in the contract endianness.
    pub off: i16,
    /// Decoded 32-bit immediate in the contract endianness.
    pub imm: i32,
}

/// Decoded final-object inventory with per-rule results.
#[derive(Debug, Clone)]
pub struct ObjectInspection {
    object_id: ArtifactId,
    kind: ObjectKind,
    families: Vec<String>,
    license: Option<String>,
    spans: Vec<FamilySpan>,
    violations: Vec<RuleViolation>,
}

impl ObjectInspection {
    /// Content-bound object identity (hex content id plus exact hash).
    pub fn object_id(&self) -> &ArtifactId {
        &self.object_id
    }

    /// Per-rule violations; empty means the object decoded cleanly.
    pub fn violations(&self) -> &[RuleViolation] {
        &self.violations
    }

    /// Whether decoding produced no violations. Profile admission is a
    /// separate `check_object` step; both must hold to admit.
    pub fn conforms(&self) -> bool {
        self.violations.is_empty()
    }

    /// Effective decoded ISA families, sorted, deduplicated.
    pub fn families(&self) -> &[String] {
        &self.families
    }

    /// Runtime license token from the single `license` section, if present
    /// and well-formed.
    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }

    /// Decoded ELF role.
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// Full per-instruction decoded inventory.
    pub fn spans(&self) -> &[FamilySpan] {
        &self.spans
    }
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
}

fn slice_at(bytes: &[u8], offset: u64, len: u64) -> Result<&[u8], OperationError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| tc03_refuse(ErrorKind::Malformed, "truncated object"))?;
    if end > bytes.len() as u64 {
        return Err(tc03_refuse(ErrorKind::Malformed, "truncated object"));
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
        usize::try_from(at).map_err(|_| tc03_refuse(ErrorKind::Malformed, "bad section name"))?;
    if start >= table.len() {
        return Err(tc03_refuse(ErrorKind::Malformed, "bad section name"));
    }
    let end = table[start..]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| tc03_refuse(ErrorKind::Malformed, "bad section name"))?;
    let name = &table[start..start + end];
    if name.is_empty() {
        return Ok(None);
    }
    std::str::from_utf8(name)
        .map(|text| Some(text.to_owned()))
        .map_err(|_| tc03_refuse(ErrorKind::Malformed, "bad section name"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Family(&'static str),
    /// 16-byte load-immediate: skip the following slot.
    Wide,
    Unknown,
}

/// Classify one 8-byte instruction by (class, op/mode, off, imm).
///
/// The table follows the pinned UAPI opcode facts; the `off`/`imm` extension
/// markers (SDIV/SMOD/MOVSX/acquire) match llc 21.1.8 emission frozen in
/// `fixtures/bpf/isa/expected.json`. Operand-form validation (register
/// ranges, call targets, jump bounds) is verifier/TC06 domain, not family
/// admission: classification is by opcode shape only.
fn classify(code: u8, off: i16, imm: i32) -> Class {
    const LD: u8 = 0x00;
    const LDX: u8 = 0x01;
    const ST: u8 = 0x02;
    const STX: u8 = 0x03;
    const ALU: u8 = 0x04;
    const JMP: u8 = 0x05;
    const JMP32: u8 = 0x06;
    const ALU64: u8 = 0x07;
    const DW: u8 = 0x18;
    const IMM: u8 = 0x00;
    const ABS: u8 = 0x20;
    const IND: u8 = 0x40;
    const MEM: u8 = 0x60;
    const MEMSX: u8 = 0x80;
    const ATOMIC: u8 = 0xc0;
    const JA: u8 = 0x00;
    const SRC_X: u8 = 0x08;
    const LOAD_ACQ: i32 = 0x100;
    const STORE_REL: i32 = 0x110;

    let class = code & 0x07;
    let op = code & 0xf0;
    let mode = code & 0xe0;
    let size = code & 0x18;
    match class {
        LD => {
            if mode == IMM && size == DW {
                Class::Wide
            } else if mode == ABS || mode == IND {
                Class::Family("base")
            } else {
                Class::Unknown
            }
        }
        LDX => {
            if (mode == MEM || mode == MEMSX) && (imm == LOAD_ACQ || imm == STORE_REL) {
                Class::Family("acqrel")
            } else if mode == MEMSX {
                Class::Family("signed-load-move")
            } else if mode == MEM {
                Class::Family("base")
            } else {
                Class::Unknown
            }
        }
        ST => {
            if mode == MEM {
                Class::Family("imm-store")
            } else {
                Class::Unknown
            }
        }
        STX => {
            if mode == MEM {
                Class::Family("base")
            } else if mode == ATOMIC {
                if imm == LOAD_ACQ || imm == STORE_REL {
                    Class::Family("acqrel")
                } else {
                    // Plain atomics (XADD/fetch/XCHG/CAS): TC04 owns their
                    // old/new-value semantics; TC03 gates the family as base.
                    Class::Family("base")
                }
            } else {
                Class::Unknown
            }
        }
        ALU => alu_family(op, off, "alu32"),
        JMP => {
            if op == JA {
                if code & SRC_X == 0 {
                    Class::Family("base")
                } else {
                    // Design-frozen: direct/indirect distinction pending TC07.
                    Class::Family("indirect-jumps")
                }
            } else {
                jump_family(op, "base")
            }
        }
        JMP32 => {
            if op == JA {
                if code & SRC_X == 0 {
                    Class::Family("long-jump")
                } else {
                    Class::Family("indirect-jumps")
                }
            } else {
                jump_family(op, "jump32")
            }
        }
        ALU64 => alu_family(op, off, "base"),
        _ => Class::Unknown,
    }
}

fn alu_family(op: u8, off: i16, plain: &'static str) -> Class {
    const ADD: u8 = 0x00;
    const SUB: u8 = 0x10;
    const MUL: u8 = 0x20;
    const DIV: u8 = 0x30;
    const OR: u8 = 0x40;
    const AND: u8 = 0x50;
    const LSH: u8 = 0x60;
    const RSH: u8 = 0x70;
    const NEG: u8 = 0x80;
    const MOD: u8 = 0x90;
    const XOR: u8 = 0xa0;
    const MOV: u8 = 0xb0;
    const ARSH: u8 = 0xc0;
    const END: u8 = 0xd0;
    if op == END {
        Class::Family("byte-swap")
    } else if (op == DIV || op == MOD) && off != 0 {
        Class::Family("signed-div")
    } else if op == MOV && off != 0 {
        Class::Family("signed-load-move")
    } else {
        match op {
            ADD | SUB | MUL | DIV | OR | AND | LSH | RSH | NEG | MOD | XOR | MOV | ARSH => {
                Class::Family(plain)
            }
            _ => Class::Unknown,
        }
    }
}

fn jump_family(op: u8, plain: &'static str) -> Class {
    const JEQ: u8 = 0x10;
    const JGT: u8 = 0x20;
    const JGE: u8 = 0x30;
    const JSET: u8 = 0x40;
    const JNE: u8 = 0x50;
    const JSGT: u8 = 0x60;
    const JSGE: u8 = 0x70;
    const CALL: u8 = 0x80;
    const EXIT: u8 = 0x90;
    const JLT: u8 = 0xa0;
    const JLE: u8 = 0xb0;
    const JSLT: u8 = 0xc0;
    const JSLE: u8 = 0xd0;
    const JCOND: u8 = 0xe0;
    match op {
        JEQ | JGT | JGE | JSET | JNE | JLT | JLE => Class::Family(plain),
        JSGT | JSGE | JSLT | JSLE => Class::Family("ext-jumps"),
        // Pseudo-jumps, calls and returns exist in the JMP class only; the
        // same op nibble in JMP32 is not a known instruction.
        JCOND if plain == "base" => Class::Family("ext-jumps"),
        CALL | EXIT if plain == "base" => Class::Family("base"),
        _ => Class::Unknown,
    }
}

/// Validate collected `license` section bodies: at most one section holding a
/// single bounded NUL-terminated ASCII token.
fn validate_license(bodies: &[&[u8]]) -> (Option<String>, Vec<RuleViolation>) {
    if bodies.len() > 1 {
        return (
            None,
            vec![RuleViolation {
                rule_id: "license.duplicated".to_owned(),
                section: Some("license".to_owned()),
                offset: None,
                kind: ErrorKind::InvalidInput,
            }],
        );
    }
    let Some(body) = bodies.first() else {
        return (None, Vec::new());
    };
    if body.is_empty() {
        return (None, Vec::new());
    }
    if body.len() > MAX_LICENSE_BYTES {
        return (
            None,
            vec![RuleViolation {
                rule_id: "license.too-long".to_owned(),
                section: Some("license".to_owned()),
                offset: None,
                kind: ErrorKind::InvalidInput,
            }],
        );
    }
    let nul_count = body.iter().filter(|byte| **byte == 0).count();
    let terminated = body.last() == Some(&0);
    if nul_count == 0 || !terminated || nul_count > 1 || body.len() == 1 {
        let rule = if nul_count == 0 {
            "license.truncated"
        } else {
            "license.duplicated"
        };
        return (
            None,
            vec![RuleViolation {
                rule_id: rule.to_owned(),
                section: Some("license".to_owned()),
                offset: None,
                kind: ErrorKind::InvalidInput,
            }],
        );
    }
    let token = &body[..body.len() - 1];
    if !token.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return (
            None,
            vec![RuleViolation {
                rule_id: "license.non-ascii".to_owned(),
                section: Some("license".to_owned()),
                offset: None,
                kind: ErrorKind::InvalidInput,
            }],
        );
    }
    (
        Some(String::from_utf8_lossy(token).into_owned()),
        Vec::new(),
    )
}

/// Decode one final linked/relocatable object over an admitted contract.
///
/// The contract governs target admission only (endianness and BPF machine);
/// CPU/feature gating is the later `check_object` layer over the decoded
/// effective families, so a preset name can never broaden admission by
/// itself. Intermediate IR or non-ELF bytes refuse [`ErrorKind::Malformed`].
pub fn inspect_final_object(
    bytes: &[u8],
    contract: &ObjectContract,
    limits: &Limits,
) -> Result<ObjectInspection, OperationError> {
    limits.validate()?;
    if bytes.len() > limits.input_bytes || bytes.len() > limits.retained_bytes {
        return Err(limited());
    }
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&Sha256::digest(bytes));
    if bytes.len() < 64 {
        return Err(tc03_refuse(ErrorKind::Malformed, "truncated elf header"));
    }
    if bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(tc03_refuse(ErrorKind::Malformed, "not an elf object"));
    }
    if bytes[4] != 2 {
        return Err(tc03_refuse(ErrorKind::Malformed, "not a 64-bit object"));
    }
    let data = match bytes[5] {
        1 => Data::Little,
        2 => Data::Big,
        _ => {
            return Err(tc03_refuse(
                ErrorKind::Malformed,
                "unknown elf data encoding",
            ))
        }
    };
    let contract_little = match contract.endian() {
        "little" => true,
        "big" => false,
        _ => return Err(tc03_refuse(ErrorKind::InvalidInput, "contract endian")),
    };
    if (data == Data::Little) != contract_little {
        return Err(tc03_refuse(
            ErrorKind::Incompatible,
            "object endianness contradicts contract",
        ));
    }
    let kind = match data.u16(&bytes[0x10..0x12]) {
        1 => ObjectKind::Rel,
        2 => ObjectKind::Exec,
        _ => {
            return Err(tc03_refuse(
                ErrorKind::InvalidInput,
                "not a relocatable or executable object",
            ));
        }
    };
    if data.u16(&bytes[0x12..0x14]) != EM_BPF {
        return Err(tc03_refuse(
            ErrorKind::Incompatible,
            "object machine contradicts bpf contract",
        ));
    }
    let shoff = data.u64(&bytes[0x28..0x30]);
    let shentsize = data.u16(&bytes[0x3a..0x3c]);
    let shnum = data.u16(&bytes[0x3c..0x3e]);
    let shstrndx = data.u16(&bytes[0x3e..0x40]);

    let mut violations = Vec::new();
    let mut spans = Vec::new();
    if shnum == 0 {
        violations.push(RuleViolation {
            rule_id: "object.no-code-sections".to_owned(),
            section: None,
            offset: None,
            kind: ErrorKind::InvalidInput,
        });
        return Ok(finish(sha256, kind, spans, violations, None));
    }
    if shentsize != 64 {
        return Err(tc03_refuse(
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
        .ok_or_else(|| tc03_refuse(ErrorKind::Malformed, "truncated section table"))?;
    if table_end > bytes.len() as u64 {
        return Err(tc03_refuse(ErrorKind::Malformed, "truncated section table"));
    }
    let mut sections = Vec::with_capacity(usize::from(shnum));
    for index in 0..shnum {
        let at = shoff + u64::from(index) * 64;
        let header = slice_at(bytes, at, 64)?;
        let kind = data.u32(&header[4..8]);
        let flags = data.u64(&header[8..16]);
        let offset = data.u64(&header[24..32]);
        let size = data.u64(&header[32..40]);
        offset
            .checked_add(size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or_else(|| tc03_refuse(ErrorKind::Malformed, "section outside file"))?;
        sections.push(Section {
            index: usize::from(index),
            name: None,
            kind,
            flags,
            offset,
            size,
        });
    }
    // Resolve names after all headers are bounds-checked.
    let names: Vec<Option<String>> = if shstrndx == 0 {
        vec![None; sections.len()]
    } else {
        if shstrndx >= shnum {
            return Err(tc03_refuse(ErrorKind::Malformed, "bad section-name index"));
        }
        let table_section = &sections[usize::from(shstrndx)];
        if table_section.size > limits.retained_bytes as u64 {
            return Err(limited());
        }
        let table = slice_at(bytes, table_section.offset, table_section.size)?;
        let mut names = Vec::with_capacity(sections.len());
        for index in 0..shnum {
            let at = shoff + u64::from(index) * 64;
            let header = slice_at(bytes, at, 64)?;
            let name = data.u32(&header[0..4]);
            names.push(section_name(table, name)?);
        }
        names
    };
    for (section, name) in sections.iter_mut().zip(names) {
        section.name = name;
    }

    let mut decoded_slots: u64 = 0;
    let mut code_sections = 0u32;
    for section in &sections {
        if section.flags & SHF_EXECINSTR == 0 || section.size == 0 {
            continue;
        }
        if section.kind != SHT_PROGBITS {
            violations.push(RuleViolation {
                rule_id: "object.unsupported-section".to_owned(),
                section: Some(section.label()),
                offset: None,
                kind: ErrorKind::InvalidInput,
            });
            continue;
        }
        if section.size % 8 != 0 {
            violations.push(RuleViolation {
                rule_id: "isa.truncated-stream".to_owned(),
                section: Some(section.label()),
                offset: None,
                kind: ErrorKind::Malformed,
            });
            continue;
        }
        code_sections += 1;
        let body = slice_at(bytes, section.offset, section.size)?;
        let mut slot = 0u64;
        let slots = section.size / 8;
        let mut skip_next = false;
        while slot < slots {
            if decoded_slots == limits.work_steps {
                return Err(limited());
            }
            decoded_slots += 1;
            let at = (slot * 8) as usize;
            let raw = &body[at..at + 8];
            slot += 1;
            if skip_next {
                skip_next = false;
                continue;
            }
            let code = raw[0];
            let off = match data {
                Data::Little => i16::from_le_bytes([raw[2], raw[3]]),
                Data::Big => i16::from_be_bytes([raw[2], raw[3]]),
            };
            let imm = match data {
                Data::Little => i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
                Data::Big => i32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            };
            let regs = raw[1];
            match classify(code, off, imm) {
                Class::Family(family) => spans.push(FamilySpan {
                    family: family.to_owned(),
                    section: section.label(),
                    offset: (slot - 1) * 8,
                    code,
                    regs,
                    off,
                    imm,
                }),
                Class::Wide => {
                    if slot == slots {
                        violations.push(RuleViolation {
                            rule_id: "isa.truncated-stream".to_owned(),
                            section: Some(section.label()),
                            offset: Some((slot - 1) * 8),
                            kind: ErrorKind::Malformed,
                        });
                    } else {
                        spans.push(FamilySpan {
                            family: "base".to_owned(),
                            section: section.label(),
                            offset: (slot - 1) * 8,
                            code,
                            regs,
                            off,
                            imm,
                        });
                        skip_next = true;
                    }
                }
                Class::Unknown => violations.push(RuleViolation {
                    rule_id: "isa.unknown-opcode".to_owned(),
                    section: Some(section.label()),
                    offset: Some((slot - 1) * 8),
                    kind: ErrorKind::InvalidInput,
                }),
            }
        }
    }
    if code_sections == 0 {
        violations.push(RuleViolation {
            rule_id: "object.no-code-sections".to_owned(),
            section: None,
            offset: None,
            kind: ErrorKind::InvalidInput,
        });
    }
    let mut license_bodies = Vec::new();
    for section in &sections {
        if section.name.as_deref() == Some("license") {
            license_bodies.push(slice_at(bytes, section.offset, section.size)?);
        }
    }
    let (license, mut license_violations) = validate_license(&license_bodies);
    violations.append(&mut license_violations);
    Ok(finish(sha256, kind, spans, violations, license))
}

fn finish(
    sha256: [u8; 32],
    kind: ObjectKind,
    spans: Vec<FamilySpan>,
    violations: Vec<RuleViolation>,
    license: Option<String>,
) -> ObjectInspection {
    let mut families: Vec<String> = spans.iter().map(|span| span.family.clone()).collect();
    families.sort();
    families.dedup();
    let id = sha256.iter().map(|byte| format!("{byte:02x}")).collect();
    ObjectInspection {
        object_id: ArtifactId::new(id, sha256),
        kind,
        families,
        license,
        spans,
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, validate_license, Class};

    #[test]
    fn classifier_covers_every_advertised_family() {
        // (code, off, imm, expected family)
        let vectors: &[(u8, i16, i32, &str)] = &[
            (0x07, 0, 1, "base"),             // ALU64 ADD K
            (0x95, 0, 0, "base"),             // EXIT
            (0x79, 0, 0, "base"),             // LDX MEM DW
            (0x0c, 0, 0, "alu32"),            // ALU ADD X
            (0x3e, 2, 0, "jump32"),           // JMP32 JGE X
            (0x65, 2, -1, "ext-jumps"),       // JMP JSGT K
            (0xd5, 0, 0, "ext-jumps"),        // JMP JSLE K
            (0xce, 0, 0, "ext-jumps"),        // JMP32 JSLT X
            (0x89, 4, 0, "signed-load-move"), // LDX MEMSX H
            (0xbf, 8, 0, "signed-load-move"), // MOVSX
            (0xdc, 0, 64, "byte-swap"),       // ALU END BE64
            (0xd7, 0, 16, "byte-swap"),       // ALU64 END LE16
            (0x3f, 1, 0, "signed-div"),       // SDIV64
            (0x9c, 1, 0, "signed-div"),       // SMOD32
            (0x06, 0, 0, "long-jump"),        // JMP32 JA
            (0x7a, -4, 7, "imm-store"),       // ST DW MEM-IMM
            (0xdb, 0, 0x100, "acqrel"),       // load-acquire
            (0xdb, 0, 0x110, "acqrel"),       // store-release
            (0xdb, 0, 0x61, "base"),          // plain atomic add-fetch
            (0x0d, 0, 0, "indirect-jumps"),   // JMP JA|X
            (0x0e, 0, 0, "indirect-jumps"),   // JMP32 JA|X
        ];
        for (code, off, imm, family) in vectors {
            assert_eq!(
                classify(*code, *off, *imm),
                Class::Family(family),
                "opcode {code:#04x}"
            );
        }
        // Plain DIV/MOD/MOV stay base-classified without the off marker.
        assert_eq!(classify(0x3f, 0, 0), Class::Family("base"));
        assert_eq!(classify(0x9f, 0, 0), Class::Family("base"));
        assert_eq!(classify(0xbf, 0, 0), Class::Family("base"));
        assert_eq!(classify(0xbc, 0, 0), Class::Family("alu32"));
        // Unknown shapes refuse instead of assuming baseline.
        for code in [0xf5u8, 0x86, 0x96, 0xe6, 0xe4, 0x19, 0x29, 0x39, 0x49] {
            assert_eq!(classify(code, 0, 0), Class::Unknown, "opcode {code:#04x}");
        }
        assert_eq!(classify(0x18, 0, 0), Class::Wide);
    }

    #[test]
    fn license_validator_separates_each_defect() {
        let (license, violations) = validate_license(&[b"GPL\0".as_slice()]);
        assert_eq!(license.as_deref(), Some("GPL"));
        assert!(violations.is_empty());
        let (none, violations) = validate_license(&[]);
        assert_eq!(none, None);
        assert!(violations.is_empty());
        for (bodies, rule) in [
            (vec![b"GPLX".as_slice()], "license.truncated"),
            (vec![b"G\0PL".as_slice()], "license.duplicated"),
            (vec![b"\0".as_slice()], "license.duplicated"),
            (
                vec![b"GPL\0".as_slice(), b"GPL\0".as_slice()],
                "license.duplicated",
            ),
            (vec![b"G\xffL\0".as_slice()], "license.non-ascii"),
            (vec![vec![b'A'; 129].as_slice()], "license.too-long"),
        ] {
            let (none, violations) = validate_license(&bodies);
            assert_eq!(none, None);
            assert_eq!(violations.len(), 1);
            assert_eq!(violations[0].rule_id, rule);
        }
    }
}
