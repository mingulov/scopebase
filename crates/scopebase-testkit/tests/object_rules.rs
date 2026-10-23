// SPDX-License-Identifier: Apache-2.0
//! TC06: restricted dead-code repair and verifier-sensitive rule manifests.
//!
//! Donor slices (all user-owned; third-party/upstream never copied):
//! - kryprobe-ws kryprobe w001 @ d153f3aaf9a3931337b47c9e1b046c692da55083,
//!   `xtask/src/bpf/strip.rs`: dead-builtins rationale 1-9, repair pipeline
//!   64-103, function tiling 249-307, call-target/entry-root resolution with
//!   the `-1` addend convention 347-412, reachability 424-474, kept-range
//!   planning and shifted-entry refusal 551-592, text compaction 594-615,
//!   symtab/reloc rewrite 617-800, post-rewrite verify 825-852, and the
//!   strip/remap/live-call/dead-reloc/entry-inside/tiling/shifted-entry
//!   vectors 1019-1076.
//! - Same worktree/commit, `docs/dependencies/pins.md` lines 72-85:
//!   `--disable-memory-builtins` stops injection, not retention, of builtins,
//!   and the 28-byte zero-chain `memset` fusion hazard.
//! - Same worktree/commit, `crates/bpf-spine/src/bin/spine.rs` lines
//!   104-132: the ring-slot init path must stay builtin-free through
//!   volatile stores (path-scoped guard donor).
//! - p11scope-ws `.worktrees/v040-integration` @
//!   2c2713e66292b0d2688508a25f79e813ae823d81,
//!   `crates/ebpf/src/main.rs` lines 173-205 (out-of-range tail-call
//!   prologue that keeps the task kernel stack) and 750-771 (named `_pad`
//!   in `SelectionTransport`: size checks alone miss unwritten padding,
//!   old verifiers refuse with EACCES while 6.5+ accepts).
//! - Same worktree/commit, `scripts/check-bpf-map-defs.py` lines
//!   1216-1302 (`validate_classic_uprobe_kernel_stack`: per-program
//!   opt-out/continuation/array-attribution contract), 1195-1214
//!   (program-array relocation attribution), 1002-1006 (tail-call helper
//!   id and opt-out index), 1042-1051 (opt-out-only bodies), and
//!   1321-1339 plus 1402-1405 (exact GLOBAL FUNC linkage in symbol and
//!   BTF, `st_info == 0x12`).
//! - Same worktree/commit, `tests/python/test_bpf_map_defs.py` lines
//!   274-356 (`test_classic_uprobe_kernel_stack` twin matrix: missing
//!   prologue, retired slot, wrong array, multi-loaded attribution).
//! - Same worktree/commit, `tests/exec_task_continuity.rs` lines 171-245:
//!   CO-RE shape predicates take safe compiled paths (scope reference;
//!   live shape behavior stays a TC07-gated cell, not an object claim).
//! Grant: OWNER-2026-10-23 plus the D03 scoped GPL-source to Apache-2.0
//! library-destination grant; original donor files/terms untouched.
use scopebase_bpf::btf::{BtfImages, BtfLimits, BtfView, ByteOrder};
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use scopebase_testkit::object::graph::{extract_call_graph, CallTarget};
use scopebase_testkit::object::inspect::RuleViolation;
use scopebase_testkit::object::{
    check_verifier_rules, inspect_final_object, prune_dead_code, prune_dead_code_with_report,
    ObjectContract, PruneAllowlist, VerifierRules, FROZEN_DEAD_BUILTINS,
};
use sha2::{Digest, Sha256};
use std::error::Error as _;

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{MANIFEST_DIR}/../../{relative}"))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn limits() -> Limits {
    Limits {
        input_bytes: 1 << 20,
        retained_bytes: 1 << 20,
        work_steps: 1 << 20,
        sites: 64,
        live_links: 64,
        pending_retirements: 64,
    }
}

fn tiny_limits(work_steps: u64) -> Limits {
    Limits {
        work_steps,
        ..limits()
    }
}

fn btf_limits() -> BtfLimits {
    BtfLimits {
        image_bytes: 1 << 20,
        types: 4096,
        strings: 1 << 20,
        wrapper_depth: 16,
        work_steps: 1_000_000,
    }
}

fn parse_btf(bytes: &[u8]) -> BtfView {
    BtfView::parse(
        BtfImages {
            base: bytes,
            module: None,
            byte_order: ByteOrder::Little,
        },
        btf_limits(),
    )
    .expect("admit test BTF image")
}

fn contract() -> ObjectContract {
    let json = r#"{
  "schema_version": 1,
  "artifact": "tc06-rules-vectors",
  "profile": "compiler-object-v1",
  "target": {"triple": "bpfel-unknown-none", "arch": "bpf", "endian": "little", "pointer_width_bits": 64},
  "backend": {"kind": "llvm-llc", "name": "llc", "version": "21.1.8", "sha256": "935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382"},
  "cpu": "generic",
  "features_enabled": [],
  "features_disabled": [],
  "required_cells": ["kernel-6.12-x86_64-verifier"],
  "optional_cells": []
}"#;
    ObjectContract::from_json(json.as_bytes(), &limits()).expect("contract")
}

fn contract_big() -> ObjectContract {
    let json = r#"{
  "schema_version": 1,
  "artifact": "tc06-rules-vectors",
  "profile": "compiler-object-v1",
  "target": {"triple": "bpfeb-unknown-none", "arch": "bpfeb", "endian": "big", "pointer_width_bits": 64},
  "backend": {"kind": "llvm-llc", "name": "llc", "version": "21.1.8", "sha256": "935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382"},
  "cpu": "generic",
  "features_enabled": [],
  "features_disabled": [],
  "required_cells": ["kernel-6.12-x86_64-verifier"],
  "optional_cells": []
}"#;
    ObjectContract::from_json(json.as_bytes(), &limits()).expect("big-endian contract")
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn rule_ids(violations: &[RuleViolation]) -> Vec<&str> {
    violations
        .iter()
        .map(|violation| violation.rule_id.as_str())
        .collect()
}

fn load_manifest(name: &str) -> VerifierRules {
    let bytes = repo_bytes(&format!("tools/bpf-compat/profiles/{name}.json"));
    VerifierRules::from_json(&bytes, &limits())
        .unwrap_or_else(|error| panic!("admit {name}: {error}"))
}

fn load_allowlist() -> PruneAllowlist {
    let bytes = repo_bytes("fixtures/bpf/object-graph/dead-builtins/allowlist.json");
    PruneAllowlist::from_json(&bytes, &limits()).expect("admit prune allowlist")
}

/// Relocation types (docs.kernel.org/bpf/llvm_reloc.html, donor-cited URL).
const R_BPF_64_64: u32 = 1;
const R_BPF_64_32: u32 = 10;

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_REL: u32 = 9;
const SHF_EXECINSTR: u64 = 0x4;

const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STB_GLOBAL: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, value: u16) -> [u8; 2] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    fn u32(self, value: u32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    fn u64(self, value: u64) -> [u8; 8] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    fn i16(self, value: i16) -> [u8; 2] {
        self.u16(value as u16)
    }

    fn i32(self, value: i32) -> [u8; 4] {
        self.u32(value as u32)
    }
}

/// Minimal synthetic ELF64 BPF relocatable builder.
///
/// Sections are appended in push order (index 0 is always null); symtab,
/// strtab and shstrtab are synthesized by [`ObjBuilder::build`]. Reloc
/// sections carry caller-chosen names and targets.
struct ObjBuilder {
    endian: Endian,
    sections: Vec<RawSection>,
    syms: Vec<RawSym>,
}

struct RawSection {
    name: String,
    shtype: u32,
    flags: u64,
    data: Vec<u8>,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

struct RawSym {
    name: String,
    info: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

impl ObjBuilder {
    fn new(endian: Endian) -> Self {
        Self {
            endian,
            sections: vec![RawSection {
                name: String::new(),
                shtype: 0,
                flags: 0,
                data: Vec::new(),
                link: 0,
                info: 0,
                align: 0,
                entsize: 0,
            }],
            syms: vec![RawSym {
                name: String::new(),
                info: 0,
                shndx: 0,
                value: 0,
                size: 0,
            }],
        }
    }

    fn little() -> Self {
        Self::new(Endian::Little)
    }

    fn section(&mut self, name: &str, shtype: u32, flags: u64, data: Vec<u8>) -> usize {
        self.sections.push(RawSection {
            name: name.to_owned(),
            shtype,
            flags,
            data,
            link: 0,
            info: 0,
            align: 8,
            entsize: 0,
        });
        self.sections.len() - 1
    }

    fn symbol(&mut self, name: &str, info: u8, shndx: u16, value: u64, size: u64) -> u32 {
        self.syms.push(RawSym {
            name: name.to_owned(),
            info,
            shndx,
            value,
            size,
        });
        (self.syms.len() - 1) as u32
    }

    fn func(&mut self, name: &str, global: bool, shndx: usize, value: u64, size: u64) -> u32 {
        let bind = if global { STB_GLOBAL } else { 0 };
        self.symbol(name, (bind << 4) | STT_FUNC, shndx as u16, value, size)
    }

    fn reloc_section(&mut self, name: &str, target: usize, entries: &[(u64, u32, u32)]) -> usize {
        let mut data = Vec::with_capacity(entries.len() * 16);
        for (offset, sym, rtype) in entries {
            data.extend_from_slice(&self.endian.u64(*offset));
            let info = ((*sym as u64) << 32) | (*rtype as u64);
            data.extend_from_slice(&self.endian.u64(info));
        }
        let index = self.section(name, SHT_REL, 0, data);
        self.sections[index].info = target as u32;
        self.sections[index].entsize = 16;
        index
    }

    fn build(mut self) -> Vec<u8> {
        let endian = self.endian;
        let mut strtab = vec![0u8];
        let mut name_off = Vec::with_capacity(self.syms.len());
        for sym in &self.syms {
            name_off.push(strtab.len() as u32);
            strtab.extend_from_slice(sym.name.as_bytes());
            strtab.push(0);
        }
        let mut symtab = Vec::with_capacity(self.syms.len() * 24);
        for (sym, off) in self.syms.iter().zip(name_off) {
            symtab.extend_from_slice(&endian.u32(off));
            symtab.push(sym.info);
            symtab.push(0);
            symtab.extend_from_slice(&endian.u16(sym.shndx));
            symtab.extend_from_slice(&endian.u64(sym.value));
            symtab.extend_from_slice(&endian.u64(sym.size));
        }
        let symtab_index = self.sections.len();
        self.sections.push(RawSection {
            name: ".symtab".to_owned(),
            shtype: SHT_SYMTAB,
            flags: 0,
            data: symtab,
            link: 0,
            info: 1,
            align: 8,
            entsize: 24,
        });
        let strtab_index = self.sections.len();
        self.sections.push(RawSection {
            name: ".strtab".to_owned(),
            shtype: SHT_STRTAB,
            flags: 0,
            data: strtab,
            link: 0,
            info: 0,
            align: 1,
            entsize: 0,
        });
        self.sections[symtab_index].link = strtab_index as u32;
        let mut shstrtab = vec![0u8];
        let mut sh_name_off = Vec::with_capacity(self.sections.len() + 1);
        sh_name_off.push(0);
        for section in self.sections.iter().skip(1) {
            sh_name_off.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(section.name.as_bytes());
            shstrtab.push(0);
        }
        sh_name_off.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(b".shstrtab");
        shstrtab.push(0);
        let shstrtab_index = self.sections.len();
        self.sections.push(RawSection {
            name: ".shstrtab".to_owned(),
            shtype: SHT_STRTAB,
            flags: 0,
            data: shstrtab,
            link: 0,
            info: 0,
            align: 1,
            entsize: 0,
        });
        let rel_sections: Vec<usize> = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, section)| section.shtype == SHT_REL)
            .map(|(index, _)| index)
            .collect();
        for index in rel_sections {
            self.sections[index].link = symtab_index as u32;
        }

        let mut out = vec![0u8; 64];
        out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2;
        out[5] = match endian {
            Endian::Little => 1,
            Endian::Big => 2,
        };
        out[6] = 1;
        out[0x10..0x12].copy_from_slice(&endian.u16(1));
        out[0x12..0x14].copy_from_slice(&endian.u16(247));
        out[0x14..0x18].copy_from_slice(&endian.u32(1));
        out[0x3a..0x3c].copy_from_slice(&endian.u16(64));
        out[0x3c..0x3e].copy_from_slice(&endian.u16(self.sections.len() as u16));
        out[0x3e..0x40].copy_from_slice(&endian.u16(shstrtab_index as u16));
        let mut offset = 64u64;
        let mut body_off = Vec::with_capacity(self.sections.len());
        body_off.push(0);
        for section in self.sections.iter().skip(1) {
            body_off.push(offset);
            offset += section.data.len() as u64;
            out.extend_from_slice(&section.data);
        }
        let shoff = out.len() as u64;
        out[0x28..0x30].copy_from_slice(&endian.u64(shoff));
        for (index, section) in self.sections.iter().enumerate() {
            let mut header = [0u8; 64];
            header[0..4].copy_from_slice(&endian.u32(sh_name_off[index]));
            header[4..8].copy_from_slice(&endian.u32(section.shtype));
            header[8..16].copy_from_slice(&endian.u64(section.flags));
            header[24..32].copy_from_slice(&endian.u64(body_off[index]));
            header[32..40].copy_from_slice(&endian.u64(section.data.len() as u64));
            header[40..44].copy_from_slice(&endian.u32(section.link));
            header[44..48].copy_from_slice(&endian.u32(section.info));
            header[48..56].copy_from_slice(&endian.u64(section.align));
            header[56..64].copy_from_slice(&endian.u64(section.entsize));
            out.extend_from_slice(&header);
        }
        out
    }
}

/// One 8-byte instruction slot in the selected endianness.
fn insn(endian: Endian, code: u8, regs: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut slot = [0u8; 8];
    slot[0] = code;
    slot[1] = regs;
    slot[2..4].copy_from_slice(&endian.i16(off));
    slot[4..8].copy_from_slice(&endian.i32(imm));
    slot
}

fn exit(endian: Endian) -> [u8; 8] {
    insn(endian, 0x95, 0, 0, 0)
}

fn call_sub(endian: Endian, imm: i32) -> [u8; 8] {
    insn(endian, 0x85, 0x10, 0, imm)
}

fn call_helper(endian: Endian, id: i32) -> [u8; 8] {
    insn(endian, 0x85, 0x00, 0, id)
}

fn mov32_r3(endian: Endian, imm: i32) -> [u8; 8] {
    insn(endian, 0xB4, 0x03, 0, imm)
}

/// `ld_imm64` wide load: two slots, second slot zero.
fn ldimm64(endian: Endian, dst: u8, imm: i32) -> [u8; 16] {
    let mut wide = [0u8; 16];
    wide[0..8].copy_from_slice(&insn(endian, 0x18, dst, 0, imm));
    wide
}

/// `stxw [r10+off], rsrc`: touches the frame so the function is provably
/// not stackless.
fn stxw_frame(endian: Endian, src: u8, off: i16) -> [u8; 8] {
    insn(endian, 0x63, 0x0A | (src << 4), off, 0)
}

/// Minimal hand-encoded BTF image builder.
///
/// Types are appended in order (ids run 1-based); strings are appended
/// with a leading empty string. The encoding follows the kernel BTF
/// layout the locked parser admits; every test image must parse.
struct BtfBuilder {
    types: Vec<u8>,
    strings: Vec<u8>,
    count: u32,
}

impl BtfBuilder {
    fn new() -> Self {
        Self {
            types: Vec::new(),
            strings: vec![0],
            count: 0,
        }
    }

    fn str_off(&mut self, text: &str) -> u32 {
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(text.as_bytes());
        self.strings.push(0);
        off
    }

    fn push_record(&mut self, name_off: u32, kind: u32, vlen: u32, size_or_type: u32) -> u32 {
        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types
            .extend_from_slice(&((kind << 24) | vlen).to_le_bytes());
        self.types.extend_from_slice(&size_or_type.to_le_bytes());
        self.count += 1;
        self.count
    }

    fn add_int(&mut self, name: &str, size: u32, bits: u32, encoding: u32) -> u32 {
        let name_off = self.str_off(name);
        let id = self.push_record(name_off, 1, 0, size);
        let data = bits | encoding << 24;
        self.types.extend_from_slice(&data.to_le_bytes());
        id
    }

    fn add_array(&mut self, elem: u32, index: u32, nelems: u32) -> u32 {
        let id = self.push_record(0, 3, 0, 0);
        self.types.extend_from_slice(&elem.to_le_bytes());
        self.types.extend_from_slice(&index.to_le_bytes());
        self.types.extend_from_slice(&nelems.to_le_bytes());
        id
    }

    fn add_struct(&mut self, name: &str, size: u32, members: &[(&str, u32, u32)]) -> u32 {
        let name_off = self.str_off(name);
        let id = self.push_record(name_off, 4, members.len() as u32, size);
        for (member, ty, bit_off) in members {
            let member_off = self.str_off(member);
            self.types.extend_from_slice(&member_off.to_le_bytes());
            self.types.extend_from_slice(&ty.to_le_bytes());
            self.types.extend_from_slice(&bit_off.to_le_bytes());
        }
        id
    }

    fn add_ptr(&mut self, to: u32) -> u32 {
        self.push_record(0, 2, 0, to)
    }

    fn add_proto(&mut self, ret: u32, params: &[(&str, u32)]) -> u32 {
        let id = self.push_record(0, 13, params.len() as u32, ret);
        for (name, ty) in params {
            let name_off = if name.is_empty() {
                0
            } else {
                self.str_off(name)
            };
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&ty.to_le_bytes());
        }
        id
    }

    fn add_func(&mut self, name: &str, proto: u32) -> u32 {
        // GLOBAL linkage (vlen 1): the default for named interface
        // functions; STATIC twins use add_func_static (F21).
        let name_off = self.str_off(name);
        self.push_record(name_off, 12, 1, proto)
    }

    fn add_func_static(&mut self, name: &str, proto: u32) -> u32 {
        let name_off = self.str_off(name);
        self.push_record(name_off, 12, 0, proto)
    }

    fn build(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xEB9Fu16.to_le_bytes());
        out.push(1);
        out.push(0);
        out.extend_from_slice(&24u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.types);
        out.extend_from_slice(&self.strings);
        out
    }
}

/// `SelectionTransport`-shaped struct: three u64, four bytes, named `_pad`.
/// `pad: None` emits the size-only mutant (same size, no `_pad` member).
fn selection_btf(pad_offset: Option<u32>) -> Vec<u8> {
    let mut btf = BtfBuilder::new();
    let u64_ty = btf.add_int("unsigned long", 8, 64, 0);
    let u8_ty = btf.add_int("unsigned char", 1, 8, 0);
    let u32_ty = btf.add_int("unsigned int", 4, 32, 0);
    let pad_ty = btf.add_array(u8_ty, u32_ty, 4);
    let mut members = vec![
        ("request_flags", u64_ty, 0),
        ("binding_id", u64_ty, 64),
        ("return_rv", u64_ty, 128),
        ("request_name_class", u8_ty, 192),
        ("request_version_class", u8_ty, 200),
        ("pause_eligible", u8_ty, 208),
        ("word_bytes", u8_ty, 216),
    ];
    if let Some(off) = pad_offset {
        members.push(("_pad", pad_ty, off * 8));
    }
    btf.add_struct("SelectionTransport", 32, &members);
    btf.build()
}

/// `.text` + entry-section fixture: `funcs` tile `.text` in order, the
/// entry program in `uprobe` calls each name in `roots` by relocation.
fn prune_fixture(endian: Endian, funcs: &[(&str, usize)], roots: &[&str]) -> (Vec<u8>, Vec<u32>) {
    let mut obj = ObjBuilder::new(endian);
    let mut text = Vec::new();
    let mut offsets = Vec::new();
    for (_, slots) in funcs {
        offsets.push(text.len());
        for _ in 0..*slots {
            text.extend_from_slice(&exit(endian));
        }
    }
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    for _ in roots {
        entry.extend_from_slice(&call_sub(endian, -1));
    }
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    obj.symbol(".text", STT_SECTION, text_idx as u16, 0, 0);
    let mut func_syms = Vec::new();
    for ((name, _), off) in funcs.iter().zip(&offsets) {
        let size = funcs
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, slots)| *slots * 8)
            .unwrap_or(0);
        func_syms.push(obj.func(name, true, text_idx, *off as u64, size as u64));
    }
    let entry_len = roots.len() as u64 * 8 + 8;
    obj.func("entry", true, uprobe_idx, 0, entry_len);
    let mut relocs = Vec::new();
    for (slot, root) in roots.iter().enumerate() {
        let sym = funcs
            .iter()
            .zip(&func_syms)
            .find(|((name, _), _)| name == root)
            .map(|(_, sym)| *sym)
            .unwrap_or_else(|| panic!("root {root} is not a .text function"));
        relocs.push((slot as u64 * 8, sym, R_BPF_64_32));
    }
    obj.reloc_section(".reluprobe", uprobe_idx, &relocs);
    (obj.build(), func_syms)
}

#[test]
fn dead_memset_is_stripped_and_live_root_remains() {
    let (obj, _) = prune_fixture(Endian::Little, &[("live", 2), ("memset", 1)], &["live"]);
    let allow = load_allowlist();
    let (out, report) =
        prune_dead_code_with_report(&obj, &contract(), &allow, &limits()).expect("prune");
    assert_eq!(report.removed(), &["memset".to_owned()]);
    assert_eq!((report.text_before(), report.text_after()), (24, 16));
    assert_eq!(report.original_sha256(), &digest(&obj));
    assert_eq!(report.output_sha256(), &digest(&out));
    assert_ne!(report.original_sha256(), report.output_sha256());
    // The stripped object re-admits: re-parse proves the rewrite is whole.
    let (out2, report2) =
        prune_dead_code_with_report(&out, &contract(), &allow, &limits()).expect("re-prune");
    assert!(report2.removed().is_empty());
    assert_eq!(out2, out);
    assert_eq!(report2.original_sha256(), report2.output_sha256());
}

#[test]
fn all_three_dead_builtins_are_stripped() {
    let (obj, _) = prune_fixture(
        Endian::Little,
        &[("live", 1), ("memcpy", 1), ("memmove", 1), ("memset", 1)],
        &["live"],
    );
    let allow = load_allowlist();
    let (out, report) =
        prune_dead_code_with_report(&obj, &contract(), &allow, &limits()).expect("prune");
    assert_eq!(
        report.removed(),
        &[
            "memcpy".to_owned(),
            "memmove".to_owned(),
            "memset".to_owned()
        ]
    );
    assert_eq!((report.text_before(), report.text_after()), (32, 8));
    assert_eq!(report.output_sha256(), &digest(&out));
}

#[test]
fn live_builtin_call_is_never_stripped() {
    // `live` calls `memset` by relocation: nothing is dead, bytes identical.
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&call_sub(endian, -1));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let live = obj.func("live", true, text_idx, 0, 16);
    let memset = obj.func("memset", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    obj.reloc_section(".rel.text", text_idx, &[(0, memset, R_BPF_64_32)]);
    let bytes = obj.build();
    let allow = load_allowlist();
    let (out, report) =
        prune_dead_code_with_report(&bytes, &contract(), &allow, &limits()).expect("prune");
    assert!(report.removed().is_empty());
    assert_eq!(out, bytes);
}

#[test]
fn dead_reloc_is_dropped_and_live_reloc_is_remapped() {
    // Map fixups at .text+0 (live) and .text+16 (dead): the dead entry is
    // dropped, the live entry keeps its symbol and offset.
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&ldimm64(endian, 1, 0));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let maps_idx = obj.section(".maps", SHT_PROGBITS, 0, vec![0u8; 32]);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let live = obj.func("live", true, text_idx, 0, 16);
    obj.func("memset", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    let map = obj.symbol(
        "NATIVE",
        (STB_GLOBAL << 4) | STT_OBJECT,
        maps_idx as u16,
        0,
        32,
    );
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    obj.reloc_section(
        ".rel.text",
        text_idx,
        &[(0, map, R_BPF_64_64), (16, map, R_BPF_64_64)],
    );
    let bytes = obj.build();
    let allow = load_allowlist();
    let (out, report) =
        prune_dead_code_with_report(&bytes, &contract(), &allow, &limits()).expect("prune");
    assert_eq!(report.removed(), &["memset".to_owned()]);
    // Exactly one map fixup survives, still against the live slot.
    let survivors = count_relocs(&out, R_BPF_64_64);
    assert_eq!(survivors, vec![(0u64, "NATIVE".to_owned())]);
}

/// Collect `(offset, symbol-name)` rows for one reloc type across every
/// REL section of a little-endian test object.
fn count_relocs(bytes: &[u8], want: u32) -> Vec<(u64, String)> {
    let shoff = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(bytes[0x3c..0x3e].try_into().unwrap()) as usize;
    let mut sym_names = Vec::new();
    let mut sym_off = 0usize;
    let mut sym_len = 0usize;
    let mut str_off = 0usize;
    for index in 0..shnum {
        let header = &bytes[shoff + index * 64..shoff + (index + 1) * 64];
        let shtype = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if shtype == SHT_SYMTAB {
            sym_off = u64::from_le_bytes(header[24..32].try_into().unwrap()) as usize;
            sym_len = u64::from_le_bytes(header[32..40].try_into().unwrap()) as usize;
            let link = u32::from_le_bytes(header[40..44].try_into().unwrap()) as usize;
            let str_header = &bytes[shoff + link * 64..shoff + (link + 1) * 64];
            str_off = u64::from_le_bytes(str_header[24..32].try_into().unwrap()) as usize;
        }
    }
    for entry in bytes[sym_off..sym_off + sym_len].chunks_exact(24) {
        let name = u32::from_le_bytes(entry[0..4].try_into().unwrap()) as usize;
        let end = bytes[str_off + name..]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap();
        sym_names
            .push(String::from_utf8(bytes[str_off + name..str_off + name + end].to_vec()).unwrap());
    }
    let mut rows = Vec::new();
    for index in 0..shnum {
        let header = &bytes[shoff + index * 64..shoff + (index + 1) * 64];
        if u32::from_le_bytes(header[4..8].try_into().unwrap()) != SHT_REL {
            continue;
        }
        let off = u64::from_le_bytes(header[24..32].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(header[32..40].try_into().unwrap()) as usize;
        for entry in bytes[off..off + len].chunks_exact(16) {
            let offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
            let info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            if (info & 0xffff_ffff) as u32 == want {
                rows.push((offset, sym_names[(info >> 32) as usize].clone()));
            }
        }
    }
    rows.sort();
    rows
}

#[test]
fn prune_uses_frozen_inventory_without_allowlist_argument() {
    assert_eq!(FROZEN_DEAD_BUILTINS, &["memcpy", "memmove", "memset"]);
    let (obj, _) = prune_fixture(Endian::Little, &[("live", 2), ("memmove", 1)], &["live"]);
    let out = prune_dead_code(&obj, &contract(), &limits()).expect("plan-exact prune");
    let (out2, report) = prune_dead_code_with_report(
        &obj,
        &contract(),
        &PruneAllowlist::frozen_builtins(),
        &limits(),
    )
    .expect("explicit frozen prune");
    assert_eq!(out, out2);
    assert_eq!(report.removed(), &["memmove".to_owned()]);
}

#[test]
fn prune_accepts_big_endian_objects() {
    let (obj, _) = prune_fixture(Endian::Big, &[("live", 2), ("memset", 1)], &["live"]);
    let allow = load_allowlist();
    let (out, report) =
        prune_dead_code_with_report(&obj, &contract_big(), &allow, &limits()).expect("prune");
    assert_eq!(report.removed(), &["memset".to_owned()]);
    assert_eq!((report.text_before(), report.text_after()), (24, 16));
    assert_eq!(report.output_sha256(), &digest(&out));
}

#[test]
fn prune_preserves_btf_without_removed_names() {
    let endian = Endian::Little;
    let mut text = Vec::new();
    for _ in 0..2 {
        text.extend_from_slice(&exit(endian));
    }
    text.extend_from_slice(&exit(endian));
    let mut builder = ObjBuilder::little();
    let text_idx = builder.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = builder.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    builder.section(".BTF", SHT_PROGBITS, 0, selection_btf(Some(28)));
    let live = builder.func("live", true, text_idx, 0, 16);
    builder.func("memcpy", true, text_idx, 16, 8);
    builder.func("entry", true, uprobe_idx, 0, 16);
    builder.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    let bytes = builder.build();
    let allow = load_allowlist();
    let (out, report) =
        prune_dead_code_with_report(&bytes, &contract(), &allow, &limits()).expect("prune");
    assert_eq!(report.removed(), &["memcpy".to_owned()]);
    // The .BTF body survives byte-identical: the repair never rewrites it.
    assert!(contains_slice(&out, &selection_btf(Some(28))));
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn named_pad_record_survives_repair_byte_identical() {
    // A 32-byte transport record with a named `_pad` member lives in
    // .rodata; the repair touches .text/symtab/relocs only, so the record
    // (including the 4 pad bytes) survives byte-identical. This is a
    // shape-preservation test: it does not prove emitted stores
    // initialize the pad (F24 stays open in TODO).
    let endian = Endian::Little;
    let mut text = Vec::new();
    for _ in 0..2 {
        text.extend_from_slice(&exit(endian));
    }
    text.extend_from_slice(&exit(endian));
    let mut record = vec![0xA5u8; 28];
    record.extend_from_slice(&[0u8; 4]);
    let mut builder = ObjBuilder::little();
    let text_idx = builder.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    builder.section(".rodata", SHT_PROGBITS, 0, record.clone());
    builder.section(".BTF", SHT_PROGBITS, 0, selection_btf(Some(28)));
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = builder.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let live = builder.func("live", true, text_idx, 0, 16);
    builder.func("memset", true, text_idx, 16, 8);
    builder.func("entry", true, uprobe_idx, 0, 16);
    builder.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    let bytes = builder.build();
    let allow = load_allowlist();
    let (out, report) =
        prune_dead_code_with_report(&bytes, &contract(), &allow, &limits()).expect("prune");
    assert_eq!(report.removed(), &["memset".to_owned()]);
    assert!(contains_slice(&out, &record));
    let padding = load_manifest("padding");
    let btf = parse_btf(&selection_btf(Some(28)));
    let violations = check_verifier_rules(&out, &contract(), &[padding], Some(&btf), &limits())
        .expect("recheck padding");
    assert!(violations.is_empty(), "unexpected: {violations:?}");
}

fn prune_error(bytes: &[u8], allow: &PruneAllowlist, limits: &Limits) -> OperationError {
    prune_dead_code_with_report(bytes, &contract(), allow, limits).expect_err("repair must refuse")
}

#[test]
fn repeated_long_names_hit_retained_ceiling() {
    // F12: every cloned symbol name accounts against the cumulative
    // retained ceiling. A ceiling just above the input size refuses,
    // while the generous ceiling admits the same object.
    let endian = Endian::Little;
    let mut obj = ObjBuilder::little();
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let live = obj.func("live", true, text_idx, 0, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    let filler = format!("filler-{}", "x".repeat(200));
    for _ in 0..1000 {
        obj.symbol(&filler, 0, 0, 0, 0);
    }
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    let bytes = obj.build();
    assert!(bytes.len() < (1 << 20), "fixture must fit input_bytes");
    let mut tight = limits();
    tight.retained_bytes = bytes.len() + 1024;
    let error = prune_error(&bytes, &load_allowlist(), &tight);
    assert_eq!(error.kind(), ErrorKind::LimitExceeded);
    assert_eq!(error.stage(), Stage::Inspect);
    let (out, report) =
        prune_dead_code_with_report(&bytes, &contract(), &load_allowlist(), &limits())
            .expect("generous ceiling admits");
    assert!(report.removed().is_empty());
    assert_eq!(out, bytes);
}

fn assert_refusal(error: &OperationError, kind: ErrorKind, stage: Stage, fragment: &str) {
    // OperationError display never formats its source, so semantic
    // assertions traverse to it explicitly (TC05 precedent).
    let text = error
        .source()
        .map(|source| source.to_string())
        .unwrap_or_default();
    assert_eq!(error.kind(), kind, "kind for {text:?}");
    assert_eq!(error.stage(), stage, "stage for {text:?}");
    assert!(
        text.contains(fragment),
        "message {text:?} must name {fragment:?}"
    );
}

#[test]
fn dead_code_outside_allowlist_refuses_repair() {
    let (obj, _) = prune_fixture(
        Endian::Little,
        &[("live", 2), ("dead_helper", 1)],
        &["live"],
    );
    let error = prune_error(&obj, &load_allowlist(), &limits());
    assert_refusal(&error, ErrorKind::Unsupported, Stage::Inspect, "allowlist");
    // A narrowed allowlist refuses the same way: `memset` dead but unlisted.
    let (obj, _) = prune_fixture(Endian::Little, &[("live", 2), ("memset", 1)], &["live"]);
    let narrow = PruneAllowlist::from_json(
        br#"{"schema_version": 1, "kind": "tc06_prune_allowlist", "names": ["memcpy"]}"#,
        &limits(),
    )
    .expect("narrow allowlist");
    let error = prune_error(&obj, &narrow, &limits());
    assert_refusal(&error, ErrorKind::Unsupported, Stage::Inspect, "allowlist");
}

#[test]
fn unknown_allowlist_entries_refuse_at_admission() {
    let error = PruneAllowlist::from_json(
        br#"{"schema_version": 1, "kind": "tc06_prune_allowlist", "names": ["memset", "helper"]}"#,
        &limits(),
    )
    .expect_err("unknown entry must refuse");
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Admission,
        "allowlist",
    );
    let error = PruneAllowlist::from_json(
        br#"{"schema_version": 1, "kind": "tc06_prune_allowlist", "names": ["memset", "memset"]}"#,
        &limits(),
    )
    .expect_err("duplicate entry must refuse");
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Admission,
        "duplicate",
    );
}

#[test]
fn disable_memory_builtins_flag_is_not_proof() {
    // The repair decides from bytes only. A manifest smuggling the
    // compiler flag in as evidence refuses at admission: the flag stops
    // injection, not retention, of linker-pulled builtins (donor pins.md).
    let error = PruneAllowlist::from_json(
        br#"{"schema_version": 1, "kind": "tc06_prune_allowlist", "names": ["memset"], "disable_memory_builtins": true}"#,
        &limits(),
    )
    .expect_err("flag field must refuse");
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Admission,
        "unknown field",
    );
    // And presence alone still repairs: dead builtins are found even when
    // nothing declares how they were built.
    let (obj, _) = prune_fixture(Endian::Little, &[("live", 2), ("memset", 1)], &["live"]);
    let (out, report) =
        prune_dead_code_with_report(&obj, &contract(), &load_allowlist(), &limits())
            .expect("presence-based repair");
    assert_eq!(report.removed(), &["memset".to_owned()]);
    assert_ne!(digest(&out), digest(&obj));
}

#[test]
fn shifted_entry_target_refuses_repair() {
    // Dead first, entry targets live@8: stripping would move the root.
    let (obj, _) = prune_fixture(Endian::Little, &[("memset", 1), ("live", 2)], &["live"]);
    let error = prune_error(&obj, &load_allowlist(), &limits());
    assert_refusal(&error, ErrorKind::InvalidInput, Stage::Inspect, "shifted");
}

#[test]
fn interior_call_target_refuses_repair() {
    // Entry relocation resolves 8 bytes inside `live`, not at a start.
    // Loader call semantics (F01): a section-symbol call adds (imm + 1)
    // slots, so imm 0 against `.text` lands at byte 8, the interior of
    // `live@0..16`.
    let endian = Endian::Little;
    let mut obj = ObjBuilder::little();
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, 0));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let text_sym = obj.symbol(".text", STT_SECTION, text_idx as u16, 0, 0);
    obj.func("live", true, text_idx, 0, 16);
    obj.func("memset", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, text_sym, R_BPF_64_32)]);
    let bytes = obj.build();
    let error = prune_error(&bytes, &load_allowlist(), &limits());
    assert_refusal(&error, ErrorKind::InvalidInput, Stage::Inspect, "inside");
}

#[test]
fn section_symbol_call_resolves_loader_slots() {
    // F01 twin: a section-symbol call with imm 0 resolves to byte 8
    // (value + (0 + 1) * 8), the live `memset`, not byte 0. The
    // unreachable trailing builtin is stripped; the section-called
    // `memset` stays live. Under the old byte addend the call resolved
    // to byte 0 and the live `memset` was stripped instead.
    let endian = Endian::Little;
    let mut obj = ObjBuilder::little();
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&call_sub(endian, 0));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let text_sym = obj.symbol(".text", STT_SECTION, text_idx as u16, 0, 0);
    let live = obj.func("live", true, text_idx, 0, 8);
    obj.func("memset", true, text_idx, 8, 8);
    obj.func("memcpy", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 24);
    obj.reloc_section(
        ".reluprobe",
        uprobe_idx,
        &[(0, live, R_BPF_64_32), (8, text_sym, R_BPF_64_32)],
    );
    let bytes = obj.build();
    let (out, report) =
        prune_dead_code_with_report(&bytes, &contract(), &load_allowlist(), &limits())
            .expect("section-called memset prunes");
    assert_eq!(report.removed(), &["memcpy".to_owned()]);
    assert_eq!((report.text_before(), report.text_after()), (24, 16));
    assert_eq!(report.output_sha256(), &digest(&out));
}

#[test]
fn shifted_section_call_dest_refuses_repair() {
    // R01: an intra-text section-symbol call whose callee shifts must
    // refuse. `live`@0 calls `memset`@16 through `.text` (imm 1 ->
    // byte 16); dead `memcpy`@8 strips, moving `memset` to 8 while the
    // immediate still says 16 (the new EOF). Neither rewrite pass
    // touches call immediates, so success would retarget the call
    // into stripped slack. Old code succeeded here.
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&call_sub(endian, 1));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let text_sym = obj.symbol(".text", STT_SECTION, text_idx as u16, 0, 0);
    let live = obj.func("live", true, text_idx, 0, 8);
    obj.func("memcpy", true, text_idx, 8, 8);
    obj.func("memset", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    obj.reloc_section(".rel.text", text_idx, &[(0, text_sym, R_BPF_64_32)]);
    let bytes = obj.build();
    let error = prune_error(&bytes, &load_allowlist(), &limits());
    assert_refusal(&error, ErrorKind::InvalidInput, Stage::Inspect, "shifted");
}

#[test]
fn stationary_section_call_dest_survives_repair() {
    // R01 guard twin: the same intra-text section-symbol call with a
    // STATIONARY callee prunes fine (dead code strips from the end, no
    // shift), and the transformed call graph keeps the live->memset
    // edge: no over-refusal, no silent retarget.
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&call_sub(endian, 0));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let text_sym = obj.symbol(".text", STT_SECTION, text_idx as u16, 0, 0);
    let live = obj.func("live", true, text_idx, 0, 8);
    obj.func("memset", true, text_idx, 8, 8);
    obj.func("memcpy", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    obj.reloc_section(".rel.text", text_idx, &[(0, text_sym, R_BPF_64_32)]);
    let bytes = obj.build();
    let (out, report) =
        prune_dead_code_with_report(&bytes, &contract(), &load_allowlist(), &limits())
            .expect("stationary section call prunes");
    assert_eq!(report.removed(), &["memcpy".to_owned()]);
    assert_eq!((report.text_before(), report.text_after()), (24, 16));
    let graph = extract_call_graph(&out, &contract(), &limits()).expect("graph extracts");
    let names: Vec<&str> = graph.functions().iter().map(|f| f.name()).collect();
    assert!(
        names.contains(&"live") && names.contains(&"memset"),
        "both ends survive: {names:?}"
    );
    let live_idx = names.iter().position(|n| *n == "live").unwrap();
    let memset_idx = names.iter().position(|n| *n == "memset").unwrap();
    assert!(
        graph.edges().iter().any(|e| {
            e.caller() == live_idx
                && matches!(e.target(), CallTarget::Local { function } if function == memset_idx)
        }),
        "live->memset edge survives the strip: {:?}",
        graph.edges()
    );
}

#[test]
fn call_into_stripped_code_refuses_repair() {
    // Dead `memset` calls dead `memcpy`: resolving the strip would orphan
    // the dead-to-dead edge, so the repair refuses instead of guessing.
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&call_sub(endian, -1));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let live = obj.func("live", true, text_idx, 0, 16);
    obj.func("memset", true, text_idx, 16, 8);
    let memcpy = obj.func("memcpy", true, text_idx, 24, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    obj.reloc_section(".rel.text", text_idx, &[(16, memcpy, R_BPF_64_32)]);
    let bytes = obj.build();
    let error = prune_error(&bytes, &load_allowlist(), &limits());
    assert_refusal(&error, ErrorKind::InvalidInput, Stage::Inspect, "stripped");
}

#[test]
fn unrelocated_call_site_refuses_repair() {
    // A linked-style immediate call with no covering relocation targets
    // the dead builtin: reloc-only reachability would misread it as dead
    // and change program semantics, so the repair refuses.
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&call_sub(endian, 1));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let live = obj.func("live", true, text_idx, 0, 16);
    obj.func("memset", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    let bytes = obj.build();
    let error = prune_error(&bytes, &load_allowlist(), &limits());
    assert_refusal(
        &error,
        ErrorKind::Unsupported,
        Stage::Inspect,
        "unrelocated",
    );
    // An unknown call form (0x85 with a reserved source field) hides a
    // potential static edge the same way: refuse, never guess.
    let mut text = Vec::new();
    text.extend_from_slice(&insn(endian, 0x85, 0x20, 0, 0));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let live = obj.func("live", true, text_idx, 0, 16);
    obj.func("memset", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    let bytes = obj.build();
    let error = prune_error(&bytes, &load_allowlist(), &limits());
    assert_refusal(&error, ErrorKind::Unsupported, Stage::Inspect, "call form");
}

#[test]
fn straddling_reloc_pair_refuses_repair() {
    // A map fixup is an 8-byte `ld_imm64` pair: this one starts in live
    // code and ends in dead code, so no consistent rewrite exists.
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&ldimm64(endian, 1, 0));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let maps_idx = obj.section(".maps", SHT_PROGBITS, 0, vec![0u8; 32]);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let live = obj.func("live", true, text_idx, 0, 16);
    obj.func("memset", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    let map = obj.symbol(
        "NATIVE",
        (STB_GLOBAL << 4) | STT_OBJECT,
        maps_idx as u16,
        0,
        32,
    );
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    obj.reloc_section(".rel.text", text_idx, &[(12, map, R_BPF_64_64)]);
    let bytes = obj.build();
    let error = prune_error(&bytes, &load_allowlist(), &limits());
    assert_refusal(&error, ErrorKind::InvalidInput, Stage::Inspect, "straddles");
}

#[test]
fn btf_reloc_against_removed_symbol_refuses_repair() {
    // A relocation inside `.BTF` references the dead builtin by symbol
    // index: no name bytes appear, so only the rewrite-time symbol check
    // catches the dangling reference.
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut builder = ObjBuilder::little();
    let text_idx = builder.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = builder.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let btf_idx = builder.section(".BTF", SHT_PROGBITS, 0, vec![0u8; 32]);
    let live = builder.func("live", true, text_idx, 0, 16);
    let memset = builder.func("memset", true, text_idx, 16, 8);
    builder.func("entry", true, uprobe_idx, 0, 16);
    builder.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    builder.reloc_section(".rel.BTF", btf_idx, &[(0, memset, R_BPF_64_64)]);
    let bytes = builder.build();
    let error = prune_error(&bytes, &load_allowlist(), &limits());
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Inspect,
        "removed symbol",
    );
}

#[test]
fn unsupported_shapes_refuse_repair() {
    let allow = load_allowlist();
    // Unknown relocation type.
    let (obj, _) = prune_fixture(Endian::Little, &[("live", 2), ("memset", 1)], &["live"]);
    let mut unknown = obj.clone();
    corrupt_first_reloc_type(&mut unknown, 99);
    let error = prune_error(&unknown, &allow, &limits());
    assert_refusal(&error, ErrorKind::InvalidInput, Stage::Inspect, "type");
    // RELA sections are never rewritten.
    let mut builder = ObjBuilder::little();
    let text_idx = builder.section(
        ".text",
        SHT_PROGBITS,
        SHF_EXECINSTR,
        vec![0x95, 0, 0, 0, 0, 0, 0, 0],
    );
    builder.section(".rela.text", 4, 0, vec![0u8; 24]);
    builder.func("live", true, text_idx, 0, 8);
    let rela = builder.build();
    let error = prune_error(&rela, &allow, &limits());
    assert_refusal(&error, ErrorKind::Unsupported, Stage::Inspect, "rela");
    // Missing .text: no repair subject.
    let mut builder = ObjBuilder::little();
    builder.section(".data", SHT_PROGBITS, 0, vec![0u8; 8]);
    let no_text = builder.build();
    let error = prune_error(&no_text, &allow, &limits());
    assert_refusal(&error, ErrorKind::InvalidInput, Stage::Inspect, ".text");
    // .BTF naming a removed function: references the repair cannot rewrite.
    let btf_hit = build_with_raw_btf(b"struct memset { int x; }");
    let error = prune_error(&btf_hit, &allow, &limits());
    assert_refusal(&error, ErrorKind::Unsupported, Stage::Inspect, "BTF");
    // .BTF.ext: func_info offsets would shift under the strip.
    let btf_ext = build_with_named_section(".BTF.ext", vec![0u8; 32]);
    let error = prune_error(&btf_ext, &allow, &limits());
    assert_refusal(&error, ErrorKind::Unsupported, Stage::Inspect, "BTF.ext");
}

/// Rewrite the first REL entry's type of the first REL section (LE).
fn corrupt_first_reloc_type(bytes: &mut [u8], rtype: u32) {
    let shoff = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(bytes[0x3c..0x3e].try_into().unwrap()) as usize;
    for index in 0..shnum {
        let header = &bytes[shoff + index * 64..shoff + (index + 1) * 64];
        if u32::from_le_bytes(header[4..8].try_into().unwrap()) != SHT_REL {
            continue;
        }
        let off = u64::from_le_bytes(header[24..32].try_into().unwrap()) as usize;
        let info = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap());
        let patched = (info & !0xffff_ffff) | u64::from(rtype);
        bytes[off + 8..off + 16].copy_from_slice(&patched.to_le_bytes());
        return;
    }
    panic!("no reloc section to corrupt");
}

/// Standard live/memset object plus a raw `.BTF` body.
fn build_with_raw_btf(btf: &[u8]) -> Vec<u8> {
    build_with_named_section(".BTF", btf.to_vec())
}

fn build_with_named_section(name: &str, body: Vec<u8>) -> Vec<u8> {
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut builder = ObjBuilder::little();
    let text_idx = builder.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = builder.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    builder.section(name, SHT_PROGBITS, 0, body);
    let live = builder.func("live", true, text_idx, 0, 16);
    builder.func("memset", true, text_idx, 16, 8);
    builder.func("entry", true, uprobe_idx, 0, 16);
    builder.reloc_section(".reluprobe", uprobe_idx, &[(0, live, R_BPF_64_32)]);
    builder.build()
}

#[test]
fn malformed_inputs_refuse_without_panics() {
    let allow = load_allowlist();
    let (obj, _) = prune_fixture(Endian::Little, &[("live", 2), ("memset", 1)], &["live"]);
    // Truncated file.
    let error = prune_error(&obj[..obj.len() / 2], &allow, &limits());
    assert_refusal(&error, ErrorKind::Malformed, Stage::Inspect, "truncated");
    // Section header past EOF.
    let mut corrupt = obj.clone();
    corrupt_sh_offset(&mut corrupt, 1, 0xffff_ffff);
    let error = prune_error(&corrupt, &allow, &limits());
    assert_refusal(&error, ErrorKind::Malformed, Stage::Inspect, "outside");
    // Misaligned .text length.
    let endian = Endian::Little;
    let mut builder = ObjBuilder::little();
    let text_idx = builder.section(".text", SHT_PROGBITS, SHF_EXECINSTR, vec![0x95u8; 12]);
    builder.func("live", true, text_idx, 0, 12);
    let misaligned = builder.build();
    let error = prune_error(&misaligned, &allow, &limits());
    assert_refusal(&error, ErrorKind::Malformed, Stage::Inspect, "aligned");
    // Tiling gap: functions do not cover .text exactly.
    let mut builder = ObjBuilder::little();
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let text_idx = builder.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    builder.func("live", true, text_idx, 0, 8);
    builder.func("memset", true, text_idx, 16, 8);
    let gapped = builder.build();
    let error = prune_error(&gapped, &allow, &limits());
    assert_refusal(&error, ErrorKind::Malformed, Stage::Inspect, "tiling");
    // No entry root: .text functions nobody calls from outside.
    let mut builder = ObjBuilder::little();
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let text_idx = builder.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    builder.func("live", true, text_idx, 0, 8);
    builder.func("memset", true, text_idx, 8, 8);
    let rootless = builder.build();
    let error = prune_error(&rootless, &allow, &limits());
    assert_refusal(&error, ErrorKind::InvalidInput, Stage::Inspect, "entry");
}

/// Overwrite section `idx`'s `sh_offset` (hostile-fixture helper, LE).
fn corrupt_sh_offset(obj: &mut [u8], idx: usize, off: u64) {
    let shoff = u64::from_le_bytes(obj[0x28..0x30].try_into().unwrap()) as usize;
    obj[shoff + idx * 64 + 24..shoff + idx * 64 + 32].copy_from_slice(&off.to_le_bytes());
}

#[test]
fn prune_respects_work_budget() {
    let (obj, _) = prune_fixture(Endian::Little, &[("live", 2), ("memset", 1)], &["live"]);
    let error = prune_error(&obj, &load_allowlist(), &tiny_limits(3));
    assert_refusal(&error, ErrorKind::LimitExceeded, Stage::Inspect, "");
}

#[test]
fn shipped_manifests_admit_strictly() {
    let padding = load_manifest("padding");
    assert_eq!(padding.name(), "padding");
    assert_eq!(padding.version(), "1");
    assert_eq!(padding.len(), 1);
    assert!(!padding.is_empty());
    let linkage = load_manifest("linkage");
    assert_eq!((linkage.name(), linkage.len()), ("linkage", 1));
    let stack = load_manifest("stack");
    assert_eq!((stack.name(), stack.len()), ("stack", 4));
    let private = load_manifest("private-stack");
    assert_eq!((private.name(), private.len()), ("private-stack", 1));
    let allow = load_allowlist();
    assert_eq!(
        allow.names(),
        &[
            "memcpy".to_owned(),
            "memmove".to_owned(),
            "memset".to_owned()
        ]
    );
}

#[test]
fn manifest_admission_refuses_lax_documents() {
    let good = repo_bytes("tools/bpf-compat/profiles/padding.json");
    let text = String::from_utf8(good).unwrap();
    // Unknown field.
    let bad = text.replace(r#""version": "1""#, r#""version": "1", "extra": true"#);
    let error = VerifierRules::from_json(bad.as_bytes(), &limits()).expect_err("unknown field");
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Admission,
        "unknown field",
    );
    // Wrong schema version.
    let bad = text.replace(r#""schema_version": 1"#, r#""schema_version": 2"#);
    let error = VerifierRules::from_json(bad.as_bytes(), &limits()).expect_err("bad version");
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Admission,
        "schema_version",
    );
    // Unknown rule discriminator.
    let bad = text.replace("padding.named-pad-required", "padding.unknown-rule");
    let error = VerifierRules::from_json(bad.as_bytes(), &limits()).expect_err("unknown rule");
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Admission,
        "unknown rule",
    );
    // Duplicate field at the top level.
    let bad = text.replace(r#""version": "1""#, r#""version": "1", "version": "1"#);
    let error = VerifierRules::from_json(bad.as_bytes(), &limits()).expect_err("duplicate field");
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Admission,
        "duplicate",
    );
    // A program array the manifest never declares cannot be referenced.
    let private = repo_bytes("tools/bpf-compat/profiles/private-stack.json");
    let text = String::from_utf8(private).unwrap();
    let bad = text.replace(
        r#""multi_array": "STACK_GUARD""#,
        r#""multi_array": "NOPE""#,
    );
    let error = VerifierRules::from_json(bad.as_bytes(), &limits()).expect_err("undeclared array");
    assert_refusal(
        &error,
        ErrorKind::InvalidInput,
        Stage::Admission,
        "program array",
    );
}

fn check_rules(
    bytes: &[u8],
    manifests: &[VerifierRules],
    btf: Option<&BtfView>,
) -> Vec<RuleViolation> {
    check_verifier_rules(bytes, &contract(), manifests, btf, &limits()).expect("rule check runs")
}

/// Minimal ELF carrier for BTF-only rules: one rooted `.text` function so
/// structural decode succeeds; rule findings come from the BTF view.
fn btf_carrier() -> Vec<u8> {
    prune_fixture(Endian::Little, &[("live", 1)], &["live"]).0
}

#[test]
fn named_padding_passes_and_size_only_mutant_fails() {
    let carrier = btf_carrier();
    let padding = load_manifest("padding");
    // Named `_pad` at the exact extent: clean.
    let btf = parse_btf(&selection_btf(Some(28)));
    let violations = check_rules(&carrier, std::slice::from_ref(&padding), Some(&btf));
    assert!(violations.is_empty(), "unexpected: {violations:?}");
    // Size-only mutant: same 32-byte size, no `_pad` member. A size check
    // alone would pass this; the named-member rule must refuse it.
    let btf = parse_btf(&selection_btf(None));
    let violations = check_rules(&carrier, std::slice::from_ref(&padding), Some(&btf));
    assert_eq!(rule_ids(&violations), ["padding.named-pad-required"]);
    assert_eq!(violations[0].kind, ErrorKind::Incompatible);
    // Wrong-offset mutant: `_pad` exists but not at byte 28.
    let btf = parse_btf(&selection_btf(Some(24)));
    let violations = check_rules(&carrier, std::slice::from_ref(&padding), Some(&btf));
    assert_eq!(rule_ids(&violations), ["padding.named-pad-required"]);
    // Missing type and missing BTF are distinct findings, not passes.
    let mut bare = BtfBuilder::new();
    bare.add_int("unsigned int", 4, 32, 0);
    let btf = parse_btf(&bare.build());
    let violations = check_rules(&carrier, std::slice::from_ref(&padding), Some(&btf));
    assert_eq!(rule_ids(&violations), ["padding.type-missing"]);
    let violations = check_rules(&carrier, std::slice::from_ref(&padding), None);
    assert_eq!(rule_ids(&violations), ["padding.btf-missing"]);
    // Same-name rival struct: ambiguous despite matching size.
    let mut rival = BtfBuilder::new();
    let u32_ty = rival.add_int("unsigned int", 4, 32, 0);
    rival.add_struct("SelectionTransport", 32, &[("x", u32_ty, 0)]);
    rival.add_struct("SelectionTransport", 32, &[("y", u32_ty, 0)]);
    let btf = parse_btf(&rival.build());
    let violations = check_rules(&carrier, &[padding], Some(&btf));
    assert_eq!(rule_ids(&violations), ["padding.type-ambiguous"]);
}

#[test]
fn old_verifier_eacces_counterexample() {
    // The size-only object is the old-verifier EACCES case: 5.15/6.2 refuse
    // the widened stack copy (`invalid read from stack`) while 6.5+ accepts
    // the very same bytes (donor SelectionTransport comment). Errno alone
    // cannot classify this — EACCES without verifier-log or object evidence
    // stays Unknown — so the rule violation below is the classifier input,
    // and live errno-to-cause attribution stays with BP03/TC07 cells.
    let carrier = btf_carrier();
    let padding = load_manifest("padding");
    let btf = parse_btf(&selection_btf(None));
    let violations = check_rules(&carrier, &[padding], Some(&btf));
    assert_eq!(rule_ids(&violations), ["padding.named-pad-required"]);
    // The named-pad twin carries no such evidence: nothing to classify.
    let btf = parse_btf(&selection_btf(Some(28)));
    let padding = load_manifest("padding");
    let violations = check_rules(&carrier, &[padding], Some(&btf));
    assert!(violations.is_empty());
}

/// BTF image with `p11_link_current_identity` FUNC linkage.
/// `variant` selects the clean shape or one linkage mutant.
fn linkage_btf(variant: &str) -> Vec<u8> {
    let mut btf = BtfBuilder::new();
    let u32_ty = btf.add_int("unsigned int", 4, 32, 0);
    let u64_ty = btf.add_int("unsigned long", 8, 64, 0);
    let ptr = btf.add_ptr(u64_ty);
    match variant {
        "clean" | "rival" => {
            let proto = btf.add_proto(u32_ty, &[("out", ptr)]);
            btf.add_func("p11_link_current_identity", proto);
            if variant == "rival" {
                let proto2 = btf.add_proto(u32_ty, &[]);
                btf.add_func("p11_link_current_identity", proto2);
            }
        }
        "bad-proto" => {
            // FUNC with a prototype whose parameter dangles: well-formed
            // kind, malformed body.
            let proto = btf.add_proto(u32_ty, &[("x", 999)]);
            btf.add_func("p11_link_current_identity", proto);
        }
        "static" => {
            // F21 twin: valid GLOBAL ELF symbol but STATIC BTF FUNC.
            let proto = btf.add_proto(u32_ty, &[("out", ptr)]);
            btf.add_func_static("p11_link_current_identity", proto);
        }
        "not-function" => {
            btf.add_struct("p11_link_current_identity", 4, &[("x", u32_ty, 0)]);
        }
        _ => panic!("unknown linkage variant {variant}"),
    }
    btf.build()
}

/// ELF carrier with the linkage symbol in `.text`: rooted, tiled, with an
/// entry call so structural decode succeeds.
fn linkage_carrier(global: bool) -> Vec<u8> {
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let target = obj.func("p11_link_current_identity", global, text_idx, 0, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, target, R_BPF_64_32)]);
    obj.build()
}

#[test]
fn global_linkage_requires_symbol_and_btf() {
    let linkage = load_manifest("linkage");
    // GLOBAL symbol plus unique FUNC with a valid prototype: clean.
    let btf = parse_btf(&linkage_btf("clean"));
    let violations = check_rules(
        &linkage_carrier(true),
        std::slice::from_ref(&linkage),
        Some(&btf),
    );
    assert!(violations.is_empty(), "unexpected: {violations:?}");
    // LOCAL binding mutant: the exact rule id names the failure.
    let btf = parse_btf(&linkage_btf("clean"));
    let violations = check_rules(
        &linkage_carrier(false),
        std::slice::from_ref(&linkage),
        Some(&btf),
    );
    assert_eq!(rule_ids(&violations), ["linkage.global-required"]);
    assert_eq!(violations[0].kind, ErrorKind::Incompatible);
    assert_eq!(violations[0].section.as_deref(), Some(".text"));
    // Same-name rival FUNC: ambiguous despite matching size.
    let btf = parse_btf(&linkage_btf("rival"));
    let violations = check_rules(
        &linkage_carrier(true),
        std::slice::from_ref(&linkage),
        Some(&btf),
    );
    assert_eq!(rule_ids(&violations), ["linkage.btf-ambiguous"]);
    // FUNC without a prototype, and a non-function same-name type.
    let btf = parse_btf(&linkage_btf("bad-proto"));
    let violations = check_rules(
        &linkage_carrier(true),
        std::slice::from_ref(&linkage),
        Some(&btf),
    );
    assert_eq!(rule_ids(&violations), ["linkage.btf-bad-prototype"]);
    let btf = parse_btf(&linkage_btf("not-function"));
    let violations = check_rules(
        &linkage_carrier(true),
        std::slice::from_ref(&linkage),
        Some(&btf),
    );
    assert_eq!(rule_ids(&violations), ["linkage.btf-not-function"]);
    // F21 STATIC twin: GLOBAL ELF symbol but STATIC BTF FUNC fails.
    let btf = parse_btf(&linkage_btf("static"));
    let violations = check_rules(
        &linkage_carrier(true),
        std::slice::from_ref(&linkage),
        Some(&btf),
    );
    assert_eq!(rule_ids(&violations), ["linkage.btf-not-global"]);
    // Absent BTF type and absent BTF image are distinct findings.
    let mut bare = BtfBuilder::new();
    bare.add_int("unsigned int", 4, 32, 0);
    let btf = parse_btf(&bare.build());
    let violations = check_rules(
        &linkage_carrier(true),
        std::slice::from_ref(&linkage),
        Some(&btf),
    );
    assert_eq!(rule_ids(&violations), ["linkage.btf-missing"]);
    let violations = check_rules(&linkage_carrier(true), &[linkage], None);
    assert_eq!(rule_ids(&violations), ["linkage.btf-missing"]);
}

/// Carrier with `frames` rooted `.text` functions: the first is the entry
/// root, the rest are reached through a call chain, so every function is
/// live and structural decode succeeds.
fn budget_carrier(frames: usize) -> Vec<u8> {
    assert!(frames >= 1);
    let endian = Endian::Little;
    let mut text = Vec::new();
    for index in 0..frames {
        if index + 1 < frames {
            text.extend_from_slice(&call_sub(endian, -1));
        } else {
            text.extend_from_slice(&exit(endian));
        }
    }
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let mut syms = Vec::new();
    for index in 0..frames {
        syms.push(obj.func(
            &format!("stage{index}"),
            true,
            text_idx,
            index as u64 * 8,
            8,
        ));
    }
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, syms[0], R_BPF_64_32)]);
    let chain: Vec<(u64, u32, u32)> = (0..frames - 1)
        .map(|index| (index as u64 * 8, syms[index + 1], R_BPF_64_32))
        .collect();
    obj.reloc_section(".rel.text", text_idx, &chain);
    obj.build()
}

/// Re-admit one rule of a shipped manifest in isolation so a test
/// asserts exactly one finding family.
fn single_rule_manifest(shipped: &str, index: usize) -> VerifierRules {
    let bytes = repo_bytes(&format!("tools/bpf-compat/profiles/{shipped}.json"));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rules = value["rules"].as_array().unwrap();
    let only: serde_json::Value = serde_json::json!({
        "schema_version": 1,
        "kind": "tc06_rule_manifest",
        "name": shipped,
        "version": "1",
        "rules": [rules[index].clone()],
    });
    VerifierRules::from_json(serde_json::to_string(&only).unwrap().as_bytes(), &limits())
        .unwrap_or_else(|error| panic!("admit {shipped} rule {index}: {error}"))
}

#[test]
fn per_frame_minimum_accounting_bounds_total_stack() {
    // The shipped manifest counts 64 bytes per frame against a 512-byte
    // budget: 3 frames (2 stages plus entry) admit, 10 frames refuse.
    let stack = single_rule_manifest("stack", 0);
    let violations = check_rules(&budget_carrier(2), std::slice::from_ref(&stack), None);
    assert!(violations.is_empty(), "unexpected: {violations:?}");
    let violations = check_rules(&budget_carrier(9), &[stack], None);
    assert_eq!(rule_ids(&violations), ["stack.per-frame-minimum"]);
    assert_eq!(violations[0].kind, ErrorKind::Incompatible);
}

/// BTF image for the call-arity rules: `classify_direct_interface` with
/// `params` scalar parameters plus the prescribed bundled twin.
fn arity_btf(params: usize) -> Vec<u8> {
    let mut btf = BtfBuilder::new();
    let u32_ty = btf.add_int("unsigned int", 4, 32, 0);
    let u64_ty = btf.add_int("unsigned long", 8, 64, 0);
    let names: Vec<String> = (0..params).map(|index| format!("a{index}")).collect();
    let proto_params: Vec<(&str, u32)> = names.iter().map(|name| (name.as_str(), u32_ty)).collect();
    let proto = btf.add_proto(u32_ty, &proto_params);
    btf.add_func("classify_direct_interface", proto);
    let ctx = btf.add_ptr(u64_ty);
    let bundle = btf.add_ptr(u32_ty);
    let bundled = btf.add_proto(u32_ty, &[("ctx", ctx), ("bundle", bundle)]);
    btf.add_func("classify_direct_interface_bundled", bundled);
    btf.build()
}

#[test]
fn six_scalar_call_requires_bundled_replacement() {
    // BPF passes call arguments in r1-r5: a six-scalar prototype exceeds
    // the register file, and only the manifest-prescribed pointer-bundled
    // replacement (exactly two pointer parameters) is admitted.
    // (Design-frozen classification; the TC07 live gate is pending and no
    // donor slice for the six-scalar form was found.)
    let stack_all = load_manifest("stack");
    assert_eq!(stack_all.len(), 4);
    let carrier = btf_carrier();
    let btf = parse_btf(&arity_btf(5));
    let violations = check_rules(&carrier, std::slice::from_ref(&stack_all), Some(&btf));
    assert!(
        !rule_ids(&violations).contains(&"call.arity-exceeded"),
        "five params must pass arity: {violations:?}"
    );
    assert!(
        !rule_ids(&violations).contains(&"call.bundle-mismatch"),
        "prescribed bundle must pass: {violations:?}"
    );
    let btf = parse_btf(&arity_btf(6));
    let violations = check_rules(&carrier, std::slice::from_ref(&stack_all), Some(&btf));
    assert!(
        rule_ids(&violations).contains(&"call.arity-exceeded"),
        "six params must fail arity: {violations:?}"
    );
    // A bundled twin with a scalar first parameter is not the prescribed
    // pointer-bundled replacement.
    let btf = parse_btf(&arity_btf_bad_bundle());
    let violations = check_rules(&carrier, std::slice::from_ref(&stack_all), Some(&btf));
    assert!(
        rule_ids(&violations).contains(&"call.bundle-mismatch"),
        "scalar bundle param must fail: {violations:?}"
    );
    // Missing function declarations are findings, not passes.
    let mut bare = BtfBuilder::new();
    bare.add_int("unsigned int", 4, 32, 0);
    let btf = parse_btf(&bare.build());
    let violations = check_rules(&carrier, &[stack_all], Some(&btf));
    assert!(
        rule_ids(&violations).contains(&"call.function-missing"),
        "missing function must fail: {violations:?}"
    );
}

/// Arity image whose bundled twin wrongly takes a scalar first parameter.
fn arity_btf_bad_bundle() -> Vec<u8> {
    let mut btf = BtfBuilder::new();
    let u32_ty = btf.add_int("unsigned int", 4, 32, 0);
    let u64_ty = btf.add_int("unsigned long", 8, 64, 0);
    let direct = btf.add_proto(u32_ty, &[("a0", u32_ty)]);
    btf.add_func("classify_direct_interface", direct);
    let bundle = btf.add_ptr(u32_ty);
    let _ = u64_ty;
    let bundled = btf.add_proto(u32_ty, &[("ctx", u32_ty), ("bundle", bundle)]);
    btf.add_func("classify_direct_interface_bundled", bundled);
    btf.build()
}

#[test]
fn init_guard_rejects_only_the_forbidden_path() {
    // The ring-slot init path `emit` must stay `memset`-free (donor
    // spine.rs: volatile stores, never a fused builtin call), while an
    // unrelated twin may call `memset`: an object-wide ban is the mutant
    // this twin kills.
    let guard = single_rule_manifest("stack", 3);
    let bytes = guard_fixture(GuardCall::Direct);
    let violations = check_rules(&bytes, std::slice::from_ref(&guard), None);
    assert_eq!(rule_ids(&violations), ["init.path-guard"]);
    assert_eq!(violations[0].kind, ErrorKind::Incompatible);
    assert_eq!(violations[0].section.as_deref(), Some(".text"));
    assert_eq!(violations[0].offset, Some(0));
    // Twin without the forbidden edge: clean despite `memset` existing.
    let bytes = guard_fixture(GuardCall::None);
    let violations = check_rules(&bytes, std::slice::from_ref(&guard), None);
    assert!(violations.is_empty(), "unexpected: {violations:?}");
    // F23: a section-symbol call landing on `memset` is the same edge.
    let bytes = guard_fixture(GuardCall::Section);
    let violations = check_rules(&bytes, std::slice::from_ref(&guard), None);
    assert_eq!(rule_ids(&violations), ["init.path-guard"]);
    assert_eq!(violations[0].offset, Some(0));
    // F23: a linked-style call the guard cannot resolve is a finding,
    // never a silent pass.
    let bytes = guard_fixture(GuardCall::Linked);
    let violations = check_rules(&bytes, std::slice::from_ref(&guard), None);
    assert_eq!(rule_ids(&violations), ["init.unresolved-call"]);
    assert_eq!(violations[0].section.as_deref(), Some(".text"));
    assert_eq!(violations[0].offset, Some(0));
    // A missing guarded path cannot be proved clean: finding, not pass.
    let violations = check_rules(&btf_carrier(), &[guard], None);
    assert_eq!(rule_ids(&violations), ["init.path-missing"]);
}

/// How `emit` reaches (or avoids) `memset` in the guard fixture.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardCall {
    /// Direct relocated call against the `memset` function symbol.
    Direct,
    /// Section-symbol call: imm 3 resolves to byte 32 (`memset`).
    Section,
    /// Linked-style immediate call with no covering relocation.
    Linked,
    /// No call at all.
    None,
}

/// `.text` with `emit` (guarded path) and `unrelated` (permitted twin);
/// `emit`'s edge to `memset` follows `style`, otherwise only the twin
/// calls it. Both functions are rooted so decode succeeds.
fn guard_fixture(style: GuardCall) -> Vec<u8> {
    let endian = Endian::Little;
    let mut text = Vec::new();
    match style {
        GuardCall::Direct => text.extend_from_slice(&call_sub(endian, -1)),
        GuardCall::Section => text.extend_from_slice(&call_sub(endian, 3)),
        GuardCall::Linked => text.extend_from_slice(&call_sub(endian, 1)),
        GuardCall::None => text.extend_from_slice(&exit(endian)),
    }
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&call_sub(endian, -1));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let emit = obj.func("emit", true, text_idx, 0, 16);
    let unrelated = obj.func("unrelated", true, text_idx, 16, 16);
    let memset = obj.func("memset", true, text_idx, 32, 8);
    obj.func("entry", true, uprobe_idx, 0, 24);
    obj.reloc_section(
        ".reluprobe",
        uprobe_idx,
        &[(0, emit, R_BPF_64_32), (8, unrelated, R_BPF_64_32)],
    );
    let mut calls = vec![(16, memset, R_BPF_64_32)];
    match style {
        GuardCall::Direct => calls.push((0, memset, R_BPF_64_32)),
        GuardCall::Section => {
            let text_sym = obj.symbol(".text", STT_SECTION, text_idx as u16, 0, 0);
            calls.push((0, text_sym, R_BPF_64_32));
        }
        GuardCall::Linked | GuardCall::None => {}
    }
    obj.reloc_section(".rel.text", text_idx, &calls);
    obj.build()
}

/// How `helper` reaches `memset` in the nested guard fixture.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NestedEdge {
    /// Relocated call against the `memset` function symbol.
    Direct,
    /// Section-symbol call: imm 1 resolves to byte 16 (`memset`).
    Section,
    /// Linked-style immediate call with no covering relocation.
    Linked,
}

/// `.text` with `emit` -> `helper` -> `memset`, plus an `unrelated`
/// twin calling `memset` directly (permitted: unreachable from the
/// root, so a scoped traversal reports nothing for it). `emit` always
/// calls `helper` through its function symbol; the helper edge
/// follows `style`.
fn nested_guard_fixture(style: NestedEdge) -> Vec<u8> {
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&call_sub(endian, -1)); // emit@0 -> helper
    match style {
        NestedEdge::Direct => text.extend_from_slice(&call_sub(endian, -1)),
        NestedEdge::Section => text.extend_from_slice(&call_sub(endian, 1)),
        NestedEdge::Linked => text.extend_from_slice(&call_sub(endian, 1)),
    }
    text.extend_from_slice(&exit(endian)); // memset@16
    text.extend_from_slice(&call_sub(endian, -1)); // unrelated@24 -> memset
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let emit = obj.func("emit", true, text_idx, 0, 8);
    let helper = obj.func("helper", true, text_idx, 8, 8);
    let memset = obj.func("memset", true, text_idx, 16, 8);
    let unrelated = obj.func("unrelated", true, text_idx, 24, 8);
    obj.func("entry", true, uprobe_idx, 0, 24);
    obj.reloc_section(
        ".reluprobe",
        uprobe_idx,
        &[(0, emit, R_BPF_64_32), (8, unrelated, R_BPF_64_32)],
    );
    let mut calls = vec![(0, helper, R_BPF_64_32), (24, memset, R_BPF_64_32)];
    match style {
        NestedEdge::Direct => calls.push((8, memset, R_BPF_64_32)),
        NestedEdge::Section => {
            let text_sym = obj.symbol(".text", STT_SECTION, text_idx as u16, 0, 0);
            calls.push((8, text_sym, R_BPF_64_32));
        }
        NestedEdge::Linked => {}
    }
    obj.reloc_section(".rel.text", text_idx, &calls);
    obj.build()
}

/// `emit` <-> `helper` cycle with an isolated `memset`: the traversal
/// must terminate (visited set) and report nothing.
fn cyclic_guard_fixture() -> Vec<u8> {
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&call_sub(endian, -1)); // emit@0 -> helper
    text.extend_from_slice(&call_sub(endian, -1)); // helper@8 -> emit
    text.extend_from_slice(&exit(endian)); // memset@16 (unreachable)
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let emit = obj.func("emit", true, text_idx, 0, 8);
    let helper = obj.func("helper", true, text_idx, 8, 8);
    obj.func("memset", true, text_idx, 16, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, emit, R_BPF_64_32)]);
    obj.reloc_section(
        ".rel.text",
        text_idx,
        &[(0, helper, R_BPF_64_32), (8, emit, R_BPF_64_32)],
    );
    obj.build()
}

#[test]
fn init_guard_follows_nested_helper_calls() {
    // R09: emit -> helper -> memset. The guard traverses the reachable
    // graph from the root, so the nested forbidden edge is a finding
    // at the helper's call site. The unrelated twin's direct edge is
    // unreachable from the root and stays silent (scoping). Old
    // root-only code reported nothing.
    let guard = single_rule_manifest("stack", 3);
    let bytes = nested_guard_fixture(NestedEdge::Direct);
    let violations = check_rules(&bytes, std::slice::from_ref(&guard), None);
    assert_eq!(rule_ids(&violations), ["init.path-guard"]);
    assert_eq!(violations[0].offset, Some(8));
}

#[test]
fn init_guard_follows_nested_section_calls() {
    // R09 + F23: the nested edge through a section symbol is the same
    // guarded edge as a direct nested call.
    let guard = single_rule_manifest("stack", 3);
    let bytes = nested_guard_fixture(NestedEdge::Section);
    let violations = check_rules(&bytes, std::slice::from_ref(&guard), None);
    assert_eq!(rule_ids(&violations), ["init.path-guard"]);
    assert_eq!(violations[0].offset, Some(8));
}

#[test]
fn init_guard_reports_nested_unresolved_calls() {
    // R09: a linked-style call inside the REACHABLE helper is a
    // finding, never a silent pass: the traversal scans helper
    // bodies, not just the root. Old code reported nothing.
    let guard = single_rule_manifest("stack", 3);
    let bytes = nested_guard_fixture(NestedEdge::Linked);
    let violations = check_rules(&bytes, std::slice::from_ref(&guard), None);
    assert_eq!(rule_ids(&violations), ["init.unresolved-call"]);
    assert_eq!(violations[0].offset, Some(8));
}

#[test]
fn init_guard_terminates_on_call_cycles() {
    // R09: a reachable call cycle terminates (visited set) and an
    // unreachable forbidden callee stays silent.
    let guard = single_rule_manifest("stack", 3);
    let bytes = cyclic_guard_fixture();
    let violations = check_rules(&bytes, std::slice::from_ref(&guard), None);
    assert!(violations.is_empty(), "unexpected: {violations:?}");
}

#[test]
fn findings_charge_retained_names_against_the_ceiling() {
    // R08: a 200KB section name times 1000 forbidden edges must trip
    // the 1MB retained ceiling instead of returning a 200MB
    // violation vector. Each finding accounts its record plus the
    // cloned name BEFORE allocating. Old code returned Ok with all
    // 1000 uncharged clones.
    let endian = Endian::Little;
    let calls = 1000u64;
    let mut text = Vec::new();
    for _ in 0..calls {
        text.extend_from_slice(&call_sub(endian, -1));
    }
    text.extend_from_slice(&exit(endian));
    let long_name: String = "s".repeat(200_000);
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(&long_name, SHT_PROGBITS, SHF_EXECINSTR, text);
    let mut entry = Vec::new();
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    let emit = obj.func("emit", true, text_idx, 0, calls * 8);
    let memset = obj.func("memset", true, text_idx, calls * 8, 8);
    obj.func("entry", true, uprobe_idx, 0, 16);
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, emit, R_BPF_64_32)]);
    let edges: Vec<(u64, u32, u32)> = (0..calls)
        .map(|i| (i * 8, memset as u32, R_BPF_64_32))
        .collect();
    obj.reloc_section(".rel.text", text_idx, &edges);
    let bytes = obj.build();
    assert!(bytes.len() < 1 << 20, "input fits its own ceiling");
    let guard = single_rule_manifest("stack", 3);
    let error = check_verifier_rules(
        &bytes,
        &contract(),
        std::slice::from_ref(&guard),
        None,
        &limits(),
    )
    .expect_err("1000 long-name findings must exhaust retained_bytes");
    assert_eq!(error.kind(), ErrorKind::LimitExceeded);
    assert_eq!(error.stage(), Stage::Inspect);
}

/// One uprobe/uretprobe program for the private-stack rule.
struct StackProgram {
    name: &'static str,
    section: &'static str,
    /// Tail-call index constant (`None` = no prologue emitted).
    index: Option<i32>,
    /// Program array loaded into r2 (`None` = unidentified array).
    array: Option<&'static str>,
    /// Whether the body touches r10 (provably not stackless).
    frame_touch: bool,
}

/// Carrier with the listed programs plus `.maps` array definitions.
/// Map fixups cover exactly the programs naming a known array.
fn stack_carrier(programs: &[StackProgram]) -> Vec<u8> {
    let endian = Endian::Little;
    let mut obj = ObjBuilder::little();
    let maps_idx = obj.section(".maps", SHT_PROGBITS, 0, vec![0u8; 64]);
    let mut array_syms = std::collections::BTreeMap::new();
    for (slot, name) in ["TAIL_CALLS", "STACK_GUARD", "PAIR_CALLS"]
        .into_iter()
        .enumerate()
    {
        let sym = obj.symbol(
            name,
            (STB_GLOBAL << 4) | STT_OBJECT,
            maps_idx as u16,
            slot as u64 * 16,
            16,
        );
        array_syms.insert(name, sym);
    }
    // Bodies are grouped per section in program order: the profile's
    // selected sections first, then any other program section (F22).
    let mut order = vec!["uprobe", "uretprobe"];
    for program in programs {
        if !order.contains(&program.section) {
            order.push(program.section);
        }
    }
    for section in order {
        let mut body = Vec::new();
        let mut relocs = Vec::new();
        let mut syms: Vec<(String, u64, u64)> = Vec::new();
        for program in programs.iter().filter(|p| p.section == section) {
            let start = body.len() as u64;
            if let Some(index) = program.index {
                if let Some(array) = program.array {
                    let at = body.len() as u64;
                    body.extend_from_slice(&ldimm64(endian, 2, 0));
                    let sym = array_syms[array];
                    relocs.push((at, sym, R_BPF_64_64));
                }
                body.extend_from_slice(&mov32_r3(endian, index));
                body.extend_from_slice(&call_helper(endian, 12));
            }
            if program.frame_touch {
                body.extend_from_slice(&stxw_frame(endian, 1, -4));
            }
            body.extend_from_slice(&exit(endian));
            syms.push((program.name.to_owned(), start, body.len() as u64 - start));
        }
        if syms.is_empty() {
            continue;
        }
        let section_idx = obj.section(section, SHT_PROGBITS, SHF_EXECINSTR, body);
        for (name, start, size) in &syms {
            obj.func(name, true, section_idx, *start, *size);
        }
        obj.reloc_section(&format!(".rel{section}"), section_idx, &relocs);
    }
    // A rooted `.text` keeps structural decode total; the rule reads the
    // uprobe sections only.
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    obj.func("live", true, text_idx, 0, 8);
    obj.build()
}

#[test]
fn private_stack_prologue_matrix() {
    let manifest = load_manifest("private-stack");
    // Clean: `big` opts out through TAIL_CALLS, `tiny` is stackless-exempt.
    let bytes = stack_carrier(&[
        StackProgram {
            name: "big",
            section: "uprobe",
            index: Some(-1),
            array: Some("TAIL_CALLS"),
            frame_touch: true,
        },
        StackProgram {
            name: "tiny",
            section: "uretprobe",
            index: None,
            array: None,
            frame_touch: false,
        },
    ]);
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert!(violations.is_empty(), "unexpected: {violations:?}");
    // Required prologue removed: the current rule fails the mutant.
    let bytes = stack_carrier(&[StackProgram {
        name: "big",
        section: "uprobe",
        index: None,
        array: None,
        frame_touch: true,
    }]);
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert_eq!(rule_ids(&violations), ["private-stack.opt-out-required"]);
    assert_eq!(violations[0].section.as_deref(), Some("uprobe"));
    // Retired slot 1: not a known slot and not the opt-out.
    let bytes = stack_carrier(&[StackProgram {
        name: "big",
        section: "uprobe",
        index: Some(1),
        array: Some("TAIL_CALLS"),
        frame_touch: true,
    }]);
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert_eq!(rule_ids(&violations), ["private-stack.unknown-slot"]);
    assert_eq!(violations[0].offset, Some(24));
    // Plain program through STACK_GUARD: wrong owner attach type.
    let bytes = stack_carrier(&[StackProgram {
        name: "big",
        section: "uprobe",
        index: Some(-1),
        array: Some("STACK_GUARD"),
        frame_touch: true,
    }]);
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert_eq!(rule_ids(&violations), ["private-stack.wrong-array"]);
    // Multi-loaded program opts out through STACK_GUARD only.
    let bytes = stack_carrier(&[StackProgram {
        name: "p11_entry",
        section: "uprobe",
        index: Some(-1),
        array: Some("STACK_GUARD"),
        frame_touch: true,
    }]);
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert!(violations.is_empty(), "unexpected: {violations:?}");
    // The pair continues through its own PAIR_CALLS slot 0.
    let bytes = stack_carrier(&[StackProgram {
        name: "p11_entry_template_pair",
        section: "uprobe",
        index: Some(0),
        array: Some("PAIR_CALLS"),
        frame_touch: true,
    }]);
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert!(violations.is_empty(), "unexpected: {violations:?}");
    // Tail call through an unidentified array: no attribution possible.
    let bytes = stack_carrier(&[StackProgram {
        name: "big",
        section: "uprobe",
        index: Some(-1),
        array: None,
        frame_touch: true,
    }]);
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert_eq!(rule_ids(&violations), ["private-stack.unknown-array"]);
    // An array named by a non-map relocation: not an attributable load.
    let bytes = bad_array_reloc_fixture();
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert_eq!(rule_ids(&violations), ["private-stack.bad-relocation"]);
    // Misaligned and out-of-range program extents cannot be scanned.
    let bytes = bad_extent_fixture();
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert_eq!(
        rule_ids(&violations),
        ["private-stack.bad-extent", "private-stack.bad-extent"]
    );
    // An array reference owned by no program body (section padding).
    let bytes = unowned_array_ref_fixture();
    let violations = check_rules(&bytes, &[manifest], None);
    assert_eq!(rule_ids(&violations), ["private-stack.unowned-reference"]);
}

#[test]
fn array_reference_outside_selected_sections_fails() {
    // F22: the uprobe/uretprobe legs are clean, but a program-array load
    // in the unselected `kprobe` section fails instead of escaping.
    let manifest = load_manifest("private-stack");
    let bytes = stack_carrier(&[
        StackProgram {
            name: "big",
            section: "uprobe",
            index: Some(-1),
            array: Some("TAIL_CALLS"),
            frame_touch: true,
        },
        StackProgram {
            name: "tiny",
            section: "uretprobe",
            index: None,
            array: None,
            frame_touch: false,
        },
        StackProgram {
            name: "sneaky",
            section: "kprobe",
            index: Some(-1),
            array: Some("TAIL_CALLS"),
            frame_touch: false,
        },
    ]);
    let violations = check_rules(&bytes, std::slice::from_ref(&manifest), None);
    assert_eq!(
        rule_ids(&violations),
        ["private-stack.unselected-reference"]
    );
    assert_eq!(violations[0].section.as_deref(), Some("kprobe"));
    assert_eq!(violations[0].offset, Some(0));
}

/// Stackless `big` plus a call relocation naming TAIL_CALLS: the program
/// is clean, the reference is not.
fn bad_array_reloc_fixture() -> Vec<u8> {
    let endian = Endian::Little;
    let mut obj = ObjBuilder::little();
    let maps_idx = obj.section(".maps", SHT_PROGBITS, 0, vec![0u8; 16]);
    let mut body = Vec::new();
    body.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, body);
    obj.func("big", true, uprobe_idx, 0, 8);
    let array = obj.symbol(
        "TAIL_CALLS",
        (STB_GLOBAL << 4) | STT_OBJECT,
        maps_idx as u16,
        0,
        16,
    );
    obj.reloc_section(".reluprobe", uprobe_idx, &[(0, array, R_BPF_64_32)]);
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    obj.func("live", true, text_idx, 0, 8);
    obj.build()
}

/// One misaligned (12-byte) and one out-of-range program extent.
fn bad_extent_fixture() -> Vec<u8> {
    let endian = Endian::Little;
    let mut obj = ObjBuilder::little();
    let maps_idx = obj.section(".maps", SHT_PROGBITS, 0, vec![0u8; 16]);
    obj.symbol(
        "TAIL_CALLS",
        (STB_GLOBAL << 4) | STT_OBJECT,
        maps_idx as u16,
        0,
        16,
    );
    let mut body = Vec::new();
    body.extend_from_slice(&exit(endian));
    body.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, body);
    obj.func("big", true, uprobe_idx, 0, 12);
    obj.func("big2", true, uprobe_idx, 8, 16);
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    obj.func("live", true, text_idx, 0, 8);
    obj.build()
}

/// A map fixup into section padding no program body owns.
fn unowned_array_ref_fixture() -> Vec<u8> {
    let endian = Endian::Little;
    let mut obj = ObjBuilder::little();
    let maps_idx = obj.section(".maps", SHT_PROGBITS, 0, vec![0u8; 16]);
    let mut body = Vec::new();
    body.extend_from_slice(&exit(endian));
    body.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, body);
    obj.func("big", true, uprobe_idx, 0, 8);
    let array = obj.symbol(
        "TAIL_CALLS",
        (STB_GLOBAL << 4) | STT_OBJECT,
        maps_idx as u16,
        0,
        16,
    );
    obj.reloc_section(".reluprobe", uprobe_idx, &[(8, array, R_BPF_64_64)]);
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    obj.func("live", true, text_idx, 0, 8);
    obj.build()
}

/// Combined BTF image for the product-shaped object: transport struct,
/// identity linkage, five-param classifier and bundled twin.
fn product_btf() -> Vec<u8> {
    let mut btf = BtfBuilder::new();
    let u64_ty = btf.add_int("unsigned long", 8, 64, 0);
    let u8_ty = btf.add_int("unsigned char", 1, 8, 0);
    let u32_ty = btf.add_int("unsigned int", 4, 32, 0);
    let pad_ty = btf.add_array(u8_ty, u32_ty, 4);
    btf.add_struct(
        "SelectionTransport",
        32,
        &[
            ("request_flags", u64_ty, 0),
            ("binding_id", u64_ty, 64),
            ("return_rv", u64_ty, 128),
            ("request_name_class", u8_ty, 192),
            ("request_version_class", u8_ty, 200),
            ("pause_eligible", u8_ty, 208),
            ("word_bytes", u8_ty, 216),
            ("_pad", pad_ty, 224),
        ],
    );
    let out_ptr = btf.add_ptr(u64_ty);
    let ident_proto = btf.add_proto(u32_ty, &[("out", out_ptr)]);
    btf.add_func("p11_link_current_identity", ident_proto);
    let direct = btf.add_proto(
        u32_ty,
        &[
            ("a0", u32_ty),
            ("a1", u32_ty),
            ("a2", u32_ty),
            ("a3", u32_ty),
            ("a4", u32_ty),
        ],
    );
    btf.add_func("classify_direct_interface", direct);
    let ctx = btf.add_ptr(u64_ty);
    let bundle = btf.add_ptr(u32_ty);
    let bundled = btf.add_proto(u32_ty, &[("ctx", ctx), ("bundle", bundle)]);
    btf.add_func("classify_direct_interface_bundled", bundled);
    btf.build()
}

/// Product-shaped object: prologue-carrying entry, rooted `.text` with one
/// dead builtin, maps, and BTF. Every shipped rule passes before and after
/// the repair.
fn product_fixture() -> Vec<u8> {
    let endian = Endian::Little;
    let mut text = Vec::new();
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    text.extend_from_slice(&exit(endian));
    let mut obj = ObjBuilder::little();
    let text_idx = obj.section(".text", SHT_PROGBITS, SHF_EXECINSTR, text);
    let maps_idx = obj.section(".maps", SHT_PROGBITS, 0, vec![0u8; 16]);
    let mut entry = Vec::new();
    entry.extend_from_slice(&ldimm64(endian, 2, 0));
    entry.extend_from_slice(&mov32_r3(endian, -1));
    entry.extend_from_slice(&call_helper(endian, 12));
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&call_sub(endian, -1));
    entry.extend_from_slice(&exit(endian));
    let uprobe_idx = obj.section("uprobe", SHT_PROGBITS, SHF_EXECINSTR, entry);
    obj.section(".BTF", SHT_PROGBITS, 0, product_btf());
    let live = obj.func("p11_link_current_identity", true, text_idx, 0, 16);
    let emit = obj.func("emit", true, text_idx, 16, 8);
    obj.func("memset", true, text_idx, 24, 8);
    obj.func("big", true, uprobe_idx, 0, 56);
    let array = obj.symbol(
        "TAIL_CALLS",
        (STB_GLOBAL << 4) | STT_OBJECT,
        maps_idx as u16,
        0,
        16,
    );
    obj.reloc_section(
        ".reluprobe",
        uprobe_idx,
        &[
            (0, array, R_BPF_64_64),
            (32, live, R_BPF_64_32),
            (40, emit, R_BPF_64_32),
        ],
    );
    obj.build()
}

#[test]
fn rule_check_refuses_malformed_elf() {
    let padding = load_manifest("padding");
    let carrier = btf_carrier();
    let error = check_verifier_rules(
        &carrier[..carrier.len() / 2],
        &contract(),
        &[padding],
        None,
        &limits(),
    )
    .expect_err("truncated input must refuse");
    assert_refusal(&error, ErrorKind::Malformed, Stage::Inspect, "truncated");
}

#[test]
fn transformed_bytes_readmit_and_rerun_clean() {
    let manifests = [
        load_manifest("padding"),
        load_manifest("linkage"),
        load_manifest("stack"),
        load_manifest("private-stack"),
    ];
    let bytes = product_fixture();
    let btf = parse_btf(&product_btf());
    let before = check_rules(&bytes, &manifests, Some(&btf));
    assert!(before.is_empty(), "unexpected: {before:?}");
    let inspection = inspect_final_object(&bytes, &contract(), &limits()).expect("inspect input");
    assert_eq!(hex(inspection.object_id().sha256()), hex(&digest(&bytes)));
    let (out, report) =
        prune_dead_code_with_report(&bytes, &contract(), &load_allowlist(), &limits())
            .expect("prune product object");
    assert_eq!(report.removed(), &["memset".to_owned()]);
    assert_eq!((report.text_before(), report.text_after()), (32, 24));
    // The transformed object is a new final artifact: re-admit and rerun
    // every rule on the repaired bytes.
    let inspection = inspect_final_object(&out, &contract(), &limits()).expect("inspect output");
    assert_eq!(hex(inspection.object_id().sha256()), hex(&digest(&out)));
    let after = check_rules(&out, &manifests, Some(&btf));
    assert!(after.is_empty(), "unexpected: {after:?}");
}
