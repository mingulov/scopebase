// SPDX-License-Identifier: Apache-2.0
//! TC05: ELF/BTF relocation, call graph and metadata preservation.
//!
//! Donor slices (all user-owned; third-party/upstream never copied):
//! - p11scope-ws p11scope w001 @ 7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4,
//!   `third-party/patches/aya-obj-0.3.0/aya-obj-map-relocation.patch` `+`
//!   lines only: error variants 9-25, exact section-offset resolution with
//!   unsigned addend and checked overflow 47-92, section fallback 99-101,
//!   unit vectors 110-220, rationale 227-256.
//! - Same worktree/commit, `tests/bpf_map_contracts.rs` lines 61-107:
//!   distinct sentinel FDs per map, `0x18`/src==1 relocation filter.
//! - Same worktree/commit, `tests/python/test_bpf_map_defs.py` lines
//!   133-163: relocation refusal matrix shape (wrong kind/symbol/offset,
//!   out-of-bounds, nonzero base).
//! - p11scope-ws w000 @ 6f97aa47, `llvm-bpf-toolchain-experiment.md` lines
//!   153-171 (exit-zero replay can discard .BTF/.BTF.ext; inspect emitted
//!   bytes, not status) and 196-200 (repaired objects retain nonempty
//!   DWARF/BTF/BTF.ext).
//! Relocation record facts follow the URL the donor patch cites,
//! docs.kernel.org/bpf/llvm_reloc.html (REL records, implicit addend,
//! R_BPF_64_64/ABS64/ABS32/NODYLD32/R_BPF_64_32 semantics); pseudo-field
//! values ride the TC03 UAPI pins. Grant: OWNER-2026-10-23.
use scopebase_bpf::btf::{BtfImages, BtfLimits, BtfView, ByteOrder};
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use scopebase_testkit::object::graph::{
    apply_relocations, diff_metadata, extract_call_graph, snapshot_metadata, verify_callbacks,
    CallTarget, CallbackSpec, MetadataInputs, RelocationAction, RelocationInputs,
};
use scopebase_testkit::object::{FinalObjectManifest, ObjectContract};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error as _;

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{MANIFEST_DIR}/../../{relative}"))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn repo_text(relative: &str) -> serde_json::Value {
    let bytes = repo_bytes(relative);
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("parse {relative}: {error}"))
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

fn maps_btf() -> Vec<u8> {
    repo_bytes("crates/scopebase-bpf/fixtures/btf-v1/images/maps.bin")
}

fn shapes_btf() -> Vec<u8> {
    repo_bytes("crates/scopebase-bpf/fixtures/btf-v1/images/shapes.bin")
}

fn contract_json(endian: &str) -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "artifact": "tc05-graph-vectors",
  "profile": "compiler-object-v1",
  "target": {{"triple": "bpfel-unknown-none", "arch": "bpf", "endian": "{endian}", "pointer_width_bits": 64}},
  "backend": {{"kind": "llvm-llc", "name": "llc", "version": "21.1.8", "sha256": "935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382"}},
  "cpu": "generic",
  "features_enabled": [],
  "features_disabled": [],
  "required_cells": ["kernel-6.12-x86_64-verifier"],
  "optional_cells": []
}}"#
    )
}

fn contract() -> ObjectContract {
    ObjectContract::from_json(contract_json("little").as_bytes(), &limits()).expect("contract")
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn manifest_json(id: &str, kind: &str, sha: &str) -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "kind": "tc03_final_object_manifest",
  "objects": [{{
    "id": "{id}",
    "kind": "{kind}",
    "path": "synthetic/{id}.o",
    "sha256": "{sha}",
    "producer_name": "tc05-synthetic",
    "producer_version": "0.1.0",
    "artifact": "tc05-graph-vectors",
    "profile": "compiler-object-v1",
    "isa_profile": "tc03-base",
    "isa_version": "1"
  }}]
}}"#
    )
}

/// Relocation types (docs.kernel.org/bpf/llvm_reloc.html, donor-cited URL).
const R_BPF_64_64: u32 = 1;
const R_BPF_64_ABS64: u32 = 2;
const R_BPF_64_ABS32: u32 = 3;
const R_BPF_64_NODYLD32: u32 = 4;
const R_BPF_64_32: u32 = 10;

/// Minimal synthetic ELF64LE BPF relocatable builder.
///
/// Sections are appended in push order (index 0 is always null); symtab,
/// strtab and shstrtab are synthesized by [`ObjBuilder::build`]. Every
/// offset in the emitted file derives from the pushed bodies, so the
/// builder cannot emit an internally inconsistent image by accident.
struct ObjBuilder {
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
}

struct RawSym {
    name: String,
    info: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

impl ObjBuilder {
    fn new() -> Self {
        Self {
            sections: vec![RawSection {
                name: String::new(),
                shtype: 0,
                flags: 0,
                data: Vec::new(),
                link: 0,
                info: 0,
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

    fn section(&mut self, name: &str, shtype: u32, flags: u64, data: Vec<u8>) -> usize {
        self.sections.push(RawSection {
            name: name.to_owned(),
            shtype,
            flags,
            data,
            link: 0,
            info: 0,
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

    fn reloc(&mut self, target: usize, entries: &[(u64, u32, u32)]) -> usize {
        let mut data = Vec::with_capacity(entries.len() * 16);
        for (offset, sym, rtype) in entries {
            data.extend_from_slice(&offset.to_le_bytes());
            data.extend_from_slice(&(((*sym as u64) << 32) | (*rtype as u64)).to_le_bytes());
        }
        let index = self.section(".rel.text", 9, 0, data);
        self.sections[index].info = target as u32;
        index
    }

    fn build(mut self) -> Vec<u8> {
        // Symbol names precede section bodies so strtab content is fixed.
        let mut strtab = vec![0u8];
        let mut name_off = Vec::with_capacity(self.syms.len());
        for sym in &self.syms {
            name_off.push(strtab.len() as u32);
            strtab.extend_from_slice(sym.name.as_bytes());
            strtab.push(0);
        }
        let mut symtab = Vec::with_capacity(self.syms.len() * 24);
        for (sym, off) in self.syms.iter().zip(name_off) {
            symtab.extend_from_slice(&off.to_le_bytes());
            symtab.push(sym.info);
            symtab.push(0);
            symtab.extend_from_slice(&sym.shndx.to_le_bytes());
            symtab.extend_from_slice(&sym.value.to_le_bytes());
            symtab.extend_from_slice(&sym.size.to_le_bytes());
        }
        let symtab_index = self.sections.len();
        self.sections.push(RawSection {
            name: ".symtab".to_owned(),
            shtype: 2,
            flags: 0,
            data: symtab,
            link: 0,
            info: 1,
        });
        let strtab_index = self.sections.len();
        self.sections.push(RawSection {
            name: ".strtab".to_owned(),
            shtype: 3,
            flags: 0,
            data: strtab,
            link: 0,
            info: 0,
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
            shtype: 3,
            flags: 0,
            data: shstrtab,
            link: 0,
            info: 0,
        });
        for section in &self.sections {
            if section.shtype == 9 {
                let _ = section;
            }
        }
        // Link REL sections at their recorded symtab now that it exists.
        let rel_targets: Vec<usize> = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.shtype == 9)
            .map(|(i, _)| i)
            .collect();
        for index in rel_targets {
            self.sections[index].link = symtab_index as u32;
        }

        let mut out = vec![0u8; 64];
        out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;
        out[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        out[0x12..0x14].copy_from_slice(&247u16.to_le_bytes());
        out[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        out[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        out[0x3c..0x3e].copy_from_slice(&(self.sections.len() as u16).to_le_bytes());
        out[0x3e..0x40].copy_from_slice(&(shstrtab_index as u16).to_le_bytes());
        let mut offset = 64u64;
        let mut body_off = Vec::with_capacity(self.sections.len());
        body_off.push(0);
        for section in self.sections.iter().skip(1) {
            body_off.push(offset);
            offset += section.data.len() as u64;
            out.extend_from_slice(&section.data);
        }
        let shoff = out.len() as u64;
        out[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        for (index, section) in self.sections.iter().enumerate() {
            let mut header = [0u8; 64];
            header[0..4].copy_from_slice(&(sh_name_off[index] as u32).to_le_bytes());
            header[4..8].copy_from_slice(&section.shtype.to_le_bytes());
            header[8..16].copy_from_slice(&section.flags.to_le_bytes());
            header[24..32].copy_from_slice(&body_off[index].to_le_bytes());
            header[32..40].copy_from_slice(&(section.data.len() as u64).to_le_bytes());
            header[40..44].copy_from_slice(&section.link.to_le_bytes());
            header[44..48].copy_from_slice(&section.info.to_le_bytes());
            header[48..56].copy_from_slice(&8u64.to_le_bytes());
            header[56..64].copy_from_slice(
                &if section.shtype == 2 {
                    24u64
                } else if section.shtype == 9 {
                    16u64
                } else {
                    0u64
                }
                .to_le_bytes(),
            );
            out.extend_from_slice(&header);
        }
        out
    }
}

const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;

fn bind_type(bind: u8, ty: u8) -> u8 {
    (bind << 4) | ty
}

fn slot(code: u8, regs: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut slot = [0u8; 8];
    slot[0] = code;
    slot[1] = regs;
    slot[2..4].copy_from_slice(&off.to_le_bytes());
    slot[4..8].copy_from_slice(&imm.to_le_bytes());
    slot
}

fn ld_imm64(addend: i32) -> Vec<u8> {
    let mut code = Vec::with_capacity(16);
    code.extend_from_slice(&slot(0x18, 0x01, 0, addend));
    code.extend_from_slice(&[0u8; 8]);
    code
}

fn exit_slot() -> [u8; 8] {
    slot(0x95, 0x00, 0, 0)
}

fn refusal(error: &OperationError) -> (ErrorKind, Stage) {
    (error.kind(), error.stage())
}

/// Refusal detail: OperationError display never formats its source, so
/// semantic assertions traverse to it explicitly.
fn message(error: &OperationError) -> String {
    error
        .source()
        .map(|source| source.to_string())
        .unwrap_or_default()
}

/// Build one relocation-case object: `.text` holds one LD_imm64 per reloc
/// plus a trailing exit; `.maps` holds `maps_size` data bytes; OBJECT
/// definitions and one section symbol mirror the donor section-symbol form.
fn reloc_object(
    defs: &[(&str, u64)],
    maps_size: usize,
    relocs: &[(i32, RelSym)],
    section_base: u64,
) -> (Vec<u8>, u32, BTreeMap<String, u32>) {
    let mut builder = ObjBuilder::new();
    let mut code = Vec::new();
    for (addend, _) in relocs {
        code.extend_from_slice(&ld_imm64(*addend));
    }
    code.extend_from_slice(&exit_slot());
    let text = builder.section(".text", 1, 0x4, code);
    let maps = builder.section(".maps", 1, 0, vec![0u8; maps_size]);
    let section_sym = builder.symbol(
        ".maps",
        bind_type(STB_LOCAL, STT_SECTION),
        maps as u16,
        section_base,
        0,
    );
    let mut def_syms = BTreeMap::new();
    for (name, offset) in defs {
        let sym = builder.symbol(
            name,
            bind_type(STB_GLOBAL, STT_OBJECT),
            maps as u16,
            *offset,
            28,
        );
        def_syms.insert((*name).to_owned(), sym);
    }
    let entries: Vec<(u64, u32, u32)> = relocs
        .iter()
        .enumerate()
        .map(|(index, (_, sym))| {
            let symbol = match sym {
                RelSym::Section => section_sym,
                RelSym::Named(name) => def_syms[name.as_str()],
                RelSym::Index(raw) => *raw,
            };
            ((index * 16) as u64, symbol, R_BPF_64_64)
        })
        .collect();
    builder.reloc(text, &entries);
    (builder.build(), section_sym, def_syms)
}

#[derive(Clone, Debug)]
enum RelSym {
    Section,
    Named(String),
    Index(u32),
}

fn slot_fields(bytes: &[u8], text_file_off: u64, slot: usize) -> (u8, u8, i32, i32) {
    let at = (text_file_off + (slot * 8) as u64) as usize;
    let code = bytes[at];
    let regs = bytes[at + 1];
    let imm = i32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
    let next = i32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
    (code, regs, imm, next)
}

fn text_file_offset(bytes: &[u8]) -> u64 {
    // Independent section walk: never trust the builder's push order.
    let shoff = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap());
    let shnum = u16::from_le_bytes(bytes[0x3c..0x3e].try_into().unwrap()) as usize;
    let shstrndx = u16::from_le_bytes(bytes[0x3e..0x40].try_into().unwrap()) as usize;
    let header = |index: usize| {
        let at = shoff as usize + index * 64;
        (
            u64::from_le_bytes(bytes[at + 24..at + 32].try_into().unwrap()),
            u64::from_le_bytes(bytes[at + 32..at + 40].try_into().unwrap()),
            u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
        )
    };
    let (str_off, str_size, _) = header(shstrndx);
    let strings = &bytes[str_off as usize..(str_off + str_size) as usize];
    for index in 0..shnum {
        let (off, _, name) = header(index);
        let end = strings[name as usize..]
            .iter()
            .position(|b| *b == 0)
            .unwrap();
        if &strings[name as usize..name as usize + end] == b".text" {
            return off;
        }
    }
    panic!("synthetic object has no .text");
}

#[test]
fn section_offsets_resolve_distinct_sentinel_fds() {
    let doc = repo_text("fixtures/bpf/object-graph/maps/expected.json");
    let case = &doc["cases"][0];
    assert_eq!(case["name"], "distinct-section-offsets");
    let defs: Vec<(String, u64)> = case["defs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|def| {
            (
                def["name"].as_str().unwrap().to_owned(),
                def["offset"].as_u64().unwrap(),
            )
        })
        .collect();
    let maps_size = case["maps_size"].as_u64().unwrap() as usize;
    let named: BTreeMap<String, i32> = case["named_fds"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, fd)| (name.clone(), fd.as_i64().unwrap() as i32))
        .collect();
    let relocs: Vec<(i32, RelSym)> = case["relocs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reloc| {
            (
                reloc["addend"].as_u64().unwrap() as u32 as i32,
                RelSym::Section,
            )
        })
        .collect();
    let def_refs: Vec<(&str, u64)> = defs.iter().map(|(n, o)| (n.as_str(), *o)).collect();
    let (bytes, _, _) = reloc_object(&def_refs, maps_size, &relocs, 0);
    let manifest = FinalObjectManifest::from_json(
        manifest_json("tc05-distinct", "rel", &hex(&digest(&bytes))).as_bytes(),
        &limits(),
    )
    .expect("admit synthetic manifest");
    let admitted = manifest
        .admit("tc05-distinct", &bytes, &limits())
        .expect("hash-bound bytes");
    assert_eq!(
        admitted.entry().kind(),
        scopebase_testkit::object::ObjectKind::Rel
    );
    let inputs = RelocationInputs {
        named_maps: &named,
        section_maps: &BTreeMap::new(),
    };
    let relocated = apply_relocations(&bytes, &contract(), &inputs, &limits()).expect("relocate");
    assert_eq!(relocated.applied().len(), 3);
    for (index, reloc) in case["relocs"].as_array().unwrap().iter().enumerate() {
        let applied = &relocated.applied()[index];
        assert_eq!(applied.section(), ".text");
        assert_eq!(applied.offset(), (index * 16) as u64);
        let (code, regs, imm, next) =
            slot_fields(relocated.bytes(), text_file_offset(&bytes), index * 2);
        assert_eq!(code, 0x18);
        assert_eq!(regs >> 4, reloc["expect_src"].as_u64().unwrap() as u8);
        assert_eq!(imm, reloc["expect_fd"].as_i64().unwrap() as i32);
        assert_eq!(next, case["second_slot_imm"].as_i64().unwrap() as i32);
        assert!(matches!(applied.action(), RelocationAction::MapFd { .. }));
    }
    // Unrelocated tail (exit slot) and every non-target byte are identical.
    let tail = relocated.bytes().len() - 8;
    assert_eq!(&relocated.bytes()[tail..], &bytes[tail..]);
    assert_ne!(relocated.output_sha256(), admitted.sha256());
}

#[test]
fn map_addend_is_unsigned_32_bit() {
    let doc = repo_text("fixtures/bpf/object-graph/maps/expected.json");
    let case = &doc["cases"][1];
    assert_eq!(case["name"], "unsigned-32bit-addend");
    let addend = case["relocs"][0]["addend"].as_u64().unwrap();
    assert_eq!(addend, 0x8000_0000);
    let (bytes, _, _) = reloc_object(
        &[("second", addend)],
        64,
        &[(addend as u32 as i32, RelSym::Section)],
        0,
    );
    let mut named = BTreeMap::new();
    named.insert("second".to_owned(), 202);
    let inputs = RelocationInputs {
        named_maps: &named,
        section_maps: &BTreeMap::new(),
    };
    let relocated = apply_relocations(&bytes, &contract(), &inputs, &limits()).expect("relocate");
    let (_, _, imm, _) = slot_fields(relocated.bytes(), text_file_offset(&bytes), 0);
    assert_eq!(imm, 202);
    // A signed reading (-2^31) must not match the zero definition instead.
    let (signed_bytes, _, _) = reloc_object(
        &[("zero", 0)],
        64,
        &[(addend as u32 as i32, RelSym::Section)],
        0,
    );
    let mut zero = BTreeMap::new();
    zero.insert("zero".to_owned(), 101);
    let inputs = RelocationInputs {
        named_maps: &zero,
        section_maps: &BTreeMap::new(),
    };
    let error = apply_relocations(&signed_bytes, &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Inspect));
    assert!(message(&error).contains("offset"), "{}", message(&error));
}

#[test]
fn named_symbol_and_global_data_paths() {
    let doc = repo_text("fixtures/bpf/object-graph/maps/expected.json");
    let named_case = &doc["cases"][2];
    assert_eq!(named_case["name"], "named-symbol");
    let (bytes, _, _) = reloc_object(
        &[("first", 0), ("second", 40)],
        64,
        &[(0, RelSym::Named("second".to_owned()))],
        0,
    );
    let mut named = BTreeMap::new();
    named.insert("first".to_owned(), 101);
    named.insert("second".to_owned(), 202);
    let inputs = RelocationInputs {
        named_maps: &named,
        section_maps: &BTreeMap::new(),
    };
    let relocated = apply_relocations(&bytes, &contract(), &inputs, &limits()).expect("relocate");
    let (_, regs, imm, _) = slot_fields(relocated.bytes(), text_file_offset(&bytes), 0);
    assert_eq!(regs >> 4, 1);
    assert_eq!(imm, 202);

    let data_case = &doc["cases"][3];
    assert_eq!(data_case["name"], "global-data-fallback");
    let (bytes, _, _) = reloc_object(&[], 32, &[(12, RelSym::Section)], 0);
    let mut sections = BTreeMap::new();
    sections.insert(".maps".to_owned(), 303);
    let inputs = RelocationInputs {
        named_maps: &BTreeMap::new(),
        section_maps: &sections,
    };
    let relocated = apply_relocations(&bytes, &contract(), &inputs, &limits()).expect("relocate");
    let (_, regs, imm, next) = slot_fields(relocated.bytes(), text_file_offset(&bytes), 0);
    assert_eq!(
        regs >> 4,
        data_case["relocs"][0]["expect_src"].as_u64().unwrap() as u8
    );
    assert_eq!(imm, 303);
    assert_eq!(next, 12);
    assert!(matches!(
        relocated.applied()[0].action(),
        RelocationAction::MapValue {
            value_offset: 12,
            ..
        }
    ));
}

#[test]
fn interior_missing_and_ambiguous_offsets_refuse() {
    let doc = repo_text("fixtures/bpf/object-graph/malformed/mutants.json");
    let refusals = doc["refusals"].as_array().unwrap();
    for entry in refusals.iter().take(5) {
        let addend = entry["reloc_addend"].as_u64().unwrap();
        let (bytes, _, _) = reloc_object(
            &[("first", 40), ("second", 0)],
            64,
            &[(addend as u32 as i32, RelSym::Section)],
            0,
        );
        let mut named = BTreeMap::new();
        named.insert("first".to_owned(), 101);
        named.insert("second".to_owned(), 202);
        let inputs = RelocationInputs {
            named_maps: &named,
            section_maps: &BTreeMap::new(),
        };
        let error = apply_relocations(&bytes, &contract(), &inputs, &limits()).unwrap_err();
        assert_eq!(
            refusal(&error),
            (ErrorKind::InvalidInput, Stage::Inspect),
            "{}",
            entry["name"]
        );
        assert!(message(&error).contains("offset"), "{}", message(&error));
    }
    // Two definitions at the same boundary are ambiguous, never first-wins.
    let (bytes, _, _) = reloc_object(
        &[("first", 0), ("second", 0)],
        64,
        &[(0, RelSym::Section)],
        0,
    );
    let mut named = BTreeMap::new();
    named.insert("first".to_owned(), 101);
    named.insert("second".to_owned(), 202);
    let inputs = RelocationInputs {
        named_maps: &named,
        section_maps: &BTreeMap::new(),
    };
    let error = apply_relocations(&bytes, &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Inspect));
    assert!(message(&error).contains("mbiguous"), "{}", message(&error));
}

#[test]
fn relocation_arithmetic_and_shape_refusals() {
    let named = BTreeMap::from([("first".to_owned(), 101), ("second".to_owned(), 202)]);
    let empty = BTreeMap::new();
    // Address overflow: section base u64::MAX plus addend 1.
    let (bytes, _, _) = reloc_object(&[("first", 0)], 64, &[(1, RelSym::Section)], u64::MAX);
    let inputs = RelocationInputs {
        named_maps: &named,
        section_maps: &empty,
    };
    let error = apply_relocations(&bytes, &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::Overflow, Stage::Inspect));
    // Dangling symbol index.
    let (bytes, _, _) = reloc_object(&[("first", 0)], 64, &[(0, RelSym::Index(99))], 0);
    let error = apply_relocations(&bytes, &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Inspect));
    assert!(message(&error).contains("symbol"), "{}", message(&error));
    // Relocation outside its target section.
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, exit_slot().to_vec());
    let maps = builder.section(".maps", 1, 0, vec![0u8; 64]);
    let section_sym = builder.symbol(
        ".maps",
        bind_type(STB_LOCAL, STT_SECTION),
        maps as u16,
        0,
        0,
    );
    builder.symbol(
        "first",
        bind_type(STB_GLOBAL, STT_OBJECT),
        maps as u16,
        0,
        28,
    );
    builder.reloc(text, &[(8, section_sym, R_BPF_64_64)]);
    let error = apply_relocations(&builder.build(), &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Inspect));
    assert!(message(&error).contains("outside"), "{}", message(&error));
    // Map relocation against a non-LD_imm64 slot.
    let mut builder = ObjBuilder::new();
    let mut code = exit_slot().to_vec();
    code.extend_from_slice(&exit_slot());
    let text = builder.section(".text", 1, 0x4, code);
    let maps = builder.section(".maps", 1, 0, vec![0u8; 64]);
    let section_sym = builder.symbol(
        ".maps",
        bind_type(STB_LOCAL, STT_SECTION),
        maps as u16,
        0,
        0,
    );
    builder.symbol(
        "first",
        bind_type(STB_GLOBAL, STT_OBJECT),
        maps as u16,
        0,
        28,
    );
    builder.reloc(text, &[(0, section_sym, R_BPF_64_64)]);
    let error = apply_relocations(&builder.build(), &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Inspect));
    assert!(message(&error).contains("slot"), "{}", message(&error));
    // Unknown relocation type.
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, ld_imm64(0));
    let maps = builder.section(".maps", 1, 0, vec![0u8; 64]);
    let section_sym = builder.symbol(
        ".maps",
        bind_type(STB_LOCAL, STT_SECTION),
        maps as u16,
        0,
        0,
    );
    builder.symbol(
        "first",
        bind_type(STB_GLOBAL, STT_OBJECT),
        maps as u16,
        0,
        28,
    );
    builder.reloc(text, &[(0, section_sym, 7)]);
    let error = apply_relocations(&builder.build(), &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Inspect));
    assert!(message(&error).contains("type"), "{}", message(&error));
}

#[test]
fn absolute_data_relocations_apply_with_checked_arithmetic() {
    // S = 16 with implicit addends 4 (u64) and 8 (u32).
    let mut builder = ObjBuilder::new();
    let data = builder.section(".data", 1, 0, vec![0u8; 32]);
    let maps = builder.section(".maps", 1, 0, vec![0u8; 64]);
    let sym = builder.symbol(
        "first",
        bind_type(STB_GLOBAL, STT_OBJECT),
        maps as u16,
        16,
        28,
    );
    let mut body = vec![0u8; 32];
    body[0..8].copy_from_slice(&4u64.to_le_bytes());
    body[8..12].copy_from_slice(&8u32.to_le_bytes());
    builder.sections[data].data = body;
    let rel = builder.reloc(data, &[(0, sym, R_BPF_64_ABS64), (8, sym, R_BPF_64_ABS32)]);
    builder.sections[rel].name = ".rel.data".to_owned();
    let bytes = builder.build();
    let inputs = RelocationInputs {
        named_maps: &BTreeMap::new(),
        section_maps: &BTreeMap::new(),
    };
    let relocated = apply_relocations(&bytes, &contract(), &inputs, &limits()).expect("relocate");
    assert_eq!(relocated.applied().len(), 2);
    // .data is the first body at file offset 64: 16+4 and 16+8.
    let out = relocated.bytes();
    assert_eq!(u64::from_le_bytes(out[64..72].try_into().unwrap()), 20);
    assert_eq!(u32::from_le_bytes(out[72..76].try_into().unwrap()), 24);
    assert!(matches!(
        relocated.applied()[0].action(),
        RelocationAction::Abs64 { value: 20 }
    ));
    // ABS32 that does not fit 32 bits refuses with overflow.
    let mut builder = ObjBuilder::new();
    let data = builder.section(".data", 1, 0, vec![0u8; 32]);
    let maps = builder.section(".maps", 1, 0, vec![0u8; 64]);
    let sym = builder.symbol(
        "first",
        bind_type(STB_GLOBAL, STT_OBJECT),
        maps as u16,
        0xffff_fff0,
        28,
    );
    let mut body = vec![0u8; 32];
    body[0..4].copy_from_slice(&0x20u32.to_le_bytes());
    builder.sections[data].data = body;
    let rel = builder.reloc(data, &[(0, sym, R_BPF_64_ABS32)]);
    builder.sections[rel].name = ".rel.data".to_owned();
    let error = apply_relocations(&builder.build(), &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::Overflow, Stage::Inspect));
}

#[test]
fn nodyld_relocations_are_preserved_not_resolved() {
    let btf = maps_btf();
    let mut builder = ObjBuilder::new();
    let btf_sec = builder.section(".BTF", 1, 0, btf.clone());
    let maps = builder.section(".maps", 1, 0, vec![0u8; 64]);
    let sym = builder.symbol(
        "first",
        bind_type(STB_GLOBAL, STT_OBJECT),
        maps as u16,
        0,
        28,
    );
    let rel = builder.reloc(btf_sec, &[(24, sym, R_BPF_64_NODYLD32)]);
    builder.sections[rel].name = ".rel.BTF".to_owned();
    let bytes = builder.build();
    let inputs = RelocationInputs {
        named_maps: &BTreeMap::new(),
        section_maps: &BTreeMap::new(),
    };
    let relocated = apply_relocations(&bytes, &contract(), &inputs, &limits()).expect("preserve");
    assert_eq!(relocated.applied().len(), 1);
    assert!(matches!(
        relocated.applied()[0].action(),
        RelocationAction::PreservedNodyld
    ));
    assert_eq!(relocated.bytes(), &bytes);
    assert_eq!(relocated.output_sha256(), &digest(&bytes));
    // The same relocation outside .BTF/.BTF.ext refuses.
    let mut builder = ObjBuilder::new();
    let data = builder.section(".data", 1, 0, vec![0u8; 32]);
    let maps = builder.section(".maps", 1, 0, vec![0u8; 64]);
    let sym = builder.symbol(
        "first",
        bind_type(STB_GLOBAL, STT_OBJECT),
        maps as u16,
        0,
        28,
    );
    let rel = builder.reloc(data, &[(0, sym, R_BPF_64_NODYLD32)]);
    builder.sections[rel].name = ".rel.data".to_owned();
    let error = apply_relocations(&builder.build(), &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Inspect));
}

#[test]
fn rela_sections_refuse_as_unsupported() {
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, ld_imm64(0));
    builder.symbol(
        "first",
        bind_type(STB_GLOBAL, STT_OBJECT),
        text as u16,
        0,
        28,
    );
    let mut rela = Vec::new();
    rela.extend_from_slice(&0u64.to_le_bytes());
    rela.extend_from_slice(&(((1u64) << 32) | 1u64).to_le_bytes());
    rela.extend_from_slice(&0i64.to_le_bytes());
    let index = builder.section(".rela.text", 4, 0, rela);
    builder.sections[index].info = text as u32;
    let inputs = RelocationInputs {
        named_maps: &BTreeMap::new(),
        section_maps: &BTreeMap::new(),
    };
    let error = apply_relocations(&builder.build(), &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::Unsupported, Stage::Inspect));
    assert!(message(&error).contains("rela"), "{}", message(&error));
}

#[test]
fn call_relocation_resolves_function_start() {
    // main @0 calls sub @16; the CALL slot carries a 64_32 relocation.
    let mut code = Vec::new();
    code.extend_from_slice(&slot(0x85, 0x10, 0, 0)); // imm patched by relocation
    code.extend_from_slice(&exit_slot());
    code.extend_from_slice(&exit_slot()); // sub @16
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, code);
    builder.symbol("main", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 16);
    let sub = builder.symbol("sub", bind_type(STB_LOCAL, STT_FUNC), text as u16, 16, 8);
    builder.reloc(text, &[(0, sub, R_BPF_64_32)]);
    let inputs = RelocationInputs {
        named_maps: &BTreeMap::new(),
        section_maps: &BTreeMap::new(),
    };
    let relocated = apply_relocations(&builder.build(), &contract(), &inputs, &limits())
        .expect("relocate call");
    let out = relocated.bytes();
    let off = text_file_offset(out) as usize;
    let imm = i32::from_le_bytes(out[off + 4..off + 8].try_into().unwrap());
    assert_eq!(imm, 1); // (16 + 0) / 8 - 1
    assert!(matches!(
        relocated.applied()[0].action(),
        RelocationAction::Call { target: 16 }
    ));
    // Misaligned call target refuses.
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, slot(0x85, 0x10, 0, 0).to_vec());
    builder.symbol("main", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 8);
    let sub = builder.symbol("sub", bind_type(STB_LOCAL, STT_FUNC), text as u16, 4, 8);
    builder.reloc(text, &[(0, sub, R_BPF_64_32)]);
    let error = apply_relocations(&builder.build(), &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Inspect));
    assert!(message(&error).contains("aligned"), "{}", message(&error));
}

#[test]
fn emitted_objects_without_relocations_pass_through() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let inputs = RelocationInputs {
        named_maps: &BTreeMap::new(),
        section_maps: &BTreeMap::new(),
    };
    let relocated = apply_relocations(&bytes, &contract(), &inputs, &limits()).expect("no relocs");
    assert!(relocated.applied().is_empty());
    assert_eq!(relocated.bytes(), &bytes);
    assert_eq!(relocated.output_sha256(), &digest(&bytes));
}

#[test]
fn call_graph_links_helpers_and_subprograms() {
    let doc = repo_text("fixtures/bpf/object-graph/callbacks/expected.json");
    let graph = &doc["graphs"][0];
    assert_eq!(graph["name"], "helper-and-subprogram");
    // main: call helper 1; pseudo-call +1 (sub); exit. sub: exit.
    let mut code = Vec::new();
    code.extend_from_slice(&slot(0x85, 0x00, 0, 1));
    code.extend_from_slice(&slot(0x85, 0x10, 0, 1));
    code.extend_from_slice(&exit_slot());
    code.extend_from_slice(&exit_slot());
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, code);
    builder.symbol("main", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 24);
    builder.symbol("sub", bind_type(STB_LOCAL, STT_FUNC), text as u16, 24, 8);
    let bytes = builder.build();
    let manifest = FinalObjectManifest::from_json(
        manifest_json("tc05-calls", "rel", &hex(&digest(&bytes))).as_bytes(),
        &limits(),
    )
    .expect("manifest");
    manifest
        .admit("tc05-calls", &bytes, &limits())
        .expect("admit");
    let graph_out = extract_call_graph(&bytes, &contract(), &limits()).expect("graph");
    assert!(graph_out.conforms());
    assert_eq!(graph_out.functions().len(), 2);
    assert_eq!(graph_out.functions()[0].name(), "main");
    assert!(graph_out.functions()[0].global());
    assert!(!graph_out.has_cycle());
    assert_eq!(graph_out.edges().len(), 2);
    assert!(matches!(
        graph_out.edges()[0].target(),
        CallTarget::Helper { id: 1 }
    ));
    assert_eq!(graph_out.edges()[0].offset(), 0);
    match graph_out.edges()[1].target() {
        CallTarget::Local { function } => {
            assert_eq!(graph_out.functions()[function].name(), "sub")
        }
        other => panic!("expected local edge, got {other:?}"),
    }
    assert_eq!(graph_out.edges()[1].caller(), 0);
    assert_eq!(graph["has_cycle"], false);
}

#[test]
fn call_graph_violations_name_dangling_interior_and_unaligned() {
    // Dangling: pseudo-call past the end.
    let mut code = Vec::new();
    code.extend_from_slice(&slot(0x85, 0x10, 0, 9));
    code.extend_from_slice(&exit_slot());
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, code);
    builder.symbol("main", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 16);
    let graph = extract_call_graph(&builder.build(), &contract(), &limits()).expect("graph");
    assert!(!graph.conforms());
    assert_eq!(graph.violations().len(), 1);
    assert_eq!(graph.violations()[0].rule_id, "call.dangling-target");
    // Interior: pseudo-call lands mid-function.
    let mut code = Vec::new();
    code.extend_from_slice(&slot(0x85, 0x10, 0, 0)); // targets slot 1, inside main
    code.extend_from_slice(&exit_slot());
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, code);
    builder.symbol("main", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 16);
    let graph = extract_call_graph(&builder.build(), &contract(), &limits()).expect("graph");
    assert_eq!(graph.violations().len(), 1);
    assert_eq!(graph.violations()[0].rule_id, "call.interior-target");
    // Unaligned function start.
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, exit_slot().to_vec());
    builder.symbol("odd", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 4, 8);
    let graph = extract_call_graph(&builder.build(), &contract(), &limits()).expect("graph");
    assert_eq!(graph.violations().len(), 1);
    assert_eq!(graph.violations()[0].rule_id, "call.unaligned-function");
}

#[test]
fn call_graph_cycles_terminate_and_report() {
    let doc = repo_text("fixtures/bpf/object-graph/callbacks/expected.json");
    assert_eq!(doc["graphs"][1]["name"], "self-recursion");
    assert_eq!(doc["graphs"][2]["name"], "mutual-recursion");
    // Self recursion: slot 0 calls slot 0 (imm -1).
    let mut code = Vec::new();
    code.extend_from_slice(&slot(0x85, 0x10, 0, -1));
    code.extend_from_slice(&exit_slot());
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, code);
    builder.symbol("rloop", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 16);
    let graph = extract_call_graph(&builder.build(), &contract(), &limits()).expect("graph");
    assert!(graph.conforms());
    assert!(graph.has_cycle());
    assert_eq!(graph.cycle_path(), &[0]);
    // Mutual recursion.
    let mut code = Vec::new();
    code.extend_from_slice(&slot(0x85, 0x10, 0, 1)); // ping -> pong @16
    code.extend_from_slice(&exit_slot());
    code.extend_from_slice(&slot(0x85, 0x10, 0, -3)); // pong -> ping @0
    code.extend_from_slice(&exit_slot());
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, code);
    builder.symbol("ping", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 16);
    builder.symbol("pong", bind_type(STB_LOCAL, STT_FUNC), text as u16, 16, 16);
    let graph = extract_call_graph(&builder.build(), &contract(), &limits()).expect("graph");
    assert!(graph.has_cycle());
    assert_eq!(graph.cycle_path().len(), 2);
}

#[test]
fn call_graph_traversal_is_work_bounded() {
    // A long call-free chain still charges per slot; a tiny budget refuses.
    let mut code = Vec::new();
    for _ in 0..32 {
        code.extend_from_slice(&slot(0xb7, 0x00, 0, 0));
    }
    code.extend_from_slice(&exit_slot());
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, code);
    builder.symbol(
        "long",
        bind_type(STB_GLOBAL, STT_FUNC),
        text as u16,
        0,
        33 * 8,
    );
    let bytes = builder.build();
    let error = extract_call_graph(&bytes, &contract(), &tiny_limits(4)).unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::LimitExceeded, Stage::Inspect));
    // The same object passes with a real budget.
    let graph = extract_call_graph(&bytes, &contract(), &limits()).expect("graph");
    assert!(graph.conforms());
    assert!(!graph.has_cycle());
}

#[test]
fn call_graph_reads_emitted_objects() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base.o");
    let graph = extract_call_graph(&bytes, &contract(), &limits()).expect("base.o graph");
    let _ = graph;
    let bytes = repo_bytes("fixtures/bpf/isa/objects/base-be.o");
    let big =
        ObjectContract::from_json(contract_json("big").as_bytes(), &limits()).expect("contract");
    let graph = extract_call_graph(&bytes, &big, &limits()).expect("base-be.o graph");
    let _ = graph;
}

#[test]
fn callbacks_resolve_func_proto_linkage() {
    let doc = repo_text("fixtures/bpf/object-graph/callbacks/expected.json");
    let view = parse_btf(&shapes_btf());
    let expected: Vec<CallbackSpec> = doc["callbacks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|callback| CallbackSpec {
            name: callback["name"].as_str().unwrap().to_owned(),
        })
        .collect();
    let report = verify_callbacks(&view, &expected).expect("callbacks");
    assert!(report.violations().is_empty());
    assert_eq!(report.links().len(), 2);
    for (link, callback) in report
        .links()
        .iter()
        .zip(doc["callbacks"].as_array().unwrap())
    {
        assert_eq!(link.name(), callback["name"].as_str().unwrap());
        assert_eq!(link.func().id, callback["func"].as_u64().unwrap() as u32);
        assert_eq!(
            link.result().id,
            callback["result"].as_u64().unwrap() as u32
        );
        let params: Vec<u32> = link.parameters().iter().map(|r| r.id).collect();
        let wanted: Vec<u32> = callback["params"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(params, wanted);
        assert_eq!(link.variadic(), callback["variadic"].as_bool().unwrap());
    }
    // Missing and non-function names become violations, not silent drops.
    let report = verify_callbacks(
        &view,
        &[CallbackSpec {
            name: "no_such_callback".to_owned(),
        }],
    )
    .expect("report");
    assert_eq!(report.violations().len(), 1);
    assert_eq!(report.violations()[0].rule_id, "callback.missing");
    let report = verify_callbacks(
        &view,
        &[CallbackSpec {
            name: "u32".to_owned(),
        }],
    )
    .expect("report");
    assert_eq!(report.violations().len(), 1);
    assert_eq!(report.violations()[0].rule_id, "callback.not-function");
}

fn metadata_object(btf: &[u8], with_ext: bool, with_debug: bool, with_license: bool) -> Vec<u8> {
    let mut builder = ObjBuilder::new();
    let text = builder.section(".text", 1, 0x4, exit_slot().to_vec());
    builder.symbol("main", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 8);
    builder.section(".maps", 1, 0, vec![0u8; 64]);
    builder.section(".BTF", 1, 0, btf.to_vec());
    if with_ext {
        builder.section(".BTF.ext", 1, 0, vec![1u8; 32]);
    }
    if with_debug {
        builder.section(".debug_info", 1, 0, vec![2u8; 48]);
    }
    if with_license {
        builder.section("license", 1, 0, b"GPL\0".to_vec());
    }
    builder.build()
}

fn snapshot_of(bytes: &[u8], view: &BtfView) -> scopebase_testkit::object::graph::MetadataSnapshot {
    let inputs = MetadataInputs {
        btf: Some(view),
        required_maps: &["my_map"],
        required_types: &["my_map"],
    };
    snapshot_metadata(bytes, &contract(), &inputs, &limits()).expect("snapshot")
}

/// Locate the `size_or_type` field of BTF type id 3 (the key PTR) by
/// walking the record stream; no magic file offsets.
fn ptr3_field(image: &[u8]) -> usize {
    let hdr_len = u32::from_le_bytes(image[4..8].try_into().unwrap()) as usize;
    let type_off = u32::from_le_bytes(image[8..12].try_into().unwrap()) as usize;
    let mut at = hdr_len + type_off;
    for _ in 1..3 {
        let info = u32::from_le_bytes(image[at + 4..at + 8].try_into().unwrap());
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let aux = match kind {
            1 | 14 | 17 => 4,
            3 => 12,
            4 | 5 => vlen * 12,
            6 => vlen * 8,
            13 => vlen * 8,
            15 => vlen * 12,
            19 => vlen * 16,
            _ => 0,
        };
        at += 12 + aux;
    }
    at + 8
}

#[test]
fn metadata_snapshot_records_sections_and_btf_linkage() {
    let doc = repo_text("fixtures/bpf/metadata/expected.json");
    let bytes = metadata_object(&maps_btf(), true, true, true);
    let view = parse_btf(&maps_btf());
    let before = snapshot_of(&bytes, &view);
    for name in doc["required_sections"].as_array().unwrap() {
        let section = before
            .sections()
            .iter()
            .find(|s| s.name() == name.as_str().unwrap())
            .unwrap_or_else(|| panic!("missing section {name}"));
        assert!(section.size() > 0, "section {name} must be nonempty");
    }
    assert_eq!(before.maps().len(), 1);
    assert_eq!(before.maps()[0].name(), "my_map");
    assert_eq!(
        before.maps()[0].key().id,
        doc["map_linkage"]["my_map"]["key"].as_u64().unwrap() as u32
    );
    assert_eq!(
        before.maps()[0].value().id,
        doc["map_linkage"]["my_map"]["value"].as_u64().unwrap() as u32
    );
    assert_eq!(before.types().len(), 1);
    let wanted: Vec<u32> = doc["named_types"]["my_map"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u32)
        .collect();
    assert_eq!(before.types()[0].ids(), &wanted);
    // An identical twin preserves everything: the diff is empty.
    let twin = metadata_object(&maps_btf(), true, true, true);
    let after = snapshot_of(&twin, &parse_btf(&maps_btf()));
    assert!(diff_metadata(&before, &after).is_empty());
}

#[test]
fn dropped_debug_sections_are_detected_as_loss() {
    let doc = repo_text("fixtures/bpf/metadata/mutants.json");
    let bytes = metadata_object(&maps_btf(), true, true, true);
    let before = snapshot_of(&bytes, &parse_btf(&maps_btf()));
    for mutant in doc["section_loss"].as_array().unwrap() {
        let drop: Vec<&str> = mutant["drop"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let stripped = metadata_object(
            &maps_btf(),
            !drop.contains(&".BTF.ext"),
            !drop.contains(&".debug_info"),
            true,
        );
        let stripped = if drop.contains(&".BTF") {
            let mut builder = ObjBuilder::new();
            let text = builder.section(".text", 1, 0x4, exit_slot().to_vec());
            builder.symbol("main", bind_type(STB_GLOBAL, STT_FUNC), text as u16, 0, 8);
            builder.section(".maps", 1, 0, vec![0u8; 64]);
            builder.section(".BTF.ext", 1, 0, vec![1u8; 32]);
            builder.section(".debug_info", 1, 0, vec![2u8; 48]);
            builder.section("license", 1, 0, b"GPL\0".to_vec());
            builder.build()
        } else {
            stripped
        };
        // Without .BTF the view cannot bind; snapshot with no view still
        // records the section inventory so the loss is visible.
        let inputs = MetadataInputs {
            btf: if drop.contains(&".BTF") {
                None
            } else {
                Some(&parse_btf(&maps_btf()))
            },
            required_maps: if drop.contains(&".BTF") {
                &[]
            } else {
                &["my_map"]
            },
            required_types: if drop.contains(&".BTF") {
                &[]
            } else {
                &["my_map"]
            },
        };
        let after =
            snapshot_metadata(&stripped, &contract(), &inputs, &limits()).expect("snapshot");
        let loss = diff_metadata(&before, &after);
        assert!(!loss.is_empty(), "{}", mutant["name"]);
        assert!(
            loss.iter()
                .any(|l| l.kind() == mutant["loss"].as_str().unwrap()
                    && l.detail().contains(drop[0])),
            "{loss:?}"
        );
    }
    // An emptied (not dropped) .BTF section is a change, not preservation:
    // verdicts come from bytes, never from a zero exit status.
    let emptied = metadata_object(&[], true, true, true);
    let inputs = MetadataInputs {
        btf: None,
        required_maps: &[],
        required_types: &[],
    };
    let after = snapshot_metadata(&emptied, &contract(), &inputs, &limits()).expect("snapshot");
    let loss = diff_metadata(&before, &after);
    assert!(loss
        .iter()
        .any(|l| l.kind() == "section.changed" && l.detail().contains(".BTF")));
}

#[test]
fn lost_and_relinked_btf_types_are_detected() {
    let bytes = metadata_object(&maps_btf(), true, true, true);
    let before = snapshot_of(&bytes, &parse_btf(&maps_btf()));
    // A transformation that swaps in shapes.bin loses my_map entirely.
    let shapes = shapes_btf();
    let after_bytes = metadata_object(&shapes, true, true, true);
    let inputs = MetadataInputs {
        btf: Some(&parse_btf(&shapes)),
        required_maps: &[],
        required_types: &["my_map"],
    };
    let after = snapshot_metadata(&after_bytes, &contract(), &inputs, &limits()).expect("snapshot");
    let loss = diff_metadata(&before, &after);
    assert!(
        loss.iter()
            .any(|l| l.kind() == "type.lost" && l.detail().contains("my_map")),
        "{loss:?}"
    );
    // A key widened from u32 to u64 keeps the map but relinks it.
    let mut relinked = maps_btf();
    let field = ptr3_field(&relinked);
    relinked[field..field + 4].copy_from_slice(&2u32.to_le_bytes());
    let relinked_bytes = metadata_object(&relinked, true, true, true);
    let inputs = MetadataInputs {
        btf: Some(&parse_btf(&relinked)),
        required_maps: &["my_map"],
        required_types: &["my_map"],
    };
    let after =
        snapshot_metadata(&relinked_bytes, &contract(), &inputs, &limits()).expect("snapshot");
    assert_eq!(after.maps()[0].key().id, 2);
    let loss = diff_metadata(&before, &after);
    assert!(
        loss.iter()
            .any(|l| l.kind() == "map.relinked" && l.detail().contains("my_map")),
        "{loss:?}"
    );
}

#[test]
fn void_unlinked_and_valueless_map_linkage_refuses() {
    let doc = repo_text("fixtures/bpf/metadata/mutants.json");
    let bytes = metadata_object(&maps_btf(), true, true, true);
    // Same-size map whose key PTR aims at void: map_types must refuse.
    let mut voided = maps_btf();
    let field = ptr3_field(&voided);
    assert_eq!(
        u32::from_le_bytes(voided[field..field + 4].try_into().unwrap()),
        1
    );
    voided[field..field + 4].copy_from_slice(&0u32.to_le_bytes());
    let view = parse_btf(&voided);
    let inputs = MetadataInputs {
        btf: Some(&view),
        required_maps: &["my_map"],
        required_types: &[],
    };
    let error = snapshot_metadata(&bytes, &contract(), &inputs, &limits()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Malformed, "{}", message(&error));
    assert_eq!(doc["btf_refusals"][0]["kind"], "Malformed");
    // Unlinked VAR and valueless definition refuse the same way.
    let view = parse_btf(&maps_btf());
    for (map, entry) in ["orphan_map", "broken_map"]
        .iter()
        .zip(doc["btf_refusals"].as_array().unwrap().iter().skip(1))
    {
        assert_eq!(entry["map"], *map);
        let inputs = MetadataInputs {
            btf: Some(&view),
            required_maps: &[map],
            required_types: &[],
        };
        let error = snapshot_metadata(&bytes, &contract(), &inputs, &limits()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed, "{map}: {error:?}");
    }
}
