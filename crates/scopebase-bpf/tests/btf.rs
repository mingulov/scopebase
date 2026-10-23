// SPDX-License-Identifier: Apache-2.0
//! BP09: bounded domain-aware BTF parser adaptation over locked btf-rs.
//!
//! ADAPT (behavior reference only, no lines copied): KryProbe
//! `kryprobe/crates/kryprobe-privilege/src/btf.rs` at frozen
//! `d153f3aaf9a3931337b47c9e1b046c692da55083` (strict header/record walk,
//! wrapper-chase depth cap, exact prototype/member discipline, split string
//! bias). The parser itself is the locked third-party btf-rs 2.0.0 at
//! `0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0` (see Cargo.toml); all budgets
//! are enforced by the ScopeBase preflight wrapper, never by upstream.
//!
//! B04 trial corpus slice binding (executor choice, BP09): T1 rival-name
//! base/split twins (`base-rivals.bin`, `split-extra.bin`), T2 the admitted
//! BP02 `btf-u32-u64.bin` linkage fixture, T3 authored shape/hostile graphs
//! (`shapes.bin`, `maps.bin`, `cycle.bin`) plus byte-surgery mutants built
//! in this file. Expected truth comes from `graphs.json`/`expected.json`,
//! never from parser roundtrip.

use scopebase_bpf::btf::{
    BtfDomainId, BtfImages, BtfLimits, BtfView, ByteOrder, TypeKind, TypeRef,
    BTF_PROFILE_MAX_IMAGE_BYTES,
};
use scopebase_bpf::{ErrorKind, OperationError, Stage};

#[path = "support/json_mini.rs"]
mod json_mini;
use json_mini::Json;

const BASE_RIVALS: &[u8] = include_bytes!("../fixtures/btf-v1/images/base-rivals.bin");
const SPLIT_EXTRA: &[u8] = include_bytes!("../fixtures/btf-v1/images/split-extra.bin");
const SHAPES: &[u8] = include_bytes!("../fixtures/btf-v1/images/shapes.bin");
const MAPS: &[u8] = include_bytes!("../fixtures/btf-v1/images/maps.bin");
const CYCLE: &[u8] = include_bytes!("../fixtures/btf-v1/images/cycle.bin");
const BP02_U32_U64: &[u8] = include_bytes!("fixtures/bp02/btf-u32-u64.bin");
const EXPECTED: &str = include_str!("../fixtures/btf-v1/expected.json");
const GRAPHS: &str = include_str!("../fixtures/btf-v1/graphs.json");

fn limits() -> BtfLimits {
    BtfLimits {
        image_bytes: 1 << 20,
        types: 4096,
        strings: 1 << 20,
        wrapper_depth: 16,
        work_steps: 1_000_000,
    }
}

fn parse_base(bytes: &[u8]) -> Result<BtfView, OperationError> {
    BtfView::parse(
        BtfImages {
            base: bytes,
            module: None,
            byte_order: ByteOrder::Little,
        },
        limits(),
    )
}

fn parse_split(base: &[u8], module: &[u8]) -> Result<BtfView, OperationError> {
    BtfView::parse(
        BtfImages {
            base,
            module: Some(module),
            byte_order: ByteOrder::Little,
        },
        limits(),
    )
}

fn ids_of(refs: &[TypeRef]) -> Vec<u32> {
    refs.iter().map(|r| r.id).collect()
}

fn expect_error(error: &OperationError, kind: ErrorKind, stage: Stage) {
    assert_eq!(error.kind(), kind, "error kind for {error:?}");
    assert_eq!(error.stage(), stage, "error stage for {error:?}");
}

fn expected_root() -> Json {
    let root = json_mini::parse(EXPECTED).expect("expected.json parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    root
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn write_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn type_section(bytes: &[u8]) -> (usize, usize) {
    let hdr_len = read_u32(bytes, 4) as usize;
    let type_off = read_u32(bytes, 8) as usize;
    let type_len = read_u32(bytes, 12) as usize;
    (hdr_len + type_off, type_len)
}

#[test]
fn views_and_refs_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BtfView>();
    assert_send_sync::<BtfDomainId>();
    assert_send_sync::<TypeRef>();
    assert_send_sync::<BtfLimits>();
    assert_send_sync::<scopebase_bpf::btf::TypeShape>();
    assert_send_sync::<scopebase_bpf::btf::MemberExtent>();
    assert_send_sync::<scopebase_bpf::btf::FunctionShape>();
}

#[test]
fn rival_names_return_all_candidates_sorted() {
    let view = parse_base(BASE_RIVALS).expect("rivals parse");
    let refs = view.types_named("dup").expect("rival lookup");
    assert_eq!(ids_of(&refs), vec![1, 2]);
    for r in &refs {
        assert_eq!(r.domain, view.domain_id());
    }
    // The anonymous pointer is addressable by the empty name only.
    assert_eq!(ids_of(&view.types_named("").expect("anon lookup")), vec![3]);
    assert!(view.types_named("zzz").expect("missing name").is_empty());
}

#[test]
fn rival_shapes_match_expected_graph() {
    let root = expected_root();
    let graph = root.get("base_rivals").unwrap();
    let view = parse_base(BASE_RIVALS).expect("rivals parse");
    let domain = view.domain_id();
    let int1 = graph.get("int1").unwrap();
    let shape = view
        .shape(TypeRef { domain, id: 1 })
        .expect("shape of ID 1");
    assert!(matches!(
        shape.kind,
        TypeKind::Integer {
            bits: 32,
            signed: true
        }
    ));
    assert_eq!(shape.size_bytes, Some(4));
    assert_eq!(int1.get("bits").unwrap().as_u64().unwrap(), 32);
    let shape = view
        .shape(TypeRef { domain, id: 2 })
        .expect("shape of ID 2");
    assert!(matches!(
        shape.kind,
        TypeKind::Integer {
            bits: 64,
            signed: false
        }
    ));
    assert_eq!(shape.size_bytes, Some(8));
    let shape = view
        .shape(TypeRef { domain, id: 3 })
        .expect("shape of ID 3");
    match shape.kind {
        TypeKind::Pointer { to } => assert_eq!(to.id, 1),
        other => panic!("ID 3 must be a pointer, found {other:?}"),
    }
    assert_eq!(shape.size_bytes, Some(8));
    // Pointers are not wrappers: canonical identity is the pointer itself.
    let canon = view
        .canonical(TypeRef { domain, id: 3 })
        .expect("pointer canonical");
    assert_eq!(canon.id, 3);
}

#[test]
fn split_domain_routes_base_and_module_ids() {
    let root = expected_root();
    let split = root.get("split_extra").unwrap();
    let base_view = parse_base(BASE_RIVALS).expect("base parses");
    let view = parse_split(BASE_RIVALS, SPLIT_EXTRA).expect("split parses");
    assert_ne!(base_view.domain_id(), view.domain_id());
    let domain = view.domain_id();
    // Base population stays visible under the split domain.
    assert_eq!(ids_of(&view.types_named("dup").expect("dup")), vec![1, 2]);
    // Module type relocates above the base population.
    let global = split.get("global_id").unwrap().as_u64().unwrap() as u32;
    assert_eq!(global, 4);
    let refs = view.types_named("split").expect("split lookup");
    assert_eq!(ids_of(&refs), vec![global]);
    let shape = view
        .shape(TypeRef { domain, id: global })
        .expect("split shape");
    assert!(matches!(
        shape.kind,
        TypeKind::Integer {
            bits: 64,
            signed: false
        }
    ));
    assert_eq!(shape.size_bytes, Some(8));
    // The base-only view cannot resolve the module id.
    let error = base_view
        .shape(TypeRef {
            domain: base_view.domain_id(),
            id: global,
        })
        .expect_err("base view must refuse module id");
    expect_error(&error, ErrorKind::InvalidInput, Stage::BtfQuery);
}

#[test]
fn parse_is_deterministic() {
    let first = parse_split(BASE_RIVALS, SPLIT_EXTRA).expect("first parse");
    let second = parse_split(BASE_RIVALS, SPLIT_EXTRA).expect("second parse");
    assert_eq!(first.domain_id(), second.domain_id());
    assert_eq!(
        ids_of(&first.types_named("dup").unwrap()),
        ids_of(&second.types_named("dup").unwrap())
    );
    let shapes = parse_base(SHAPES).expect("shapes parse");
    assert_ne!(shapes.domain_id(), first.domain_id());
}

#[test]
fn bp02_linkage_fixture_vectors() {
    // T2 slice: the admitted BP02 u32/u64 image keeps its key/value linkage.
    let view = parse_base(BP02_U32_U64).expect("bp02 image parses");
    let domain = view.domain_id();
    assert_eq!(ids_of(&view.types_named("u32").unwrap()), vec![1]);
    assert_eq!(ids_of(&view.types_named("u64").unwrap()), vec![2]);
    let key = view.shape(TypeRef { domain, id: 1 }).unwrap();
    assert!(matches!(
        key.kind,
        TypeKind::Integer {
            bits: 32,
            signed: false
        }
    ));
    assert_eq!(key.size_bytes, Some(4));
    let value = view.shape(TypeRef { domain, id: 2 }).unwrap();
    assert!(matches!(
        value.kind,
        TypeKind::Integer {
            bits: 64,
            signed: false
        }
    ));
    assert_eq!(value.size_bytes, Some(8));
}

#[test]
fn empty_base_is_invalid_input() {
    let error = BtfView::parse(
        BtfImages {
            base: &[],
            module: None,
            byte_order: ByteOrder::Little,
        },
        limits(),
    )
    .expect_err("empty base must refuse");
    expect_error(&error, ErrorKind::InvalidInput, Stage::Admission);
}

#[test]
fn big_endian_profile_is_unsupported() {
    let error = BtfView::parse(
        BtfImages {
            base: BASE_RIVALS,
            module: None,
            byte_order: ByteOrder::Big,
        },
        limits(),
    )
    .expect_err("big-endian must refuse in the initial profile");
    expect_error(&error, ErrorKind::Unsupported, Stage::Admission);
}

#[test]
fn oversize_profile_input_is_unsupported_before_parse() {
    const {
        assert!(BTF_PROFILE_MAX_IMAGE_BYTES >= (1 << 20));
    }
    let big = vec![0u8; BTF_PROFILE_MAX_IMAGE_BYTES + 1];
    let error = BtfView::parse(
        BtfImages {
            base: &big,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            image_bytes: usize::MAX,
            ..limits()
        },
    )
    .expect_err("profile ceiling refuses regardless of caller budget");
    expect_error(&error, ErrorKind::Unsupported, Stage::Admission);
}

#[test]
fn caller_image_budget_is_enforced() {
    let error = BtfView::parse(
        BtfImages {
            base: BASE_RIVALS,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            image_bytes: BASE_RIVALS.len() - 1,
            ..limits()
        },
    )
    .expect_err("image over caller budget must refuse");
    expect_error(&error, ErrorKind::LimitExceeded, Stage::Admission);
    let error = BtfView::parse(
        BtfImages {
            base: BASE_RIVALS,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            image_bytes: 0,
            ..limits()
        },
    )
    .expect_err("zero image budget refuses positive input");
    expect_error(&error, ErrorKind::LimitExceeded, Stage::Admission);
}

#[test]
fn type_and_string_budgets_are_enforced() {
    let error = BtfView::parse(
        BtfImages {
            base: SHAPES,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            types: 5,
            ..limits()
        },
    )
    .expect_err("type population over budget must refuse");
    expect_error(&error, ErrorKind::LimitExceeded, Stage::Admission);
    let error = BtfView::parse(
        BtfImages {
            base: SHAPES,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            strings: 4,
            ..limits()
        },
    )
    .expect_err("string section over budget must refuse");
    expect_error(&error, ErrorKind::LimitExceeded, Stage::Admission);
}

#[test]
fn zero_work_budget_refuses_parse() {
    let error = BtfView::parse(
        BtfImages {
            base: BASE_RIVALS,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            work_steps: 0,
            ..limits()
        },
    )
    .expect_err("zero work budget refuses positive parse work");
    expect_error(&error, ErrorKind::LimitExceeded, Stage::Admission);
}

#[test]
fn parse_work_budget_is_exact() {
    // White-box N/N+1 on the documented charging schedule: admission 1 +
    // header 1 + per-record (1 + aux units) + strtab closeout 1.
    // base-rivals holds two INT records (1 aux unit each) and one PTR
    // record (1 step, 0 aux units).
    let exact = 1 + 1 + (1 + 1) + (1 + 1) + 1 + 1;
    assert_eq!(exact, 8);
    BtfView::parse(
        BtfImages {
            base: BASE_RIVALS,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            work_steps: exact,
            ..limits()
        },
    )
    .expect("exact work budget parses");
    let error = BtfView::parse(
        BtfImages {
            base: BASE_RIVALS,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            work_steps: exact - 1,
            ..limits()
        },
    )
    .expect_err("one step short must refuse");
    expect_error(&error, ErrorKind::LimitExceeded, Stage::Admission);
}

#[test]
fn truncated_header_is_malformed() {
    for len in [1usize, 7, 12, 23] {
        let error = parse_base(&BASE_RIVALS[..len]).expect_err("short header must refuse");
        expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    }
}

#[test]
fn bad_magic_version_flags_refuse() {
    let mut magic = BASE_RIVALS.to_vec();
    magic[0] = 0x00;
    let error = parse_base(&magic).expect_err("bad magic must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    let mut version = BASE_RIVALS.to_vec();
    version[2] = 2;
    let error = parse_base(&version).expect_err("bad version must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    let mut flags = BASE_RIVALS.to_vec();
    flags[3] = 1;
    let error = parse_base(&flags).expect_err("nonzero flags must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    let mut hdr_len = BASE_RIVALS.to_vec();
    write_u32(&mut hdr_len, 4, 16);
    let error = parse_base(&hdr_len).expect_err("short hdr_len must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
}

#[test]
fn section_range_overflow_refuses() {
    for field in [8usize, 12, 16, 20] {
        let mut bytes = BASE_RIVALS.to_vec();
        write_u32(&mut bytes, field, u32::MAX);
        let error = parse_base(&bytes).expect_err("overflowing range refuses");
        expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    }
    // Empty string table cannot name anything.
    let mut bytes = BASE_RIVALS.to_vec();
    write_u32(&mut bytes, 20, 0);
    let error = parse_base(&bytes).expect_err("empty strtab must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
}

#[test]
fn truncated_records_refuse() {
    let (type_at, type_len) = type_section(BASE_RIVALS);
    // Cut inside the first record header.
    let error =
        parse_base(&BASE_RIVALS[..type_at + 7]).expect_err("truncated record header must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    // Cut inside the first record aux data.
    let error = parse_base(&BASE_RIVALS[..type_at + 13]).expect_err("truncated aux must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    // Declared section longer than the image.
    let mut bytes = BASE_RIVALS.to_vec();
    write_u32(&mut bytes, 12, type_len as u32 + 64);
    let error = parse_base(&bytes).expect_err("overlong section must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
}

#[test]
fn unknown_kind_and_bad_header_refs_refuse() {
    let (type_at, _) = type_section(BASE_RIVALS);
    // First unassigned kind.
    let mut kind = BASE_RIVALS.to_vec();
    let info = read_u32(&kind, type_at + 4);
    write_u32(&mut kind, type_at + 4, (info & 0xE0FF_FFFF) | (20 << 24));
    let error = parse_base(&kind).expect_err("unknown kind must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    // Kind zero is never a stored type.
    let mut zero = BASE_RIVALS.to_vec();
    write_u32(&mut zero, type_at + 4, info & 0xE0FF_FFFF);
    let error = parse_base(&zero).expect_err("kind zero must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    // Name offset past the string table.
    let mut name = BASE_RIVALS.to_vec();
    write_u32(&mut name, type_at, 0x0100_0000);
    let error = parse_base(&name).expect_err("name overflow must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    // INT with nonzero vlen.
    let mut vlen = BASE_RIVALS.to_vec();
    write_u32(&mut vlen, type_at + 4, info | 2);
    let error = parse_base(&vlen).expect_err("INT vlen must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
}

#[test]
fn bogus_func_linkage_refuses() {
    // FUNC vlen is linkage (0/1); anything else is corrupt.
    let bytes = SHAPES.to_vec();
    let (type_at, _) = type_section(&bytes);
    // Walk to ID 12 (do_work FUNC): sizes are fixed by the generator.
    let mut pos = type_at;
    for _ in 1..12u32 {
        let info = read_u32(&bytes, pos + 4);
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;
        let aux = match kind {
            1 | 14 | 17 => 4,
            3 => 12,
            4 | 5 | 15 => vlen * 12,
            6 | 13 => vlen * 8,
            _ => 0,
        };
        pos += 12 + aux;
    }
    let info = read_u32(&bytes, pos + 4);
    assert_eq!(((info >> 24) & 0x1F) as u8, 12, "expected FUNC at ID 12");
    let mut mutant = bytes.clone();
    write_u32(&mut mutant, pos + 4, (info & !0xFFFF) | 7);
    let error = parse_base(&mutant).expect_err("bogus linkage must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
}

#[test]
fn decl_tag_and_var_aux_rules_refuse() {
    // DECL_TAG carries a fixed 4-byte component index (vlen must be 0);
    // VAR carries linkage 0/1 with one aux word.
    let bytes = SHAPES.to_vec();
    let (type_at, _) = type_section(&bytes);
    let mut pos = type_at;
    for _ in 1..18u32 {
        let info = read_u32(&bytes, pos + 4);
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;
        let aux = match kind {
            1 | 14 | 17 => 4,
            3 => 12,
            4 | 5 | 15 => vlen * 12,
            6 | 13 => vlen * 8,
            _ => 0,
        };
        pos += 12 + aux;
    }
    let decl_tag_at = pos;
    let info = read_u32(&bytes, decl_tag_at + 4);
    assert_eq!(
        ((info >> 24) & 0x1F) as u8,
        17,
        "expected DECL_TAG at ID 18"
    );
    let mut mutant = bytes.clone();
    write_u32(&mut mutant, decl_tag_at + 4, info | 1);
    let error = parse_base(&mutant).expect_err("DECL_TAG vlen must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
    // VAR linkage beyond 0/1 is corrupt (maps.bin ID 6 is a VAR).
    let maps = MAPS.to_vec();
    let (maps_at, _) = type_section(&maps);
    let mut pos = maps_at;
    for _ in 1..6u32 {
        let info = read_u32(&maps, pos + 4);
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;
        let aux = match kind {
            1 => 4,
            3 => 12,
            4 | 5 => vlen * 12,
            _ => 0,
        };
        pos += 12 + aux;
    }
    let info = read_u32(&maps, pos + 4);
    assert_eq!(((info >> 24) & 0x1F) as u8, 14, "expected VAR at ID 6");
    let mut mutant = maps.clone();
    write_u32(&mut mutant, pos + 4, (info & !0xFFFF) | 9);
    let error = parse_base(&mutant).expect_err("bogus VAR linkage must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::Admission);
}

#[test]
fn every_prefix_terminates_typed() {
    // Hostile truncation battery: no prefix may panic or hang; the full
    // image parses and every proper prefix fails typed.
    for image in [BASE_RIVALS, SHAPES, MAPS] {
        let mut errors = 0usize;
        for len in 0..image.len() {
            match parse_base(&image[..len]) {
                Ok(_) => panic!("prefix {len} of {} bytes unexpectedly parses", image.len()),
                Err(error) => {
                    assert_eq!(error.stage(), Stage::Admission);
                    assert!(
                        matches!(
                            error.kind(),
                            ErrorKind::InvalidInput
                                | ErrorKind::Malformed
                                | ErrorKind::LimitExceeded
                        ),
                        "prefix {len} has typed kind {:?}",
                        error.kind()
                    );
                    errors += 1;
                }
            }
        }
        assert_eq!(errors, image.len());
        parse_base(image).expect("full image parses");
    }
}

#[test]
fn every_bitflip_terminates_typed() {
    // Single-bit hostile battery over the smallest corpus image: every
    // mutant terminates with Ok or a typed error; at least one mutant of
    // each outcome proves the battery is not vacuous.
    let mut ok = 0usize;
    let mut err = 0usize;
    for index in 0..BASE_RIVALS.len() {
        for bit in 0..8u8 {
            let mut mutant = BASE_RIVALS.to_vec();
            mutant[index] ^= 1 << bit;
            match parse_base(&mutant) {
                Ok(_) => ok += 1,
                Err(error) => {
                    assert_eq!(error.stage(), Stage::Admission);
                    assert!(
                        matches!(
                            error.kind(),
                            ErrorKind::Malformed
                                | ErrorKind::LimitExceeded
                                | ErrorKind::Unsupported
                        ),
                        "mutant [{index}]:{bit} has typed kind {:?}",
                        error.kind()
                    );
                    err += 1;
                }
            }
        }
    }
    assert_eq!(ok + err, BASE_RIVALS.len() * 8);
    assert!(ok > 0, "content-bit mutants keep parsing");
    assert!(err > 0, "structural-bit mutants refuse");
}

fn strtab_name(strings_hex: &str, bias: u32, name_off: u32) -> String {
    let bytes: Vec<u8> = (0..strings_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&strings_hex[i..i + 2], 16).unwrap())
        .collect();
    let local = name_off.wrapping_sub(bias) as usize;
    let tail = &bytes[local..];
    let end = tail.iter().position(|b| *b == 0).unwrap();
    String::from_utf8(tail[..end].to_vec()).unwrap()
}

#[test]
fn graphs_json_oracle_agrees_with_parser() {
    // Independent-oracle cross-check: every id the generator logged is
    // reachable through the public name/id queries with the logged kind.
    let root = json_mini::parse(GRAPHS).expect("graphs.json parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    let images = root.get("images").unwrap();
    let blobs: &[(&str, &[u8])] = &[
        ("base-rivals", BASE_RIVALS),
        ("shapes", SHAPES),
        ("maps", MAPS),
        ("cycle", CYCLE),
    ];
    for (name, bytes) in blobs {
        let graph = images.get(name).unwrap();
        let strings_hex = graph.get("strings_hex").unwrap().as_str().unwrap();
        let view = parse_base(bytes).expect("corpus image parses");
        let domain = view.domain_id();
        for entry in graph.get("types").unwrap().as_arr().unwrap() {
            let id = entry.get("id").unwrap().as_u64().unwrap() as u32;
            let kind = entry.get("kind").unwrap().as_u64().unwrap();
            let name_off = entry.get("name_off").unwrap().as_u64().unwrap() as u32;
            let logged = strtab_name(strings_hex, 0, name_off);
            let refs = view.types_named(&logged).expect("name lookup");
            assert!(
                ids_of(&refs).contains(&id),
                "{name}: id {id} (kind {kind}) missing from {logged:?}"
            );
            // The hostile cycle image parses (references are lazy) but no
            // shape survives its cyclic/void/dangling references.
            let hostile = *name == "cycle";
            match view.shape(TypeRef { domain, id }) {
                Ok(_) => assert!(!hostile, "{name}: hostile id {id} shaped"),
                Err(error) => {
                    assert!(hostile, "{name}: id {id} unexpectedly refused");
                    expect_error(&error, ErrorKind::Malformed, Stage::BtfQuery);
                }
            }
        }
    }
}

#[test]
fn composite_and_scalar_shapes_are_exact() {
    let view = parse_base(SHAPES).expect("shapes parse");
    let domain = view.domain_id();
    let shape = |id| view.shape(TypeRef { domain, id }).unwrap();
    assert!(matches!(shape(7).kind, TypeKind::Struct));
    assert_eq!(shape(7).size_bytes, Some(16));
    assert!(matches!(shape(9).kind, TypeKind::Union));
    assert_eq!(shape(9).size_bytes, Some(8));
    match shape(6).kind {
        TypeKind::Array { element, count } => {
            assert_eq!(element.id, 1);
            assert_eq!(count, 4);
        }
        other => panic!("ID 6 must be an array, found {other:?}"),
    }
    assert_eq!(shape(6).size_bytes, Some(16));
    assert!(matches!(
        shape(10).kind,
        TypeKind::Enum {
            bits: 32,
            signed: true
        }
    ));
    assert_eq!(shape(10).size_bytes, Some(4));
    assert!(matches!(shape(12).kind, TypeKind::Function));
    assert_eq!(shape(12).size_bytes, None);
    assert!(matches!(shape(11).kind, TypeKind::FunctionPrototype));
    assert!(matches!(shape(18).kind, TypeKind::Other));
    assert!(matches!(shape(21).kind, TypeKind::Other));
    assert!(matches!(shape(22).kind, TypeKind::Other));
    assert_eq!(shape(22).size_bytes, Some(4));
    assert!(matches!(
        shape(23).kind,
        TypeKind::Enum {
            bits: 64,
            signed: false
        }
    ));
    // Narrowed INT reports value bits, not storage width.
    assert!(matches!(
        shape(19).kind,
        TypeKind::Integer {
            bits: 12,
            signed: false
        }
    ));
    assert_eq!(shape(19).size_bytes, Some(4));
    let maps = parse_base(MAPS).expect("maps parse");
    let maps_domain = maps.domain_id();
    let var = maps
        .shape(TypeRef {
            domain: maps_domain,
            id: 6,
        })
        .expect("VAR shape");
    assert!(matches!(var.kind, TypeKind::Other));
    let sec = maps
        .shape(TypeRef {
            domain: maps_domain,
            id: 7,
        })
        .expect("DATASEC shape");
    assert!(matches!(sec.kind, TypeKind::Other));
    assert_eq!(sec.size_bytes, Some(20));
}

#[test]
fn canonical_chase_cycle_and_depth() {
    let view = parse_base(SHAPES).expect("shapes parse");
    let domain = view.domain_id();
    let canon = |id| view.canonical(TypeRef { domain, id }).unwrap().id;
    assert_eq!(canon(3), 1);
    assert_eq!(canon(20), 1);
    assert_eq!(canon(26), 7);
    assert_eq!(canon(1), 1);
    let error = BtfView::parse(
        BtfImages {
            base: SHAPES,
            module: None,
            byte_order: ByteOrder::Little,
        },
        BtfLimits {
            wrapper_depth: 1,
            ..limits()
        },
    )
    .expect("shallow view parses")
    .canonical(TypeRef { domain, id: 20 })
    .expect_err("two-hop chase over depth 1 must refuse");
    // Note: the shallow view has the same domain (same bytes), so the
    // TypeRef stays valid; only the traversal budget differs.
    expect_error(&error, ErrorKind::LimitExceeded, Stage::BtfQuery);
    let cycle = parse_base(CYCLE).expect("cycle image parses");
    let cycle_domain = cycle.domain_id();
    for id in [1u32, 2, 4] {
        let error = cycle
            .canonical(TypeRef {
                domain: cycle_domain,
                id,
            })
            .expect_err("cyclic/void chase must refuse");
        expect_error(&error, ErrorKind::Malformed, Stage::BtfQuery);
    }
    let error = cycle
        .shape(TypeRef {
            domain: cycle_domain,
            id: 3,
        })
        .expect_err("dangling pointee must refuse");
    expect_error(&error, ErrorKind::Malformed, Stage::BtfQuery);
}

#[test]
fn foreign_and_bad_refs_refuse_typed() {
    let shapes = parse_base(SHAPES).expect("shapes parse");
    let maps = parse_base(MAPS).expect("maps parse");
    let foreign = TypeRef {
        domain: maps.domain_id(),
        id: 1,
    };
    for error in [
        shapes.shape(foreign).expect_err("foreign shape"),
        shapes.canonical(foreign).expect_err("foreign canonical"),
        shapes.member(foreign, &["x"]).expect_err("foreign member"),
        shapes.function(foreign).expect_err("foreign function"),
    ] {
        expect_error(&error, ErrorKind::Incompatible, Stage::BtfQuery);
    }
    let domain = shapes.domain_id();
    for id in [0u32, 999, u32::MAX] {
        let bad = TypeRef { domain, id };
        expect_error(
            &shapes.shape(bad).expect_err("bad id shape"),
            ErrorKind::InvalidInput,
            Stage::BtfQuery,
        );
        expect_error(
            &shapes.canonical(bad).expect_err("bad id canonical"),
            ErrorKind::InvalidInput,
            Stage::BtfQuery,
        );
        expect_error(
            &shapes.member(bad, &["x"]).expect_err("bad id member"),
            ErrorKind::InvalidInput,
            Stage::BtfQuery,
        );
        expect_error(
            &shapes.function(bad).expect_err("bad id function"),
            ErrorKind::InvalidInput,
            Stage::BtfQuery,
        );
    }
}

fn assert_extent(extent: &scopebase_bpf::btf::MemberExtent, domain: BtfDomainId, expected: &Json) {
    assert_eq!(
        extent.byte_offset,
        expected.get("byte").unwrap().as_u64().unwrap()
    );
    assert_eq!(
        extent.bit_offset,
        expected.get("bit").unwrap().as_u64().unwrap() as u8
    );
    match expected.get("width").unwrap() {
        Json::Null => assert_eq!(extent.bit_width, None),
        width => assert_eq!(extent.bit_width, Some(width.as_u64().unwrap() as u8)),
    }
    assert_eq!(
        extent.size_bytes,
        expected.get("size").unwrap().as_u64().unwrap()
    );
    assert_eq!(extent.ty.domain, domain);
    assert_eq!(
        extent.ty.id,
        expected.get("ty").unwrap().as_u64().unwrap() as u32
    );
}

#[test]
fn member_extents_match_expected_graph() {
    let root = expected_root();
    let graph = root.get("shapes").unwrap();
    let view = parse_base(SHAPES).expect("shapes parse");
    let domain = view.domain_id();
    let parent = |id| TypeRef { domain, id };
    assert_extent(
        &view.member(parent(7), &["x"]).unwrap(),
        domain,
        graph.get("point_x").unwrap(),
    );
    assert_extent(
        &view.member(parent(7), &["y"]).unwrap(),
        domain,
        graph.get("point_y").unwrap(),
    );
    assert_extent(
        &view.member(parent(8), &["flags"]).unwrap(),
        domain,
        graph.get("outer_flags").unwrap(),
    );
    assert_extent(
        &view.member(parent(8), &["pt", "y"]).unwrap(),
        domain,
        graph.get("nested_pt_y").unwrap(),
    );
    assert_extent(
        &view.member(parent(9), &["b"]).unwrap(),
        domain,
        graph.get("union_b").unwrap(),
    );
    assert_extent(
        &view.member(parent(15), &["f"]).unwrap(),
        domain,
        graph.get("bitfield_f").unwrap(),
    );
    assert_extent(
        &view.member(parent(15), &["g"]).unwrap(),
        domain,
        graph.get("bitfield_g").unwrap(),
    );
    assert_extent(
        &view.member(parent(16), &["w"]).unwrap(),
        domain,
        graph.get("anon_direct").unwrap(),
    );
    assert_extent(
        &view.member(parent(16), &["v"]).unwrap(),
        domain,
        graph.get("anon_descend").unwrap(),
    );
    assert_extent(
        &view.member(parent(16), &["", "v"]).unwrap(),
        domain,
        graph.get("anon_descend").unwrap(),
    );
    // Qualified parents chase before descent.
    assert_extent(
        &view.member(parent(26), &["x"]).unwrap(),
        domain,
        graph.get("point_x").unwrap(),
    );
}

#[test]
fn rival_composites_keep_exact_identity() {
    let root = expected_root();
    let graph = root.get("shapes").unwrap();
    let view = parse_base(SHAPES).expect("shapes parse");
    let domain = view.domain_id();
    let rivals = view.types_named("Riv").expect("rival lookup");
    assert_eq!(ids_of(&rivals), vec![24, 25]);
    assert_extent(
        &view.member(TypeRef { domain, id: 24 }, &["x"]).unwrap(),
        domain,
        graph.get("rival_first_x").unwrap(),
    );
    assert_extent(
        &view.member(TypeRef { domain, id: 25 }, &["x"]).unwrap(),
        domain,
        graph.get("rival_second_x").unwrap(),
    );
}

#[test]
fn member_misuse_refuses_typed() {
    let view = parse_base(SHAPES).expect("shapes parse");
    let domain = view.domain_id();
    let point = TypeRef { domain, id: 7 };
    expect_error(
        &view.member(point, &[]).expect_err("empty path"),
        ErrorKind::InvalidInput,
        Stage::BtfQuery,
    );
    expect_error(
        &view.member(point, &["nope"]).expect_err("unknown member"),
        ErrorKind::InvalidInput,
        Stage::BtfQuery,
    );
    expect_error(
        &view
            .member(TypeRef { domain, id: 1 }, &["x"])
            .expect_err("scalar parent"),
        ErrorKind::Incompatible,
        Stage::BtfQuery,
    );
    expect_error(
        &view
            .member(point, &["x", "y"])
            .expect_err("descent into scalar"),
        ErrorKind::Incompatible,
        Stage::BtfQuery,
    );
}

#[test]
fn member_corruption_refuses_typed() {
    let view = parse_base(SHAPES).expect("shapes parse");
    let domain = view.domain_id();
    let bytes = SHAPES.to_vec();
    let (type_at, _) = type_section(&bytes);
    // Locate ID 7 (Point) and its member aux records.
    let mut pos = type_at;
    for _ in 1..7u32 {
        let info = read_u32(&bytes, pos + 4);
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;
        let aux = match kind {
            1 => 4,
            3 => 12,
            4 | 5 => vlen * 12,
            6 | 13 => vlen * 8,
            _ => 0,
        };
        pos += 12 + aux;
    }
    let member_base = pos + 12;
    // Escape: y at bit 120 with 8 bytes overruns the 16-byte parent.
    let mut escape = bytes.clone();
    write_u32(&mut escape, member_base + 12 + 8, 120);
    let view = parse_base(&escape).expect("escaped image still parses");
    expect_error(
        &view
            .member(
                TypeRef {
                    domain: view.domain_id(),
                    id: 7,
                },
                &["y"],
            )
            .expect_err("parent escape"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
    // Misaligned: x at bit 4 without the bitfield flag.
    let mut misaligned = bytes.clone();
    write_u32(&mut misaligned, member_base + 8, 4);
    let view = parse_base(&misaligned).expect("misaligned image parses");
    expect_error(
        &view
            .member(
                TypeRef {
                    domain: view.domain_id(),
                    id: 7,
                },
                &["x"],
            )
            .expect_err("misaligned member"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
    // Ambiguous: both Point members named x.
    let x_off = read_u32(&bytes, member_base);
    let mut ambiguous = bytes.clone();
    write_u32(&mut ambiguous, member_base + 12, x_off);
    let view = parse_base(&ambiguous).expect("ambiguous image parses");
    expect_error(
        &view
            .member(
                TypeRef {
                    domain: view.domain_id(),
                    id: 7,
                },
                &["x"],
            )
            .expect_err("duplicate member"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
    let _ = (view, domain);
}

#[test]
fn anonymous_ambiguity_refuses_typed() {
    // HasAnon (ID 16) with w anonymized holds two anonymous members.
    let bytes = SHAPES.to_vec();
    let (type_at, _) = type_section(&bytes);
    let mut pos = type_at;
    for _ in 1..16u32 {
        let info = read_u32(&bytes, pos + 4);
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;
        let aux = match kind {
            1 => 4,
            3 => 12,
            4 | 5 | 15 => vlen * 12,
            6 | 13 => vlen * 8,
            14 | 17 => 4,
            _ => 0,
        };
        pos += 12 + aux;
    }
    let mut mutant = bytes.clone();
    write_u32(&mut mutant, pos + 12 + 12, 0);
    let view = parse_base(&mutant).expect("mutant parses");
    let domain = view.domain_id();
    expect_error(
        &view
            .member(TypeRef { domain, id: 16 }, &[""])
            .expect_err("ambiguous anonymous address"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
    // The unmutated image addresses its single anonymous member exactly.
    let view = parse_base(SHAPES).expect("shapes parse");
    let extent = view
        .member(
            TypeRef {
                domain: view.domain_id(),
                id: 16,
            },
            &[""],
        )
        .expect("single anonymous member");
    assert_eq!(extent.ty.id, 17);
    let _ = domain;
}

#[test]
fn function_shapes_match_expected_graph() {
    let root = expected_root();
    let graph = root.get("shapes").unwrap();
    let view = parse_base(SHAPES).expect("shapes parse");
    let domain = view.domain_id();
    let check = |id: u32, key: &str| {
        let shape = view
            .function(TypeRef { domain, id })
            .unwrap_or_else(|e| panic!("function {id}: {e:?}"));
        let expected = graph.get(key).unwrap();
        assert_eq!(shape.result.domain, domain);
        assert_eq!(
            shape.result.id,
            expected.get("result").unwrap().as_u64().unwrap() as u32
        );
        let params: Vec<u32> = shape.parameters.iter().map(|r| r.id).collect();
        let expected_params: Vec<u32> = expected
            .get("params")
            .unwrap()
            .as_arr()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(params, expected_params);
        for param in &shape.parameters {
            assert_eq!(param.domain, domain);
        }
        assert_eq!(
            shape.variadic,
            expected.get("variadic").unwrap().as_bool().unwrap()
        );
    };
    check(12, "func");
    check(14, "void_func");
}

#[test]
fn malformed_prototypes_refuse_typed() {
    let bytes = SHAPES.to_vec();
    let (type_at, _) = type_section(&bytes);
    // Locate ID 12 (do_work FUNC).
    let mut pos = type_at;
    for _ in 1..12u32 {
        let info = read_u32(&bytes, pos + 4);
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;
        let aux = match kind {
            1 => 4,
            3 => 12,
            4 | 5 => vlen * 12,
            6 | 13 => vlen * 8,
            _ => 0,
        };
        pos += 12 + aux;
    }
    // FUNC at a non-prototype is well-formed but incompatible.
    let mut wrong = bytes.clone();
    write_u32(&mut wrong, pos + 8, 1);
    let view = parse_base(&wrong).expect("wrong-target image parses");
    expect_error(
        &view
            .function(TypeRef {
                domain: view.domain_id(),
                id: 12,
            })
            .expect_err("non-prototype target"),
        ErrorKind::Incompatible,
        Stage::BtfQuery,
    );
    // FUNC at a dangling id is corrupt.
    let mut dangling = bytes.clone();
    write_u32(&mut dangling, pos + 8, 99);
    let view = parse_base(&dangling).expect("dangling image parses");
    expect_error(
        &view
            .function(TypeRef {
                domain: view.domain_id(),
                id: 12,
            })
            .expect_err("dangling target"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
}

#[test]
fn map_linkage_is_exact() {
    let root = expected_root();
    let expected: Vec<u32> = root
        .get("maps")
        .unwrap()
        .get("my_map")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u32)
        .collect();
    assert_eq!(expected, vec![1, 2]);
    let view = parse_base(MAPS).expect("maps parse");
    let domain = view.domain_id();
    let (key, value) = view.map_types("my_map").expect("map linkage");
    assert_eq!(key.domain, domain);
    assert_eq!(value.domain, domain);
    assert_eq!((key.id, value.id), (1, 2));
}

#[test]
fn void_pointer_reports_void_pointee() {
    // ID 5 retargeted at VOID stays a well-formed void pointer.
    let bytes = SHAPES.to_vec();
    let (type_at, _) = type_section(&bytes);
    let mut pos = type_at;
    for _ in 1..5u32 {
        let info = read_u32(&bytes, pos + 4);
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;
        let aux = match kind {
            1 => 4,
            3 => 12,
            4 | 5 => vlen * 12,
            6 | 13 => vlen * 8,
            _ => 0,
        };
        pos += 12 + aux;
    }
    let mut mutant = bytes.clone();
    write_u32(&mut mutant, pos + 8, 0);
    let view = parse_base(&mutant).expect("void-pointer image parses");
    let domain = view.domain_id();
    let shape = view
        .shape(TypeRef { domain, id: 5 })
        .expect("void pointer shape");
    match shape.kind {
        TypeKind::Pointer { to } => assert_eq!(to.id, 0),
        other => panic!("ID 5 must stay a pointer, found {other:?}"),
    }
    expect_error(
        &view
            .shape(TypeRef { domain, id: 0 })
            .expect_err("void as input"),
        ErrorKind::InvalidInput,
        Stage::BtfQuery,
    );
}

#[test]
fn map_zero_ids_refuse() {
    // The key pointer retargeted at VOID leaves the linkage id missing.
    let bytes = MAPS.to_vec();
    let (type_at, _) = type_section(&bytes);
    // ID 3 is the third record: two 16-byte INT records precede it.
    let mut mutant = bytes.clone();
    write_u32(&mut mutant, type_at + 32 + 8, 0);
    let view = parse_base(&mutant).expect("zero-id image parses");
    expect_error(
        &view.map_types("my_map").expect_err("zero key id"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
}

#[test]
fn map_linkage_gaps_refuse_typed() {
    let view = parse_base(MAPS).expect("maps parse");
    expect_error(
        &view.map_types("orphan_map").expect_err("unlinked VAR"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
    expect_error(
        &view.map_types("broken_map").expect_err("missing value"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
    expect_error(
        &view.map_types("nope").expect_err("unknown map"),
        ErrorKind::InvalidInput,
        Stage::BtfQuery,
    );
    // A second VAR under the same name makes the linkage ambiguous.
    let bytes = MAPS.to_vec();
    let (type_at, _) = type_section(&bytes);
    let mut pos = type_at;
    let mut var_name = Vec::new();
    for _ in 1..=11u32 {
        let info = read_u32(&bytes, pos + 4);
        let kind = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;
        if kind == 14 {
            var_name.push((pos, read_u32(&bytes, pos)));
        }
        let aux = match kind {
            1 => 4,
            3 => 12,
            4 | 5 => vlen * 12,
            6 | 13 => vlen * 8,
            14 | 17 => 4,
            15 => vlen * 12,
            _ => 0,
        };
        pos += 12 + aux;
    }
    assert_eq!(var_name.len(), 3);
    let mut mutant = bytes.clone();
    write_u32(&mut mutant, var_name[1].0, var_name[0].1);
    let view = parse_base(&mutant).expect("rival-VAR image parses");
    expect_error(
        &view.map_types("my_map").expect_err("rival map VARs"),
        ErrorKind::Malformed,
        Stage::BtfQuery,
    );
}
