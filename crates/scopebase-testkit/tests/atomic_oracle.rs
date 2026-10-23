// SPDX-License-Identifier: Apache-2.0
//! TC04: atomic RMW old/new-value oracle and AtomicLoad selector regressions.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py` lines
//! 15-59 (user-authored oracle template: per-width initial/operand,
//! live/dead/CAS/load bodies and retval bits),
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/cases.json` lines
//! 1-142 (28-case matrix names), `llvm-bpf-toolchain-experiment.md` lines
//! 55-70 (seven wrong-old-value cases), `llvm-bpf-atomic-load-report.md`
//! lines 62-73 (9-row AtomicLoad selection matrix). Emission facts come from
//! the pinned local tool (ubuntu-llc-21.1.8, same binary as TC03); opcode
//! numbers are cited from pinned kernel UAPI headers (hashes only, recorded
//! in `fixtures/bpf/isa/expected.json`; no lines copied).
//! Grant: OWNER-2026-10-23.
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use scopebase_testkit::object::atomic::{
    check_atomics, check_load_selector, decode_atomic, decode_plain_access, select_atomic_load,
    verify_outcome, AtomicCase, AtomicCell, AtomicDecodeError, AtomicLoadOutcome, AtomicOp,
    AtomicWidth, BackendClass, CpuClass, LoadOrdering, LoadRefusalReason, ObservedOutcome,
    OutcomeVerdict,
};
use scopebase_testkit::object::{inspect_final_object, ObjectContract};
use sha2::{Digest, Sha256};

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

fn refusal(error: &OperationError) -> (ErrorKind, Stage) {
    (error.kind(), error.stage())
}

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{MANIFEST_DIR}/../../{relative}"))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn atomic_vectors() -> serde_json::Value {
    serde_json::from_slice(&repo_bytes("fixtures/bpf/isa/atomic.json")).unwrap()
}

fn contract() -> ObjectContract {
    ObjectContract::from_json(
        br#"{
  "schema_version": 1,
  "artifact": "tc04-atomic-vectors",
  "profile": "compiler-object-v1",
  "target": {"triple": "bpfel-unknown-none", "arch": "bpfel", "endian": "little", "pointer_width_bits": 64},
  "backend": {"kind": "llvm-llc", "name": "llc", "version": "21.1.8", "sha256": "935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382"},
  "cpu": "v3",
  "features_enabled": [],
  "features_disabled": [],
  "required_cells": ["kernel-6.12-x86_64-verifier"],
  "optional_cells": []
}"#,
        &limits(),
    )
    .unwrap()
}

fn op(name: &str) -> AtomicOp {
    match name {
        "add" => AtomicOp::Add,
        "sub" => AtomicOp::Sub,
        "and" => AtomicOp::And,
        "or" => AtomicOp::Or,
        "xor" => AtomicOp::Xor,
        "xchg" => AtomicOp::Xchg,
        "cas" => AtomicOp::Cas,
        other => panic!("unknown op {other}"),
    }
}

fn width(bits: u64) -> AtomicWidth {
    match bits {
        32 => AtomicWidth::W32,
        64 => AtomicWidth::W64,
        other => panic!("unknown width {other}"),
    }
}

fn u64_field(row: &serde_json::Value, field: &str) -> u64 {
    row[field].as_u64().unwrap_or_else(|| panic!("{field} u64"))
}

// ---------------------------------------------------------------------------
// Pure oracle over the frozen 28-case donor matrix
// ---------------------------------------------------------------------------

#[test]
fn oracle_matches_all_frozen_rmw_vectors() {
    let vectors = atomic_vectors();
    assert_eq!(vectors["schema_version"], 1);
    assert_eq!(vectors["kind"], "tc04_atomic_vectors");
    let cases = vectors["rmw_cases"].as_array().unwrap();
    // 20 op/width/live-dead rows + 2 xchg + 4 CAS + (4 load rows live separately).
    assert_eq!(cases.len(), 26, "frozen RMW vector count");
    let mut h29 = 0u32;
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let case = AtomicCase {
            op: op(row["op"].as_str().unwrap()),
            width: width(u64_field(row, "width")),
            initial: u64_field(row, "initial"),
            operand: u64_field(row, "operand"),
            comparator: row.get("comparator").and_then(|v| v.as_u64()).unwrap_or(0),
            live: row["live"].as_bool().unwrap(),
        };
        let expected = scopebase_testkit::object::atomic::atomic_reference(&case).unwrap();
        assert_eq!(expected.old, u64_field(row, "expected_old"), "{name}: old");
        assert_eq!(expected.new, u64_field(row, "expected_new"), "{name}: new");
        // Retval bits follow the donor rule (live/CAS -> 3, dead -> 2); the
        // frozen column is checked against the rule, not echoed.
        let rule_retval = if !case.live { 2 } else { 3 };
        assert_eq!(u64_field(row, "retval"), rule_retval, "{name}: retval rule");
        if row["h29"].as_bool().unwrap() {
            h29 += 1;
        }
    }
    assert_eq!(
        h29, 7,
        "exactly the seven H29 wrong-old-value cases flagged"
    );
    let loads = vectors["load_cases"].as_array().unwrap();
    assert_eq!(loads.len(), 4, "frozen load vector count");
    for row in loads {
        assert_eq!(u64_field(row, "retval"), 1, "load retval bit");
    }
}

#[test]
fn oracle_plan_example_seven_plus_three() {
    let case = AtomicCase {
        op: AtomicOp::Add,
        width: AtomicWidth::W32,
        initial: 7,
        operand: 3,
        comparator: 0,
        live: true,
    };
    let expected = scopebase_testkit::object::atomic::atomic_reference(&case).unwrap();
    assert_eq!(expected.old, 7, "returned old value");
    assert_eq!(expected.new, 10, "stored new value");
}

#[test]
fn oracle_wrapping_and_bitwise_boundaries() {
    // u32 overflow wraps; 0-1 wraps to u32::MAX; i32::MIN-1 wraps bit-wise.
    for (op, initial, operand, new) in [
        (AtomicOp::Add, u64::from(u32::MAX), 1, 0),
        (AtomicOp::Sub, 0, 1, u64::from(u32::MAX)),
        (AtomicOp::Add, 0x8000_0000, 0x8000_0000, 0),
        (AtomicOp::Sub, 0x8000_0000, 1, 0x7fff_ffff),
        (AtomicOp::And, 0b1100, 0b1010, 0b1000),
        (AtomicOp::Or, 0b1100, 0b1010, 0b1110),
        (AtomicOp::Xor, 0b1100, 0b1010, 0b0110),
        (AtomicOp::Xchg, 0xdead_beef, 0x1234_5678, 0x1234_5678),
    ] {
        let case = AtomicCase {
            op,
            width: AtomicWidth::W32,
            initial,
            operand,
            comparator: 0,
            live: true,
        };
        let expected = scopebase_testkit::object::atomic::atomic_reference(&case).unwrap();
        assert_eq!(expected.old, initial);
        assert_eq!(expected.new, new, "w32 {op:?} {initial:#x} {operand:#x}");
    }
    // u64 overflow wraps past the full 64-bit mask.
    let case = AtomicCase {
        op: AtomicOp::Add,
        width: AtomicWidth::W64,
        initial: u64::MAX,
        operand: 1,
        comparator: 0,
        live: true,
    };
    let expected = scopebase_testkit::object::atomic::atomic_reference(&case).unwrap();
    assert_eq!(expected.new, 0);
    // CAS hit stores the operand; CAS miss keeps the initial value; the old
    // value is the initial cell content in both outcomes.
    for (comparator, new) in [(7u64, 3u64), (8u64, 7u64)] {
        let case = AtomicCase {
            op: AtomicOp::Cas,
            width: AtomicWidth::W32,
            initial: 7,
            operand: 3,
            comparator,
            live: true,
        };
        let expected = scopebase_testkit::object::atomic::atomic_reference(&case).unwrap();
        assert_eq!(expected.old, 7);
        assert_eq!(expected.new, new);
    }
    // Out-of-width operands refuse admission instead of silently masking.
    for (width, initial, operand) in [
        (AtomicWidth::W32, 1u64 << 32, 1u64),
        (AtomicWidth::W32, 1, 1u64 << 33),
    ] {
        let case = AtomicCase {
            op: AtomicOp::Add,
            width,
            initial,
            operand,
            comparator: 0,
            live: true,
        };
        assert_eq!(
            refusal(&scopebase_testkit::object::atomic::atomic_reference(&case).unwrap_err()),
            (ErrorKind::InvalidInput, Stage::Admission)
        );
    }
}

#[test]
fn oracle_nonfetch_mutant_fails_old_not_setup() {
    let case = AtomicCase {
        op: AtomicOp::Add,
        width: AtomicWidth::W32,
        initial: 53,
        operand: 13,
        comparator: 0,
        live: true,
    };
    // Stale src-reg defendant's old (13, the operand) with a correct stored
    // new (66): the H29 accepted-but-wrong observation fails the returned-old
    // assertion, not setup.
    assert_eq!(
        verify_outcome(
            &case,
            &ObservedOutcome {
                old: Some(13),
                new: 66
            }
        )
        .unwrap(),
        OutcomeVerdict::OldMismatch {
            expected: 53,
            observed: 13
        }
    );
    // Correct stored value with correct returned old passes.
    assert_eq!(
        verify_outcome(
            &case,
            &ObservedOutcome {
                old: Some(53),
                new: 66
            }
        )
        .unwrap(),
        OutcomeVerdict::Pass
    );
    // A wrong stored value fails the new-value assertion instead.
    assert_eq!(
        verify_outcome(
            &case,
            &ObservedOutcome {
                old: Some(53),
                new: 67
            }
        )
        .unwrap(),
        OutcomeVerdict::NewMismatch {
            expected: 66,
            observed: 67
        }
    );
    // Live cases require an observed old value; dead cases verify the stored
    // value only and refuse a supplied old as a harness mistake.
    assert_eq!(
        refusal(&verify_outcome(&case, &ObservedOutcome { old: None, new: 66 }).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    let dead = AtomicCase {
        live: false,
        ..case
    };
    assert_eq!(
        verify_outcome(&dead, &ObservedOutcome { old: None, new: 66 }).unwrap(),
        OutcomeVerdict::Pass
    );
    assert_eq!(
        refusal(
            &verify_outcome(
                &dead,
                &ObservedOutcome {
                    old: Some(53),
                    new: 66
                }
            )
            .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

// ---------------------------------------------------------------------------
// Decoder: every atomic shape plus the three negative families
// ---------------------------------------------------------------------------

#[test]
fn decode_covers_every_atomic_shape() {
    // (imm low byte, expected op)
    let ops = [
        (0x00u8, AtomicOp::Add),
        (0x40, AtomicOp::Or),
        (0x50, AtomicOp::And),
        (0xa0, AtomicOp::Xor),
        (0xe0, AtomicOp::Xchg),
        (0xf0, AtomicOp::Cas),
    ];
    for (base_imm, op) in ops {
        for (code, width) in [(0xc3u8, AtomicWidth::W32), (0xdbu8, AtomicWidth::W64)] {
            for fetch in [false, true] {
                let imm = i32::from(base_imm | u8::from(fetch));
                let insn = decode_atomic(code, -8, imm, 0x2a).unwrap();
                assert_eq!(insn.op, op);
                assert_eq!(insn.width, width);
                assert_eq!(insn.fetch, fetch);
                assert_eq!(insn.dst, 10);
                assert_eq!(insn.src, 2);
                assert_eq!(insn.off, -8);
                assert_eq!(insn.imm, imm);
            }
        }
    }
    // Plain (non-ATOMIC-mode) slots are not atomics, including the STX MEM
    // shape that differs only in the mode bits.
    for code in [0x63u8, 0x7b, 0x79, 0x61, 0x95, 0x18] {
        assert_eq!(
            decode_atomic(code, 0, 0, 0x10).unwrap_err(),
            AtomicDecodeError::NotAtomic,
            "code {code:#04x}"
        );
    }
    // Acquire/release-marked STX slots belong to the load/store selector, not
    // the RMW decoder.
    for imm in [0x100i32, 0x110] {
        assert_eq!(
            decode_atomic(0xdb, 0, imm, 0x10).unwrap_err(),
            AtomicDecodeError::NotAtomic,
            "imm {imm:#06x}"
        );
    }
}

#[test]
fn decode_refuses_wrong_width_unknown_op_and_misaligned() {
    // Half-word and byte atomics are not valid widths.
    for code in [0xcbu8, 0xd3] {
        assert_eq!(
            decode_atomic(code, 0, 0, 0x1a).unwrap_err(),
            AtomicDecodeError::WrongWidth,
            "code {code:#04x}"
        );
    }
    // Undefined op nibbles refuse even with a clean width and alignment.
    for imm in [0x10i32, 0x20, 0x21, 0x02, 0x200] {
        assert_eq!(
            decode_atomic(0xdb, -8, imm, 0x1a).unwrap_err(),
            AtomicDecodeError::UnknownOp,
            "imm {imm:#06x}"
        );
    }
    // Off-alignment refuses per width: u64 needs 8, u32 needs 4.
    assert_eq!(
        decode_atomic(0xdb, -7, 0, 0x1a).unwrap_err(),
        AtomicDecodeError::Misaligned
    );
    assert_eq!(
        decode_atomic(0xdb, -4, 0, 0x1a).unwrap_err(),
        AtomicDecodeError::Misaligned
    );
    assert_eq!(
        decode_atomic(0xc3, -2, 0, 0x1a).unwrap_err(),
        AtomicDecodeError::Misaligned
    );
    decode_atomic(0xdb, -8, 0, 0x1a).unwrap();
    decode_atomic(0xc3, -4, 0, 0x1a).unwrap();
    decode_atomic(0xc3, 0, 0, 0x1a).unwrap();
}

// ---------------------------------------------------------------------------
// Frozen objects over TC03 inspection machinery
// ---------------------------------------------------------------------------

fn cell(base: u8, off: i16, width_bytes: u8) -> AtomicCell {
    AtomicCell {
        base,
        off,
        width_bytes,
    }
}

#[test]
fn frozen_objects_match_hashes_slots_and_atomic_inventory() {
    let vectors = atomic_vectors();
    let objects = vectors["objects"].as_array().unwrap();
    assert_eq!(objects.len(), 6, "frozen atomic object count");
    let on_disk = std::fs::read_dir(format!(
        "{MANIFEST_DIR}/../../fixtures/bpf/isa/objects-atomic"
    ))
    .unwrap()
    .map(|entry| entry.unwrap().file_name().into_string().unwrap())
    .collect::<Vec<_>>();
    assert_eq!(on_disk.len(), 6, "no unrecorded atomic object on disk");
    let contract = contract();
    for object in objects {
        let file = object["file"].as_str().unwrap();
        let bytes = repo_bytes(&format!("fixtures/bpf/isa/{file}"));
        assert_eq!(
            hex(&digest(&bytes)),
            object["sha256"].as_str().unwrap(),
            "{file}: frozen hash"
        );
        let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
        assert!(inspection.conforms(), "{file}: TC03 decodes cleanly");
        let want: Vec<String> = object["families"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(inspection.families(), &want, "{file}: effective families");
        assert_eq!(
            inspection.spans().len(),
            object["slots"].as_u64().unwrap() as usize,
            "{file}: decoded slot count"
        );
        match object.get("atomic") {
            Some(spec) if !spec.is_null() => {
                let slot = spec["slot"].as_u64().unwrap();
                let span = inspection
                    .spans()
                    .iter()
                    .find(|span| span.offset / 8 == slot)
                    .unwrap_or_else(|| panic!("{file}: atomic span at slot {slot}"));
                let insn = decode_atomic(span.code, span.off, span.imm, span.regs).unwrap();
                assert_eq!(insn.width, width(spec["width"].as_u64().unwrap()));
                assert_eq!(insn.op, op(spec["op"].as_str().unwrap()));
                assert_eq!(insn.fetch, spec["fetch"].as_bool().unwrap());
                assert_eq!(insn.dst, spec["dst"].as_u64().unwrap() as u8);
                assert_eq!(insn.src, spec["src"].as_u64().unwrap() as u8);
                assert_eq!(insn.off, spec["off"].as_i64().unwrap() as i16);
                assert_eq!(insn.imm, spec["imm"].as_i64().unwrap() as i32);
                // Exactly one atomic slot per RMW object.
                let atomics = inspection
                    .spans()
                    .iter()
                    .filter(|span| decode_atomic(span.code, span.off, span.imm, span.regs).is_ok())
                    .count();
                assert_eq!(atomics, 1, "{file}: single atomic slot");
                // Plain init/verify traffic decodes exactly as recorded.
                let plains = object["plains"].as_array().unwrap();
                assert_eq!(plains.len(), 2, "{file}: init + verify accesses");
                for plain in plains {
                    let slot = plain["slot"].as_u64().unwrap();
                    let span = inspection
                        .spans()
                        .iter()
                        .find(|span| span.offset / 8 == slot)
                        .unwrap_or_else(|| panic!("{file}: plain span at slot {slot}"));
                    let access = decode_plain_access(span.code, span.off, span.imm, span.regs)
                        .expect("plain access");
                    assert_eq!(access.base, plain["base"].as_u64().unwrap() as u8);
                    assert_eq!(access.off, plain["off"].as_i64().unwrap() as i16);
                    assert_eq!(access.width_bytes, plain["width"].as_u64().unwrap() as u8);
                    assert_eq!(access.write, plain["write"].as_bool().unwrap());
                }
            }
            _ => {
                // Load-selector object: no atomic slot, one ordinary u64 load.
                let atomics = inspection
                    .spans()
                    .iter()
                    .filter(|span| decode_atomic(span.code, span.off, span.imm, span.regs).is_ok())
                    .count();
                assert_eq!(atomics, 0, "{file}: no atomic slot");
                let spec = &object["ordinary_load"];
                let span = &inspection.spans()[spec["slot"].as_u64().unwrap() as usize];
                let access = decode_plain_access(span.code, span.off, span.imm, span.regs)
                    .expect("ordinary load");
                assert_eq!(access.base, spec["base"].as_u64().unwrap() as u8);
                assert!(!access.write);
            }
        }
    }
}

#[test]
fn frozen_live_objects_flag_missing_fetch() {
    let contract = contract();
    // Both as-emitted live-add objects carry the H29 shape: used result, no
    // fetch bit. The checker flags it; these are regression positives, not
    // passing twins.
    for (file, base, off, width_bytes) in [
        (
            "fixtures/bpf/isa/objects-atomic/rmw-add32-live.o",
            10u8,
            -4i16,
            4u8,
        ),
        (
            "fixtures/bpf/isa/objects-atomic/rmw-add64-live.o",
            10u8,
            -8i16,
            8u8,
        ),
    ] {
        let bytes = repo_bytes(file);
        let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
        let violations = check_atomics(
            inspection.spans(),
            true,
            &cell(base, off, width_bytes),
            &[cell(base, off, width_bytes)],
        );
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "atomic.missing-fetch"),
            "{file}: missing-fetch flagged"
        );
    }
    // Unused-result, always-fetch xchg and CAS controls carry no finding.
    for (file, live, base, off, width_bytes) in [
        (
            "fixtures/bpf/isa/objects-atomic/rmw-add32-dead.o",
            false,
            10u8,
            -4i16,
            4u8,
        ),
        (
            "fixtures/bpf/isa/objects-atomic/rmw-xchg64.o",
            true,
            10u8,
            -8i16,
            8u8,
        ),
        (
            "fixtures/bpf/isa/objects-atomic/rmw-cas64-hit.o",
            true,
            10u8,
            -8i16,
            8u8,
        ),
    ] {
        let bytes = repo_bytes(file);
        let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
        let violations = check_atomics(
            inspection.spans(),
            live,
            &cell(base, off, width_bytes),
            &[cell(base, off, width_bytes)],
        );
        assert!(violations.is_empty(), "{file}: clean controls");
    }
}

#[test]
fn fetch_restored_twin_passes_old_and_new() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects-atomic/rmw-add32-live.o");
    // Socket data starts at file 0x40; slot 3 imm lives at +28..32.
    assert_eq!(&bytes[0x58..0x60], &[0xc3, 0x1a, 0xfc, 0xff, 0, 0, 0, 0]);
    let mut twin = bytes.clone();
    twin[0x5c] = 0x01; // set the fetch bit: imm 0x00 -> 0x01.
    let contract = contract();
    let inspection = inspect_final_object(&twin, &contract, &limits()).unwrap();
    assert!(inspection.conforms());
    let violations = check_atomics(
        inspection.spans(),
        true,
        &cell(10, -4, 4),
        &[cell(10, -4, 4)],
    );
    assert!(violations.is_empty(), "restored twin carries no finding");
    let span = inspection
        .spans()
        .iter()
        .find(|span| span.offset / 8 == 3)
        .unwrap();
    assert!(
        decode_atomic(span.code, span.off, span.imm, span.regs)
            .unwrap()
            .fetch
    );
    // With fetch restored, the reference old/new pair verifies clean.
    let case = AtomicCase {
        op: AtomicOp::Add,
        width: AtomicWidth::W32,
        initial: 53,
        operand: 13,
        comparator: 0,
        live: true,
    };
    assert_eq!(
        verify_outcome(
            &case,
            &ObservedOutcome {
                old: Some(53),
                new: 66
            }
        )
        .unwrap(),
        OutcomeVerdict::Pass
    );
}

#[test]
fn wrong_width_mutant_refused() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects-atomic/rmw-add64-live.o");
    assert_eq!(bytes[0x68], 0xdb, "guard: slot5 is STX ATOMIC DW");
    let mut mutant = bytes.clone();
    mutant[0x68] = 0xcb; // DW -> H: half-word atomic.
    let contract = contract();
    let inspection = inspect_final_object(&mutant, &contract, &limits()).unwrap();
    assert!(inspection.conforms(), "TC03 still decodes the shape");
    let violations = check_atomics(
        inspection.spans(),
        true,
        &cell(10, -8, 8),
        &[cell(10, -8, 8)],
    );
    let hit = violations
        .iter()
        .find(|v| v.rule_id == "atomic.wrong-width")
        .expect("wrong-width");
    assert_eq!(hit.section.as_deref(), Some("socket"));
    assert_eq!(hit.offset, Some(5 * 8));
    assert_eq!(hit.kind, ErrorKind::InvalidInput);
    let valid = inspect_final_object(&bytes, &contract, &limits()).unwrap();
    assert!(
        check_atomics(valid.spans(), true, &cell(10, -8, 8), &[cell(10, -8, 8)])
            .iter()
            .all(|v| v.rule_id != "atomic.wrong-width")
    );
}

#[test]
fn misaligned_mutant_refused() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects-atomic/rmw-add64-live.o");
    assert_eq!(&bytes[0x6a..0x6c], &[0xf8, 0xff], "guard: slot5 off -8");
    let mut mutant = bytes.clone();
    mutant[0x6a] = 0xf9; // off -8 -> -7: u64 cell off-alignment.
    let contract = contract();
    let inspection = inspect_final_object(&mutant, &contract, &limits()).unwrap();
    assert!(inspection.conforms(), "TC03 still decodes the shape");
    let violations = check_atomics(
        inspection.spans(),
        true,
        &cell(10, -8, 8),
        &[cell(10, -8, 8)],
    );
    let hit = violations
        .iter()
        .find(|v| v.rule_id == "atomic.misaligned")
        .expect("misaligned");
    assert_eq!(hit.section.as_deref(), Some("socket"));
    assert_eq!(hit.offset, Some(5 * 8));
    assert_eq!(hit.kind, ErrorKind::InvalidInput);
}

#[test]
fn unknown_op_mutant_refused() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects-atomic/rmw-add64-live.o");
    assert_eq!(&bytes[0x6c..0x70], &[0, 0, 0, 0], "guard: slot5 imm 0");
    let mut mutant = bytes.clone();
    mutant[0x6c] = 0x20; // undefined atomic op nibble.
    let contract = contract();
    let inspection = inspect_final_object(&mutant, &contract, &limits()).unwrap();
    let violations = check_atomics(
        inspection.spans(),
        true,
        &cell(10, -8, 8),
        &[cell(10, -8, 8)],
    );
    assert!(violations.iter().any(|v| v.rule_id == "atomic.unknown-op"));
}

#[test]
fn undeclared_cell_mutant_refused() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects-atomic/rmw-add32-live.o");
    assert_eq!(&bytes[0x5a..0x5c], &[0xfc, 0xff], "guard: slot3 off -4");
    let mut mutant = bytes.clone();
    mutant[0x5a] = 0xf8; // off -4 -> -8: aligned, but outside (r10,-4,4).
    let contract = contract();
    let inspection = inspect_final_object(&mutant, &contract, &limits()).unwrap();
    let violations = check_atomics(
        inspection.spans(),
        true,
        &cell(10, -4, 4),
        &[cell(10, -4, 4)],
    );
    assert!(violations
        .iter()
        .any(|v| v.rule_id == "atomic.undeclared-cell"));
    assert!(
        violations.iter().all(|v| v.rule_id != "atomic.misaligned"),
        "aligned twin must not misfire the alignment rule"
    );
}

#[test]
fn aliasing_allowances_cover_genuine_traffic() {
    let bytes = repo_bytes("fixtures/bpf/isa/objects-atomic/rmw-add32-live.o");
    let contract = contract();
    let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
    // Declared init/verify traffic on the cell is allowed.
    assert!(check_atomics(
        inspection.spans(),
        false,
        &cell(10, -4, 4),
        &[cell(10, -4, 4)]
    )
    .iter()
    .all(|v| v.rule_id != "atomic.plain-alias"));
    // With allowances emptied, the genuine init store (slot 1) and verify
    // load (slot 8) both fire the non-atomic-aliasing rule.
    let violations = check_atomics(inspection.spans(), false, &cell(10, -4, 4), &[]);
    let hits: Vec<_> = violations
        .iter()
        .filter(|v| v.rule_id == "atomic.plain-alias")
        .collect();
    assert_eq!(hits.len(), 2, "init store and verify load flagged");
    let mut offsets: Vec<u64> = hits.iter().filter_map(|v| v.offset).collect();
    offsets.sort();
    assert_eq!(offsets, vec![8, 64]);
    assert!(hits.iter().all(|v| v.kind == ErrorKind::InvalidInput));
}

// ---------------------------------------------------------------------------
// AtomicLoad selector over the donor 9-row matrix
// ---------------------------------------------------------------------------

fn backend(name: &str) -> BackendClass {
    match name {
        "ubuntu-llc-18.1.8" => BackendClass::LlvmPre21,
        "ubuntu-llc-21.1.8" | "llvm-23.1.2-pristine-llc" | "rust-llvm-22.1.4" => {
            BackendClass::LlvmModern
        }
        "bpf-linker-0.10.4" => BackendClass::BpfLinker,
        other => panic!("unknown backend {other}"),
    }
}

fn cpu(name: &str) -> Option<CpuClass> {
    match name {
        "none" => None,
        "generic" => Some(CpuClass::Generic),
        "v3" => Some(CpuClass::V3),
        "v4" => Some(CpuClass::V4),
        other => panic!("unknown cpu {other}"),
    }
}

fn ordering(name: &str) -> LoadOrdering {
    match name {
        "monotonic" => LoadOrdering::Monotonic,
        "acquire" => LoadOrdering::Acquire,
        other => panic!("unknown ordering {other}"),
    }
}

#[test]
fn selector_matches_donor_rows() {
    let vectors = atomic_vectors();
    let rows = vectors["selector_rows"].as_array().unwrap();
    assert_eq!(rows.len(), 10, "frozen selector row count");
    let mut cells = 0u32;
    for row in rows {
        let id = row["id"].as_str().unwrap();
        let backend = backend(row["backend"].as_str().unwrap());
        let acqrel = row["acqrel"].as_bool().unwrap_or(false);
        let want = match row["outcome"].as_str().unwrap() {
            "compile-refusal" => {
                AtomicLoadOutcome::CompileRefusal(match row["reason"].as_str().unwrap() {
                    "backend-generation" => LoadRefusalReason::BackendGeneration,
                    "llvm-selection" => LoadRefusalReason::LlvmSelection,
                    "linker-cli" => LoadRefusalReason::LinkerCli,
                    other => panic!("unknown reason {other}"),
                })
            }
            "ordinary-load" => AtomicLoadOutcome::OrdinaryLoad,
            "acquire-load" => AtomicLoadOutcome::AcquireLoad,
            other => panic!("unknown outcome {other}"),
        };
        for cpu_name in row["cpu"].as_array().unwrap() {
            for ordering_name in row["ordering"].as_array().unwrap() {
                let got = select_atomic_load(
                    backend,
                    cpu(cpu_name.as_str().unwrap()),
                    acqrel,
                    ordering(ordering_name.as_str().unwrap()),
                );
                assert_eq!(got, want, "{id} {} {}", cpu_name, ordering_name);
                cells += 1;
            }
        }
    }
    assert!(cells >= 20, "matrix covers {cells} cpu/ordering cells");
    // No CPU claim is weaker than generic: it refuses like generic.
    assert_eq!(
        select_atomic_load(
            BackendClass::LlvmModern,
            None,
            true,
            LoadOrdering::Monotonic
        ),
        AtomicLoadOutcome::CompileRefusal(LoadRefusalReason::LlvmSelection)
    );
    // Unknown CPU names refuse admission instead of guessing a bundle.
    assert_eq!(
        refusal(&CpuClass::parse("v9").unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    assert_eq!(CpuClass::parse("v4").unwrap(), Some(CpuClass::V4));
    assert_eq!(CpuClass::parse("none").unwrap(), None);
}

#[test]
fn selector_vs_frozen_objects() {
    let contract = contract();
    // v4 monotonic object: ordinary-load expectation holds; an acquire
    // expectation against it misfires (success must not be labeled an
    // acquire-opcode requirement).
    let bytes = repo_bytes("fixtures/bpf/isa/objects-atomic/ld-mono64.o");
    let inspection = inspect_final_object(&bytes, &contract, &limits()).unwrap();
    assert!(check_load_selector(inspection.spans(), false).is_empty());
    let violations = check_load_selector(inspection.spans(), true);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].rule_id, "atomic-load.unexpected-ordinary");
    // TC03 acquire object: acquire-load expectation holds; an ordinary
    // expectation against it misfires.
    let bytes = repo_bytes("fixtures/bpf/isa/objects/acq.o");
    let v4 = ObjectContract::from_json(
        br#"{
  "schema_version": 1,
  "artifact": "tc04-atomic-vectors",
  "profile": "compiler-object-v1",
  "target": {"triple": "bpfel-unknown-none", "arch": "bpfel", "endian": "little", "pointer_width_bits": 64},
  "backend": {"kind": "llvm-llc", "name": "llc", "version": "21.1.8", "sha256": "935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382"},
  "cpu": "v4",
  "features_enabled": ["acqrel"],
  "features_disabled": [],
  "required_cells": ["kernel-6.12-x86_64-verifier"],
  "optional_cells": []
}"#,
        &limits(),
    )
    .unwrap();
    let inspection = inspect_final_object(&bytes, &v4, &limits()).unwrap();
    assert!(inspection.families().contains(&"acqrel".to_owned()));
    assert!(check_load_selector(inspection.spans(), true).is_empty());
    let violations = check_load_selector(inspection.spans(), false);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].rule_id, "atomic-load.unexpected-acquire");
    assert_eq!(violations[0].section.as_deref(), Some("socket"));
}

#[test]
fn documented_mutants_match_exercised_ids() {
    let mutants: serde_json::Value =
        serde_json::from_slice(&repo_bytes("fixtures/bpf/isa/atomic-mutants.json")).unwrap();
    assert_eq!(mutants["schema_version"], 1);
    assert_eq!(mutants["kind"], "tc04_atomic_mutants");
    let ids: Vec<&str> = mutants["mutants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![
            "nonfetch-live-add32",
            "fetch-restored-twin",
            "nonfetch-old-fails",
            "stored-new-fails",
            "wrong-width-atomic",
            "misaligned-atomic",
            "unknown-atomic-op",
            "undeclared-cell",
            "plain-alias-narrow",
            "selector-mismatch-acquire",
            "selector-mismatch-ordinary",
        ]
    );
}
