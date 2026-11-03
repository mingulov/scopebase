// SPDX-License-Identifier: Apache-2.0
//! BP07: program/CPU writer ownership, insertion provenance, full-map diagnostics.
//!
//! ADAPT: KryProbe d153f3aa `kryprobe/crates/kryprobe-abi/src/kcrypto_agg.rs`
//! (program ordinals 75-108, `kattrloss_fold` 148-160, `VWho`/`try_fold_vwho`
//! 508-560/825-868, fold vectors 1172-1240); BPF writer discipline from
//! `kryprobe/crates/bpf-kcrypto/src/bin/kcrypto.rs` (`who_drops_inc` 790-811,
//! `fence_admit` 813-841, `update_who_slot`/`who_upsert` 1013-1177); slot-drain
//! and scripted countermodels from
//! `kryprobe/crates/kryprobe-privilege/src/kcrypto_fence.rs` (208-278, 406-426);
//! full-map/loss vectors from
//! `kryprobe/crates/kryprobe-privilege/tests/kcrypto_who.rs` (698-780, 783-1021);
//! partition rationale from KryProbe `docs/decisions/ADR-0013.md` (13-45).
//! Grant: OWNER-2026-10-23 + D03 (user-owned GPL donor, library destination).
//! Product key/UID/cgroup/stack state stays local to donors; only the generic
//! slot arithmetic, marker discipline, capped fold and occupancy proof port.
//! Live H14/H15/H17/H18 discrimination cells are NOT_RUN (TT05 live binding).

use scopebase_bpf::loss::{fold_degradation_255, FullMap, LossEpoch, LossGrid, DEGRADATION_CAP};
use scopebase_bpf::writer::{
    fold_insertion, guard_admit, insertion_owner, insertion_total, writer_slot, GuardKind,
    IdentityLane, MissLedger, WriterArch, WriterDeclaration, WriterPartition, IDENTITY_PRESENT,
};
use scopebase_bpf::{CpuTopology, ErrorKind, OperationError, Stage};
use std::collections::{HashMap, HashSet};

#[path = "support/json_mini.rs"]
mod json_mini;

use json_mini::Json;

const INTERLEAVINGS: &str = include_str!("../fixtures/writer-v1/interleavings.json");
const WHO_INSERT: &str = include_str!("../fixtures/writer-v1/who-insert.json");
const FULL_MAP_LOSS: &str = include_str!("../fixtures/writer-v1/full-map-loss.json");

fn kind_of(name: &str) -> ErrorKind {
    match name {
        "InvalidInput" => ErrorKind::InvalidInput,
        "Malformed" => ErrorKind::Malformed,
        "Unsupported" => ErrorKind::Unsupported,
        "Overflow" => ErrorKind::Overflow,
        "Changed" => ErrorKind::Changed,
        other => panic!("unknown kind {other:?}"),
    }
}

fn stage_of(name: &str) -> Stage {
    match name {
        "Admission" => Stage::Admission,
        other => panic!("unknown stage {other:?}"),
    }
}

fn assert_refuses<T: std::fmt::Debug>(
    result: Result<T, OperationError>,
    kind: ErrorKind,
    stage: Stage,
) {
    let error = result.expect_err("must refuse");
    assert_eq!(error.kind(), kind, "refusal kind");
    assert_eq!(error.stage(), stage, "refusal stage");
}

fn topology_0_3() -> CpuTopology {
    CpuTopology::parse_possible(b"0-3", 65535, 65536).expect("0-3 parses")
}

fn partition_9x8() -> WriterPartition {
    WriterPartition::new(9, 8).expect("9x8 partition admits")
}

fn decl(program: u32, site: u32, cpu: u32) -> WriterDeclaration {
    WriterDeclaration::new(program, site, cpu, GuardKind::Unguarded, WriterArch::X86_64)
}

#[test]
fn slots_nine_by_eight_by_lanes_are_distinct() {
    let topology = topology_0_3();
    let partition = partition_9x8();
    let mut seen = HashSet::new();
    for program in 0..9 {
        for site in 0..8 {
            for cpu in 0..4 {
                let slot = writer_slot(&decl(program, site, cpu), &partition, &topology)
                    .expect("in-range writer maps");
                assert!(
                    seen.insert(slot),
                    "slot collision at {program}/{site}/{cpu}"
                );
            }
        }
    }
    assert_eq!(seen.len(), 9 * 8 * 4, "every writer owns a distinct slot");
}

#[test]
fn different_programs_same_cpu_do_not_share_slot() {
    let topology = topology_0_3();
    let partition = partition_9x8();
    let a = writer_slot(&decl(2, 1, 1), &partition, &topology).expect("program 2 maps");
    let b = writer_slot(&decl(3, 1, 1), &partition, &topology).expect("program 3 maps");
    assert_ne!(a, b, "same CPU interleaved by two programs needs two slots");
    let again = writer_slot(&decl(2, 1, 1), &partition, &topology).expect("mapping is stable");
    assert_eq!(a, again, "same writer always maps to the same slot");
}

#[test]
fn shared_slot_countermodel_collides() {
    // The ADR-0013 hazard, pinned: legacy math that ignores the program
    // ordinal maps an interleaved pair onto ONE slot and would lose an
    // increment. This test documents the hole; `writer_slot` must not
    // reproduce it (see the distinctness tests above).
    fn legacy_slot(site: u32, lane: usize, lanes: usize) -> usize {
        site as usize * lanes + lane
    }
    let pair = (legacy_slot(1, 1, 4), legacy_slot(1, 1, 4));
    assert_eq!(pair.0, pair.1, "legacy math collides by construction");
    let topology = topology_0_3();
    let partition = partition_9x8();
    let a = writer_slot(&decl(2, 1, 1), &partition, &topology).expect("maps");
    let b = writer_slot(&decl(3, 1, 1), &partition, &topology).expect("maps");
    assert_ne!(a, b, "partitioned math keeps the interleaved pair apart");
}

#[test]
fn guarded_same_program_refusal_uses_miss_ledger() {
    let topology = topology_0_3();
    let partition = partition_9x8();
    let mut ledger = MissLedger::new(9, 4).expect("ledger admits");
    let guarded = WriterDeclaration::new(2, 1, 1, GuardKind::Guarded, WriterArch::X86_64);
    // A reentrant same-program entry while busy refuses and counts exactly
    // one miss on its own (program, lane) channel.
    assert!(!guard_admit(&guarded, 1, true, &mut ledger).expect("decision"));
    assert_eq!(ledger.misses(2, 1).expect("read"), 1);
    assert!(!guard_admit(&guarded, 1, true, &mut ledger).expect("decision"));
    assert_eq!(ledger.misses(2, 1).expect("read"), 2);
    assert_eq!(ledger.total_misses().expect("total"), 2);
    // Idle guarded and unguarded writers admit without touching the ledger.
    assert!(guard_admit(&guarded, 1, false, &mut ledger).expect("decision"));
    assert!(guard_admit(&decl(2, 1, 1), 1, true, &mut ledger).expect("decision"));
    assert_eq!(
        ledger.total_misses().expect("total"),
        2,
        "admits add no miss"
    );
    // Refusal never moves the slot mapping.
    let before = writer_slot(&decl(2, 1, 1), &partition, &topology).expect("maps");
    assert!(!guard_admit(&guarded, 1, true, &mut ledger).expect("decision"));
    let after = writer_slot(&decl(2, 1, 1), &partition, &topology).expect("maps");
    assert_eq!(before, after, "miss accounting leaves slots alone");
}

#[test]
fn miss_ledger_refuses_unknown_writer_and_overflow() {
    let mut ledger = MissLedger::new(9, 4).expect("ledger admits");
    assert_refuses(
        ledger.record_miss(9, 0).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        ledger.record_miss(0, 4).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        ledger.misses(9, 0).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    ledger
        .record_many(0, 0, u64::MAX)
        .expect("exact fill admits");
    assert_eq!(ledger.misses(0, 0).expect("read"), u64::MAX);
    assert_refuses(
        ledger.record_miss(0, 0).map(|_| ()),
        ErrorKind::Overflow,
        Stage::Admission,
    );
    assert_refuses(
        MissLedger::new(0, 4).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        MissLedger::new(9, 0).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    // Guard decisions authenticate the writer too: a foreign program ordinal
    // is refused, never admitted into another writer's slot.
    let foreign = WriterDeclaration::new(9, 0, 0, GuardKind::Guarded, WriterArch::X86_64);
    assert_refuses(
        guard_admit(&foreign, 0, false, &mut ledger).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
}

#[test]
fn writer_slot_refusals() {
    let topology = topology_0_3();
    let partition = partition_9x8();
    assert_refuses(
        writer_slot(&decl(9, 0, 0), &partition, &topology).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        writer_slot(&decl(0, 8, 0), &partition, &topology).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        writer_slot(&decl(0, 0, 9), &partition, &topology).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    let other_arch = WriterDeclaration::new(0, 0, 0, GuardKind::Unguarded, WriterArch(1));
    assert_refuses(
        writer_slot(&other_arch, &partition, &topology).map(|_| ()),
        ErrorKind::Unsupported,
        Stage::Admission,
    );
    assert_refuses(
        WriterPartition::new(0, 8).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        WriterPartition::new(9, 0).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    let huge = WriterPartition::new(u32::MAX, u32::MAX).expect("shape admits");
    assert_eq!(
        huge.slots().expect("representable shape"),
        18446744065119617025
    );
    assert_refuses(
        writer_slot(&decl(u32::MAX - 1, 0, 0), &huge, &topology).map(|_| ()),
        ErrorKind::Overflow,
        Stage::Admission,
    );
}

#[test]
fn fixture_interleavings() {
    let root = json_mini::parse(INTERLEAVINGS).expect("interleavings parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    let programs = root.get("programs").unwrap().as_u64().unwrap() as u32;
    let sites = root.get("sites_per_program").unwrap().as_u64().unwrap() as u32;
    let partition = WriterPartition::new(programs, sites).expect("fixture partition");
    let topology_src = root.get("topology").unwrap().as_str().unwrap();
    let topology =
        CpuTopology::parse_possible(topology_src.as_bytes(), 65535, 65536).expect("topology");
    let mut by_name: HashMap<&str, usize> = HashMap::new();
    for case in root.get("cases").unwrap().as_arr().unwrap() {
        let name = case.get("name").unwrap().as_str().unwrap();
        let arch = case
            .get("arch")
            .ok()
            .map(|v| WriterArch(v.as_u64().unwrap() as u32))
            .unwrap_or(WriterArch::X86_64);
        let declaration = WriterDeclaration::new(
            case.get("program").unwrap().as_u64().unwrap() as u32,
            case.get("site").unwrap().as_u64().unwrap() as u32,
            case.get("cpu").unwrap().as_u64().unwrap() as u32,
            GuardKind::Unguarded,
            arch,
        );
        let expect = case.get("expect").unwrap();
        match expect.get("outcome").unwrap().as_str().unwrap() {
            "slot" => {
                let slot = writer_slot(&declaration, &partition, &topology)
                    .unwrap_or_else(|e| panic!("{name} maps: {e:?}"));
                assert_eq!(
                    slot,
                    expect.get("slot").unwrap().as_usize().unwrap(),
                    "{name}"
                );
                by_name.insert(name, slot);
            }
            "error" => assert_refuses(
                writer_slot(&declaration, &partition, &topology).map(|_| ()),
                kind_of(expect.get("kind").unwrap().as_str().unwrap()),
                stage_of(expect.get("stage").unwrap().as_str().unwrap()),
            ),
            other => panic!("unknown outcome {other:?}"),
        }
    }
    assert_ne!(
        by_name["interleave-side-a"], by_name["interleave-side-b"],
        "fixture interleave pair stays partitioned"
    );
}

fn lane(marker: u32, count: u64, identity: &[u8]) -> IdentityLane<'_> {
    IdentityLane::new(marker, count, identity)
}

#[test]
fn insertion_unique_mark_owns() {
    // Migration shape: the inserting lane is marked with identity, the
    // latest-writer secondary lane is unmarked with zeroed identity.
    let inserting = [8u8, 0, 0, 1];
    let zeroed = [0u8; 4];
    let lanes = [lane(IDENTITY_PRESENT, 1, &inserting), lane(0, 1, &zeroed)];
    assert_eq!(insertion_owner(&lanes).expect("unique mark owns"), 0);
    let record = fold_insertion(&lanes).expect("record folds");
    assert_eq!(record.owner(), 0);
    assert_eq!(record.identity(), &inserting);
    assert_eq!(record.total(), 2, "both lanes contribute counts");
    assert_eq!(insertion_total(&lanes).expect("total"), 2);
}

#[test]
fn insertion_zero_payload_owns_and_unmarked_counts_only() {
    // Validity rides the marker, never numeric zeros: marked all-zero
    // identity is genuine, and unmarked lanes only add counts.
    let zeros = [0u8; 4];
    let other = [9u8; 4];
    let lanes = [lane(0, 2, &other), lane(IDENTITY_PRESENT, 3, &zeros)];
    assert_eq!(insertion_owner(&lanes).expect("marked zeros own"), 1);
    let record = fold_insertion(&lanes).expect("record folds");
    assert_eq!(
        record.identity(),
        &zeros,
        "owner payload wins even when zero"
    );
    assert_eq!(record.total(), 5, "unmarked lane contributes counts only");
}

#[test]
fn insertion_refusals() {
    let id = [8u8, 0, 0, 1];
    let zero = [0u8; 4];
    assert_refuses(
        insertion_owner(&[]).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        insertion_owner(&[lane(0, 3, &id)]).map(|_| ()),
        ErrorKind::Malformed,
        Stage::Admission,
    );
    assert_refuses(
        insertion_owner(&[lane(1, 1, &id), lane(1, 1, &id)]).map(|_| ()),
        ErrorKind::Malformed,
        Stage::Admission,
    );
    assert_refuses(
        insertion_owner(&[lane(2, 1, &id)]).map(|_| ()),
        ErrorKind::Malformed,
        Stage::Admission,
    );
    assert_refuses(
        insertion_total(&[lane(1, 1, &id), lane(0, u64::MAX, &zero)]).map(|_| ()),
        ErrorKind::Overflow,
        Stage::Admission,
    );
    assert_refuses(
        insertion_total(&[lane(1, u64::MAX - 1, &id), lane(0, 5, &zero)]).map(|_| ()),
        ErrorKind::Overflow,
        Stage::Admission,
    );
    assert_refuses(
        fold_insertion(&[lane(0, 1, &id)]).map(|_| ()),
        ErrorKind::Malformed,
        Stage::Admission,
    );
}

#[test]
fn fixture_who_insert() {
    let root = json_mini::parse(WHO_INSERT).expect("who-insert parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    assert_eq!(
        root.get("marker").unwrap().as_u64().unwrap(),
        u64::from(IDENTITY_PRESENT)
    );
    for case in root.get("cases").unwrap().as_arr().unwrap() {
        let name = case.get("name").unwrap().as_str().unwrap();
        let payloads: Vec<Vec<u8>> = case
            .get("lanes")
            .unwrap()
            .as_arr()
            .unwrap()
            .iter()
            .map(|l| {
                l.get("identity")
                    .unwrap()
                    .as_arr()
                    .unwrap()
                    .iter()
                    .map(|b| b.as_u64().unwrap() as u8)
                    .collect()
            })
            .collect();
        let raw = case.get("lanes").unwrap().as_arr().unwrap();
        let lanes: Vec<IdentityLane> = raw
            .iter()
            .zip(payloads.iter())
            .map(|(l, id)| {
                IdentityLane::new(
                    l.get("marker").unwrap().as_u64().unwrap() as u32,
                    l.get("count").unwrap().as_u64().unwrap(),
                    id,
                )
            })
            .collect();
        let expect = case.get("expect").unwrap();
        match expect.get("outcome").unwrap().as_str().unwrap() {
            "owner" => {
                let owner =
                    insertion_owner(&lanes).unwrap_or_else(|e| panic!("{name} owns: {e:?}"));
                assert_eq!(
                    owner,
                    expect.get("owner").unwrap().as_usize().unwrap(),
                    "{name}"
                );
                let record = fold_insertion(&lanes).expect("record folds");
                assert_eq!(record.owner(), owner, "{name}");
                let want: Vec<u8> = expect
                    .get("identity")
                    .unwrap()
                    .as_arr()
                    .unwrap()
                    .iter()
                    .map(|b| b.as_u64().unwrap() as u8)
                    .collect();
                assert_eq!(record.identity(), want.as_slice(), "{name}");
                assert_eq!(
                    record.total(),
                    expect.get("total").unwrap().as_u64().unwrap(),
                    "{name}"
                );
            }
            "error" => {
                let kind = kind_of(expect.get("kind").unwrap().as_str().unwrap());
                let stage = stage_of(expect.get("stage").unwrap().as_str().unwrap());
                if lanes.is_empty() || kind == ErrorKind::Malformed {
                    assert_refuses(insertion_owner(&lanes).map(|_| ()), kind, stage);
                } else {
                    assert_refuses(insertion_total(&lanes).map(|_| ()), kind, stage);
                }
            }
            other => panic!("unknown outcome {other:?}"),
        }
    }
}

#[test]
fn fold_vectors_match_capped_contract() {
    assert_eq!(DEGRADATION_CAP, 255);
    assert_eq!(fold_degradation_255(&[0, 0]).value(), 0);
    assert_eq!(fold_degradation_255(&[7, 8]).value(), 15);
    assert_eq!(fold_degradation_255(&[250, 10]).value(), 255);
    assert_eq!(fold_degradation_255(&[255, 255, 255]).value(), 255);
    assert_eq!(fold_degradation_255(&[]).value(), 0);
}

#[test]
fn flag_reports_degradation_not_count() {
    let clean = fold_degradation_255(&[0, 0]);
    assert!(!clean.is_degraded());
    assert!(!clean.is_capped());
    let degraded = fold_degradation_255(&[7, 8]);
    assert!(degraded.is_degraded());
    assert!(!degraded.is_capped());
    // 300 failures are a capped indication, never the exact count 300.
    let many = vec![1u8; 300];
    let capped = fold_degradation_255(&many);
    assert_eq!(capped.value(), 255);
    assert!(capped.is_degraded());
    assert!(capped.is_capped());
    // An already-saturated lane stays capped: idempotent, no wrap.
    assert_eq!(fold_degradation_255(&[255, 10]).value(), 255);
    assert_eq!(capped, fold_degradation_255(&[255]));
}

#[test]
fn fixture_fold_cases() {
    let root = json_mini::parse(FULL_MAP_LOSS).expect("full-map-loss parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    assert_eq!(
        root.get("cap").unwrap().as_u64().unwrap(),
        u64::from(DEGRADATION_CAP)
    );
    for case in root.get("fold_cases").unwrap().as_arr().unwrap() {
        let name = case.get("name").unwrap().as_str().unwrap();
        let lanes: Vec<u8> = case
            .get("lanes")
            .unwrap()
            .as_arr()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(
            fold_degradation_255(&lanes).value(),
            case.get("expect").unwrap().as_u64().unwrap() as u8,
            "{name}"
        );
    }
}

/// Finite-capacity key model with `BPF_NOEXIST` insert discipline (test-only
/// mirror of the donor `SimKwho` shape): an insert into a full map fails and
/// the key stays absent, and re-inserting an existing key fails (EEXIST).
struct SimMap {
    keys: HashSet<(u64, u32)>,
    capacity: usize,
}

impl SimMap {
    fn insert_noexist(&mut self, key: (u64, u32)) -> bool {
        // S186: real `BPF_NOEXIST` fails EEXIST on an existing key.
        if self.keys.contains(&key) {
            return false;
        }
        if self.keys.len() >= self.capacity {
            return false;
        }
        self.keys.insert(key)
    }
}

#[test]
fn sim_map_noexist_reinsert_refuses() {
    // S186: real `BPF_NOEXIST` fails EEXIST when the key exists; the
    // sim must refuse the twin insert instead of modelling success.
    let mut sim = SimMap {
        keys: HashSet::new(),
        capacity: 8,
    };
    assert!(sim.insert_noexist((7, 11)), "first insert admits");
    assert!(
        !sim.insert_noexist((7, 11)),
        "twin insert refuses (EEXIST edge)"
    );
}

#[test]
fn full_map_carries_typed_occupancy_proof() {
    let full = FullMap::new(2048, 2048, 1).expect("exact-full admits");
    assert_eq!(full.capacity(), 2048);
    assert_eq!(full.admitted(), 2048);
    assert_eq!(full.refused(), 1);
    assert_eq!(full.attempted().expect("attempted"), 2049);
    let mut full = full;
    full.record_refusal().expect("second refusal records");
    assert_eq!(full.refused(), 2);
    assert_eq!(full.attempted().expect("attempted"), 2050);
}

#[test]
fn full_map_construction_refuses_non_proof_shapes() {
    // Below capacity is not full: no proof, no diagnostic.
    assert_refuses(
        FullMap::new(2048, 128, 0).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    // A full map with zero refusals is the silent-drop shape: refused.
    assert_refuses(
        FullMap::new(2048, 2048, 0).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    // Over-capacity occupancy contradicts the proof.
    assert_refuses(
        FullMap::new(2048, 2049, 1).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        FullMap::new(0, 0, 1).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    let mut full = FullMap::new(4, 4, u64::MAX).expect("saturated refusal count admits");
    assert_refuses(
        full.record_refusal().map(|_| ()),
        ErrorKind::Overflow,
        Stage::Admission,
    );
    assert_eq!(full.refused(), u64::MAX, "failed increment keeps the proof");
}

#[test]
fn full_map_cannot_hide_independent_loss() {
    // Flagship H17 shape: the identity map fills exactly, the overflow key
    // refuses, the independent per-program/per-CPU lanes still observe the
    // failure, and aggregate totals reconcile despite the loss.
    let mut map = SimMap {
        keys: HashSet::new(),
        capacity: 2048,
    };
    let kh = 0x0123_4567_89ab_cdefu64;
    let grid = LossGrid::new(9, 4).expect("grid admits");
    let mut lanes = vec![0u8; grid.expected_lanes().expect("36 lanes")];
    let (mut agg_calls, mut tot_calls) = (0u64, 0u64);
    for tgid in 0..2048u32 {
        assert!(map.insert_noexist((kh, tgid)), "map fills to capacity");
        agg_calls += 1;
        tot_calls += 1;
    }
    assert_eq!(map.keys.len(), 2048, "map is exactly full");
    assert!(!map.insert_noexist((kh, 2048)), "overflow key refuses");
    agg_calls += 1;
    tot_calls += 1;
    lanes[2 * 4] = lanes[2 * 4].saturating_add(1); // program 2, cpu 0
    let full = FullMap::new(2048, 2048, 1).expect("typed full diagnostic");
    let flag = grid.fold(&lanes).expect("independent lanes fold");
    assert_eq!(agg_calls, tot_calls, "totals reconcile despite loss");
    assert_eq!(full.attempted().expect("attempted"), 2049);
    assert!(flag.is_degraded(), "loss survives the full map");
    assert_eq!(flag.value(), 1);
}

#[test]
fn below_capacity_positive_twin_stays_clean() {
    let mut map = SimMap {
        keys: HashSet::new(),
        capacity: 2048,
    };
    let kh = 0x0123_4567_89ab_cdefu64;
    for tgid in 0..128u32 {
        assert!(map.insert_noexist((kh, tgid)));
    }
    let grid = LossGrid::new(9, 4).expect("grid admits");
    let lanes = vec![0u8; grid.expected_lanes().expect("lanes")];
    let flag = grid.fold(&lanes).expect("clean lanes fold");
    assert!(!flag.is_degraded(), "no failure means no loss");
    assert_refuses(
        FullMap::new(2048, 128, 0).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
}

#[test]
fn preexisting_loss_survives_fill() {
    // A flag recorded before the map fills stays visible and accumulates
    // upward rather than disappearing under later failures.
    let grid = LossGrid::new(9, 4).expect("grid admits");
    let mut lanes = vec![0u8; grid.expected_lanes().expect("lanes")];
    lanes[2 * 4] = 1;
    assert_eq!(
        grid.fold(&lanes).expect("folds").value(),
        1,
        "early flag visible"
    );
    let mut map = SimMap {
        keys: HashSet::new(),
        capacity: 8,
    };
    for tgid in 0..8u32 {
        assert!(map.insert_noexist((7, tgid)));
    }
    assert!(!map.insert_noexist((7, 8)), "overflow refuses");
    lanes[2 * 4] = lanes[2 * 4].saturating_add(1);
    let flag = grid.fold(&lanes).expect("folds");
    assert_eq!(flag.value(), 2, "present flag accumulates upward");
    assert!(flag.is_degraded());
}

#[test]
fn cross_program_cpu_failures_fold_with_idle_zero() {
    let grid = LossGrid::new(9, 4).expect("grid admits");
    let mut lanes = vec![0u8; grid.expected_lanes().expect("lanes")];
    for cpu in 0..4 {
        lanes[2 * 4 + cpu] = 1;
    }
    assert_eq!(
        grid.fold(&lanes).expect("folds").value(),
        4,
        "cross-CPU accumulates"
    );
    let mut lanes = vec![0u8; grid.expected_lanes().expect("lanes")];
    lanes[2 * 4] = 1;
    lanes[5 * 4 + 1] = 1;
    lanes[7 * 4] = 1;
    assert_eq!(
        grid.fold(&lanes).expect("folds").value(),
        3,
        "cross-program accumulates"
    );
    let idle: u64 = lanes
        .iter()
        .enumerate()
        .filter(|(i, _)| i / 4 != 2 && i / 4 != 5 && i / 4 != 7)
        .map(|(_, &v)| u64::from(v))
        .sum();
    assert_eq!(idle, 0, "idle program slots stay zero");
}

#[test]
fn loss_grid_refuses_partial_and_foreign_shapes() {
    let grid = LossGrid::new(9, 4).expect("grid admits");
    assert_eq!(grid.programs(), 9);
    assert_eq!(grid.lanes_per_program(), 4);
    assert_eq!(grid.expected_lanes().expect("lanes"), 36);
    assert_refuses(
        grid.fold(&[1u8; 35]).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        grid.fold(&[0u8; 37]).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    // A foreign four-bucket accounting shape (the KCTX domain width) is not
    // a loss grid and can never fold as one: domains stay separate.
    assert_refuses(
        grid.fold(&[0u8; 4]).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        LossGrid::new(0, 4).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
    assert_refuses(
        LossGrid::new(9, 0).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
}

#[test]
fn loss_epoch_resets_and_refuses_regression() {
    let grid = LossGrid::new(1, 3).expect("grid admits");
    let first = grid
        .fold_epoch(7, None, &[1, 1, 1])
        .expect("first epoch folds");
    assert_eq!(first.epoch(), 7);
    assert_eq!(first.flag().value(), 3);
    let refold = grid
        .fold_epoch(7, Some(&first), &[1, 1, 1])
        .expect("same epoch re-folds");
    assert_eq!(refold.flag().value(), 3, "re-read is idempotent");
    // Map replacement advances the epoch with zeroed lanes: no carried loss.
    let replaced = grid
        .fold_epoch(8, Some(&first), &[0, 0, 0])
        .expect("replacement folds");
    assert_eq!(replaced.epoch(), 8);
    assert!(!replaced.flag().is_degraded(), "reset lanes read clean");
    // A stale epoch can never overwrite a newer read.
    assert_refuses(
        grid.fold_epoch(6, Some(&first), &[1, 0, 0]).map(|_| ()),
        ErrorKind::Changed,
        Stage::Admission,
    );
    assert_refuses(
        grid.fold_epoch(7, Some(&first), &[1, 0]).map(|_| ()),
        ErrorKind::InvalidInput,
        Stage::Admission,
    );
}

fn epoch_from_fixture(grid: &LossGrid, prior: &Json) -> LossEpoch {
    // Priors are built through the real fold: a flag byte always folds from
    // a single lane, so `[flag, 0, 0]` reproduces any fixture flag exactly.
    let flag = prior.get("flag").unwrap().as_u64().unwrap() as u8;
    grid.fold_epoch(
        prior.get("epoch").unwrap().as_u64().unwrap(),
        None,
        &[flag, 0, 0],
    )
    .expect("fixture prior folds")
}

#[test]
fn fixture_loss_cases() {
    let root = json_mini::parse(FULL_MAP_LOSS).expect("full-map-loss parses");
    let grid_json = root.get("grid").unwrap();
    let grid = LossGrid::new(
        grid_json.get("programs").unwrap().as_u64().unwrap() as u32,
        grid_json
            .get("lanes_per_program")
            .unwrap()
            .as_usize()
            .unwrap(),
    )
    .expect("fixture grid");
    for case in root.get("grid_cases").unwrap().as_arr().unwrap() {
        let name = case.get("name").unwrap().as_str().unwrap();
        let lanes: Vec<u8> = case
            .get("lanes")
            .unwrap()
            .as_arr()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        let expect = case.get("expect").unwrap();
        match expect.get("outcome").unwrap().as_str().unwrap() {
            "flag" => {
                let flag = grid
                    .fold(&lanes)
                    .unwrap_or_else(|e| panic!("{name} folds: {e:?}"));
                assert_eq!(
                    flag.value(),
                    expect.get("flag").unwrap().as_u64().unwrap() as u8,
                    "{name}"
                );
            }
            "error" => assert_refuses(
                grid.fold(&lanes).map(|_| ()),
                kind_of(expect.get("kind").unwrap().as_str().unwrap()),
                stage_of(expect.get("stage").unwrap().as_str().unwrap()),
            ),
            other => panic!("unknown outcome {other:?}"),
        }
    }
    for case in root.get("fullmap_cases").unwrap().as_arr().unwrap() {
        let name = case.get("name").unwrap().as_str().unwrap();
        let built = FullMap::new(
            case.get("capacity").unwrap().as_u64().unwrap(),
            case.get("admitted").unwrap().as_u64().unwrap(),
            case.get("refused").unwrap().as_u64().unwrap(),
        );
        let expect = case.get("expect").unwrap();
        match expect.get("outcome").unwrap().as_str().unwrap() {
            "ok" => {
                let full = built.unwrap_or_else(|e| panic!("{name} admits: {e:?}"));
                assert_eq!(
                    full.attempted().expect("attempted"),
                    expect.get("attempted").unwrap().as_u64().unwrap(),
                    "{name}"
                );
            }
            "error" => assert_refuses(
                built.map(|_| ()),
                kind_of(expect.get("kind").unwrap().as_str().unwrap()),
                stage_of(expect.get("stage").unwrap().as_str().unwrap()),
            ),
            other => panic!("unknown outcome {other:?}"),
        }
    }
    let epoch_grid = LossGrid::new(1, 3).expect("epoch grid");
    for case in root.get("epoch_cases").unwrap().as_arr().unwrap() {
        let name = case.get("name").unwrap().as_str().unwrap();
        let lanes: Vec<u8> = case
            .get("lanes")
            .unwrap()
            .as_arr()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        let prior_json = case.get("prior").unwrap();
        let prior = if prior_json.is_null() {
            None
        } else {
            Some(epoch_from_fixture(&epoch_grid, prior_json))
        };
        let built = epoch_grid.fold_epoch(
            case.get("epoch").unwrap().as_u64().unwrap(),
            prior.as_ref(),
            &lanes,
        );
        let expect = case.get("expect").unwrap();
        match expect.get("outcome").unwrap().as_str().unwrap() {
            "epoch" => {
                let folded = built.unwrap_or_else(|e| panic!("{name} folds: {e:?}"));
                assert_eq!(
                    folded.epoch(),
                    expect.get("epoch").unwrap().as_u64().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    folded.flag().value(),
                    expect.get("flag").unwrap().as_u64().unwrap() as u8,
                    "{name}"
                );
            }
            "error" => assert_refuses(
                built.map(|_| ()),
                kind_of(expect.get("kind").unwrap().as_str().unwrap()),
                stage_of(expect.get("stage").unwrap().as_str().unwrap()),
            ),
            other => panic!("unknown outcome {other:?}"),
        }
    }
}

#[test]
fn public_getters_expose_declared_shape() {
    let partition = partition_9x8();
    assert_eq!(
        (partition.programs(), partition.sites_per_program()),
        (9, 8)
    );
    assert_eq!(partition.slots().expect("slots"), 72);
    let declaration = WriterDeclaration::new(2, 1, 1, GuardKind::Guarded, WriterArch::X86_64);
    assert_eq!(declaration.program(), 2);
    assert_eq!(declaration.site(), 1);
    assert_eq!(declaration.cpu(), 1);
    assert_eq!(declaration.guard(), GuardKind::Guarded);
    assert_eq!(declaration.arch(), WriterArch::X86_64);
    assert!(WriterArch::X86_64.is_supported());
    assert!(!WriterArch(1).is_supported());
    let id = [1u8, 2, 3, 4];
    let lane = IdentityLane::new(IDENTITY_PRESENT, 7, &id);
    assert_eq!(lane.marker(), IDENTITY_PRESENT);
    assert_eq!(lane.count(), 7);
    assert_eq!(lane.identity(), &id);
    // Flags compare only with flags; distinct folds stay distinct.
    assert_ne!(fold_degradation_255(&[1]), fold_degradation_255(&[2]));
}
