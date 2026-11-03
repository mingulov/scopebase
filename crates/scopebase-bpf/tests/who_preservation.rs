// SPDX-License-Identifier: Apache-2.0
// ADAPT owner-authorized frozen K host regressions; historical GPL-3.0-or-later.
#[path = "support/who_fixture.rs"]
mod who_fixture;
use who_fixture::*;
/// One `VWho` lane: `(uid, cgroup, stack)` identity, `tid`,
/// `(calls, first_ns, last_ns)` tallies, and the provenance marker.
fn who_lane(id: (u32, u64, i32), tid: u32, tally: (u64, u64, u64), marked: bool) -> VWho {
    VWho {
        comm: [b'c'; 16],
        tid,
        uid: id.0,
        cgroup: id.1,
        ppid: 12,
        pcomm: [b'p'; 16],
        stack: id.2,
        calls: tally.0,
        first_ns: tally.1,
        last_ns: tally.2,
        identity_present: if marked { KWHO_IDENTITY_PRESENT } else { 0 },
        _rsv: 0,
    }
}

#[test]
fn try_fold_vwho_sources_identity_from_unique_marked_lane() {
    // Migration shape: inserting lane marked with identity, the
    // latest-writer secondary lane unmarked with zeroed identity.
    // Identity rides the marked lane; tid/comm ride the latest.
    let inserting = who_lane((1000, 123, 7), 4243, (1, 100, 100), true);
    let mut secondary = who_lane((0, 0, 0), 4244, (1, 200, 200), false);
    secondary.comm = [b'w'; 16];
    let folded = try_fold_vwho(&[inserting, secondary]).expect("unique mark qualifies");
    assert_eq!(folded.calls, 2);
    assert_eq!((folded.uid, folded.cgroup, folded.stack), (1000, 123, 7));
    assert_eq!(folded.ppid, 12);
    assert_eq!(
        (folded.tid, folded.first_ns, folded.last_ns),
        (4244, 100, 200)
    );
    assert_eq!(folded.comm, [b'w'; 16]);
    assert_eq!(folded.identity_present, KWHO_IDENTITY_PRESENT);
    assert_eq!(folded._rsv, 0);
}

#[test]
fn try_fold_vwho_refuses_missing_and_conflicting_provenance() {
    let marked = who_lane((1000, 123, 7), 4243, (1, 100, 100), true);
    let unmarked = who_lane((0, 0, 0), 4244, (1, 200, 200), false);
    // Missing: no lane marked (busy or idle) refuses.
    assert_eq!(try_fold_vwho(&[unmarked, VWho::default()]), None);
    assert_eq!(try_fold_vwho(&[]), None);
    // Conflicting: two marked lanes refuse, even with identical identity.
    assert_eq!(try_fold_vwho(&[marked, marked]), None);
    // Unknown marker values refuse (only 0 and the marker exist).
    let mut odd = marked;
    odd.identity_present = 2;
    assert_eq!(try_fold_vwho(&[odd]), None);
    assert_eq!(try_fold_vwho(&[marked, odd]), None);
}

#[test]
fn try_fold_vwho_accepts_genuine_root_and_stack_zero() {
    // Validity comes from the marker, never from numeric zeros:
    // a MARKED uid 0 / stack 0 is genuine root identity and a
    // genuine stack-id 0 (both legitimate), never a refusal.
    let root = who_lane((0, 5, 0), 1, (3, 100, 300), true);
    let idle = VWho::default();
    let folded = try_fold_vwho(&[idle, root, idle]).expect("marked zeros qualify");
    assert_eq!((folded.uid, folded.cgroup, folded.stack), (0, 5, 0));
    assert_eq!(folded.calls, 3);
    // The same zeros UNMARKED refuse (no observed identity).
    let unmarked_root = who_lane((0, 5, 0), 1, (3, 100, 300), false);
    assert_eq!(try_fold_vwho(&[unmarked_root]), None);
}

#[test]
fn try_fold_vwho_refuses_saturated_calls() {
    // The try_ N5 contract (same as try_fold_vagg): a saturated
    // input word or an overflowing sum refuses; stamps exempt.
    let marked = who_lane((1000, 123, 7), 4243, (1, 100, 100), true);
    let mut full = who_lane((0, 0, 0), 9, (u64::MAX, 0, 0), false);
    full.last_ns = u64::MAX;
    assert_eq!(try_fold_vwho(&[marked, full]), None);
    let mut big = who_lane((1000, 123, 7), 4243, (u64::MAX - 1, 50, 60), true);
    big.last_ns = u64::MAX;
    let small = who_lane((0, 0, 0), 9, (5, 70, 80), false);
    let folded = try_fold_vwho(&[marked, small]).expect("clean lanes qualify");
    assert_eq!(
        (folded.calls, folded.first_ns, folded.last_ns),
        (6, 70, 100)
    );
    assert_eq!(try_fold_vwho(&[big, small]), None);
}
// F01/BPF3: kernel-faithful per-CPU WHO producer/fold regression.
// ---------------------------------------------------------------------------

/// Kernel-faithful per-CPU-hash WHO lane model (Linux 6.12
/// `kernel/bpf/hashtab.c`: `pcpu_init_value` copies the insert input
/// to the CURRENT CPU lane and zeroes every other lane;
/// `htab_percpu_map_update_elem` passes `onallcpus=false` — an
/// insert is NOT a broadcast).
///
/// Hit updates mirror BPF `update_who_slot`: `calls` + 1
/// (saturating), first-touch `first_ns` stamp, `last_ns`, and the
/// last-writer `tid`/`comm` — identity fields are never refreshed on
/// the hit path. The FOLD under test is always the real shipped
/// [`try_fold_vwho`]; only the kernel/BPF producer side is modeled
/// (the owned live migration control exercises actual helper
/// semantics; see the F01 handoff for its lease gate).
struct PcpuWho {
    lanes: Vec<VWho>,
}

impl PcpuWho {
    fn new(ncpu: usize) -> Self {
        Self {
            lanes: vec![VWho::default(); ncpu],
        }
    }

    /// `BPF_NOEXIST` insert on `cpu`: the current lane takes the full
    /// init value; every other lane stays zero (kernel insert
    /// semantics).
    fn insert(&mut self, cpu: usize, val: VWho) {
        self.lanes[cpu] = val;
    }

    /// Concurrent-insert race: the winner's lane takes the marked
    /// init value; the loser's insert fails (`EEXIST`), so its lane
    /// stays exactly as the kernel left it (zero — never marked).
    fn race_insert(&mut self, winner_cpu: usize, loser_cpu: usize, val: VWho) {
        self.lanes[winner_cpu] = val;
        assert_eq!(
            self.lanes[loser_cpu],
            VWho::default(),
            "losing insert marks nothing"
        );
    }

    /// Hit-path update on `cpu` (mirrors `update_who_slot`; observes
    /// no identity — `uid`/`cgroup`/`ppid`/`pcomm`/`stack` untouched).
    fn hit(&mut self, cpu: usize, tid: u32, comm: &[u8; 16], now: u64) {
        let lane = &mut self.lanes[cpu];
        let was = lane.calls;
        lane.calls = was.saturating_add(1);
        if was == 0 {
            lane.first_ns = now;
        }
        lane.last_ns = now;
        lane.tid = tid;
        lane.comm = *comm;
    }

    fn fold(&self) -> Option<VWho> {
        try_fold_vwho(&self.lanes)
    }
}

/// BPF `who_upsert` init value: full observed identity with zero
/// tallies/stamps plus the insertion marker (the insert carries
/// `calls == 0`; the re-lookup stamps the inserting lane).
fn who_init(
    comm: [u8; 16],
    tid: u32,
    uid: u32,
    cgroup: u64,
    ppid: u32,
    pcomm: [u8; 16],
    stack: i32,
) -> VWho {
    VWho {
        comm,
        tid,
        uid,
        cgroup,
        ppid,
        pcomm,
        stack,
        calls: 0,
        first_ns: 0,
        last_ns: 0,
        identity_present: KWHO_IDENTITY_PRESENT,
        _rsv: 0,
    }
}

fn comm_of(name: &[u8]) -> [u8; 16] {
    let mut comm = [0u8; 16];
    comm[..name.len()].copy_from_slice(name);
    comm
}

#[test]
fn who_migration_initializes_secondary_lane() {
    // BPF3: a non-root caller creates one (kh, tgid) KWHO key on CPU
    // A, then the same process makes the same call on CPU B. The
    // kernel zeroed B's lane at insert; the hit path only counts.
    // The fold must report insertion-observed identity (never
    // fabricated zeros) with exact summed calls.
    let comm = comm_of(b"python3");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(2);
    map.insert(0, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm, 100);
    // Pin the kernel premise, not just the conclusion: the secondary
    // lane is all zero before its first hit.
    assert_eq!(
        map.lanes[1],
        VWho::default(),
        "kernel zeroes non-inserting lanes"
    );
    map.hit(1, 4243, &comm, 200);
    let folded = map.fold().expect("migration fold qualifies");
    assert_eq!(folded.calls, 2, "exact summed calls");
    assert_eq!(folded.uid, 1000, "insertion-frozen uid, not lane-B zero");
    assert_eq!(folded.cgroup, 123, "insertion cgroup, not lane-B zero");
    assert_eq!(folded.ppid, 12, "insertion parent, not lane-B zero");
    assert_eq!(&folded.pcomm[..4], b"bash");
    assert_eq!(folded.stack, 7, "insertion stack, not unrelated stack-id 0");
    assert_eq!((folded.first_ns, folded.last_ns), (100, 200));
}

#[test]
fn who_single_cpu_control_keeps_identity() {
    // Positive control: no migration — insert + two hits on one CPU
    // keep identity, sum calls, and fold stamps exactly.
    let comm = comm_of(b"python3");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(2);
    map.insert(0, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm, 100);
    map.hit(0, 4243, &comm, 200);
    let folded = map.fold().expect("single-CPU fold qualifies");
    assert_eq!(folded.calls, 2);
    assert_eq!(
        (folded.uid, folded.cgroup, folded.ppid, folded.stack),
        (1000, 123, 12, 7)
    );
    assert_eq!(
        (folded.tid, folded.first_ns, folded.last_ns),
        (4243, 100, 200)
    );
    assert_eq!(&folded.comm[..7], b"python3");
}

#[test]
fn who_migration_under_change_keeps_insertion_identity() {
    // Migration accompanied by a changed thread/comm: the hit path
    // observes no identity (mirrors `update_who_slot`, which reads
    // no uid/cgroup/stack), so even changed live credentials cannot
    // move the folded identity — insertion-frozen fields stay from
    // the original key insert while tid/comm follow the latest
    // writer.
    let comm_a = comm_of(b"python3");
    let comm_b = comm_of(b"worker");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(2);
    map.insert(0, who_init(comm_a, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm_a, 100);
    map.hit(1, 4244, &comm_b, 200);
    let folded = map.fold().expect("changed-context fold qualifies");
    assert_eq!(folded.calls, 2, "exact summed calls");
    assert_eq!(
        (folded.uid, folded.cgroup, folded.ppid, folded.stack),
        (1000, 123, 12, 7),
        "insertion-frozen identity survives migration under change"
    );
    assert_eq!(folded.tid, 4244, "tid follows the latest writer");
    assert_eq!(&folded.comm[..6], b"worker", "comm follows latest writer");
}

#[test]
fn who_noexist_race_loser_never_marks() {
    // BPF_NOEXIST race preserved: two CPUs miss concurrently; the
    // winner's insert marks its lane, the loser's insert fails and
    // its lane stays unmarked through its own hit update. The fold
    // keeps the winner's insertion identity with exact summed calls.
    let comm = comm_of(b"python3");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(2);
    map.race_insert(0, 1, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm, 100);
    map.hit(1, 4243, &comm, 200);
    assert_eq!(
        map.lanes[1].identity_present, 0,
        "loser lane stays unmarked after its hit"
    );
    let folded = map.fold().expect("race fold qualifies");
    assert_eq!(folded.calls, 2, "exact summed calls");
    assert_eq!(
        (folded.uid, folded.cgroup, folded.ppid, folded.stack),
        (1000, 123, 12, 7),
        "winner insertion identity, never loser zeros"
    );
    assert_eq!(folded.identity_present, KWHO_IDENTITY_PRESENT);
}

#[test]
fn who_fold_ignores_unrelated_stack_id_zero() {
    // One marked insert plus hits across three secondary lanes: every
    // secondary carries stack-id 0 (kernel-zeroed, unrelated to any
    // KSTACK row); the fold must report the insertion stack, never
    // the unrelated zero.
    let comm = comm_of(b"python3");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(4);
    map.insert(0, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm, 100);
    map.hit(1, 4243, &comm, 200);
    map.hit(2, 4243, &comm, 300);
    map.hit(3, 4243, &comm, 400);
    for lane in &map.lanes[1..] {
        assert_eq!((lane.stack, lane.identity_present), (0, 0));
    }
    let folded = map.fold().expect("multi-lane fold qualifies");
    assert_eq!(folded.calls, 4);
    assert_eq!(folded.stack, 7, "insertion stack, not unrelated id 0");
    assert_eq!((folded.uid, folded.cgroup), (1000, 123));
    assert_eq!((folded.first_ns, folded.last_ns), (100, 400));
}

#[test]
fn who_fold_accepts_genuine_root_and_stack_zero() {
    // Validity comes from the marker, never from numeric zeros: a
    // MARKED uid 0 is genuine root and a MARKED stack 0 is a genuine
    // stack-id 0 (both legitimate), never a refusal.
    let comm = comm_of(b"init");
    let pcomm = comm_of(b"swapper");
    let mut map = PcpuWho::new(2);
    map.insert(0, who_init(comm, 1, 0, 5, 0, pcomm, 0));
    map.hit(0, 1, &comm, 100);
    map.hit(1, 1, &comm, 200);
    let folded = map.fold().expect("marked zeros qualify");
    assert_eq!(folded.calls, 2);
    assert_eq!((folded.uid, folded.cgroup, folded.stack), (0, 5, 0));
}

#[test]
fn who_fold_refuses_missing_and_conflicting_provenance() {
    // Missing: busy lanes with no marked insert refuse (no observed
    // identity to report — never guess from zeros).
    let comm = comm_of(b"python3");
    let mut missing = PcpuWho::new(2);
    missing.hit(0, 4243, &comm, 100);
    missing.hit(1, 4243, &comm, 200);
    assert_eq!(missing.fold(), None, "unmarked lanes refuse");
    // Conflicting: two marked inserts (contradictory kernel state)
    // refuse rather than pick a lane.
    let pcomm = comm_of(b"bash");
    let mut conflicting = PcpuWho::new(2);
    conflicting.insert(0, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    conflicting.insert(1, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    assert_eq!(conflicting.fold(), None, "double-marked lanes refuse");
}

#[test]
fn individual_max_refuses_but_exact_sum_max_accepts() {
    let mut a = VWho {
        identity_present: 1,
        calls: u64::MAX - 1,
        ..VWho::default()
    };
    let mut b = VWho {
        calls: 1,
        ..VWho::default()
    };
    assert_eq!(
        try_fold_vwho(&[a, b]).unwrap().calls,
        u64::MAX,
        "exact sum MAX is valid"
    );
    b.calls = 2;
    assert!(try_fold_vwho(&[a, b]).is_none(), "overflow refuses");
    a.calls = u64::MAX;
    assert!(try_fold_vwho(&[a]).is_none(), "individual MAX sentinel");
    a.calls = 1;
    a.first_ns = u64::MAX;
    a.last_ns = u64::MAX;
    assert_eq!(try_fold_vwho(&[a]).unwrap().last_ns, u64::MAX);
}
#[test]
fn who88_every_lookup_path() {
    let raw = include_bytes!("fixtures/bp02/who88-two-lanes.bin");
    let key = include_bytes!("fixtures/bp02/kwho-key16.bin");
    assert!(
        vwho_from_bytes(&raw[..80]).is_none(),
        "BP02_STALE80_DECODER_REJECTION"
    );
    assert!(
        report_rows(&[key.as_slice()], 1, |_| Ok(Some(raw[..80].to_vec()))).is_err(),
        "BP02_STALE80_SLICE_REJECTION"
    );
    assert!(
        report_rows(&[key.as_slice()], 2, |_| Ok(Some(raw[..160].to_vec()))).is_err(),
        "BP02_STALE80_REPORT_REJECTION"
    );
    assert!(vwho_from_bytes(&raw[..87]).is_none());
    assert!(vwho_from_bytes(&raw[..89]).is_none());
    assert!(kwho_key_from_bytes(&key[..15]).is_none());
    let mut long = key.to_vec();
    long.push(0);
    assert!(kwho_key_from_bytes(&long).is_none());
    let report = report_rows(&[key.as_slice(), key.as_slice()], 2, |_| {
        Ok(Some(raw.to_vec()))
    })
    .unwrap();
    assert_eq!(report.len(), 2);
    assert_eq!(report[0].1.calls, 12);
    assert_eq!(report[0].1.uid, 0);
    assert_eq!(report[0].1.stack, 0);
    assert_eq!(report[0].1.tid, 101);
    let mut n = 0;
    assert!(
        report_rows(&[key.as_slice(), key.as_slice()], 2, |_| {
            n += 1;
            Ok(if n == 1 { Some(raw.to_vec()) } else { None })
        })
        .is_err(),
        "disappeared row aborts entire report"
    );
}
#[path = "support/aggregate_fixture.rs"]
mod aggregate;
#[test]
fn who_codecs_roundtrip_and_reject_short() {
    let raw = include_bytes!("fixtures/bp02/who88-two-lanes.bin");
    let a = vwho_from_bytes(&raw[..88]).unwrap();
    let b = vwho_from_bytes(&raw[88..]).unwrap();
    assert_eq!(
        (
            &a.comm[..8],
            a.tid,
            a.uid,
            a.cgroup,
            a.ppid,
            &a.pcomm[..6],
            a.stack,
            a.calls,
            a.first_ns,
            a.last_ns,
            a.identity_present,
            a._rsv
        ),
        (
            b"inserter".as_slice(),
            100,
            0,
            291,
            4,
            b"parent".as_slice(),
            0,
            5,
            11,
            22,
            1,
            0
        )
    );
    assert_eq!(
        (
            &b.comm[..6],
            b.tid,
            b.uid,
            b.cgroup,
            b.ppid,
            &b.pcomm[..5],
            b.stack,
            b.calls,
            b.first_ns,
            b.last_ns,
            b.identity_present,
            b._rsv
        ),
        (
            b"latest".as_slice(),
            101,
            999,
            999,
            999,
            b"noise".as_slice(),
            7,
            7,
            33,
            44,
            0,
            0
        )
    );
    let k = kwho_key_from_bytes(include_bytes!("fixtures/bp02/kwho-key16.bin")).unwrap();
    assert_eq!((k.kh, k.tgid, k._pad), (0x8e834f55dbe259a5, 4242, 0));
    assert_eq!(KWhoKey::FIELDS, &["kh", "tgid", "_pad"]);
    assert_eq!(VWho::FIELDS.len(), 12);
    let mut reserved = raw[..88].to_vec();
    reserved[84..88].copy_from_slice(&99u32.to_le_bytes());
    assert_eq!(vwho_from_bytes(&reserved).unwrap()._rsv, 99);
    assert_eq!(
        try_fold_vwho(&[vwho_from_bytes(&reserved).unwrap()])
            .unwrap()
            ._rsv,
        0
    );
    let first = VWho {
        tid: 7,
        identity_present: 0,
        ..VWho::default()
    };
    let marker = VWho {
        tid: 8,
        uid: 0,
        stack: 0,
        identity_present: 1,
        ..VWho::default()
    };
    let v = try_fold_vwho(&[first, marker]).unwrap();
    assert_eq!(
        (v.tid, v.first_ns, v.last_ns, v.uid, v.stack),
        (7, 0, 0, 0, 0)
    );
}
#[test]
fn terminal_unavailable_topology_refuses_before_bpf() {
    let mut calls = 0;
    assert!(aggregate::terminal(None, || {
        calls += 1;
        Ok(())
    })
    .is_err());
    assert_eq!(calls, 0);
    aggregate::terminal(Some(4), || {
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
}
#[test]
fn unavailable_topology_refuses_totals_before_bpf() {
    let mut calls = 0;
    assert!(aggregate::terminal(None, || {
        calls += 1;
        let _ = aggregate::totals(2, 4, true, |_| Ok(None))?;
        Ok(())
    })
    .is_err());
    assert_eq!(calls, 0);
}
#[test]
fn aggregate_totals_diagnostic_policies_stay_distinct() {
    let mut raw = vec![0; 240];
    raw[..8].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    raw[120..128].copy_from_slice(&2u64.to_le_bytes());
    assert_eq!(aggregate::fold(&raw, 2, false).unwrap()[0], u64::MAX);
    assert!(aggregate::fold(&raw, 2, true).is_err());
    assert!(aggregate::totals(2, 2, true, |_| Ok(None))
        .unwrap()
        .is_none());
    let mut n = 0;
    assert!(aggregate::totals(2, 2, true, |_| {
        n += 1;
        Ok(if n == 1 { Some(vec![0; 240]) } else { None })
    })
    .is_err());
    assert!(aggregate::diagnostic(2, |_| Ok(None)).is_err());
    assert!(aggregate::diagnostic(2, |_| Err("denied".into())).is_err());
    assert_eq!(
        aggregate::diagnostic(2, |_| Ok(Some(vec![0; 16]))).unwrap(),
        [0, 0]
    );
}

#[test]
fn aggregate_huge_counts_refuse_without_panic() {
    // S185: `fold` already checks its extent multiply; `totals`,
    // `diagnostic` and `walk` must refuse huge counts with typed
    // extent errors instead of panicking (debug) or wrapping
    // (release) on the identical computation.
    assert!(aggregate::totals(1, usize::MAX, true, |_| Ok(Some(vec![0u8; 8]))).is_err());
    assert!(aggregate::diagnostic(usize::MAX, |_| Ok(Some(vec![0u8; 8]))).is_err());
    let key = [0u8; 260];
    assert!(aggregate::walk(&[&key[..]], usize::MAX, |_| Ok(Some(vec![0u8; 8]))).is_err());
}
