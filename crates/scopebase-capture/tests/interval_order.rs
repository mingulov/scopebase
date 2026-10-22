// SPDX-License-Identifier: Apache-2.0
//! CP08: scoped sweep-order proof over half-open interval edges.
//! ADAPT: MemVeil fix 6ea5ffc via tests/unit/test_mappings.mojo:302-501
//! (release-before-acquire ties, out-of-order delivery withholds the
//! peak while per-generation facts stand, non-state events ignored).
//! MappingTracker/_note_peak_order are concept references only: this
//! module proves submitted order and computes no metric.
use scopebase_capture::{
    domain::ClockDomain,
    time::{validate_sweep_order, EdgeKind, StateEdge, TimeInterval, Timestamp},
    ContractError,
};
use std::collections::BTreeMap;

fn clock() -> ClockDomain {
    ClockDomain::new([1; 16]).unwrap()
}
fn edge(ticks: u64, kind: EdgeKind, id: u64) -> StateEdge {
    StateEdge::new(Timestamp::new(clock(), ticks), kind, id)
}

#[test]
fn release_before_acquire_tie_is_valid() {
    // MemVeil test_equal_timestamp_release_first_keeps_peak: half-open
    // [1.1,1.2) and [1.2,1.4) never coincide; release-first ties validate.
    let edges = [
        edge(1100, EdgeKind::Acquire, 1),
        edge(1200, EdgeKind::Release, 1 + 100),
        edge(1200, EdgeKind::Acquire, 2),
        edge(1400, EdgeKind::Release, 2 + 100),
    ];
    assert!(validate_sweep_order(&edges).is_ok());
    // Ordered overlap and disjoint intervals validate too.
    assert!(validate_sweep_order(&[
        edge(1100, EdgeKind::Acquire, 11),
        edge(1200, EdgeKind::Acquire, 12),
        edge(1300, EdgeKind::Release, 13),
        edge(1400, EdgeKind::Release, 14),
    ])
    .is_ok());
    // Empty stream yields an ordering-only proof, never activity support.
    assert!(validate_sweep_order(&[]).is_ok());
}

#[test]
fn acquire_before_release_tie_withholds_sweep() {
    // MemVeil test_equal_timestamp_map_first_withholds_peak: acquire
    // before release at the shared instant cannot separate intervals.
    let edges = [
        edge(1100, EdgeKind::Acquire, 1),
        edge(1200, EdgeKind::Acquire, 2),
        edge(1200, EdgeKind::Release, 101),
        edge(1400, EdgeKind::Release, 102),
    ];
    assert_eq!(validate_sweep_order(&edges), Err(ContractError::InvalidInterval));
    // Backward delivery refuses as well (tick 6 then tick 5).
    assert_eq!(
        validate_sweep_order(&[edge(6, EdgeKind::Acquire, 1), edge(5, EdgeKind::Release, 2)]),
        Err(ContractError::InvalidInterval)
    );
    // Clock mismatch refuses before order is considered.
    let foreign = StateEdge::new(
        Timestamp::new(ClockDomain::new([2; 16]).unwrap(), 1300),
        EdgeKind::Release,
        3,
    );
    assert_eq!(
        validate_sweep_order(&[edge(1100, EdgeKind::Acquire, 1), foreign]),
        Err(ContractError::DomainMismatch)
    );
    // The tie-policy mutant (accept acquire-before-release ties) would
    // pass the bad order above; the InvalidInterval refusal kills it.
}

#[test]
fn reordered_edges_do_not_destroy_independent_duration() {
    // MemVeil test_overlapping_intervals_delivered_out_of_time_order:
    // out-of-order delivery withholds the sweep while per-generation
    // durations stand. Only the dependent proof is lost.
    let generation = TimeInterval::new(
        Timestamp::new(clock(), 0),
        Timestamp::new(clock(), 5),
    )
    .unwrap();
    assert_eq!(generation.duration_ns(), 5);
    // Second generation's delivery violates timestamp order.
    let bad = [
        edge(3, EdgeKind::Acquire, 21),
        edge(1, EdgeKind::Acquire, 22),
        edge(4, EdgeKind::Release, 23),
    ];
    assert_eq!(validate_sweep_order(&bad), Err(ContractError::InvalidInterval));
    // The independently validated duration is unchanged by the refusal.
    assert_eq!(generation.duration_ns(), 5);
    // The global-quality-poisoning mutant (one bad sweep taints every
    // duration) would destroy the duration above; it survives instead.
}

#[test]
fn timestamp_zero_is_valid() {
    // Tick zero is an ordinary timestamp, not a missing sentinel.
    assert!(validate_sweep_order(&[
        edge(0, EdgeKind::Release, 1),
        edge(0, EdgeKind::Acquire, 2),
    ])
    .is_ok());
    assert!(validate_sweep_order(&[edge(0, EdgeKind::Acquire, 1)]).is_ok());
    // A reversed tie at zero still refuses, while the zero-duration
    // lifetime stands (MemVeil test_zero_timestamp_tie_withholds_spike).
    assert_eq!(
        validate_sweep_order(&[
            edge(0, EdgeKind::Acquire, 1),
            edge(0, EdgeKind::Release, 2),
        ]),
        Err(ContractError::InvalidInterval)
    );
    let zero = TimeInterval::new(Timestamp::new(clock(), 0), Timestamp::new(clock(), 0)).unwrap();
    assert_eq!(zero.duration_ns(), 0);
}

#[test]
fn generation_local_zero_ordinals_map_to_distinct_sweep_ids() {
    // Test-only adapter: stable injective map from source
    // (generation, local ordinal) to sweep-unique u64 IDs. Two distinct
    // generations legitimately reuse local ordinal 0.
    struct Adapter {
        next: u64,
        table: BTreeMap<(u64, u64), u64>,
    }
    impl Adapter {
        fn new() -> Self {
            Self { next: 41, table: BTreeMap::new() }
        }
        fn id(&mut self, generation: u64, ordinal: u64) -> Result<u64, ContractError> {
            if let Some(found) = self.table.get(&(generation, ordinal)) {
                return Ok(*found);
            }
            let assigned = self.next;
            self.next = self.next.checked_add(1).ok_or(ContractError::CapacityExceeded)?;
            self.table.insert((generation, ordinal), assigned);
            Ok(assigned)
        }
    }
    // Independent source ledger: (generation7,ordinal0)@tick1 and
    // (generation8,ordinal0)@tick2 with their releases.
    let mut adapter = Adapter::new();
    let a_map = adapter.id(7, 0).unwrap();
    let b_map = adapter.id(8, 0).unwrap();
    assert_eq!((a_map, b_map), (41, 42));
    // A repeated source event retains its original ID.
    assert_eq!(adapter.id(7, 0).unwrap(), 41);
    let edges = [
        edge(1, EdgeKind::Acquire, a_map),
        edge(2, EdgeKind::Acquire, b_map),
        edge(3, EdgeKind::Release, adapter.id(7, 1).unwrap()),
        edge(4, EdgeKind::Release, adapter.id(8, 1).unwrap()),
    ];
    assert!(validate_sweep_order(&edges).is_ok());
    // IDs need not increase: distinct IDs 42/41 with valid timestamp
    // order succeed; order comes from timestamps, never numeric IDs.
    assert!(validate_sweep_order(&[
        edge(1, EdgeKind::Acquire, 42),
        edge(2, EdgeKind::Acquire, 41),
    ])
    .is_ok());
    // The adapter mutant passing local ordinal 0 directly for both
    // generations submits ID 0 twice and must fail DuplicateKey.
    assert_eq!(
        validate_sweep_order(&[
            edge(1, EdgeKind::Acquire, 0),
            edge(2, EdgeKind::Acquire, 0),
        ]),
        Err(ContractError::DuplicateKey)
    );
}

#[test]
fn duplicate_sweep_event_id_refuses() {
    // Repeating ID 41 in one sweep refuses without touching the
    // independently validated per-generation duration.
    let generation = TimeInterval::new(
        Timestamp::new(clock(), 0),
        Timestamp::new(clock(), 5),
    )
    .unwrap();
    assert_eq!(
        validate_sweep_order(&[
            edge(1, EdgeKind::Acquire, 41),
            edge(2, EdgeKind::Acquire, 42),
            edge(3, EdgeKind::Release, 41),
        ]),
        Err(ContractError::DuplicateKey)
    );
    assert_eq!(generation.duration_ns(), 5);
    // The checker mutant accepting ID 41 twice would return Ok above;
    // the DuplicateKey refusal kills it. Distinct IDs still pass.
    assert!(validate_sweep_order(&[
        edge(1, EdgeKind::Acquire, 41),
        edge(2, EdgeKind::Acquire, 42),
        edge(3, EdgeKind::Release, 43),
    ])
    .is_ok());
}

#[test]
fn non_state_facts_do_not_break_the_sweep() {
    // MemVeil test_non_state_events_ignore_peak_proof: copies, syncs and
    // attempts never join the live sweep. The adapter submits only state
    // edges, so wild non-state timestamps cannot break the proof.
    struct SourceEvent {
        ticks: u64,
        state: Option<EdgeKind>,
        id: u64,
    }
    let ledger = [
        SourceEvent { ticks: 1100, state: Some(EdgeKind::Acquire), id: 1 },
        SourceEvent { ticks: 0, state: None, id: 100 }, // copy at ts 0
        SourceEvent { ticks: 0, state: None, id: 101 }, // sync at ts 0
        SourceEvent { ticks: 1300, state: Some(EdgeKind::Release), id: 2 },
    ];
    let edges: Vec<StateEdge> = ledger
        .iter()
        .filter_map(|event| event.state.map(|kind| edge(event.ticks, kind, event.id)))
        .collect();
    assert!(validate_sweep_order(&edges).is_ok());
    // Arrival order is not time order: submitting the same state edges
    // in ledger-arrival disorder still refuses; the checker never sorts.
    assert_eq!(
        validate_sweep_order(&[
            edge(1300, EdgeKind::Release, 2),
            edge(1100, EdgeKind::Acquire, 1),
        ]),
        Err(ContractError::InvalidInterval)
    );
}
