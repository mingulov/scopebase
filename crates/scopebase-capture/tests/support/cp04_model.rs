// SPDX-License-Identifier: Apache-2.0
//! Test-only ADAPT of selected KryProbe d153f3aa PcpuWho/Sim* slices.
//! Kernel insertion premises and interleavings are scripted, not live evidence.
#![allow(dead_code)]
use scopebase_capture::{
    provenance::*,
    quantity::{Count, Events},
    ContractError,
};
use std::collections::{HashMap, HashSet};
pub type Identity = (u32, u64, u32, [u8; 16], i32);
pub fn identity_fixture() -> Identity {
    (1000, 123, 12, [b'p'; 16], 7)
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawLane {
    pub identity: Identity,
    pub marked: bool,
    pub calls: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    pub tid: u32,
    pub comm: [u8; 16],
    pub display: u64,
}
pub fn raw_lane<I>(identity: LaneIdentity<I>, raw: u64) -> ProvenanceLane<I, Events> {
    if raw == u64::MAX {
        ProvenanceLane::saturated(identity)
    } else {
        ProvenanceLane::new(identity, Count::new(raw))
    }
}
pub struct ProvenanceModel {
    pub lanes: Vec<RawLane>,
}
impl ProvenanceModel {
    pub fn new(ncpu: usize) -> Self {
        assert!((1..=4).contains(&ncpu));
        Self {
            lanes: vec![RawLane::default(); ncpu],
        }
    }
    pub fn insert(&mut self, cpu: usize, identity: Identity) {
        self.lanes[cpu] = RawLane {
            identity,
            marked: true,
            tid: 4243,
            comm: [b'c'; 16],
            ..RawLane::default()
        };
    }
    pub fn race_insert(&mut self, winner: usize, loser: usize, identity: Identity) {
        assert_ne!(winner, loser);
        self.insert(winner, identity);
        assert_eq!(
            self.lanes[loser],
            RawLane::default(),
            "losing insert marks nothing"
        );
        // CP04_CONTROL_RACE: only the successful inserter marks its lane.
    }
    pub fn hit(&mut self, cpu: usize, tid: u32, comm: [u8; 16], now: u64, display: u64) {
        let lane = &mut self.lanes[cpu];
        let was = lane.calls;
        lane.calls = was.saturating_add(1);
        if was == 0 {
            lane.first_ns = now;
        }
        lane.last_ns = now;
        lane.tid = tid;
        lane.comm = comm;
        lane.display = display;
        // CP04_CONTROL_HIT: identity and marker are untouched by a hit.
    }
    pub fn fold(&self) -> Result<InsertionFold<Identity, Events>, ContractError> {
        let lanes: Vec<_> = self
            .lanes
            .iter()
            .map(|lane| {
                let identity = if lane.marked {
                    LaneIdentity::InsertionOwner(lane.identity)
                } else {
                    LaneIdentity::Secondary
                };
                raw_lane(identity, lane.calls)
            })
            .collect();
        fold_insertion_identity(&lanes)
    }
    pub fn display(&self) -> (u32, [u8; 16], u64, u64, u64) {
        let latest = self.lanes.iter().max_by_key(|lane| lane.last_ns).unwrap();
        let first = self
            .lanes
            .iter()
            .filter(|lane| lane.calls > 0)
            .map(|lane| lane.first_ns)
            .min()
            .unwrap_or(0);
        (
            latest.tid,
            latest.comm,
            first,
            latest.last_ns,
            latest.display,
        )
    }
}
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum GateKey {
    Identity(u64),
    Diagnostic,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityGate {
    pub entries: HashMap<GateKey, u8>,
    capacity: usize,
}
impl IdentityGate {
    pub fn new(capacity: usize) -> Self {
        assert!((1..=2048).contains(&capacity));
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }
    pub fn insert_noexist(&mut self, key: GateKey) -> bool {
        if self.entries.contains_key(&key) {
            return true;
        }
        if self.entries.len() >= self.capacity {
            return false;
        }
        self.entries.insert(key, 0);
        true
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributionTable {
    pub keys: HashSet<(u64, u32)>,
    pub owners: HashMap<(u64, u32), Identity>,
    capacity: usize,
}
impl AttributionTable {
    pub fn new(capacity: usize) -> Self {
        assert!((1..=2048).contains(&capacity));
        Self {
            keys: HashSet::new(),
            owners: HashMap::new(),
            capacity,
        }
    }
    pub fn insert_noexist(&mut self, key: (u64, u32), owner: Identity) -> bool {
        if self.keys.contains(&key) {
            return true;
        }
        if self.keys.len() >= self.capacity {
            return false;
        }
        self.keys.insert(key);
        self.owners.insert(key, owner);
        true
    }
}
pub struct DiagnosticSlots {
    ncpu: usize,
    slots: Vec<u8>,
}
impl DiagnosticSlots {
    pub fn new(ncpu: usize, slots: usize) -> Self {
        assert!((1..=4).contains(&ncpu));
        assert!((1..=2).contains(&slots));
        Self {
            ncpu,
            slots: vec![0; ncpu * slots],
        }
    }
    pub fn set(&mut self, cpu: usize, slot: usize, value: u8) {
        assert!(cpu < self.ncpu);
        self.slots[slot * self.ncpu + cpu] = value;
    }
    pub fn inc(&mut self, cpu: usize, slot: usize, _gate: &mut IdentityGate) {
        assert!(cpu < self.ncpu);
        let lane = &mut self.slots[slot * self.ncpu + cpu];
        *lane = lane.saturating_add(1); // CP04_CONTROL_SEPARATE_STORAGE
    }
    pub fn read(&self, _gate: &IdentityGate) -> u8 {
        scopebase_capture::loss::fold_capped_signals(&self.slots, 255).unwrap()
    }
    pub fn slot(&self, slot: usize) -> u8 {
        scopebase_capture::loss::fold_capped_signals(
            &self.slots[slot * self.ncpu..(slot + 1) * self.ncpu],
            255,
        )
        .unwrap()
    }
}
pub fn local_attribution_partial(signal: u8) -> bool {
    signal > 0
}
