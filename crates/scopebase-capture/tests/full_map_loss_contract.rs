// SPDX-License-Identifier: Apache-2.0
//! Preserved host full-map regressions. Immutable journals supply expected truth.
#[path = "support/cp04_model.rs"]
mod model;
use model::*;
struct Run {
    gate: IdentityGate,
    table: AttributionTable,
    diagnostics: DiagnosticSlots,
    aggregate: u64,
    total: u64,
}
impl Run {
    fn new(gate: usize, table: usize) -> Self {
        Self {
            gate: IdentityGate::new(gate),
            table: AttributionTable::new(table),
            diagnostics: DiagnosticSlots::new(2, 2),
            aggregate: 0,
            total: 0,
        }
    }
    fn attempt(&mut self, id: u32, cpu: usize, slot: usize) -> bool {
        self.aggregate += 1;
        self.total += 1;
        let retained = self.table.insert_noexist((77, id), identity_fixture());
        if !retained {
            self.diagnostics.inc(cpu, slot, &mut self.gate);
        }
        retained
    }
    fn signal(&self) -> u8 {
        self.diagnostics.read(&self.gate)
    }
}
#[test]
fn full_table_signal_survives_repeated_failure() {
    let journal = [1, 2, 3, 4, 5];
    let failed_ids = [2, 3, 4, 5];
    let mut r = Run::new(1, 1);
    assert!(r.gate.insert_noexist(GateKey::Identity(77)));
    for id in journal {
        assert_eq!(r.attempt(id, 0, 0), !failed_ids.contains(&id));
        assert_eq!(r.table.keys.len(), 1);
    }
    assert_eq!(r.gate.entries.len(), 1, "gate full before loss read");
    assert_eq!((r.aggregate, r.total), (5, 5));
    for id in failed_ids {
        assert!(!r.table.keys.contains(&(77, id)));
    }
    assert_eq!(r.signal(), 4, "independent signal survives full tables");
    assert!(local_attribution_partial(r.signal()));
}
#[test]
fn below_capacity_control() {
    let journal = [1, 2, 3, 4, 5];
    let mut r = Run::new(5, 5);
    for id in journal {
        assert!(r.gate.insert_noexist(GateKey::Identity(id as u64)));
        assert!(r.attempt(id, 0, 0));
    }
    assert_eq!(r.table.keys.len(), 5);
    assert_eq!((r.aggregate, r.total), (5, 5));
    assert_eq!(r.signal(), 0);
    assert!(!local_attribution_partial(r.signal()));
}
#[test]
fn preexisting_signal_survives_and_caps() {
    let journal = [1, 2, 3, 4, 5];
    let failed_ids = [2, 3, 4, 5];
    let mut r = Run::new(1, 1);
    r.gate.insert_noexist(GateKey::Identity(77));
    r.diagnostics.set(0, 0, 254);
    for id in journal {
        assert_eq!(r.attempt(id, 0, 0), !failed_ids.contains(&id));
    }
    assert_eq!(failed_ids.len(), 4);
    assert_eq!(r.signal(), 255);
    assert_eq!((r.aggregate, r.total), (5, 5));
}
#[test]
fn historical_full_identity_and_who_maps() {
    let journal: Vec<_> = (0..=2048).collect();
    let failed_ids = [2048];
    let mut r = Run::new(256, 2048);
    for id in 0..256 {
        assert!(r.gate.insert_noexist(GateKey::Identity(id)));
    }
    assert_eq!(r.gate.entries.len(), 256, "all256 slots identity usable");
    assert!(!r.gate.entries.contains_key(&GateKey::Diagnostic));
    for &id in &journal[..2048] {
        assert!(r.attempt(id, 0, 0));
    }
    assert_eq!(
        r.table.keys.len(),
        2048,
        "WHO exactly full before failed insertion"
    );
    for id in failed_ids {
        assert!(!r.attempt(id, 0, 0));
        assert!(!r.table.keys.contains(&(77, id)));
    }
    assert_eq!((r.aggregate, r.total), (2049, 2049));
    assert_eq!(journal.len(), 2049);
    assert_eq!(r.gate.entries.len(), 256);
    assert_eq!(r.table.keys.len(), 2048);
    assert_eq!(r.signal(), 1, "historical loss survives full identity gate");
    assert!(local_attribution_partial(r.signal()));
}
#[test]
fn historical_below_capacity_twin() {
    let journal: Vec<_> = (0..128).collect();
    let mut r = Run::new(256, 2048);
    for &id in &journal {
        assert!(r.gate.insert_noexist(GateKey::Identity(id as u64)));
        assert!(r.attempt(id, 0, 0));
    }
    assert_eq!(r.gate.entries.len(), 128);
    assert_eq!(r.table.keys.len(), 128);
    assert_eq!((r.aggregate, r.total), (128, 128));
    assert_eq!(r.signal(), 0);
    assert!(!local_attribution_partial(r.signal()));
}
#[test]
fn existing_key_at_capacity_is_not_a_failure() {
    let mut r = Run::new(1, 1);
    r.gate.insert_noexist(GateKey::Identity(77));
    assert!(r.attempt(1, 0, 0));
    let before = r.table.clone();
    assert!(r.attempt(1, 0, 0));
    assert_eq!(r.table, before);
    assert_eq!((r.aggregate, r.total, r.signal()), (2, 2, 0));
}
#[test]
fn failed_insert_is_atomic() {
    let mut r = Run::new(1, 1);
    r.gate.insert_noexist(GateKey::Identity(77));
    assert!(r.attempt(1, 0, 0));
    let before = r.table.clone();
    let gate = r.gate.clone();
    assert!(!r.attempt(2, 0, 0));
    assert_eq!(r.table, before, "keys and owner identities preserved");
    assert_eq!(r.gate, gate);
    assert_eq!((r.aggregate, r.total, r.signal()), (2, 2, 1));
}
#[test]
fn cross_lane_failure_slots_are_independent() {
    let journal = [(1, 0, 0), (2, 0, 0), (3, 1, 0), (4, 1, 1), (5, 1, 1)];
    let failed_ids = [2, 3, 4, 5];
    let mut r = Run::new(1, 1);
    r.gate.insert_noexist(GateKey::Identity(77));
    for (id, cpu, slot) in journal {
        assert_eq!(r.attempt(id, cpu, slot), !failed_ids.contains(&id));
    }
    assert_eq!(r.diagnostics.slot(0), 2);
    assert_eq!(r.diagnostics.slot(1), 2);
    assert_eq!(
        r.signal(),
        scopebase_capture::loss::fold_capped_signals(&[1, 1, 0, 2], 255).unwrap()
    );
    assert_eq!(r.signal(), 4);
}
