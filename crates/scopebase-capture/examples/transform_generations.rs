// SPDX-License-Identifier: Apache-2.0
//! Scoped transform reference client: submit-bound completion/config journal.
//! This is not a kernel decoder, a refcount policy or an application migration.
use scopebase_capture::{
    domain::{CaptureId, Epoch, ProducerId},
    generation::{require_generation, ObjectKey},
};
use std::collections::BTreeMap;

struct Transform {
    key: ObjectKey<u64>,
    live: bool,
    revision: u64,
}
struct Transforms {
    epoch: Epoch,
    next: u64,
    rows: Vec<Transform>,
    pending: BTreeMap<u8, Option<ObjectKey<u64>>>,
    journal: Vec<&'static str>,
}
impl Transforms {
    fn occupant(&self, raw: u64) -> Option<&Transform> {
        self.rows.iter().find(|r| r.live && *r.key.raw() == raw)
    }
    fn allocate(&mut self, raw: u64) {
        if let Some(r) = self.rows.iter_mut().find(|r| r.live && *r.key.raw() == raw) {
            r.live = false;
            self.journal.push("forced-old");
        }
        self.rows.push(Transform {
            key: ObjectKey::new(self.epoch.clone(), raw, self.next),
            live: true,
            revision: 0,
        });
        self.next += 1;
        self.journal.push("allocated");
    }
    fn submit(&mut self, token: u8, raw: u64) {
        if self.pending.contains_key(&token) {
            self.journal.push("duplicate-token");
            return;
        }
        let binding = self.occupant(raw).map(|r| r.key.clone());
        self.pending.insert(token, binding);
        self.journal.push("submitted");
    }
    fn finish(&mut self, token: u8, raw: u64, config: bool) -> bool {
        let Some(Some(binding)) = self.pending.remove(&token) else {
            self.journal.push("unbound");
            return false;
        };
        let Some(row) = self.rows.iter_mut().find(|r| r.live && *r.key.raw() == raw) else {
            self.journal.push("stale");
            return false;
        };
        if require_generation(&binding, &row.key).is_err() {
            self.journal.push("stale");
            return false;
        }
        if config {
            row.revision += 1;
            self.journal.push("configured");
        } else {
            row.live = false;
            self.journal.push("retired");
        }
        true
    }
}
fn main() {
    let epoch = Epoch::new(
        CaptureId::new([11; 16]).unwrap(),
        ProducerId::new([22; 16]).unwrap(),
        0,
    );
    let mut t = Transforms {
        epoch,
        next: 1,
        rows: Vec::new(),
        pending: BTreeMap::new(),
        journal: Vec::new(),
    };
    t.allocate(7);
    t.submit(1, 7);
    t.allocate(7);
    assert!(!t.finish(1, 7, false), "old completion refused");
    assert_eq!(t.occupant(7).map(|r| r.key.generation()), Some(2));
    t.submit(2, 7);
    assert!(t.finish(2, 7, true));
    assert_eq!(t.occupant(7).unwrap().revision, 1);
    t.submit(3, 8);
    t.allocate(8);
    assert!(!t.finish(3, 8, false));
    assert!(t.occupant(8).is_some());
    t.submit(4, 7);
    assert!(t.finish(4, 7, false));
    assert!(t.occupant(7).is_none());
    assert_eq!(
        t.journal,
        vec![
            "allocated",
            "submitted",
            "forced-old",
            "allocated",
            "stale",
            "submitted",
            "configured",
            "submitted",
            "allocated",
            "unbound",
            "submitted",
            "retired"
        ]
    );
    println!("CP05 transform client: stale=1 unbound=1 configured=1 retired=1 successor=2");
}
