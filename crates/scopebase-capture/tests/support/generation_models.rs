// SPDX-License-Identifier: Apache-2.0
//! Separate test-local K/M policies adapted from narrow owner-authorized scopes.
//! K d153f3aa: entry-bound stable IDs, count bounds, ambiguous forced retirement,
//! retired-only eviction. M 8307a17d: structured domain, identity-present reader
//! gate and retired ring. No native decoding or first-seen branch body is ported.
use super::oracle::{Action, Outcome, Projection, Transition};
use scopebase_capture::{
    domain::{CaptureId, Epoch, ProducerId},
    generation::{require_generation, ObjectKey},
};
use std::collections::BTreeMap;

fn epoch() -> Epoch {
    Epoch::new(
        CaptureId::new([1; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        0,
    )
}
#[derive(Clone, Debug)]
pub struct RawDomain {
    pub device: String,
    pub namespace: String,
    pub token: String,
}
impl RawDomain {
    pub fn new(device: &str, namespace: &str, token: &str) -> Self {
        Self {
            device: device.into(),
            namespace: namespace.into(),
            token: token.into(),
        }
    }
}
impl PartialEq for RawDomain {
    fn eq(&self, other: &Self) -> bool {
        self.device == other.device
            && self.namespace == other.namespace
            && self.token == other.token
    }
}
impl Eq for RawDomain {}
pub fn local_lineage(generation: u64) -> bool {
    generation >= 1
}
#[derive(Clone, Debug, Default)]
pub struct Provenance {
    pub name: String,
    pub alg_type: u32,
    pub mask: u32,
    pub driver: String,
    pub origin: String,
}
impl Provenance {
    pub fn literal(name: &str, alg_type: u32, mask: u32, origin: &str) -> Self {
        Self {
            name: name.into(),
            alg_type,
            mask,
            origin: origin.into(),
            driver: String::new(),
        }
    }
}
pub struct Record {
    pub key: ObjectKey<u64>,
    pub retired: bool,
    pub ambiguous: bool,
    pub creation_observed: bool,
    pub provenance: Provenance,
    pub config_revision: u64,
    pub configs: u64,
}
pub enum Pending {
    Allocation(Provenance),
    Destroy {
        raw: u64,
        binding: Option<ObjectKey<u64>>,
    },
    Config {
        raw: u64,
        binding: Option<ObjectKey<u64>>,
    },
}
pub struct KModel {
    cap: usize,
    next_id: u64,
    pub records: Vec<Record>,
    pub pending: BTreeMap<u8, Pending>,
    pub evictions: usize,
    pub forced: usize,
    pub proved: usize,
    pub stale: usize,
    pub colliding: usize,
    pub unknown: usize,
    pub unknown_creation: usize,
    pub completed_allocs: usize,
    exact: bool,
}
impl KModel {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            next_id: 1,
            records: Vec::new(),
            pending: BTreeMap::new(),
            evictions: 0,
            forced: 0,
            proved: 0,
            stale: 0,
            colliding: 0,
            unknown: 0,
            unknown_creation: 0,
            completed_allocs: 0,
            exact: true,
        }
    }
    pub fn current(&self, raw: u64) -> Option<&ObjectKey<u64>> {
        self.records
            .iter()
            .find(|r| !r.retired && *r.key.raw() == raw)
            .map(|r| &r.key)
    }
    pub fn record(&self, id: u64) -> Option<&Record> {
        self.records.iter().find(|r| r.key.generation() == id)
    }
    pub fn live_len(&self) -> usize {
        self.records.iter().filter(|r| !r.retired).count()
    }
    pub fn retired_ids(&self) -> Vec<u64> {
        self.records
            .iter()
            .filter(|r| r.retired)
            .map(|r| r.key.generation())
            .collect()
    }
    pub fn reuse_exact(&self) -> bool {
        self.exact
    }
    pub fn continuity(&self, id: u64) -> Outcome {
        if self.record(id).is_some() {
            Outcome::Matched
        } else {
            Outcome::UnknownContinuity
        }
    }
    fn compact(&mut self) {
        while self.records.iter().filter(|r| r.retired).count() > self.cap {
            let pos = self.records.iter().position(|r| r.retired).unwrap(); // CP05_FIFO
            self.records.remove(pos);
            self.evictions += 1;
        }
    }
    pub fn allocate(&mut self, raw: u64, creation_observed: bool) -> bool {
        if let Some(old) = self
            .records
            .iter_mut()
            .find(|r| !r.retired && *r.key.raw() == raw)
        {
            old.retired = true;
            old.ambiguous = true; // CP05_FORCED
            self.forced += 1;
            self.exact = false;
            self.compact();
        }
        if self.live_len() >= self.cap {
            return false;
        } // CP05_LIVE_CAP
        let id = self.next_id;
        self.next_id += 1; // CP05_STABLE_ID
        if !creation_observed {
            self.unknown_creation += 1;
            self.exact = false;
        } // CP05_CREATION
        self.records.push(Record {
            key: ObjectKey::new(epoch(), raw, id),
            retired: false,
            ambiguous: false,
            creation_observed,
            provenance: Provenance::default(),
            config_revision: 0,
            configs: 0,
        });
        true
    }
    pub fn submit_alloc(&mut self, token: u8, provenance: Provenance) -> bool {
        if self.pending.contains_key(&token) || self.pending.len() >= self.cap {
            return false;
        } // CP05_ALLOC_CAP
          // CP05_ALLOC_ENTRY: generation assignment waits for the successful pair.
        self.pending.insert(token, Pending::Allocation(provenance));
        true
    }
    pub fn complete_alloc(&mut self, token: u8, raw: u64, driver: &str) -> bool {
        let Some(Pending::Allocation(mut provenance)) = self.pending.remove(&token) else {
            return false;
        };
        self.completed_allocs += 1;
        if !self.allocate(raw, true) {
            return false;
        }
        provenance.driver = driver.into(); // CP05_PROVENANCE
        self.records.last_mut().unwrap().provenance = provenance;
        true
    }
    pub fn submit_destroy(&mut self, token: u8, raw: u64) -> Transition {
        if self.pending.contains_key(&token) {
            return Transition {
                duplicate: true,
                ..Transition::default()
            };
        } // CP05_DUPLICATE
        if self.pending.len() >= self.cap {
            return Transition {
                outcome: Some(Outcome::CapacityRefused),
                ..Transition::default()
            };
        }
        let binding = self.current(raw).cloned(); // CP05_DESTROY_BIND
        let t = Transition {
            admitted: true,
            bound: binding.is_some(),
            unbound: binding.is_none(),
            ..Transition::default()
        };
        self.pending
            .insert(token, Pending::Destroy { raw, binding });
        t
    }
    pub fn complete_destroy(&mut self, token: u8) -> Transition {
        let Some(Pending::Destroy { raw, binding }) = self.pending.remove(&token) else {
            return Transition {
                outcome: Some(Outcome::UnknownContinuity),
                ..Transition::default()
            };
        };
        // CP05_RETURN_BIND: retain the submission binding across reuse.
        let Some(bound) = binding else {
            let colliding = self.current(raw).is_some();
            if colliding {
                self.colliding += 1;
                self.exact = false;
            } else {
                self.unknown += 1;
            }
            return Transition {
                outcome: Some(Outcome::UnknownContinuity),
                unbound: true,
                colliding,
                ..Transition::default()
            };
        };
        let current = self.current(raw);
        if current.is_none_or(|key| require_generation(&bound, key).is_err()) {
            // CP05_COMPLETE_MATCH
            self.stale += 1; // CP05_STALE
            return Transition {
                outcome: Some(Outcome::Mismatch),
                stale: true,
                ..Transition::default()
            };
        }
        self.proved_retire(raw);
        Transition {
            outcome: Some(Outcome::Matched),
            ..Transition::default()
        }
    }
    pub fn proved_retire(&mut self, raw: u64) -> Transition {
        let Some(record) = self
            .records
            .iter_mut()
            .find(|r| !r.retired && *r.key.raw() == raw)
        else {
            return Transition {
                outcome: Some(Outcome::UnknownContinuity),
                ..Transition::default()
            };
        };
        record.retired = true;
        self.proved += 1;
        self.compact();
        Transition {
            outcome: Some(Outcome::Matched),
            ..Transition::default()
        }
    }
    pub fn submit_config(&mut self, token: u8, raw: u64) -> bool {
        if self.pending.contains_key(&token) || self.pending.len() >= self.cap {
            return false;
        }
        let binding = self.current(raw).cloned(); // CP05_CONFIG_BIND
        self.pending.insert(token, Pending::Config { raw, binding });
        true
    }
    pub fn complete_config(&mut self, token: u8) -> bool {
        let Some(Pending::Config { raw, binding }) = self.pending.remove(&token) else {
            return false;
        };
        let Some(bound) = binding else {
            return false;
        }; // CP05_CONFIG_UNBOUND
        let Some(record) = self
            .records
            .iter_mut()
            .find(|r| !r.retired && *r.key.raw() == raw)
        else {
            return false;
        };
        if require_generation(&bound, &record.key).is_err() {
            return false;
        } // CP05_CONFIG_MATCH
        record.config_revision += 1;
        record.configs += 1; // CP05_CONFIG_EFFECT
        true
    }
    pub fn step(&mut self, action: Action) -> Transition {
        match action {
            Action::Allocate7 => {
                let old = self.forced;
                let ok = self.allocate(7, true);
                Transition {
                    admitted: ok,
                    forced: self.forced != old,
                    outcome: if ok {
                        None
                    } else {
                        Some(Outcome::CapacityRefused)
                    },
                    ..Transition::default()
                }
            }
            Action::SubmitDestroy(t) => self.submit_destroy(t, 7),
            Action::CompleteDestroy(t) => self.complete_destroy(t),
            Action::ProvedRetire7 => self.proved_retire(7),
        }
    }
    pub fn projection(&self, transition: Option<Transition>) -> Projection {
        Projection {
            transition,
            current: self.current(7).map(|k| k.generation()),
            retired: self
                .records
                .iter()
                .filter(|r| r.retired)
                .map(|r| (r.key.generation(), r.ambiguous))
                .collect(),
            pending: self
                .pending
                .iter()
                .filter_map(|(token, p)| {
                    if let Pending::Destroy { binding, .. } = p {
                        Some((*token, binding.as_ref().map(|k| k.generation())))
                    } else {
                        None
                    }
                })
                .collect(),
            continuity: (1..self.next_id).map(|id| self.continuity(id)).collect(),
            evictions: self.evictions,
            exact: self.exact,
        }
    }
}

#[derive(Default)]
pub struct Reader {
    pub events: Vec<u64>,
    pub known: Vec<ObjectKey<u64>>,
}
impl Reader {
    pub fn observe(&mut self, event: u64, identity: Option<ObjectKey<u64>>) -> bool {
        // CP05_UNKNOWN: unknown observations never mint a shared key.
        if let Some(key) = identity {
            if self.known.iter().any(|k| k.matches(&key)) {
                return false;
            } // CP05_KNOWN_DUPLICATE
            self.known.push(key);
        }
        self.events.push(event);
        true
    }
}
pub struct Mapping {
    pub key: ObjectKey<u64>,
    pub bytes: u64,
    pub start: u64,
}
pub struct Mappings {
    active_cap: usize,
    retired_cap: usize,
    pub live: Vec<Mapping>,
    retired: Vec<ObjectKey<u64>>,
    next: usize,
    pub partial: bool,
    pub evictions: usize,
    pub durations: Vec<u64>,
    pub successes: usize,
}
impl Mappings {
    pub fn new(active_cap: usize, retired_cap: usize) -> Self {
        Self {
            active_cap,
            retired_cap,
            live: Vec::new(),
            retired: Vec::new(),
            next: 0,
            partial: false,
            evictions: 0,
            durations: Vec::new(),
            successes: 0,
        }
    }
    pub fn map_unknown(&mut self, _bytes: u64) -> bool {
        self.partial = true;
        false
    }
    pub fn map(&mut self, key: ObjectKey<u64>, bytes: u64, start: u64) -> bool {
        if self.live.len() >= self.active_cap
            || self.live.iter().any(|r| r.key.matches(&key))
            || self.retired.iter().any(|k| k.matches(&key))
        {
            return false;
        }
        self.live.push(Mapping { key, bytes, start });
        self.successes += 1;
        true
    }
    pub fn unmap(&mut self, key: &ObjectKey<u64>, end: u64) -> bool {
        let Some(pos) = self.live.iter().position(|r| r.key.matches(key)) else {
            return false;
        };
        let rec = self.live.remove(pos);
        self.durations.push(end - rec.start); // CP05_MAPPING_SAMPLES
        if self.retired_cap == 0 {
            self.partial = true;
            return true;
        }
        if self.retired.len() < self.retired_cap {
            self.retired.push(rec.key);
        } else {
            self.retired[self.next] = rec.key;
            self.next = (self.next + 1) % self.retired_cap;
            self.evictions += 1;
            self.partial = true; // CP05_MAPPING_EVICTION
        }
        true
    }
    pub fn continuity(&self, key: &ObjectKey<u64>) -> Outcome {
        if self.live.iter().any(|r| r.key.matches(key))
            || self.retired.iter().any(|k| k.matches(key))
        {
            Outcome::Matched
        } else {
            Outcome::UnknownContinuity
        }
    }
    pub fn live_bytes(&self) -> u64 {
        self.live.iter().map(|r| r.bytes).sum()
    }
}
