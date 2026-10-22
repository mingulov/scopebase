// SPDX-License-Identifier: Apache-2.0
//! Independent literal action/fact oracle. No production API or model imports.
//! Allocation identity is the journal action index; ordinals are projected by
//! counting allocation facts, never read from the adapter's return values.
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allocate7,
    SubmitDestroy(u8),
    CompleteDestroy(u8),
    ProvedRetire7,
}
impl Action {
    pub const ALPHABET: [Self; 6] = [
        Self::Allocate7,
        Self::SubmitDestroy(0),
        Self::SubmitDestroy(1),
        Self::CompleteDestroy(0),
        Self::CompleteDestroy(1),
        Self::ProvedRetire7,
    ];
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Matched,
    Mismatch,
    UnknownContinuity,
    CapacityRefused,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transition {
    pub outcome: Option<Outcome>,
    pub admitted: bool,
    pub duplicate: bool,
    pub bound: bool,
    pub unbound: bool,
    pub stale: bool,
    pub colliding: bool,
    pub forced: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Projection {
    pub transition: Option<Transition>,
    pub current: Option<u64>,
    pub retired: Vec<(u64, bool)>,
    pub pending: Vec<(u8, Option<u64>)>,
    pub continuity: Vec<Outcome>,
    pub evictions: usize,
    pub exact: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FactKind {
    InputObservation,
    Allocation,
    ForcedRetirement,
    SubmissionBinding,
    CompletionRetirement,
    ExplicitRetirement,
    CapacityRefusal,
    DuplicateTokenRefusal,
}
#[derive(Debug)]
pub struct Fact {
    pub id: (usize, FactKind),
    pub allocation: Option<usize>,
}
#[derive(Debug)]
pub struct Row {
    pub action: Action,
    pub facts: Vec<Fact>,
}
pub struct Journal {
    pub rows: Vec<Row>,
    current: Option<usize>,
    dead: BTreeMap<usize, bool>,
    parked: BTreeMap<u8, Option<usize>>,
    evictions: usize,
    exact: bool,
    events: [bool; 4],
}
impl Journal {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            current: None,
            dead: BTreeMap::new(),
            parked: BTreeMap::new(),
            evictions: 0,
            exact: true,
            events: [false; 4],
        }
    }
    pub fn observe(&mut self, action: Action) -> Transition {
        self.events = [false; 4];
        assert!(self.rows.len() < 6, "journal action bound");
        let index = self.rows.len();
        let mut facts = vec![Fact {
            id: (index, FactKind::InputObservation),
            allocation: None,
        }];
        let mut t = Transition::default();
        match action {
            Action::Allocate7 => {
                if let Some(old) = self.current.take() {
                    self.dead.insert(old, true);
                    self.exact = false;
                    t.forced = true;
                    facts.push(Fact {
                        id: (index, FactKind::ForcedRetirement),
                        allocation: Some(old),
                    });
                }
                self.current = Some(index);
                t.admitted = true;
                facts.push(Fact {
                    id: (index, FactKind::Allocation),
                    allocation: Some(index),
                });
            }
            Action::SubmitDestroy(token) => {
                if self.parked.contains_key(&token) {
                    t.duplicate = true;
                    facts.push(Fact {
                        id: (index, FactKind::DuplicateTokenRefusal),
                        allocation: None,
                    });
                } else if self.parked.len() == 2 {
                    t.outcome = Some(Outcome::CapacityRefused);
                    facts.push(Fact {
                        id: (index, FactKind::CapacityRefusal),
                        allocation: None,
                    });
                } else {
                    self.events[1] = self.current.is_none();
                    self.events[2] = self.current.is_some()
                        && self.parked.values().any(|id| *id == self.current);
                    self.parked.insert(token, self.current);
                    t.admitted = true;
                    t.bound = self.current.is_some();
                    t.unbound = self.current.is_none();
                    facts.push(Fact {
                        id: (index, FactKind::SubmissionBinding),
                        allocation: self.current,
                    });
                }
            }
            Action::CompleteDestroy(token) => match self.parked.remove(&token) {
                Some(Some(id)) if Some(id) == self.current => {
                    self.current = None;
                    self.dead.insert(id, false);
                    t.outcome = Some(Outcome::Matched);
                    facts.push(Fact {
                        id: (index, FactKind::CompletionRetirement),
                        allocation: Some(id),
                    });
                }
                Some(Some(old)) => {
                    self.events[0] = self.rows.iter().flat_map(|r| &r.facts).any(|f| {
                        f.id.1 == FactKind::Allocation && f.allocation.is_some_and(|id| id > old)
                    });
                    t.stale = true;
                    t.outcome = Some(Outcome::Mismatch);
                }
                Some(None) => {
                    t.unbound = true;
                    t.colliding = self.current.is_some();
                    if t.colliding {
                        self.exact = false;
                    }
                    t.outcome = Some(Outcome::UnknownContinuity);
                }
                None => {
                    t.outcome = Some(Outcome::UnknownContinuity);
                }
            },
            Action::ProvedRetire7 => {
                if let Some(id) = self.current.take() {
                    self.dead.insert(id, false);
                    t.outcome = Some(Outcome::Matched);
                    facts.push(Fact {
                        id: (index, FactKind::ExplicitRetirement),
                        allocation: Some(id),
                    });
                } else {
                    t.outcome = Some(Outcome::UnknownContinuity);
                }
            }
        }
        while self.dead.len() > 2 {
            self.dead.pop_first();
            self.evictions += 1;
            self.events[3] = true;
        }
        self.rows.push(Row { action, facts });
        t
    }
    fn allocation_indices(&self) -> Vec<usize> {
        self.rows
            .iter()
            .flat_map(|r| &r.facts)
            .filter(|f| f.id.1 == FactKind::Allocation)
            .map(|f| f.allocation.unwrap())
            .collect()
    }
    pub fn projection(&self, transition: Option<Transition>) -> Projection {
        let births = self.allocation_indices();
        let ordinal = |id: usize| {
            (births
                .iter()
                .position(|i| *i == id)
                .expect("allocation fact exists")
                + 1) as u64
        };
        Projection {
            transition,
            current: self.current.map(ordinal),
            retired: self.dead.iter().map(|(id, a)| (ordinal(*id), *a)).collect(),
            pending: self
                .parked
                .iter()
                .map(|(token, id)| (*token, id.map(ordinal)))
                .collect(),
            continuity: births
                .iter()
                .map(|id| {
                    if self.current == Some(*id) || self.dead.contains_key(id) {
                        Outcome::Matched
                    } else {
                        Outcome::UnknownContinuity
                    }
                })
                .collect(),
            evictions: self.evictions,
            exact: self.exact,
        }
    }
    pub fn actions(&self) -> Vec<Action> {
        self.rows.iter().map(|r| r.action).collect()
    }
    /// Reused-old completion, admitted unbound submission, simultaneous bound
    /// same-target overlap, and an actual eviction in the last literal action.
    pub fn population_events(&self) -> [bool; 4] {
        self.events
    }
    pub fn fact_count(&self) -> usize {
        self.rows.iter().map(|r| r.facts.len()).sum()
    }
    pub fn check_fact_ids(&self) {
        for (index, row) in self.rows.iter().enumerate() {
            assert!(row.facts.len() <= 3);
            assert_eq!(row.facts[0].id, (index, FactKind::InputObservation));
            let mut seen = std::collections::BTreeSet::new();
            for fact in &row.facts {
                assert_eq!(fact.id.0, index);
                assert!(seen.insert(fact.id));
                if let Some(id) = fact.allocation {
                    assert!(id <= index);
                }
            }
        }
    }
}
