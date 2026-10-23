// SPDX-License-Identifier: Apache-2.0
//! Scripted effectful fake backend for BP05 executor/retirement tests.
//!
//! Test support only: drives `execute_plan` through scripted node outcomes
//! keyed by plan-index range, records every backend call in order, and
//! serves programmable retire/retire_uncertain outcomes. The fake honors
//! the `AttachBackend` safety contract (audited charge, proven no-effect,
//! custody-carrying uncertain, truthful retirement); it performs no native
//! effects, so all custody assertions here are ownership/accounting proofs.
//! Genuine native retirement failure stays a TT05 live case.
//!
//! The pool takes backend ownership, so observation flows through a shared
//! [`Probe`] handle cloned before the backend moves into the pool.
#![allow(dead_code)]

use scopebase_bpf::attach::{
    AttachBackend, AttachMode, CustodyCharge, NativeAttach, NativeRetire, Site,
};
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

/// Scripted outcome for one attach node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptOutcome {
    Attached,
    NoEffect(ErrorKind),
    Uncertain,
}

/// Programmable retirement result: FIFO queues per object id, defaulting
/// to `NativeRetire::Retired` once exhausted.
#[derive(Debug, Default)]
pub struct RetireScript {
    link: HashMap<u64, VecDeque<RetireStep>>,
    uncertain: HashMap<u64, VecDeque<RetireStep>>,
}

#[derive(Debug, Clone)]
pub enum RetireStep {
    Retired,
    Pending,
    Failed(ErrorKind),
}

impl RetireStep {
    fn into_native(self) -> NativeRetire {
        match self {
            RetireStep::Retired => NativeRetire::Retired,
            RetireStep::Pending => NativeRetire::Pending,
            RetireStep::Failed(kind) => {
                NativeRetire::Failed(OperationError::new(kind, Stage::Retire, None, None))
            }
        }
    }
}

impl RetireScript {
    pub fn link_steps(&mut self, id: u64, steps: Vec<RetireStep>) {
        self.link.insert(id, steps.into());
    }

    pub fn uncertain_steps(&mut self, id: u64, steps: Vec<RetireStep>) {
        self.uncertain.insert(id, steps.into());
    }

    fn next_link(&mut self, id: u64) -> NativeRetire {
        self.link
            .get_mut(&id)
            .and_then(VecDeque::pop_front)
            .unwrap_or(RetireStep::Retired)
            .into_native()
    }

    fn next_uncertain(&mut self, id: u64) -> NativeRetire {
        self.uncertain
            .get_mut(&id)
            .and_then(VecDeque::pop_front)
            .unwrap_or(RetireStep::Retired)
            .into_native()
    }
}

/// Shared observation handle: survives the backend's move into the pool.
#[derive(Debug, Default)]
pub struct Probe {
    /// Ordered call log: `attach start-end`, `retire link:id`,
    /// `retire_uncertain id`. Charge calls use tick counters instead:
    /// `custody_charge` takes `&self`, so it cannot push to this log.
    pub log: RefCell<Vec<String>>,
    clock: Cell<usize>,
    pub charge_tick: Cell<Option<usize>>,
    first_attach_tick: Cell<Option<usize>>,
    pub charge_calls: Cell<usize>,
    pub attach_calls: Cell<usize>,
    pub retire_calls: Cell<usize>,
    pub link_drops: Rc<Cell<usize>>,
    pub uncertain_drops: Rc<Cell<usize>>,
}

impl Probe {
    fn tick(&self) -> usize {
        let tick = self.clock.get() + 1;
        self.clock.set(tick);
        tick
    }

    /// True when a charge call preceded the first attach call.
    pub fn charge_precedes_first_attach(&self) -> bool {
        match (self.charge_tick.get(), self.first_attach_tick.get()) {
            (Some(charge), Some(first)) => charge < first,
            _ => false,
        }
    }

    /// Attach node ranges in call order, e.g. `["0-4", "0-2"]`.
    pub fn attach_order(&self) -> Vec<String> {
        self.log
            .borrow()
            .iter()
            .filter_map(|entry| entry.strip_prefix("attach ").map(str::to_string))
            .collect()
    }

    /// Retired link ids in call order.
    pub fn retire_order(&self) -> Vec<u64> {
        self.log
            .borrow()
            .iter()
            .filter_map(|entry| {
                entry
                    .strip_prefix("retire link:")
                    .and_then(|id| id.parse::<u64>().ok())
            })
            .collect()
    }

    /// Uncertain-retire ids in call order.
    pub fn uncertain_retire_order(&self) -> Vec<u64> {
        self.log
            .borrow()
            .iter()
            .filter_map(|entry| {
                entry
                    .strip_prefix("retire_uncertain ")
                    .and_then(|id| id.parse::<u64>().ok())
            })
            .collect()
    }
}

/// Drop-counted fake link: the guard proves the pool drops link values
/// only after confirmed native retirement (clean path) and never runs
/// their destructors when leaking unresolved state (pool-Drop path).
#[derive(Debug)]
pub struct FakeLink {
    pub id: u64,
    drop_count: Rc<Cell<usize>>,
}

impl Drop for FakeLink {
    fn drop(&mut self) {
        self.drop_count.set(self.drop_count.get() + 1);
    }
}

/// Drop-counted fake uncertain custody.
#[derive(Debug)]
pub struct FakeUncertain {
    pub id: u64,
    drop_count: Rc<Cell<usize>>,
}

impl Drop for FakeUncertain {
    fn drop(&mut self) {
        self.drop_count.set(self.drop_count.get() + 1);
    }
}

/// Scripted backend with unit authority (pure executor tests).
#[derive(Debug)]
pub struct ScriptBackend {
    /// Full plan sites, used to map an attach slice back to its node range.
    sites: Vec<Site>,
    script: HashMap<(usize, usize), ScriptOutcome>,
    default: ScriptOutcome,
    pub retire_script: RetireScript,
    next_id: u64,
    /// When set, `attach` panics at the given call index (0-based).
    pub panic_at_attach: Option<usize>,
    pub probe: Rc<Probe>,
}

impl ScriptBackend {
    pub fn new(sites: Vec<Site>) -> Self {
        Self {
            sites,
            script: HashMap::new(),
            default: ScriptOutcome::Attached,
            retire_script: RetireScript::default(),
            next_id: 0,
            panic_at_attach: None,
            probe: Rc::new(Probe::default()),
        }
    }

    pub fn script_node(&mut self, node: (usize, usize), outcome: ScriptOutcome) {
        self.script.insert(node, outcome);
    }

    pub fn set_default(&mut self, outcome: ScriptOutcome) {
        self.default = outcome;
    }

    fn node_of(&self, sites: &[Site]) -> (usize, usize) {
        assert!(!sites.is_empty(), "fake never receives empty slices");
        let start = self
            .sites
            .iter()
            .position(|site| *site == sites[0])
            .expect("attach slice starts at a plan site");
        assert_eq!(
            &self.sites[start..start + sites.len()],
            sites,
            "attach slice is a contiguous plan range"
        );
        (start, start + sites.len())
    }
}

// SAFETY: test fake; the script serves contract-honoring outcomes only.
unsafe impl AttachBackend for ScriptBackend {
    type Authority = ();
    type Link = FakeLink;
    type Uncertain = FakeUncertain;

    fn custody_charge(
        &self,
        _authority: &Self::Authority,
        sites: &[Site],
    ) -> Result<CustodyCharge, OperationError> {
        self.probe
            .charge_calls
            .set(self.probe.charge_calls.get() + 1);
        self.probe.charge_tick.set(Some(self.probe.tick()));
        Ok(CustodyCharge {
            link_slots: sites.len() + 1,
            retained_bytes: sites.len() * 16,
        })
    }

    fn attach(
        &mut self,
        _authority: &Self::Authority,
        sites: &[Site],
        _mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        let call = self.probe.attach_calls.get();
        self.probe.attach_calls.set(call + 1);
        if self.panic_at_attach == Some(call) {
            panic!("scripted backend panic at attach call {call}");
        }
        if self.probe.first_attach_tick.get().is_none() {
            self.probe.first_attach_tick.set(Some(self.probe.tick()));
        }
        let node = self.node_of(sites);
        self.probe
            .log
            .borrow_mut()
            .push(format!("attach {}-{}", node.0, node.1));
        match self.script.get(&node).copied().unwrap_or(self.default) {
            ScriptOutcome::Attached => {
                let id = self.next_id;
                self.next_id += 1;
                NativeAttach::Attached(FakeLink {
                    id,
                    drop_count: Rc::clone(&self.probe.link_drops),
                })
            }
            ScriptOutcome::NoEffect(kind) => {
                NativeAttach::NoEffect(OperationError::new(kind, Stage::Attach, None, None))
            }
            ScriptOutcome::Uncertain => {
                let id = self.next_id;
                self.next_id += 1;
                NativeAttach::Uncertain {
                    custody: FakeUncertain {
                        id,
                        drop_count: Rc::clone(&self.probe.uncertain_drops),
                    },
                    cause: OperationError::new(ErrorKind::Backend, Stage::Attach, None, None),
                }
            }
        }
    }

    fn retire(&mut self, link: &mut Self::Link) -> NativeRetire {
        let call = self.probe.retire_calls.get();
        self.probe.retire_calls.set(call + 1);
        self.probe
            .log
            .borrow_mut()
            .push(format!("retire link:{}", link.id));
        self.retire_script.next_link(link.id)
    }

    fn retire_uncertain(&mut self, custody: &mut Self::Uncertain) -> NativeRetire {
        let call = self.probe.retire_calls.get();
        self.probe.retire_calls.set(call + 1);
        self.probe
            .log
            .borrow_mut()
            .push(format!("retire_uncertain {}", custody.id));
        self.retire_script.next_uncertain(custody.id)
    }
}
