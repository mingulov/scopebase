// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use scopebase_testkit::*;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
pub fn label(s: &str) -> Label {
    Label::parse(s).unwrap()
}
#[derive(Clone, Copy)]
pub enum Retirement {
    Empty,
    Pending,
    AtRun,
    Now,
    Omit,
    Unknown,
}
pub struct Probe {
    pub flag: Arc<AtomicBool>,
    pub polls: Arc<AtomicUsize>,
    pub cancel_at: usize,
}
impl CancellationProbe for Probe {
    fn cancellation_requested(&self) -> bool {
        let p = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.cancel_at == p {
            self.flag.store(true, Ordering::Release)
        }
        self.flag.load(Ordering::Acquire)
    }
}
pub struct Session<'a> {
    pub c: RunContract,
    pub inputs: Vec<FixtureInput<'static>>,
    pub resources: Vec<FixtureResource<'a>>,
    pub flag: Arc<AtomicBool>,
    pub polls: Arc<AtomicUsize>,
    pub cancel_at: usize,
    pub acquisitions: usize,
    pub prepare_error: Option<FixtureErrorCategory>,
    pub collect_error: Option<FixtureErrorCategory>,
    pub collect_error_after_first: bool,
    pub effect: bool,
    pub mode: Retirement,
    pub cancel_prepare: bool,
    pub events: Rc<RefCell<Vec<String>>>,
    pub acquired: bool,
    pub error_first_only: bool,
    pub operation_input: Option<&'static [u8]>,
    pub error_twin_only: bool,
    pub expected_override: Option<&'static [u8]>,
    pub model_input: Option<&'static [u8]>,
}
impl<'a> Session<'a> {
    pub fn new(c: RunContract) -> Self {
        Self {
            c,
            inputs: vec![FixtureInput::new(label("operands"), b"2\n3\n")],
            resources: vec![],
            flag: Arc::new(AtomicBool::new(false)),
            polls: Arc::new(AtomicUsize::new(0)),
            cancel_at: usize::MAX,
            acquisitions: 0,
            prepare_error: None,
            collect_error: None,
            collect_error_after_first: false,
            effect: false,
            mode: Retirement::Empty,
            cancel_prepare: false,
            events: Rc::new(RefCell::new(vec![])),
            acquired: false,
            error_first_only: false,
            operation_input: None,
            error_twin_only: false,
            expected_override: None,
            model_input: None,
        }
    }
    fn batch(&self, i: &CaseInvocation) -> EffectBatch {
        let l = self.c.limits();
        EffectBatch::new(
            EffectBatchValues {
                registrations: if self.effect {
                    vec![EffectRegistration::new(
                        EffectRegistrationValues {
                            resource_id: label(&format!("fixture.{}", i.key().operation_id())),
                            owner: Owner::Fixture,
                            origin: i.key().clone(),
                            kind: label("owned-state"),
                            identity_sha256: Digest256::of_bytes(b"exact resource identity"),
                            recovery_evidence_id: None,
                        },
                        l,
                    )
                    .unwrap()]
                } else {
                    vec![]
                },
                complete: !matches!(self.mode, Retirement::Unknown),
            },
            l,
        )
        .unwrap()
    }
    fn error(
        &self,
        i: &CaseInvocation,
        stage: FixtureStage,
        category: FixtureErrorCategory,
        batch: EffectBatch,
    ) -> FixtureError {
        FixtureError::new(
            FixtureErrorValues {
                key: Some(i.key().clone()),
                stage,
                category,
                errno: Some(13),
                diagnostic_bytes: b"typed fixture failure".to_vec(),
                effects: batch,
                read_progress: None,
            },
            self.c.limits(),
        )
        .unwrap()
    }
}
impl FixtureSession for Session<'_> {
    fn contract(&self) -> &RunContract {
        self.events.borrow_mut().push("contract".into());
        &self.c
    }
    fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static> {
        self.acquisitions += 1;
        self.acquired = true;
        self.events.borrow_mut().push("probe".into());
        Box::new(Probe {
            flag: self.flag.clone(),
            polls: self.polls.clone(),
            cancel_at: self.cancel_at,
        })
    }
    fn prepare(&mut self, i: &CaseInvocation) -> Result<FixtureAccess<'_>, FixtureError> {
        self.events.borrow_mut().push("prepare".into());
        if i.script().schema_id().as_str() == "tt02-refusal-v1" {
            if i.key().case_key().case_id().as_str() == "H01.sum" {
                self.inputs = vec![FixtureInput::new(
                    label("operands"),
                    include_bytes!("positive-input.json"),
                )]
            } else if let Some(bytes) = self.model_input {
                self.inputs = vec![FixtureInput::new(label("operands"), bytes)]
            }
        } else {
            self.inputs = vec![FixtureInput::new(
                label("operands"),
                self.operation_input.unwrap_or(b"2\n3\n"),
            )]
        }
        let batch = self.batch(i);
        if self.cancel_prepare {
            self.flag.store(true, Ordering::Release)
        }
        if let Some(category) = self.prepare_error {
            if (!self.error_first_only || *i.key().operation_id() == 1)
                && (!self.error_twin_only || i.key().case_key().case_id().as_str() == "H01.sum")
            {
                return Err(self.error(i, FixtureStage::Prepare, category, batch));
            }
        }
        FixtureAccess::new(&self.inputs, &self.resources, batch, self.c.limits())
    }
    fn collect(&mut self, i: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError> {
        self.events.borrow_mut().push("collect".into());
        if let Some(category) = self
            .collect_error
            .filter(|_| !self.collect_error_after_first || *i.key().operation_id() > 1)
        {
            return Err(self.error(
                i,
                FixtureStage::Collect,
                category,
                EffectBatch::empty(self.c.limits()),
            ));
        }
        let cov = self
            .c
            .case_rules()
            .iter()
            .find(|r| r.case_key() == i.key().case_key())
            .unwrap()
            .coverage()
            .iter()
            .map(|r| {
                CoverageEvidence::new(
                    CoverageEvidenceValues {
                        id: r.id().clone(),
                        step_ids: r.step_ids().clone(),
                        achieved: 1,
                    },
                    self.c.limits(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let ledger = if i.key().case_key().case_id().as_str() == "H01.sum"
            && *i.key().attempt() == 1
            && *i.key().operation_id() == 1
        {
            include_bytes!("ledger.json").to_vec()
        } else {
            serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"tt02-vector-ledger","key":i.key(),"truth_kind":"fixed-before-execute","evidence_tier":"T0","coverage":cov})).unwrap()
        };
        ExpectedEvidence::new(ExpectedEvidenceValues{key:i.key().clone(),oracle:self.c.expected_oracle().clone(),fixture_schema:i.fixture_schema().clone(),truth_kind:TruthKind::IndependentLedger,expected_bytes:if i.script().schema_id().as_str()=="tt02-refusal-v1"{if i.key().case_key().case_id().as_str()=="H01.sum"{include_bytes!("positive-expected.json").to_vec()}else{self.expected_override.unwrap().to_vec()}}else{br#"{"schema_version":1,"kind":"tt02-u64-expected","steps":[{"step_id":"sum","value":"5"}]}"#.to_vec()},ledger_bytes:ledger,coverage:cov,effects:EffectBatch::empty(self.c.limits())},self.c.limits()).map_err(|_|self.error(i,FixtureStage::Collect,FixtureErrorCategory::InvalidProtocol,EffectBatch::empty(self.c.limits())))
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        self.events
            .borrow_mut()
            .push(format!("retire-fixture-{}", r.call_id()));
        retire(r, self.mode, self.c.limits())
    }
}
pub fn retire(r: &RetireRequest, mode: Retirement, l: &RunLimits) -> RetirementReport {
    let settle = matches!(mode, Retirement::Now)
        || matches!(mode, Retirement::AtRun) && matches!(r.scope(), CleanupScope::Run(_));
    let transitions = if settle {
        r.known_pending()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                EffectTransition::new(
                    EffectTransitionValues {
                        transition_id: label(&format!("retired.{}.{}", r.call_id(), i)),
                        effect: p.clone(),
                        to: TransitionTo::Retired,
                        evidence_ids: vec![label("owned-proof")],
                    },
                    l,
                )
                .unwrap()
            })
            .collect()
    } else {
        vec![]
    };
    RetirementReport::new(
        RetirementReportValues {
            call_id: r.call_id(),
            owner: r.owner(),
            scope: r.scope().clone(),
            discovered: vec![],
            transitions,
            pending_snapshot: if settle || matches!(mode, Retirement::Omit) {
                vec![]
            } else {
                r.known_pending().to_vec()
            },
            complete: !matches!(mode, Retirement::Unknown),
            diagnostic: None,
        },
        l,
    )
    .unwrap()
}
pub struct Adapter {
    pub inner: super::adapter::ArithmeticAdapter,
    pub flag: Arc<AtomicBool>,
    pub cancel_execute: bool,
    pub events: Rc<RefCell<Vec<String>>>,
    pub mode: Retirement,
    pub require_resource: bool,
}
impl ConformanceAdapter for Adapter {
    fn subject(&self) -> SubjectBinding {
        self.events.borrow_mut().push("subject".into());
        self.inner.subject()
    }
    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        self.events.borrow_mut().push("execute".into());
        if self.require_resource {
            let r = f
                .resource::<NonClone>(&label("actual-owner"))
                .expect("actual borrowed resource");
            assert_eq!(r.0, 123)
        }
        let o = self.inner.execute(i, f);
        if self.cancel_execute {
            self.flag.store(true, Ordering::Release)
        }
        o
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        self.events
            .borrow_mut()
            .push(format!("retire-adapter-{}", r.call_id()));
        retire(r, self.mode, &RunLimits::default())
    }
}
pub struct NonClone(pub u64);
pub fn adapter(s: &Session<'_>) -> Adapter {
    Adapter {
        inner: super::adapter::ArithmeticAdapter {
            subject: s.c.expected_subject().clone(),
            wrong: false,
            calls: 0,
        },
        flag: s.flag.clone(),
        cancel_execute: false,
        events: s.events.clone(),
        mode: Retirement::Empty,
        require_resource: false,
    }
}
