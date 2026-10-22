// SPDX-License-Identifier: Apache-2.0
//! Strict descriptive receipts. Imported records never acquire live authority.
use crate::artifact::*;
use crate::*;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
wire_enum!(Qualification{Qualified=>"qualified",Failed=>"failed",Incomplete=>"incomplete",Invalid=>"invalid"});
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportOrigin {
    ExecutedHere,
    Imported,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupScope {
    Case(InvocationKey),
    Run(RunId),
}
impl Serialize for CleanupScope {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Case(key) => serde_json::json!({"kind":"case","key":key}).serialize(s),
            Self::Run(run_id) => serde_json::json!({"kind":"run","run_id":run_id}).serialize(s),
        }
    }
}
impl Decode for CleanupScope {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        match v.get("kind").and_then(Value::as_str) {
            Some("case") => {
                let mut o = Obj::new(v, &["kind", "key"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::Case(o.get("key", l)?))
            }
            Some("run") => {
                let mut o = Obj::new(v, &["kind", "run_id"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::Run(o.get("run_id", l)?))
            }
            _ => Err(he(HarnessErrorKind::InvalidInput, "cleanup scope")),
        }
    }
}
#[derive(Debug)]
pub struct RetireRequest {
    pub(crate) call_id: u64,
    pub(crate) owner: Owner,
    pub(crate) scope: CleanupScope,
    pub(crate) deadline: Instant,
    pub(crate) remaining: Duration,
    pub(crate) known_pending: Vec<PendingEffectRef>,
    pub(crate) uncertainty_ids: Vec<Label>,
    pub(crate) remaining_records: u64,
    pub(crate) remaining_retained_bytes: u64,
}
impl RetireRequest {
    pub fn call_id(&self) -> u64 {
        self.call_id
    }
    pub fn owner(&self) -> Owner {
        self.owner
    }
    pub fn scope(&self) -> &CleanupScope {
        &self.scope
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn remaining(&self) -> Duration {
        self.remaining
    }
    pub fn known_pending(&self) -> &[PendingEffectRef] {
        &self.known_pending
    }
    pub fn uncertainty_ids(&self) -> &[Label] {
        &self.uncertainty_ids
    }
    pub fn remaining_records(&self) -> u64 {
        self.remaining_records
    }
    pub fn remaining_retained_bytes(&self) -> u64 {
        self.remaining_retained_bytes
    }
}
record!(RetirementReport,RetirementReportValues{#[serde(with="decimal")]call_id:u64,owner:Owner,scope:CleanupScope,discovered:Vec<EffectRegistration>,transitions:Vec<EffectTransition>,pending_snapshot:Vec<PendingEffectRef>,complete:bool,diagnostic:Option<String>},|v:&RetirementReportValues,l:&RunLimits|{if v.call_id==0{return Err(he(HarnessErrorKind::InvalidInput,"retirement call ID"))}bound(v.discovered.len(),l.effects_total(),"discoveries")?;bound(v.transitions.len(),l.effects_total(),"transitions")?;bound(v.pending_snapshot.len(),l.effects_total(),"snapshot")?;sorted(&v.discovered.iter().map(|r|r.resource_id()).collect::<Vec<_>>())?;sorted(&v.pending_snapshot.iter().map(|r|r.resource_id()).collect::<Vec<_>>())?;if let Some(d)=&v.diagnostic{bound(d.len(),l.diagnostic_bytes(),"retirement diagnostic")?}Ok(())});
wire_enum!(CleanupState{NotRequired=>"not_required",Complete=>"complete",Unresolved=>"unresolved"});
wire_enum!(CleanupCallStatus{Called=>"called",CalledOverBudget=>"called_over_budget",UncalledNoParticipation=>"uncalled_no_participation",UncalledBudgetExhausted=>"uncalled_budget_exhausted"});
wire_enum!(CleanupErrorKind{InvalidProtocol=>"invalid_protocol",LimitExceeded=>"limit_exceeded",BudgetExhausted=>"budget_exhausted"});
record!(
    CleanupError,
    CleanupErrorValues {
        kind: CleanupErrorKind,
        diagnostic: String
    },
    |v: &CleanupErrorValues, l: &RunLimits| bound(
        v.diagnostic.len(),
        l.diagnostic_bytes(),
        "cleanup error"
    )
);
// Private constructor/decoder fields: runner-created observations cannot be injected into ExecutedHere.
macro_rules! internal_getter {
    (oracle_verdict,$ty:ty) => {
        pub fn oracle_verdict(&self) -> Option<&AssertionVerdict> {
            self.oracle_verdict.as_ref()
        }
    };
    (fixture_failure,$ty:ty) => {
        pub fn fixture_failure(&self) -> Option<&FixtureError> {
            self.fixture_failure.as_ref()
        }
    };
    ($field:ident,$ty:ty) => {
        pub fn $field(&self) -> &$ty {
            &self.$field
        }
    };
}
macro_rules! internal_record{($n:ident{$($(#[$attr:meta])* $field:ident:$ty:ty),*$(,)?})=>{#[derive(Clone,Debug,Eq,PartialEq,Serialize)]pub struct $n{$($(#[$attr])*pub(crate)$field:$ty),*}impl $n{$(internal_getter!($field,$ty);)*}impl Decode for $n{fn decode(v:Value,l:&RunLimits)->Result<Self,HarnessError>{let mut o=Obj::new(v,&[$(stringify!($field)),*])?;Ok(Self{$($field:o.get(stringify!($field),l)?),*})}}};}
pub(crate) use internal_record;
internal_record!(CleanupRecord{#[serde(with="decimal")]call_id:u64,owner:Owner,scope:CleanupScope,status:CleanupCallStatus,response:Option<RetirementReport>,error:Option<CleanupError>,state_at_case_end:Option<CleanupState>,state_at_run_end:CleanupState,pending_ids:Vec<Label>,uncertainty_ids:Vec<Label>,#[serde(with="decimal")]hook_elapsed_ns:u64,#[serde(with="decimal")]remaining_before_ns:u64,#[serde(with="decimal")]remaining_after_ns:u64,#[serde(with="decimal")]phase_elapsed_ns:u64,transition_ids:Vec<Label>});
wire_enum!(OmissionCause{PriorStop=>"prior_stop",CaseNotExecutable=>"case_not_executable",StageNotReached=>"stage_not_reached",CleanupUnresolved=>"cleanup_unresolved",NoExecutableMembers=>"no_executable_members",NotEntered=>"not_entered"});
internal_record!(ExecutionCheckpoint{#[serde(with="decimal")]poll_started_elapsed_ns:u64,#[serde(with="decimal")]poll_finished_elapsed_ns:u64,cancelled:Option<bool>});
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckpointSlot {
    Sampled { sample: ExecutionCheckpoint },
    Omitted { cause: OmissionCause },
    NotRecorded,
}
impl Decode for CheckpointSlot {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        match v.get("kind").and_then(Value::as_str) {
            Some("sampled") => {
                let mut o = Obj::new(v, &["kind", "sample"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::Sampled {
                    sample: o.get("sample", l)?,
                })
            }
            Some("omitted") => {
                let mut o = Obj::new(v, &["kind", "cause"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::Omitted {
                    cause: o.get("cause", l)?,
                })
            }
            Some("not_recorded") => {
                Obj::new(v, &["kind"])?;
                Ok(Self::NotRecorded)
            }
            _ => Err(he(HarnessErrorKind::InvalidInput, "checkpoint")),
        }
    }
}
impl CheckpointSlot {
    pub(crate) fn omitted(cause: OmissionCause) -> Self {
        Self::Omitted { cause }
    }
    pub(crate) fn stop(&self, d: u64) -> bool {
        matches!(self,Self::Sampled{sample}if sample.cancelled==Some(true)||sample.poll_finished_elapsed_ns>=d)
    }
}
internal_record!(CheckpointPair {
    before: CheckpointSlot,
    after: CheckpointSlot
});
impl CheckpointPair {
    pub(crate) fn omitted(cause: OmissionCause) -> Self {
        Self {
            before: CheckpointSlot::omitted(cause),
            after: CheckpointSlot::omitted(OmissionCause::NotEntered),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataObservation<T: Serialize> {
    pub(crate) checkpoints: CheckpointPair,
    pub(crate) value: Option<T>,
    #[serde(with = "optional_decimal")]
    pub(crate) returned_elapsed_ns: Option<u64>,
}
impl<T: Serialize> MetadataObservation<T> {
    pub fn checkpoints(&self) -> &CheckpointPair {
        &self.checkpoints
    }
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }
    pub fn returned_elapsed_ns(&self) -> Option<u64> {
        self.returned_elapsed_ns
    }
    pub(crate) fn omitted(cause: OmissionCause) -> Self {
        Self {
            checkpoints: CheckpointPair::omitted(cause),
            value: None,
            returned_elapsed_ns: None,
        }
    }
}
impl<T: Decode + Serialize> Decode for MetadataObservation<T> {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        let mut o = Obj::new(v, &["checkpoints", "value", "returned_elapsed_ns"])?;
        Ok(Self {
            checkpoints: o.get("checkpoints", l)?,
            value: o.get("value", l)?,
            returned_elapsed_ns: o.get("returned_elapsed_ns", l)?,
        })
    }
}
internal_record!(RunnerObservations{#[serde(with="decimal")]contract_returned_elapsed_ns:u64,after_contract:CheckpointSlot,entry_subject:MetadataObservation<SubjectBinding>,entry_oracle:MetadataObservation<OracleBinding>,final_subject:MetadataObservation<SubjectBinding>,final_oracle:MetadataObservation<OracleBinding>,completion:CheckpointSlot});
internal_record!(ExecutionCheckpoints {
    prepare: CheckpointPair,
    execute: CheckpointPair,
    collect: CheckpointPair,
    judge: CheckpointPair
});
impl ExecutionCheckpoints {
    pub(crate) fn omitted(cause: OmissionCause) -> Self {
        Self {
            prepare: CheckpointPair::omitted(cause),
            execute: CheckpointPair::omitted(cause),
            collect: CheckpointPair::omitted(cause),
            judge: CheckpointPair::omitted(cause),
        }
    }
    pub(crate) fn pair(&self, s: EnteredStage) -> &CheckpointPair {
        match s {
            EnteredStage::Prepare => &self.prepare,
            EnteredStage::Execute => &self.execute,
            EnteredStage::Collect => &self.collect,
            EnteredStage::Judge => &self.judge,
        }
    }
    pub(crate) fn pair_mut(&mut self, s: EnteredStage) -> &mut CheckpointPair {
        match s {
            EnteredStage::Prepare => &mut self.prepare,
            EnteredStage::Execute => &mut self.execute,
            EnteredStage::Collect => &mut self.collect,
            EnteredStage::Judge => &mut self.judge,
        }
    }
}
wire_enum!(EnteredStage{Prepare=>"prepare",Execute=>"execute",Collect=>"collect",Judge=>"judge"});
wire_enum!(ExecutionState{Completed=>"completed",Blocked=>"blocked",NotRun=>"not_run",Skipped=>"skipped",HarnessError=>"harness_error"});
internal_record!(EffectiveCoverage{id:Label,step_ids:Vec<Label>,#[serde(with="decimal")]raw_achieved:u64,#[serde(with="decimal")]effective_achieved:u64});
internal_record!(CaseTerminal {
    key: InvocationKey,
    execution: ExecutionState,
    #[serde(with = "decimal")]
    after_cleanup_call_id: u64
});
internal_record!(CaseResult{key:InvocationKey,script_sha256:Digest256,tier:EvidenceTier,entered_stages:Vec<EnteredStage>,execution_checkpoints:ExecutionCheckpoints,execution:ExecutionState,reason:Option<String>,outcome:Option<CaseOutcome>,fixture_failure:Option<FixtureError>,expected_evidence:Option<ExpectedEvidence>,oracle_verdict:Option<AssertionVerdict>,effective_checks:Vec<AssertionCheck>,capability:CapabilityEvidence,coverage:Vec<EffectiveCoverage>,effect_batches:Vec<EffectBatch>,#[serde(with="decimal_list")]case_cleanup_call_ids:Vec<u64>,terminal:Option<CaseTerminal>});
internal_record!(RunTerminal{qualification:Qualification,reasons:Vec<Label>,#[serde(with="decimal")]after_cleanup_call_id:u64});
internal_record!(ReportWire{schema_version:u32,kind:String,run_contract_sha256:Digest256,run_id:RunId,selection:SelectionBinding,artifacts:Vec<ArtifactBinding>,runner_observations:RunnerObservations,case_results:Vec<CaseResult>,cleanup_records:Vec<CleanupRecord>,run_terminal:Option<RunTerminal>});
/// An admitted descriptive report cannot manufacture fixture or process owners.
/// ```compile_fail
/// use scopebase_testkit::RunReport;
/// let forged = RunReport { qualification: Default::default() };
/// ```
#[derive(Clone, Debug)]
pub struct RunReport {
    pub(crate) wire: ReportWire,
    pub(crate) qualification: Qualification,
    pub(crate) origin: ReportOrigin,
    pub(crate) limits: RunLimits,
}
impl RunReport {
    pub fn qualification(&self) -> Qualification {
        self.qualification
    }
    pub fn origin(&self) -> ReportOrigin {
        self.origin
    }
    pub fn case_results(&self) -> &[CaseResult] {
        &self.wire.case_results
    }
    pub fn cleanup_records(&self) -> &[CleanupRecord] {
        &self.wire.cleanup_records
    }
    pub fn runner_observations(&self) -> &RunnerObservations {
        &self.wire.runner_observations
    }
    pub fn reasons(&self) -> &[Label] {
        self.wire.run_terminal.as_ref().map_or(&[], |t| &t.reasons)
    }
    pub fn to_json(&self, ceiling: RunLimits) -> Result<Vec<u8>, HarnessError> {
        ceiling
            .lowered(self.limits.values())
            .map_err(|e| he(HarnessErrorKind::LimitExceeded, &e.to_string()))?;
        let encoded = encoded_size(
            &self.wire,
            self.limits
                .receipt_bytes()
                .min(self.limits.retained_bytes()),
        )?;
        // The wire is already owned. Reserve a conservative payload bound for
        // it and the exact new encoding before allocating its output buffer.
        let mut budget = RetainedPayload::new(encoded, self.limits.retained_bytes())?;
        budget.reserve(encoded)?;
        let mut b = Vec::new();
        b.try_reserve_exact(
            usize::try_from(encoded)
                .map_err(|_| he(HarnessErrorKind::LimitExceeded, "encoded size"))?,
        )
        .map_err(|_| he(HarnessErrorKind::LimitExceeded, "receipt allocation"))?;
        serde_json::to_writer(&mut b, &self.wire)
            .map_err(|_| he(HarnessErrorKind::InvalidInput, "receipt encoding"))?;
        bound(b.len(), self.limits.receipt_bytes(), "receipt")?;
        bound(b.len(), self.limits.retained_bytes(), "encoded receipt")?;
        Ok(b)
    }
    pub fn from_json(
        c: &RunContract,
        bytes: &[u8],
        ceiling: RunLimits,
    ) -> Result<Self, HarnessError> {
        ceiling
            .lowered(c.limits().values())
            .map_err(|e| he(HarnessErrorKind::LimitExceeded, &e.to_string()))?;
        // Decoding can simultaneously own a parsed hexadecimal String and its
        // decoded byte vector. Reserve that conservative peak before parsing;
        // caller-owned input is borrowed and is not silently used as allowance.
        let decode_peak = (bytes.len() as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add(c.0.reservation))
            .ok_or_else(|| he(HarnessErrorKind::LimitExceeded, "receipt decode peak"))?;
        if decode_peak > c.limits().retained_bytes() {
            return Err(he(HarnessErrorKind::LimitExceeded, "receipt retention"));
        }
        let mut wire = ReportWire::decode(
            parse(bytes, c.limits().receipt_bytes(), c.limits())?,
            c.limits(),
        )?;
        let q = reconstruct(c, &mut wire, true)?;
        Ok(Self {
            wire,
            qualification: q,
            origin: ReportOrigin::Imported,
            limits: c.limits().clone(),
        })
    }
}
#[derive(Default)]
pub(crate) struct Dimensions {
    pub invalid: bool,
    pub failed: bool,
    pub incomplete: bool,
    pub reasons: BTreeSet<String>,
}
impl Dimensions {
    pub fn reason(&mut self, q: Qualification, s: &str) {
        match q {
            Qualification::Invalid => self.invalid = true,
            Qualification::Failed => self.failed = true,
            Qualification::Incomplete => self.incomplete = true,
            _ => {}
        }
        self.reasons.insert(s.into());
    }
    pub fn qualification(&self) -> Qualification {
        if self.invalid {
            Qualification::Invalid
        } else if self.failed {
            Qualification::Failed
        } else if self.incomplete {
            Qualification::Incomplete
        } else {
            Qualification::Qualified
        }
    }
}
#[derive(Default)]
pub(crate) struct Ledger {
    pub regs: BTreeMap<Label, EffectRegistration>,
    pub retired: BTreeSet<Label>,
    pub transitions: BTreeSet<Label>,
    pub uncertain: BTreeMap<Label, (Owner, InvocationKey)>,
    pub participants: BTreeSet<(Owner, InvocationKey)>,
    pub by_origin: BTreeMap<(Owner, InvocationKey), BTreeSet<Label>>,
    pub by_uncertainty: BTreeMap<(Owner, InvocationKey), BTreeSet<Label>>,
    pub counts: BTreeMap<InvocationKey, u64>,
}
impl Ledger {
    pub(crate) fn pending(&self, owner: Owner, scope: &CleanupScope) -> Vec<PendingEffectRef> {
        match scope {
            CleanupScope::Case(key) => self
                .by_origin
                .get(&(owner, key.clone()))
                .into_iter()
                .flatten()
                .filter(|id| !self.retired.contains(*id))
                .map(|id| PendingEffectRef::registration(&self.regs[id]))
                .collect(),
            CleanupScope::Run(_) => self
                .regs
                .values()
                .filter(|r| {
                    *r.owner() == owner
                        && !self.retired.contains(r.resource_id())
                        && in_scope(r.origin(), scope)
                })
                .map(PendingEffectRef::registration)
                .collect(),
        }
    }
    pub(crate) fn uncertainty(&self, owner: Owner, scope: &CleanupScope) -> Vec<Label> {
        match scope {
            CleanupScope::Case(key) => self
                .by_uncertainty
                .get(&(owner, key.clone()))
                .map_or(vec![], |s| s.iter().cloned().collect()),
            CleanupScope::Run(_) => self
                .uncertain
                .iter()
                .filter(|(_, (o, k))| *o == owner && in_scope(k, scope))
                .map(|(id, _)| id.clone())
                .collect(),
        }
    }
    pub(crate) fn participates(&self, owner: Owner, scope: &CleanupScope) -> bool {
        match scope {
            CleanupScope::Case(key) => self.participants.contains(&(owner, key.clone())),
            CleanupScope::Run(_) => self
                .participants
                .iter()
                .any(|(o, k)| *o == owner && in_scope(k, scope)),
        }
    }
    pub(crate) fn uncertain_at(&mut self, owner: Owner, key: &InvocationKey, stage: &str) {
        let id = Label::parse(&format!(
            "u.{}.{}.{}",
            key.operation_id(),
            match owner {
                Owner::Adapter => "a",
                Owner::Fixture => "f",
            },
            stage
        ))
        .expect("bounded uncertainty label");
        self.uncertain
            .entry(id.clone())
            .or_insert((owner, key.clone()));
        self.by_uncertainty
            .entry((owner, key.clone()))
            .or_default()
            .insert(id);
    }
    pub(crate) fn register(
        &mut self,
        c: &RunContract,
        r: &EffectRegistration,
        owner: Owner,
        scope: &CleanupScope,
    ) -> Result<(), HarnessError> {
        if *r.owner() != owner
            || r.origin().run_id() != c.run_id()
            || !in_scope(r.origin(), scope)
            || !self.participants.contains(&(owner, r.origin().clone()))
            || self.regs.contains_key(r.resource_id())
        {
            return Err(he(
                HarnessErrorKind::InvalidProtocol,
                "effect owner/origin/duplicate",
            ));
        }
        if self.regs.len() as u64 >= c.limits().effects_total()
            || self.counts.get(r.origin()).copied().unwrap_or(0)
                >= *c.rule(r.origin().case_key()).max_effects() as u64
        {
            return Err(he(HarnessErrorKind::LimitExceeded, "effect inventory"));
        }
        self.by_origin
            .entry((owner, r.origin().clone()))
            .or_default()
            .insert(r.resource_id().clone());
        *self.counts.entry(r.origin().clone()).or_default() += 1;
        self.regs.insert(r.resource_id().clone(), r.clone());
        Ok(())
    }
    pub(crate) fn batch(
        &mut self,
        c: &RunContract,
        b: &EffectBatch,
        owner: Owner,
        key: &InvocationKey,
        stage: &str,
    ) -> Result<(), HarnessError> {
        for r in b.registrations() {
            self.register(c, r, owner, &CleanupScope::Case(key.clone()))?
        }
        if !*b.complete() {
            self.uncertain_at(owner, key, stage)
        }
        Ok(())
    }
    pub(crate) fn response(
        &mut self,
        c: &RunContract,
        r: &RetirementReport,
        owner: Owner,
        scope: &CleanupScope,
        call: u64,
    ) -> Result<(), HarnessError> {
        if *r.call_id() != call || *r.owner() != owner || r.scope() != scope {
            return Err(he(
                HarnessErrorKind::InvalidProtocol,
                "retirement response identity",
            ));
        }
        for d in r.discovered() {
            self.register(c, d, owner, scope)?
        }
        for t in r.transitions() {
            let p = t.effect();
            let Some(orig) = self.regs.get(p.resource_id()) else {
                return Err(he(
                    HarnessErrorKind::InvalidProtocol,
                    "unknown transition resource",
                ));
            };
            if PendingEffectRef::registration(orig) != *p
                || *p.owner() != owner
                || !in_scope(p.origin(), scope)
                || self.retired.contains(p.resource_id())
                || !self.transitions.insert(t.transition_id().clone())
            {
                return Err(he(
                    HarnessErrorKind::InvalidProtocol,
                    "retirement transition",
                ));
            }
            self.retired.insert(p.resource_id().clone());
        }
        let expected = self.pending(owner, scope);
        for p in r.pending_snapshot() {
            if expected
                .binary_search_by(|x| x.resource_id().cmp(p.resource_id()))
                .ok()
                .is_none_or(|i| expected[i] != *p)
            {
                return Err(he(
                    HarnessErrorKind::InvalidProtocol,
                    "snapshot changed or retired resource",
                ));
            }
        }
        if *r.complete() && r.pending_snapshot() != &expected {
            return Err(he(
                HarnessErrorKind::InvalidProtocol,
                "omitted pending resource",
            ));
        }
        if !*r.complete() {
            for k in self
                .participants
                .iter()
                .filter(|(o, k)| *o == owner && in_scope(k, scope))
                .map(|(_, k)| k.clone())
                .collect::<Vec<_>>()
            {
                self.uncertain_at(owner, &k, "inventory")
            }
        }
        Ok(())
    }
    pub(crate) fn state(
        &self,
        owner: Owner,
        scope: &CleanupScope,
        called: bool,
        complete: bool,
    ) -> CleanupState {
        if !self.pending(owner, scope).is_empty()
            || !self.uncertainty(owner, scope).is_empty()
            || (self.participates(owner, scope) && (!called || !complete))
        {
            CleanupState::Unresolved
        } else if match scope {
            CleanupScope::Case(key) => self.by_origin.contains_key(&(owner, key.clone())),
            CleanupScope::Run(_) => self
                .regs
                .values()
                .any(|r| *r.owner() == owner && in_scope(r.origin(), scope)),
        } {
            CleanupState::Complete
        } else {
            CleanupState::NotRequired
        }
    }
}
pub(crate) fn in_scope(k: &InvocationKey, s: &CleanupScope) -> bool {
    match s {
        CleanupScope::Case(x) => k == x,
        CleanupScope::Run(id) => k.run_id() == id,
    }
}
fn protocol(s: &str) -> HarnessError {
    he(HarnessErrorKind::InvalidProtocol, s)
}
pub(crate) fn validate_read_progress(
    c: &RunContract,
    p: &InputReadProgress,
) -> Result<(), HarnessError> {
    let a = c
        .artifact(p.file_id())
        .ok_or_else(|| protocol("read progress artifact"))?;
    if *a.length() != p.expected_length()
        || p.bytes_returned()
            > p.expected_length()
                .checked_add(1)
                .ok_or_else(|| protocol("read progress overflow"))?
        || p.read_calls() > c.limits().read_calls()
        || (p.bytes_returned() > 0 && p.read_calls() == 0)
    {
        return Err(protocol("read progress bound"));
    }
    Ok(())
}
pub(crate) fn validate_expected(
    c: &RunContract,
    key: &InvocationKey,
    r: &CaseRule,
    e: &ExpectedEvidence,
) -> Result<(), HarnessError> {
    e.check_bounds(c.limits())?;
    if e.key() != key
        || e.oracle() != c.expected_oracle()
        || e.fixture_schema() != r.fixture_schema()
    {
        return Err(protocol("expected evidence identity"));
    }
    if e.coverage().len() != r.coverage().len()
        || e.coverage().iter().any(|v| {
            !r.coverage()
                .iter()
                .any(|need| v.id() == need.id() && v.step_ids() == need.step_ids())
        })
    {
        return Err(protocol("expected coverage set"));
    }
    if *e.truth_kind() == TruthKind::FixedBeforeExecute {
        let raw = admit_vector_ledger(e.ledger_bytes(), key, r, c.limits())?;
        if raw != *e.coverage() {
            return Err(protocol("coverage differs from ledger"));
        }
    }
    for (bytes, role, digest) in [
        (
            e.expected_bytes(),
            ArtifactRole::ExpectedVector,
            e.expected_sha256(),
        ),
        (
            e.ledger_bytes(),
            ArtifactRole::FixtureLedger,
            e.ledger_sha256(),
        ),
    ] {
        if !c
            .0
            .truth_bindings
            .contains(&(role, bytes.len() as u64, digest))
        {
            return Err(protocol("inline truth artifact"));
        }
    }
    Ok(())
}
pub(crate) fn validate_outcome(
    k: &InvocationKey,
    r: &CaseRule,
    o: &CaseOutcome,
    limits: &RunLimits,
) -> Result<(), HarnessError> {
    match o {
        CaseOutcome::Observed(v) => v.check_bounds(limits)?,
        CaseOutcome::OperationError(v) => v.check_bounds(limits)?,
    }
    if o.key() != k {
        return Err(protocol("outcome key"));
    }
    let steps = r
        .script()
        .steps()
        .iter()
        .map(|s| s.step_id().clone())
        .collect::<Vec<_>>();
    let done = o.completed_steps();
    if done.len() > steps.len() || done != &steps[..done.len()] {
        return Err(protocol("completed step prefix"));
    }
    match o {
        CaseOutcome::Observed(x) => {
            if done != steps
                || x.schema_id() != r.observation_schema().id()
                || x.schema_revision() != r.observation_schema().revision()
            {
                return Err(protocol("observation schema/progress"));
            }
        }
        CaseOutcome::OperationError(e) => {
            if *e.category() == CaseErrorCategory::UnsupportedSchema
                && (e.step_id().is_some()
                    || !done.is_empty()
                    || e.partial_observation().is_some()
                    || e.errno().is_some()
                    || *e.cause().cause() != RefusalCause::Unknown)
            {
                return Err(protocol("dialect rejection progress/cause"));
            }
            if let Some(id) = e.step_id() {
                if steps.get(done.len()) != Some(id) {
                    return Err(protocol("failing step progress"));
                }
            }
            if let Some(p) = e.partial_observation() {
                if p.schema_id() != r.observation_schema().id()
                    || p.schema_revision() != r.observation_schema().revision()
                {
                    return Err(protocol("partial schema"));
                }
            }
        }
    }
    Ok(())
}
fn coverage_for(r: &CaseRule, x: &CaseResult) -> Result<Vec<EffectiveCoverage>, HarnessError> {
    let mut out = vec![];
    for need in r.coverage() {
        let raw = x
            .expected_evidence
            .as_ref()
            .and_then(|e| e.coverage().iter().find(|c| c.id() == need.id()));
        if let Some(raw) = raw {
            if raw.step_ids() != need.step_ids() {
                return Err(protocol("coverage steps"));
            }
        }
        let raw_achieved = raw.map_or(0, |c| *c.achieved());
        let participated=match need.kind(){CoverageKind::Setup=>x.entered_stages.contains(&EnteredStage::Execute),CoverageKind::Positive=>x.outcome.as_ref().is_some_and(|o|need.step_ids().iter().all(|id|o.completed_steps().contains(id))),CoverageKind::Trigger|CoverageKind::ActiveExcluded=>x.outcome.as_ref().is_some_and(|o|need.step_ids().iter().all(|id|o.completed_steps().contains(id)||matches!(o,CaseOutcome::OperationError(e)if e.step_id().as_ref()==Some(id))))};
        out.push(EffectiveCoverage {
            id: need.id().clone(),
            step_ids: need.step_ids().clone(),
            raw_achieved,
            effective_achieved: if participated { raw_achieved } else { 0 },
        })
    }
    Ok(out)
}
fn row_functional(r: &CaseRule, x: &CaseResult) -> bool {
    x.execution == ExecutionState::Completed
        && matches!(x.outcome, Some(CaseOutcome::Observed(..)))
        && x.oracle_verdict
            .as_ref()
            .is_some_and(|v| matches!(v.harness(), HarnessValidity::Valid))
        && x.effective_checks.len() == r.assertions().len()
        && x.effective_checks
            .iter()
            .all(|c| *c.status() == CheckStatus::Pass)
        && x.coverage.iter().all(|c| {
            r.coverage()
                .iter()
                .any(|n| n.id() == &c.id && c.effective_achieved >= *n.minimum())
        })
        && *x.capability.state() == CapabilityState::Supported
}
fn intent_ok(r: &CaseRule, x: &CaseResult, twin_ok: bool) -> bool {
    let cap = &x.capability;
    match r.intent() {
        ClaimIntent::PositiveSupport => {
            matches!(x.outcome, Some(CaseOutcome::Observed(..)))
                && *cap.state() == CapabilityState::Supported
        }
        ClaimIntent::AssertionOnly => {
            x.outcome.is_some()
                && matches!(
                    cap.state(),
                    CapabilityState::Unknown | CapabilityState::NotApplicable
                )
        }
        ClaimIntent::ExpectedRefusal {
            cause,
            step_id,
            stage,
            positive_twin: _,
            ..
        } => {
            let state = match cause {
                KnownRefusalCause::Permission => CapabilityState::Denied,
                KnownRefusalCause::Verifier | KnownRefusalCause::License => {
                    CapabilityState::Incompatible
                }
                KnownRefusalCause::UnsupportedOperation => CapabilityState::Unsupported,
            };
            let actual = match cause {
                KnownRefusalCause::Permission => RefusalCause::Permission,
                KnownRefusalCause::Verifier => RefusalCause::Verifier,
                KnownRefusalCause::License => RefusalCause::License,
                KnownRefusalCause::UnsupportedOperation => RefusalCause::UnsupportedOperation,
            };
            *cap.state() == state
                && twin_ok
                && matches!(&x.outcome,Some(CaseOutcome::OperationError(e))if e.step_id().as_ref()==Some(step_id)&&e.stage()==stage&&*e.category()==CaseErrorCategory::Refused&&*e.cause().cause()==actual)
        }
    }
}
struct Gates<'a> {
    d: u64,
    last: u64,
    stopped: bool,
    tail: bool,
    full: bool,
    dims: &'a mut Dimensions,
}
impl Gates<'_> {
    fn slot(&mut self, s: &CheckpointSlot) -> Result<Option<bool>, HarnessError> {
        match s {
            CheckpointSlot::Sampled { sample: p } => {
                if self.tail
                    || p.poll_started_elapsed_ns < self.last
                    || p.poll_finished_elapsed_ns < p.poll_started_elapsed_ns
                {
                    return Err(protocol("checkpoint ordering"));
                }
                if p.poll_started_elapsed_ns >= self.d {
                    if p.cancelled.is_some()
                        || p.poll_finished_elapsed_ns != p.poll_started_elapsed_ns
                    {
                        return Err(protocol("deadline poll must be null"));
                    }
                } else if p.cancelled.is_none() {
                    return Err(protocol("null cancellation is not false"));
                }
                self.last = p.poll_finished_elapsed_ns;
                let cancel = p.cancelled == Some(true);
                let deadline = p.poll_finished_elapsed_ns >= self.d;
                if cancel {
                    self.dims
                        .reason(Qualification::Incomplete, "runner.cancelled")
                }
                if deadline {
                    self.dims
                        .reason(Qualification::Incomplete, "runner.deadline")
                }
                self.stopped |= cancel || deadline;
                Ok(Some(!cancel && !deadline))
            }
            CheckpointSlot::NotRecorded => {
                if self.full {
                    return Err(protocol("full receipt unrecorded checkpoint"));
                }
                self.tail = true;
                self.dims
                    .reason(Qualification::Incomplete, "runner.observations_partial");
                Ok(None)
            }
            CheckpointSlot::Omitted { .. } => Ok(None),
        }
    }
    fn pair(
        &mut self,
        p: &CheckpointPair,
        entered: bool,
        allowed: impl Fn(OmissionCause, bool) -> bool,
    ) -> Result<(), HarnessError> {
        let prior = self.stopped;
        let before = self.slot(&p.before)?;
        if entered {
            if prior || before != Some(true) {
                return Err(protocol("call entered after stop or without before gate"));
            }
            if !matches!(
                p.after,
                CheckpointSlot::Sampled { .. } | CheckpointSlot::NotRecorded
            ) {
                return Err(protocol("returned call missing after gate"));
            }
            self.slot(&p.after)?;
        } else {
            if let CheckpointSlot::Omitted { cause } = &p.before {
                if !allowed(*cause, prior) {
                    return Err(protocol("false omission premise"));
                }
            } else if before == Some(true) && self.full {
                return Err(protocol("permitted call not entered"));
            }
            if !matches!(
                p.after,
                CheckpointSlot::Omitted {
                    cause: OmissionCause::NotEntered
                } | CheckpointSlot::NotRecorded
            ) {
                return Err(protocol("uncalled after gate"));
            }
            self.slot(&p.after)?;
        }
        Ok(())
    }
    fn metadata<T: Serialize + Eq>(
        &mut self,
        m: &MetadataObservation<T>,
        expected: &T,
        label: &str,
        final_slot: bool,
        noexec: bool,
        unresolved: bool,
    ) -> Result<(), HarnessError> {
        if m.value.is_some() != m.returned_elapsed_ns.is_some() {
            return Err(protocol("metadata value/time pair"));
        }
        let prior = self.stopped;
        let before = self.slot(&m.checkpoints.before)?;
        if let Some(value) = &m.value {
            if prior || before != Some(true) {
                return Err(protocol("metadata called without permitted gate"));
            }
            let returned = m.returned_elapsed_ns.unwrap();
            if returned < self.last {
                return Err(protocol("metadata return ordering"));
            }
            self.last = returned;
            if !matches!(
                m.checkpoints.after,
                CheckpointSlot::Sampled { .. } | CheckpointSlot::NotRecorded
            ) {
                return Err(protocol("returned metadata missing after gate"));
            }
            self.slot(&m.checkpoints.after)?;
            if value != expected {
                self.dims
                    .reason(Qualification::Invalid, &format!("runner.{label}_mismatch"));
                self.stopped = true
            }
        } else {
            if let CheckpointSlot::Omitted { cause } = &m.checkpoints.before {
                let okay = match cause {
                    OmissionCause::PriorStop => prior,
                    OmissionCause::NoExecutableMembers => noexec,
                    OmissionCause::CleanupUnresolved => final_slot && unresolved,
                    _ => false,
                };
                if !okay {
                    return Err(protocol("metadata omission premise"));
                }
            } else if before == Some(true) && self.full {
                return Err(protocol("missing returned metadata"));
            }
            if !matches!(
                m.checkpoints.after,
                CheckpointSlot::Omitted {
                    cause: OmissionCause::NotEntered
                } | CheckpointSlot::NotRecorded
            ) {
                return Err(protocol("uncalled metadata after"));
            }
            self.slot(&m.checkpoints.after)?;
            self.dims.reason(
                Qualification::Incomplete,
                &format!("runner.{label}_missing"),
            );
        }
        Ok(())
    }
}
pub(crate) fn reconstruct(
    c: &RunContract,
    w: &mut ReportWire,
    check: bool,
) -> Result<Qualification, HarnessError> {
    if !check {
        // Discard previous derived payload before the completion fold. Raw
        // returned evidence remains intact, and no old/new summary overlap is
        // hidden behind assignment.
        for x in &mut w.case_results {
            x.effective_checks.clear();
            x.coverage.clear();
            x.capability = unjudged(c.limits());
        }
    }
    let vectors = c
        .artifacts()
        .iter()
        .filter(|a| {
            matches!(
                a.role(),
                ArtifactRole::FixtureInput
                    | ArtifactRole::ExpectedVector
                    | ArtifactRole::FixtureLedger
            )
        })
        .try_fold(0u64, |n, a| {
            n.checked_add(*a.length())
                .ok_or_else(|| he(HarnessErrorKind::LimitExceeded, "retained vectors"))
        })?;
    let base =
        c.0.reservation
            .checked_add(vectors)
            .ok_or_else(|| he(HarnessErrorKind::LimitExceeded, "retained fold"))?;
    let mut copies = RetainedPayload::new(base, c.limits().retained_bytes())?;
    copies.reserve(encoded_size(w, c.limits().retained_bytes())?)?;
    if w.schema_version != 1 || w.kind != "tt02-run-report" {
        return Err(he(
            HarnessErrorKind::UnsupportedSchema,
            "receipt major/kind",
        ));
    }
    if w.run_contract_sha256 != c.sha256()
        || &w.run_id != c.run_id()
        || &w.selection != c.selection()
        || w.artifacts != c.artifacts()
    {
        return Err(he(
            HarnessErrorKind::InvalidBinding,
            "receipt contract/selection/artifacts",
        ));
    }
    let full = w.run_terminal.is_some();
    let mut dims = Dimensions::default();
    if !full {
        dims.reason(Qualification::Incomplete, "run.unfinished")
    }
    if !*c.selection().definition_complete() {
        dims.reason(Qualification::Incomplete, "selection.draft")
    }
    if !c.selection().open_owners().is_empty() {
        dims.reason(Qualification::Incomplete, "selection.open_owner")
    }
    let noexec =
        c.0.cases
            .values()
            .all(|s| s.implementation_status() == ImplementationStatus::Unimplemented);
    if noexec {
        dims.reason(Qualification::Incomplete, "runner.no_executable_members")
    }
    if matches!(
        c.expected_subject().provenance(),
        BindingProvenance::SelfReported { .. }
    ) || matches!(
        c.expected_oracle().provenance(),
        BindingProvenance::SelfReported { .. }
    ) {
        dims.reason(Qualification::Incomplete, "binding.self_reported")
    }
    for (i, record) in w.cleanup_records.iter().enumerate() {
        if record.call_id != i as u64 + 1 {
            return Err(protocol("cleanup slots must form a fixed prefix"));
        }
    }
    unique(&w.case_results.iter().map(|x| &x.key).collect::<Vec<_>>())?;
    if w.case_results.len() > c.schedule().len()
        || w.case_results
            .iter()
            .zip(c.schedule())
            .any(|(x, key)| &x.key != key)
    {
        return Err(protocol("case results must form a schedule prefix"));
    }
    if w.case_results.len() != c.schedule().len() {
        dims.reason(Qualification::Incomplete, "case.missing")
    }
    let mut functional_stats: BTreeMap<CaseKey, (usize, bool)> = BTreeMap::new();
    let row_index = w
        .case_results
        .iter()
        .enumerate()
        .map(|(i, x)| (x.key.clone(), i))
        .collect::<BTreeMap<_, _>>();
    let mut ledger = Ledger::default();
    let mut rec_index = 0;
    let mut closed_ns = 0u64;
    let allowance = c.limits().retirement_ms() * 1_000_000;
    let mut run_complete = BTreeMap::new();
    for index in 0..=c.schedule().len() {
        let scope = if index < c.schedule().len() {
            CleanupScope::Case(c.schedule()[index].clone())
        } else {
            CleanupScope::Run(c.run_id().clone())
        };
        if index < c.schedule().len() {
            let key = &c.schedule()[index];
            let r = c.rule(key.case_key());
            if c.0.cases[key.case_key()].implementation_status()
                == ImplementationStatus::Unimplemented
            {
                dims.reason(Qualification::Incomplete, "selection.unimplemented")
            }
            if let Some(row) = row_index.get(key) {
                let x = &mut w.case_results[*row];
                if let Some(reason) = &x.reason {
                    bound(reason.len(), c.limits().diagnostic_bytes(), "case reason")?;
                }
                if x.script_sha256 != r.script().sha256()
                    || x.tier != *r.tier()
                    || x.case_cleanup_call_ids != vec![2 * index as u64 + 1, 2 * index as u64 + 2]
                {
                    return Err(protocol("case rule/script/schema/call slots"));
                }
                let stages = [
                    EnteredStage::Prepare,
                    EnteredStage::Execute,
                    EnteredStage::Collect,
                    EnteredStage::Judge,
                ];
                if x.entered_stages.len() > 4
                    || x.entered_stages != stages[..x.entered_stages.len()]
                {
                    return Err(protocol("entered stages prefix"));
                }
                if x.execution == ExecutionState::NotRun && !x.entered_stages.is_empty() {
                    return Err(protocol("not run entered"));
                }
                if x.entered_stages.contains(&EnteredStage::Prepare) {
                    ledger.participants.insert((Owner::Fixture, key.clone()));
                }
                if x.entered_stages.contains(&EnteredStage::Execute) {
                    ledger.participants.insert((Owner::Adapter, key.clone()));
                }
                if let Some(o) = &x.outcome {
                    if !x.entered_stages.contains(&EnteredStage::Execute) {
                        return Err(protocol("unentered outcome"));
                    }
                    validate_outcome(key, r, o, c.limits())?;
                } else if x.entered_stages.contains(&EnteredStage::Collect) {
                    return Err(protocol("collect without outcome"));
                }
                if let Some(e) = &x.expected_evidence {
                    if !x.entered_stages.contains(&EnteredStage::Collect) {
                        return Err(protocol("unentered expected evidence"));
                    }
                    validate_expected(c, key, r, e)?;
                }
                if x.entered_stages.contains(&EnteredStage::Judge)
                    && (x.outcome.is_none() || x.expected_evidence.is_none())
                {
                    return Err(protocol("judge without prerequisites"));
                }
                if let Some(error) = &x.fixture_failure {
                    let stage = match error.stage() {
                        FixtureStage::Prepare => EnteredStage::Prepare,
                        FixtureStage::Collect => EnteredStage::Collect,
                        _ => return Err(protocol("fixture failure stage")),
                    };
                    let count = if stage == EnteredStage::Prepare { 1 } else { 3 };
                    if error.key().as_ref() != Some(key)
                        || x.entered_stages.len() != count
                        || x.entered_stages.last() != Some(&stage)
                        || x.expected_evidence.is_some()
                        || x.oracle_verdict.is_some()
                        || (stage == EnteredStage::Prepare && x.outcome.is_some())
                        || (stage == EnteredStage::Collect && x.outcome.is_none())
                    {
                        return Err(protocol("fixture failure key/placement"));
                    }
                    let execution = if *error.category() == FixtureErrorCategory::InvalidProtocol {
                        ExecutionState::HarnessError
                    } else {
                        ExecutionState::Blocked
                    };
                    if x.execution != execution {
                        return Err(protocol("fixture failure execution"));
                    }
                    if let Some(p) = error.read_progress() {
                        validate_read_progress(c, p)?;
                    }
                    if *error.category() == FixtureErrorCategory::InvalidProtocol {
                        dims.reason(Qualification::Invalid, "fixture.invalid_protocol")
                    }
                }
                let producing = [
                    EnteredStage::Prepare,
                    EnteredStage::Execute,
                    EnteredStage::Collect,
                ];
                if x.effect_batches.len() > 3 {
                    return Err(protocol("extra effect mirror"));
                }
                for (position, batch) in x.effect_batches.iter().enumerate() {
                    let stage = producing[position];
                    if !x.entered_stages.contains(&stage) {
                        return Err(protocol("effect mirror unentered stage"));
                    }
                    let owner = if stage == EnteredStage::Execute {
                        Owner::Adapter
                    } else {
                        Owner::Fixture
                    };
                    let source = match stage {
                        EnteredStage::Prepare => x
                            .fixture_failure
                            .as_ref()
                            .filter(|e| *e.stage() == FixtureStage::Prepare)
                            .map(|e| e.effects()),
                        EnteredStage::Execute => x.outcome.as_ref().map(|o| o.effects()),
                        EnteredStage::Collect => x
                            .fixture_failure
                            .as_ref()
                            .filter(|e| *e.stage() == FixtureStage::Collect)
                            .map(|e| e.effects())
                            .or_else(|| x.expected_evidence.as_ref().map(|e| e.effects())),
                        _ => None,
                    };
                    if let Some(source) = source {
                        if source != batch {
                            return Err(protocol("effect mirror mismatch"));
                        }
                    } else if stage != EnteredStage::Prepare {
                        return Err(protocol("effect mirror lacks returned source"));
                    }
                    ledger.batch(
                        c,
                        batch,
                        owner,
                        key,
                        match stage {
                            EnteredStage::Prepare => "prepare",
                            EnteredStage::Execute => "execute",
                            _ => "collect",
                        },
                    )?;
                }
                for (position, stage) in producing.into_iter().enumerate() {
                    let typed_return = match stage {
                        EnteredStage::Prepare => {
                            x.fixture_failure
                                .as_ref()
                                .is_some_and(|e| *e.stage() == FixtureStage::Prepare)
                                || x.entered_stages.contains(&EnteredStage::Execute)
                        }
                        EnteredStage::Execute => x.outcome.is_some(),
                        EnteredStage::Collect => {
                            x.expected_evidence.is_some()
                                || x.fixture_failure
                                    .as_ref()
                                    .is_some_and(|e| *e.stage() == FixtureStage::Collect)
                        }
                        _ => false,
                    };
                    if x.entered_stages.contains(&stage)
                        && (typed_return
                            || matches!(
                                x.execution_checkpoints.pair(stage).after,
                                CheckpointSlot::Sampled { .. }
                            ))
                        && x.effect_batches.len() <= position
                    {
                        return Err(protocol("returned effect mirror missing"));
                    }
                }
                let cv = coverage_for(r, x)?;
                if check && x.coverage != cv {
                    return Err(protocol("effective coverage contradiction"));
                }
                x.coverage = cv;
                let twin_ok = match r.intent() {
                    ClaimIntent::ExpectedRefusal { positive_twin, .. } => {
                        functional_stats.get(positive_twin).is_some_and(|(n, ok)| {
                            *ok && *n == *c.rule(positive_twin).attempts() as usize
                        })
                    }
                    _ => true,
                };
                let mut checks = vec![];
                let mut capability = unjudged(c.limits());
                if let Some(v) = &x.oracle_verdict {
                    if !x.entered_stages.contains(&EnteredStage::Judge)
                        || v.checks().len() != r.assertions().len()
                        || v.checks()
                            .iter()
                            .any(|a| !r.assertions().iter().any(|r| r.id() == a.id()))
                    {
                        return Err(protocol("oracle assertion set/stage"));
                    }
                    let harness_valid = matches!(v.harness(), HarnessValidity::Valid);
                    if !harness_valid {
                        if x.execution != ExecutionState::HarnessError {
                            return Err(protocol("invalid harness execution"));
                        }
                        dims.reason(Qualification::Invalid, "oracle.harness_invalid")
                    } else {
                        capability = copies.cloned(v.capability())?;
                    }
                    for rule in r.assertions() {
                        let raw = v.checks().iter().find(|a| a.id() == rule.id()).unwrap();
                        let gate = (!*rule.requires_positive_twin() || twin_ok)
                            && rule.requires_coverage().iter().all(|id| {
                                x.coverage.iter().any(|cv| {
                                    &cv.id == id
                                        && r.coverage().iter().any(|n| {
                                            n.id() == id && cv.effective_achieved >= *n.minimum()
                                        })
                                })
                            });
                        let mut a = copies.cloned(raw)?;
                        if !harness_valid {
                            a.0.status = CheckStatus::NotJudged;
                            a.0.reason = Some("oracle.harness_invalid".into())
                        } else if !gate {
                            a.0.status = CheckStatus::NotJudged;
                            a.0.reason = Some("prerequisite missing".into())
                        }
                        checks.push(a);
                    }
                } else {
                    if x.entered_stages.contains(&EnteredStage::Judge)
                        && matches!(
                            x.execution_checkpoints.judge.after,
                            CheckpointSlot::Sampled { .. }
                        )
                    {
                        return Err(protocol("returned judge verdict missing"));
                    }
                    dims.reason(Qualification::Incomplete, "case.not_judged");
                    checks = r
                        .assertions()
                        .iter()
                        .map(|a| {
                            AssertionCheck::new(
                                AssertionCheckValues {
                                    id: a.id().clone(),
                                    status: CheckStatus::NotJudged,
                                    reason: Some("oracle.not_returned".into()),
                                },
                                c.limits(),
                            )
                            .expect("admitted assertion")
                        })
                        .collect();
                }
                if check && x.capability != capability {
                    return Err(protocol("derived capability contradiction"));
                }
                x.capability = capability;
                if check && checks != x.effective_checks {
                    return Err(protocol("effective checks contradiction"));
                }
                x.effective_checks = checks;
                for a in &x.effective_checks {
                    match a.status() {
                        CheckStatus::Fail => {
                            dims.reason(Qualification::Failed, "case.semantic_fail")
                        }
                        CheckStatus::NotJudged => {
                            dims.reason(Qualification::Incomplete, "case.not_judged")
                        }
                        _ => {}
                    }
                }
                if x.coverage.iter().any(|cv| {
                    r.coverage()
                        .iter()
                        .any(|n| n.id() == &cv.id && cv.effective_achieved < *n.minimum())
                }) {
                    dims.reason(Qualification::Incomplete, "case.coverage")
                }
                if x.execution != ExecutionState::Completed {
                    dims.reason(Qualification::Incomplete, "case.not_completed")
                }
                if !intent_ok(r, x, twin_ok) {
                    dims.reason(Qualification::Incomplete, "case.intent")
                }
                if let Some(t) = &x.terminal {
                    if t.key != x.key
                        || t.execution != x.execution
                        || t.after_cleanup_call_id != 2 * index as u64 + 2
                    {
                        return Err(protocol("case terminal"));
                    }
                } else {
                    dims.reason(Qualification::Incomplete, "case.unfinished")
                }
                let stats = functional_stats
                    .entry(key.case_key().clone())
                    .or_insert((0, true));
                stats.0 += 1;
                stats.1 &= row_functional(r, x);
            }
        }
        let phase_start_index = rec_index;
        let mut phase_ns = None;
        let mut prior_remaining = allowance.saturating_sub(closed_ns);
        let mut hooks = 0u64;
        for (offset, owner) in [Owner::Adapter, Owner::Fixture].into_iter().enumerate() {
            let id = 2 * index as u64 + offset as u64 + 1;
            let Some(rec) = w.cleanup_records.get_mut(rec_index) else {
                dims.reason(Qualification::Incomplete, "cleanup.missing");
                continue;
            };
            if rec.call_id != id {
                if full {
                    return Err(protocol("missing/out of order cleanup slot"));
                }
                dims.reason(Qualification::Incomplete, "cleanup.missing");
                continue;
            }
            rec_index += 1;
            if rec.owner != owner || rec.scope != scope {
                return Err(protocol("cleanup owner/scope"));
            }
            if phase_ns.is_some_and(|n| n != rec.phase_elapsed_ns)
                || rec.remaining_before_ns > prior_remaining
                || rec.remaining_after_ns > rec.remaining_before_ns
                || rec.hook_elapsed_ns > rec.phase_elapsed_ns
            {
                return Err(protocol("cleanup phase accounting"));
            }
            phase_ns = Some(rec.phase_elapsed_ns);
            prior_remaining = rec.remaining_after_ns;
            hooks = hooks
                .checked_add(rec.hook_elapsed_ns)
                .ok_or_else(|| protocol("cleanup time overflow"))?;
            let participated = ledger.participates(owner, &scope);
            let mut complete = false;
            let called = matches!(
                rec.status,
                CleanupCallStatus::Called | CleanupCallStatus::CalledOverBudget
            );
            match rec.status {
                CleanupCallStatus::UncalledNoParticipation => {
                    if participated
                        || rec.response.is_some()
                        || rec.error.is_some()
                        || rec.hook_elapsed_ns != 0
                    {
                        return Err(protocol("false no participation"));
                    }
                }
                CleanupCallStatus::UncalledBudgetExhausted => {
                    if !participated
                        || rec.remaining_before_ns != 0
                        || rec.response.is_some()
                        || rec.hook_elapsed_ns != 0
                    {
                        return Err(protocol("false exhausted retirement"));
                    }
                    dims.reason(Qualification::Incomplete, "retirement.budget");
                    for k in ledger
                        .participants
                        .iter()
                        .filter(|(o, k)| *o == owner && in_scope(k, &scope))
                        .map(|(_, k)| k.clone())
                        .collect::<Vec<_>>()
                    {
                        ledger.uncertain_at(
                            owner,
                            &k,
                            if index < c.schedule().len() {
                                "case-uncalled"
                            } else {
                                "run-uncalled"
                            },
                        )
                    }
                }
                CleanupCallStatus::Called | CleanupCallStatus::CalledOverBudget => {
                    if !participated || rec.remaining_before_ns == 0 {
                        return Err(protocol(
                            "retirement called without allowance/participation",
                        ));
                    }
                    let Some(response) = &rec.response else {
                        return Err(protocol("called retirement response absent"));
                    };
                    if rec.status == CleanupCallStatus::CalledOverBudget {
                        if rec.hook_elapsed_ns <= rec.remaining_before_ns {
                            return Err(protocol("false overbudget"));
                        }
                        dims.reason(Qualification::Incomplete, "retirement.budget")
                    } else if rec.hook_elapsed_ns > rec.remaining_before_ns {
                        return Err(protocol("hidden retirement overrun"));
                    }
                    ledger.response(c, response, owner, &scope, id)?;
                    complete = *response.complete() && rec.error.is_none();
                    if rec.transition_ids
                        != response
                            .transitions()
                            .iter()
                            .map(|t| t.transition_id().clone())
                            .collect::<Vec<_>>()
                    {
                        return Err(protocol("transition IDs"));
                    }
                }
            }
            if let Some(error) = &rec.error {
                if called {
                    let keys = ledger
                        .participants
                        .iter()
                        .filter(|(o, k)| *o == owner && in_scope(k, &scope))
                        .map(|(_, k)| k.clone())
                        .collect::<Vec<_>>();
                    for key in keys {
                        ledger.uncertain_at(
                            owner,
                            &key,
                            if index < c.schedule().len() {
                                "case-invalid"
                            } else {
                                "run-invalid"
                            },
                        );
                    }
                }
                match error.kind() {
                    CleanupErrorKind::InvalidProtocol => {
                        dims.reason(Qualification::Invalid, "cleanup.invalid_protocol")
                    }
                    CleanupErrorKind::LimitExceeded => {
                        dims.reason(Qualification::Incomplete, "cleanup.limit")
                    }
                    CleanupErrorKind::BudgetExhausted => {
                        dims.reason(Qualification::Incomplete, "retirement.budget")
                    }
                }
            }
            let state = ledger.state(owner, &scope, called, complete);
            let pending = ledger
                .pending(owner, &scope)
                .iter()
                .map(|p| p.resource_id().clone())
                .collect::<Vec<_>>();
            let uncertain = ledger.uncertainty(owner, &scope);
            if check
                && (rec.pending_ids != pending
                    || rec.uncertainty_ids != uncertain
                    || (index < c.schedule().len() && rec.state_at_case_end != Some(state))
                    || (index == c.schedule().len() && rec.state_at_case_end.is_some()))
            {
                return Err(protocol("cleanup derived snapshot/state"));
            }
            rec.pending_ids = pending;
            rec.uncertainty_ids = uncertain;
            if index < c.schedule().len() {
                rec.state_at_case_end = Some(state)
            } else {
                rec.state_at_case_end = None;
                run_complete.insert(owner, called && complete);
            }
        }
        if let Some(n) = phase_ns {
            if hooks > n || prior_remaining > allowance.saturating_sub(closed_ns.saturating_add(n))
            {
                return Err(protocol("cleanup cumulative time"));
            }
            closed_ns = closed_ns.saturating_add(n);
            if closed_ns >= allowance && ledger.participants.len() > 0 {
                dims.reason(Qualification::Incomplete, "retirement.budget")
            }
        }
        if full && rec_index - phase_start_index != 2 {
            return Err(protocol("terminal missing cleanup slots"));
        }
    }
    if rec_index != w.cleanup_records.len() {
        return Err(protocol("extra cleanup records"));
    }
    let mut unresolved = false;
    for rec in &mut w.cleanup_records {
        let complete = run_complete.get(&rec.owner).copied().unwrap_or(false);
        let state = ledger.state(rec.owner, &rec.scope, complete, complete);
        if check && rec.state_at_run_end != state {
            return Err(protocol("case-to-run cleanup state"));
        }
        rec.state_at_run_end = state;
        if state == CleanupState::Unresolved {
            unresolved = true;
            dims.reason(Qualification::Incomplete, "cleanup.unresolved")
        }
    }
    // Fixed normal-work evidence traversal, including final-only drift and late stops.
    let d = c.limits().execution_ms() * 1_000_000;
    let obs = &w.runner_observations;
    let mut gates = Gates {
        d,
        last: obs.contract_returned_elapsed_ns,
        stopped: false,
        tail: false,
        full,
        dims: &mut dims,
    };
    gates.slot(&obs.after_contract)?;
    if full && !matches!(obs.after_contract, CheckpointSlot::Sampled { .. }) {
        return Err(protocol("after contract sample required"));
    }
    gates.metadata(
        &obs.entry_subject,
        c.expected_subject(),
        "entry_subject",
        false,
        noexec,
        unresolved,
    )?;
    gates.metadata(
        &obs.entry_oracle,
        c.expected_oracle(),
        "entry_oracle",
        false,
        noexec,
        unresolved,
    )?;
    for key in c.schedule() {
        if let Some(row) = row_index.get(key) {
            let x = &w.case_results[*row];
            let executable = c.0.cases[key.case_key()].implementation_status()
                != ImplementationStatus::Unimplemented;
            for s in [
                EnteredStage::Prepare,
                EnteredStage::Execute,
                EnteredStage::Collect,
                EnteredStage::Judge,
            ] {
                let entered = x.entered_stages.contains(&s);
                let stage_blocked = match s {
                    EnteredStage::Prepare => false,
                    EnteredStage::Execute | EnteredStage::Collect => x
                        .fixture_failure
                        .as_ref()
                        .is_some_and(|e| *e.stage() == FixtureStage::Prepare),
                    EnteredStage::Judge => x.fixture_failure.is_some(),
                };
                gates.pair(
                    x.execution_checkpoints.pair(s),
                    entered,
                    |cause, prior| match cause {
                        OmissionCause::PriorStop => prior,
                        OmissionCause::CaseNotExecutable => {
                            !executable
                                && x.entered_stages.is_empty()
                                && x.execution == ExecutionState::NotRun
                        }
                        OmissionCause::StageNotReached => stage_blocked,
                        _ => false,
                    },
                )?;
                if let Some(error) = x.fixture_failure.as_ref().filter(|e| {
                    matches!(
                        (s, e.stage()),
                        (EnteredStage::Prepare, FixtureStage::Prepare)
                            | (EnteredStage::Collect, FixtureStage::Collect)
                    )
                }) {
                    match error.category() {
                        FixtureErrorCategory::Cancelled => {
                            gates.stopped = true;
                            gates
                                .dims
                                .reason(Qualification::Incomplete, "runner.cancelled")
                        }
                        FixtureErrorCategory::TimedOut => {
                            gates.stopped = true;
                            gates
                                .dims
                                .reason(Qualification::Incomplete, "runner.deadline")
                        }
                        FixtureErrorCategory::InvalidProtocol => {
                            gates.stopped = true;
                        }
                        _ => {}
                    }
                }
                if s == EnteredStage::Execute
                    && matches!(&x.outcome,Some(CaseOutcome::OperationError(e))if matches!(e.category(),CaseErrorCategory::Cancelled|CaseErrorCategory::TimedOut))
                {
                    gates.stopped = true;
                    match x.outcome.as_ref() {
                        Some(CaseOutcome::OperationError(error))
                            if *error.category() == CaseErrorCategory::Cancelled =>
                        {
                            gates
                                .dims
                                .reason(Qualification::Incomplete, "runner.cancelled")
                        }
                        _ => gates
                            .dims
                            .reason(Qualification::Incomplete, "runner.deadline"),
                    }
                }
                if s == EnteredStage::Judge
                    && x.oracle_verdict
                        .as_ref()
                        .is_some_and(|v| matches!(v.harness(), HarnessValidity::Invalid { .. }))
                {
                    gates.stopped = true;
                }
            }
        } else {
            // An omitted unfinished row closes the normal-work stream. Fixed
            // cleanup recovery remains valid, but no later sample can follow.
            gates.tail = true;
        }
    }
    gates.metadata(
        &obs.final_subject,
        c.expected_subject(),
        "final_subject",
        true,
        noexec,
        unresolved,
    )?;
    gates.metadata(
        &obs.final_oracle,
        c.expected_oracle(),
        "final_oracle",
        true,
        noexec,
        unresolved,
    )?;
    gates.slot(&obs.completion)?;
    if full && !matches!(obs.completion, CheckpointSlot::Sampled { .. }) {
        return Err(protocol("completion sample required"));
    }
    if matches!(obs.completion, CheckpointSlot::Sampled { .. }) && closed_ns > gates.last {
        return Err(protocol("cleanup phases exceed run elapsed"));
    }
    let q = dims.qualification();
    let reasons = dims
        .reasons
        .iter()
        .map(|s| Label::parse(s).expect("fixed reason labels"))
        .collect::<Vec<_>>();
    if let Some(t) = &mut w.run_terminal {
        if t.after_cleanup_call_id != 2 * c.schedule().len() as u64 + 2
            || w.cleanup_records.len() != 2 * c.schedule().len() + 2
        {
            return Err(protocol("run terminal before cleanup"));
        }
        if check && (t.qualification != q || t.reasons != reasons) {
            return Err(protocol("terminal summary contradiction"));
        }
        t.qualification = q;
        t.reasons = reasons;
    }
    Ok(q)
}
impl BoundValue for CleanupScope {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        match self {
            Self::Case(k) => k.check_bounds(l),
            Self::Run(_) => Ok(()),
        }
    }
}

pub(crate) fn unjudged(l: &RunLimits) -> CapabilityEvidence {
    CapabilityEvidence::new(
        CapabilityEvidenceValues {
            state: CapabilityState::Unknown,
            method: Label::parse("runner.unjudged").expect("fixed label"),
            context: String::new(),
            evidence_ids: vec![],
        },
        l,
    )
    .expect("unjudged sentinel")
}
