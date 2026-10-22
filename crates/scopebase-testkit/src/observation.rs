// SPDX-License-Identifier: Apache-2.0
//! Outcomes carry facts and progress, never a qualification setter.
use crate::artifact::*;
use crate::*;
use serde::Serialize;
use serde_json::Value;
wire_enum!(Owner{Adapter=>"adapter",Fixture=>"fixture"});
wire_enum!(CaseErrorCategory{Unavailable=>"unavailable",Refused=>"refused",InvalidOutput=>"invalid_output",UnsupportedSchema=>"unsupported_schema",Cancelled=>"cancelled",TimedOut=>"timed_out",Io=>"io",Other=>"other"});
wire_enum!(FixtureErrorCategory{Unavailable=>"unavailable",Denied=>"denied",InvalidProtocol=>"invalid_protocol",Cancelled=>"cancelled",TimedOut=>"timed_out",Io=>"io",Other=>"other"});
wire_enum!(FixtureStage{Admission=>"admission",Prepare=>"prepare",Collect=>"collect",Retire=>"retire"});
wire_enum!(RefusalCause{Permission=>"permission",Verifier=>"verifier",License=>"license",UnsupportedOperation=>"unsupported_operation",Unknown=>"unknown"});
wire_enum!(KnownRefusalCause{Permission=>"permission",Verifier=>"verifier",License=>"license",UnsupportedOperation=>"unsupported_operation"});
wire_enum!(TruthKind{FixedBeforeExecute=>"fixed_before_execute",IndependentLedger=>"independent_ledger"});
record!(
    SchemaBinding,
    SchemaBindingValues {
        id: Label,
        revision: u32
    },
    |v: &SchemaBindingValues, _: &RunLimits| {
        if v.revision == 0 {
            Err(he(HarnessErrorKind::InvalidInput, "schema revision"))
        } else {
            Ok(())
        }
    }
);
record!(EffectRegistration,EffectRegistrationValues{resource_id:Label,owner:Owner,origin:InvocationKey,kind:Label,identity_sha256:Digest256,recovery_evidence_id:Option<Label>},|_:&EffectRegistrationValues,_:&RunLimits|Ok(()));
record!(EffectBatch,EffectBatchValues{registrations:Vec<EffectRegistration>,complete:bool},|v:&EffectBatchValues,l:&RunLimits|{bound(v.registrations.len(),l.effects_per_case(),"effects")?;sorted(&v.registrations.iter().map(|r|r.resource_id()).collect::<Vec<_>>())});
impl EffectBatch {
    pub fn empty(l: &RunLimits) -> Self {
        Self::new(
            EffectBatchValues {
                registrations: vec![],
                complete: true,
            },
            l,
        )
        .expect("empty batch")
    }
}
record!(
    PendingEffectRef,
    PendingEffectRefValues {
        resource_id: Label,
        owner: Owner,
        origin: InvocationKey,
        identity_sha256: Digest256
    },
    |_: &PendingEffectRefValues, _: &RunLimits| Ok(())
);
impl PendingEffectRef {
    pub(crate) fn registration(r: &EffectRegistration) -> Self {
        Self(PendingEffectRefValues {
            resource_id: r.resource_id().clone(),
            owner: *r.owner(),
            origin: r.origin().clone(),
            identity_sha256: *r.identity_sha256(),
        })
    }
}
wire_enum!(TransitionTo{Retired=>"retired"});
record!(EffectTransition,EffectTransitionValues{transition_id:Label,effect:PendingEffectRef,to:TransitionTo,evidence_ids:Vec<Label>},|v:&EffectTransitionValues,l:&RunLimits|{bound(v.evidence_ids.len(),l.effects_total(),"evidence")?;if v.evidence_ids.is_empty(){return Err(he(HarnessErrorKind::InvalidInput,"transition evidence"))}sorted(&v.evidence_ids)});
record!(RefusalEvidence,RefusalEvidenceValues{cause:RefusalCause,method:Label,evidence_ids:Vec<Label>,tier:EvidenceTier},|v:&RefusalEvidenceValues,l:&RunLimits|{bound(v.evidence_ids.len(),l.effects_total(),"evidence")?;sorted(&v.evidence_ids)});
record!(PartialObservation,PartialObservationValues{schema_id:Label,schema_revision:u32,#[serde(with="hex_bytes")]bytes:Vec<u8>},|v:&PartialObservationValues,l:&RunLimits|{bound(v.bytes.len(),l.observation_bytes(),"partial observation")?;if v.schema_revision==0{return Err(he(HarnessErrorKind::InvalidInput,"schema revision"))}Ok(())});
record!(Observation,ObservationValues{key:InvocationKey,schema_id:Label,schema_revision:u32,completed_steps:Vec<Label>,#[serde(with="hex_bytes")]bytes:Vec<u8>,effects:EffectBatch},|v:&ObservationValues,l:&RunLimits|{bound(v.bytes.len(),l.observation_bytes(),"observation")?;bound(v.completed_steps.len(),l.steps_per_invocation(),"completed steps")?;unique(&v.completed_steps)?;if v.schema_revision==0{return Err(he(HarnessErrorKind::InvalidInput,"schema revision"))}Ok(())});
record!(CaseError,CaseErrorValues{key:InvocationKey,step_id:Option<Label>,stage:Label,category:CaseErrorCategory,errno:Option<i32>,#[serde(with="hex_bytes")]diagnostic_bytes:Vec<u8>,cause:RefusalEvidence,completed_steps:Vec<Label>,partial_observation:Option<PartialObservation>,effects:EffectBatch},|v:&CaseErrorValues,l:&RunLimits|{bound(v.diagnostic_bytes.len(),l.diagnostic_bytes(),"diagnostic")?;bound(v.completed_steps.len(),l.steps_per_invocation(),"completed steps")?;unique(&v.completed_steps)?;if v.category==CaseErrorCategory::UnsupportedSchema&&(v.step_id.is_some()||!v.completed_steps.is_empty()||v.partial_observation.is_some()||v.errno.is_some()||*v.cause.cause()!=RefusalCause::Unknown){return Err(he(HarnessErrorKind::InvalidInput,"dialect rejection progress/cause"))}Ok(())});
impl std::fmt::Display for CaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "case {:?} at {}", self.category(), self.stage().as_str())
    }
}
impl std::error::Error for CaseError {}
record!(FixtureError,FixtureErrorValues{key:Option<InvocationKey>,stage:FixtureStage,category:FixtureErrorCategory,errno:Option<i32>,#[serde(with="hex_bytes")]diagnostic_bytes:Vec<u8>,effects:EffectBatch,read_progress:Option<InputReadProgress>},|v:&FixtureErrorValues,l:&RunLimits|bound(v.diagnostic_bytes.len(),l.diagnostic_bytes(),"fixture diagnostic"));
impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fixture {:?} at {:?}", self.category(), self.stage())
    }
}
impl std::error::Error for FixtureError {}
impl FixtureError {
    pub(crate) fn harness(
        e: HarnessError,
        key: Option<InvocationKey>,
        stage: FixtureStage,
    ) -> Self {
        let l = RunLimits::default();
        Self(FixtureErrorValues {
            key,
            stage,
            category: FixtureErrorCategory::InvalidProtocol,
            errno: None,
            diagnostic_bytes: e.to_string().into_bytes().into_iter().take(65536).collect(),
            effects: EffectBatch::empty(&l),
            read_progress: None,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseOutcome {
    Observed(Observation),
    OperationError(CaseError),
}
impl Serialize for CaseOutcome {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut o = s.serialize_struct("CaseOutcome", 2)?;
        match self {
            Self::Observed(x) => {
                o.serialize_field("kind", "observed")?;
                o.serialize_field("observation", x)?
            }
            Self::OperationError(e) => {
                o.serialize_field("kind", "operation_error")?;
                o.serialize_field("error", e)?
            }
        }
        o.end()
    }
}
impl Decode for CaseOutcome {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        match v.get("kind").and_then(Value::as_str) {
            Some("observed") => {
                let mut o = Obj::new(v, &["kind", "observation"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::Observed(o.get("observation", l)?))
            }
            Some("operation_error") => {
                let mut o = Obj::new(v, &["kind", "error"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::OperationError(o.get("error", l)?))
            }
            _ => Err(he(HarnessErrorKind::InvalidInput, "outcome")),
        }
    }
}
impl CaseOutcome {
    pub fn key(&self) -> &InvocationKey {
        match self {
            Self::Observed(observation) => observation.key(),
            Self::OperationError(error) => error.key(),
        }
    }
    pub fn effects(&self) -> &EffectBatch {
        match self {
            Self::Observed(observation) => observation.effects(),
            Self::OperationError(error) => error.effects(),
        }
    }
    pub fn completed_steps(&self) -> &[Label] {
        match self {
            Self::Observed(observation) => observation.completed_steps(),
            Self::OperationError(error) => error.completed_steps(),
        }
    }
}
record!(CoverageEvidence,CoverageEvidenceValues{id:Label,step_ids:Vec<Label>,#[serde(with="decimal")]achieved:u64},|v:&CoverageEvidenceValues,l:&RunLimits|{bound(v.step_ids.len(),l.steps_per_invocation(),"coverage steps")?;unique(&v.step_ids)});
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExpectedEvidenceValues {
    pub key: InvocationKey,
    pub oracle: OracleBinding,
    pub fixture_schema: SchemaBinding,
    pub truth_kind: TruthKind,
    #[serde(with = "hex_bytes")]
    pub expected_bytes: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ledger_bytes: Vec<u8>,
    pub coverage: Vec<CoverageEvidence>,
    pub effects: EffectBatch,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedEvidence {
    values: ExpectedEvidenceValues,
    expected_bytes: std::sync::Arc<Vec<u8>>,
    ledger_bytes: std::sync::Arc<Vec<u8>>,
    expected_sha256: Digest256,
    ledger_sha256: Digest256,
}
impl Serialize for ExpectedEvidence {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            key: &'a InvocationKey,
            oracle: &'a OracleBinding,
            fixture_schema: &'a SchemaBinding,
            truth_kind: &'a TruthKind,
            #[serde(with = "hex_bytes")]
            expected_bytes: &'a [u8],
            #[serde(with = "hex_bytes")]
            ledger_bytes: &'a [u8],
            coverage: &'a [CoverageEvidence],
            effects: &'a EffectBatch,
        }
        Wire {
            key: self.key(),
            oracle: self.oracle(),
            fixture_schema: self.fixture_schema(),
            truth_kind: self.truth_kind(),
            expected_bytes: self.expected_bytes(),
            ledger_bytes: self.ledger_bytes(),
            coverage: self.coverage(),
            effects: self.effects(),
        }
        .serialize(s)
    }
}
impl ExpectedEvidence {
    pub fn new(v: ExpectedEvidenceValues, l: &RunLimits) -> Result<Self, HarnessError> {
        let mut e = Self::from_verified(v, l, Digest256::of_bytes(&[]), Digest256::of_bytes(&[]))?;
        e.expected_sha256 = Digest256::of_bytes(e.expected_bytes());
        e.ledger_sha256 = Digest256::of_bytes(e.ledger_bytes());
        Ok(e)
    }
    pub(crate) fn from_verified(
        mut v: ExpectedEvidenceValues,
        l: &RunLimits,
        expected_sha256: Digest256,
        ledger_sha256: Digest256,
    ) -> Result<Self, HarnessError> {
        let expected = std::sync::Arc::new(std::mem::take(&mut v.expected_bytes));
        let ledger = std::sync::Arc::new(std::mem::take(&mut v.ledger_bytes));
        Self::from_shared(v, l, expected, ledger, expected_sha256, ledger_sha256)
    }
    pub(crate) fn from_shared(
        v: ExpectedEvidenceValues,
        l: &RunLimits,
        expected_bytes: std::sync::Arc<Vec<u8>>,
        ledger_bytes: std::sync::Arc<Vec<u8>>,
        expected_sha256: Digest256,
        ledger_sha256: Digest256,
    ) -> Result<Self, HarnessError> {
        debug_assert!(v.expected_bytes.is_empty() && v.ledger_bytes.is_empty());
        let e = Self {
            values: v,
            expected_bytes,
            ledger_bytes,
            expected_sha256,
            ledger_sha256,
        };
        e.check_bounds(l)?;
        Ok(e)
    }
    pub fn key(&self) -> &InvocationKey {
        &self.values.key
    }
    pub fn oracle(&self) -> &OracleBinding {
        &self.values.oracle
    }
    pub fn fixture_schema(&self) -> &SchemaBinding {
        &self.values.fixture_schema
    }
    pub fn truth_kind(&self) -> &TruthKind {
        &self.values.truth_kind
    }
    pub fn expected_bytes(&self) -> &Vec<u8> {
        &self.expected_bytes
    }
    pub fn ledger_bytes(&self) -> &Vec<u8> {
        &self.ledger_bytes
    }
    pub fn coverage(&self) -> &Vec<CoverageEvidence> {
        &self.values.coverage
    }
    pub fn effects(&self) -> &EffectBatch {
        &self.values.effects
    }
    pub(crate) fn expected_sha256(&self) -> Digest256 {
        self.expected_sha256
    }
    pub(crate) fn ledger_sha256(&self) -> Digest256 {
        self.ledger_sha256
    }
}
impl BoundValue for ExpectedEvidence {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        let v = &self.values;
        v.key.check_bounds(l)?;
        v.oracle.check_bounds(l)?;
        v.fixture_schema.check_bounds(l)?;
        v.coverage.check_bounds(l)?;
        v.effects.check_bounds(l)?;
        bound(
            self.expected_bytes.len(),
            l.vector_bytes(),
            "expected bytes",
        )?;
        bound(self.ledger_bytes.len(), l.vector_bytes(), "ledger bytes")?;
        bound(v.coverage.len(), l.coverage_per_case(), "coverage")?;
        sorted(&v.coverage.iter().map(|c| c.id()).collect::<Vec<_>>())
    }
}
impl Decode for ExpectedEvidence {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        let mut o = Obj::new(
            v,
            &[
                "key",
                "oracle",
                "fixture_schema",
                "truth_kind",
                "expected_bytes",
                "ledger_bytes",
                "coverage",
                "effects",
            ],
        )?;
        Self::new(
            ExpectedEvidenceValues {
                key: o.get("key", l)?,
                oracle: o.get("oracle", l)?,
                fixture_schema: o.get("fixture_schema", l)?,
                truth_kind: o.get("truth_kind", l)?,
                expected_bytes: o.get("expected_bytes", l)?,
                ledger_bytes: o.get("ledger_bytes", l)?,
                coverage: o.get("coverage", l)?,
                effects: o.get("effects", l)?,
            },
            l,
        )
    }
}

// The following crate-private construction is restricted to the one-step,
// empty-effects prepared dialect. General public record validators stay intact.
// All buffers are admitted before dispatch; these finishers move them directly.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum OneStepResponseStage {
    Binding,
    Preflight,
    Input,
    Admission,
    Metadata,
    Allocate,
    Read,
    Attach,
    Drain,
    Retire,
    BtfQuery,
    Compile,
    Inspect,
    Execute,
}
const RESPONSE_STAGES: [&str; 14] = [
    "binding",
    "preflight",
    "input",
    "admission",
    "metadata",
    "allocate",
    "read",
    "attach",
    "drain",
    "retire",
    "btf_query",
    "compile",
    "inspect",
    "execute",
];
#[allow(dead_code)]
impl OneStepResponseStage {
    fn index(self) -> usize {
        self as usize
    }
}
/// Fixed stack diagnostic scratch. No truncation, formatting allocation or growth.
#[allow(dead_code)]
pub(crate) struct OneStepDiagnostic {
    bytes: [u8; 128],
    len: usize,
}
#[allow(dead_code)]
impl OneStepDiagnostic {
    pub(crate) fn new(bytes: &[u8]) -> Result<Self, ()> {
        let mut value = Self {
            bytes: [0; 128],
            len: 0,
        };
        value.extend(bytes)?;
        Ok(value)
    }
    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|n| *n <= 128)
            .ok_or(())?;
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    pub(crate) fn decimal(&mut self, mut value: usize) -> Result<(), ()> {
        let mut digits = [0u8; usize::BITS as usize];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.extend(&digits[start..])
    }
}
#[allow(dead_code)]
pub(crate) struct OneStepOutput(Vec<u8>);
#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum OneStepOutputFailure {
    Length { required: usize },
    Capacity { required: usize },
    Overflow,
}
struct OneStepStorage {
    key: InvocationKey,
    stages: Vec<Label>,
    method: Label,
    diagnostic: Vec<u8>,
    completed: Vec<Label>,
    observation_ceiling: u64,
    charge: usize,
}
#[allow(dead_code)]
pub(crate) struct OneStepResponse {
    storage: OneStepStorage,
    schema: Label,
    revision: u32,
    step: Label,
}
/// Error-only preparation never reads a script/schema/step. It is used for
/// stored-limit binding and closed dialect refusal before operation admission.
#[allow(dead_code)]
pub(crate) struct OneStepErrorResponse {
    storage: OneStepStorage,
}
fn response_vec<T>(
    count: usize,
    budget: &mut crate::prepared::ResponseBudget,
    component: ResponsePreparationComponent,
) -> Result<Vec<T>, ResponsePreparationFailure> {
    use ResponsePreparationFailureKind as Kind;
    let requested =
        count
            .checked_mul(std::mem::size_of::<T>())
            .ok_or(ResponsePreparationFailure {
                kind: Kind::Overflow,
                component,
                requested_bytes: Some(count),
                observed_bytes: None,
            })?;
    budget.reserve_minimum(requested, component)?;
    let mut vector = Vec::new();
    vector
        .try_reserve_exact(count)
        .map_err(|_| ResponsePreparationFailure {
            kind: Kind::Allocation,
            component,
            requested_bytes: Some(requested),
            observed_bytes: None,
        })?;
    let actual = vector
        .capacity()
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(ResponsePreparationFailure {
            kind: Kind::Overflow,
            component,
            requested_bytes: Some(requested),
            observed_bytes: None,
        })?;
    budget.observe_capacity(requested, actual, component)?;
    Ok(vector)
}
impl OneStepStorage {
    fn prepare(
        key: &InvocationKey,
        limits: &RunLimits,
        ceiling: usize,
        inline: usize,
    ) -> Result<(Self, crate::prepared::ResponseBudget), ResponsePreparationFailure> {
        use ResponsePreparationComponent as Part;
        if limits.diagnostic_bytes() < 128 || limits.steps_per_invocation() < 1 {
            return Err(ResponsePreparationFailure {
                kind: ResponsePreparationFailureKind::InvalidInvocation,
                component: Part::Total,
                requested_bytes: None,
                observed_bytes: None,
            });
        }
        let inline = inline
            .max(std::mem::size_of::<Observation>())
            .max(std::mem::size_of::<CaseError>());
        let mut budget = crate::prepared::ResponseBudget::new(inline, ceiling)?;
        let key = crate::ids::rsp01_copy_key(key, limits, &mut budget)?;
        let mut stages = response_vec(RESPONSE_STAGES.len(), &mut budget, Part::Stage)?;
        for text in RESPONSE_STAGES {
            stages.push(crate::ids::rsp01_copy_label(
                text,
                limits,
                &mut budget,
                Part::Stage,
            )?);
        }
        let method = crate::ids::rsp01_copy_label("bp03-model", limits, &mut budget, Part::Method)?;
        let diagnostic = response_vec(128, &mut budget, Part::Diagnostic)?;
        let completed = response_vec(1, &mut budget, Part::CompletionStorage)?;
        Ok((
            Self {
                key,
                stages,
                method,
                diagnostic,
                completed,
                observation_ceiling: limits.observation_bytes(),
                charge: 0,
            },
            budget,
        ))
    }
    fn finish_error(
        mut self,
        step: Option<Label>,
        category: CaseErrorCategory,
        stage: OneStepResponseStage,
        diagnostic: OneStepDiagnostic,
        errno: Option<i32>,
    ) -> CaseError {
        // Diagnostic scratch is <=128 and admission retained >=128 usable bytes.
        self.diagnostic
            .extend_from_slice(&diagnostic.bytes[..diagnostic.len]);
        let dialect = category == CaseErrorCategory::UnsupportedSchema;
        let stage = self.stages.swap_remove(stage.index());
        CaseError(CaseErrorValues {
            key: self.key,
            step_id: if dialect { None } else { step },
            stage,
            category,
            errno: if dialect { None } else { errno },
            diagnostic_bytes: self.diagnostic,
            cause: RefusalEvidence(RefusalEvidenceValues {
                cause: RefusalCause::Unknown,
                method: self.method,
                evidence_ids: Vec::new(),
                tier: EvidenceTier::T0,
            }),
            completed_steps: Vec::new(),
            partial_observation: None,
            effects: EffectBatch(EffectBatchValues {
                registrations: Vec::new(),
                complete: true,
            }),
        })
    }
}
#[allow(dead_code)]
impl OneStepResponse {
    // actual_call_inline is the complete opaque call, including its enum/context
    // and both borrows. Replacing the component inline avoids double counting.
    pub(crate) fn prepare(
        key: &InvocationKey,
        schema: &SchemaBinding,
        step: &Label,
        limits: &RunLimits,
        ceiling: usize,
        actual_call_inline: usize,
    ) -> Result<Self, ResponsePreparationFailure> {
        use ResponsePreparationComponent as Part;
        if *schema.revision() == 0 {
            return Err(ResponsePreparationFailure {
                kind: ResponsePreparationFailureKind::InvalidInvocation,
                component: Part::Schema,
                requested_bytes: None,
                observed_bytes: None,
            });
        }
        let (mut storage, mut budget) = OneStepStorage::prepare(
            key,
            limits,
            ceiling,
            std::mem::size_of::<Self>().max(actual_call_inline),
        )?;
        let schema_copy =
            crate::ids::rsp01_copy_label(schema.id().as_str(), limits, &mut budget, Part::Schema)?;
        let step = crate::ids::rsp01_copy_label(step.as_str(), limits, &mut budget, Part::Step)?;
        storage.charge = budget.used();
        Ok(Self {
            storage,
            schema: schema_copy,
            revision: *schema.revision(),
            step,
        })
    }
    pub(crate) fn admitted_bytes(&self) -> usize {
        self.storage.charge
    }
    pub(crate) fn admit_output(
        &self,
        bytes: Vec<u8>,
        joint_payload_ceiling: usize,
    ) -> Result<OneStepOutput, OneStepOutputFailure> {
        self.check_output(&bytes, joint_payload_ceiling)?;
        Ok(OneStepOutput(bytes))
    }
    fn check_output(
        &self,
        bytes: &Vec<u8>,
        joint_payload_ceiling: usize,
    ) -> Result<(), OneStepOutputFailure> {
        if bytes.len() as u64 > self.storage.observation_ceiling {
            return Err(OneStepOutputFailure::Length {
                required: bytes.len(),
            });
        }
        // J counts the actual output Vec inline plus its heap capacity once.
        let demand = std::mem::size_of::<Vec<u8>>()
            .checked_add(bytes.capacity())
            .ok_or(OneStepOutputFailure::Overflow)?;
        if demand > joint_payload_ceiling {
            return Err(OneStepOutputFailure::Capacity { required: demand });
        }
        Ok(())
    }
    pub(crate) fn finish_observation(
        mut self,
        output: OneStepOutput,
        joint_payload_ceiling: usize,
    ) -> Result<Observation, (Self, OneStepOutputFailure)> {
        // A token may come from another context or an earlier joint ceiling.
        // Recheck this receiver and current J without allocating metadata. On
        // refusal, retain this exact key/storage for the caller's error finish.
        if let Err(failure) = self.check_output(&output.0, joint_payload_ceiling) {
            return Err((self, failure));
        }
        // Exactly one element fits the admitted completion backing. Moving the
        // single step and output never invokes generic allocating unique().
        self.storage.completed.push(self.step);
        Ok(Observation(ObservationValues {
            key: self.storage.key,
            schema_id: self.schema,
            schema_revision: self.revision,
            completed_steps: self.storage.completed,
            bytes: output.0,
            effects: EffectBatch(EffectBatchValues {
                registrations: Vec::new(),
                complete: true,
            }),
        }))
    }
    pub(crate) fn finish_error(
        self,
        category: CaseErrorCategory,
        stage: OneStepResponseStage,
        diagnostic: OneStepDiagnostic,
        attempted_step: bool,
        errno: Option<i32>,
    ) -> CaseError {
        self.storage.finish_error(
            if attempted_step {
                Some(self.step)
            } else {
                None
            },
            category,
            stage,
            diagnostic,
            errno,
        )
    }
}
#[allow(dead_code)]
impl OneStepErrorResponse {
    pub(crate) fn prepare(
        key: &InvocationKey,
        limits: &RunLimits,
        ceiling: usize,
        actual_call_inline: usize,
    ) -> Result<Self, ResponsePreparationFailure> {
        let (mut storage, budget) = OneStepStorage::prepare(
            key,
            limits,
            ceiling,
            std::mem::size_of::<Self>().max(actual_call_inline),
        )?;
        storage.charge = budget.used();
        Ok(Self { storage })
    }
    pub(crate) fn admitted_bytes(&self) -> usize {
        self.storage.charge
    }
    pub(crate) fn finish_error(
        self,
        category: CaseErrorCategory,
        stage: OneStepResponseStage,
        diagnostic: OneStepDiagnostic,
    ) -> CaseError {
        self.storage
            .finish_error(None, category, stage, diagnostic, None)
    }
}

#[cfg(test)]
pub(crate) mod rsp01_test_support {
    use super::*;
    // The independent test sum reads the actual owned buffers, never the
    // admission budget/recorded charge. All simultaneous alternatives count.
    pub(crate) fn context_bytes(response: &OneStepResponse) -> usize {
        let s = &response.storage;
        std::mem::size_of::<OneStepResponse>()
            .max(std::mem::size_of::<Observation>())
            .max(std::mem::size_of::<CaseError>())
            + crate::ids::rsp01_key_capacities(&s.key)
                .iter()
                .sum::<usize>()
            + s.stages.capacity() * std::mem::size_of::<Label>()
            + s.stages
                .iter()
                .map(crate::ids::rsp01_label_capacity)
                .sum::<usize>()
            + crate::ids::rsp01_label_capacity(&s.method)
            + s.diagnostic.capacity()
            + s.completed.capacity() * std::mem::size_of::<Label>()
            + crate::ids::rsp01_label_capacity(&response.schema)
            + crate::ids::rsp01_label_capacity(&response.step)
    }
    pub(crate) fn observation_bytes(response: &Observation) -> usize {
        // Output payload belongs to J; its Vec inline is already in the header.
        std::mem::size_of::<Observation>()
            + crate::ids::rsp01_key_capacities(response.key())
                .iter()
                .sum::<usize>()
            + crate::ids::rsp01_label_capacity(response.schema_id())
            + response.completed_steps().capacity() * std::mem::size_of::<Label>()
            + response
                .completed_steps()
                .iter()
                .map(crate::ids::rsp01_label_capacity)
                .sum::<usize>()
    }
    // Error-only twin of context_bytes: the same owned storage buffers read
    // back from the actual error response. Error preparation never reads a
    // script/schema/step, so there are no schema/step terms to add.
    pub(crate) fn error_context_bytes(response: &OneStepErrorResponse) -> usize {
        let s = &response.storage;
        std::mem::size_of::<OneStepErrorResponse>()
            .max(std::mem::size_of::<Observation>())
            .max(std::mem::size_of::<CaseError>())
            + crate::ids::rsp01_key_capacities(&s.key)
                .iter()
                .sum::<usize>()
            + s.stages.capacity() * std::mem::size_of::<Label>()
            + s.stages
                .iter()
                .map(crate::ids::rsp01_label_capacity)
                .sum::<usize>()
            + crate::ids::rsp01_label_capacity(&s.method)
            + s.diagnostic.capacity()
            + s.completed.capacity() * std::mem::size_of::<Label>()
    }
}
