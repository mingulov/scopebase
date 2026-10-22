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
