// SPDX-License-Identifier: Apache-2.0
//! External contracts freeze the denominator before effect-capable calls.
use crate::artifact::*;
use crate::*;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScriptScalar {
    U64 {
        #[serde(with = "decimal")]
        value: u64,
    },
    Bool {
        value: bool,
    },
    Bytes {
        #[serde(with = "hex_bytes")]
        hex: Vec<u8>,
    },
}
impl Decode for ScriptScalar {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        let k = v.get("kind").and_then(Value::as_str);
        match k {
            Some("u64") => {
                let mut o = Obj::new(v, &["kind", "value"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::U64 {
                    value: o.get("value", l)?,
                })
            }
            Some("bool") => {
                let mut o = Obj::new(v, &["kind", "value"])?;
                let _: String = o.get("kind", l)?;
                Ok(Self::Bool {
                    value: o.get("value", l)?,
                })
            }
            Some("bytes") => {
                let mut o = Obj::new(v, &["kind", "hex"])?;
                let _: String = o.get("kind", l)?;
                let hex: Vec<u8> = o.get("hex", l)?;
                bound(hex.len(), l.scalar_bytes(), "scalar bytes")?;
                Ok(Self::Bytes { hex })
            }
            _ => Err(he(HarnessErrorKind::UnsupportedSchema, "scalar kind")),
        }
    }
}
record!(OperationStep,OperationStepValues{step_id:Label,operation:Label,inputs:Vec<Label>,parameters:Vec<ScriptScalar>},|v:&OperationStepValues,l:&RunLimits|{bound(v.inputs.len(),l.input_slots(),"step inputs")?;bound(v.parameters.len(),l.script_parameters(),"step parameters")?;unique(&v.inputs)});
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationScript {
    schema_version: u32,
    kind: String,
    schema_id: Label,
    steps: Vec<OperationStep>,
    #[serde(skip)]
    sha256: Digest256,
}
impl OperationScript {
    pub fn load(bytes: &[u8], l: &RunLimits) -> Result<Self, HarnessError> {
        let mut s = Self::decode(parse(bytes, l.input_bytes(), l)?, l)?;
        s.sha256 = Digest256::of_bytes(bytes);
        Ok(s)
    }
    pub fn schema_id(&self) -> &Label {
        &self.schema_id
    }
    pub fn steps(&self) -> &[OperationStep] {
        &self.steps
    }
    pub fn sha256(&self) -> Digest256 {
        self.sha256
    }
}
impl Decode for OperationScript {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        let mut o = Obj::new(v, &["schema_version", "kind", "schema_id", "steps"])?;
        let schema_version: u32 = o.get("schema_version", l)?;
        let kind: String = o.get("kind", l)?;
        if schema_version != 1 || kind != "steps-v1" {
            return Err(he(HarnessErrorKind::UnsupportedSchema, "steps-v1"));
        }
        let schema_id = o.get("schema_id", l)?;
        let steps: Vec<OperationStep> = o.get("steps", l)?;
        if steps.is_empty() {
            return Err(he(HarnessErrorKind::InvalidInput, "empty script"));
        }
        bound(steps.len(), l.steps_per_invocation(), "script steps")?;
        unique(&steps.iter().map(|s| s.step_id()).collect::<Vec<_>>())?;
        Ok(Self {
            schema_version,
            kind,
            schema_id,
            steps,
            sha256: Digest256::of_bytes(&[]),
        })
    }
}
wire_enum!(CoverageKind{Setup=>"setup",Trigger=>"trigger",Positive=>"positive",ActiveExcluded=>"active_excluded"});
record!(CoverageRequirement,CoverageRequirementValues{id:Label,kind:CoverageKind,#[serde(with="decimal")]minimum:u64,step_ids:Vec<Label>},|v:&CoverageRequirementValues,l:&RunLimits|{if v.minimum==0||v.step_ids.is_empty(){return Err(he(HarnessErrorKind::InvalidInput,"coverage minimum/steps"))}bound(v.step_ids.len(),l.steps_per_invocation(),"coverage steps")?;unique(&v.step_ids)});
record!(AssertionRule,AssertionRuleValues{id:Label,requires_coverage:Vec<Label>,requires_positive_twin:bool},|v:&AssertionRuleValues,l:&RunLimits|{bound(v.requires_coverage.len(),l.coverage_per_case(),"assertion prerequisites")?;unique(&v.requires_coverage)});
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimIntent {
    PositiveSupport,
    ExpectedRefusal {
        cause: KnownRefusalCause,
        step_id: Label,
        stage: Label,
        positive_twin: CaseKey,
        equivalence_assertion: Label,
    },
    AssertionOnly,
}
impl Decode for ClaimIntent {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        match v.get("kind").and_then(Value::as_str) {
            Some("positive_support") => {
                Obj::new(v, &["kind"])?;
                Ok(Self::PositiveSupport)
            }
            Some("assertion_only") => {
                Obj::new(v, &["kind"])?;
                Ok(Self::AssertionOnly)
            }
            Some("expected_refusal") => {
                let mut o = Obj::new(
                    v,
                    &[
                        "kind",
                        "cause",
                        "step_id",
                        "stage",
                        "positive_twin",
                        "equivalence_assertion",
                    ],
                )?;
                let _: String = o.get("kind", l)?;
                Ok(Self::ExpectedRefusal {
                    cause: o.get("cause", l)?,
                    step_id: o.get("step_id", l)?,
                    stage: o.get("stage", l)?,
                    positive_twin: o.get("positive_twin", l)?,
                    equivalence_assertion: o.get("equivalence_assertion", l)?,
                })
            }
            _ => Err(he(HarnessErrorKind::InvalidInput, "intent")),
        }
    }
}
record!(CaseRule,CaseRuleValues{case_key:CaseKey,tier:EvidenceTier,observation_schema:SchemaBinding,fixture_schema:SchemaBinding,script:OperationScript,assertions:Vec<AssertionRule>,coverage:Vec<CoverageRequirement>,intent:ClaimIntent,attempts:u32,#[serde(with="decimal_list")]operation_ids:Vec<u64>,max_effects:u32},|v:&CaseRuleValues,l:&RunLimits|{
 if v.attempts==0||v.attempts as u64>l.attempts_per_case()||v.operation_ids.len()!=v.attempts as usize||v.operation_ids.contains(&0)||v.assertions.is_empty(){return Err(he(HarnessErrorKind::InvalidInput,"rule attempts/assertions"))}unique(&v.operation_ids)?;bound(v.assertions.len(),l.assertions_per_case(),"assertions")?;bound(v.coverage.len(),l.coverage_per_case(),"coverage")?;if v.max_effects as u64>l.effects_per_case(){return Err(he(HarnessErrorKind::LimitExceeded,"max effects"))}unique(&v.assertions.iter().map(|a|a.id()).collect::<Vec<_>>())?;unique(&v.coverage.iter().map(|a|a.id()).collect::<Vec<_>>())?;
 let steps=v.script.steps().iter().map(|s|s.step_id()).collect::<BTreeSet<_>>();let ids=v.coverage.iter().map(|c|c.id()).collect::<BTreeSet<_>>();for c in &v.coverage{if c.step_ids().iter().any(|s|!steps.contains(s)){return Err(he(HarnessErrorKind::InvalidInput,"coverage step"))}}
 for a in &v.assertions{if a.requires_coverage().iter().any(|id|!ids.contains(id))||(*a.requires_positive_twin()&&!matches!(v.intent,ClaimIntent::ExpectedRefusal{..})){return Err(he(HarnessErrorKind::InvalidInput,"assertion prerequisite"))}}
 let has=|kind,step:Option<&Label>|v.coverage.iter().any(|c|*c.kind()==kind&&step.is_none_or(|s|c.step_ids().contains(s)));
 match &v.intent{ClaimIntent::PositiveSupport=>{if !has(CoverageKind::Setup,None)||!has(CoverageKind::Trigger,None)||!has(CoverageKind::Positive,None){return Err(he(HarnessErrorKind::InvalidInput,"support populations"))}},ClaimIntent::ExpectedRefusal{step_id,equivalence_assertion,..}=>{if !steps.contains(step_id)||!has(CoverageKind::Setup,Some(step_id))||!has(CoverageKind::Trigger,Some(step_id)){return Err(he(HarnessErrorKind::InvalidInput,"refusal populations"))}let req=v.coverage.iter().filter(|c|matches!(c.kind(),CoverageKind::Setup|CoverageKind::Trigger)).map(|c|c.id()).collect::<BTreeSet<_>>();for id in ["refusal.intended-cause",equivalence_assertion.as_str()]{let Some(a)=v.assertions.iter().find(|a|a.id().as_str()==id)else{return Err(he(HarnessErrorKind::InvalidInput,"refusal assertions"))};if !*a.requires_positive_twin()||!req.iter().all(|r|a.requires_coverage().contains(r)){return Err(he(HarnessErrorKind::InvalidInput,"refusal assertion gates"))}}},_=>{}}Ok(())});
record!(RequiredCellBinding,RequiredCellBindingValues{case_id:CaseId,case_version:u32,cell_id:String,tier:EvidenceTier,implementation_status:ImplementationStatus,required_by:Vec<ProfileId>},|v:&RequiredCellBindingValues,_:&RunLimits|{if v.case_version==0||v.cell_id.is_empty(){return Err(he(HarnessErrorKind::InvalidInput,"required cell"))}unique(&v.required_by)});
record!(SelectionBinding,SelectionBindingValues{requested:ProfileId,profiles:Vec<ProfileId>,extensions:Vec<ProfileId>,required:Vec<RequiredCellBinding>,open_owners:Vec<String>,definition_complete:bool},|v:&SelectionBindingValues,_:&RunLimits|{unique(&v.profiles)?;unique(&v.extensions)?;unique(&v.open_owners)});
impl SelectionBinding {
    pub(crate) fn plan(p: &ProfilePlan) -> Self {
        Self(SelectionBindingValues {
            requested: p.requested().clone(),
            profiles: p.profiles().to_vec(),
            extensions: p.extensions().to_vec(),
            required: p
                .required()
                .iter()
                .map(|r| {
                    RequiredCellBinding(RequiredCellBindingValues {
                        case_id: r.case_id().clone(),
                        case_version: r.case_version(),
                        cell_id: r.cell_id().into(),
                        tier: r.tier(),
                        implementation_status: r.implementation_status(),
                        required_by: r.required_by().to_vec(),
                    })
                })
                .collect(),
            open_owners: p.open_owners().to_vec(),
            definition_complete: p.definition_complete(),
        })
    }
}
#[derive(Debug)]
pub(crate) struct ContractInner {
    pub sha: Digest256,
    pub run_id: RunId,
    pub selection: SelectionBinding,
    pub expected_subject: SubjectBinding,
    pub expected_oracle: OracleBinding,
    pub artifacts: Vec<ArtifactBinding>,
    pub rules: Vec<CaseRule>,
    pub limits: RunLimits,
    pub cases: BTreeMap<CaseKey, CaseSpec>,
    pub schedule: Vec<InvocationKey>,
    pub reservation: u64,
    pub rule_index: BTreeMap<CaseKey, usize>,
    pub artifact_index: BTreeMap<Label, usize>,
    pub truth_bindings: BTreeSet<(ArtifactRole, u64, Digest256)>,
}
#[derive(Clone, Debug)]
pub struct RunContract(pub(crate) Arc<ContractInner>);
impl RunContract {
    pub fn sha256(&self) -> Digest256 {
        self.0.sha
    }
    pub fn limits(&self) -> &RunLimits {
        &self.0.limits
    }
    pub fn run_id(&self) -> &RunId {
        &self.0.run_id
    }
    pub fn selection(&self) -> &SelectionBinding {
        &self.0.selection
    }
    pub fn expected_subject(&self) -> &SubjectBinding {
        &self.0.expected_subject
    }
    pub fn expected_oracle(&self) -> &OracleBinding {
        &self.0.expected_oracle
    }
    pub fn artifacts(&self) -> &[ArtifactBinding] {
        &self.0.artifacts
    }
    pub fn case_rules(&self) -> &[CaseRule] {
        &self.0.rules
    }
    pub fn schedule(&self) -> &[InvocationKey] {
        &self.0.schedule
    }
    pub(crate) fn rule(&self, k: &CaseKey) -> &CaseRule {
        &self.0.rules[self.0.rule_index[k]]
    }
    pub(crate) fn artifact(&self, id: &Label) -> Option<&ArtifactBinding> {
        self.0.artifact_index.get(id).map(|i| &self.0.artifacts[*i])
    }
    pub fn load(
        catalog: &CaseCatalog,
        plan: &ProfilePlan,
        bytes: &[u8],
        ceiling: RunLimits,
    ) -> Result<Self, HarnessError> {
        let v = parse(bytes, ceiling.input_bytes(), &ceiling)?;
        let fields = &[
            "schema_version",
            "kind",
            "run_id",
            "catalog_sha256",
            "catalog_revision",
            "selection",
            "expected_subject",
            "expected_oracle",
            "artifacts",
            "case_rules",
            "limits",
        ];
        let mut o = Obj::new(v, fields)?;
        let limits = ceiling
            .lowered(o.get("limits", &ceiling)?)
            .map_err(|e| he(HarnessErrorKind::LimitExceeded, &e.to_string()))?;
        bound(bytes.len(), limits.input_bytes(), "contract bytes")?;
        // The external ceiling only permits reading the limits envelope. Drop
        // that tree before admitting the complete structure under its choice.
        drop(o);
        let mut o = Obj::new(parse(bytes, limits.input_bytes(), &limits)?, fields)?;
        let _: RunLimitValues = o.get("limits", &limits)?;
        let schema: u32 = o.get("schema_version", &limits)?;
        let kind: String = o.get("kind", &limits)?;
        if schema != 1 || kind != "tt02-run-contract" {
            return Err(he(HarnessErrorKind::UnsupportedSchema, "contract"));
        }
        let catalog_sha256: Digest256 = o.get("catalog_sha256", &limits)?;
        let rev: u32 = o.get("catalog_revision", &limits)?;
        if catalog_sha256 != catalog.source_sha256() || rev != catalog.revision() {
            return Err(he(HarnessErrorKind::InvalidBinding, "catalog"));
        }
        let run_id: RunId = o.get("run_id", &limits)?;
        let selection: SelectionBinding = o.get("selection", &limits)?;
        if selection != SelectionBinding::plan(plan) || plan.required().is_empty() {
            return Err(he(HarnessErrorKind::InvalidSelection, "full selection"));
        }
        bound(
            plan.required().len(),
            limits.case_attempts(),
            "planned selection",
        )?;
        let expected_subject: SubjectBinding = o.get("expected_subject", &limits)?;
        let expected_oracle: OracleBinding = o.get("expected_oracle", &limits)?;
        let artifacts: Vec<ArtifactBinding> = o.get("artifacts", &limits)?;
        bound(artifacts.len(), limits.artifacts(), "artifact inventory")?;
        sorted(&artifacts.iter().map(|a| a.id()).collect::<Vec<_>>())?;
        for object in expected_subject.objects() {
            if !artifacts.contains(object) {
                return Err(he(
                    HarnessErrorKind::InvalidBinding,
                    "subject object inventory",
                ));
            }
        }
        if !artifacts.iter().any(|a| {
            a.id() == expected_oracle.artifact_id()
                && *a.role() == ArtifactRole::OracleSource
                && a.sha256() == expected_oracle.source_sha256()
                && a.revision() == expected_oracle.revision()
        }) {
            return Err(he(
                HarnessErrorKind::InvalidBinding,
                "external oracle source",
            ));
        }
        let mut rules: Vec<CaseRule> = o.get("case_rules", &limits)?;
        if rules.len() != plan.required().len() {
            return Err(he(HarnessErrorKind::InvalidSelection, "case rules"));
        }
        unique(&rules.iter().map(|r| r.case_key()).collect::<Vec<_>>())?;
        // Hash original non-overlapping script spans, preserving their byte identities.
        let spans = script_spans(bytes)?;
        if spans.len() != rules.len() {
            return Err(he(HarnessErrorKind::InvalidInput, "script spans"));
        }
        for (r, (a, b)) in rules.iter_mut().zip(spans) {
            r.0.script.sha256 = Digest256::of_bytes(&bytes[a..b]);
        }
        let mut cases = BTreeMap::new();
        let mut ids = BTreeSet::new();
        let (mut attempts, mut steps, mut assertions, mut coverage) = (0u64, 0u64, 0u64, 0u64);
        for cell in plan.required() {
            let k = CaseKey::new(
                CaseKeyValues {
                    case_id: cell.case_id().clone(),
                    case_version: cell.case_version(),
                    cell_id: cell.cell_id().into(),
                },
                &limits,
            )?;
            let r = rules
                .iter()
                .find(|r| r.case_key() == &k)
                .ok_or_else(|| he(HarnessErrorKind::InvalidSelection, "rule key"))?;
            if *r.tier() != cell.tier() {
                return Err(he(HarnessErrorKind::InvalidSelection, "rule tier"));
            }
            let c = catalog
                .case(cell.case_id(), cell.case_version())
                .ok_or_else(|| he(HarnessErrorKind::InvalidSelection, "case"))?
                .clone();
            if let Some(reg) = c.registration() {
                if expected_oracle.artifact_id().as_str() != reg.oracle().id()
                    || expected_oracle.source_sha256().as_str() != reg.oracle().sha256()
                    || *expected_oracle.revision() != reg.oracle().revision()
                {
                    return Err(he(
                        HarnessErrorKind::InvalidBinding,
                        "selected oracle registration",
                    ));
                }
                for (reg, role) in [
                    (reg.executable(), ArtifactRole::CaseSource),
                    (reg.fixture(), ArtifactRole::FixtureManifest),
                    (reg.oracle(), ArtifactRole::OracleSource),
                    (reg.bad_control(), ArtifactRole::ControlSource),
                ] {
                    if !artifacts.iter().any(|a| {
                        a.id().as_str() == reg.id()
                            && *a.revision() == reg.revision()
                            && a.sha256().as_str() == reg.sha256()
                            && *a.role() == role
                    }) {
                        return Err(he(HarnessErrorKind::InvalidBinding, "registered artifact"));
                    }
                }
            }
            for id in r.operation_ids() {
                if !ids.insert(*id) {
                    return Err(he(HarnessErrorKind::InvalidInput, "operation ID duplicate"));
                }
            }
            let n = *r.attempts() as u64;
            attempts += n;
            steps += n * r.script().steps().len() as u64;
            assertions += n * r.assertions().len() as u64;
            coverage += n * r.coverage().len() as u64;
            cases.insert(k, c);
        }
        if attempts > limits.case_attempts()
            || steps > limits.steps_total()
            || assertions > limits.assertion_records()
            || coverage > limits.coverage_records()
        {
            return Err(he(HarnessErrorKind::LimitExceeded, "planned denominator"));
        }
        let order = ordered_rules(&rules)?;
        let mut schedule = Vec::new();
        for i in order {
            let r = &rules[i];
            for (a, op) in r.operation_ids().iter().enumerate() {
                schedule.push(InvocationKey::new(
                    InvocationKeyValues {
                        run_id: run_id.clone(),
                        case_key: r.case_key().clone(),
                        attempt: a as u32 + 1,
                        operation_id: *op,
                    },
                    &limits,
                )?);
            }
        }
        // Conservative preallocation for every fixed slot, row, copied key and uncertainty.
        let key_bytes: u64 = schedule
            .iter()
            .map(|k| k.case_key().cell_id().len() as u64 + 256)
            .sum();
        let possible_effects = rules
            .iter()
            .map(|r| *r.max_effects() as u64 * *r.attempts() as u64)
            .sum::<u64>()
            .min(limits.effects_total());
        // Reserve labels for mandatory runner reasons and possible uncertainty
        // IDs before effects; lowered limits must refuse rather than panic later.
        bound(
            "runner.entry_subject_mismatch".len(),
            limits.label_bytes(),
            "runner reason labels",
        )?;
        bound(
            "cumulative retirement allowance exhausted".len(),
            limits.diagnostic_bytes(),
            "mandatory runner diagnostics",
        )?;
        for key in &schedule {
            bound(
                format!("u.{}.a.prepare-invalid", key.operation_id()).len(),
                limits.label_bytes(),
                "runner uncertainty labels",
            )?;
        }
        let effect_reservation = possible_effects
            * (4096
                + schedule
                    .iter()
                    .map(|k| k.case_key().cell_id().len() as u64)
                    .max()
                    .unwrap_or(0)
                    * 8);
        let reservation =
            bytes.len() as u64 * 4 + key_bytes * 12 + attempts * 4096 + effect_reservation + 65536;
        if reservation > limits.retained_bytes()
            || attempts * 4096 + key_bytes * 8 + effect_reservation > limits.receipt_bytes()
        {
            return Err(he(
                HarnessErrorKind::LimitExceeded,
                "mandatory receipt/retention",
            ));
        }
        let truth_bindings = artifacts
            .iter()
            .map(|a| (*a.role(), *a.length(), *a.sha256()))
            .collect();
        let rule_index = rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.case_key().clone(), i))
            .collect();
        let artifact_index = artifacts
            .iter()
            .enumerate()
            .map(|(i, a)| (a.id().clone(), i))
            .collect();
        Ok(Self(Arc::new(ContractInner {
            rule_index,
            artifact_index,
            truth_bindings,
            sha: Digest256::of_bytes(bytes),
            run_id,
            selection,
            expected_subject,
            expected_oracle,
            artifacts,
            rules,
            limits,
            cases,
            schedule,
            reservation,
        })))
    }
}
fn ordered_rules(rules: &[CaseRule]) -> Result<Vec<usize>, HarnessError> {
    fn visit(
        i: usize,
        r: &[CaseRule],
        active: &mut BTreeSet<usize>,
        done: &mut BTreeSet<usize>,
        out: &mut Vec<usize>,
    ) -> Result<(), HarnessError> {
        if done.contains(&i) {
            return Ok(());
        }
        if !active.insert(i) {
            return Err(he(HarnessErrorKind::InvalidInput, "twin cycle"));
        }
        if let ClaimIntent::ExpectedRefusal { positive_twin, .. } = r[i].intent() {
            let j = r
                .iter()
                .position(|r| r.case_key() == positive_twin)
                .ok_or_else(|| he(HarnessErrorKind::InvalidInput, "missing twin"))?;
            if !matches!(r[j].intent(), ClaimIntent::PositiveSupport) {
                return Err(he(HarnessErrorKind::InvalidInput, "twin intent"));
            }
            visit(j, r, active, done, out)?
        }
        active.remove(&i);
        done.insert(i);
        out.push(i);
        Ok(())
    }
    let mut sorted = (0..rules.len()).collect::<Vec<_>>();
    sorted.sort_by_key(|i| rules[*i].case_key());
    let (mut out, mut active, mut done) = (vec![], BTreeSet::new(), BTreeSet::new());
    for i in sorted {
        visit(i, rules, &mut active, &mut done, &mut out)?
    }
    Ok(out)
}
fn script_spans(b: &[u8]) -> Result<Vec<(usize, usize)>, HarnessError> {
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < b.len() {
            if b[i] == b'\\' {
                i += 2;
                continue;
            }
            if b[i] == b'"' {
                break;
            }
            i += 1
        }
        i += 1;
        let key: Result<String, _> = serde_json::from_slice(&b[start..i]);
        if !matches!(key.as_deref(), Ok("script")) {
            continue;
        }
        let mut a = i;
        while a < b.len() && b[a].is_ascii_whitespace() {
            a += 1
        }
        if b.get(a) != Some(&b':') {
            continue;
        }
        a += 1;
        while a < b.len() && b[a].is_ascii_whitespace() {
            a += 1
        }
        if b.get(a) != Some(&b'{') {
            continue;
        }
        let (mut j, mut depth, mut quoted) = (a, 0, false);
        while j < b.len() {
            let c = b[j];
            if quoted {
                if c == b'\\' {
                    j += 2;
                    continue;
                }
                if c == b'"' {
                    quoted = false
                }
            } else {
                match c {
                    b'"' => quoted = true,
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            j += 1
        }
        out.push((a, j));
        i = j;
    }
    Ok(out)
}
record!(
    CaseInvocation,
    CaseInvocationValues {
        key: InvocationKey,
        observation_schema: SchemaBinding,
        fixture_schema: SchemaBinding,
        script: OperationScript,
        limits: RunLimits
    },
    |_: &CaseInvocationValues, _: &RunLimits| Ok(())
);
impl Decode for RunLimits {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        l.lowered(RunLimitValues::decode(v, l)?)
            .map_err(|e| he(HarnessErrorKind::LimitExceeded, &e.to_string()))
    }
}
impl BoundValue for ScriptScalar {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        if let Self::Bytes { hex } = self {
            bound(hex.len(), l.scalar_bytes(), "scalar")?
        }
        Ok(())
    }
}
impl BoundValue for OperationScript {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        self.schema_id.check_bounds(l)?;
        bound(self.steps.len(), l.steps_per_invocation(), "steps")?;
        self.steps.check_bounds(l)
    }
}
impl BoundValue for ClaimIntent {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        if let Self::ExpectedRefusal {
            step_id,
            stage,
            positive_twin,
            equivalence_assertion,
            ..
        } = self
        {
            step_id.check_bounds(l)?;
            stage.check_bounds(l)?;
            positive_twin.check_bounds(l)?;
            equivalence_assertion.check_bounds(l)?
        }
        Ok(())
    }
}

use crate::result::{
    reconstruct, CaseResult, CaseTerminal, CleanupRecord, ExecutionCheckpoint,
    ExecutionCheckpoints, Ledger, MetadataObservation, ReportWire, RunTerminal, RunnerObservations,
};
fn duration_ns(duration: Duration) -> Result<u64, HarnessError> {
    u64::try_from(duration.as_nanos()).map_err(|_| {
        he(
            HarnessErrorKind::LimitExceeded,
            "monotonic elapsed overflow",
        )
    })
}
fn checked_elapsed(start: Instant, end: Instant) -> Result<u64, HarnessError> {
    let duration = end.checked_duration_since(start).ok_or_else(|| {
        he(
            HarnessErrorKind::InvalidProtocol,
            "monotonic clock reversed",
        )
    })?;
    duration_ns(duration)
}
trait Clock {
    fn now(&self) -> Instant;
}
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
struct Engine<'a, C: Clock> {
    c: RunContract,
    entry: Instant,
    clock: &'a C,
    probe: &'a dyn Fn() -> bool,
    stopped: bool,
    invalid: Option<HarnessError>,
    ledger: Ledger,
    closed: Duration,
    records: Vec<CleanupRecord>,
    used: u64,
    last_elapsed: u64,
}
impl<C: Clock> Engine<'_, C> {
    fn elapsed(&mut self) -> Option<u64> {
        let result = checked_elapsed(self.entry, self.clock.now()).and_then(|ns| {
            if ns < self.last_elapsed {
                Err(he(
                    HarnessErrorKind::InvalidProtocol,
                    "monotonic clock reversed",
                ))
            } else {
                Ok(ns)
            }
        });
        match result {
            Ok(ns) => {
                self.last_elapsed = ns;
                Some(ns)
            }
            Err(error) => {
                self.reject(error);
                None
            }
        }
    }
    fn sample(&mut self) -> CheckpointSlot {
        let Some(start) = self.elapsed() else {
            return CheckpointSlot::NotRecorded;
        };
        let d = self.c.limits().execution_ms() * 1_000_000;
        let cancelled = if start >= d {
            None
        } else {
            Some((self.probe)())
        };
        let end = if cancelled.is_none() {
            start
        } else {
            let Some(end) = self.elapsed() else {
                return CheckpointSlot::NotRecorded;
            };
            end
        };
        let sample = CheckpointSlot::Sampled {
            sample: ExecutionCheckpoint {
                poll_started_elapsed_ns: start,
                poll_finished_elapsed_ns: end,
                cancelled,
            },
        };
        self.stopped |= sample.stop(d);
        sample
    }
    fn reject(&mut self, e: HarnessError) {
        self.stopped = true;
        if self.invalid.is_none() {
            self.invalid = Some(e)
        }
    }
    fn retain<T: Serialize>(&mut self, v: &T) -> Result<(), HarnessError> {
        let n = encoded_size(v, self.c.limits().retained_bytes())?;
        let sum = self
            .used
            .checked_add(n)
            .ok_or_else(|| he(HarnessErrorKind::LimitExceeded, "retained overflow"))?;
        if sum > self.c.limits().retained_bytes() {
            return Err(he(HarnessErrorKind::LimitExceeded, "retained response"));
        }
        self.used = sum;
        Ok(())
    }
    fn effect(&mut self, key: &InvocationKey, stage: EnteredStage, b: &EffectBatch) {
        let owner = if stage == EnteredStage::Execute {
            Owner::Adapter
        } else {
            Owner::Fixture
        };
        let name = match stage {
            EnteredStage::Prepare => "prepare",
            EnteredStage::Execute => "execute",
            _ => "collect",
        };
        if let Err(e) = self.ledger.batch(&self.c, b, owner, key, name) {
            self.ledger.uncertain_at(owner, key, name);
            self.reject(e)
        }
    }
    fn capture_batch(
        &mut self,
        key: &InvocationKey,
        stage: EnteredStage,
        b: &EffectBatch,
    ) -> Option<EffectBatch> {
        // The contract reserves bounded ledger registrations and indexes. The
        // separate chronological mirror is dynamic owned payload and must be
        // charged before cloning, including a successful prepare response.
        let keep = b.check_bounds(self.c.limits()).and_then(|_| self.retain(b));
        self.effect(key, stage, b);
        match keep {
            Ok(()) => Some(b.clone()),
            Err(error) => {
                let owner = if stage == EnteredStage::Execute {
                    Owner::Adapter
                } else {
                    Owner::Fixture
                };
                self.ledger.uncertain_at(owner, key, "copy-invalid");
                self.reject(error);
                None
            }
        }
    }
    fn phase(
        &mut self,
        index: usize,
        adapter: &mut dyn ConformanceAdapter,
        fixtures: &mut dyn FixtureSession,
    ) {
        let scope = if index < self.c.schedule().len() {
            CleanupScope::Case(self.c.schedule()[index].clone())
        } else {
            CleanupScope::Run(self.c.run_id().clone())
        };
        let phase_start = self.clock.now();
        let allowance = Duration::from_millis(self.c.limits().retirement_ms());
        let available = allowance.saturating_sub(self.closed);
        let Some(deadline) = phase_start.checked_add(available) else {
            self.reject(he(
                HarnessErrorKind::LimitExceeded,
                "retirement deadline overflow",
            ));
            return;
        };
        let start_record = self.records.len();
        for (offset, owner) in [Owner::Adapter, Owner::Fixture].into_iter().enumerate() {
            let call = 2 * index as u64 + offset as u64 + 1;
            let now = self.clock.now();
            let participate = self.ledger.participates(owner, &scope);
            let mut request = if participate {
                let request = RetireRequest {
                    call_id: call,
                    owner,
                    scope: scope.clone(),
                    deadline,
                    remaining: Duration::ZERO,
                    known_pending: self.ledger.pending(owner, &scope),
                    uncertainty_ids: self.ledger.uncertainty(owner, &scope),
                    remaining_records: self
                        .c
                        .limits()
                        .effects_total()
                        .saturating_sub(self.ledger.regs.len() as u64),
                    remaining_retained_bytes: self
                        .c
                        .limits()
                        .retained_bytes()
                        .saturating_sub(self.used),
                };
                Some(request)
            } else {
                None
            };
            // Request preparation is charged to the fixed phase deadline.
            // Remaining and hook elapsed start at the same actual entry sample.
            let started = if participate { self.clock.now() } else { now };
            let remaining = deadline.saturating_duration_since(started);
            if let Some(request) = &mut request {
                request.remaining = remaining;
            }

            let Ok(before) = duration_ns(remaining) else {
                self.reject(he(
                    HarnessErrorKind::LimitExceeded,
                    "retirement remaining overflow",
                ));
                return;
            };
            let (mut status, mut response, mut error, mut elapsed) =
                (CleanupCallStatus::UncalledNoParticipation, None, None, 0);
            if participate && remaining.is_zero() {
                status = CleanupCallStatus::UncalledBudgetExhausted;
                error = Some(
                    CleanupError::new(
                        CleanupErrorValues {
                            kind: CleanupErrorKind::BudgetExhausted,
                            diagnostic: "cumulative retirement allowance exhausted".into(),
                        },
                        self.c.limits(),
                    )
                    .expect("bounded retirement error"),
                );
                for k in self
                    .ledger
                    .participants
                    .iter()
                    .filter(|(o, k)| *o == owner && crate::result::in_scope(k, &scope))
                    .map(|(_, k)| k.clone())
                    .collect::<Vec<_>>()
                {
                    self.ledger.uncertain_at(
                        owner,
                        &k,
                        if index < self.c.schedule().len() {
                            "case-uncalled"
                        } else {
                            "run-uncalled"
                        },
                    )
                }
            } else if participate {
                let request = request.take().expect("participating request");
                let r = match owner {
                    Owner::Adapter => adapter.retire(&request),
                    Owner::Fixture => fixtures.retire(&request),
                };
                let ended = self.clock.now();
                match checked_elapsed(started, ended) {
                    Ok(ns) => elapsed = ns,
                    Err(error) => {
                        self.reject(error);
                        return;
                    }
                }
                status = if ended > deadline {
                    CleanupCallStatus::CalledOverBudget
                } else {
                    CleanupCallStatus::Called
                };
                let retained = self.retain(&r);
                let keep_response = retained.is_ok();
                let validation = r
                    .check_bounds(self.c.limits())
                    .and(retained)
                    .and_then(|_| self.ledger.response(&self.c, &r, owner, &scope, call));
                if let Err(e) = validation {
                    for k in self
                        .ledger
                        .participants
                        .iter()
                        .filter(|(o, k)| *o == owner && crate::result::in_scope(k, &scope))
                        .map(|(_, k)| k.clone())
                        .collect::<Vec<_>>()
                    {
                        self.ledger.uncertain_at(
                            owner,
                            &k,
                            if index < self.c.schedule().len() {
                                "case-invalid"
                            } else {
                                "run-invalid"
                            },
                        )
                    }
                    error = Some(
                        CleanupError::new(
                            CleanupErrorValues {
                                kind: CleanupErrorKind::InvalidProtocol,
                                diagnostic: "retirement response invalid".into(),
                            },
                            self.c.limits(),
                        )
                        .expect("bounded error"),
                    );
                    self.reject(e)
                }
                response = if keep_response { Some(r) } else { None };
            }
            let remaining_after =
                match duration_ns(deadline.saturating_duration_since(self.clock.now())) {
                    Ok(ns) => ns,
                    Err(error) => {
                        self.reject(error);
                        return;
                    }
                };
            let complete = response.as_ref().is_some_and(|r| *r.complete()) && error.is_none();
            let called = matches!(
                status,
                CleanupCallStatus::Called | CleanupCallStatus::CalledOverBudget
            );
            let state = self.ledger.state(owner, &scope, called, complete);
            self.records.push(CleanupRecord {
                call_id: call,
                owner,
                scope: scope.clone(),
                status,
                transition_ids: response.as_ref().map_or(vec![], |r| {
                    r.transitions()
                        .iter()
                        .map(|t| t.transition_id().clone())
                        .collect()
                }),
                response,
                error,
                state_at_case_end: if index < self.c.schedule().len() {
                    Some(state)
                } else {
                    None
                },
                state_at_run_end: state,
                pending_ids: self
                    .ledger
                    .pending(owner, &scope)
                    .iter()
                    .map(|p| p.resource_id().clone())
                    .collect(),
                uncertainty_ids: self.ledger.uncertainty(owner, &scope),
                hook_elapsed_ns: elapsed,
                remaining_before_ns: before,
                remaining_after_ns: remaining_after,
                phase_elapsed_ns: 0,
            });
        }
        let phase_end = self.clock.now();
        let Some(duration) = phase_end.checked_duration_since(phase_start) else {
            self.records.truncate(start_record);
            self.reject(he(
                HarnessErrorKind::InvalidProtocol,
                "retirement clock reversed",
            ));
            return;
        };
        let Ok(ns) = duration_ns(duration) else {
            self.records.truncate(start_record);
            self.reject(he(
                HarnessErrorKind::LimitExceeded,
                "retirement phase overflow",
            ));
            return;
        };
        self.closed = self.closed.saturating_add(duration);
        for r in &mut self.records[start_record..] {
            r.phase_elapsed_ns = ns
        }
        if let Some(r) = self.records.last_mut() {
            r.remaining_after_ns = duration_ns(deadline.saturating_duration_since(phase_end))
                .expect("remaining bounded by admitted retirement allowance")
        }
    }
}
fn metadata<T: Serialize + Clone + Eq + BoundValue, C: Clock>(
    engine: &mut Engine<'_, C>,
    expected: &T,
    hook: impl FnOnce() -> T,
) -> MetadataObservation<T> {
    if engine.stopped {
        return MetadataObservation::omitted(OmissionCause::PriorStop);
    }
    let before = engine.sample();
    if engine.stopped {
        return MetadataObservation {
            checkpoints: CheckpointPair {
                before,
                after: CheckpointSlot::omitted(OmissionCause::NotEntered),
            },
            value: None,
            returned_elapsed_ns: None,
        };
    }
    let value = hook();
    let returned = engine.elapsed();
    let retained = engine.retain(&value);
    let keep = retained.is_ok();
    let validation = value.check_bounds(engine.c.limits()).and(retained);
    let after = engine.sample();
    if let Err(e) = validation {
        engine.reject(e)
    }
    if &value != expected {
        engine.stopped = true
    }
    MetadataObservation {
        checkpoints: CheckpointPair { before, after },
        value: if keep { Some(value) } else { None },
        returned_elapsed_ns: returned,
    }
}
fn invocation(c: &RunContract, key: &InvocationKey) -> CaseInvocation {
    let r = c.rule(key.case_key());
    CaseInvocation::new(
        CaseInvocationValues {
            key: key.clone(),
            observation_schema: r.observation_schema().clone(),
            fixture_schema: r.fixture_schema().clone(),
            script: r.script().clone(),
            limits: c.limits().clone(),
        },
        c.limits(),
    )
    .expect("admitted invocation")
}
fn run_engine<C: Clock>(
    plan: &ProfilePlan,
    adapter: &mut dyn ConformanceAdapter,
    fixtures: &mut dyn FixtureSession,
    oracle: &dyn CaseOracle,
    c: RunContract,
    entry: Instant,
    contract_returned: u64,
    probe: &dyn Fn() -> bool,
    clock: &C,
) -> Result<RunReport, HarnessError> {
    if c.selection() != &SelectionBinding::plan(plan) {
        return Err(he(HarnessErrorKind::InvalidSelection, "external plan"));
    }
    let retained_vectors = c
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
        .map(|a| *a.length())
        .sum::<u64>();
    let used =
        c.0.reservation
            .checked_add(retained_vectors)
            .ok_or_else(|| he(HarnessErrorKind::LimitExceeded, "retained vectors"))?;
    if used > c.limits().retained_bytes() {
        return Err(he(HarnessErrorKind::LimitExceeded, "retained vectors"));
    }
    let mut e = Engine {
        c: c.clone(),
        entry,
        clock,
        probe,
        stopped: false,
        invalid: None,
        ledger: Ledger::default(),
        closed: Duration::ZERO,
        records: Vec::with_capacity(2 * c.schedule().len() + 2),
        used,
        last_elapsed: contract_returned,
    };
    let noexec =
        c.0.cases
            .values()
            .all(|case| case.implementation_status() == ImplementationStatus::Unimplemented);
    let after_contract = e.sample();
    let (entry_subject, entry_oracle) = if noexec {
        (
            MetadataObservation::omitted(OmissionCause::NoExecutableMembers),
            MetadataObservation::omitted(OmissionCause::NoExecutableMembers),
        )
    } else {
        let subject = metadata(&mut e, c.expected_subject(), || adapter.subject());
        if subject
            .value
            .as_ref()
            .is_some_and(|s| s != c.expected_subject())
        {
            return Err(he(HarnessErrorKind::InvalidBinding, "entry subject"));
        }
        let oracle = metadata(&mut e, c.expected_oracle(), || oracle.identity());
        if oracle
            .value
            .as_ref()
            .is_some_and(|s| s != c.expected_oracle())
        {
            return Err(he(HarnessErrorKind::InvalidBinding, "entry oracle"));
        }
        (subject, oracle)
    };
    let mut rows = Vec::with_capacity(c.schedule().len());
    for (index, key) in c.schedule().iter().enumerate() {
        let r = c.rule(key.case_key());
        let executable = c.0.cases[key.case_key()].implementation_status()
            != ImplementationStatus::Unimplemented;
        let omission = if !executable {
            OmissionCause::CaseNotExecutable
        } else if e.stopped {
            OmissionCause::PriorStop
        } else {
            OmissionCause::StageNotReached
        };
        let mut x = CaseResult {
            key: key.clone(),
            script_sha256: r.script().sha256(),
            tier: *r.tier(),
            entered_stages: vec![],
            execution_checkpoints: ExecutionCheckpoints::omitted(omission),
            execution: ExecutionState::NotRun,
            reason: Some(
                if executable {
                    "prior stop"
                } else {
                    "case unimplemented"
                }
                .into(),
            ),
            outcome: None,
            fixture_failure: None,
            expected_evidence: None,
            oracle_verdict: None,
            effective_checks: vec![],
            capability: crate::result::unjudged(c.limits()),
            coverage: vec![],
            effect_batches: vec![],
            case_cleanup_call_ids: vec![2 * index as u64 + 1, 2 * index as u64 + 2],
            terminal: None,
        };
        if executable && !e.stopped {
            let i = invocation(&c, key);
            let before = e.sample();
            x.execution_checkpoints.prepare.before = before;
            if !e.stopped {
                x.entered_stages.push(EnteredStage::Prepare);
                e.ledger.participants.insert((Owner::Fixture, key.clone()));
                x.execution = ExecutionState::Blocked;
                x.reason = None;
                let access = fixtures.prepare(&i);
                match access {
                    Ok(access) => {
                        if let Some(batch) =
                            e.capture_batch(key, EnteredStage::Prepare, access.effects())
                        {
                            x.effect_batches.push(batch);
                        }
                        x.execution_checkpoints.prepare.after = e.sample();
                        if !e.stopped {
                            let before = e.sample();
                            x.execution_checkpoints.execute.before = before;
                            if !e.stopped {
                                if e.used
                                    .checked_add(c.limits().observation_bytes())
                                    .is_none_or(|n| n > c.limits().retained_bytes())
                                {
                                    e.reject(he(
                                        HarnessErrorKind::LimitExceeded,
                                        "next observation allowance",
                                    ))
                                } else {
                                    x.entered_stages.push(EnteredStage::Execute);
                                    e.ledger.participants.insert((Owner::Adapter, key.clone()));
                                    let outcome = match adapter.execute(&i, &access) {
                                        Ok(o) => CaseOutcome::Observed(o),
                                        Err(err) => CaseOutcome::OperationError(err),
                                    };
                                    let keep = e.retain(&outcome);
                                    if let Some(batch) = e.capture_batch(
                                        key,
                                        EnteredStage::Execute,
                                        outcome.effects(),
                                    ) {
                                        x.effect_batches.push(batch);
                                    }
                                    if keep.is_ok() {
                                        x.outcome = Some(outcome);
                                    }
                                    x.execution_checkpoints.execute.after = e.sample();
                                    if let Err(error) = keep {
                                        e.reject(error)
                                    }
                                    if let Some(outcome) = &x.outcome {
                                        if let Err(error) = crate::result::validate_outcome(
                                            key,
                                            r,
                                            outcome,
                                            c.limits(),
                                        ) {
                                            e.reject(error)
                                        }
                                        if matches!(outcome,CaseOutcome::OperationError(err)if matches!(err.category(),CaseErrorCategory::Cancelled|CaseErrorCategory::TimedOut))
                                        {
                                            e.stopped = true;
                                        }
                                    }
                                }
                            }
                        }
                        drop(access);
                    }
                    Err(err) => {
                        let category = *err.category();
                        let retained = e.retain(&err);
                        let keep = retained.is_ok();
                        let validation =
                            validate_fixture_failure(key, FixtureStage::Prepare, &err, &c)
                                .and(retained);
                        if let Some(batch) =
                            e.capture_batch(key, EnteredStage::Prepare, err.effects())
                        {
                            x.effect_batches.push(batch);
                        }
                        if keep {
                            x.fixture_failure = Some(err);
                        }
                        x.reason = Some("fixture prepare failed".into());
                        x.execution_checkpoints.prepare.after = e.sample();
                        if let Err(error) = validation {
                            e.ledger
                                .uncertain_at(Owner::Fixture, key, "prepare-invalid");
                            e.reject(error)
                        }
                        if matches!(
                            category,
                            FixtureErrorCategory::Cancelled
                                | FixtureErrorCategory::TimedOut
                                | FixtureErrorCategory::InvalidProtocol
                        ) {
                            e.stopped = true;
                        }
                        if category == FixtureErrorCategory::InvalidProtocol {
                            x.execution = ExecutionState::HarnessError
                        }
                    }
                }
                if !e.stopped && x.outcome.is_some() {
                    x.execution_checkpoints.collect.before = e.sample();
                    if !e.stopped {
                        x.entered_stages.push(EnteredStage::Collect);
                        match fixtures.collect(&i) {
                            Ok(expected) => {
                                let validation =
                                    crate::result::validate_expected(&c, key, r, &expected);
                                let retained = e.retain(&expected);
                                if let Some(batch) =
                                    e.capture_batch(key, EnteredStage::Collect, expected.effects())
                                {
                                    x.effect_batches.push(batch);
                                }
                                if retained.is_ok() {
                                    x.expected_evidence = Some(expected);
                                }
                                let check = validation.and(retained);
                                if let Err(error) = check {
                                    e.reject(error)
                                }
                            }
                            Err(err) => {
                                let category = *err.category();
                                let retained = e.retain(&err);
                                let keep = retained.is_ok();
                                let validation =
                                    validate_fixture_failure(key, FixtureStage::Collect, &err, &c)
                                        .and(retained);
                                if let Some(batch) =
                                    e.capture_batch(key, EnteredStage::Collect, err.effects())
                                {
                                    x.effect_batches.push(batch);
                                }
                                if keep {
                                    x.fixture_failure = Some(err);
                                }
                                x.reason = Some("fixture collect failed".into());
                                if let Err(error) = validation {
                                    e.ledger
                                        .uncertain_at(Owner::Fixture, key, "collect-invalid");
                                    e.reject(error)
                                }
                                if matches!(
                                    category,
                                    FixtureErrorCategory::Cancelled
                                        | FixtureErrorCategory::TimedOut
                                        | FixtureErrorCategory::InvalidProtocol
                                ) {
                                    e.stopped = true;
                                }
                                if category == FixtureErrorCategory::InvalidProtocol {
                                    x.execution = ExecutionState::HarnessError
                                }
                            }
                        }
                        x.execution_checkpoints.collect.after = e.sample();
                    }
                }
                if !e.stopped && x.outcome.is_some() && x.expected_evidence.is_some() {
                    x.execution_checkpoints.judge.before = e.sample();
                    if !e.stopped {
                        x.entered_stages.push(EnteredStage::Judge);
                        let v = oracle.evaluate(
                            &c.0.cases[key.case_key()],
                            x.expected_evidence.as_ref().unwrap(),
                            x.outcome.as_ref().unwrap(),
                        );
                        let check = v.check_bounds(c.limits()).and_then(|_| e.retain(&v));
                        let harness_invalid =
                            matches!(v.harness(), HarnessValidity::Invalid { .. });
                        // The raw capability is retained once here. The pure
                        // fold reserves its derived owned copy before cloning.
                        x.capability = crate::result::unjudged(c.limits());
                        x.oracle_verdict = Some(v);
                        x.execution = if harness_invalid {
                            ExecutionState::HarnessError
                        } else {
                            ExecutionState::Completed
                        };
                        if harness_invalid {
                            e.stopped = true;
                        }
                        x.reason = None;
                        x.execution_checkpoints.judge.after = e.sample();
                        if let Err(error) = check {
                            e.reject(error)
                        }
                        if x.oracle_verdict.as_ref().is_some_and(|v| {
                            v.checks().len() != r.assertions().len()
                                || v.checks()
                                    .iter()
                                    .any(|a| !r.assertions().iter().any(|r| r.id() == a.id()))
                        }) {
                            e.reject(he(
                                HarnessErrorKind::InvalidProtocol,
                                "oracle assertion set",
                            ));
                            x.capability = crate::result::unjudged(c.limits());
                        }
                    }
                }
            }
            if e.invalid.is_some() {
                x.execution = ExecutionState::HarnessError
            }
            // Explain each unentered stage by the fixed stopping latch or local prerequisite.
            for stage in [
                EnteredStage::Prepare,
                EnteredStage::Execute,
                EnteredStage::Collect,
                EnteredStage::Judge,
            ] {
                if !x.entered_stages.contains(&stage) {
                    let pair = x.execution_checkpoints.pair_mut(stage);
                    if !matches!(pair.before, CheckpointSlot::Sampled { .. }) {
                        pair.before = CheckpointSlot::omitted(if e.stopped {
                            OmissionCause::PriorStop
                        } else {
                            OmissionCause::StageNotReached
                        })
                    }
                    pair.after = CheckpointSlot::omitted(OmissionCause::NotEntered)
                }
            }
        }
        e.phase(index, adapter, fixtures);
        x.terminal = Some(CaseTerminal {
            key: key.clone(),
            execution: x.execution,
            after_cleanup_call_id: 2 * index as u64 + 2,
        });
        rows.push(x);
    }
    e.phase(c.schedule().len(), adapter, fixtures);
    let unresolved = [Owner::Adapter, Owner::Fixture].into_iter().any(|owner| {
        let scope = CleanupScope::Run(c.run_id().clone());
        let called = e
            .records
            .iter()
            .find(|r| r.owner == owner && r.scope == scope)
            .is_some_and(|r| {
                matches!(
                    r.status,
                    CleanupCallStatus::Called | CleanupCallStatus::CalledOverBudget
                ) && r.error.is_none()
                    && r.response.as_ref().is_some_and(|r| *r.complete())
            });
        e.ledger.state(owner, &scope, called, called) == CleanupState::Unresolved
    });
    let (final_subject, final_oracle) = if noexec {
        (
            MetadataObservation::omitted(OmissionCause::NoExecutableMembers),
            MetadataObservation::omitted(OmissionCause::NoExecutableMembers),
        )
    } else if e.stopped {
        (
            MetadataObservation::omitted(OmissionCause::PriorStop),
            MetadataObservation::omitted(OmissionCause::PriorStop),
        )
    } else if unresolved {
        (
            MetadataObservation::omitted(OmissionCause::CleanupUnresolved),
            MetadataObservation::omitted(OmissionCause::CleanupUnresolved),
        )
    } else {
        let subject = metadata(&mut e, c.expected_subject(), || adapter.subject());
        let oracle = metadata(&mut e, c.expected_oracle(), || oracle.identity());
        (subject, oracle)
    };
    let obs = RunnerObservations {
        contract_returned_elapsed_ns: contract_returned,
        after_contract,
        entry_subject,
        entry_oracle,
        final_subject,
        final_oracle,
        completion: CheckpointSlot::NotRecorded,
    };
    let mut w = ReportWire {
        schema_version: 1,
        kind: "tt02-run-report".into(),
        run_contract_sha256: c.sha256(),
        run_id: c.run_id().clone(),
        selection: c.selection().clone(),
        artifacts: c.artifacts().to_vec(),
        runner_observations: obs,
        case_results: rows,
        cleanup_records: std::mem::take(&mut e.records),
        run_terminal: Some(RunTerminal {
            qualification: Qualification::Incomplete,
            reasons: vec![],
            after_cleanup_call_id: 2 * c.schedule().len() as u64 + 2,
        }),
    };
    // Compute the case/ledger fold before the last custom checkpoint as required.
    let terminal = w.run_terminal.take();
    let preliminary = reconstruct(&c, &mut w, false);
    w.run_terminal = terminal;
    if let Err(error) = preliminary {
        e.reject(error)
    }

    w.runner_observations.completion = e.sample();
    let q = match reconstruct(&c, &mut w, false) {
        Ok(q) => q,
        Err(error) => {
            let mut error = e.invalid.take().unwrap_or(error);
            w.run_terminal = None;
            error.partial = Some(Box::new(RunReport {
                wire: w,
                qualification: Qualification::Invalid,
                origin: ReportOrigin::ExecutedHere,
                limits: c.limits().clone(),
            }));
            return Err(error);
        }
    };
    let report = RunReport {
        wire: w,
        qualification: q,
        origin: ReportOrigin::ExecutedHere,
        limits: c.limits().clone(),
    };
    if let Err(error) = encoded_size(&report.wire, c.limits().receipt_bytes()) {
        e.reject(error);
    }
    if let Some(mut error) = e.invalid {
        error.partial = Some(Box::new(report));
        Err(error)
    } else {
        Ok(report)
    }
}

/// Run one frozen sequential profile with independently bound input/truth channels.
pub fn run_profile(
    plan: &ProfilePlan,
    adapter: &mut dyn ConformanceAdapter,
    fixtures: &mut dyn FixtureSession,
    oracle: &dyn CaseOracle,
) -> Result<RunReport, HarnessError> {
    run_with_clock(plan, adapter, fixtures, oracle, &SystemClock)
}
fn run_with_clock<C: Clock>(
    plan: &ProfilePlan,
    adapter: &mut dyn ConformanceAdapter,
    fixtures: &mut dyn FixtureSession,
    oracle: &dyn CaseOracle,
    clock: &C,
) -> Result<RunReport, HarnessError> {
    let entry = clock.now();
    let c = fixtures.contract().clone();
    let returned = checked_elapsed(entry, clock.now())?;
    if c.selection() != &SelectionBinding::plan(plan) {
        return Err(he(HarnessErrorKind::InvalidSelection, "external plan"));
    }
    let duration = Duration::from_millis(c.limits().execution_ms());
    entry.checked_add(duration).ok_or_else(|| {
        he(
            HarnessErrorKind::LimitExceeded,
            "execution deadline overflow",
        )
    })?;
    let probe_elapsed = checked_elapsed(entry, clock.now())?;
    let probe = if Duration::from_nanos(probe_elapsed) >= duration {
        None
    } else {
        Some(fixtures.cancellation_probe())
    };
    let poll = || {
        probe
            .as_ref()
            .expect("unexpired checkpoint requires acquired owned probe")
            .cancellation_requested()
    };
    run_engine(
        plan, adapter, fixtures, oracle, c, entry, returned, &poll, clock,
    )
}
#[cfg(test)]
mod tests;

fn validate_fixture_failure(
    key: &InvocationKey,
    stage: FixtureStage,
    e: &FixtureError,
    c: &RunContract,
) -> Result<(), HarnessError> {
    e.check_bounds(c.limits())?;
    if e.key().as_ref() != Some(key) || *e.stage() != stage {
        return Err(he(
            HarnessErrorKind::InvalidProtocol,
            "fixture failure key/stage",
        ));
    }
    if let Some(p) = e.read_progress() {
        crate::result::validate_read_progress(c, p)?;
    }
    Ok(())
}
