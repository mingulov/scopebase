// SPDX-License-Identifier: Apache-2.0
//! Caller-owned fixture authority and immutable, separately bound vector truth.
use crate::artifact::*;
use crate::*;
use serde::Serialize;
use serde_json::Value;
use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet},
    fs::File,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
#[cfg(all(
    target_os = "linux",
    any(feature = "linux-fixtures", feature = "seccomp-fixture")
))]
pub mod linux;
/// Independently owned observer that may outlive a mutable fixture borrow.
/// A reference captured from the fixture cannot satisfy the owned probe lifetime:
/// ```compile_fail
/// use scopebase_testkit::CancellationProbe;
/// struct Borrowed<'a>(&'a bool);
/// impl CancellationProbe for Borrowed<'_>{fn cancellation_requested(&self)->bool{*self.0}}
/// fn forbidden(flag:&bool)->Box<dyn CancellationProbe+'static>{Box::new(Borrowed(flag))}
/// ```
/// The previous shared-session poll conflicts with the retained prepare borrow:
/// ```compile_fail,E0502
/// use scopebase_testkit::{CaseInvocation,FixtureAccess,Label};
/// trait OldSession{
///   fn prepare(&mut self,i:&CaseInvocation)->FixtureAccess<'_>;
///   fn cancellation_requested(&self)->bool;
/// }
/// fn wrong(s:&mut dyn OldSession,i:&CaseInvocation){
///   let access=s.prepare(i);
///   let _=s.cancellation_requested();
///   let _=access.input(&Label::parse("operands").unwrap());
/// }
/// ```
pub trait CancellationProbe {
    fn cancellation_requested(&self) -> bool;
}
pub trait FixtureSession {
    fn contract(&self) -> &RunContract;
    fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static>;
    fn prepare(&mut self, invocation: &CaseInvocation) -> Result<FixtureAccess<'_>, FixtureError>;
    fn collect(&mut self, invocation: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError>;
    fn retire(&mut self, request: &RetireRequest) -> RetirementReport;
}
pub struct FixtureInput<'a> {
    slot: Label,
    bytes: &'a [u8],
}
impl<'a> FixtureInput<'a> {
    pub fn new(slot: Label, bytes: &'a [u8]) -> Self {
        Self { slot, bytes }
    }
}
pub struct FixtureResource<'a> {
    id: Label,
    value: &'a dyn Any,
}
impl<'a> FixtureResource<'a> {
    pub fn new(id: Label, value: &'a dyn Any) -> Self {
        Self { id, value }
    }
}
/// Borrowed inputs and actual owners; reports cannot create this access.
/// ```compile_fail
/// use scopebase_testkit::FixtureAccess;
/// let a = FixtureAccess { inputs: vec![], resources: vec![] };
/// ```
/// Entry arrays may be local to a provider's prepare call. Their labels are
/// copied; only the supplied bytes and actual resource owners remain borrowed.
/// Returning access cannot extend an underlying owner's lifetime:
/// ```compile_fail,E0515
/// use scopebase_testkit::{EffectBatch, FixtureAccess, FixtureInput, FixtureResource, Label, RunLimits};
/// fn forbidden<'a>(bytes: &'a [u8]) -> FixtureAccess<'a> {
///     let limits = RunLimits::default();
///     let owner = String::from("retained owner");
///     let inputs = [FixtureInput::new(Label::parse("input").unwrap(), bytes)];
///     let resources = [FixtureResource::new(Label::parse("owner").unwrap(), &owner)];
///     FixtureAccess::new(&inputs, &resources, EffectBatch::empty(&limits), &limits).unwrap()
/// }
/// ```
/// Nor can access outlive the input allocation:
/// ```compile_fail,E0515
/// use scopebase_testkit::{EffectBatch, FixtureAccess, FixtureInput, FixtureResource, Label, RunLimits};
/// fn forbidden<'a>(owner: &'a dyn std::any::Any) -> FixtureAccess<'a> {
///     let limits = RunLimits::default();
///     let bytes = vec![1, 2, 3];
///     let inputs = [FixtureInput::new(Label::parse("input").unwrap(), &bytes)];
///     let resources = [FixtureResource::new(Label::parse("owner").unwrap(), owner)];
///     FixtureAccess::new(&inputs, &resources, EffectBatch::empty(&limits), &limits).unwrap()
/// }
/// ```
pub struct FixtureAccess<'a> {
    inputs: Vec<(Label, &'a [u8])>,
    resources: Vec<(Label, &'a dyn Any)>,
    effects: EffectBatch,
}
impl<'a> FixtureAccess<'a> {
    pub fn new(
        inputs: &[FixtureInput<'a>],
        resources: &[FixtureResource<'a>],
        effects: EffectBatch,
        l: &RunLimits,
    ) -> Result<Self, FixtureError> {
        let f = || -> Result<(), HarnessError> {
            bound(inputs.len(), l.input_slots(), "fixture input slots")?;
            bound(resources.len(), l.resource_views(), "resource views")?;
            unique(&inputs.iter().map(|x| &x.slot).collect::<Vec<_>>())?;
            unique(&resources.iter().map(|x| &x.id).collect::<Vec<_>>())?;
            for i in inputs {
                i.slot.check_bounds(l)?;
                bound(i.bytes.len(), l.vector_bytes(), "fixture input")?
            }
            for r in resources {
                r.id.check_bounds(l)?;
            }
            effects.check_bounds(l)?;
            Ok(())
        };
        f().map_err(|e| FixtureError::harness(e, None, FixtureStage::Prepare))?;
        Ok(Self {
            inputs: inputs.iter().map(|x| (x.slot.clone(), x.bytes)).collect(),
            resources: resources.iter().map(|x| (x.id.clone(), x.value)).collect(),
            effects,
        })
    }
    pub fn input(&self, slot: &Label) -> Option<&[u8]> {
        self.inputs.iter().find(|(s, _)| s == slot).map(|(_, b)| *b)
    }
    pub fn resource<T: Any>(&self, id: &Label) -> Option<&T> {
        self.resources
            .iter()
            .find(|(s, _)| s == id)
            .and_then(|(_, v)| v.downcast_ref())
    }
    pub fn effects(&self) -> &EffectBatch {
        &self.effects
    }
}
wire_enum!(VectorRole{Input=>"input",Expected=>"expected",Ledger=>"ledger"});
record!(
    VectorFile,
    VectorFileValues {
        file_id: Label,
        role: VectorRole,
        #[serde(with = "decimal")]
        length: u64,
        sha256: Digest256
    },
    |v: &VectorFileValues, l: &RunLimits| {
        if v.length > l.vector_bytes() {
            return Err(he(HarnessErrorKind::LimitExceeded, "vector length"));
        }
        Ok(())
    }
);
record!(
    VectorSlot,
    VectorSlotValues {
        slot: Label,
        file_id: Label
    },
    |_: &VectorSlotValues, _: &RunLimits| Ok(())
);
record!(VectorInvocation,VectorInvocationValues{key:InvocationKey,inputs:Vec<VectorSlot>,expected_file:Label,ledger_file:Label},|v:&VectorInvocationValues,l:&RunLimits|{bound(v.inputs.len(),l.input_slots(),"input slots")?;sorted(&v.inputs.iter().map(|s|s.slot()).collect::<Vec<_>>())});
#[derive(Debug)]
pub struct VectorManifest {
    contract: RunContract,
    files: Vec<VectorFile>,
    invocations: Vec<VectorInvocation>,
}
impl VectorManifest {
    pub fn load(
        contract: &RunContract,
        bytes: &[u8],
        ceiling: RunLimits,
    ) -> Result<Self, FixtureError> {
        Self::admit(contract, bytes, ceiling)
            .map_err(|e| FixtureError::harness(e, None, FixtureStage::Admission))
    }
    fn admit(c: &RunContract, b: &[u8], ceiling: RunLimits) -> Result<Self, HarnessError> {
        if c.case_rules().iter().any(|r| *r.tier() != EvidenceTier::T0) {
            return Err(he(
                HarnessErrorKind::InvalidBinding,
                "authored vector provider is T0",
            ));
        }
        ceiling
            .lowered(c.limits().values())
            .map_err(|e| he(HarnessErrorKind::LimitExceeded, &e.to_string()))?;
        let l = c.limits();
        let mut o = Obj::new(
            parse(b, l.input_bytes(), l)?,
            &[
                "schema_version",
                "kind",
                "run_contract_sha256",
                "run_id",
                "files",
                "invocations",
            ],
        )?;
        let version: u32 = o.get("schema_version", l)?;
        let kind: String = o.get("kind", l)?;
        if version != 1 || kind != "tt02-vector-bundle" {
            return Err(he(HarnessErrorKind::UnsupportedSchema, "vector bundle"));
        }
        let sha: Digest256 = o.get("run_contract_sha256", l)?;
        let run: RunId = o.get("run_id", l)?;
        if sha != c.sha256() || &run != c.run_id() {
            return Err(he(HarnessErrorKind::InvalidBinding, "vector contract"));
        }
        let files: Vec<VectorFile> = o.get("files", l)?;
        let invocations: Vec<VectorInvocation> = o.get("invocations", l)?;
        bound(files.len(), l.artifacts(), "vector files")?;
        sorted(&files.iter().map(|f| f.file_id()).collect::<Vec<_>>())?;
        if invocations.len() != c.schedule().len() {
            return Err(he(HarnessErrorKind::InvalidSelection, "vector invocations"));
        }
        let file_index = files
            .iter()
            .map(|f| (f.file_id(), f))
            .collect::<BTreeMap<_, _>>();
        let mut used = BTreeSet::new();
        for (row, key) in invocations.iter().zip(c.schedule()) {
            if row.key() != key {
                return Err(he(
                    HarnessErrorKind::InvalidSelection,
                    "vector invocation key/order",
                ));
            }
            let slots = c
                .rule(key.case_key())
                .script()
                .steps()
                .iter()
                .flat_map(|s| s.inputs())
                .collect::<BTreeSet<_>>();
            if slots != row.inputs().iter().map(|s| s.slot()).collect() {
                return Err(he(HarnessErrorKind::InvalidInput, "vector slot set"));
            }
            for (id, role) in row
                .inputs()
                .iter()
                .map(|s| (s.file_id(), VectorRole::Input))
                .chain([
                    (row.expected_file(), VectorRole::Expected),
                    (row.ledger_file(), VectorRole::Ledger),
                ])
            {
                let f = file_index
                    .get(id)
                    .copied()
                    .ok_or_else(|| he(HarnessErrorKind::InvalidBinding, "vector file missing"))?;
                if *f.role() != role {
                    return Err(he(HarnessErrorKind::InvalidBinding, "vector role"));
                }
                used.insert(id);
            }
        }
        if used.len() != files.len() {
            return Err(he(HarnessErrorKind::InvalidInput, "unreferenced vector"));
        }
        for f in &files {
            let role = match f.role() {
                VectorRole::Input => ArtifactRole::FixtureInput,
                VectorRole::Expected => ArtifactRole::ExpectedVector,
                VectorRole::Ledger => ArtifactRole::FixtureLedger,
            };
            if !c.artifacts().iter().any(|a| {
                a.id() == f.file_id()
                    && a.role() == &role
                    && a.length() == f.length()
                    && a.sha256() == f.sha256()
            }) {
                return Err(he(HarnessErrorKind::InvalidBinding, "vector artifact"));
            }
        }
        Ok(Self {
            contract: c.clone(),
            files,
            invocations,
        })
    }
    pub fn files(&self) -> &[VectorFile] {
        &self.files
    }
}
pub struct OpenedVector<'a> {
    pub file_id: Label,
    pub file: &'a File,
}
pub struct VectorBundle {
    contract: RunContract,
    files: BTreeMap<Label, Arc<Vec<u8>>>,
    invocations: Vec<VectorInvocation>,
}
impl VectorBundle {
    pub fn read(
        manifest: &VectorManifest,
        opened: &[OpenedVector<'_>],
        meter: &mut ArtifactMeasurer,
    ) -> Result<Self, FixtureError> {
        let c = &manifest.contract;
        let l = c.limits();
        let fail = |e| FixtureError::harness(e, None, FixtureStage::Admission);
        if &meter.run_id != c.run_id() || &meter.limits != l {
            return Err(fail(he(HarnessErrorKind::InvalidBinding, "meter binding")));
        }
        if opened.len() != manifest.files.len() {
            return Err(fail(he(
                HarnessErrorKind::InvalidInput,
                "opened file inventory",
            )));
        }
        unique(&opened.iter().map(|o| &o.file_id).collect::<Vec<_>>()).map_err(fail)?;
        let total = manifest.files.iter().try_fold(c.0.reservation, |n, f| {
            n.checked_add(*f.length())
                .ok_or_else(|| fail(he(HarnessErrorKind::LimitExceeded, "retention overflow")))
        })?;
        if total > l.retained_bytes() {
            return Err(fail(he(
                HarnessErrorKind::LimitExceeded,
                "vector retention",
            )));
        }
        let opened = opened
            .iter()
            .map(|o| (&o.file_id, o.file))
            .collect::<BTreeMap<_, _>>();
        let mut files = BTreeMap::new();
        for f in &manifest.files {
            let file = opened
                .get(f.file_id())
                .copied()
                .ok_or_else(|| fail(he(HarnessErrorKind::InvalidBinding, "opened file ID")))?;
            let a = c.artifact(f.file_id()).unwrap();
            let b = meter.read(a, file, true).map_err(|e| {
                let mut f = fail(he(HarnessErrorKind::InvalidBinding, &e.to_string()));
                f.0.read_progress = e.progress;
                f
            })?;
            files.insert(f.file_id().clone(), share_vector(b));
        }
        Ok(Self {
            contract: c.clone(),
            files,
            invocations: manifest.invocations.clone(),
        })
    }
}
fn share_vector(bytes: Vec<u8>) -> Arc<Vec<u8>> {
    Arc::new(bytes)
}
pub struct VectorFixtureSession {
    contract: RunContract,
    bundle: VectorBundle,
    next: usize,
    prepared: Option<usize>,
    started: bool,
    finished: bool,
    cancellation_bound: bool,
    cancel: Arc<AtomicBool>,
}
impl VectorFixtureSession {
    pub fn new(contract: RunContract, bundle: VectorBundle) -> Result<Self, FixtureError> {
        if contract.sha256() != bundle.contract.sha256()
            || contract.run_id() != bundle.contract.run_id()
            || contract.limits() != bundle.contract.limits()
        {
            return Err(FixtureError::harness(
                he(HarnessErrorKind::InvalidBinding, "bundle binding"),
                None,
                FixtureStage::Admission,
            ));
        }
        Ok(Self {
            contract,
            bundle,
            next: 0,
            prepared: None,
            started: false,
            finished: false,
            cancellation_bound: false,
            cancel: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn set_cancellation(&mut self, flag: Arc<AtomicBool>) -> Result<(), FixtureError> {
        if self.started || self.finished || self.cancellation_bound {
            return Err(FixtureError::harness(
                he(HarnessErrorKind::InvalidProtocol, "session started"),
                None,
                FixtureStage::Admission,
            ));
        }
        self.cancel = flag;
        Ok(())
    }
}
impl FixtureSession for VectorFixtureSession {
    fn contract(&self) -> &RunContract {
        &self.contract
    }
    fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static> {
        self.cancellation_bound = true;
        Box::new(AtomicCancellationProbe(Arc::clone(&self.cancel)))
    }
    fn prepare(&mut self, i: &CaseInvocation) -> Result<FixtureAccess<'_>, FixtureError> {
        self.started = true;
        let fail = || {
            FixtureError::harness(
                he(HarnessErrorKind::InvalidProtocol, "prepare order"),
                Some(i.key().clone()),
                FixtureStage::Prepare,
            )
        };
        if self.finished || self.prepared.is_some() {
            return Err(fail());
        }
        while self.next < self.bundle.invocations.len()
            && self.contract.0.cases[self.bundle.invocations[self.next].key().case_key()]
                .implementation_status()
                == ImplementationStatus::Unimplemented
        {
            self.next += 1
        }
        let Some(row) = self.bundle.invocations.get(self.next) else {
            return Err(fail());
        };
        if row.key() != i.key() {
            return Err(fail());
        }
        self.started = true;
        self.prepared = Some(self.next);
        Ok(FixtureAccess {
            inputs: row
                .inputs()
                .iter()
                .map(|s| (s.slot().clone(), self.bundle.files[s.file_id()].as_slice()))
                .collect(),
            resources: vec![],
            effects: EffectBatch::empty(self.contract.limits()),
        })
    }
    fn collect(&mut self, i: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError> {
        let fail = |e| FixtureError::harness(e, Some(i.key().clone()), FixtureStage::Collect);
        if self.finished || self.prepared != Some(self.next) {
            return Err(fail(he(HarnessErrorKind::InvalidProtocol, "collect order")));
        }
        let row = &self.bundle.invocations[self.next];
        if row.key() != i.key() {
            return Err(fail(he(HarnessErrorKind::InvalidProtocol, "collect key")));
        }
        let l = self.contract.limits();
        let ledger = &self.bundle.files[row.ledger_file()];
        let coverage =
            admit_vector_ledger(ledger, i.key(), self.contract.rule(i.key().case_key()), l)
                .map_err(fail)?;
        let v = ExpectedEvidence::from_shared(
            ExpectedEvidenceValues {
                key: i.key().clone(),
                oracle: self.contract.expected_oracle().clone(),
                fixture_schema: i.fixture_schema().clone(),
                truth_kind: TruthKind::FixedBeforeExecute,
                expected_bytes: vec![],
                ledger_bytes: vec![],
                coverage,
                effects: EffectBatch::empty(l),
            },
            l,
            Arc::clone(&self.bundle.files[row.expected_file()]),
            Arc::clone(ledger),
            *self
                .contract
                .artifact(row.expected_file())
                .expect("admitted expected")
                .sha256(),
            *self
                .contract
                .artifact(row.ledger_file())
                .expect("admitted ledger")
                .sha256(),
        )
        .map_err(fail)?;
        self.prepared = None;
        self.next += 1;
        Ok(v)
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        if matches!(r.scope(), CleanupScope::Run(_)) {
            self.finished = true
        }
        RetirementReport::new(
            RetirementReportValues {
                call_id: r.call_id(),
                owner: r.owner(),
                scope: r.scope().clone(),
                discovered: vec![],
                transitions: vec![],
                pending_snapshot: r.known_pending().to_vec(),
                complete: true,
                diagnostic: None,
            },
            self.contract.limits(),
        )
        .expect("bounded empty vector retirement")
    }
}
pub(crate) fn admit_vector_ledger(
    bytes: &[u8],
    key: &InvocationKey,
    rule: &CaseRule,
    l: &RunLimits,
) -> Result<Vec<CoverageEvidence>, HarnessError> {
    if *rule.tier() != EvidenceTier::T0 {
        return Err(he(
            HarnessErrorKind::InvalidBinding,
            "authored vector ledger is T0",
        ));
    }
    let mut o = Obj::new(
        parse(bytes, l.vector_bytes(), l)?,
        &[
            "schema_version",
            "kind",
            "key",
            "truth_kind",
            "evidence_tier",
            "coverage",
        ],
    )?;
    let schema: u32 = o.get("schema_version", l)?;
    let kind: String = o.get("kind", l)?;
    let k: InvocationKey = o.get("key", l)?;
    let truth: String = o.get("truth_kind", l)?;
    let tier: String = o.get("evidence_tier", l)?;
    if schema != 1
        || kind != "tt02-vector-ledger"
        || truth != "fixed-before-execute"
        || tier != "T0"
    {
        return Err(he(HarnessErrorKind::UnsupportedSchema, "vector ledger"));
    }
    if &k != key {
        return Err(he(HarnessErrorKind::InvalidBinding, "ledger key"));
    }
    let coverage: Vec<CoverageEvidence> = o.get("coverage", l)?;
    sorted(&coverage.iter().map(|c| c.id()).collect::<Vec<_>>())?;
    if coverage.len() != rule.coverage().len()
        || coverage.iter().any(|c| {
            !rule
                .coverage()
                .iter()
                .any(|r| r.id() == c.id() && r.step_ids() == c.step_ids())
        })
    {
        return Err(he(HarnessErrorKind::InvalidBinding, "ledger coverage"));
    }
    Ok(coverage)
}
#[cfg(test)]
mod tests;

struct AtomicCancellationProbe(Arc<AtomicBool>);
impl CancellationProbe for AtomicCancellationProbe {
    fn cancellation_requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
