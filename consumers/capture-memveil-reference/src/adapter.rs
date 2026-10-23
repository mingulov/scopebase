// SPDX-License-Identifier: Apache-2.0
//! MemVeil-shaped standalone adapter over facts, generations and views.
//!
//! NEW (CP11): reference-only; no donor lines copied. Each scenario composes
//! exact packaged `scopebase-capture` calls with this consumer's own fixed
//! script constants. Capture contract refusals are observed data encoded as
//! `refuse=<Variant>;`; only adapter-level failures (missing slot, unknown
//! operation, malformed script) become `CaseError`.
use scopebase_capture::{
    correction::{Correction, Revision, Versioned},
    domain::{
        BindingId, CaptureId, ChannelId, ClaimId, ClockDomain, Epoch, Origin, ProducerId,
        SourceRef,
    },
    feeds::FeedRegistry,
    generation::{require_generation, ObjectKey},
    holder::HolderPair,
    loss::{LossFact, LossKind, LossMagnitude},
    quantity::{Count, Events},
    time::{validate_sweep_order, EdgeKind, StateEdge, Timestamp},
    view::{ClaimAssessment, ClaimLedger, LedgerLimits, QualityReason, QueryOverlay},
    ContractError,
};
use scopebase_testkit::{
    BindingProvenance, CaseError, CaseErrorCategory, CaseErrorValues, CaseInvocation,
    ConformanceAdapter, ConsumerBinding, ConsumerBindingValues, Digest256, EffectBatch,
    EvidenceTier, FixtureAccess, HarnessError, Label, Observation, ObservationValues,
    RefusalCause, RefusalEvidence, RefusalEvidenceValues, RetireRequest, RetirementReport,
    RetirementReportValues, RunLimits, SubjectBinding, SubjectBindingValues,
};

const PACKAGE: &str = "capture-memveil-reference";
const CONSUMER: &str = "memveil-adapter";
const SCHEMA_ID: &str = "memveil-reference-v1";
const SCHEMA_REVISION: u32 = 1;

/// RB4 (R02): truncate a refusal diagnostic to an invocation byte
/// ceiling. Diagnostics are bounded context inside an already-honest
/// refusal; observation bodies are never truncated (R07).
fn fit_bytes(bytes: &[u8], ceiling: u64) -> Vec<u8> {
    let max = ceiling.min(usize::MAX as u64) as usize;
    bytes.iter().take(max).copied().collect()
}

/// RB4 (R02): truncate a completed-step list to the invocation step ceiling.
fn fit_steps(steps: Vec<Label>, limits: &RunLimits) -> Vec<Label> {
    let max = limits.steps_per_invocation().min(usize::MAX as u64) as usize;
    steps.into_iter().take(max).collect()
}

/// MemVeil-shaped reference adapter: fact claims, object generations,
/// sweep order, claim-ledger views, feed presence and correction holders.
pub struct MemveilReferenceAdapter {
    limits: RunLimits,
    subject: SubjectBinding,
    // RB4 (R02): fixed dialect labels parsed once at construction and
    // truncated per invocation ceiling at use. The per-invocation path
    // carries no Label::parse expect and honors the live ceiling,
    // never the adapter default.
    schema: Label,
    method_execute: Label,
    stage_dispatch: Label,
    stage_admission: Label,
    stage_collect: Label,
    slot_script: Label,
}

impl MemveilReferenceAdapter {
    /// Build the adapter with its self-reported development subject binding.
    pub fn new() -> Result<Self, HarnessError> {
        let limits = RunLimits::default();
        let digest = Digest256::of_bytes(b"CP11 capture-memveil-reference subject v1");
        let host = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
        let subject = SubjectBinding::new(
            SubjectBindingValues {
                package_name: PACKAGE.to_string(),
                package_version: "0.1.0".to_string(),
                source_sha256: digest,
                build_inputs_sha256: digest,
                features: Vec::new(),
                backend: None,
                host: host.clone(),
                target: host,
                consumer: ConsumerBinding::new(
                    ConsumerBindingValues {
                        name: CONSUMER.to_string(),
                        build_inputs_sha256: digest,
                        executable_sha256: digest,
                    },
                    &limits,
                )?,
                objects: Vec::new(),
                provenance: BindingProvenance::SelfReported {
                    reason: "CP11 standalone reference consumer; self-reported development binding"
                        .to_string(),
                },
            },
            &limits,
        )?;
        // RB4 (R02): fixed dialect labels parse once at construction, so
        // the per-invocation path carries no Label::parse expect. These
        // expects can only fire on a mistyped constant (a programming
        // error every construction test exercises); Label::parse has no
        // HarnessError conversion, so a fallible parse is inexpressible.
        Ok(Self {
            limits,
            subject,
            schema: Label::parse(SCHEMA_ID).expect("CP11:fixed schema parses"),
            method_execute: Label::parse("execute").expect("CP11:fixed label parses"),
            stage_dispatch: Label::parse("dispatch").expect("CP11:fixed stage parses"),
            stage_admission: Label::parse("admission").expect("CP11:fixed stage parses"),
            stage_collect: Label::parse("collect").expect("CP11:fixed stage parses"),
            slot_script: Label::parse("script").expect("CP11:fixed slot parses"),
        })
    }

    // RB4 (R02/R07): every response is built under the invocation's own
    // limits, never under the adapter default. The body travels whole:
    // an over-ceiling body refuses at collect instead of truncating, and
    // the schema id is identity (refuse on over), not fitted metadata.
    fn observed(
        &self,
        invocation: &CaseInvocation,
        step: &Label,
        body: &str,
    ) -> Result<Observation, HarnessError> {
        let l = invocation.limits();
        Observation::new(
            ObservationValues {
                key: invocation.key().clone(),
                schema_id: self.schema.clone(),
                schema_revision: SCHEMA_REVISION,
                completed_steps: fit_steps(vec![step.clone()], l),
                bytes: body.as_bytes().to_vec(),
                effects: EffectBatch::empty(l),
            },
            l,
        )
    }

    fn cause(&self, l: &RunLimits) -> RefusalEvidence {
        RefusalEvidence::new(
            RefusalEvidenceValues {
                cause: RefusalCause::Unknown,
                // RB4 (R02): the method tag is convenience metadata, so it
                // is truncated to the live ceiling; the refusal cause and
                // category carry the identity and stay exact.
                method: self.method_execute.truncate(l.label_bytes()),
                evidence_ids: Vec::new(),
                tier: EvidenceTier::T0,
            },
            l,
        )
        .expect("RB4:fitted refusal cause fits invocation limits")
    }

    fn refusal(
        &self,
        invocation: &CaseInvocation,
        step: Option<Label>,
        stage: &Label,
        diagnostic: &str,
    ) -> CaseError {
        let l = invocation.limits();
        CaseError::new(
            CaseErrorValues {
                key: invocation.key().clone(),
                step_id: step,
                // RB4 (R02): fitted stage tag (see cause).
                stage: stage.truncate(l.label_bytes()),
                category: CaseErrorCategory::Refused,
                errno: None,
                diagnostic_bytes: fit_bytes(diagnostic.as_bytes(), l.diagnostic_bytes()),
                cause: self.cause(l),
                completed_steps: Vec::new(),
                partial_observation: None,
                effects: EffectBatch::empty(l),
            },
            l,
        )
        .expect("RB4:pre-fitted refusal fits invocation limits")
    }
}

impl ConformanceAdapter for MemveilReferenceAdapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }

    fn execute(
        &mut self,
        invocation: &CaseInvocation,
        fixture: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        let Some(step) = invocation.script().steps().first() else {
            return Err(self.refusal(
                invocation,
                None,
                &self.stage_dispatch,
                "CP11:script has no steps",
            ));
        };
        let op = step.operation().as_str();
        let Some(raw) = fixture.input(&self.slot_script) else {
            return Err(self.refusal(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_admission,
                "CP11:missing script slot",
            ));
        };
        let Some(case) = parse_case(raw) else {
            return Err(self.refusal(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_admission,
                "CP11:malformed script",
            ));
        };
        let Some(outcome) = run_scenario(op, case) else {
            let stage = if is_known_op(op) {
                &self.stage_admission
            } else {
                &self.stage_dispatch
            };
            let message = if is_known_op(op) {
                "CP11:unknown case"
            } else {
                "CP11:unknown operation"
            };
            return Err(self.refusal(invocation, Some(step.step_id().clone()), stage, message));
        };
        let body = match outcome {
            Ok(text) => text,
            Err(contract) => format!("refuse={};", refusal_name(&contract)),
        };
        self.observed(invocation, step.step_id(), &body)
            .map_err(|_| {
                self.refusal(
                    invocation,
                    Some(step.step_id().clone()),
                    &self.stage_collect,
                    "CP11:observation bounds",
                )
            })
    }

    fn retire(&mut self, request: &RetireRequest) -> RetirementReport {
        // RB4 (R02): the runner protocol guarantees a nonzero call id
        // (runner sequences from 1; RetireRequest is testkit-internal so
        // no downstream caller can inject 0). The clamp keeps this
        // infallible signature total even against a future producer bug.
        let call_id = request.call_id().max(1);
        RetirementReport::new(
            RetirementReportValues {
                call_id,
                owner: request.owner(),
                scope: request.scope().clone(),
                discovered: Vec::new(),
                transitions: Vec::new(),
                pending_snapshot: Vec::new(),
                complete: true,
                diagnostic: None,
            },
            &self.limits,
        )
        // RB4 (R02): clamped nonzero id, validated-type echoes (every
        // touched ceiling equals its maximum under the adapter default),
        // empty lists, no diagnostic: fits by construction.
        .expect("RB4:clamped retirement echoes fit adapter limits")
    }
}

fn is_known_op(op: &str) -> bool {
    matches!(op, "facts" | "sweep" | "views" | "feed" | "holder")
}

fn parse_case(raw: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut parts = text.split(';');
    let name = parts.next()?.strip_prefix("case=")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    if parts.any(|rest| !rest.is_empty()) {
        return None;
    }
    Some(name)
}

fn refusal_name(error: &ContractError) -> &'static str {
    match error {
        ContractError::InvalidId => "InvalidId",
        ContractError::DomainMismatch => "DomainMismatch",
        ContractError::ArithmeticOverflow => "ArithmeticOverflow",
        ContractError::ReversedBounds => "ReversedBounds",
        ContractError::ConservationMismatch => "ConservationMismatch",
        ContractError::MissingProvenance => "MissingProvenance",
        ContractError::ConflictingProvenance => "ConflictingProvenance",
        ContractError::DuplicateKey => "DuplicateKey",
        ContractError::EpochExhausted => "EpochExhausted",
        ContractError::GenerationMismatch => "GenerationMismatch",
        ContractError::CapacityExceeded => "CapacityExceeded",
        ContractError::MissingFeed => "MissingFeed",
        ContractError::DuplicateFeed => "DuplicateFeed",
        ContractError::StaleRevision => "StaleRevision",
        ContractError::InvalidInterval => "InvalidInterval",
        ContractError::InvalidSample => "InvalidSample",
        ContractError::InvalidProfile => "InvalidProfile",
        ContractError::IncompatibleVersion => "IncompatibleVersion",
        ContractError::InvalidReplay => "InvalidReplay",
        ContractError::SaturatedCount => "SaturatedCount",
        _ => "UnknownContract",
    }
}

fn epoch() -> Result<Epoch, ContractError> {
    Ok(Epoch::new(
        CaptureId::new([21; 16])?,
        ProducerId::new([22; 16])?,
        3,
    ))
}

fn source() -> Result<SourceRef, ContractError> {
    Ok(SourceRef::new(
        epoch()?,
        BindingId::new([23; 32])?,
        Origin::AdapterReported,
    ))
}

/// Run one operation/case scenario. `None` names an unknown operation or case.
pub fn run_scenario(op: &str, case: &str) -> Option<Result<String, ContractError>> {
    match (op, case) {
        ("facts", "ok") => Some(facts_ok()),
        ("facts", "erased") => Some(facts_erased()),
        ("facts", "unknown-mapping") => Some(facts_unknown_mapping()),
        ("sweep", "ok") => Some(sweep_ok()),
        ("sweep", "tie-order") => Some(sweep_tie_order()),
        ("sweep", "duplicate-id") => Some(sweep_duplicate_id()),
        ("views", "partial-then-final") => Some(views_partial_then_final()),
        ("views", "zero-benign") => Some(views_zero_case(false)),
        ("views", "atleast-zero-damaging") => Some(views_zero_case(true)),
        ("feed", "missing") => Some(feed_case(false)),
        ("feed", "complete") => Some(feed_case(true)),
        ("holder", "agree") => Some(holder_agree()),
        ("holder", "dropped") => Some(holder_dropped()),
        ("holder", "stale") => Some(holder_stale()),
        _ => None,
    }
}

fn current_key() -> Result<ObjectKey<u64>, ContractError> {
    Ok(ObjectKey::new(epoch()?, 42u64, 0).next_generation()?)
}

fn facts_ok() -> Result<String, ContractError> {
    let current = current_key()?;
    let submitted = ObjectKey::new(epoch()?, 42u64, 1);
    require_generation(&submitted, &current)?;
    Ok(format!("match=true;generation={};", current.generation()))
}

fn facts_erased() -> Result<String, ContractError> {
    let current = current_key()?;
    let submitted = ObjectKey::new(epoch()?, 42u64, 0);
    require_generation(&submitted, &current)?;
    Ok("match=true;".to_string())
}

fn facts_unknown_mapping() -> Result<String, ContractError> {
    let current = current_key()?;
    let submitted = ObjectKey::new(epoch()?, 7u64, 1);
    require_generation(&submitted, &current)?;
    Ok("match=true;".to_string())
}

fn edge(at: u64, kind: EdgeKind, id: u64) -> Result<StateEdge, ContractError> {
    Ok(StateEdge::new(
        Timestamp::new(ClockDomain::new([24; 16])?, at),
        kind,
        id,
    ))
}

fn sweep_ok() -> Result<String, ContractError> {
    let mut edges = Vec::new();
    for id in 0..10u64 {
        let kind = if id % 2 == 0 {
            EdgeKind::Release
        } else {
            EdgeKind::Acquire
        };
        edges.push(edge(id / 2, kind, id)?);
    }
    validate_sweep_order(&edges)?;
    Ok(format!("sweep=ok;edges={};", edges.len()))
}

fn sweep_tie_order() -> Result<String, ContractError> {
    let edges = vec![
        edge(5, EdgeKind::Acquire, 0)?,
        edge(5, EdgeKind::Release, 1)?,
    ];
    validate_sweep_order(&edges)?;
    Ok("sweep=ok;".to_string())
}

fn sweep_duplicate_id() -> Result<String, ContractError> {
    let edges = vec![
        edge(0, EdgeKind::Release, 0)?,
        edge(1, EdgeKind::Acquire, 0)?,
    ];
    validate_sweep_order(&edges)?;
    Ok("sweep=ok;".to_string())
}

fn ledger() -> Result<ClaimLedger, ContractError> {
    ClaimLedger::new(
        epoch()?,
        LedgerLimits {
            claims: 4,
            reasons_per_claim: 2,
            loss_facts: 4,
        },
    )
}

fn loss_fact(magnitude: LossMagnitude<Events>) -> Result<LossFact<Events>, ContractError> {
    LossFact::new(source()?, ChannelId::new(2), LossKind::Discovery, magnitude)
}

fn reason_name(reason: &QualityReason) -> &'static str {
    match reason {
        QualityReason::ConsumedLoss => "consumed-loss",
        QualityReason::MissingEvidence => "missing-evidence",
        QualityReason::QueryPartial => "query-partial",
        QualityReason::Ambiguous => "ambiguous",
        QualityReason::Capacity => "capacity",
        _ => "other",
    }
}

fn reasons_text(assessment: &ClaimAssessment) -> String {
    assessment
        .reasons()
        .iter()
        .map(reason_name)
        .collect::<Vec<_>>()
        .join("+")
}

fn views_partial_then_final() -> Result<String, ContractError> {
    let mut ledger = ledger()?;
    ledger.record_loss(
        &loss_fact(LossMagnitude::Exact(Count::new(2)))?,
        &[ClaimId::new(1)],
    )?;
    let overlay = QueryOverlay::new(&[ClaimId::new(1)], 4)?;
    let first = ledger.snapshot(&[ClaimId::new(1)], &overlay)?;
    let bare = QueryOverlay::new(&[], 4)?;
    let second = ledger.snapshot(&[ClaimId::new(1)], &bare)?;
    Ok(format!(
        "first={};second={};",
        reasons_text(&first[0]),
        reasons_text(&second[0])
    ))
}

fn views_zero_case(at_least: bool) -> Result<String, ContractError> {
    let mut ledger = ledger()?;
    let magnitude = if at_least {
        LossMagnitude::AtLeast(Count::new(0))
    } else {
        LossMagnitude::Exact(Count::new(0))
    };
    ledger.record_loss(&loss_fact(magnitude)?, &[ClaimId::new(1)])?;
    let bare = QueryOverlay::new(&[], 4)?;
    let view = ledger.snapshot(&[ClaimId::new(1)], &bare)?;
    Ok(format!("reasons={};", reasons_text(&view[0])))
}

fn feed_case(complete: bool) -> Result<String, ContractError> {
    let mut registry = FeedRegistry::new(epoch()?, &[ChannelId::new(7), ChannelId::new(8)], 4)?;
    let src = source()?;
    let fact = |channel: u32| {
        LossFact::new(
            src.clone(),
            ChannelId::new(channel),
            LossKind::Transport,
            LossMagnitude::<Events>::Unknown,
        )
    };
    registry.feed(&fact(7)?)?;
    if complete {
        registry.feed(&fact(8)?)?;
    }
    registry.finish()?;
    Ok("feeds=complete;".to_string())
}

fn view_snapshot() -> Result<Vec<ClaimAssessment>, ContractError> {
    let mut ledger = ledger()?;
    ledger.record_loss(
        &loss_fact(LossMagnitude::Exact(Count::new(2)))?,
        &[ClaimId::new(9)],
    )?;
    let bare = QueryOverlay::new(&[], 4)?;
    ledger.snapshot(&[ClaimId::new(9)], &bare)
}

fn holder_pair() -> Result<HolderPair<Vec<ClaimAssessment>>, ContractError> {
    Ok(HolderPair::new(
        Versioned::new(epoch()?, view_snapshot()?),
        Versioned::new(epoch()?, view_snapshot()?),
    ))
}

fn is_rev1(revision: Revision) -> bool {
    revision == Revision::new(1)
}

fn holder_agree() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    let corrected = view_snapshot()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), corrected.clone())?)?;
    pair.apply_export(Correction::new(epoch()?, Revision::new(0), corrected)?)?;
    Ok(format!(
        "report_rev1={};export_rev1={};report_len={};export_len={};agree={};",
        is_rev1(pair.report().revision()),
        is_rev1(pair.export().revision()),
        pair.report().value().len(),
        pair.export().value().len(),
        pair.agree()
    ))
}

fn holder_dropped() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), view_snapshot()?)?)?;
    Ok(format!(
        "report_rev1={};export_rev1={};report_len={};export_len={};agree={};diverged={};",
        is_rev1(pair.report().revision()),
        is_rev1(pair.export().revision()),
        pair.report().value().len(),
        pair.export().value().len(),
        pair.agree(),
        pair.divergence().is_some()
    ))
}

fn holder_stale() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), view_snapshot()?)?)?;
    match pair.apply_report(Correction::new(epoch()?, Revision::new(0), view_snapshot()?)?) {
        Err(ContractError::StaleRevision) => Ok(format!(
            "refuse=StaleRevision;report_len={};",
            pair.report().value().len()
        )),
        Err(other) => Err(other),
        Ok(()) => Ok("unexpected-accept;".to_string()),
    }
}
